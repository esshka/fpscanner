package alert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/shopspring/decimal"

	"github.com/esshka/fp-scanner-go/internal/config"
)

const (
	patternColumnWidth = 32
)

type webSink struct {
	listenAddr string
	retention  time.Duration
	logger     zerolog.Logger

	mu    sync.RWMutex
	stats map[string]map[string]*aggregateStats
	start time.Time

	server *http.Server
}

type aggregateStats struct {
	alerts      int
	totalVolume decimal.Decimal
	totalDiff   time.Duration
	maxDiff     time.Duration
	lastAlert   time.Time
	windows     map[time.Duration]struct{}
}

type tableEntry struct {
	Instrument  string          `json:"instrument"`
	Pattern     string          `json:"pattern"`
	Alerts      int             `json:"alerts"`
	TotalVolume decimal.Decimal `json:"totalVolume"`
	AvgDiff     time.Duration   `json:"avgDiff"`
	MaxDiff     time.Duration   `json:"maxDiff"`
	Windows     []time.Duration `json:"windows"`
	LastAlert   time.Time       `json:"lastAlert"`
}

func newWebSink(addr string, retention time.Duration, logger zerolog.Logger) *webSink {
	if strings.TrimSpace(addr) == "" {
		addr = ":9300"
	}
	return &webSink{
		listenAddr: addr,
		retention:  retention,
		logger:     logger,
		stats:      make(map[string]map[string]*aggregateStats),
	}
}

func (w *webSink) Name() string { return "web" }

func (w *webSink) Start(ctx context.Context) error {
	w.mu.Lock()
	w.stats = make(map[string]map[string]*aggregateStats)
	w.start = time.Now()
	w.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/", w.handleIndex)
	mux.HandleFunc("/api/alerts", w.handleAPI)

	server := &http.Server{
		Addr:    w.listenAddr,
		Handler: mux,
	}
	w.server = server

	errCh := make(chan error, 1)
	go func() {
		w.logger.Info().Str("addr", w.listenAddr).Msg("web UI listening")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			w.logger.Warn().Err(err).Msg("web UI shutdown error")
		}
		return context.Canceled
	case err := <-errCh:
		return err
	}
}

func (w *webSink) Send(_ context.Context, alert Alert) error {
	_, size, _ := parseKeyFields(alert)

	w.mu.Lock()
	stats := w.ensureStats(alert.InstID, formatPattern(alert))

	diff := alert.LastSeen.Sub(alert.FirstSeen)
	if diff < 0 {
		diff = 0
	}

	stats.alerts++
	stats.totalVolume = stats.totalVolume.Add(size.Mul(decimal.NewFromInt(int64(alert.Count))))
	stats.totalDiff += diff
	if diff > stats.maxDiff {
		stats.maxDiff = diff
	}
	if alert.LastSeen.After(stats.lastAlert) {
		stats.lastAlert = alert.LastSeen
	}
	if stats.windows == nil {
		stats.windows = make(map[time.Duration]struct{})
	}
	stats.windows[alert.Window] = struct{}{}

	w.mu.Unlock()
	return nil
}

func (w *webSink) ensureStats(instID, pattern string) *aggregateStats {
	perPattern, ok := w.stats[instID]
	if !ok {
		perPattern = make(map[string]*aggregateStats)
		w.stats[instID] = perPattern
	}
	stat, ok := perPattern[pattern]
	if !ok {
		stat = &aggregateStats{}
		perPattern[pattern] = stat
	}
	return stat
}

func (w *webSink) snapshot() []tableEntry {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.snapshotLocked()
}

func (w *webSink) snapshotLocked() []tableEntry {
	entries := make([]tableEntry, 0)
	now := time.Now()
	for inst, patterns := range w.stats {
		for pattern, stats := range patterns {
			if !w.start.IsZero() && (stats.lastAlert.IsZero() || stats.lastAlert.Before(w.start)) {
				delete(patterns, pattern)
				continue
			}
			if w.retention > 0 && !stats.lastAlert.IsZero() && now.Sub(stats.lastAlert) > w.retention {
				delete(patterns, pattern)
				continue
			}
			avg := time.Duration(0)
			if stats.alerts > 0 {
				avg = time.Duration(int64(stats.totalDiff) / int64(stats.alerts))
			}
			windows := make([]time.Duration, 0, len(stats.windows))
			for window := range stats.windows {
				windows = append(windows, window)
			}
			entries = append(entries, tableEntry{
				Instrument:  inst,
				Pattern:     pattern,
				Alerts:      stats.alerts,
				TotalVolume: stats.totalVolume,
				AvgDiff:     avg,
				MaxDiff:     stats.maxDiff,
				Windows:     windows,
				LastAlert:   stats.lastAlert,
			})
		}
		if len(patterns) == 0 {
			delete(w.stats, inst)
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		cmp := entries[i].TotalVolume.Cmp(entries[j].TotalVolume)
		if cmp == 0 {
			if entries[i].Instrument == entries[j].Instrument {
				return entries[i].Pattern < entries[j].Pattern
			}
			return entries[i].Instrument < entries[j].Instrument
		}
		return cmp > 0
	})

	return entries
}

func (w *webSink) handleIndex(rw http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(rw, r)
		return
	}

	entries := w.snapshot()
	payload := struct {
		Entries     []tableEntry
		GeneratedAt time.Time
	}{
		Entries:     entries,
		GeneratedAt: time.Now(),
	}

	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := indexTemplate.Execute(rw, payload); err != nil {
		w.logger.Error().Err(err).Msg("render index page")
	}
}

func (w *webSink) handleAPI(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	entries := w.snapshot()
	payload := struct {
		GeneratedAt time.Time    `json:"generatedAt"`
		Entries     []tableEntry `json:"entries"`
	}{
		GeneratedAt: time.Now(),
		Entries:     entries,
	}

	rw.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(rw).Encode(payload); err != nil {
		w.logger.Error().Err(err).Msg("encode alerts payload")
	}
}

var indexTemplate = template.Must(template.New("index").Funcs(template.FuncMap{
	"formatDuration":  formatDuration,
	"formatWindows":   formatWindows,
	"formatLast":      formatLast,
	"truncatePattern": truncatePattern,
}).Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta http-equiv="refresh" content="5">
  <title>FP Scanner Alerts</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem; background-color: #0b0c10; color: #f0f3f6; }
    h1 { margin-bottom: 0.25rem; }
    .meta { color: #9aa5b1; margin-bottom: 1.5rem; }
    table { border-collapse: collapse; width: 100%; }
    th, td { padding: 0.5rem 0.75rem; text-align: left; }
    th { background-color: #1f2833; color: #66fcf1; position: sticky; top: 0; }
    tr:nth-child(even) { background-color: #162128; }
    tr:hover { background-color: #1b2a36; }
    .right { text-align: right; }
    .center { text-align: center; }
  </style>
</head>
<body>
  <h1>Duplicate Patterns</h1>
  <div class="meta">Updated {{ formatLast .GeneratedAt }}</div>
  <table>
    <thead>
      <tr>
        <th>Ticker</th>
        <th>Pattern</th>
        <th class="center">Alerts</th>
        <th class="right">Total Volume</th>
        <th class="right">Avg Diff</th>
        <th class="right">Max Diff</th>
        <th>Windows</th>
        <th>Last Alert</th>
      </tr>
    </thead>
    <tbody>
      {{ if .Entries }}
        {{ range .Entries }}
          <tr>
            <td>{{ .Instrument }}</td>
            <td>{{ truncatePattern .Pattern }}</td>
            <td class="center">{{ .Alerts }}</td>
            <td class="right">{{ .TotalVolume }}</td>
            <td class="right">{{ formatDuration .AvgDiff }}</td>
            <td class="right">{{ formatDuration .MaxDiff }}</td>
            <td>{{ formatWindows .Windows }}</td>
            <td>{{ formatLast .LastAlert }}</td>
          </tr>
        {{ end }}
      {{ else }}
        <tr>
          <td colspan="8" class="center">No duplicates observed yet.</td>
        </tr>
      {{ end }}
    </tbody>
  </table>
  <p class="meta">API: <a href="/api/alerts">/api/alerts</a></p>
</body>
</html>`))

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "00:00:00"
	}
	seconds := int(d.Round(time.Second).Seconds())
	h := seconds / 3600
	m := (seconds % 3600) / 60
	s := seconds % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

func formatWindows(set []time.Duration) string {
	if len(set) == 0 {
		return "-"
	}
	sort.Slice(set, func(i, j int) bool { return set[i] < set[j] })
	parts := make([]string, len(set))
	for i, w := range set {
		parts[i] = fmt.Sprintf("%ds", int(w.Seconds()))
	}
	return strings.Join(parts, ", ")
}

func formatLast(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.In(time.Local).Format("2006-01-02 15:04:05")
}

func truncatePattern(pattern string) string {
	runes := []rune(pattern)
	if patternColumnWidth <= 0 || len(runes) <= patternColumnWidth {
		return pattern
	}
	if patternColumnWidth == 1 {
		return string(runes[0])
	}
	return string(runes[:patternColumnWidth-1]) + "…"
}

func formatPattern(alert Alert) string {
	price, size, side := parseKeyFields(alert)
	direction := formatDirection(side)

	switch alert.DuplicateMode {
	case config.DuplicateModePriceOnly:
		if price.Equal(decimal.Zero) {
			return direction
		}
		if direction == "" {
			return price.String()
		}
		return fmt.Sprintf("%s %s", price.String(), direction)
	default:
		base := ""
		if !price.Equal(decimal.Zero) && !size.Equal(decimal.Zero) {
			base = fmt.Sprintf("%s x %s", price.String(), size.String())
		} else if !price.Equal(decimal.Zero) {
			base = price.String()
		} else {
			base = alert.Key
		}
		if direction == "" {
			return base
		}
		return strings.TrimSpace(base + " " + direction)
	}
}

func formatDirection(side string) string {
	side = strings.ToLower(strings.TrimSpace(side))
	switch side {
	case "buy":
		return "Up"
	case "sell":
		return "Down"
	case "":
		return ""
	default:
		return strings.Title(side)
	}
}

func parseKeyFields(a Alert) (price decimal.Decimal, size decimal.Decimal, side string) {
	parts := strings.Split(a.Key, "|")
	switch a.DuplicateMode {
	case config.DuplicateModeStrict:
		if len(parts) >= 3 {
			price = safeDecimal(parts[0])
			size = safeDecimal(parts[1])
			side = parts[2]
		}
	case config.DuplicateModePriceOnly:
		if len(parts) >= 2 {
			price = safeDecimal(parts[0])
			side = parts[1]
		}
	default:
		if len(parts) >= 3 {
			price = safeDecimal(parts[0])
			size = safeDecimal(parts[1])
			side = parts[2]
		}
	}
	return price, size, side
}

func safeDecimal(value string) decimal.Decimal {
	d, err := decimal.NewFromString(value)
	if err != nil {
		return decimal.Zero
	}
	return d
}
