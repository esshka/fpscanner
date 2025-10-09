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
	patternColumnWidth = 48
)

type webSink struct {
	listenAddr string
	retention  time.Duration
	logger     zerolog.Logger

	mu    sync.RWMutex
	stats map[string]*aggregateStats
	start time.Time

	server *http.Server
}

type aggregateStats struct {
	tag            string
	pattern        string
	alerts         int
	totalNotional  decimal.Decimal
	totalDiff      time.Duration
	maxDiff        time.Duration
	lastAlert      time.Time
	windows        map[time.Duration]struct{}
	instruments    map[string]int
	cadence        time.Duration
	cadenceJitter  time.Duration
	cadenceSamples int
}

type tableEntry struct {
	Tag            string          `json:"tag"`
	Pattern        string          `json:"pattern"`
	Instruments    []string        `json:"instruments"`
	Alerts         int             `json:"alerts"`
	TotalNotional  decimal.Decimal `json:"totalNotional"`
	AvgDiff        time.Duration   `json:"avgDiff"`
	MaxDiff        time.Duration   `json:"maxDiff"`
	Windows        []time.Duration `json:"windows"`
	LastAlert      time.Time       `json:"lastAlert"`
	Cadence        time.Duration   `json:"cadence,omitempty"`
	CadenceJitter  time.Duration   `json:"cadenceJitter,omitempty"`
	CadenceSamples int             `json:"cadenceSamples,omitempty"`
	CadenceSummary string          `json:"cadenceSummary,omitempty"`
}

func newWebSink(addr string, retention time.Duration, logger zerolog.Logger) *webSink {
	if strings.TrimSpace(addr) == "" {
		addr = ":9300"
	}
	return &webSink{
		listenAddr: addr,
		retention:  retention,
		logger:     logger,
		stats:      make(map[string]*aggregateStats),
	}
}

func (w *webSink) Name() string { return "web" }

func (w *webSink) Start(ctx context.Context) error {
	w.mu.Lock()
	w.stats = make(map[string]*aggregateStats)
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
	_, notional, _ := parseKeyFields(alert)

	tag := strings.TrimSpace(alert.RobotTag)
	if tag == "" {
		tag = formatPattern(alert)
	}
	pattern := formatPattern(alert)

	diff := alert.LastSeen.Sub(alert.FirstSeen)
	if diff < 0 {
		diff = 0
	}

	w.mu.Lock()
	stats := w.ensureStats(tag)

	prevLast := stats.lastAlert
	sameEvent := !alert.LastSeen.IsZero() && alert.LastSeen.Equal(prevLast)

	stats.tag = tag
	stats.pattern = pattern
	stats.windows[alert.Window] = struct{}{}
	if !sameEvent {
		stats.alerts++
		notionalTotal := notional.Mul(decimal.NewFromInt(int64(alert.Count)))
		stats.totalNotional = stats.totalNotional.Add(notionalTotal)
		stats.totalDiff += diff
		if diff > stats.maxDiff {
			stats.maxDiff = diff
		}
		stats.instruments[alert.InstID]++
	}
	if alert.LastSeen.After(prevLast) {
		stats.lastAlert = alert.LastSeen
	}
	if alert.TimingPattern != nil {
		stats.cadence = alert.TimingPattern.Interval
		stats.cadenceJitter = alert.TimingPattern.Jitter
		stats.cadenceSamples = alert.TimingPattern.Samples
	}

	w.mu.Unlock()
	return nil
}

func (w *webSink) ensureStats(tag string) *aggregateStats {
	stat, ok := w.stats[tag]
	if !ok {
		stat = &aggregateStats{
			tag:         tag,
			windows:     make(map[time.Duration]struct{}),
			instruments: make(map[string]int),
		}
		w.stats[tag] = stat
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
	for tag, stats := range w.stats {
		if !w.start.IsZero() && (stats.lastAlert.IsZero() || stats.lastAlert.Before(w.start)) {
			delete(w.stats, tag)
			continue
		}
		if w.retention > 0 && !stats.lastAlert.IsZero() && now.Sub(stats.lastAlert) > w.retention {
			delete(w.stats, tag)
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
		sort.Slice(windows, func(i, j int) bool { return windows[i] < windows[j] })
		instruments := make([]string, 0, len(stats.instruments))
		for inst := range stats.instruments {
			instruments = append(instruments, inst)
		}
		sort.Strings(instruments)
		cadenceSummary := buildCadenceSummary(stats.cadence, stats.cadenceJitter, stats.cadenceSamples)
		pattern := stats.pattern
		if strings.TrimSpace(pattern) == "" {
			pattern = tag
		}
		entries = append(entries, tableEntry{
			Tag:            tag,
			Pattern:        pattern,
			Instruments:    instruments,
			Alerts:         stats.alerts,
			TotalNotional:  stats.totalNotional,
			AvgDiff:        avg,
			MaxDiff:        stats.maxDiff,
			Windows:        windows,
			LastAlert:      stats.lastAlert,
			Cadence:        stats.cadence,
			CadenceJitter:  stats.cadenceJitter,
			CadenceSamples: stats.cadenceSamples,
			CadenceSummary: cadenceSummary,
		})
	}

	sort.Slice(entries, func(i, j int) bool {
		cmp := entries[i].TotalNotional.Cmp(entries[j].TotalNotional)
		if cmp == 0 {
			return entries[i].Tag < entries[j].Tag
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
	"formatDuration":    formatDuration,
	"formatWindows":     formatWindows,
	"formatLast":        formatLast,
	"truncatePattern":   truncatePattern,
	"formatInstruments": formatInstruments,
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
        <th>Tag</th>
        <th>Instruments</th>
        <th>Pattern</th>
        <th class="center">Alerts</th>
        <th class="right">Total Notional (USDT)</th>
        <th class="right">Avg Diff</th>
        <th class="right">Max Diff</th>
        <th>Windows</th>
        <th class="right">Cadence</th>
        <th>Last Alert</th>
      </tr>
    </thead>
    <tbody>
      {{ if .Entries }}
        {{ range .Entries }}
          <tr>
            <td>{{ .Tag }}</td>
            <td>{{ formatInstruments .Instruments }}</td>
            <td>{{ truncatePattern .Pattern }}</td>
            <td class="center">{{ .Alerts }}</td>
            <td class="right">{{ .TotalNotional }}</td>
            <td class="right">{{ formatDuration .AvgDiff }}</td>
            <td class="right">{{ formatDuration .MaxDiff }}</td>
            <td>{{ formatWindows .Windows }}</td>
            <td class="right">{{ if .CadenceSummary }}{{ .CadenceSummary }}{{ else }}-{{ end }}</td>
            <td>{{ formatLast .LastAlert }}</td>
          </tr>
        {{ end }}
      {{ else }}
        <tr>
          <td colspan="10" class="center">No duplicates observed yet.</td>
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

func formatInstruments(set []string) string {
	if len(set) == 0 {
		return "-"
	}
	return strings.Join(set, ", ")
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
	price, notional, side := parseKeyFields(alert)
	direction := formatDirection(side)

	var pattern string
	switch alert.DuplicateMode {
	case config.DuplicateModePriceOnly:
		if !price.Equal(decimal.Zero) {
			pattern = price.String()
		}
	default:
		if !price.Equal(decimal.Zero) && !notional.Equal(decimal.Zero) {
			pattern = fmt.Sprintf("%s x %s USDT", price.String(), notional.String())
		} else if !price.Equal(decimal.Zero) {
			pattern = price.String()
		}
	}
	if pattern == "" {
		if direction != "" {
			pattern = direction
			direction = ""
		} else {
			pattern = alert.Key
		}
	}
	if direction != "" {
		pattern = strings.TrimSpace(pattern + " " + direction)
	}
	return pattern
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

func parseKeyFields(a Alert) (price decimal.Decimal, notional decimal.Decimal, side string) {
	parts := strings.Split(a.Key, "|")
	switch a.DuplicateMode {
	case config.DuplicateModeStrict:
		if len(parts) >= 3 {
			price = safeDecimal(parts[0])
			notional = safeDecimal(parts[1])
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
			notional = safeDecimal(parts[1])
			side = parts[2]
		}
	}
	return price, notional, side
}

func safeDecimal(value string) decimal.Decimal {
	d, err := decimal.NewFromString(value)
	if err != nil {
		return decimal.Zero
	}
	return d
}

func buildCadenceSummary(cadence, jitter time.Duration, samples int) string {
	if cadence <= 0 || samples <= 0 {
		return ""
	}
	summary := formatCompactDuration(cadence)
	if jitter > 0 {
		summary = fmt.Sprintf("%s (spread %s)", summary, formatCompactDuration(jitter))
	}
	return fmt.Sprintf("%s, n=%d", summary, samples)
}

func formatCompactDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	rounded := d
	if d < time.Minute {
		rounded = d.Round(10 * time.Millisecond)
	}
	if rounded < time.Second {
		return fmt.Sprintf("%dms", rounded/time.Millisecond)
	}
	if rounded < time.Minute {
		seconds := float64(rounded) / float64(time.Second)
		return fmt.Sprintf("%.2fs", seconds)
	}
	return rounded.String()
}
