package alert

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/shopspring/decimal"

	"github.com/esshka/fp-scanner-go/internal/config"
)

const (
	patternColumnWidth = 32
	windowsColumnWidth = 18
)

type tableSink struct {
	app   *tview.Application
	table *tview.Table

	mu        sync.Mutex
	stats     map[string]map[string]*aggregateStats
	start     time.Time
	retention time.Duration
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
	instrument  string
	pattern     string
	alerts      int
	totalVolume decimal.Decimal
	avgDiff     time.Duration
	maxDiff     time.Duration
	windows     []time.Duration
	lastAlert   time.Time
}

func newTableSink(retention time.Duration) *tableSink {
	app := tview.NewApplication()
	tbl := tview.NewTable().
		SetBorders(false).
		SetFixed(1, 0).
		SetSelectable(true, false)

	tbl.SetBorder(true).
		SetTitle(" Duplicate Patterns ")

	return &tableSink{
		app:       app,
		table:     tbl,
		stats:     make(map[string]map[string]*aggregateStats),
		retention: retention,
	}
}

func (t *tableSink) Name() string { return "tview" }

// Start implements a lifecycle hook allowing the router to run the TUI.
func (t *tableSink) Start(ctx context.Context) error {
	stopCh := make(chan struct{})
	var stopOnce sync.Once
	requestStop := func() {
		stopOnce.Do(func() { close(stopCh) })
	}

	t.mu.Lock()
	t.stats = make(map[string]map[string]*aggregateStats)
	t.start = time.Now()
	t.mu.Unlock()

	t.app.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch {
		case event.Key() == tcell.KeyCtrlC,
			event.Key() == tcell.KeyEscape,
			event.Key() == tcell.KeyRune && (event.Rune() == 'q' || event.Rune() == 'Q'):
			requestStop()
			return nil
		}
		return event
	})

	go func() {
		<-ctx.Done()
		requestStop()
	}()

	go func() {
		<-stopCh
		t.app.QueueUpdateDraw(func() {
			t.app.Stop()
		})
	}()

	t.update(nil)
	t.app.SetRoot(t.table, true)
	t.app.EnableMouse(true)

	err := t.app.Run()

	select {
	case <-ctx.Done():
		return context.Canceled
	case <-stopCh:
		if err == nil || errors.Is(err, context.Canceled) {
			return context.Canceled
		}
		return err
	default:
		return err
	}
}

func (t *tableSink) Send(_ context.Context, alert Alert) error {
	_, size, _ := parseKeyFields(alert)

	t.mu.Lock()
	stats := t.ensureStats(alert.InstID, formatPattern(alert))

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

	snapshot := t.snapshotLocked()
	t.mu.Unlock()

	t.app.QueueUpdateDraw(func() {
		t.update(snapshot)
	})

	return nil
}

func (t *tableSink) ensureStats(instID, pattern string) *aggregateStats {
	perPattern, ok := t.stats[instID]
	if !ok {
		perPattern = make(map[string]*aggregateStats)
		t.stats[instID] = perPattern
	}
	stat, ok := perPattern[pattern]
	if !ok {
		stat = &aggregateStats{}
		perPattern[pattern] = stat
	}
	return stat
}

func (t *tableSink) snapshotLocked() []tableEntry {
	entries := make([]tableEntry, 0)
	now := time.Now()
	for inst, patterns := range t.stats {
		for pattern, stats := range patterns {
			if !t.start.IsZero() && (stats.lastAlert.IsZero() || stats.lastAlert.Before(t.start)) {
				delete(patterns, pattern)
				continue
			}
			if t.retention > 0 && !stats.lastAlert.IsZero() && now.Sub(stats.lastAlert) > t.retention {
				delete(patterns, pattern)
				continue
			}
			avg := time.Duration(0)
			if stats.alerts > 0 {
				avg = time.Duration(int64(stats.totalDiff) / int64(stats.alerts))
			}
			windows := make([]time.Duration, 0, len(stats.windows))
			for w := range stats.windows {
				windows = append(windows, w)
			}
			entries = append(entries, tableEntry{
				instrument:  inst,
				pattern:     pattern,
				alerts:      stats.alerts,
				totalVolume: stats.totalVolume,
				avgDiff:     avg,
				maxDiff:     stats.maxDiff,
				windows:     windows,
				lastAlert:   stats.lastAlert,
			})
		}
		if len(patterns) == 0 {
			delete(t.stats, inst)
		}
	}

	sort.Slice(entries, func(i, j int) bool {
		cmp := entries[i].totalVolume.Cmp(entries[j].totalVolume)
		if cmp == 0 {
			if entries[i].instrument == entries[j].instrument {
				return entries[i].pattern < entries[j].pattern
			}
			return entries[i].instrument < entries[j].instrument
		}
		return cmp > 0
	})

	return entries
}

func (t *tableSink) update(entries []tableEntry) {
	currentRow, currentCol := t.table.GetSelection()

	t.table.Clear()

	headers := []string{"Ticker", "Pattern", "Alerts", "Total Volume", "Avg Diff", "Max Diff", "Windows", "Last Alert"}
	for col, text := range headers {
		t.table.SetCell(0, col, headerCell(text))
	}

	for row, entry := range entries {
		r := row + 1
		t.table.SetCell(r, 0, valueCell(entry.instrument))
		t.table.SetCell(r, 1, valueCell(truncateString(entry.pattern, patternColumnWidth)))
		t.table.SetCell(r, 2, valueCell(fmt.Sprintf("%d", entry.alerts)).SetAlign(tview.AlignRight))
		t.table.SetCell(r, 3, valueCell(entry.totalVolume.String()).SetAlign(tview.AlignRight))
		t.table.SetCell(r, 4, valueCell(formatDuration(entry.avgDiff)))
		t.table.SetCell(r, 5, valueCell(formatDuration(entry.maxDiff)))
		t.table.SetCell(r, 6, valueCell(truncateString(formatWindows(entry.windows), windowsColumnWidth)))
		last := "-"
		if !entry.lastAlert.IsZero() {
			last = entry.lastAlert.In(time.Local).Format("15:04:05")
		}
		t.table.SetCell(r, 7, valueCell(last))
	}

	if len(entries) == 0 {
		t.table.Select(0, 0)
		return
	}

	if currentRow <= 0 || currentRow > len(entries) {
		t.table.Select(1, 0)
		return
	}

	t.table.Select(currentRow, currentCol)
}

func headerCell(text string) *tview.TableCell {
	return tview.NewTableCell(text).
		SetTextColor(tcell.ColorAqua).
		SetSelectable(false).
		SetAlign(tview.AlignLeft).
		SetAttributes(tcell.AttrBold)
}

func valueCell(text string) *tview.TableCell {
	return tview.NewTableCell(text).
		SetTextColor(tcell.ColorWhite).
		SetAlign(tview.AlignLeft)
}

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
	return strings.Join(parts, ",")
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

func truncateString(s string, width int) string {
	if width <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= width {
		return s
	}
	if width == 1 {
		return string(runes[0])
	}
	return string(runes[:width-1]) + "…"
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
