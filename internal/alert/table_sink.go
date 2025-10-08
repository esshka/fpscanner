package alert

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/shopspring/decimal"

	"github.com/esshka/fp-scanner-go/internal/config"
)

const (
	tableClearCommand = "\033[H\033[2J"
	tableHeader       = "+----------+--------+---------+--------------+------------+------------+----------------------+----------------------+"
	patternWidth      = 20
	redrawInterval    = 500 * time.Millisecond
)

type tableSink struct {
	mu       sync.Mutex
	stats    map[string]map[time.Duration]*aggregateStats
	lastDraw time.Time
}

func newTableSink() *tableSink {
	return &tableSink{stats: make(map[string]map[time.Duration]*aggregateStats)}
}

func (t *tableSink) Name() string { return "table" }

func (t *tableSink) Send(_ context.Context, a Alert) error {
	_, size, _ := parseKeyFields(a)

	t.mu.Lock()
	defer t.mu.Unlock()

	diff := a.LastSeen.Sub(a.FirstSeen)
	if diff < 0 {
		diff = 0
	}

	stats := t.ensureStats(a.InstID, a.Window)
	stats.alerts++
	volume := size.Mul(decimal.NewFromInt(int64(a.Count)))
	stats.totalVolume = stats.totalVolume.Add(volume)
	stats.totalDiff += diff
	if diff > stats.maxDiff {
		stats.maxDiff = diff
	}
	if a.LastSeen.After(stats.lastAlert) {
		stats.lastAlert = a.LastSeen
	}
	stats.lastPattern = formatPattern(a)

	if time.Since(t.lastDraw) >= redrawInterval {
		t.render()
		t.lastDraw = time.Now()
	}

	return nil
}

type aggregateStats struct {
	alerts      int
	totalVolume decimal.Decimal
	totalDiff   time.Duration
	maxDiff     time.Duration
	lastAlert   time.Time
	lastPattern string
}

func (t *tableSink) ensureStats(instID string, window time.Duration) *aggregateStats {
	perWindow, ok := t.stats[instID]
	if !ok {
		perWindow = make(map[time.Duration]*aggregateStats)
		t.stats[instID] = perWindow
	}
	stat, ok := perWindow[window]
	if !ok {
		stat = &aggregateStats{}
		perWindow[window] = stat
	}
	return stat
}

func (t *tableSink) render() {
	fmt.Print(tableClearCommand)
	fmt.Println(tableHeader)
	fmt.Println("| Ticker   | Window | Alerts  | Total Volume | Avg Diff   | Max Diff   | Last Alert (local)  | Last Pattern         |")
	fmt.Println(tableHeader)

	instIDs := make([]string, 0, len(t.stats))
	for inst := range t.stats {
		instIDs = append(instIDs, inst)
	}
	sort.Strings(instIDs)

	for _, inst := range instIDs {
		windows := make([]time.Duration, 0, len(t.stats[inst]))
		for w := range t.stats[inst] {
			windows = append(windows, w)
		}
		sort.Slice(windows, func(i, j int) bool { return windows[i] < windows[j] })

		for _, w := range windows {
			stats := t.stats[inst][w]
			avg := time.Duration(0)
			if stats.alerts > 0 {
				avg = time.Duration(int64(stats.totalDiff) / int64(stats.alerts))
			}
			last := "-"
			if !stats.lastAlert.IsZero() {
				last = stats.lastAlert.In(time.Local).Format("15:04:05")
			}
			pattern := stats.lastPattern
			if pattern == "" {
				pattern = "-"
			}
			fmt.Printf("| %-8s | %-6s | %7d | %-12s | %-10s | %-10s | %-20s | %-20s |\n",
				inst,
				formatWindow(w),
				stats.alerts,
				stats.totalVolume.String(),
				fmtDuration(avg),
				fmtDuration(stats.maxDiff),
				last,
				truncateString(pattern, patternWidth),
			)
		}
	}

	fmt.Println(tableHeader)
}

func fmtDuration(d time.Duration) string {
	if d <= 0 {
		return "00:00:00"
	}
	seconds := int(d.Round(time.Second).Seconds())
	h := seconds / 3600
	m := (seconds % 3600) / 60
	s := seconds % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
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

func formatWindow(d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}

func formatPattern(a Alert) string {
	price, size, side := parseKeyFields(a)
	direction := formatDirection(side)

	var base string
	switch a.DuplicateMode {
	case config.DuplicateModePriceOnly:
		if !price.Equal(decimal.Zero) {
			base = price.String()
		}
	default:
		if !price.Equal(decimal.Zero) && !size.Equal(decimal.Zero) {
			base = fmt.Sprintf("%s x %s", price.String(), size.String())
		} else if !price.Equal(decimal.Zero) {
			base = price.String()
		}
	}

	if base == "" {
		base = a.Key
	}
	if direction != "" {
		return strings.TrimSpace(base + " " + direction)
	}
	return base
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

func truncateString(s string, max int) string {
	if max <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	if max == 1 {
		return string(runes[0])
	}
	return string(runes[:max-1]) + "…"
}
