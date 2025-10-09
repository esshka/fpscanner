package detector

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/shopspring/decimal"

	"github.com/esshka/fp-scanner-go/internal/alert"
	"github.com/esshka/fp-scanner-go/internal/config"
	"github.com/esshka/fp-scanner-go/internal/trade"
)

type mockDispatcher struct {
	alerts []alert.Alert
}

func (m *mockDispatcher) Dispatch(a alert.Alert) {
	m.alerts = append(m.alerts, a)
}

func TestWindowStateDuplicateFlow(t *testing.T) {
	state := newWindowState(3*time.Second, 2*time.Second)
	base := time.Unix(0, 0)

	if alert, count, _ := state.insert(base, "k", 2); alert || count != 1 {
		t.Fatalf("expected no alert on first insert, got alert=%v count=%d", alert, count)
	}

	if alert, count, first := state.insert(base.Add(time.Second), "k", 2); !alert || count != 2 || !first.Equal(base) {
		t.Fatalf("expected alert on second insert, got alert=%v count=%d first=%v", alert, count, first)
	}

	if alert, count, _ := state.insert(base.Add(1500*time.Millisecond), "k", 2); alert || count != 3 {
		t.Fatalf("expected cooldown to suppress alert, got alert=%v count=%d", alert, count)
	}

	// advance beyond cooldown and window to validate eviction
	ts := base.Add(5 * time.Second)
	if alert, count, _ := state.insert(ts, "k", 2); alert || count != 1 {
		t.Fatalf("expected no alert with single fresh event, got alert=%v count=%d", alert, count)
	}

	if alert, count, first := state.insert(ts.Add(200*time.Millisecond), "k", 2); !alert || count != 2 || !first.Equal(ts) {
		t.Fatalf("expected alert after new duplicate, got alert=%v count=%d first=%v", alert, count, first)
	}
}

func TestWindowStateDetectTimingPattern(t *testing.T) {
	state := newWindowState(5*time.Second, time.Second)
	base := time.Unix(0, 0)

	cfg := patternSettings{
		enabled:        true,
		minOccurrences: 3,
		maxLookback:    5,
		maxJitter:      50 * time.Millisecond,
		relativeJitter: 0.1,
		minInterval:    0,
	}

	for i := 0; i < 3; i++ {
		state.insert(base.Add(time.Duration(i)*200*time.Millisecond), "k", 2)
	}

	res := state.detectTimingPattern("k", cfg)
	if res == nil {
		t.Fatalf("expected timing pattern detection")
	}
	if res.samples != 3 {
		t.Fatalf("expected 3 samples, got %d", res.samples)
	}
	if res.interval != 200*time.Millisecond {
		t.Fatalf("expected interval 200ms, got %s", res.interval)
	}
	if res.jitter != 0 {
		t.Fatalf("expected zero jitter, got %s", res.jitter)
	}
}

func TestWindowStateDetectTimingPatternRejectsJitter(t *testing.T) {
	state := newWindowState(5*time.Second, time.Second)
	base := time.Unix(0, 0)

	cfg := patternSettings{
		enabled:        true,
		minOccurrences: 3,
		maxLookback:    5,
		maxJitter:      20 * time.Millisecond,
		relativeJitter: 0.05,
		minInterval:    0,
	}

	state.insert(base, "k", 2)
	state.insert(base.Add(200*time.Millisecond), "k", 2)
	state.insert(base.Add(400*time.Millisecond+75*time.Millisecond), "k", 2)

	if res := state.detectTimingPattern("k", cfg); res != nil {
		t.Fatalf("expected jitter to suppress detection, got %+v", res)
	}
}

func TestBucketValue(t *testing.T) {
	tick, _ := decimal.NewFromString("0.1")
	price, _ := decimal.NewFromString("123.456")
	bucket := bucketValue(price, tick)
	expected, _ := decimal.NewFromString("123.5")
	if !bucket.Equal(expected) {
		t.Fatalf("expected %s got %s", expected.String(), bucket.String())
	}
}

func TestDetectorBucketedModeKeying(t *testing.T) {
	cfg := config.ScreenerConfig{
		Windows:       []config.Duration{{Duration: time.Second}},
		DuplicateMode: config.DuplicateModeBucketed,
		MinDupes:      2,
		Cooldown:      config.Duration{Duration: time.Second},
		Bucket: config.BucketConfig{
			PriceTick: "0.5",
			SizeTick:  "0.1",
		},
	}

	det, err := New(cfg, nil, nil, zerolog.New(io.Discard))
	if err != nil {
		t.Fatalf("failed to create detector: %v", err)
	}

	price1 := decimal.RequireFromString("100.26")
	price2 := decimal.RequireFromString("100.74")
	size1 := decimal.RequireFromString("0.11")
	size2 := decimal.RequireFromString("0.1092")

	evt1 := trade.Event{InstType: "SPOT", InstID: "BTCUSDT", Side: "buy", Price: price1, Size: size1, Timestamp: time.Unix(0, 0)}
	evt2 := trade.Event{InstType: "SPOT", InstID: "BTCUSDT", Side: "buy", Price: price2, Size: size2, Timestamp: time.Unix(0, 0).Add(200 * time.Millisecond)}

	key1, err := det.keyFor(evt1)
	if err != nil {
		t.Fatalf("keyFor evt1 failed: %v", err)
	}
	key2, err := det.keyFor(evt2)
	if err != nil {
		t.Fatalf("keyFor evt2 failed: %v", err)
	}

	if key1 != key2 {
		t.Fatalf("expected equal keys for bucketed events, got %s and %s", key1, key2)
	}

	if !strings.Contains(key1, "100.5") {
		t.Fatalf("expected price bucket 100.5 in key %s", key1)
	}

	det.Process(evt1)
	det.Process(evt2)

	det.mu.Lock()
	state := det.states["BTCUSDT"][time.Second]
	det.mu.Unlock()

	if state == nil {
		t.Fatalf("expected state for BTCUSDT window")
	}

	bucket := state.buckets[key1]
	if bucket == nil || bucket.len() != 2 {
		t.Fatalf("expected bucket to contain 2 events, got %+v", bucket)
	}
}

func TestDetectorEmitsTimingPatternAlerts(t *testing.T) {
	cfg := config.ScreenerConfig{
		Windows:       []config.Duration{{Duration: time.Second}},
		DuplicateMode: config.DuplicateModeStrict,
		MinDupes:      2,
		Cooldown:      config.Duration{Duration: time.Second},
		Pattern: config.PatternConfig{
			MinOccurrences: 3,
			MaxLookback:    4,
			MaxJitter:      config.Duration{Duration: 50 * time.Millisecond},
			RelativeJitter: 0.05,
			MinInterval:    config.Duration{Duration: 50 * time.Millisecond},
		},
	}

	det, err := New(cfg, nil, nil, zerolog.New(io.Discard))
	if err != nil {
		t.Fatalf("failed to create detector: %v", err)
	}

	mock := &mockDispatcher{}
	det.alerts = mock

	price := decimal.RequireFromString("1")
	size := decimal.RequireFromString("1")
	base := time.Unix(0, 0)

	newEvent := func(ts time.Time) trade.Event {
		return trade.Event{
			InstType:  "SPOT",
			InstID:    "PATTERN",
			Side:      "buy",
			Price:     price,
			Size:      size,
			Timestamp: ts,
		}
	}

	det.Process(newEvent(base))
	det.Process(newEvent(base.Add(200 * time.Millisecond)))
	det.Process(newEvent(base.Add(400 * time.Millisecond)))

	if len(mock.alerts) != 2 {
		t.Fatalf("expected 2 alerts (duplicate + pattern), got %d", len(mock.alerts))
	}
	if mock.alerts[0].TimingPattern != nil {
		t.Fatalf("expected first alert to omit timing pattern")
	}
	if mock.alerts[1].TimingPattern == nil {
		t.Fatalf("expected second alert to include timing pattern")
	}
	if mock.alerts[1].TimingPattern.Interval != 200*time.Millisecond {
		t.Fatalf("expected interval 200ms, got %s", mock.alerts[1].TimingPattern.Interval)
	}
	if mock.alerts[1].TimingPattern.Samples != 3 {
		t.Fatalf("expected samples=3, got %d", mock.alerts[1].TimingPattern.Samples)
	}
	if mock.alerts[1].Count != 3 {
		t.Fatalf("expected alert count 3, got %d", mock.alerts[1].Count)
	}
	tag := mock.alerts[0].RobotTag
	if tag == "" {
		t.Fatalf("expected robot tag on first alert")
	}
	if mock.alerts[1].RobotTag != tag {
		t.Fatalf("expected matching robot tags, got %q and %q", tag, mock.alerts[1].RobotTag)
	}

	// Additional trade inside cooldown should not emit another pattern alert.
	det.Process(newEvent(base.Add(600 * time.Millisecond)))
	if len(mock.alerts) != 2 {
		t.Fatalf("expected pattern cooldown to suppress additional alerts, got %d", len(mock.alerts))
	}
}

func TestDetectorAssignsRobotTagsWithoutPattern(t *testing.T) {
	cfg := config.ScreenerConfig{
		Windows:       []config.Duration{{Duration: time.Second}},
		DuplicateMode: config.DuplicateModeStrict,
		MinDupes:      2,
		Cooldown:      config.Duration{Duration: time.Second},
		Pattern:       config.PatternConfig{},
	}

	det, err := New(cfg, nil, nil, zerolog.New(io.Discard))
	if err != nil {
		t.Fatalf("failed to create detector: %v", err)
	}

	mock := &mockDispatcher{}
	det.alerts = mock

	price := decimal.RequireFromString("2")
	size := decimal.RequireFromString("1")
	base := time.Unix(0, 0)

	evt := func(ts time.Time) trade.Event {
		return trade.Event{
			InstType:  "SPOT",
			InstID:    "TAGLESS",
			Side:      "sell",
			Price:     price,
			Size:      size,
			Timestamp: ts,
		}
	}

	det.Process(evt(base))
	det.Process(evt(base.Add(150 * time.Millisecond)))

	if len(mock.alerts) != 1 {
		t.Fatalf("expected single duplicate alert, got %d", len(mock.alerts))
	}
	if mock.alerts[0].RobotTag == "" {
		t.Fatalf("expected robot tag on duplicate alert")
	}
	if mock.alerts[0].TimingPattern != nil {
		t.Fatalf("expected no timing pattern for two events")
	}
}
