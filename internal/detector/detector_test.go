package detector

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/shopspring/decimal"

	"github.com/esshka/fp-scanner-go/internal/config"
	"github.com/esshka/fp-scanner-go/internal/trade"
)

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
