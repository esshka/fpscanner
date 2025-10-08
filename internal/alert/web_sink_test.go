package alert

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/esshka/fp-scanner-go/internal/config"
)

func TestWebSinkDeduplicatesWindows(t *testing.T) {
	sink := newWebSink(":0", time.Minute, zerolog.New(io.Discard))

	alert := Alert{
		InstType:      "SPOT",
		InstID:        "BTCUSDT",
		Window:        30 * time.Second,
		DuplicateMode: config.DuplicateModeStrict,
		Key:           "100|10|buy",
		Count:         2,
		FirstSeen:     time.Unix(0, 0),
		LastSeen:      time.Unix(1, 0),
		RobotTag:      "RB-001",
	}

	if err := sink.Send(context.Background(), alert); err != nil {
		t.Fatalf("first send failed: %v", err)
	}

	alert.Window = 15 * time.Second
	if err := sink.Send(context.Background(), alert); err != nil {
		t.Fatalf("second send failed: %v", err)
	}

	sink.mu.RLock()
	defer sink.mu.RUnlock()
	stats := sink.stats["RB-001"]
	if stats == nil {
		t.Fatalf("expected stats for RB-001")
	}
	if stats.alerts != 1 {
		t.Fatalf("expected 1 alert, got %d", stats.alerts)
	}
	if len(stats.windows) != 2 {
		t.Fatalf("expected 2 windows, got %d", len(stats.windows))
	}
}
