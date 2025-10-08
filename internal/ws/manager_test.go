package ws

import (
	"io"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/esshka/fp-scanner-go/internal/trade"
)

type collectingConsumer struct {
	events []trade.Event
}

func (c *collectingConsumer) Consume(evt trade.Event) {
	c.events = append(c.events, evt)
}

func TestHandleMessageTrade(t *testing.T) {
	consumer := &collectingConsumer{}
	worker := &connectionWorker{
		consumer: consumer,
		logger:   zerolog.New(io.Discard),
	}

	payload := []byte(`{"arg":{"instType":"SPOT","channel":"trade","instId":"BTCUSDT"},"data":[{"ts":"1712345678901","price":"12345.67","size":"0.10","side":"buy","tradeId":"abc"}]}`)

	if err := worker.handleMessage(payload); err != nil {
		t.Fatalf("handleMessage returned error: %v", err)
	}

	if len(consumer.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(consumer.events))
	}

	evt := consumer.events[0]
	if evt.InstID != "BTCUSDT" {
		t.Fatalf("expected instId BTCUSDT, got %s", evt.InstID)
	}
	if evt.InstType != "SPOT" {
		t.Fatalf("expected instType SPOT, got %s", evt.InstType)
	}
	if evt.TradeID != "abc" {
		t.Fatalf("expected tradeId abc, got %s", evt.TradeID)
	}
	if evt.Side != "buy" {
		t.Fatalf("expected side buy, got %s", evt.Side)
	}

	want := time.UnixMilli(1712345678901).UTC()
	if !evt.Timestamp.Equal(want) {
		t.Fatalf("timestamp mismatch, want %s got %s", want, evt.Timestamp)
	}

	if evt.ReceivedAt.IsZero() {
		t.Fatalf("expected ReceivedAt to be set")
	}
}

func TestHandleMessageIgnoresNonTrade(t *testing.T) {
	consumer := &collectingConsumer{}
	worker := &connectionWorker{
		consumer: consumer,
		logger:   zerolog.New(io.Discard),
	}

	payload := []byte(`{"arg":{"instType":"SPOT","channel":"books","instId":"BTCUSDT"},"data":[{"ts":"1712345678901","price":"12345.67","size":"0.10","side":"buy","tradeId":"abc"}]}`)

	if err := worker.handleMessage(payload); err != nil {
		t.Fatalf("handleMessage returned error: %v", err)
	}

	if len(consumer.events) != 0 {
		t.Fatalf("expected no events for non-trade channel, got %d", len(consumer.events))
	}
}
