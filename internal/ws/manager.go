package ws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	backoff "github.com/cenkalti/backoff/v4"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	"github.com/esshka/fp-scanner-go/internal/config"
	"github.com/esshka/fp-scanner-go/internal/metrics"
	"github.com/esshka/fp-scanner-go/internal/rest"
	"github.com/esshka/fp-scanner-go/internal/trade"
)

// Manager owns websocket connections and fan-out of trade messages.
type Manager struct {
	cfg         config.WebsocketConfig
	instruments []config.Instrument
	consumer    trade.Consumer
	warm        *rest.WarmStarter
	metrics     *metrics.Collector
	logger      zerolog.Logger
}

// NewManager builds a websocket connection manager.
func NewManager(cfg config.WebsocketConfig, instruments []config.Instrument, consumer trade.Consumer, warm *rest.WarmStarter, collector *metrics.Collector, logger zerolog.Logger) *Manager {
	return &Manager{
		cfg:         cfg,
		instruments: instruments,
		consumer:    consumer,
		warm:        warm,
		metrics:     collector,
		logger:      logger,
	}
}

// Run spawns websocket workers and blocks until the context is cancelled or a
// fatal error occurs.
func (m *Manager) Run(ctx context.Context) error {
	if len(m.instruments) == 0 {
		return errors.New("ws manager: no instruments configured")
	}

	batches := partition(m.instruments, m.cfg.BatchSize)
	g, ctx := errgroup.WithContext(ctx)

	for idx, batch := range batches {
		worker := newConnectionWorker(idx, m.cfg, batch, m.consumer, m.warm, m.metrics, m.logger.With().Int("conn", idx).Int("batchSize", len(batch)).Logger())
		g.Go(func() error {
			return worker.run(ctx)
		})
	}

	return g.Wait()
}

func partition(instruments []config.Instrument, batchSize int) [][]config.Instrument {
	if batchSize <= 0 {
		batchSize = len(instruments)
	}
	max := int(math.Max(1, float64(batchSize)))

	var batches [][]config.Instrument
	for i := 0; i < len(instruments); i += max {
		end := i + max
		if end > len(instruments) {
			end = len(instruments)
		}
		batch := make([]config.Instrument, end-i)
		copy(batch, instruments[i:end])
		batches = append(batches, batch)
	}
	return batches
}

// -----------------------------------------------------------------------------
// connection worker

type connectionWorker struct {
	id          int
	cfg         config.WebsocketConfig
	instruments []config.Instrument
	consumer    trade.Consumer
	warm        *rest.WarmStarter
	metrics     *metrics.Collector
	logger      zerolog.Logger
	limiter     *rate.Limiter
}

func newConnectionWorker(id int, cfg config.WebsocketConfig, instruments []config.Instrument, consumer trade.Consumer, warm *rest.WarmStarter, collector *metrics.Collector, logger zerolog.Logger) *connectionWorker {
	limiter := rate.NewLimiter(rate.Inf, 1)
	if cfg.MaxMessagesPerSec > 0 {
		limiter = rate.NewLimiter(rate.Limit(cfg.MaxMessagesPerSec), cfg.MaxMessagesPerSec)
	}
	return &connectionWorker{
		id:          id,
		cfg:         cfg,
		instruments: instruments,
		consumer:    consumer,
		warm:        warm,
		metrics:     collector,
		logger:      logger,
		limiter:     limiter,
	}
}

func (w *connectionWorker) run(ctx context.Context) error {
	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = w.cfg.Backoff.Initial.OrDefault(time.Second)
	bo.Multiplier = w.cfg.Backoff.Multiplier
	bo.MaxInterval = w.cfg.Backoff.Max.OrDefault(30 * time.Second)
	bo.RandomizationFactor = w.cfg.Backoff.Jitter
	bo.MaxElapsedTime = 0 // retry indefinitely

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if err := w.connectAndRun(ctx); err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}
			wait := bo.NextBackOff()
			if wait < 0 {
				wait = w.cfg.Backoff.Max.OrDefault(30 * time.Second)
			}
			w.logger.Warn().Err(err).Dur("backoff", wait).Msg("connection loop retry")
			if w.metrics != nil {
				w.metrics.IncWSReconnect()
			}
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return ctx.Err()
			}
			continue
		}

		bo.Reset()
	}
}

func (w *connectionWorker) connectAndRun(ctx context.Context) error {
	dialer := websocket.Dialer{
		Proxy:            httpProxyFromEnv,
		HandshakeTimeout: w.cfg.HandshakeTimeout.OrDefault(15 * time.Second),
		ReadBufferSize:   w.cfg.ReadBufferBytes,
		WriteBufferSize:  w.cfg.WriteBufferBytes,
	}

	conn, resp, err := dialer.DialContext(ctx, w.cfg.URL, nil)
	if resp != nil {
		resp.Body.Close()
	}
	if err != nil {
		return err
	}
	defer conn.Close()

	conn.EnableWriteCompression(false)

	if w.metrics != nil {
		w.metrics.AddWSConnection(1)
	}
	defer func() {
		if w.metrics != nil {
			w.metrics.AddWSConnection(-1)
		}
	}()

	pingInterval := w.cfg.PingInterval.OrDefault(30 * time.Second)
	writeTimeout := w.cfg.MessageWriteTimeout.OrDefault(5 * time.Second)

	var pingMu sync.Mutex
	var lastPing time.Time

	conn.SetPongHandler(func(string) error {
		pingMu.Lock()
		sent := lastPing
		pingMu.Unlock()
		if !sent.IsZero() && w.metrics != nil {
			w.metrics.ObservePingPong(time.Since(sent))
		}
		conn.SetReadDeadline(time.Now().Add(pingInterval * 2))
		return nil
	})

	readErr := make(chan error, 1)
	go func() {
		readErr <- w.readLoop(ctx, conn, pingInterval, &pingMu, &lastPing)
	}()

	pingErr := make(chan error, 1)
	go func() {
		pingErr <- w.pingLoop(ctx, conn, pingInterval, writeTimeout, &pingMu, &lastPing)
	}()

	if err := w.subscribe(ctx, conn); err != nil {
		return err
	}

	if w.warm != nil {
		w.logger.Info().Msg("starting warm-start recovery")
		w.warm.Warm(ctx, w.instruments, w.consumer)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-readErr:
			if err != nil {
				return err
			}
			return nil
		case err := <-pingErr:
			if err != nil {
				return err
			}
			// ping loop ended gracefully; keep waiting for read loop.
			pingErr = nil
		}
	}
}

func (w *connectionWorker) readLoop(ctx context.Context, conn *websocket.Conn, pingInterval time.Duration, pingMu *sync.Mutex, lastPing *time.Time) error {
	defer conn.SetReadDeadline(time.Time{})

	for {
		if ctx.Err() != nil {
			return nil
		}
		conn.SetReadDeadline(time.Now().Add(pingInterval * 2))
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			return err
		}

		if msgType != websocket.TextMessage && msgType != websocket.BinaryMessage {
			continue
		}

		if w.metrics != nil {
			w.metrics.IncWSMessages(1)
		}

		trimmed := bytes.TrimSpace(payload)
		if bytes.Equal(trimmed, []byte("pong")) {
			pingMu.Lock()
			sent := *lastPing
			pingMu.Unlock()
			if !sent.IsZero() && w.metrics != nil {
				w.metrics.ObservePingPong(time.Since(sent))
			}
			continue
		}
		if bytes.Equal(trimmed, []byte("ping")) {
			// respond to server-side ping messages
			if err := w.waitSend(ctx); err != nil {
				return err
			}
			deadline := time.Now().Add(w.cfg.MessageWriteTimeout.OrDefault(5 * time.Second))
			conn.SetWriteDeadline(deadline)
			if err := conn.WriteMessage(websocket.TextMessage, []byte("pong")); err != nil {
				return err
			}
			continue
		}

		if err := w.handleMessage(trimmed); err != nil {
			if w.metrics != nil {
				w.metrics.IncParseError()
			}
			w.logger.Warn().Err(err).Msg("failed to handle message")
		}
	}
}

func (w *connectionWorker) handleMessage(payload []byte) error {
	if len(payload) == 0 {
		return nil
	}

	var envelope messageEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}

	if envelope.Event != "" {
		if envelope.Event == "error" {
			return fmt.Errorf("bitget error: code=%s msg=%s", envelope.Code, envelope.Msg)
		}
		w.logger.Debug().Str("event", envelope.Event).Interface("arg", envelope.Arg).Msg("control event")
		return nil
	}

	if envelope.Op != "" {
		// Response to operations such as subscribe.
		w.logger.Debug().Str("op", envelope.Op).Str("code", envelope.Code).Msg("op response")
		return nil
	}

	if len(envelope.Data) == 0 {
		return nil
	}

	if !strings.EqualFold(envelope.Arg.Channel, "trade") {
		return nil
	}

	for _, item := range envelope.Data {
		ts, err := trade.ParseMillis(item.Timestamp)
		if err != nil {
			return fmt.Errorf("parse ts: %w", err)
		}
		price, err := trade.ParseDecimal(item.Price)
		if err != nil {
			return fmt.Errorf("parse price: %w", err)
		}
		size, err := trade.ParseDecimal(item.Size)
		if err != nil {
			return fmt.Errorf("parse size: %w", err)
		}

		evt := trade.Event{
			Exchange:   "bitget",
			InstType:   envelope.Arg.InstType,
			InstID:     envelope.Arg.InstID,
			Timestamp:  ts,
			Price:      price,
			Size:       size,
			Side:       strings.ToLower(item.Side),
			TradeID:    item.TradeID,
			ReceivedAt: time.Now().UTC(),
		}
		if w.consumer != nil {
			w.consumer.Consume(evt)
		}
	}

	return nil
}

func (w *connectionWorker) pingLoop(ctx context.Context, conn *websocket.Conn, interval, writeTimeout time.Duration, mu *sync.Mutex, lastPing *time.Time) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := w.waitSend(ctx); err != nil {
				return err
			}
			deadline := time.Now().Add(writeTimeout)
			conn.SetWriteDeadline(deadline)
			mu.Lock()
			*lastPing = time.Now()
			mu.Unlock()
			if err := conn.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
				return err
			}
		}
	}
}

func (w *connectionWorker) subscribe(ctx context.Context, conn *websocket.Conn) error {
	chunk := w.cfg.SubscribeChunk
	if chunk <= 0 {
		chunk = len(w.instruments)
	}
	delay := w.cfg.SubscribeInterval.OrDefault(300 * time.Millisecond)

	for start := 0; start < len(w.instruments); start += chunk {
		end := start + chunk
		if end > len(w.instruments) {
			end = len(w.instruments)
		}
		args := make([]subscribeArg, 0, end-start)
		for _, inst := range w.instruments[start:end] {
			args = append(args, subscribeArg{
				InstType: inst.InstType,
				Channel:  "trade",
				InstID:   inst.InstID,
			})
		}
		payload := subscribeMessage{Op: "subscribe", Args: args}
		if err := w.writeJSON(ctx, conn, payload); err != nil {
			return err
		}

		if delay > 0 && end < len(w.instruments) {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
	}

	w.logger.Info().Int("subscriptions", len(w.instruments)).Msg("subscriptions completed")
	return nil
}

func (w *connectionWorker) writeJSON(ctx context.Context, conn *websocket.Conn, payload interface{}) error {
	if err := w.waitSend(ctx); err != nil {
		return err
	}
	deadline := time.Now().Add(w.cfg.MessageWriteTimeout.OrDefault(5 * time.Second))
	conn.SetWriteDeadline(deadline)
	return conn.WriteJSON(payload)
}

func (w *connectionWorker) waitSend(ctx context.Context) error {
	if w.limiter == nil {
		return nil
	}
	if err := w.limiter.Wait(ctx); err != nil {
		if w.metrics != nil {
			w.metrics.IncRateLimitBackoff()
		}
		return err
	}
	return nil
}

// -----------------------------------------------------------------------------
// Helpers & types

type subscribeMessage struct {
	Op   string         `json:"op"`
	Args []subscribeArg `json:"args"`
}

type subscribeArg struct {
	InstType string `json:"instType"`
	Channel  string `json:"channel"`
	InstID   string `json:"instId"`
}

type messageEnvelope struct {
	Event  string        `json:"event"`
	Op     string        `json:"op"`
	Code   string        `json:"code"`
	Msg    string        `json:"msg"`
	Arg    envelopeArg   `json:"arg"`
	Action string        `json:"action"`
	Data   []tradeRecord `json:"data"`
}

type envelopeArg struct {
	InstType string `json:"instType"`
	Channel  string `json:"channel"`
	InstID   string `json:"instId"`
}

type tradeRecord struct {
	Timestamp string `json:"ts"`
	Price     string `json:"price"`
	Size      string `json:"size"`
	Side      string `json:"side"`
	TradeID   string `json:"tradeId"`
}

// httpProxyFromEnv defers to environment proxy configuration. websocket.Dialer
// expects a function; we reuse the default http proxy settings.
func httpProxyFromEnv(req *http.Request) (*url.URL, error) {
	return http.ProxyFromEnvironment(req)
}
