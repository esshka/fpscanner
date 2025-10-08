package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/zerolog"

	"github.com/esshka/fp-scanner-go/internal/config"
	"github.com/esshka/fp-scanner-go/internal/metrics"
)

// Alert represents an actionable duplicate detection event.
type Alert struct {
	InstType      string               `json:"instType"`
	InstID        string               `json:"instId"`
	Window        time.Duration        `json:"windowSec"`
	DuplicateMode config.DuplicateMode `json:"duplicateMode"`
	Key           string               `json:"key"`
	Count         int                  `json:"count"`
	FirstSeen     time.Time            `json:"firstSeen"`
	LastSeen      time.Time            `json:"lastSeen"`
}

// Sink delivers alerts to downstream systems.
type Sink interface {
	Name() string
	Send(ctx context.Context, alert Alert) error
}

// Starter is implemented by sinks that require their own goroutine (e.g. a
// terminal UI). The router invokes Start with the same context it uses for
// workers, and stops the sink when that context is cancelled.
type Starter interface {
	Start(ctx context.Context) error
}

// Router keeps fan-out logic for alerts.
type Router struct {
	logger  zerolog.Logger
	metrics *metrics.Collector
	sinks   []Sink
	alerts  chan Alert
	timeout time.Duration
}

const (
	defaultBufferSize = 1024
	workerCount       = 3
)

// NewRouter configures sinks based on the provided alert configuration.
func NewRouter(cfg config.AlertConfig, logger zerolog.Logger, collector *metrics.Collector) (*Router, error) {
	timeout := cfg.Timeout.OrDefault(5 * time.Second)

	var sinks []Sink
	if cfg.Console {
		sinks = append(sinks, &consoleSink{logger: logger})
	}
	if cfg.Table {
		sinks = append(sinks, newTableSink(cfg.TableRetention.OrDefault(15*time.Minute)))
	}
	for i, url := range cfg.Webhooks {
		sinks = append(sinks, newWebhookSink(url, cfg, logger.With().Str("sink", "webhook").Int("index", i).Logger()))
	}
	if cfg.SlackWebhook != "" {
		sinks = append(sinks, newWebhookSink(cfg.SlackWebhook, cfg, logger.With().Str("sink", "slackWebhook").Logger()))
	}
	if len(sinks) == 0 {
		sinks = append(sinks, &consoleSink{logger: logger})
	}

	return &Router{
		logger:  logger,
		metrics: collector,
		sinks:   sinks,
		alerts:  make(chan Alert, defaultBufferSize),
		timeout: timeout,
	}, nil
}

// Dispatch forwards an alert to the router. Drops alerts when the buffer is
// exhausted to avoid blocking the ingestion hot-path.
func (r *Router) Dispatch(alert Alert) {
	select {
	case r.alerts <- alert:
	default:
		r.logger.Warn().Str("instId", alert.InstID).Float64("windowSec", alert.Window.Seconds()).Msg("dropping alert due to backpressure")
		if r.metrics != nil {
			r.metrics.IncDrop()
		}
	}
}

// Run processes alerts until the context is cancelled.
func (r *Router) Run(parent context.Context) {
	runCtx, cancel := context.WithCancel(parent)
	defer cancel()

	errCh := make(chan error, len(r.sinks))

	var starterWG sync.WaitGroup
	for _, sink := range r.sinks {
		if starter, ok := sink.(Starter); ok {
			starterWG.Add(1)
			go func(st Starter) {
				defer starterWG.Done()
				if err := st.Start(runCtx); err != nil && !errors.Is(err, context.Canceled) {
					select {
					case errCh <- err:
					default:
					}
				}
			}(starter)
		}
	}

	var workerWG sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		workerWG.Add(1)
		go func() {
			defer workerWG.Done()
			r.worker(runCtx)
		}()
	}

	select {
	case <-runCtx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) {
			r.logger.Error().Err(err).Msg("alert sink terminated")
		}
		cancel()
	}

	workerWG.Wait()
	cancel()
	starterWG.Wait()
}

func (r *Router) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case alert := <-r.alerts:
			r.deliver(ctx, alert)
		}
	}
}

func (r *Router) deliver(ctx context.Context, alert Alert) {
	if r.metrics != nil {
		r.metrics.IncAlert(alert.Window)
	}
	for _, sink := range r.sinks {
		sctx, cancel := context.WithTimeout(ctx, r.timeout)
		if err := sink.Send(sctx, alert); err != nil {
			r.logger.Error().Err(err).Str("sink", sink.Name()).Str("instId", alert.InstID).Msg("alert delivery failed")
		}
		cancel()
	}
}

// consoleSink logs alerts locally.
type consoleSink struct {
	logger zerolog.Logger
}

func (c *consoleSink) Name() string { return "console" }

func (c *consoleSink) Send(_ context.Context, alert Alert) error {
	c.logger.Info().
		Str("sink", c.Name()).
		Str("instId", alert.InstID).
		Str("instType", alert.InstType).
		Float64("windowSec", alert.Window.Seconds()).
		Str("mode", string(alert.DuplicateMode)).
		Int("count", alert.Count).
		Str("key", alert.Key).
		Time("firstSeen", alert.FirstSeen).
		Time("lastSeen", alert.LastSeen).
		Msg("duplicate detected")
	return nil
}

// webhookSink posts alerts to an HTTP endpoint.
type webhookSink struct {
	client *retryablehttp.Client
	url    string
	name   string
	logger zerolog.Logger
}

func newWebhookSink(url string, cfg config.AlertConfig, logger zerolog.Logger) *webhookSink {
	client := retryablehttp.NewClient()
	client.Logger = nil
	client.RetryMax = 5
	client.RetryWaitMin = cfg.Retry.Initial.OrDefault(time.Second)
	client.RetryWaitMax = cfg.Retry.Max.OrDefault(30 * time.Second)
	client.Backoff = retryablehttp.DefaultBackoff

	return &webhookSink{
		client: client,
		url:    url,
		name:   "webhook",
		logger: logger,
	}
}

func (w *webhookSink) Name() string { return w.name }

func (w *webhookSink) Send(ctx context.Context, alert Alert) error {
	payload := struct {
		Alert
		EmittedAt time.Time `json:"emittedAt"`
	}{Alert: alert, EmittedAt: time.Now().UTC()}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := retryablehttp.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return &httpError{StatusCode: resp.StatusCode}
	}
	return nil
}

type httpError struct {
	StatusCode int
}

func (e *httpError) Error() string {
	return http.StatusText(e.StatusCode)
}
