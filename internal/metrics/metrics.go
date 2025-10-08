package metrics

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
)

// Collector wraps Prometheus metrics used by the screener.
type Collector struct {
	registry *prometheus.Registry

	wsConnections     prometheus.Gauge
	wsReconnects      prometheus.Counter
	wsForcedRotations prometheus.Counter
	pingPongLatency   prometheus.Histogram
	wsMessagesIn      prometheus.Counter
	tradesInTotal     *prometheus.CounterVec
	windowEvents      *prometheus.CounterVec
	duplicateKeys     *prometheus.CounterVec
	alertsEmitted     *prometheus.CounterVec
	lastTradeAge      *prometheus.GaugeVec
	restCalls         prometheus.Counter
	restThrottled     prometheus.Counter
	parseErrors       prometheus.Counter
	drops             prometheus.Counter
	rateLimitBackoffs prometheus.Counter
}

// NewCollector initialises and registers all metrics.
func NewCollector() *Collector {
	reg := prometheus.NewRegistry()

	c := &Collector{
		registry: reg,
		wsConnections: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "fp_scanner",
			Name:      "ws_connections_open",
			Help:      "Number of active websocket connections.",
		}),
		wsReconnects: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "fp_scanner",
			Name:      "ws_reconnects_total",
			Help:      "Total websocket reconnect attempts.",
		}),
		wsForcedRotations: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "fp_scanner",
			Name:      "ws_forced_rotations_total",
			Help:      "Total websocket reconnects triggered by forced rotation.",
		}),
		pingPongLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: "fp_scanner",
			Name:      "ping_pong_latency_seconds",
			Help:      "Latency between ping and pong frames.",
			Buckets:   prometheus.ExponentialBuckets(0.01, 2, 12),
		}),
		wsMessagesIn: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "fp_scanner",
			Name:      "ws_messages_in_total",
			Help:      "Total websocket messages received.",
		}),
		tradesInTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "fp_scanner",
			Name:      "trades_in_total",
			Help:      "Total trades ingested per instrument.",
		}, []string{"inst_id"}),
		windowEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "fp_scanner",
			Name:      "window_events_total",
			Help:      "Events processed per instrument and window.",
		}, []string{"inst_id", "window"}),
		duplicateKeys: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "fp_scanner",
			Name:      "duplicate_keys_total",
			Help:      "Number of duplicate keys detected per window.",
		}, []string{"window"}),
		alertsEmitted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "fp_scanner",
			Name:      "alerts_emitted_total",
			Help:      "Alerts emitted per window.",
		}, []string{"window"}),
		lastTradeAge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "fp_scanner",
			Name:      "last_trade_age_seconds",
			Help:      "Seconds since the last trade was observed per instrument.",
		}, []string{"inst_id"}),
		restCalls: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "fp_scanner",
			Name:      "rest_calls_total",
			Help:      "REST warm-start calls made.",
		}),
		restThrottled: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "fp_scanner",
			Name:      "rest_throttled_total",
			Help:      "REST warm-start calls skipped due to rate limiting.",
		}),
		parseErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "fp_scanner",
			Name:      "parse_errors_total",
			Help:      "Total payload parse errors.",
		}),
		drops: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "fp_scanner",
			Name:      "drops_total",
			Help:      "Total dropped messages due to overload or parsing failures.",
		}),
		rateLimitBackoffs: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "fp_scanner",
			Name:      "rate_limit_backoffs_total",
			Help:      "Total rate-limit backoff events triggered on outbound traffic.",
		}),
	}

	reg.MustRegister(
		c.wsConnections,
		c.wsReconnects,
		c.wsForcedRotations,
		c.pingPongLatency,
		c.wsMessagesIn,
		c.tradesInTotal,
		c.windowEvents,
		c.duplicateKeys,
		c.alertsEmitted,
		c.lastTradeAge,
		c.restCalls,
		c.restThrottled,
		c.parseErrors,
		c.drops,
		c.rateLimitBackoffs,
	)

	return c
}

func windowLabel(d time.Duration) string {
	return fmt.Sprintf("%ds", int(d.Seconds()))
}

// Registry returns the underlying Prometheus registry.
func (c *Collector) Registry() *prometheus.Registry {
	return c.registry
}

// StartServer exposes Prometheus metrics on the configured address.
func (c *Collector) StartServer(ctx context.Context, addr string, logger zerolog.Logger) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(c.registry, promhttp.HandlerOpts{}))

	srv := &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	done := make(chan struct{})
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Warn().Err(err).Msg("metrics server shutdown failed")
		}
		close(done)
	}()

	logger.Info().Str("addr", addr).Msg("starting metrics endpoint")
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("metrics server failed: %w", err)
	}
	<-done
	return nil
}

// Update helper methods ----------------------------------------------------

// AddWSConnection increments/decrements the number of open websocket connections.
func (c *Collector) AddWSConnection(delta float64) {
	c.wsConnections.Add(delta)
}

// IncWSReconnect records a reconnect attempt.
func (c *Collector) IncWSReconnect() {
	c.wsReconnects.Inc()
}

// IncForcedRotation increments the forced rotation counter.
func (c *Collector) IncForcedRotation() {
	c.wsForcedRotations.Inc()
}

// ObservePingPong records ping/pong latency.
func (c *Collector) ObservePingPong(latency time.Duration) {
	c.pingPongLatency.Observe(latency.Seconds())
}

// IncWSMessages increments received websocket messages.
func (c *Collector) IncWSMessages(count int) {
	c.wsMessagesIn.Add(float64(count))
}

// IncTrades increments the trade counter for a specific instrument.
func (c *Collector) IncTrades(instID string, count int) {
	c.tradesInTotal.WithLabelValues(instID).Add(float64(count))
}

// ObserveWindowEvent increments the per-window event counter.
func (c *Collector) ObserveWindowEvent(instID string, window time.Duration) {
	c.windowEvents.WithLabelValues(instID, windowLabel(window)).Inc()
}

// IncDuplicateKey increments the duplicate key counter for a window.
func (c *Collector) IncDuplicateKey(window time.Duration) {
	c.duplicateKeys.WithLabelValues(windowLabel(window)).Inc()
}

// IncAlert increments the alerts emitted counter.
func (c *Collector) IncAlert(window time.Duration) {
	c.alertsEmitted.WithLabelValues(windowLabel(window)).Inc()
}

// SetLastTradeAge sets the last trade age gauge for an instrument.
func (c *Collector) SetLastTradeAge(instID string, age time.Duration) {
	c.lastTradeAge.WithLabelValues(instID).Set(age.Seconds())
}

// IncRestCall increments the REST call count.
func (c *Collector) IncRestCall() {
	c.restCalls.Inc()
}

// IncRestThrottled increments the throttled REST counter.
func (c *Collector) IncRestThrottled() {
	c.restThrottled.Inc()
}

// IncParseError increments the parse error counter.
func (c *Collector) IncParseError() {
	c.parseErrors.Inc()
}

// IncDrop increments the drop counter.
func (c *Collector) IncDrop() {
	c.drops.Inc()
}

// IncRateLimitBackoff increments an outbound rate-limit backoff observation.
func (c *Collector) IncRateLimitBackoff() {
	c.rateLimitBackoffs.Inc()
}
