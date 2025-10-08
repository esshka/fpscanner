package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"golang.org/x/time/rate"

	"github.com/esshka/fp-scanner-go/internal/config"
	"github.com/esshka/fp-scanner-go/internal/metrics"
	"github.com/esshka/fp-scanner-go/internal/trade"
)

// WarmStarter optionally recovers missed trades via REST.
type WarmStarter struct {
	cfg     config.WarmStartConfig
	metrics *metrics.Collector
	logger  zerolog.Logger
	client  *http.Client
	limiter *rate.Limiter
	enabled bool
}

// NewWarmStarter constructs a warm starter helper. When warm start is disabled
// the returned instance performs no work.
func NewWarmStarter(cfg config.WarmStartConfig, collector *metrics.Collector, logger zerolog.Logger) *WarmStarter {
	if !cfg.Enable {
		return &WarmStarter{enabled: false}
	}

	starter := &WarmStarter{
		cfg:     cfg,
		metrics: collector,
		logger:  logger,
		client:  &http.Client{Timeout: 5 * time.Second},
		enabled: true,
	}

	if cfg.MaxRequestsPerSecond > 0 {
		burst := int(math.Ceil(cfg.MaxRequestsPerSecond))
		if burst < 1 {
			burst = 1
		}
		starter.limiter = rate.NewLimiter(rate.Limit(cfg.MaxRequestsPerSecond), burst)
	} else {
		starter.limiter = rate.NewLimiter(rate.Inf, 1)
	}

	return starter
}

// Warm fetches recent trades for the provided instruments and replays them to
// the consumer. Errors are logged but otherwise ignored to avoid impacting the
// hot path.
func (w *WarmStarter) Warm(ctx context.Context, instruments []config.Instrument, consumer trade.Consumer) {
	if !w.enabled || consumer == nil {
		return
	}

	cutoff := time.Now().Add(-w.cfg.Lookback.OrDefault(3 * time.Second))

	for _, inst := range instruments {
		if err := w.wait(ctx); err != nil {
			w.logger.Warn().Str("instId", inst.InstID).Msg("warm start aborted due to context cancellation")
			return
		}

		events, err := w.fetch(ctx, inst)
		if err != nil {
			w.logger.Warn().Err(err).Str("instId", inst.InstID).Msg("warm start fetch failed")
			continue
		}

		if w.metrics != nil {
			w.metrics.IncRestCall()
		}

		sort.Slice(events, func(i, j int) bool { return events[i].Timestamp.Before(events[j].Timestamp) })

		for _, evt := range events {
			if evt.Timestamp.Before(cutoff) {
				continue
			}
			consumer.Consume(evt)
		}
	}
}

func (w *WarmStarter) wait(ctx context.Context) error {
	if w.limiter == nil {
		return nil
	}
	return w.limiter.Wait(ctx)
}

func (w *WarmStarter) fetch(ctx context.Context, inst config.Instrument) ([]trade.Event, error) {
	endpoint := fmt.Sprintf("%s%s", strings.TrimRight(w.cfg.BaseURL, "/"), w.cfg.RestEndpoint)
	values := url.Values{}
	values.Set("symbol", inst.InstID)
	values.Set("limit", "100")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"?"+values.Encode(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	var payload restResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}

	events := make([]trade.Event, 0, len(payload.Data))
	for _, item := range payload.Data {
		ts, err := trade.ParseMillis(item.Timestamp)
		if err != nil {
			if w.metrics != nil {
				w.metrics.IncParseError()
			}
			continue
		}
		price, err := trade.ParseDecimal(item.Price)
		if err != nil {
			if w.metrics != nil {
				w.metrics.IncParseError()
			}
			continue
		}
		size, err := trade.ParseDecimal(item.Size)
		if err != nil {
			if w.metrics != nil {
				w.metrics.IncParseError()
			}
			continue
		}

		events = append(events, trade.Event{
			Exchange:   "bitget",
			InstType:   inst.InstType,
			InstID:     inst.InstID,
			Timestamp:  ts,
			Price:      price,
			Size:       size,
			Side:       item.Side,
			TradeID:    item.TradeID,
			ReceivedAt: time.Now().UTC(),
		})
	}

	return events, nil
}

type restResponse struct {
	Data []restTrade `json:"data"`
}

type restTrade struct {
	TradeID   string `json:"tradeId"`
	Price     string `json:"price"`
	Size      string `json:"size"`
	Side      string `json:"side"`
	Timestamp string `json:"ts"`
}
