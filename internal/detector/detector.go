package detector

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"github.com/shopspring/decimal"

	"github.com/esshka/fp-scanner-go/internal/alert"
	"github.com/esshka/fp-scanner-go/internal/config"
	"github.com/esshka/fp-scanner-go/internal/metrics"
	"github.com/esshka/fp-scanner-go/internal/trade"
)

// Detector performs sliding window duplicate detection and emits alerts.
type Detector struct {
	logger  zerolog.Logger
	metrics *metrics.Collector
	alerts  *alert.Router

	mode       config.DuplicateMode
	minDupes   int
	windows    []time.Duration
	cooldown   time.Duration
	priceTick  decimal.Decimal
	sizeTick   decimal.Decimal
	useBuckets bool

	mu     sync.Mutex
	states map[string]map[time.Duration]*windowState // instId -> window -> state
}

// New creates a detector from configuration.
func New(cfg config.ScreenerConfig, alerts *alert.Router, collector *metrics.Collector, logger zerolog.Logger) (*Detector, error) {
	d := &Detector{
		logger:   logger,
		metrics:  collector,
		alerts:   alerts,
		mode:     cfg.DuplicateMode,
		minDupes: cfg.MinDupes,
		cooldown: cfg.Cooldown.OrDefault(60 * time.Second),
		states:   make(map[string]map[time.Duration]*windowState),
	}

	if len(cfg.Windows) == 0 {
		return nil, fmt.Errorf("detector: no windows configured")
	}

	d.windows = make([]time.Duration, len(cfg.Windows))
	for i, w := range cfg.Windows {
		d.windows[i] = w.OrDefault(0)
		if d.windows[i] <= 0 {
			return nil, fmt.Errorf("detector: invalid window duration %d", i)
		}
	}

	if d.mode == config.DuplicateModeBucketed {
		priceTick, err := parseTick(cfg.Bucket.PriceTick)
		if err != nil {
			return nil, fmt.Errorf("detector: invalid price tick: %w", err)
		}
		sizeTick, err := parseTick(cfg.Bucket.SizeTick)
		if err != nil {
			return nil, fmt.Errorf("detector: invalid size tick: %w", err)
		}
		d.priceTick = priceTick
		d.sizeTick = sizeTick
		d.useBuckets = true
	}

	return d, nil
}

func parseTick(value string) (decimal.Decimal, error) {
	if strings.TrimSpace(value) == "" {
		return decimal.Decimal{}, fmt.Errorf("empty tick")
	}
	tick, err := decimal.NewFromString(value)
	if err != nil {
		return decimal.Decimal{}, err
	}
	if tick.LessThanOrEqual(decimal.Zero) {
		return decimal.Decimal{}, fmt.Errorf("tick must be positive")
	}
	return tick, nil
}

// Process ingests a trade event, updates sliding windows, and issues alerts when
// duplicates meet the threshold.
func (d *Detector) Process(evt trade.Event) {
	key, err := d.keyFor(evt)
	if err != nil {
		d.logger.Error().Err(err).Str("instId", evt.InstID).Msg("failed to compute duplicate key")
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	perWindow, ok := d.states[evt.InstID]
	if !ok {
		perWindow = make(map[time.Duration]*windowState, len(d.windows))
		d.states[evt.InstID] = perWindow
	}

	for _, window := range d.windows {
		state, ok := perWindow[window]
		if !ok {
			state = newWindowState(window, d.cooldown)
			perWindow[window] = state
		}
		shouldAlert, count, firstSeen := state.insert(evt.Timestamp, key, d.minDupes)

		if d.metrics != nil {
			d.metrics.ObserveWindowEvent(evt.InstID, window)
		}

		if shouldAlert {
			if d.metrics != nil {
				d.metrics.IncDuplicateKey(window)
			}
			if d.alerts != nil {
				d.alerts.Dispatch(alert.Alert{
					InstType:      evt.InstType,
					InstID:        evt.InstID,
					Window:        window,
					DuplicateMode: d.mode,
					Key:           key,
					Count:         count,
					FirstSeen:     firstSeen,
					LastSeen:      evt.Timestamp,
				})
			}
		}
	}

	if d.metrics != nil {
		d.metrics.IncTrades(evt.InstID, 1)
		age := time.Since(evt.Timestamp)
		if age < 0 {
			age = 0
		}
		d.metrics.SetLastTradeAge(evt.InstID, age)
	}
}

// Consume implements a simple interface adapter for detector usage in other
// components.
func (d *Detector) Consume(evt trade.Event) {
	d.Process(evt)
}

func (d *Detector) keyFor(evt trade.Event) (string, error) {
	side := strings.ToLower(evt.Side)
	switch d.mode {
	case config.DuplicateModeStrict:
		return fmt.Sprintf("%s|%s|%s", evt.Price.String(), evt.Size.String(), side), nil
	case config.DuplicateModePriceOnly:
		return fmt.Sprintf("%s|%s", evt.Price.String(), side), nil
	case config.DuplicateModeBucketed:
		if !d.useBuckets {
			return "", fmt.Errorf("bucketed mode but ticks not configured")
		}
		priceBucket := bucketValue(evt.Price, d.priceTick)
		sizeBucket := bucketValue(evt.Size, d.sizeTick)
		return fmt.Sprintf("%s|%s|%s", priceBucket.String(), sizeBucket.String(), side), nil
	default:
		return "", fmt.Errorf("unknown duplicate mode %q", d.mode)
	}
}

func bucketValue(value, tick decimal.Decimal) decimal.Decimal {
	if tick.Equal(decimal.Zero) {
		return value
	}
	// Round to the nearest tick using bankers rounding.
	ratio := value.Div(tick)
	rounded := ratio.Round(0)
	return rounded.Mul(tick)
}

// windowState keeps sliding window state for one instrument & window duration.
type windowState struct {
	duration time.Duration
	cooldown time.Duration

	queue   []keyedEvent
	head    int
	buckets map[string]*timestampQueue
	alerts  map[string]time.Time
}

type keyedEvent struct {
	timestamp time.Time
	key       string
}

func newWindowState(duration, cooldown time.Duration) *windowState {
	return &windowState{
		duration: duration,
		cooldown: cooldown,
		buckets:  make(map[string]*timestampQueue),
		alerts:   make(map[string]time.Time),
	}
}

func (w *windowState) insert(ts time.Time, key string, minDupes int) (bool, int, time.Time) {
	cutoff := ts.Add(-w.duration)
	w.evictBefore(cutoff)

	bucket := w.ensureBucket(key)
	bucket.push(ts)
	w.queue = append(w.queue, keyedEvent{timestamp: ts, key: key})

	count := bucket.len()
	if count < minDupes {
		return false, count, bucket.first()
	}

	lastAlert, ok := w.alerts[key]
	if ok && ts.Sub(lastAlert) < w.cooldown {
		return false, count, bucket.first()
	}

	w.alerts[key] = ts
	return true, count, bucket.first()
}

func (w *windowState) ensureBucket(key string) *timestampQueue {
	bucket, ok := w.buckets[key]
	if !ok {
		bucket = &timestampQueue{}
		w.buckets[key] = bucket
	}
	return bucket
}

func (w *windowState) evictBefore(cutoff time.Time) {
	for w.head < len(w.queue) {
		ev := w.queue[w.head]
		if ev.timestamp.After(cutoff) {
			break
		}
		w.head++
		bucket := w.buckets[ev.key]
		if bucket != nil {
			bucket.pop()
			if bucket.len() == 0 {
				delete(w.buckets, ev.key)
				delete(w.alerts, ev.key)
			}
		}
	}

	if w.head == len(w.queue) {
		w.queue = w.queue[:0]
		w.head = 0
		return
	}

	if w.head > 0 && w.head*2 >= len(w.queue) {
		trimmed := make([]keyedEvent, len(w.queue)-w.head)
		copy(trimmed, w.queue[w.head:])
		w.queue = trimmed
		w.head = 0
	}
}

// timestampQueue is a simple deque for timestamps.
type timestampQueue struct {
	data []time.Time
	head int
}

func (q *timestampQueue) len() int {
	return len(q.data) - q.head
}

func (q *timestampQueue) push(ts time.Time) {
	q.data = append(q.data, ts)
}

func (q *timestampQueue) pop() (time.Time, bool) {
	if q.head >= len(q.data) {
		return time.Time{}, false
	}
	ts := q.data[q.head]
	q.head++
	if q.head == len(q.data) {
		q.data = q.data[:0]
		q.head = 0
	} else if q.head > 64 && q.head*2 >= len(q.data) {
		trimmed := make([]time.Time, len(q.data)-q.head)
		copy(trimmed, q.data[q.head:])
		q.data = trimmed
		q.head = 0
	}
	return ts, true
}

func (q *timestampQueue) first() time.Time {
	if q.head >= len(q.data) {
		return time.Time{}
	}
	return q.data[q.head]
}

func (q *timestampQueue) last() time.Time {
	if len(q.data) == 0 {
		return time.Time{}
	}
	return q.data[len(q.data)-1]
}
