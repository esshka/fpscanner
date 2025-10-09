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
	alerts  alertDispatcher

	mode            config.DuplicateMode
	minDupes        int
	windows         []time.Duration
	cooldown        time.Duration
	priceTick       decimal.Decimal
	sizeTick        decimal.Decimal
	useBuckets      bool
	pattern         patternSettings
	tagPriceTick    decimal.Decimal
	tagNotionalTick decimal.Decimal
	tags            *robotTagger

	mu     sync.Mutex
	states map[string]map[time.Duration]*windowState // instId -> window -> state
}

type patternSettings struct {
	enabled        bool
	minOccurrences int
	maxLookback    int
	maxJitter      time.Duration
	relativeJitter float64
	minInterval    time.Duration
}

type timingPatternResult struct {
	interval time.Duration
	jitter   time.Duration
	samples  int
}

type robotTagger struct {
	mu   sync.Mutex
	next int
	tags map[string]string
}

func newRobotTagger() *robotTagger {
	return &robotTagger{
		tags: make(map[string]string),
	}
}

func (r *robotTagger) tag(signature string) string {
	return r.tagWithBase(signature, "")
}

func (r *robotTagger) tagWithBase(signature, base string) string {
	if signature == "" {
		signature = base
	}
	if signature == "" {
		return ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if tag, ok := r.tags[signature]; ok {
		return tag
	}
	if base != "" {
		if tag, ok := r.tags[base]; ok {
			r.tags[signature] = tag
			return tag
		}
	}
	r.next++
	tag := fmt.Sprintf("RB-%03d", r.next)
	r.tags[signature] = tag
	if base != "" {
		r.tags[base] = tag
	}
	return tag
}

type alertDispatcher interface {
	Dispatch(alert.Alert)
}

// New creates a detector from configuration.
func New(cfg config.ScreenerConfig, alerts *alert.Router, collector *metrics.Collector, logger zerolog.Logger) (*Detector, error) {
	d := &Detector{
		logger:   logger,
		metrics:  collector,
		mode:     cfg.DuplicateMode,
		minDupes: cfg.MinDupes,
		cooldown: cfg.Cooldown.OrDefault(60 * time.Second),
		states:   make(map[string]map[time.Duration]*windowState),
		tags:     newRobotTagger(),
	}
	if alerts != nil {
		d.alerts = alerts
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

	d.pattern = patternSettings{
		enabled:        cfg.Pattern.MinOccurrences >= 2,
		minOccurrences: cfg.Pattern.MinOccurrences,
		maxLookback:    cfg.Pattern.MaxLookback,
		maxJitter:      cfg.Pattern.MaxJitter.OrDefault(150 * time.Millisecond),
		relativeJitter: cfg.Pattern.RelativeJitter,
		minInterval:    cfg.Pattern.MinInterval.OrDefault(0),
	}
	if d.pattern.maxLookback == 0 || d.pattern.maxLookback < d.pattern.minOccurrences {
		d.pattern.maxLookback = d.pattern.minOccurrences
	}

	if tick := strings.TrimSpace(cfg.Tagging.PriceTick); tick != "" {
		parsed, err := parseTick(tick)
		if err != nil {
			return nil, fmt.Errorf("detector: invalid tagging price tick: %w", err)
		}
		d.tagPriceTick = parsed
	}
	if tick := strings.TrimSpace(cfg.Tagging.NotionalTick); tick != "" {
		parsed, err := parseTick(tick)
		if err != nil {
			return nil, fmt.Errorf("detector: invalid tagging notional tick: %w", err)
		}
		d.tagNotionalTick = parsed
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

		var patternResult *timingPatternResult
		var patternAllowed bool
		if d.pattern.enabled {
			patternResult = state.detectTimingPattern(key, d.pattern)
			if patternResult != nil && state.canEmitPattern(evt.Timestamp, key) {
				patternAllowed = true
			}
		}

		emitAlert := shouldAlert || patternAllowed
		if emitAlert {
			signature, baseSignature := d.robotSignature(evt, patternResult)
			robotTag := ""
			if d.tags != nil {
				robotTag = d.tags.tagWithBase(signature, baseSignature)
			}
			var timingPattern *alert.TimingPattern
			if patternResult != nil {
				timingPattern = &alert.TimingPattern{
					Type:     alert.PatternTypeUniformInterval,
					Interval: patternResult.interval,
					Jitter:   patternResult.jitter,
					Samples:  patternResult.samples,
				}
				state.markPatternAlert(evt.Timestamp, key)
			}
			if shouldAlert && d.metrics != nil {
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
					TimingPattern: timingPattern,
					RobotTag:      robotTag,
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
	notional := evt.Price.Mul(evt.Size)
	switch d.mode {
	case config.DuplicateModeStrict:
		return fmt.Sprintf("%s|%s|%s", evt.Price.String(), notional.String(), side), nil
	case config.DuplicateModePriceOnly:
		return fmt.Sprintf("%s|%s", evt.Price.String(), side), nil
	case config.DuplicateModeBucketed:
		if !d.useBuckets {
			return "", fmt.Errorf("bucketed mode but ticks not configured")
		}
		priceBucket := bucketValue(evt.Price, d.priceTick)
		notionalBucket := bucketValue(notional, d.sizeTick)
		return fmt.Sprintf("%s|%s|%s", priceBucket.String(), notionalBucket.String(), side), nil
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

	queue         []keyedEvent
	head          int
	buckets       map[string]*timestampQueue
	alerts        map[string]time.Time
	patternAlerts map[string]time.Time
}

type keyedEvent struct {
	timestamp time.Time
	key       string
}

func newWindowState(duration, cooldown time.Duration) *windowState {
	return &windowState{
		duration:      duration,
		cooldown:      cooldown,
		buckets:       make(map[string]*timestampQueue),
		alerts:        make(map[string]time.Time),
		patternAlerts: make(map[string]time.Time),
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
				delete(w.patternAlerts, ev.key)
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

func (w *windowState) detectTimingPattern(key string, cfg patternSettings) *timingPatternResult {
	if !cfg.enabled {
		return nil
	}
	bucket, ok := w.buckets[key]
	if !ok || bucket == nil {
		return nil
	}
	timestamps := bucket.timestamps()
	if len(timestamps) < cfg.minOccurrences {
		return nil
	}
	if cfg.maxLookback > 0 && len(timestamps) > cfg.maxLookback {
		timestamps = timestamps[len(timestamps)-cfg.maxLookback:]
		if len(timestamps) < cfg.minOccurrences {
			return nil
		}
	}
	intervals := make([]time.Duration, 0, len(timestamps)-1)
	for i := 1; i < len(timestamps); i++ {
		delta := timestamps[i].Sub(timestamps[i-1])
		if delta <= 0 {
			return nil
		}
		if cfg.minInterval > 0 && delta < cfg.minInterval {
			return nil
		}
		intervals = append(intervals, delta)
	}
	if len(intervals) < cfg.minOccurrences-1 {
		return nil
	}
	sum := time.Duration(0)
	minDelta := intervals[0]
	maxDelta := intervals[0]
	for _, delta := range intervals {
		sum += delta
		if delta < minDelta {
			minDelta = delta
		}
		if delta > maxDelta {
			maxDelta = delta
		}
	}
	avg := time.Duration(int64(sum) / int64(len(intervals)))
	jitter := maxDelta - minDelta
	allowed := cfg.maxJitter
	if avg > 0 && cfg.relativeJitter > 0 {
		if rel := time.Duration(float64(avg) * cfg.relativeJitter); rel > allowed {
			allowed = rel
		}
	}
	if allowed == 0 {
		if jitter > 0 {
			return nil
		}
	} else if jitter > allowed {
		return nil
	}
	return &timingPatternResult{
		interval: avg,
		jitter:   jitter,
		samples:  len(timestamps),
	}
}

func (w *windowState) canEmitPattern(ts time.Time, key string) bool {
	last, ok := w.patternAlerts[key]
	if !ok {
		return true
	}
	return ts.Sub(last) >= w.cooldown
}

func (w *windowState) markPatternAlert(ts time.Time, key string) {
	if w.patternAlerts == nil {
		w.patternAlerts = make(map[string]time.Time)
	}
	w.patternAlerts[key] = ts
}

func (d *Detector) robotSignature(evt trade.Event, pattern *timingPatternResult) (string, string) {
	side := strings.ToLower(strings.TrimSpace(evt.Side))
	if side == "" {
		side = "unknown"
	}
	notional := evt.Price.Mul(evt.Size)
	notionalBucket := notional
	if !d.tagNotionalTick.Equal(decimal.Zero) {
		notionalBucket = bucketValue(notionalBucket, d.tagNotionalTick)
	}
	parts := []string{evt.InstID, string(d.mode), side, notionalBucket.String()}
	if !d.tagPriceTick.Equal(decimal.Zero) {
		priceBucket := bucketValue(evt.Price, d.tagPriceTick)
		parts = append(parts, priceBucket.String())
	}
	base := strings.Join(parts, "|")
	if pattern == nil || pattern.interval <= 0 {
		return base, base
	}
	interval := normalizeDuration(pattern.interval)
	jitter := normalizeDuration(pattern.jitter)
	detail := fmt.Sprintf("%s|cad:%d", base, interval.Milliseconds())
	if jitter > 0 {
		detail = fmt.Sprintf("%s|jit:%d", detail, jitter.Milliseconds())
	}
	detail = fmt.Sprintf("%s|samples:%d", detail, pattern.samples)
	return detail, base
}

func normalizeDuration(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	if d < 10*time.Millisecond {
		return d
	}
	return d.Round(10 * time.Millisecond)
}

// timestampQueue is a simple deque for timestamps.
type timestampQueue struct {
	data []time.Time
	head int
}

func (q *timestampQueue) len() int {
	return len(q.data) - q.head
}

func (q *timestampQueue) timestamps() []time.Time {
	if q.head >= len(q.data) {
		return nil
	}
	return q.data[q.head:]
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
