package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DuplicateMode defines how duplicate keys are produced.
type DuplicateMode string

const (
	DuplicateModeStrict    DuplicateMode = "strict"
	DuplicateModePriceOnly DuplicateMode = "priceOnly"
	DuplicateModeBucketed  DuplicateMode = "bucketed"
)

// Duration wraps time.Duration to support YAML unmarshalling from either a
// string (e.g. "30s") or a raw number representing seconds.
type Duration struct {
	time.Duration
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		raw := strings.TrimSpace(value.Value)
		if raw == "" {
			d.Duration = 0
			return nil
		}
		if ms, err := time.ParseDuration(raw); err == nil {
			d.Duration = ms
			return nil
		}
		// Fallback: treat as seconds
		var seconds float64
		if err := value.Decode(&seconds); err != nil {
			return fmt.Errorf("config: invalid duration %q: %w", raw, err)
		}
		d.Duration = time.Duration(seconds * float64(time.Second))
		return nil
	default:
		return fmt.Errorf("config: unsupported YAML node for duration: %v", value.Kind)
	}
}

// MarshalYAML renders the duration as a string.
func (d Duration) MarshalYAML() (interface{}, error) {
	return d.Duration.String(), nil
}

// OrDefault returns the duration or a fallback when zero.
func (d Duration) OrDefault(fallback time.Duration) time.Duration {
	if d.Duration == 0 {
		return fallback
	}
	return d.Duration
}

// Config is the root configuration schema for the screener application.
type Config struct {
	Instruments []Instrument    `yaml:"instruments"`
	Websocket   WebsocketConfig `yaml:"websocket"`
	Screener    ScreenerConfig  `yaml:"screener"`
	Alerts      AlertConfig     `yaml:"alerts"`
	Metrics     MetricsConfig   `yaml:"metrics"`
	WarmStart   WarmStartConfig `yaml:"warmStart"`
	Logging     LoggingConfig   `yaml:"logging"`
}

// Instrument defines an instrument subscription target.
type Instrument struct {
	InstType string `yaml:"instType"`
	InstID   string `yaml:"instId"`
}

// WebsocketConfig covers Bitget websocket behaviour and rate limiting.
type WebsocketConfig struct {
	URL                 string        `yaml:"url"`
	PingInterval        Duration      `yaml:"pingInterval"`
	MaxMessagesPerSec   int           `yaml:"maxMessagesPerSec"`
	BatchSize           int           `yaml:"batchSize"`
	SubscribeChunk      int           `yaml:"subscribeChunk"`
	SubscribeInterval   Duration      `yaml:"subscribeInterval"`
	ReadBufferBytes     int           `yaml:"readBufferBytes"`
	WriteBufferBytes    int           `yaml:"writeBufferBytes"`
	HandshakeTimeout    Duration      `yaml:"handshakeTimeout"`
	MessageWriteTimeout Duration      `yaml:"messageWriteTimeout"`
	Backoff             BackoffConfig `yaml:"backoff"`
}

// BackoffConfig governs reconnect behaviour.
type BackoffConfig struct {
	Initial    Duration `yaml:"initial"`
	Max        Duration `yaml:"max"`
	Multiplier float64  `yaml:"multiplier"`
	Jitter     float64  `yaml:"jitter"`
}

// ScreenerConfig drives duplicate detection windows and thresholds.
type ScreenerConfig struct {
	Windows       []Duration    `yaml:"windows"`
	DuplicateMode DuplicateMode `yaml:"duplicateMode"`
	MinDupes      int           `yaml:"minDupes"`
	Cooldown      Duration      `yaml:"cooldown"`
	TopN          int           `yaml:"topN"`
	Bucket        BucketConfig  `yaml:"bucket"`
}

// BucketConfig configures bucketed duplicate keys.
type BucketConfig struct {
	PriceTick string `yaml:"priceTick"`
	SizeTick  string `yaml:"sizeTick"`
}

// AlertConfig holds sink configuration for alerts.
type AlertConfig struct {
	Console      bool          `yaml:"console"`
	Table        bool          `yaml:"table"`
	Webhooks     []string      `yaml:"webhooks"`
	SlackWebhook string        `yaml:"slackWebhook"`
	Cooldown     Duration      `yaml:"cooldown"`
	Timeout      Duration      `yaml:"timeout"`
	Retry        BackoffConfig `yaml:"retry"`
}

// MetricsConfig configures the Prometheus metrics endpoint.
type MetricsConfig struct {
	ListenAddr string `yaml:"listenAddr"`
}

// WarmStartConfig controls the optional REST backfill.
type WarmStartConfig struct {
	Enable               bool     `yaml:"enable"`
	BaseURL              string   `yaml:"baseUrl"`
	RestEndpoint         string   `yaml:"restEndpoint"`
	Lookback             Duration `yaml:"lookback"`
	MaxRequestsPerSecond float64  `yaml:"maxRequestsPerSecond"`
}

// LoggingConfig toggles logging.
type LoggingConfig struct {
	Level string `yaml:"level"`
	Human bool   `yaml:"human"`
}

// Load reads configuration from YAML file and applies defaults.
func Load(path string) (*Config, error) {
	cfg := defaultConfig()

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Return defaults when the file is absent so the binary can start
			// with CLI-provided overrides only.
			return cfg, nil
		}
		return nil, fmt.Errorf("config: failed to read %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("config: invalid YAML: %w", err)
	}

	cfg.applyDefaults()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

func defaultConfig() *Config {
	return &Config{
		Websocket: WebsocketConfig{
			URL:                 "wss://ws.bitget.com/v2/ws/public",
			PingInterval:        Duration{Duration: 30 * time.Second},
			MaxMessagesPerSec:   10,
			BatchSize:           40,
			SubscribeChunk:      20,
			SubscribeInterval:   Duration{Duration: 300 * time.Millisecond},
			ReadBufferBytes:     32 * 1024,
			WriteBufferBytes:    32 * 1024,
			HandshakeTimeout:    Duration{Duration: 15 * time.Second},
			MessageWriteTimeout: Duration{Duration: 5 * time.Second},
			Backoff: BackoffConfig{
				Initial:    Duration{Duration: 1 * time.Second},
				Max:        Duration{Duration: 30 * time.Second},
				Multiplier: 2.0,
				Jitter:     0.2,
			},
		},
		Screener: ScreenerConfig{
			Windows: []Duration{
				{Duration: 30 * time.Second},
				{Duration: 15 * time.Second},
				{Duration: 12 * time.Second},
				{Duration: 11 * time.Second},
			},
			DuplicateMode: DuplicateModeStrict,
			MinDupes:      2,
			Cooldown:      Duration{Duration: 60 * time.Second},
			TopN:          5,
			Bucket: BucketConfig{
				PriceTick: "0.1",
				SizeTick:  "0.1",
			},
		},
		Alerts: AlertConfig{
			Console:  true,
			Table:    false,
			Cooldown: Duration{Duration: 60 * time.Second},
			Timeout:  Duration{Duration: 5 * time.Second},
			Retry: BackoffConfig{
				Initial:    Duration{Duration: 1 * time.Second},
				Max:        Duration{Duration: 15 * time.Second},
				Multiplier: 2.0,
				Jitter:     0.2,
			},
		},
		Metrics: MetricsConfig{
			ListenAddr: ":9100",
		},
		WarmStart: WarmStartConfig{
			Enable:               false,
			BaseURL:              "https://api.bitget.com",
			RestEndpoint:         "/api/v2/spot/market/fills",
			Lookback:             Duration{Duration: 3 * time.Second},
			MaxRequestsPerSecond: 8.0,
		},
		Logging: LoggingConfig{
			Level: "info",
			Human: false,
		},
	}
}

// applyDefaults fills zero-values with defaults where a YAML override has not
// been provided.
func (c *Config) applyDefaults() {
	// Websocket defaults
	if c.Websocket.URL == "" {
		c.Websocket.URL = "wss://ws.bitget.com/v2/ws/public"
	}
	if c.Websocket.MaxMessagesPerSec == 0 {
		c.Websocket.MaxMessagesPerSec = 10
	}
	if c.Websocket.BatchSize == 0 {
		c.Websocket.BatchSize = 40
	}
	if c.Websocket.SubscribeChunk == 0 {
		c.Websocket.SubscribeChunk = 20
	}
	if c.Websocket.SubscribeInterval.Duration == 0 {
		c.Websocket.SubscribeInterval = Duration{Duration: 300 * time.Millisecond}
	}
	if c.Websocket.PingInterval.Duration == 0 {
		c.Websocket.PingInterval = Duration{Duration: 30 * time.Second}
	}
	if c.Websocket.ReadBufferBytes == 0 {
		c.Websocket.ReadBufferBytes = 32 * 1024
	}
	if c.Websocket.WriteBufferBytes == 0 {
		c.Websocket.WriteBufferBytes = 32 * 1024
	}
	if c.Websocket.HandshakeTimeout.Duration == 0 {
		c.Websocket.HandshakeTimeout = Duration{Duration: 15 * time.Second}
	}
	if c.Websocket.MessageWriteTimeout.Duration == 0 {
		c.Websocket.MessageWriteTimeout = Duration{Duration: 5 * time.Second}
	}
	if c.Websocket.Backoff.Initial.Duration == 0 {
		c.Websocket.Backoff.Initial = Duration{Duration: 1 * time.Second}
	}
	if c.Websocket.Backoff.Max.Duration == 0 {
		c.Websocket.Backoff.Max = Duration{Duration: 30 * time.Second}
	}
	if c.Websocket.Backoff.Multiplier == 0 {
		c.Websocket.Backoff.Multiplier = 2.0
	}
	if c.Websocket.Backoff.Jitter == 0 {
		c.Websocket.Backoff.Jitter = 0.2
	}

	if len(c.Screener.Windows) == 0 {
		c.Screener.Windows = []Duration{
			{Duration: 30 * time.Second},
			{Duration: 15 * time.Second},
			{Duration: 12 * time.Second},
			{Duration: 11 * time.Second},
		}
	}
	if c.Screener.DuplicateMode == "" {
		c.Screener.DuplicateMode = DuplicateModeStrict
	}
	if c.Screener.MinDupes == 0 {
		c.Screener.MinDupes = 2
	}
	if c.Screener.Cooldown.Duration == 0 {
		c.Screener.Cooldown = Duration{Duration: 60 * time.Second}
	}
	if c.Screener.TopN == 0 {
		c.Screener.TopN = 5
	}

	if c.Alerts.Cooldown.Duration == 0 {
		c.Alerts.Cooldown = Duration{Duration: 60 * time.Second}
	}
	if c.Alerts.Timeout.Duration == 0 {
		c.Alerts.Timeout = Duration{Duration: 5 * time.Second}
	}
	if c.Alerts.Retry.Initial.Duration == 0 {
		c.Alerts.Retry.Initial = Duration{Duration: time.Second}
	}
	if c.Alerts.Retry.Max.Duration == 0 {
		c.Alerts.Retry.Max = Duration{Duration: 15 * time.Second}
	}
	if c.Alerts.Retry.Multiplier == 0 {
		c.Alerts.Retry.Multiplier = 2.0
	}
	if c.Alerts.Retry.Jitter == 0 {
		c.Alerts.Retry.Jitter = 0.2
	}

	if c.Metrics.ListenAddr == "" {
		c.Metrics.ListenAddr = ":9100"
	}

	if c.WarmStart.RestEndpoint == "" {
		c.WarmStart.RestEndpoint = "/api/v2/spot/market/fills"
	}
	if c.WarmStart.BaseURL == "" {
		c.WarmStart.BaseURL = "https://api.bitget.com"
	}
	if c.WarmStart.Lookback.Duration == 0 {
		c.WarmStart.Lookback = Duration{Duration: 3 * time.Second}
	}
	if c.WarmStart.MaxRequestsPerSecond == 0 {
		c.WarmStart.MaxRequestsPerSecond = 8.0
	}

	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
}

// Validate ensures required configuration is present.
func (c *Config) Validate() error {
	validModes := map[DuplicateMode]struct{}{
		DuplicateModeStrict:    {},
		DuplicateModePriceOnly: {},
		DuplicateModeBucketed:  {},
	}
	if _, ok := validModes[c.Screener.DuplicateMode]; !ok {
		return fmt.Errorf("config: unsupported duplicate mode %q", c.Screener.DuplicateMode)
	}
	if c.Screener.MinDupes < 2 {
		return errors.New("config: minDupes must be >= 2")
	}
	if c.Websocket.MaxMessagesPerSec <= 0 {
		return errors.New("config: maxMessagesPerSec must be > 0")
	}
	if c.Websocket.BatchSize <= 0 {
		return errors.New("config: batchSize must be > 0")
	}
	if c.Websocket.SubscribeChunk <= 0 {
		return errors.New("config: subscribeChunk must be > 0")
	}
	return nil
}
