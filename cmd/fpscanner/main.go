package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/sync/errgroup"

	"github.com/esshka/fp-scanner-go/internal/alert"
	"github.com/esshka/fp-scanner-go/internal/config"
	"github.com/esshka/fp-scanner-go/internal/detector"
	"github.com/esshka/fp-scanner-go/internal/logging"
	"github.com/esshka/fp-scanner-go/internal/metrics"
	"github.com/esshka/fp-scanner-go/internal/rest"
	"github.com/esshka/fp-scanner-go/internal/trade"
	"github.com/esshka/fp-scanner-go/internal/ws"
)

func main() {
	var configPath string
	var instrumentFlags multiInstrument

	flag.StringVar(&configPath, "config", "config.yaml", "Path to configuration file")
	flag.Var(&instrumentFlags, "instrument", "Additional instrument in the form INSTTYPE:INSTID (repeatable)")
	flag.Parse()

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	if len(instrumentFlags) > 0 {
		cfg.Instruments = instrumentFlags.toInstruments()
	}

	if len(cfg.Instruments) == 0 {
		fmt.Fprintln(os.Stderr, "no instruments configured; set in config file or via --instrument INSTTYPE:INSTID")
		os.Exit(1)
	}

	logger := logging.New(cfg.Logging)
	logger.Info().Msg("starting fp-scanner")

	metricsCollector := metrics.NewCollector()

	alertRouter, err := alert.NewRouter(cfg.Alerts, logger.With().Str("component", "alert").Logger(), metricsCollector)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to initialise alert router")
	}

	detectorLogger := logger.With().Str("component", "detector").Logger()
	dupDetector, err := detector.New(cfg.Screener, alertRouter, metricsCollector, detectorLogger)
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to initialise detector")
	}

	warmStarter := rest.NewWarmStarter(cfg.WarmStart, metricsCollector, logger.With().Str("component", "warmstart").Logger())

	manager := ws.NewManager(cfg.Websocket, cfg.Instruments, dupDetector, warmStarter, metricsCollector, logger.With().Str("component", "ws").Logger())

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	group, ctx := errgroup.WithContext(ctx)

	group.Go(func() error {
		alertRouter.Run(ctx)
		return nil
	})

	group.Go(func() error {
		return metricsCollector.StartServer(ctx, cfg.Metrics.ListenAddr, logger.With().Str("component", "metrics").Logger())
	})

	group.Go(func() error {
		return manager.Run(ctx)
	})

	if err := group.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error().Err(err).Msg("fp-scanner shutting down with error")
		os.Exit(1)
	}
	logger.Info().Msg("fp-scanner stopped")
}

// multiInstrument is a flag.Value implementation for repeated instrument
// definitions.
type multiInstrument []string

func (m *multiInstrument) String() string {
	return strings.Join(*m, ",")
}

func (m *multiInstrument) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("instrument cannot be empty")
	}
	*m = append(*m, value)
	return nil
}

func (m multiInstrument) toInstruments() []config.Instrument {
	out := make([]config.Instrument, 0, len(m))
	for _, raw := range m {
		parts := strings.SplitN(raw, ":", 2)
		if len(parts) != 2 {
			continue
		}
		out = append(out, config.Instrument{InstType: strings.TrimSpace(parts[0]), InstID: strings.TrimSpace(parts[1])})
	}
	return out
}

// ensure detector satisfies the trade.Consumer interface
var _ trade.Consumer = (*detector.Detector)(nil)
