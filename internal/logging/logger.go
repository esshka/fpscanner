package logging

import (
	"io"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/esshka/fp-scanner-go/internal/config"
)

// New initialises a zerolog logger according to the provided configuration.
func New(cfg config.LoggingConfig) zerolog.Logger {
	level := parseLevel(cfg.Level)
	zerolog.TimeFieldFormat = time.RFC3339Nano

	var writer io.Writer = os.Stdout
	if cfg.Human {
		writer = zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	}

	logger := zerolog.New(writer).With().Timestamp().Logger().Level(level)
	log.Logger = logger
	return logger
}

func parseLevel(level string) zerolog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "trace":
		return zerolog.TraceLevel
	case "debug":
		return zerolog.DebugLevel
	case "info", "":
		return zerolog.InfoLevel
	case "warn", "warning":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	case "fatal":
		return zerolog.FatalLevel
	case "panic":
		return zerolog.PanicLevel
	default:
		return zerolog.InfoLevel
	}
}
