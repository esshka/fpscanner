package trade

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/shopspring/decimal"
)

// Event represents a normalized trade from Bitget.
type Event struct {
	Exchange   string
	InstType   string
	InstID     string
	Timestamp  time.Time
	Price      decimal.Decimal
	Size       decimal.Decimal
	Side       string
	TradeID    string
	ReceivedAt time.Time
}

// ParseDecimal converts Bitget decimal strings into a decimal.Decimal.
func ParseDecimal(value string) (decimal.Decimal, error) {
	d, err := decimal.NewFromString(strings.TrimSpace(value))
	if err != nil {
		return decimal.Decimal{}, fmt.Errorf("trade: invalid decimal %q: %w", value, err)
	}
	return d, nil
}

// ParseMillis converts a millisecond timestamp string into time.Time.
func ParseMillis(value string) (time.Time, error) {
	millis, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("trade: invalid timestamp %q: %w", value, err)
	}
	return time.UnixMilli(millis).UTC(), nil
}
