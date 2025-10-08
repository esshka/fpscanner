package trade

// Consumer represents a sink for normalized trade events.
type Consumer interface {
	Consume(Event)
}
