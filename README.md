# FP Scanner Go

A real-time identical prints screener for Bitget public markets. The service
consumes the Bitget v2 public websocket feed, maintains sliding windows across
configurable durations, and emits alerts whenever duplicate trade prints recur
within those windows. It targets quant workflows that need fast detection of
potential iceberg or flow patterns across many instruments.

## Features

- Rate-limit aware websocket manager with automatic resubscribe & heartbeat.
- Sliding-window duplicate detection for 30s/15s/12s/11s (configurable) using
  strict, price-only, or bucketed keys.
- Pluggable alert router: console logging by default, plus generic webhooks and
  Slack-compatible webhook delivery with retry and timeout controls.
- Optional REST warm-start to backfill trades on reconnect while respecting
  Bitget's 10 req/s IP budget.
- Prometheus metrics (`/metrics`) covering connectivity, ingest throughput,
  duplicate counts, and REST usage.
- Structured logging via `zerolog`.

## Getting Started

1. Install Go 1.22 or newer.
2. Copy the example configuration and adjust to your instrument list:

   ```bash
   cp config.example.yaml config.yaml
   ```

3. Build or run the scanner:

   ```bash
   go build -o fpscanner ./cmd/fpscanner
   ./fpscanner --config config.yaml
   ```

   You can also add instruments directly via CLI overrides:

   ```bash
   ./fpscanner --config config.yaml --instrument SPOT:BTCUSDT --instrument SPOT:ETHUSDT
   ```

4. Scrape metrics from `http://localhost:9100/metrics` (customise via
   `metrics.listenAddr`).

## Configuration Highlights

- `websocket`: tune batching (`batchSize`), subscribe chunking, and ping
  intervals to meet Bitget's 10 msg/sec / 4096 byte limits.
- `screener`: choose `duplicateMode` (`strict`, `priceOnly`, `bucketed`), set
  `windows`, `minDupes`, and per-key `cooldown`.
- `alerts`: enable console/log sinks or define webhook targets. Slack incoming
  webhooks plug in under `alerts.slackWebhook`.
- `warmStart`: enable REST recovery with a lookback horizon; the service filters
  data to the configured window.

Refer to `PRD.md` for the detailed product requirements that shaped this
implementation.

### Configuration Reference

| Section      | Keys & Notes |
|--------------|--------------|
| `instruments` | List of `{instType, instId}` pairs. These are sharded across websocket connections according to `websocket.batchSize`. |
| `websocket`   | `maxMessagesPerSec`, `subscribeChunk`, and `subscribeInterval` enforce Bitget’s 10 msg/s budget. `backoff` controls reconnect behaviour (initial/max interval, multiplier, jitter). |
| `screener`    | `windows` accepts Go duration strings (`30s`, `500ms`). `duplicateMode` can be `strict`, `priceOnly`, or `bucketed` (requires `bucket.priceTick` and `bucket.sizeTick`). `cooldown` throttles repeat alerts per `(instId, window, key)`. |
| `alerts`      | `console` toggles structured logs; `table` enables an aggregated per-instrument terminal table similar to desktop scanners. `webhooks` is a list of HTTPS endpoints. `slackWebhook` sends Slack-compatible payloads. `retry` uses exponential backoff when a sink fails. |
| `metrics`     | Set `listenAddr` for the Prometheus HTTP listener, e.g. `":9100"` or `"0.0.0.0:9100"`. |
| `warmStart`   | Enable to fetch recent trades via REST after reconnects. `lookback` defines how far back to replay trades; `maxRequestsPerSecond` throttles requests per Bitget’s 10 rps cap. |

### Logs & Alert Interpretation

Sample log:

```
2025-10-08T13:28:14+02:00 INF duplicate detected component=alert count=2 firstSeen=2025-10-08T11:25:44.502Z instId=COAIUSDT instType=SPOT key=3.7876|2.63|sell lastSeen=2025-10-08T11:28:14.672Z mode=strict sink=console windowSec=30
```

- Timestamp uses local time; `mode` shows the active duplicate definition.
- `key` is the tuple `(price|size|side)` for `strict`, `(price|side)` for `priceOnly`, or bucketed values.
- `count` is how many matching trades landed inside the sliding window; `firstSeen` and `lastSeen` are UTC.
- `windowSec` indicates which window triggered the alert. Multiple windows may fire if the trades overlap several durations.
- `sink` reveals the destination (console, webhook, Slack, etc.).

Enable human-readable logs with `logging.human=true` while tuning, or switch on `alerts.table=true` to render an ASCII table that mimics common desktop scanners. Once integrated with log pipelines, revert to JSON console output for parsing.

Example aggregated table (`alerts.table=true`):

```
+----------+--------+---------+--------------+------------+------------+----------------------+----------------------+
| Ticker   | Window | Alerts  | Total Volume | Avg Diff   | Max Diff   | Last Alert (local)  | Last Pattern         |
+----------+--------+---------+--------------+------------+------------+----------------------+----------------------+
| COAIUSDT | 11s    |       5 | 16.42        | 00:00:03   | 00:00:05   | 13:44:22             | 3.7876 x 2.63 Down   |
| COAIUSDT | 30s    |       2 | 10.52        | 00:00:46   | 00:01:08   | 13:44:22             | 3.7854 x 0.43 Up     |
+----------+--------+---------+--------------+------------+------------+----------------------+----------------------+
```

`Alerts` counts how many duplicate alerts fired for that instrument/window, `Total Volume` sums the duplicate volume (`size × count` per alert), `Avg Diff`/`Max Diff` track the window span between first/last trade for each alert, `Last Alert` shows the most recent local timestamp, and `Last Pattern` mirrors the latest duplicate key (price/size/direction).

### Metrics & Health Checks

The Prometheus endpoint exposes the key gauges and counters described in the PRD. Common ones to monitor:

- `fp_scanner_ws_connections_open`: active websocket sessions.
- `fp_scanner_ws_reconnects_total`: cumulative reconnect attempts.
- `fp_scanner_trades_in_total{inst_id}` and `fp_scanner_window_events_total{inst_id,win}`: ingest throughput.
- `fp_scanner_duplicate_keys_total{win}` and `fp_scanner_alerts_emitted_total{win}`: duplicate detection frequency.
- `fp_scanner_last_trade_age_seconds{inst_id}`: staleness indicator (alert if it grows unexpectedly).

Scrape `http://<host>:9100/metrics` or adjust `metrics.listenAddr`. Pair with dashboards or alert rules to watch reconnect spikes and rate-limit backoffs.

### Deployment Notes

- **Live verification:** Start the service with your production instruments, observe the `duplicate detected` logs, and inspect metrics for increasing `ws_messages_in_total` and `trades_in_total` counters.
- **Resilience:** The manager automatically resubscribes after disconnects. Consider using a process supervisor (systemd, Docker, Kubernetes) for restarts and log shipping.
- **Firewall:** Allow outbound TCP to `wss://ws.bitget.com` and inbound access to the metrics port if scraping remotely.

### Building for Other Platforms

- Linux/macOS (native Go toolchain): `go build -o fpscanner ./cmd/fpscanner`.
- Windows cross-build from Unix:
  ```bash
  GOOS=windows GOARCH=amd64 go build -o fpscanner.exe ./cmd/fpscanner
  ```
  Copy `fpscanner.exe` and `config.yaml` to the Windows host and run
  `fpscanner.exe --config C:\\path\\to\\config.yaml`.

- Enable CGO disabled builds (`CGO_ENABLED=0`) if you need a fully static binary for minimal containers.


## Development

- Run `go test ./...` (tests to be added for sliding windows, parsing, etc.).
- Use `golangci-lint` or `go vet` for additional static checks.
- Prometheus metrics are registered in `internal/metrics`; add new counters/gauges
  there when extending functionality.
- Alert sinks implement `alert.Sink`. Add new sinks by satisfying the interface
  and appending during router construction.

## Future Enhancements

- Add full unit coverage for window eviction and duplicate detection edge cases.
- Support gRPC/REST control plane for dynamic instrument lists.
- Integrate persistent queue or snapshotting for stateful failover.
