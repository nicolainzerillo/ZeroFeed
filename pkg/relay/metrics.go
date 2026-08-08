package relay

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"time"
)

// Metrics manages atomic, lock-free zero-knowledge telemetry counters.
// Guaranteed Zero-Knowledge: No IPs, Session IDs, passphrases, or payload contents are recorded.
type Metrics struct {
	ActiveSessions               atomic.Int64
	SessionsCreatedTotal         atomic.Uint64
	ActiveConnections            atomic.Int64
	BytesTransferredTotal        atomic.Uint64
	MessagesRelayedTotal         atomic.Uint64
	RateLimitBansTotal           atomic.Uint64
	MalformedPacketsDroppedTotal atomic.Uint64
	BackpressurePausesTotal      atomic.Uint64
	SlowConsumersPrunedTotal     atomic.Uint64
	startTime                    time.Time
}

// NewMetrics initializes a Metrics instance.
func NewMetrics() *Metrics {
	return &Metrics{
		startTime: time.Now(),
	}
}

// Handler returns an http.Handler that exports metrics in Prometheus text format.
func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

		uptimeSeconds := time.Since(m.startTime).Seconds()

		fmt.Fprintf(w, "# HELP zerofeed_relay_uptime_seconds Total relay server uptime in seconds.\n")
		fmt.Fprintf(w, "# TYPE zerofeed_relay_uptime_seconds gauge\n")
		fmt.Fprintf(w, "zerofeed_relay_uptime_seconds %.2f\n\n", uptimeSeconds)

		fmt.Fprintf(w, "# HELP zerofeed_relay_active_sessions Gauge of current active E2EE sessions.\n")
		fmt.Fprintf(w, "# TYPE zerofeed_relay_active_sessions gauge\n")
		fmt.Fprintf(w, "zerofeed_relay_active_sessions %d\n\n", m.ActiveSessions.Load())

		fmt.Fprintf(w, "# HELP zerofeed_relay_sessions_created_total Cumulative count of created sessions.\n")
		fmt.Fprintf(w, "# TYPE zerofeed_relay_sessions_created_total counter\n")
		fmt.Fprintf(w, "zerofeed_relay_sessions_created_total %d\n\n", m.SessionsCreatedTotal.Load())

		fmt.Fprintf(w, "# HELP zerofeed_relay_active_connections Gauge of active socket connections.\n")
		fmt.Fprintf(w, "# TYPE zerofeed_relay_active_connections gauge\n")
		fmt.Fprintf(w, "zerofeed_relay_active_connections %d\n\n", m.ActiveConnections.Load())

		fmt.Fprintf(w, "# HELP zerofeed_relay_bytes_transferred_total Cumulative bytes relayed through server.\n")
		fmt.Fprintf(w, "# TYPE zerofeed_relay_bytes_transferred_total counter\n")
		fmt.Fprintf(w, "zerofeed_relay_bytes_transferred_total %d\n\n", m.BytesTransferredTotal.Load())

		fmt.Fprintf(w, "# HELP zerofeed_relay_messages_relayed_total Cumulative frames forwarded.\n")
		fmt.Fprintf(w, "# TYPE zerofeed_relay_messages_relayed_total counter\n")
		fmt.Fprintf(w, "zerofeed_relay_messages_relayed_total %d\n\n", m.MessagesRelayedTotal.Load())

		fmt.Fprintf(w, "# HELP zerofeed_relay_ratelimit_bans_total Cumulative IP rate-limit bans.\n")
		fmt.Fprintf(w, "# TYPE zerofeed_relay_ratelimit_bans_total counter\n")
		fmt.Fprintf(w, "zerofeed_relay_ratelimit_bans_total %d\n\n", m.RateLimitBansTotal.Load())

		fmt.Fprintf(w, "# HELP zerofeed_relay_malformed_packets_dropped_total Cumulative invalid frames dropped.\n")
		fmt.Fprintf(w, "# TYPE zerofeed_relay_malformed_packets_dropped_total counter\n")
		fmt.Fprintf(w, "zerofeed_relay_malformed_packets_dropped_total %d\n\n", m.MalformedPacketsDroppedTotal.Load())

		fmt.Fprintf(w, "# HELP zerofeed_relay_backpressure_pauses_total Cumulative watermark backpressure pauses.\n")
		fmt.Fprintf(w, "# TYPE zerofeed_relay_backpressure_pauses_total counter\n")
		fmt.Fprintf(w, "zerofeed_relay_backpressure_pauses_total %d\n\n", m.BackpressurePausesTotal.Load())

		fmt.Fprintf(w, "# HELP zerofeed_relay_slow_consumers_pruned_total Cumulative stalled subscribers pruned.\n")
		fmt.Fprintf(w, "# TYPE zerofeed_relay_slow_consumers_pruned_total counter\n")
		fmt.Fprintf(w, "zerofeed_relay_slow_consumers_pruned_total %d\n", m.SlowConsumersPrunedTotal.Load())
	})
}
