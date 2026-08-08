# ZeroFeed Relay - Zero-Knowledge Prometheus Observability Guide

> **Audience**: DevOps Engineers, Site Reliability Engineers (SRE), Infrastructure & Security Auditors

This document provides technical documentation for the **Zero-Knowledge Prometheus Telemetry Engine** implemented in the ZeroFeed Relay node ([pkg/relay/metrics.go](../pkg/relay/metrics.go)).

---

## 1. Zero-Knowledge Privacy Guarantee

ZeroFeed operates under a strict **Zero-Knowledge Privacy Policy**:
- **Zero Disk Persistence**: All relay operations execute strictly in RAM.
- **Zero IP / Identity Tracking**: Metric counters use lock-free `atomic.Uint64` / `atomic.Int64` scalar aggregations. No IP addresses, Session IDs, passphrases, or client identifiers are ever recorded, cached, or exported.
- **Zero Payload Inspection**: No data contents, message lengths, or cryptographic hashes are stored.

---

## 2. Enabling the Prometheus Metrics Endpoint

To expose the `/metrics` endpoint on the Relay node:

### CLI Options
```bash
# Expose metrics on port 9090 (0.0.0.0:9090)
zerofeed relay --port 8443 --quic --metrics-port 9090

# Expose metrics bound strictly to localhost (127.0.0.1:9090)
zerofeed relay --port 8443 --quic --metrics-addr "127.0.0.1:9090"
```

### Docker Compose Configuration (`docker-compose.yml`)
```yaml
version: '3.8'

services:
  zerofeed-relay:
    build: .
    container_name: zerofeed-relay
    command: ["/zerofeed", "relay", "--port", "8443", "--quic", "--no-rate-limit", "--metrics-port", "9090"]
    ports:
      - "8443:8443/tcp"
      - "8443:8443/udp"
      - "9090:9090/tcp"
```

---

## 3. Prometheus Metrics Schema Specification

All metrics follow standard OpenMetrics / Prometheus exposition text format 0.0.4.

| Metric Name | Type | Description |
| :--- | :--- | :--- |
| `zerofeed_relay_uptime_seconds` | Gauge | Total relay server uptime in seconds since process boot. |
| `zerofeed_relay_active_sessions` | Gauge | Current number of active in-memory E2EE pub/sub sessions. |
| `zerofeed_relay_sessions_created_total` | Counter | Cumulative count of E2EE sessions initialized. |
| `zerofeed_relay_active_connections` | Gauge | Current number of active TCP & QUIC socket connections. |
| `zerofeed_relay_bytes_transferred_total` | Counter | Cumulative bytes relayed through the server. |
| `zerofeed_relay_messages_relayed_total` | Counter | Cumulative encrypted frames/payloads forwarded. |
| `zerofeed_relay_ratelimit_bans_total` | Counter | Cumulative IP rate-limiting bans enforced. |
| `zerofeed_relay_malformed_packets_dropped_total` | Counter | Cumulative malformed magic headers / invalid packets dropped. |

---

## 4. Sample `/metrics` Response

```text
# HELP zerofeed_relay_uptime_seconds Total relay server uptime in seconds.
# TYPE zerofeed_relay_uptime_seconds gauge
zerofeed_relay_uptime_seconds 3412.50

# HELP zerofeed_relay_active_sessions Gauge of current active E2EE sessions.
# TYPE zerofeed_relay_active_sessions gauge
zerofeed_relay_active_sessions 42

# HELP zerofeed_relay_sessions_created_total Cumulative count of created sessions.
# TYPE zerofeed_relay_sessions_created_total counter
zerofeed_relay_sessions_created_total 1280

# HELP zerofeed_relay_active_connections Gauge of active socket connections.
# TYPE zerofeed_relay_active_connections gauge
zerofeed_relay_active_connections 84

# HELP zerofeed_relay_bytes_transferred_total Cumulative bytes relayed through server.
# TYPE zerofeed_relay_bytes_transferred_total counter
zerofeed_relay_bytes_transferred_total 5368709120

# HELP zerofeed_relay_messages_relayed_total Cumulative frames forwarded.
# TYPE zerofeed_relay_messages_relayed_total counter
zerofeed_relay_messages_relayed_total 165000

# HELP zerofeed_relay_ratelimit_bans_total Cumulative IP rate-limit bans.
# TYPE zerofeed_relay_ratelimit_bans_total counter
zerofeed_relay_ratelimit_bans_total 14

# HELP zerofeed_relay_malformed_packets_dropped_total Cumulative invalid frames dropped.
# TYPE zerofeed_relay_malformed_packets_dropped_total counter
zerofeed_relay_malformed_packets_dropped_total 3
```

---

## 5. Prometheus Scrape Config (`prometheus.yml`)

```yaml
scrape_configs:
  - job_name: 'zerofeed-relay'
    scrape_interval: 10s
    static_configs:
      - targets: ['zerofeed-relay.internal:9090']
```

---

## 6. Grafana PromQL Dashboard Queries

- **Relay Throughput Bandwidth (MB/s)**:
  ```promql
  rate(zerofeed_relay_bytes_transferred_total[1m]) / 1024 / 1024
  ```

- **Message Forwarding Rate (Msg/sec)**:
  ```promql
  rate(zerofeed_relay_messages_relayed_total[1m])
  ```

- **Active Sessions vs Connections**:
  ```promql
  zerofeed_relay_active_sessions
  zerofeed_relay_active_connections
  ```

- **DDoS / Anomaly Dropped Packets Rate**:
  ```promql
  rate(zerofeed_relay_malformed_packets_dropped_total[5m])
  ```
