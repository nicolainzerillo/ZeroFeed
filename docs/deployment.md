# ZeroFeed Relay Deployment & DevOps Guide

> **Audience**: DevOps Engineers, System Administrators, Infrastructure Teams

This guide provides production-ready deployment configurations for hosting a **ZeroFeed Relay Node** on Linux servers, Docker containers, systemd services, and cloud environments (Fly.io, AWS NLB, HAProxy).

---

## 1. Relay Operating Modes & Deployment Scenarios

ZeroFeed Relay can be deployed across three distinct environment architectures:

| Scenario | Command Flags | Description |
| :--- | :--- | :--- |
| **Direct VPS / Bare-Metal (Default 0-Config)** | `zerofeed relay --port 8443 --quic` | Native per-IP rate limiting on `conn.RemoteAddr()`. Recommended for dedicated Linux VPS without reverse proxies. |
| **Cloud Proxy with PROXY Protocol v2** | `zerofeed relay --port 8443 --quic --trust-proxy` | Parses HAProxy PROXY Protocol v2 binary headers from trusted L4 load balancers (AWS NLB, HAProxy) to extract true client source IPs for rate limiting. |
| **Managed Cloud Ingress** | `zerofeed relay --port 8443 --quic --no-rate-limit` | Disables internal IP rate limiting when edge protection and DDoS filtering are managed by cloud proxies (Fly.io, Cloudflare Spectrum, AWS WAF). |

---

## 2. Production Docker Deployment (< 4 MB Scratch Container)

ZeroFeed compiles into a single static binary with zero OS dependencies, running inside an ultra-minimal `scratch` container.

### `Dockerfile`
```dockerfile
# Build Stage
FROM golang:alpine AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags quic -ldflags="-s -w" -o zerofeed main.go

# Production Stage (Scratch - Zero OS vulnerabilities & < 4MB RAM)
FROM scratch
COPY --from=builder /app/zerofeed /zerofeed
EXPOSE 8443/tcp 8443/udp
ENTRYPOINT ["/zerofeed", "relay", "--port", "8443", "--quic", "--no-rate-limit"]
```

### `docker-compose.yml`
```yaml
version: '3.8'

services:
  zerofeed-relay:
    build: .
    container_name: zerofeed-relay
    restart: always
    ports:
      - "8443:8443/tcp"
      - "8443:8443/udp"
    environment:
      - GOMAXPROCS=2
    healthcheck:
      test: ["CMD-SHELL", "nc -z 127.0.0.1 8443 || exit 1"]
      interval: 30s
      timeout: 5s
      retries: 3
```

---

## 3. Fly.io Cloud Deployment (`fly.toml`)

For global zero-configuration deployments on Fly.io (e.g. Frankfurt `fra` datacenter):

```toml
app = "zerofeed-relay"
primary_region = "fra"

[build]
  dockerfile = "Dockerfile"

[[services]]
  internal_port = 8443
  protocol = "tcp"

  [[services.ports]]
    port = 443
    handlers = ["tls"]

  [[services.ports]]
    port = 8443
    handlers = ["tls"]

  [services.concurrency]
    type = "connections"
    hard_limit = 2000
    soft_limit = 1500

[[services]]
  internal_port = 8443
  protocol = "udp"

  [[services.ports]]
    port = 8443
```

---

## 4. Automatic Client Transport Fallback (Happy Eyeballs QUIC -> TCP)

The ZeroFeed CLI client includes automatic **Happy Eyeballs** transport fallback (`pkg/feed/publisher.go` and `pkg/feed/subscriber.go`):
1. **Primary Transport**: Dials UDP/QUIC multiplexed transport.
2. **Automatic Fallback**: If UDP is blocked by enterprise firewalls, CGNATs, or unrouted shared IPv4 networks within 1.5 seconds, the CLI automatically falls back to TCP (TLS 1.3).
3. **Zero Cryptographic Downgrade**: Both QUIC and TCP transports enforce identical E2EE PAKE (Argon2id) and AES-256-GCM framing.

---

## 5. Linux Systemd Service (`zerofeed-relay.service`)

For native deployment on Ubuntu, Debian, RHEL, or CentOS servers without Docker:

### Step 1: Install Binary
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags quic -ldflags="-s -w" -o /usr/local/bin/zerofeed main.go
chmod +x /usr/local/bin/zerofeed
useradd -r -s /bin/false zerofeed
```

### Step 2: Systemd Unit File (`/etc/systemd/system/zerofeed-relay.service`)
```ini
[Unit]
Description=ZeroFeed Zero-Knowledge Ephemeral Relay Node
After=network.target

[Service]
Type=simple
User=zerofeed
ExecStart=/usr/local/bin/zerofeed relay --port 8443 --quic
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536
MemoryMax=64M
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

### Step 3: Enable & Start Service
```bash
systemctl daemon-reload
systemctl enable --now zerofeed-relay
systemctl status zerofeed-relay
```

---

## 6. Multi-Region Global Subscriber Automation & Testing

To benchmark or deploy subscriber instances globally across Fly.io regions (e.g. Frankfurt `fra`, Tokyo `nrt`, Sydney `syd`, Washington `iad`, San Paolo `gru`), use the automated test runner [scripts/global_test.sh](../scripts/global_test.sh):

```bash
# Launch global subscribers and run local publisher 50 MB benchmark
./scripts/global_test.sh --pub --size 50 --regions "fra,nrt,syd,iad,gru"
```

### Key Infrastructure & Sizing Notes:
1. **VM Memory Sizing (`--vm-memory 512`)**:
   ZeroFeed subscribers lock memory into RAM using `crypto.LockMemory()` (`mlockall`) to prevent key material swapping. Fly Machine containers must be provisioned with at least **512 MB RAM** (`--vm-memory 512`). Micro-VMs with 256 MB will trigger Linux kernel OOM kills.
2. **Internal Mesh Routing (6PN)**:
   Inter-container connections within Fly.io use internal IPv6 mesh addressing (`zerofeed-relay.internal:8443`), bypassing edge TLS proxy resets. External clients (dev machines) connect via public endpoint `zerofeed-relay.fly.dev:8443`.

---

## 7. Prometheus Observability & Telemetry (`/metrics`)

ZeroFeed Relay includes a lock-free, atomic zero-knowledge telemetry exporter compliant with the Prometheus text format (`text/plain; version=0.0.4`).

### Enabling Prometheus Telemetry Endpoint
To launch the metrics HTTP server on port `9090`:
```bash
zerofeed relay --port 8443 --quic --metrics-port 9090
```

### Exported Metrics Overview

| Metric Name | Type | Description |
| :--- | :--- | :--- |
| `zerofeed_relay_uptime_seconds` | `gauge` | Total relay server uptime in seconds. |
| `zerofeed_relay_active_sessions` | `gauge` | Gauge of current active E2EE sessions in RAM. |
| `zerofeed_relay_sessions_created_total` | `counter` | Cumulative count of created sessions. |
| `zerofeed_relay_active_connections` | `gauge` | Gauge of active network socket connections. |
| `zerofeed_relay_bytes_transferred_total` | `counter` | Cumulative bytes relayed through server. |
| `zerofeed_relay_messages_relayed_total` | `counter` | Cumulative frames forwarded. |
| `zerofeed_relay_ratelimit_bans_total` | `counter` | Cumulative IP rate-limit bans. |
| `zerofeed_relay_malformed_packets_dropped_total` | `counter` | Cumulative invalid frames dropped. |

### Prometheus Scrape Configuration (`prometheus.yml`)
```yaml
scrape_configs:
  - job_name: 'zerofeed-relay'
    scrape_interval: 15s
    static_configs:
      - targets: ['zerofeed-relay.internal:9090']
```


