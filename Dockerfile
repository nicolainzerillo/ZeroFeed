# ==========================================
# Stage 1: Build static ZeroFeed binary
# ==========================================
FROM golang:1.24-alpine AS builder

WORKDIR /src

# Install git and ca-certificates
RUN apk add --no-cache git ca-certificates

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build static Linux binary (ARM64/AMD64) with QUIC support
RUN CGO_ENABLED=0 GOOS=linux go build -tags quic -ldflags="-s -w" -o /bin/zerofeed main.go

# ==========================================
# Stage 2: Minimal non-root production image
# ==========================================
FROM alpine:3.20

LABEL org.opencontainers.image.title="ZeroFeed Relay Node" \
      org.opencontainers.image.description="Ephemeral, RAM-only, zero-knowledge E2EE pub/sub relay node" \
      org.opencontainers.image.vendor="ZeroFeed" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 10001 -g zerofeed zerofeed

COPY --from=builder /bin/zerofeed /usr/local/bin/zerofeed

USER zerofeed:zerofeed

# Default Ports:
# 8443: TCP Relay / QUIC UDP
# 8444: WebSocket (WSS) Bridge for Web WASM
# 9090: Prometheus Metrics Exporter
EXPOSE 8443/tcp 8443/udp 8444/tcp 9090/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:9090/metrics || exit 1

ENTRYPOINT ["/usr/local/bin/zerofeed", "relay"]
CMD ["--port", "8443", "--ws-port", "8444", "--metrics-addr", "0.0.0.0:9090", "--log-format", "json"]
