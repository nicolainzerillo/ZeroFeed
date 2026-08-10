# Build Stage
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -tags quic -ldflags="-s -w" -o zerofeed main.go

# Production Stage (Scratch - Zero OS footprint, Zero persistent disk, RAM-only)
FROM scratch
COPY --from=builder /app/zerofeed /zerofeed
EXPOSE 8443/tcp 8443/udp 8444/tcp 9090/tcp
ENTRYPOINT ["/zerofeed", "relay", "--port", "8443", "--ws-port", "8444", "--quic", "--no-rate-limit", "--metrics-addr", "0.0.0.0:9090"]
