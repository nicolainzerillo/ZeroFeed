# Build Stage
FROM golang:alpine AS builder
WORKDIR /app
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags quic -ldflags="-s -w" -o zerofeed main.go

# Production Stage (Scratch - Zero OS vulnerabilities & < 4MB Image)
FROM scratch
COPY --from=builder /app/zerofeed /zerofeed
EXPOSE 8443/tcp 8443/udp 8444/tcp
ENTRYPOINT ["/zerofeed", "relay", "--port", "8443", "--ws-port", "8444", "--quic", "--no-rate-limit"]
