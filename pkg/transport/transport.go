package transport

import (
	"context"
)

type Mode string

const (
	ModeTCP  Mode = "tcp"
	ModeQUIC Mode = "quic"
)

// DatagramConn is an interface for loss-tolerant datagram transport (e.g. VoIP / real-time media over QUIC).
type DatagramConn interface {
	SendDatagram(b []byte) error
	ReceiveDatagram(ctx context.Context) ([]byte, error)
}
