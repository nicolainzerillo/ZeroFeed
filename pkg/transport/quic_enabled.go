//go:build quic

package transport

import (
	"context"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// QuicStreamWrapper wraps a quic.Stream to implement net.Conn interface for seamless protocol framing.
type QuicStreamWrapper struct {
	*quic.Stream
	conn *quic.Conn
}

func NewQuicStreamWrapper(stream *quic.Stream, conn *quic.Conn) *QuicStreamWrapper {
	return &QuicStreamWrapper{
		Stream: stream,
		conn:   conn,
	}
}

func (w *QuicStreamWrapper) LocalAddr() net.Addr {
	return w.conn.LocalAddr()
}

func (w *QuicStreamWrapper) RemoteAddr() net.Addr {
	return w.conn.RemoteAddr()
}

func (w *QuicStreamWrapper) SetDeadline(t time.Time) error {
	_ = w.Stream.SetReadDeadline(t)
	return w.Stream.SetWriteDeadline(t)
}

func (w *QuicStreamWrapper) SendDatagram(b []byte) error {
	return w.conn.SendDatagram(b)
}

func (w *QuicStreamWrapper) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	return w.conn.ReceiveDatagram(ctx)
}

// DialQUIC connects to a QUIC relay endpoint using in-memory TLS 1.3 config and enables QUIC datagrams.
func DialQUIC(ctx context.Context, addr string) (*QuicStreamWrapper, error) {
	tlsConfig, err := GenerateEphemeralTLSConfig()
	if err != nil {
		return nil, err
	}

	quicConfig := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 5 * time.Second,
	}

	conn, err := quic.DialAddr(ctx, addr, tlsConfig, quicConfig)
	if err != nil {
		return nil, err
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "failed to open stream")
		return nil, err
	}

	return NewQuicStreamWrapper(stream, conn), nil
}
