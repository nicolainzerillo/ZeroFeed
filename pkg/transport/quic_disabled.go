//go:build !quic

package transport

import (
	"context"
	"errors"
	"net"
	"time"
)

type QuicStreamWrapper struct{}

func (w *QuicStreamWrapper) Read(b []byte) (n int, err error)   { return 0, errors.New("quic disabled") }
func (w *QuicStreamWrapper) Write(b []byte) (n int, err error)  { return 0, errors.New("quic disabled") }
func (w *QuicStreamWrapper) Close() error                       { return nil }
func (w *QuicStreamWrapper) LocalAddr() net.Addr                { return nil }
func (w *QuicStreamWrapper) RemoteAddr() net.Addr               { return nil }
func (w *QuicStreamWrapper) SetDeadline(t time.Time) error      { return nil }
func (w *QuicStreamWrapper) SetReadDeadline(t time.Time) error  { return nil }
func (w *QuicStreamWrapper) SetWriteDeadline(t time.Time) error { return nil }

var ErrQUICDisabled = errors.New("zerofeed/transport: QUIC transport disabled at build time (compile with -tags quic)")

// DialQUIC returns an error indicating QUIC support was not compiled in.
func DialQUIC(ctx context.Context, addr string) (*QuicStreamWrapper, error) {
	return nil, ErrQUICDisabled
}
