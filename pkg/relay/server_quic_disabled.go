//go:build !quic

package relay

import (
	"context"
	"errors"
)

// ErrQUICDisabled is returned when QUIC listener is requested on a binary compiled without the quic build tag.
var ErrQUICDisabled = errors.New("zerofeed/relay: QUIC listener disabled at build time (compile with -tags quic)")

// StartQUIC returns an error indicating QUIC support was not compiled in.
func (srv *Server) StartQUIC(ctx context.Context) error {
	return ErrQUICDisabled
}
