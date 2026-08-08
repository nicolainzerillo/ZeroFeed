//go:build quic

package transport_test

import (
	"context"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/zerofeed/zerofeed/pkg/transport"
)

func TestQUICStreamAndDatagramTransport(t *testing.T) {
	tlsConfig, err := transport.GenerateEphemeralTLSConfig()
	if err != nil {
		t.Fatalf("GenerateEphemeralTLSConfig failed: %v", err)
	}

	quicConfig := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 5 * time.Second,
	}

	listener, err := quic.ListenAddr("127.0.0.1:0", tlsConfig, quicConfig)
	if err != nil {
		t.Fatalf("ListenAddr failed: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().String()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Server goroutine accepting QUIC connection, stream, and datagram
	errChan := make(chan error, 1)
	go func() {
		conn, err := listener.Accept(ctx)
		if err != nil {
			errChan <- err
			return
		}

		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			errChan <- err
			return
		}

		buf := make([]byte, 100)
		n, err := stream.Read(buf)
		if err != nil {
			errChan <- err
			return
		}

		if string(buf[:n]) != "HELLO_QUIC_STREAM" {
			t.Errorf("unexpected stream msg: %s", string(buf[:n]))
		}

		// Echo back stream payload
		_, _ = stream.Write([]byte("ACK_QUIC_STREAM"))

		// Receive Datagram (VoIP style)
		dg, err := conn.ReceiveDatagram(ctx)
		if err != nil {
			errChan <- err
			return
		}

		if string(dg) != "VOIP_AUDIO_FRAME_01" {
			t.Errorf("unexpected datagram msg: %s", string(dg))
		}

		errChan <- nil
	}()

	// Client connecting via DialQUIC
	clientWrapper, err := transport.DialQUIC(ctx, addr)
	if err != nil {
		t.Fatalf("DialQUIC failed: %v", err)
	}
	defer clientWrapper.Close()

	_, err = clientWrapper.Write([]byte("HELLO_QUIC_STREAM"))
	if err != nil {
		t.Fatalf("client Write failed: %v", err)
	}

	respBuf := make([]byte, 100)
	n, err := clientWrapper.Read(respBuf)
	if err != nil {
		t.Fatalf("client Read failed: %v", err)
	}

	if string(respBuf[:n]) != "ACK_QUIC_STREAM" {
		t.Fatalf("expected ACK_QUIC_STREAM, got %s", string(respBuf[:n]))
	}

	// Send VoIP Datagram
	if err := clientWrapper.SendDatagram([]byte("VOIP_AUDIO_FRAME_01")); err != nil {
		t.Fatalf("SendDatagram failed: %v", err)
	}

	if err := <-errChan; err != nil {
		t.Fatalf("server error: %v", err)
	}
}
