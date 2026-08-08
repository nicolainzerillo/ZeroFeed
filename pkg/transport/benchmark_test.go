//go:build quic

package transport_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/zerofeed/zerofeed/pkg/transport"
)

func BenchmarkTCPThroughput4KB(b *testing.B) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Listen failed: %v", err)
	}
	defer l.Close()

	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		_, _ = io.Copy(io.Discard, conn)
	}()

	client, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		b.Fatalf("Dial failed: %v", err)
	}
	defer client.Close()

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, err := client.Write(payload)
		if err != nil {
			b.Fatalf("Write failed: %v", err)
		}
	}
}

func BenchmarkQUICThroughput4KB(b *testing.B) {
	tlsConfig, err := transport.GenerateEphemeralTLSConfig()
	if err != nil {
		b.Fatalf("GenerateEphemeralTLSConfig failed: %v", err)
	}

	quicConfig := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 5 * time.Second,
	}

	listener, err := quic.ListenAddr("127.0.0.1:0", tlsConfig, quicConfig)
	if err != nil {
		b.Fatalf("ListenAddr failed: %v", err)
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	go func() {
		qConn, err := listener.Accept(ctx)
		if err != nil {
			return
		}

		stream, err := qConn.AcceptStream(ctx)
		if err != nil {
			return
		}
		defer stream.Close()

		_, _ = io.Copy(io.Discard, stream)
	}()

	clientWrapper, err := transport.DialQUIC(ctx, listener.Addr().String())
	if err != nil {
		b.Fatalf("DialQUIC failed: %v", err)
	}
	defer clientWrapper.Close()

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		_, err := clientWrapper.Write(payload)
		if err != nil {
			b.Fatalf("Write failed: %v", err)
		}
	}
}
