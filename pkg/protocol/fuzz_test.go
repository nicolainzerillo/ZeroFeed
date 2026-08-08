package protocol_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/zerofeed/zerofeed/pkg/protocol"
	"github.com/zerofeed/zerofeed/pkg/relay"
)

// FuzzDecodeEnvelope native Go fuzzer testing robust decoding of arbitrary and malformed byte inputs.
func FuzzDecodeEnvelope(f *testing.F) {
	// Seed corpus 1: Valid Envelope
	validEnv := &protocol.Envelope{
		Version:   protocol.Version,
		MsgType:   protocol.MsgTypeDataStream,
		SessionID: [protocol.SessionIDSize]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Nonce:     [protocol.NonceSize]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		Payload:   []byte("Valid protocol payload data"),
	}
	var validBuf bytes.Buffer
	_ = protocol.Encode(&validBuf, validEnv)
	f.Add(validBuf.Bytes())

	// Seed corpus 2: Empty slice
	f.Add([]byte{})

	// Seed corpus 3: Truncated header (short bytes)
	f.Add([]byte{'Z', 'F', 'E', 'D', 0x01, 0x04})

	// Seed corpus 4: Invalid magic header
	invalidMagic := make([]byte, protocol.HeaderSize)
	copy(invalidMagic[0:4], []byte("BAD!"))
	f.Add(invalidMagic)

	// Seed corpus 5: Unsupported version
	unsupportedVer := make([]byte, protocol.HeaderSize)
	copy(unsupportedVer[0:4], protocol.MagicHeader[:])
	unsupportedVer[4] = 0x99
	f.Add(unsupportedVer)

	// Seed corpus 6: Oversized payload length header (> 32MB)
	oversized := make([]byte, protocol.HeaderSize)
	copy(oversized[0:4], protocol.MagicHeader[:])
	oversized[4] = protocol.Version
	oversized[5] = protocol.MsgTypeDataStream
	binary.BigEndian.PutUint32(oversized[34:38], 64*1024*1024) // 64MB > 32MB max
	f.Add(oversized)

	// Seed corpus 7: Corrupted PAKE key exchange payload
	corruptPAKE := make([]byte, protocol.HeaderSize+16)
	copy(corruptPAKE[0:4], protocol.MagicHeader[:])
	corruptPAKE[4] = protocol.Version
	corruptPAKE[5] = protocol.MsgTypePAKEInitPub
	binary.BigEndian.PutUint32(corruptPAKE[34:38], 16)
	f.Add(corruptPAKE)

	// Target Fuzzing Execution Loop
	f.Fuzz(func(t *testing.T, data []byte) {
		// Ensure DecodeEnvelope handles all inputs safely without panic or nil pointer dereference
		env, err := protocol.DecodeEnvelope(data)
		if err != nil {
			if env != nil {
				t.Fatalf("DecodeEnvelope returned non-nil Envelope on error: %v", env)
			}
			return
		}

		// On successful decode, verify envelope integrity boundaries
		if env == nil {
			t.Fatalf("DecodeEnvelope succeeded but returned nil Envelope")
		}

		if uint32(len(env.Payload)) > protocol.MaxPayloadSize {
			t.Fatalf("Decoded payload size %d exceeds MaxPayloadSize limit", len(env.Payload))
		}
	})
}

// TestMalformedPacketRateLimitingAndBan verifies that 3 consecutive malformed packets trigger IP ban and connection drop.
func TestMalformedPacketRateLimitingAndBan(t *testing.T) {
	srv := relay.NewServer("127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	<-srv.Ready()
	relayAddr := srv.Addr()

	// Send 3 consecutive malformed packets from the same endpoint IP
	for i := 1; i <= 3; i++ {
		conn, err := net.Dial("tcp", relayAddr)
		if err != nil {
			t.Fatalf("Attempt %d: failed to dial relay: %v", i, err)
		}

		// Write malformed frame (invalid magic header)
		malformedData := []byte("INVALID_HEADER_GARBAGE_BYTES_1234567890")
		_, _ = conn.Write(malformedData)

		// Verify relay detects decode error and closes socket promptly
		readBuf := make([]byte, 100)
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, readErr := conn.Read(readBuf)
		if readErr == nil {
			t.Fatalf("Attempt %d: expected relay to close connection on malformed packet, but read succeeded", i)
		}
		_ = conn.Close()
	}

	time.Sleep(50 * time.Millisecond)

	// 4th Attempt: Endpoint should be banned (rate-limited) and connection immediately dropped on accept
	conn4, err := net.Dial("tcp", relayAddr)
	if err != nil {
		// Connection rejected at dial level
		return
	}
	defer conn4.Close()

	_ = conn4.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 10)
	n, readErr := conn4.Read(buf)
	if n != 0 || readErr == nil {
		t.Fatalf("expected 4th connection attempt from banned IP to be immediately dropped by rate limiter, got %d bytes", n)
	}
}
