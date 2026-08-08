package protocol_test

import (
	"bytes"
	"testing"

	"github.com/zerofeed/zerofeed/pkg/protocol"
)

func TestEnvelopeEncodeDecode(t *testing.T) {
	var sessionID [protocol.SessionIDSize]byte
	copy(sessionID[:], []byte("0123456789abcdef"))

	var nonce [protocol.NonceSize]byte
	copy(nonce[:], []byte("123456789012"))

	payload := []byte("Hello ZeroFeed E2EE binary protocol stream!")

	originalEnv := &protocol.Envelope{
		Version:   protocol.Version,
		MsgType:   protocol.MsgTypeDataStream,
		SessionID: sessionID,
		Nonce:     nonce,
		Payload:   payload,
	}

	buf := new(bytes.Buffer)
	if err := protocol.Encode(buf, originalEnv); err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	decodedEnv, err := protocol.Decode(buf)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}

	if decodedEnv.Version != originalEnv.Version {
		t.Errorf("version mismatch: got %d, want %d", decodedEnv.Version, originalEnv.Version)
	}

	if decodedEnv.MsgType != originalEnv.MsgType {
		t.Errorf("msgType mismatch: got %d, want %d", decodedEnv.MsgType, originalEnv.MsgType)
	}

	if decodedEnv.SessionID != originalEnv.SessionID {
		t.Errorf("sessionID mismatch: got %x, want %x", decodedEnv.SessionID, originalEnv.SessionID)
	}

	if decodedEnv.Nonce != originalEnv.Nonce {
		t.Errorf("nonce mismatch: got %x, want %x", decodedEnv.Nonce, originalEnv.Nonce)
	}

	if !bytes.Equal(decodedEnv.Payload, originalEnv.Payload) {
		t.Errorf("payload mismatch: got %q, want %q", string(decodedEnv.Payload), string(originalEnv.Payload))
	}
}

func TestInvalidMagicHeader(t *testing.T) {
	invalidBuf := bytes.NewBuffer([]byte("BADM\x01\x04" + string(make([]byte, 32))))
	_, err := protocol.Decode(invalidBuf)
	if err != protocol.ErrInvalidMagic {
		t.Fatalf("expected ErrInvalidMagic, got %v", err)
	}
}
