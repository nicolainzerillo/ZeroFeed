package e2e_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/zerofeed/zerofeed/pkg/crypto"
	"github.com/zerofeed/zerofeed/pkg/protocol"
	"github.com/zerofeed/zerofeed/pkg/relay"
)

func TestCiphertextTamperingRejection(t *testing.T) {
	key := []byte("SECURE_TAMPER_PROOF_KEY_32BYTES!")
	ciph, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}
	defer ciph.Close()

	plaintext := []byte("CONFIDENTIAL_PAYLOAD_STRING")
	ciphertext, nonce, err := ciph.Encrypt(plaintext, nil, nil)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// 1. Decrypt valid ciphertext
	decrypted, err := ciph.Decrypt(ciphertext, nonce, nil)
	if err != nil {
		t.Fatalf("valid decryption failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted payload mismatch")
	}

	// 2. Tamper with a single byte in ciphertext (simulate MAC tag or ciphertext forgery)
	tamperedCiphertext := make([]byte, len(ciphertext))
	copy(tamperedCiphertext, ciphertext)
	tamperedCiphertext[len(tamperedCiphertext)-1] ^= 0xFF

	// 3. Attempt decryption on tampered payload: MUST FAIL
	_, err = ciph.Decrypt(tamperedCiphertext, nonce, nil)
	if err == nil {
		t.Fatalf("expected decryption error on tampered ciphertext, but got nil")
	}
	if err != crypto.ErrDecryptionFailed {
		t.Logf("correctly rejected tampered ciphertext with error: %v", err)
	}
}

func TestInvalidPAKEPayloadTampering(t *testing.T) {
	passphrase := []byte("secret-tamper-passphrase")
	pakePub, err := crypto.NewPAKEPublisher(passphrase)
	if err != nil {
		t.Fatalf("NewPAKEPublisher failed: %v", err)
	}
	defer pakePub.Close()

	pakeSub, err := crypto.NewPAKESubscriber(passphrase)
	if err != nil {
		t.Fatalf("NewPAKESubscriber failed: %v", err)
	}
	defer pakeSub.Close()

	// 1. Feed invalid short payload (16 bytes instead of 32)
	invalidShortPayload := []byte("1234567890123456")
	err = pakeSub.Update(invalidShortPayload)
	if err == nil {
		t.Fatalf("expected PAKE update error on short payload, got nil")
	}

	// 2. Corrupt subscriber payload during Publisher PAKE update
	corruptPayload := make([]byte, crypto.SubWireMsgSize)
	for i := range corruptPayload {
		corruptPayload[i] = 0xFF
	}
	err = pakePub.Update(corruptPayload)
	if err == nil {
		t.Fatalf("expected PAKE update error on corrupt payload, got nil")
	}

	_, err = pakePub.SessionKey()
	if err == nil {
		t.Fatalf("expected SessionKey error on corrupted PAKE update, got nil")
	}
}

func TestProtocolHeaderTamperingRejection(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen failed: %v", err)
	}
	defer l.Close()

	srv := relay.NewServer(l.Addr().String())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer conn.Close()

	// Send invalid magic header ('BADM' instead of 'ZFED')
	badEnvelope := &protocol.Envelope{
		Version:   protocol.Version,
		MsgType:   protocol.MsgTypePAKEInitPub,
		SessionID: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Payload:   []byte("INVALID_MAGIC"),
	}

	rawBuf := make([]byte, protocol.HeaderSize)
	protocol.SerializeHeader(rawBuf, badEnvelope.Version, badEnvelope.MsgType, badEnvelope.SessionID, badEnvelope.Nonce, uint32(len(badEnvelope.Payload)))
	copy(rawBuf[0:4], []byte("BADM")) // Tamper magic header

	_, err = conn.Write(rawBuf)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Relay server should immediately close connection on invalid magic header
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	readBuf := make([]byte, 100)
	n, err := conn.Read(readBuf)
	if n > 0 {
		t.Fatalf("expected 0 bytes from relay on bad magic header, got %d", n)
	}
	fmt.Printf("Relay correctly rejected bad magic header connection: %v\n", err)
}
