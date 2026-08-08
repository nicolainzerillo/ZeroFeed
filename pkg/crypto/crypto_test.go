package crypto_test

import (
	"bytes"
	"testing"

	"github.com/zerofeed/zerofeed/pkg/crypto"
)

func TestHKDFAndAEADCipher(t *testing.T) {
	sharedSecret := []byte("super-secret-pake-master-key")
	sessionID := []byte("1234567890123456")

	key, err := crypto.DeriveKey(sharedSecret, sessionID)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if len(key) != crypto.KeySize {
		t.Fatalf("expected key length %d, got %d", crypto.KeySize, len(key))
	}

	cipher, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}
	defer cipher.Close()

	plaintext := []byte("Sensitive payload message in RAM only!")
	aad := []byte("session-auth-data")

	ciphertext, nonce, err := cipher.Encrypt(plaintext, nil, aad)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := cipher.Decrypt(ciphertext, nonce, aad)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("expected decrypted text %q, got %q", string(plaintext), string(decrypted))
	}

	// Test tamper detection (failed MAC verification)
	ciphertext[0] ^= 0xFF
	_, err = cipher.Decrypt(ciphertext, nonce, aad)
	if err == nil {
		t.Fatalf("expected error decrypting tampered ciphertext, got nil")
	}
}

func TestPAKEKeyExchangeSuccess(t *testing.T) {
	passphrase := []byte("5-omega-phoenix")

	pubPeer, err := crypto.NewPAKEPublisher(passphrase)
	if err != nil {
		t.Fatalf("NewPAKEPublisher failed: %v", err)
	}
	defer pubPeer.Close()

	subPeer, err := crypto.NewPAKESubscriber(passphrase)
	if err != nil {
		t.Fatalf("NewPAKESubscriber failed: %v", err)
	}
	defer subPeer.Close()

	// Subscriber sends initial message (1216 bytes)
	subMsg := subPeer.Bytes()
	if len(subMsg) != crypto.SubWireMsgSize {
		t.Fatalf("expected subscriber message size %d, got %d", crypto.SubWireMsgSize, len(subMsg))
	}

	// Publisher updates with subscriber message and generates response message (1120 bytes)
	if err := pubPeer.Update(subMsg); err != nil {
		t.Fatalf("pubPeer.Update failed: %v", err)
	}

	pubMsg := pubPeer.Bytes()
	if len(pubMsg) != crypto.PubWireMsgSize {
		t.Fatalf("expected publisher message size %d, got %d", crypto.PubWireMsgSize, len(pubMsg))
	}

	// Subscriber updates with publisher response message
	if err := subPeer.Update(pubMsg); err != nil {
		t.Fatalf("subPeer.Update failed: %v", err)
	}

	pubKey, err := pubPeer.SessionKey()
	if err != nil {
		t.Fatalf("pubPeer.SessionKey failed: %v", err)
	}

	subKey, err := subPeer.SessionKey()
	if err != nil {
		t.Fatalf("subPeer.SessionKey failed: %v", err)
	}

	if !bytes.Equal(pubKey, subKey) {
		t.Fatalf("PAKE derived session keys do not match!\nPublisher: %x\nSubscriber: %x", pubKey, subKey)
	}
}

func TestPAKEKeyExchangeMismatchPassphrase(t *testing.T) {
	pubPeer, _ := crypto.NewPAKEPublisher([]byte("correct-passphrase"))
	subPeer, _ := crypto.NewPAKESubscriber([]byte("wrong-passphrase"))

	subMsg := subPeer.Bytes()
	pubErr := pubPeer.Update(subMsg)
	pubMsg := pubPeer.Bytes()
	subErr := subPeer.Update(pubMsg)

	pubKey, pubKeyErr := pubPeer.SessionKey()
	subKey, subKeyErr := subPeer.SessionKey()

	if pubErr == nil && subErr == nil && pubKeyErr == nil && subKeyErr == nil && bytes.Equal(pubKey, subKey) {
		t.Fatalf("expected key exchange failure or non-matching session keys for mismatched passphrases!")
	}
}

func TestMemZero(t *testing.T) {
	b := []byte("secret-key-material")
	crypto.ZeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte at index %d was not zeroed: %d", i, v)
		}
	}
}

func TestCalculateSAS(t *testing.T) {
	key1 := []byte("test-session-key-1-32-bytes-long!")
	hex1, emoji1 := crypto.CalculateSAS(key1)
	if len(hex1) != 8 {
		t.Fatalf("expected hex SAS length 8, got %d (%s)", len(hex1), hex1)
	}
	if len(emoji1) == 0 {
		t.Fatalf("expected non-empty emoji SAS")
	}

	key2 := []byte("test-session-key-1-32-bytes-long!")
	hex2, emoji2 := crypto.CalculateSAS(key2)
	if hex1 != hex2 || emoji1 != emoji2 {
		t.Fatalf("expected deterministic SAS output for identical keys")
	}
}

