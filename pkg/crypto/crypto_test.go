package crypto_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/zerofeed/zerofeed/pkg/crypto"
)

func TestHKDFAndAEADCipher_TableDriven(t *testing.T) {
	tests := []struct {
		name          string
		secret        []byte
		sessionID     []byte
		plaintext     []byte
		aad           []byte
		corruptNonce  bool
		corruptAAD    bool
		corruptCipher bool
		expectErr     bool
	}{
		{
			name:      "Valid standard encryption and decryption",
			secret:    []byte("super-secret-pake-master-key"),
			sessionID: []byte("1234567890123456"),
			plaintext: []byte("Sensitive payload message in RAM only!"),
			aad:       []byte("session-auth-data"),
		},
		{
			name:          "Tampered ciphertext MAC check failure",
			secret:        []byte("super-secret-pake-master-key"),
			sessionID:     []byte("1234567890123456"),
			plaintext:     []byte("Sensitive payload message in RAM only!"),
			aad:           []byte("session-auth-data"),
			corruptCipher: true,
			expectErr:     true,
		},
		{
			name:       "Tampered AAD header check failure",
			secret:     []byte("super-secret-pake-master-key"),
			sessionID:  []byte("1234567890123456"),
			plaintext:  []byte("Sensitive payload message in RAM only!"),
			aad:        []byte("session-auth-data"),
			corruptAAD: true,
			expectErr:  true,
		},
		{
			name:         "Corrupted nonce check failure",
			secret:       []byte("super-secret-pake-master-key"),
			sessionID:    []byte("1234567890123456"),
			plaintext:    []byte("Sensitive payload message in RAM only!"),
			aad:          []byte("session-auth-data"),
			corruptNonce: true,
			expectErr:    true,
		},
		{
			name:      "Empty payload message",
			secret:    []byte("super-secret-pake-master-key"),
			sessionID: []byte("1234567890123456"),
			plaintext: []byte(""),
			aad:       []byte("header-aad"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := crypto.DeriveKey(tt.secret, tt.sessionID)
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

			ciphertext, nonce, err := cipher.Encrypt(tt.plaintext, nil, tt.aad)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			testCipher := append([]byte(nil), ciphertext...)
			testNonce := append([]byte(nil), nonce...)
			testAAD := append([]byte(nil), tt.aad...)

			if tt.corruptCipher && len(testCipher) > 0 {
				testCipher[0] ^= 0xFF
			}
			if tt.corruptNonce && len(testNonce) > 0 {
				testNonce[0] ^= 0xFF
			}
			if tt.corruptAAD && len(testAAD) > 0 {
				testAAD[0] ^= 0xFF
			}

			decrypted, err := cipher.Decrypt(testCipher, testNonce, testAAD)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error during decryption failure scenario, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected Decrypt failure: %v", err)
				}
				if !bytes.Equal(decrypted, tt.plaintext) {
					t.Fatalf("decrypted payload mismatch! got %q, want %q", decrypted, tt.plaintext)
				}
			}
		})
	}
}

func TestNewCipher_InvalidKeyLength(t *testing.T) {
	invalidKeys := [][]byte{
		nil,
		{},
		[]byte("short-key"),
		make([]byte, 16),
		make([]byte, 64),
	}
	for _, k := range invalidKeys {
		_, err := crypto.NewCipher(k)
		if err == nil {
			t.Errorf("expected error for invalid key length %d, got nil", len(k))
		}
	}
}

func TestCipher_UpdateKeyAndGetKey(t *testing.T) {
	initialKey := make([]byte, 32)
	for i := range initialKey {
		initialKey[i] = byte(i + 1)
	}

	cipher, err := crypto.NewCipher(initialKey)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}
	defer cipher.Close()

	gotKey := cipher.GetKey()
	if !bytes.Equal(gotKey, initialKey) {
		t.Fatalf("GetKey returned mismatch key! got %x, want %x", gotKey, initialKey)
	}
	crypto.ZeroBytes(gotKey)

	// Update key with invalid key size
	err = cipher.UpdateKey([]byte("invalid-size"))
	if err == nil {
		t.Fatal("expected error updating key with invalid size, got nil")
	}

	// Update key with valid key
	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(i + 42)
	}
	err = cipher.UpdateKey(newKey)
	if err != nil {
		t.Fatalf("UpdateKey failed: %v", err)
	}

	updatedKey := cipher.GetKey()
	if !bytes.Equal(updatedKey, newKey) {
		t.Fatalf("GetKey after UpdateKey returned mismatch! got %x, want %x", updatedKey, newKey)
	}
	crypto.ZeroBytes(updatedKey)
}

func TestCipher_DecryptInvalidInputs(t *testing.T) {
	key := make([]byte, 32)
	cipher, err := crypto.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	// Nonce wrong length
	_, err = cipher.Decrypt([]byte("ciphertext"), make([]byte, 8), nil)
	if err == nil {
		t.Error("expected error for invalid nonce length 8, got nil")
	}

	// Truncated ciphertext shorter than GCM tag size (16 bytes)
	_, err = cipher.Decrypt([]byte("short"), make([]byte, 12), nil)
	if err == nil {
		t.Error("expected error for truncated ciphertext, got nil")
	}

	cipher.Close()
	if cipher.GetKey() != nil {
		t.Error("expected GetKey to return nil after Close()")
	}
}

func TestConstructNonceRFC5116(t *testing.T) {
	salt := [4]byte{0x01, 0x02, 0x03, 0x04}
	seqNum := uint64(0x0102030405060708)
	nonce := crypto.ConstructNonceRFC5116(salt, seqNum)

	if len(nonce) != 12 {
		t.Fatalf("expected 12-byte nonce, got %d", len(nonce))
	}
	if !bytes.Equal(nonce[0:4], salt[:]) {
		t.Fatalf("salt portion mismatch: got %x, want %x", nonce[0:4], salt)
	}
}

func TestPAKEKeyExchange_SuccessAndErrorPaths(t *testing.T) {
	passphrase := []byte("quantum-falcon-orbit-99")

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

	// SessionKey before completion must fail
	_, err = pubPeer.SessionKey()
	if err == nil {
		t.Fatal("expected error calling SessionKey before handshake complete")
	}

	// Invalid message size update error
	err = pubPeer.Update([]byte("too-short"))
	if err == nil {
		t.Fatal("expected error updating PAKE peer with malformed message length")
	}

	// Subscriber initial message size
	subMsg := subPeer.Bytes()
	if len(subMsg) != crypto.SubWireMsgSize {
		t.Fatalf("expected subscriber wire msg size %d, got %d", crypto.SubWireMsgSize, len(subMsg))
	}

	if err := pubPeer.Update(subMsg); err != nil {
		t.Fatalf("pubPeer.Update failed: %v", err)
	}

	pubMsg := pubPeer.Bytes()
	if len(pubMsg) != crypto.PubWireMsgSize {
		t.Fatalf("expected publisher wire msg size %d, got %d", crypto.PubWireMsgSize, len(pubMsg))
	}

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
		t.Fatalf("PAKE derived keys mismatch! Pub: %x, Sub: %x", pubKey, subKey)
	}
}

func TestDeriveMasterKeyArgon2(t *testing.T) {
	pass := []byte("test-passphrase-argon2")
	k1 := crypto.DeriveMasterKeyArgon2(pass)
	defer crypto.ZeroBytes(k1)

	if len(k1) != crypto.KeySize {
		t.Fatalf("expected Argon2 key size %d, got %d", crypto.KeySize, len(k1))
	}

	k2 := crypto.DeriveMasterKeyArgon2(pass)
	defer crypto.ZeroBytes(k2)

	if !bytes.Equal(k1, k2) {
		t.Fatal("expected deterministic Argon2 derivation for identical passphrase")
	}

	emptyKey := crypto.DeriveMasterKeyArgon2(nil)
	defer crypto.ZeroBytes(emptyKey)

	if len(emptyKey) != crypto.KeySize {
		t.Fatalf("expected 32-byte key for empty passphrase, got %d", len(emptyKey))
	}
}

func TestDeriveBlindMatchTag(t *testing.T) {
	pass := []byte("rendezvous-channel-tag-test")
	tag1 := crypto.DeriveBlindMatchTag(pass)
	tag2 := crypto.DeriveBlindMatchTag(pass)

	if !bytes.Equal(tag1[:], tag2[:]) {
		t.Fatal("expected deterministic blind match tag for identical passphrase")
	}

	if bytes.Equal(tag1[:], make([]byte, 32)) {
		t.Fatal("blind match tag should not be all zeroes")
	}
}

func TestRatchetKey(t *testing.T) {
	currKey := make([]byte, 32)
	for i := range currKey {
		currKey[i] = byte(i + 1)
	}
	salt := []byte("ratchet-salt-12345")

	nextKey, err := crypto.RatchetKey(currKey, salt)
	if err != nil {
		t.Fatalf("RatchetKey failed: %v", err)
	}
	if len(nextKey) != 32 {
		t.Fatalf("expected ratcheted key length 32, got %d", len(nextKey))
	}
	if bytes.Equal(currKey, nextKey) {
		t.Fatal("ratcheted key must differ from current key")
	}
}

func TestCalculateSPKIFingerprint(t *testing.T) {
	mockCert := []byte("MOCK_DER_X509_CERTIFICATE_BYTES")
	fingerprint := crypto.CalculateSPKIFingerprint(mockCert)

	expected := sha256.Sum256(mockCert)
	if len(fingerprint) != 64 {
		t.Fatalf("expected 64 hex char fingerprint, got %d (%s)", len(fingerprint), fingerprint)
	}
	_ = expected
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

func TestPAKEKeyConfirmation(t *testing.T) {
	passphrase := []byte("confirm-test-passphrase-88")

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

	if err := pubPeer.Update(subPeer.Bytes()); err != nil {
		t.Fatalf("pubPeer.Update failed: %v", err)
	}
	if err := subPeer.Update(pubPeer.Bytes()); err != nil {
		t.Fatalf("subPeer.Update failed: %v", err)
	}

	pubTag, err := pubPeer.ConfirmTag()
	if err != nil {
		t.Fatalf("pubPeer.ConfirmTag failed: %v", err)
	}
	subTag, err := subPeer.ConfirmTag()
	if err != nil {
		t.Fatalf("subPeer.ConfirmTag failed: %v", err)
	}

	if err := subPeer.VerifyPeerConfirm(pubTag); err != nil {
		t.Fatalf("subPeer failed to verify pubTag: %v", err)
	}
	if err := pubPeer.VerifyPeerConfirm(subTag); err != nil {
		t.Fatalf("pubPeer failed to verify subTag: %v", err)
	}

	// Corrupted tag verification must fail
	pubTag[0] ^= 0xFF
	if err := subPeer.VerifyPeerConfirm(pubTag); err == nil {
		t.Fatal("expected error verifying corrupted peer confirmation tag, got nil")
	}
}
