package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

const (
	// KeySize is the byte size for AES-256 symmetric keys (32 bytes).
	KeySize = 32
	// NonceSize is the standard nonce size for AES-GCM (12 bytes).
	NonceSize = 12
	// DomainInfo is the domain separation context string for ZeroFeed key derivation.
	DomainInfo = "zerofeed-v2-hkdf-aead"
)

var (
	ErrDecryptionFailed = errors.New("zerofeed/crypto: AEAD decryption failed or MAC authentication tag mismatch")
	ErrInvalidKeySize   = errors.New("zerofeed/crypto: key size must be 32 bytes")
	ErrInvalidNonceSize = errors.New("zerofeed/crypto: nonce size must be 12 bytes")
	ErrEmptySecret      = errors.New("zerofeed/crypto: secret cannot be empty")
)

// HKDFSHA256 derives pseudo-random key material using HKDF (RFC 5869) with SHA-256.
func HKDFSHA256(secret, salt, info []byte, length int) ([]byte, error) {
	if len(secret) == 0 {
		return nil, ErrEmptySecret
	}
	if len(salt) == 0 {
		salt = []byte("zerofeed-v2-default-salt")
	}

	// Extract step: PRK = HMAC-Hash(salt, IKM)
	extractor := hmac.New(sha256.New, salt)
	extractor.Write(secret)
	prk := extractor.Sum(nil)
	defer ZeroBytes(prk)

	// Expand step: OKM = HMAC-Hash(PRK, info || 0x01 || ...)
	var okm []byte
	var prev []byte
	counter := byte(1)

	for len(okm) < length {
		expander := hmac.New(sha256.New, prk)
		expander.Write(prev)
		expander.Write(info)
		expander.Write([]byte{counter})
		nextPrev := expander.Sum(nil)
		if len(prev) > 0 {
			ZeroBytes(prev)
		}
		prev = nextPrev
		okm = append(okm, prev...)
		counter++
	}
	if len(prev) > 0 {
		ZeroBytes(prev)
	}

	result := make([]byte, length)
	copy(result, okm[:length])
	ZeroBytes(okm)
	return result, nil
}

// DeriveKey derives a deterministic 32-byte AES-256 key from secret and session ID using HKDF-SHA256.
func DeriveKey(secret []byte, sessionID []byte) ([]byte, error) {
	salt := append([]byte("zerofeed-v2-session-key-salt:"), sessionID...)
	defer ZeroBytes(salt)
	return HKDFSHA256(secret, salt, []byte(DomainInfo), KeySize)
}

// GenerateNonce creates a cryptographically secure 12-byte random nonce.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("zerofeed/crypto: failed to generate random nonce: %w", err)
	}
	return nonce, nil
}

// ConstructNonceRFC5116 constructs an RFC 5116 12-byte AEAD nonce from a 4-byte session salt and uint64 sequence counter.
func ConstructNonceRFC5116(sessionSalt [4]byte, seqNum uint64) [NonceSize]byte {
	var nonce [NonceSize]byte
	copy(nonce[0:4], sessionSalt[:])
	binary.BigEndian.PutUint64(nonce[4:12], seqNum)
	return nonce
}

// CalculateSPKIFingerprint returns the hex-encoded SHA-256 digest of a certificate's SPKI raw bytes.
func CalculateSPKIFingerprint(rawCertDER []byte) string {
	cert, err := x509.ParseCertificate(rawCertDER)
	if err != nil {
		h := sha256.Sum256(rawCertDER)
		return hex.EncodeToString(h[:])
	}
	h := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h[:])
}

// Cipher encapsulates AES-256-GCM AEAD symmetric encryption operations.
type Cipher struct {
	aead cipher.AEAD
	key  []byte
}

// NewCipher constructs a new AEAD Cipher from a 32-byte symmetric key.
func NewCipher(key []byte) (*Cipher, error) {
	if len(key) != KeySize {
		return nil, ErrInvalidKeySize
	}

	keyCopy := make([]byte, KeySize)
	copy(keyCopy, key)

	block, err := aes.NewCipher(keyCopy)
	if err != nil {
		ZeroBytes(keyCopy)
		return nil, fmt.Errorf("zerofeed/crypto: failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		ZeroBytes(keyCopy)
		return nil, fmt.Errorf("zerofeed/crypto: failed to create AES-GCM: %w", err)
	}

	return &Cipher{
		aead: aead,
		key:  keyCopy,
	}, nil
}

// RatchetKey derives a new 32-byte key from currentKey and salt via HKDF-SHA256.
func RatchetKey(currentKey []byte, salt []byte) ([]byte, error) {
	info := []byte("zerofeed-v2-key-ratchet-pfs")
	return HKDFSHA256(currentKey, salt, info, KeySize)
}

// UpdateKey safely replaces stored AEAD instance with newKey and zeroizes the old key.
func (c *Cipher) UpdateKey(newKey []byte) error {
	if len(newKey) != KeySize {
		return ErrInvalidKeySize
	}

	keyCopy := make([]byte, KeySize)
	copy(keyCopy, newKey)

	block, err := aes.NewCipher(keyCopy)
	if err != nil {
		ZeroBytes(keyCopy)
		return fmt.Errorf("zerofeed/crypto: failed to create AES cipher for rekey: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		ZeroBytes(keyCopy)
		return fmt.Errorf("zerofeed/crypto: failed to create AES-GCM for rekey: %w", err)
	}

	if c.key != nil {
		ZeroBytes(c.key)
	}

	c.aead = aead
	c.key = keyCopy
	return nil
}

// GetKey returns a copy of the active 32-byte key (caller must zeroize).
func (c *Cipher) GetKey() []byte {
	if c.key == nil {
		return nil
	}
	keyCopy := make([]byte, KeySize)
	copy(keyCopy, c.key)
	return keyCopy
}

// Encrypt encrypts plaintext using AES-256-GCM AEAD with the given nonce and optional AAD.
func (c *Cipher) Encrypt(plaintext []byte, nonce []byte, aad []byte) ([]byte, []byte, error) {
	if nonce == nil {
		var err error
		nonce, err = GenerateNonce()
		if err != nil {
			return nil, nil, err
		}
	} else if len(nonce) != NonceSize {
		return nil, nil, ErrInvalidNonceSize
	}

	ciphertext := c.aead.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nonce, nil
}

// Decrypt authenticates and decrypts ciphertext using the provided nonce and optional AAD.
func (c *Cipher) Decrypt(ciphertext []byte, nonce []byte, aad []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, ErrInvalidNonceSize
	}

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// Close zeroes out the stored symmetric key in memory.
func (c *Cipher) Close() {
	if c.key != nil {
		ZeroBytes(c.key)
		c.key = nil
	}
}

// SASVisualEmojis contains curated, easily distinguishable emojis for SAS visual verification.
var SASVisualEmojis = []string{
	"🛡️", "⚡", "🚀", "🔒", "🔑", "🐺", "🦅", "💎",
	"🎯", "🔥", "🌊", "🔮", "🏆", "🌟", "⚓", "👑",
}

// CalculateSAS computes a deterministic 8-character hex string and 4-emoji visual badge from key material.
func CalculateSAS(key []byte) (hexSAS string, emojiSAS string) {
	h := sha256.Sum256(key)
	hexSAS = fmt.Sprintf("%08X", binary.BigEndian.Uint32(h[0:4]))
	idx1 := int(h[4]) % len(SASVisualEmojis)
	idx2 := int(h[5]) % len(SASVisualEmojis)
	idx3 := int(h[6]) % len(SASVisualEmojis)
	idx4 := int(h[7]) % len(SASVisualEmojis)
	emojiSAS = SASVisualEmojis[idx1] + SASVisualEmojis[idx2] + SASVisualEmojis[idx3] + SASVisualEmojis[idx4]
	return hexSAS, emojiSAS
}
