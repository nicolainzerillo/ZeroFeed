package crypto

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	// UniformWireMsgSize is the standardized byte size for ALL PAKE payloads (1280B IPv6 Min MTU).
	UniformWireMsgSize = 1280
	// RawPubWireMsgSize is the raw unpadded byte size of Publisher's PAKE payload (32B X25519 + 1088B ML-KEM-768 ciphertext).
	RawPubWireMsgSize = 1120
	// RawSubWireMsgSize is the raw unpadded byte size of Subscriber's PAKE payload (32B X25519 + 1184B ML-KEM-768 encapsulation key).
	RawSubWireMsgSize = 1216

	// Backwards compatibility aliases
	PubWireMsgSize = UniformWireMsgSize
	SubWireMsgSize = UniformWireMsgSize
)

var (
	ErrPAKEFailed     = errors.New("zerofeed/crypto: PAKE authentication key exchange failed")
	ErrInvalidPeerMsg = errors.New("zerofeed/crypto: invalid PAKE peer payload message")
)

// PAKEPeer handles a Password-Authenticated Key Exchange session using Hybrid X25519 + ML-KEM-768.
type PAKEPeer struct {
	privKey    *ecdh.PrivateKey
	mlkemDecap *mlkem.DecapsulationKey768
	pubBytes   []byte
	role       int // 1 = Publisher, 2 = Subscriber
	sharedKey  []byte
	macTag     []byte
	passphrase []byte
}

// NewPAKEPublisher initializes a PAKE actor for Publisher (Role 1).
func NewPAKEPublisher(passphrase []byte) (*PAKEPeer, error) {
	return newPAKEPeer(passphrase, 1)
}

// NewPAKESubscriber initializes a PAKE actor for Subscriber (Role 2).
func NewPAKESubscriber(passphrase []byte) (*PAKEPeer, error) {
	return newPAKEPeer(passphrase, 2)
}

func newPAKEPeer(passphrase []byte, role int) (*PAKEPeer, error) {
	if len(passphrase) == 0 {
		return nil, ErrEmptySecret
	}

	curve := ecdh.X25519()
	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("zerofeed/crypto: failed to generate ECDH key: %w", err)
	}

	pubRawX25519 := privKey.PublicKey().Bytes()

	passCopy := make([]byte, len(passphrase))
	copy(passCopy, passphrase)

	peer := &PAKEPeer{
		privKey:    privKey,
		role:       role,
		passphrase: passCopy,
	}

	if role == 2 {
		// Subscriber (Role 2) generates ML-KEM-768 Decapsulation Key
		decapKey, err := mlkem.GenerateKey768()
		if err != nil {
			ZeroBytes(passCopy)
			return nil, fmt.Errorf("zerofeed/crypto: failed to generate ML-KEM key: %w", err)
		}
		peer.mlkemDecap = decapKey

		encapKeyBytes := decapKey.EncapsulationKey().Bytes()
		pubRaw := append(append([]byte(nil), pubRawX25519...), encapKeyBytes...)

		// Pad raw payload to UniformWireMsgSize (1280B) using CSPRNG random noise
		pubPadded := make([]byte, UniformWireMsgSize)
		if _, err := rand.Read(pubPadded[len(pubRaw):]); err != nil {
			ZeroBytes(passCopy)
			return nil, fmt.Errorf("zerofeed/crypto: failed to generate random padding: %w", err)
		}
		copy(pubPadded, pubRaw)
		peer.pubBytes = pubPadded
	}

	return peer, nil
}

// Bytes returns the public key byte slice to send to the peer.
func (p *PAKEPeer) Bytes() []byte {
	if p == nil {
		return nil
	}
	return p.pubBytes
}

// Update processes the remote peer's ephemeral public message and computes the post-quantum shared master secret.
func (p *PAKEPeer) Update(peerBytes []byte) error {
	if len(peerBytes) != UniformWireMsgSize {
		return ErrInvalidPeerMsg
	}

	peerRaw := peerBytes

	// Extract peer X25519 public key (first 32 bytes)
	peerX25519Raw := peerRaw[:32]
	curve := ecdh.X25519()
	peerPubKey, err := curve.NewPublicKey(peerX25519Raw)
	if err != nil {
		return fmt.Errorf("%w: invalid peer Curve25519 public key: %v", ErrPAKEFailed, err)
	}

	sharedX25519, err := p.privKey.ECDH(peerPubKey)
	if err != nil {
		return fmt.Errorf("%w: ECDH computation failed: %v", ErrPAKEFailed, err)
	}
	defer ZeroBytes(sharedX25519)

	var sharedMLKEM []byte

	if p.role == 1 {
		// Publisher (Role 1) processes Subscriber's (Role 2) ML-KEM Encapsulation Key (1184 bytes starting at index 32)
		peerMLKEMKeyRaw := peerRaw[32 : 32+1184]
		encapKey, err := mlkem.NewEncapsulationKey768(peerMLKEMKeyRaw)
		if err != nil {
			return fmt.Errorf("%w: invalid peer ML-KEM encapsulation key: %v", ErrPAKEFailed, err)
		}

		var ciphertext []byte
		sharedMLKEM, ciphertext = encapKey.Encapsulate()
		defer ZeroBytes(sharedMLKEM)

		// Publisher constructs its response wire payload (32B X25519 + 1088B ML-KEM Ciphertext padded to 1280B)
		pubX25519Raw := p.privKey.PublicKey().Bytes()
		pubRaw := append(append([]byte(nil), pubX25519Raw...), ciphertext...)

		pubPadded := make([]byte, UniformWireMsgSize)
		if _, err := rand.Read(pubPadded[len(pubRaw):]); err != nil {
			return fmt.Errorf("zerofeed/crypto: failed to generate random publisher padding: %w", err)
		}
		copy(pubPadded, pubRaw)
		p.pubBytes = pubPadded
	} else {
		// Subscriber (Role 2) processes Publisher's (Role 1) ML-KEM Ciphertext (1088 bytes starting at index 32)
		peerMLKEMCiphertext := peerRaw[32 : 32+1088]
		if p.mlkemDecap == nil {
			return ErrPAKEFailed
		}
		sharedMLKEM, err = p.mlkemDecap.Decapsulate(peerMLKEMCiphertext)
		if err != nil {
			return fmt.Errorf("%w: ML-KEM decapsulation failed: %v", ErrPAKEFailed, err)
		}
		defer ZeroBytes(sharedMLKEM)
	}

	// Combine X25519 shared secret (32B) + ML-KEM shared secret (32B)
	combinedSecret := append(append([]byte(nil), sharedX25519...), sharedMLKEM...)
	defer ZeroBytes(combinedSecret)

	// Derive memory-hard Argon2id key from passphrase
	argon2Key := DeriveMasterKeyArgon2(p.passphrase)
	defer ZeroBytes(argon2Key)

	// Derive final master key from combined secret + Argon2id key
	masterKey, err := HKDFSHA256(combinedSecret, argon2Key, []byte("zerofeed-v3-pake-master-secret"), KeySize)
	if err != nil {
		return err
	}
	p.sharedKey = masterKey

	// Generate MAC tag for mutual handshake authentication
	mac := hmac.New(sha256.New, p.sharedKey)
	mac.Write([]byte("zerofeed-v3-pake-handshake-auth"))
	mac.Write([]byte{byte(p.role)})
	p.macTag = mac.Sum(nil)

	return nil
}

// DeriveMasterKeyArgon2 derives a memory-hard 32-byte key from passphrase using Argon2id.
// Time=1, Memory=64MB (65536 KB), Threads=1 (Deterministic cross-platform across Native CLI and WASM).
func DeriveMasterKeyArgon2(passphrase []byte) []byte {
	salt := sha256.Sum256(append([]byte("zerofeed-v3-argon2id-static-context:"), passphrase...))
	return argon2.IDKey(passphrase, salt[:], 1, 64*1024, 1, KeySize)
}

// DeriveBlindMatchTag derives a 32-byte Blind HMAC tag for zero-knowledge Relay session pairing.
func DeriveBlindMatchTag(argon2Key []byte) [32]byte {
	var tag [32]byte
	h := hmac.New(sha256.New, argon2Key)
	h.Write([]byte("zerofeed-relay-blind-match-tag-v3"))
	copy(tag[:], h.Sum(nil))
	return tag
}

// ConfirmTag returns the HMAC key confirmation tag for this peer.
func (p *PAKEPeer) ConfirmTag() ([]byte, error) {
	if p == nil || p.sharedKey == nil {
		return nil, ErrPAKEFailed
	}
	mac := hmac.New(sha256.New, p.sharedKey)
	mac.Write([]byte("zerofeed-v3-pake-key-confirmation-v1"))
	mac.Write([]byte{byte(p.role)})
	return mac.Sum(nil), nil
}

// VerifyPeerConfirm checks the HMAC key confirmation tag from the remote peer.
func (p *PAKEPeer) VerifyPeerConfirm(peerTag []byte) error {
	if p == nil || p.sharedKey == nil || len(peerTag) == 0 {
		return ErrPAKEFailed
	}
	expectedMAC := hmac.New(sha256.New, p.sharedKey)
	expectedMAC.Write([]byte("zerofeed-v3-pake-key-confirmation-v1"))
	expectedMAC.Write([]byte{byte(3 - p.role)})
	if !hmac.Equal(peerTag, expectedMAC.Sum(nil)) {
		return fmt.Errorf("%w: peer key confirmation tag mismatch", ErrPAKEFailed)
	}
	return nil
}

// SessionKey returns the derived shared master secret after successful PAKE exchange.
func (p *PAKEPeer) SessionKey() ([]byte, error) {
	if p.sharedKey == nil {
		return nil, ErrPAKEFailed
	}
	keyCopy := make([]byte, len(p.sharedKey))
	copy(keyCopy, p.sharedKey)
	return keyCopy, nil
}

// Close scrubs sensitive key material from memory.
func (p *PAKEPeer) Close() {
	if p.sharedKey != nil {
		ZeroBytes(p.sharedKey)
		p.sharedKey = nil
	}
	if p.pubBytes != nil {
		ZeroBytes(p.pubBytes)
		p.pubBytes = nil
	}
	if p.passphrase != nil {
		ZeroBytes(p.passphrase)
		p.passphrase = nil
	}
	if p.macTag != nil {
		ZeroBytes(p.macTag)
		p.macTag = nil
	}
	if p.mlkemDecap != nil {
		p.mlkemDecap = nil
	}
}
