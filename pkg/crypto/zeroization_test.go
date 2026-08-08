package crypto_test

import (
	"runtime"
	"testing"
	"unsafe"

	"github.com/zerofeed/zerofeed/pkg/crypto"
	"github.com/zerofeed/zerofeed/pkg/feed"
)

type memRef struct {
	ptr unsafe.Pointer
	len int
}

// TestMemoryZeroization audits RAM scrubbing and zeroization to prevent sensitive data leaks.
func TestMemoryZeroization(t *testing.T) {
	// 1. Allocate a 256-bit AES key (32 bytes) and circular buffer with simulated sensitive data
	rawKeyBytes := []byte("SUPER_SECRET_AES256_KEY_MAT_32B!")
	if len(rawKeyBytes) != crypto.KeySize {
		t.Fatalf("expected key length %d, got %d", crypto.KeySize, len(rawKeyBytes))
	}

	aesKey := make([]byte, crypto.KeySize)
	copy(aesKey, rawKeyBytes)

	cipher, err := crypto.NewCipher(aesKey)
	if err != nil {
		t.Fatalf("NewCipher failed: %v", err)
	}

	rb := feed.NewRingBuffer(5)

	payloads := [][]byte{
		[]byte("CONFIDENTIAL_PAKE_MASTER_SECRET_KEY_001"),
		[]byte("TOP_SECRET_EPHEMERAL_STREAM_TOKEN_002"),
		[]byte("PRIVATE_PASSPHRASE_BLINDING_MASK_003"),
		[]byte("SENSITIVE_SESSION_IDENTIFIER_BYTES_004"),
		[]byte("ENCRYPTED_AEAD_PLAINTEXT_PAYLOAD_005"),
	}

	for i, p := range payloads {
		rb.Push(uint64(i+1), p)
	}

	// 2. Save memory pointers (pointer / slice headers) of these sensitive buffers
	aesKeyPtr := unsafe.Pointer(&aesKey[0])
	aesKeyLen := len(aesKey)

	var payloadRefs []memRef
	for _, p := range payloads {
		payloadRefs = append(payloadRefs, memRef{
			ptr: unsafe.Pointer(&p[0]),
			len: len(p),
		})
	}

	// 3. Invoke session self-destruction and RAM wiping methods
	crypto.ZeroBytes(aesKey)
	cipher.Close()

	for _, p := range payloads {
		crypto.ZeroBytes(p)
	}

	rb.Wipe()

	// 5. Use runtime.KeepAlive to ensure compiler optimization (dead-store elimination) did not ignore zeroing
	runtime.KeepAlive(aesKey)
	runtime.KeepAlive(payloads)
	runtime.KeepAlive(rb)
	runtime.KeepAlive(cipher)

	// 4. Inspect bytes directly at saved memory pointers and verify EVERY single byte is 0x00
	inspectBytes := unsafe.Slice((*byte)(aesKeyPtr), aesKeyLen)
	for i, b := range inspectBytes {
		if b != 0x00 {
			t.Errorf("AES Key memory at byte offset %d was NOT zeroed: got 0x%02x, expected 0x00", i, b)
		}
	}

	for idx, ref := range payloadRefs {
		pBytes := unsafe.Slice((*byte)(ref.ptr), ref.len)
		for i, b := range pBytes {
			if b != 0x00 {
				t.Errorf("Payload[%d] memory at byte offset %d was NOT zeroed: got 0x%02x, expected 0x00", idx, i, b)
			}
		}
	}
}
