package feed_test

import (
	"testing"

	"github.com/zerofeed/zerofeed/pkg/crypto"
)

func BenchmarkAESGCMEncryptionThroughput(b *testing.B) {
	key := []byte("BENCHMARK_SECRET_KEY_AES256_32B!")
	ciph, err := crypto.NewCipher(key)
	if err != nil {
		b.Fatalf("NewCipher failed: %v", err)
	}
	defer ciph.Close()

	payload := make([]byte, 4096) // 4KB payload block
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()

	for b.Loop() {
		ciphertext, nonce, err := ciph.Encrypt(payload, nil, nil)
		if err != nil {
			b.Fatalf("Encrypt failed: %v", err)
		}
		crypto.ZeroBytes(ciphertext)
		crypto.ZeroBytes(nonce)
	}
}

func BenchmarkAESGCMDecryptionThroughput(b *testing.B) {
	key := []byte("BENCHMARK_SECRET_KEY_AES256_32B!")
	ciph, err := crypto.NewCipher(key)
	if err != nil {
		b.Fatalf("NewCipher failed: %v", err)
	}
	defer ciph.Close()

	payload := make([]byte, 4096) // 4KB payload block
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	ciphertext, nonce, err := ciph.Encrypt(payload, nil, nil)
	if err != nil {
		b.Fatalf("Encrypt failed: %v", err)
	}

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()

	for b.Loop() {
		plaintext, err := ciph.Decrypt(ciphertext, nonce, nil)
		if err != nil {
			b.Fatalf("Decrypt failed: %v", err)
		}
		crypto.ZeroBytes(plaintext)
	}
}
