package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

// GenerateEphemeralTLSConfig generates an in-memory self-signed TLS 1.3 configuration for QUIC sessions.
func GenerateEphemeralTLSConfig() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"ZeroFeed Ephemeral Node"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	cert := tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  key,
	}

	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		NextProtos:         []string{"zerofeed-quic-v1"},
		InsecureSkipVerify: true, // E2EE security is enforced via SPAKE2 PAKE at application layer
		MinVersion:         tls.VersionTLS13,
	}, nil
}
