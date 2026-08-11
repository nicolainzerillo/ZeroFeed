package feed

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/zerofeed/zerofeed/pkg/crypto"
	"github.com/zerofeed/zerofeed/pkg/protocol"
)

// DeriveBlindMatchTag derives a 32-byte zero-knowledge match tag for Relay session pairing.
func DeriveBlindMatchTag(passphrase []byte) [32]byte {
	argon2Key := crypto.DeriveMasterKeyArgon2(passphrase)
	defer crypto.ZeroBytes(argon2Key)
	return crypto.DeriveBlindMatchTag(argon2Key)
}

// DeriveSessionID derives an anonymized 16-byte zero-knowledge session identifier from passphrase using Argon2id.
func DeriveSessionID(passphrase []byte) [protocol.SessionIDSize]byte {
	argon2Key := crypto.DeriveMasterKeyArgon2(passphrase)
	defer crypto.ZeroBytes(argon2Key)

	h := hmac.New(sha256.New, argon2Key)
	h.Write([]byte("zerofeed-relay-channel-rendezvous-v3"))
	tag := h.Sum(nil)

	var sessionID [protocol.SessionIDSize]byte
	copy(sessionID[:], tag[:protocol.SessionIDSize])
	return sessionID
}

// GenerateEphemeralSessionID creates a 100% random 16-byte session identifier for each connection attempt.
func GenerateEphemeralSessionID() [protocol.SessionIDSize]byte {
	var sessionID [protocol.SessionIDSize]byte
	_, _ = rand.Read(sessionID[:])
	return sessionID
}

// DialRelay connects to the specified relay server using TCP or TLS (with SNI support for cloud proxies).
func DialRelay(ctx context.Context, relayAddr string) (net.Conn, error) {
	return DialRelayWithPin(ctx, relayAddr, "")
}

// DialRelayWithPin connects to the specified relay server enforcing SPKI TLS Certificate Pinning if fingerprint is non-empty.
func DialRelayWithPin(ctx context.Context, relayAddr string, expectedFingerprint string) (net.Conn, error) {
	var d net.Dialer
	d.FallbackDelay = 100 * time.Millisecond
	if deadline, ok := ctx.Deadline(); ok {
		d.Deadline = deadline
	}
	host, port, err := net.SplitHostPort(relayAddr)
	if err != nil {
		host = relayAddr
	}

	serverName := host
	if net.ParseIP(host) != nil {
		if envSNI := os.Getenv("ZEROFEED_TLS_SNI"); envSNI != "" {
			serverName = envSNI
		} else {
			serverName = "zerofeed.duckdns.org"
		}
	}

	expectedFingerprint = strings.TrimSpace(strings.ToLower(expectedFingerprint))

	// Use TLS first if:
	// - Port is 443 or 8443 AND the host is a DNS name (likely a TLS-terminating proxy like Fly.io), OR
	// - SPKI fingerprint pinning is explicitly requested (works with both IPs and hostnames).
	// Skip TLS probe for raw IP addresses without pinning: there's no cert to verify,
	// and the probe would send a TLS ClientHello that the relay sees as a malformed frame.
	isRawIP := net.ParseIP(host) != nil
	isIPv6 := isRawIP && strings.Contains(host, ":")

	// Select network type: use "tcp4"/"tcp6" for raw IP literals to avoid macOS
	// Happy Eyeballs / dual-stack hangs when only one address family is reachable.
	tcpNetwork := "tcp"
	if isRawIP {
		if isIPv6 {
			tcpNetwork = "tcp6"
		} else {
			tcpNetwork = "tcp4"
		}
	}

	useTLSFirst := (!isRawIP && (port == "443" || port == "8443")) || expectedFingerprint != ""
	if useTLSFirst {
		// Enforce Standard PKI System CA verification by default (InsecureSkipVerify = false).
		// Only override PKI when explicit SPKI Certificate Fingerprint Pinning is requested by the client.
		isPinningRequested := expectedFingerprint != ""
		tlsConfig := &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: isPinningRequested,
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if !isPinningRequested {
					return nil
				}
				if len(rawCerts) == 0 {
					return fmt.Errorf("zerofeed/feed: no server TLS certificates presented for SPKI verification")
				}
				actualFingerprint := crypto.CalculateSPKIFingerprint(rawCerts[0])
				if actualFingerprint != expectedFingerprint {
					return fmt.Errorf("zerofeed/feed: SPKI TLS Certificate Pin Mismatch!\n  Expected: %s\n  Got:      %s", expectedFingerprint, actualFingerprint)
				}
				return nil
			},
		}

		// Probe TLS with strict 2.5s timeout to preserve context deadline for plain TCP fallback
		tlsTimeout := 2500 * time.Millisecond
		if deadline, ok := ctx.Deadline(); ok {
			if rem := time.Until(deadline); rem < tlsTimeout {
				tlsTimeout = rem
			}
		}
		tlsDialer := net.Dialer{
			Timeout:       tlsTimeout,
			FallbackDelay: 100 * time.Millisecond,
		}
		tlsConn, tlsErr := tls.DialWithDialer(&tlsDialer, tcpNetwork, relayAddr, tlsConfig)
		if tlsErr == nil {
			return tlsConn, nil
		}
		if expectedFingerprint != "" {
			return nil, fmt.Errorf("zerofeed/feed: TLS connection failed with SPKI pinning: %w", tlsErr)
		}
	}

	// Default to plain TCP (use specific network family for raw IP literals)
	return d.DialContext(ctx, tcpNetwork, relayAddr)
}
