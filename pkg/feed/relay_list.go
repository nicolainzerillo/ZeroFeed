package feed

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// DefaultRelayDNS is the DNS name used to discover the default public relay list.
// Kept separate from any hardcoded IP. Override with ZEROFEED_RELAY env var or --relay flag.
const DefaultRelayDNS = "relay.zerofeed.app"

// DefaultRelayPort is the default port used when resolving DefaultRelayDNS.
const DefaultRelayPort = "8443"

// ParseRelayList splits a comma-separated relay address string into a slice.
// Each entry is trimmed of whitespace. Empty entries are ignored.
//
// Example:
//
//	ParseRelayList("relay1.example.com:8443, relay2.example.com:8443")
//	// → ["relay1.example.com:8443", "relay2.example.com:8443"]
func ParseRelayList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// DialFirstAvailable attempts to connect to each relay in the list sequentially,
// returning the first successful connection and the address that succeeded.
//
// It respects ctx for cancellation. Each individual dial uses dialTimeout.
// If all relays fail, the combined error list is returned.
//
// The caller is responsible for closing the returned connection.
func DialFirstAvailable(ctx context.Context, relays []string, dialTimeout time.Duration) (net.Conn, string, error) {
	if len(relays) == 0 {
		return nil, "", fmt.Errorf("relay list is empty: set ZEROFEED_RELAY or use --relay")
	}

	var lastErr error
	for _, addr := range relays {
		dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
		conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
		cancel()
		if err == nil {
			return conn, addr, nil
		}
		lastErr = fmt.Errorf("relay %s: %w", addr, err)
	}
	return nil, "", fmt.Errorf("all relays unreachable: %w", lastErr)
}

// ProbeFirstAvailable checks each relay address in sequence and returns the
// address of the first reachable one, without keeping the connection open.
//
// Use this to resolve which relay to use when you only need the address,
// not the connection itself (avoids connection leaks in caller code).
func ProbeFirstAvailable(ctx context.Context, relays []string, dialTimeout time.Duration) (string, error) {
	conn, addr, err := DialFirstAvailable(ctx, relays, dialTimeout)
	if err != nil {
		return "", err
	}
	_ = conn.Close()
	return addr, nil
}

// ResolveDefaultRelays resolves DefaultRelayDNS to a list of relay addresses.
// Falls back to an empty list (no relay) if DNS lookup fails.
// This function does NOT block for long — it uses a 3-second timeout.
func ResolveDefaultRelays() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	addrs, err := (&net.Resolver{}).LookupHost(ctx, DefaultRelayDNS)
	if err != nil || len(addrs) == 0 {
		return nil
	}

	relays := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		relays = append(relays, net.JoinHostPort(addr, DefaultRelayPort))
	}
	return relays
}
