package feed

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestParseRelayList(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"single", "relay.example.com:8443", []string{"relay.example.com:8443"}},
		{"comma-separated with spaces", "relay1.example.com:8443, relay2.example.com:8443", []string{"relay1.example.com:8443", "relay2.example.com:8443"}},
		{"three relays", "a:8443,b:8443,c:8443", []string{"a:8443", "b:8443", "c:8443"}},
		{"empty string", "", []string{}},
		{"trailing comma ignored", "relay.example.com:8443,", []string{"relay.example.com:8443"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseRelayList(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("ParseRelayList(%q) = %v, want %v", tt.input, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("[%d] got %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestDialFirstAvailable_AllFail(t *testing.T) {
	relays := []string{"127.0.0.2:19999", "127.0.0.3:19999"}
	conn, addr, err := DialFirstAvailable(context.Background(), relays, 200*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatalf("expected error, got connection to %s", addr)
	}
}

func TestDialFirstAvailable_FirstSucceeds(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("could not bind local listener:", err)
	}
	defer ln.Close()
	goodAddr := ln.Addr().String()
	relays := []string{"127.0.0.2:19999", goodAddr}
	conn, addr, err := DialFirstAvailable(context.Background(), relays, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("DialFirstAvailable error: %v", err)
	}
	conn.Close()
	if addr != goodAddr {
		t.Errorf("expected %q, got %q", goodAddr, addr)
	}
}

func TestDialFirstAvailable_EmptyList(t *testing.T) {
	_, _, err := DialFirstAvailable(context.Background(), nil, time.Second)
	if err == nil {
		t.Fatal("expected error for empty list")
	}
}
