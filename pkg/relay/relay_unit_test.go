package relay_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zerofeed/zerofeed/pkg/relay"
)

func TestServerOptionsAndGetters(t *testing.T) {
	srv := relay.NewServer("127.0.0.1:0")

	// Test Setters
	srv.SetRateLimiting(false)
	srv.SetRateLimiting(true)
	srv.DisableRateLimiting()
	srv.SetTrustProxy(true)
	srv.SetTrustProxy(false)

	m := srv.Metrics()
	if m == nil {
		t.Fatal("srv.Metrics returned nil")
	}
}

func TestStartMetricsServer(t *testing.T) {
	srv := relay.NewServer("127.0.0.1:0")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := srv.StartMetricsServer(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("StartMetricsServer failed: %v", err)
	}

	// Verify Prometheus endpoint handler directly
	m := srv.Metrics()
	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	m.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected http status 200, got %d", rr.Code)
	}
}

func TestWebSocketUpgradeFailure(t *testing.T) {
	req := httptest.NewRequest("GET", "/ws", nil)
	rr := httptest.NewRecorder()

	_, err := relay.UpgradeWebSocket(rr, req)
	if err == nil {
		t.Fatal("expected error for non-websocket upgrade request, got nil")
	}
}

func TestStartWebSocketServer(t *testing.T) {
	srv := relay.NewServer("127.0.0.1:0")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err := srv.StartWebSocketServer(ctx, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("StartWebSocketServer failed: %v", err)
	}
}

func TestCloseServer(t *testing.T) {
	srv := relay.NewServer("127.0.0.1:0")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	<-srv.Ready()
	err := srv.Close()
	if err != nil {
		t.Fatalf("srv.Close error: %v", err)
	}
}

func TestWebSocketOriginValidation(t *testing.T) {
	// Blocked cross-site origin
	reqBad := httptest.NewRequest("GET", "/ws", nil)
	reqBad.Header.Set("Upgrade", "websocket")
	reqBad.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	reqBad.Header.Set("Origin", "https://malicious-site.com")
	rrBad := httptest.NewRecorder()

	_, errBad := relay.UpgradeWebSocket(rrBad, reqBad)
	if errBad == nil || !strings.Contains(errBad.Error(), "origin not allowed") {
		t.Fatalf("expected origin not allowed error, got: %v", errBad)
	}

	// Allowed localhost origin
	reqLocal := httptest.NewRequest("GET", "/ws", nil)
	reqLocal.Header.Set("Upgrade", "websocket")
	reqLocal.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	reqLocal.Header.Set("Origin", "http://localhost:8080")
	rrLocal := httptest.NewRecorder()

	_, errLocal := relay.UpgradeWebSocket(rrLocal, reqLocal)
	if errLocal != nil && strings.Contains(errLocal.Error(), "origin not allowed") {
		t.Fatalf("localhost origin should be allowed, but was rejected: %v", errLocal)
	}

	// Allowed GitHub Pages origin
	reqGH := httptest.NewRequest("GET", "/ws", nil)
	reqGH.Header.Set("Upgrade", "websocket")
	reqGH.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	reqGH.Header.Set("Origin", "https://nicolainzerillo.github.io")
	rrGH := httptest.NewRecorder()

	_, errGH := relay.UpgradeWebSocket(rrGH, reqGH)
	if errGH != nil && strings.Contains(errGH.Error(), "origin not allowed") {
		t.Fatalf("github.io origin should be allowed, but was rejected: %v", errGH)
	}
}
