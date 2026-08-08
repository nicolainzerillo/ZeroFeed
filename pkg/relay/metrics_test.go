package relay_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zerofeed/zerofeed/pkg/relay"
)

func TestMetricsCollectionAndPrometheusExporter(t *testing.T) {
	m := relay.NewMetrics()

	m.ActiveSessions.Add(5)
	m.SessionsCreatedTotal.Add(12)
	m.ActiveConnections.Add(10)
	m.BytesTransferredTotal.Add(1048576)
	m.MessagesRelayedTotal.Add(500)
	m.RateLimitBansTotal.Add(3)
	m.MalformedPacketsDroppedTotal.Add(2)

	ts := httptest.NewServer(m.Handler())
	defer ts.Close()

	resp, err := http.Get(ts.URL)
	if err != nil {
		t.Fatalf("Failed to query metrics HTTP endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected HTTP 200 OK, got %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	body := string(bodyBytes)

	expectedMetrics := []string{
		"zerofeed_relay_uptime_seconds",
		"zerofeed_relay_active_sessions 5",
		"zerofeed_relay_sessions_created_total 12",
		"zerofeed_relay_active_connections 10",
		"zerofeed_relay_bytes_transferred_total 1048576",
		"zerofeed_relay_messages_relayed_total 500",
		"zerofeed_relay_ratelimit_bans_total 3",
		"zerofeed_relay_malformed_packets_dropped_total 2",
	}

	for _, metric := range expectedMetrics {
		if !strings.Contains(body, metric) {
			t.Errorf("Prometheus output missing metric snippet %q. Body:\n%s", metric, body)
		}
	}
}

func TestServerMetricsIntegration(t *testing.T) {
	srv := relay.NewServer("127.0.0.1:0")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.Start(ctx)
	}()

	<-srv.Ready()

	m := srv.Metrics()
	if m == nil {
		t.Fatalf("Server.Metrics() returned nil")
	}

	if m.ActiveSessions.Load() != 0 {
		t.Errorf("Expected initial ActiveSessions to be 0, got %d", m.ActiveSessions.Load())
	}
}
