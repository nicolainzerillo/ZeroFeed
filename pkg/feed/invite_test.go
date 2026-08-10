package feed

import (
	"testing"
)

func TestInvite_ParsePlainCode(t *testing.T) {
	raw := "cipher-falcon-orbit-948201"
	inv, err := ParseInvite(raw)
	if err != nil {
		t.Fatalf("ParseInvite plain code error: %v", err)
	}
	if inv.Code != raw {
		t.Errorf("got code %q, want %q", inv.Code, raw)
	}
	if inv.RelayAddr != "" {
		t.Errorf("expected empty relay addr, got %q", inv.RelayAddr)
	}
}

func TestInvite_ParseURI(t *testing.T) {
	raw := "zerofeed://join?code=secret-passphrase-123&relay=relay.zerofeed.app:8443&transport=quic"
	inv, err := ParseInvite(raw)
	if err != nil {
		t.Fatalf("ParseInvite URI error: %v", err)
	}
	if inv.Code != "secret-passphrase-123" {
		t.Errorf("got code %q, want secret-passphrase-123", inv.Code)
	}
	if inv.RelayAddr != "relay.zerofeed.app:8443" {
		t.Errorf("got relay %q, want relay.zerofeed.app:8443", inv.RelayAddr)
	}
	if inv.TransportMode != "quic" {
		t.Errorf("got transport %q, want quic", inv.TransportMode)
	}
}

func TestInvite_ParseWebURL(t *testing.T) {
	webURL := "https://nicolainzerillo.github.io/ZeroFeed-Landing/#join=zerofeed%3A%2F%2Fjoin%3Fcode%3Dweb-passphrase-999%26relay%3D92.4.216.150%3A8443"
	inv, err := ParseInvite(webURL)
	if err != nil {
		t.Fatalf("ParseInvite Web URL error: %v", err)
	}
	if inv.Code != "web-passphrase-999" {
		t.Errorf("got code %q, want web-passphrase-999", inv.Code)
	}
	if inv.RelayAddr != "92.4.216.150:8443" {
		t.Errorf("got relay %q, want 92.4.216.150:8443", inv.RelayAddr)
	}
}

func TestInvite_ToURIAndWebURL(t *testing.T) {
	inv := GenerateInvite("my-super-secret", "relay.zerofeed.app:8443")
	uri := inv.ToURI()
	if uri != "zerofeed://join?code=my-super-secret&relay=relay.zerofeed.app:8443" {
		t.Errorf("unexpected URI: %s", uri)
	}

	reparsed, err := ParseInvite(uri)
	if err != nil {
		t.Fatalf("ParseInvite failed on generated URI: %v", err)
	}
	if reparsed.Code != inv.Code || reparsed.RelayAddr != inv.RelayAddr {
		t.Errorf("reparsed mismatch: %+v vs %+v", reparsed, inv)
	}

	webURL := inv.ToWebURL()
	reparsedWeb, err := ParseInvite(webURL)
	if err != nil {
		t.Fatalf("ParseInvite failed on generated Web URL: %v", err)
	}
	if reparsedWeb.Code != inv.Code || reparsedWeb.RelayAddr != inv.RelayAddr {
		t.Errorf("reparsedWeb mismatch: %+v vs %+v", reparsedWeb, inv)
	}
}

func TestInvite_FormatBanner(t *testing.T) {
	inv := GenerateInvite("test-code-123", "relay.zerofeed.app:8443")
	banner := inv.FormatBanner()
	if banner == "" {
		t.Fatal("FormatBanner returned empty string")
	}
}
