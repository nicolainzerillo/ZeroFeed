package feed

import (
	"fmt"
	"net/url"
	"strings"
)

// DefaultLandingURL is the official ZeroFeed web landing page URL.
const DefaultLandingURL = "https://nicolainzerillo.github.io/ZeroFeed-Landing/"

// Invite represents a client-generated, zero-knowledge invite token.
// The Relay server receives no invite state or registration tables — all invite parameters are encoded into the invite token itself.
type Invite struct {
	Code            string `json:"code"`
	RelayAddr       string `json:"relay,omitempty"`
	TransportMode   string `json:"transport,omitempty"`
	SPKIFingerprint string `json:"fingerprint,omitempty"`
}

// GenerateInvite creates a new Invite structure from channel code and relay address.
func GenerateInvite(code string, relayAddr string) *Invite {
	return &Invite{
		Code:      strings.TrimSpace(code),
		RelayAddr: strings.TrimSpace(relayAddr),
	}
}

// ParseInvite parses an input string into an Invite structure.
// The input can be:
//   1. A plain channel passphrase/code (e.g. "cipher-falcon-orbit-948201")
//   2. A zerofeed URI scheme (e.g. "zerofeed://join?code=...&relay=...")
//   3. A web landing page URL with hash fragment (e.g. "https://nicolainzerillo.github.io/ZeroFeed-Landing/#join=...")
func ParseInvite(raw string) (*Invite, error) {
	input := strings.TrimSpace(raw)
	if input == "" {
		return nil, fmt.Errorf("zerofeed/invite: invite string cannot be empty")
	}

	// 1. Check if input is a zerofeed:// URI
	if strings.HasPrefix(input, "zerofeed://") {
		u, err := url.Parse(input)
		if err != nil {
			return nil, fmt.Errorf("zerofeed/invite: invalid zerofeed URI: %w", err)
		}
		q := u.Query()
		code := q.Get("code")
		if code == "" {
			return nil, fmt.Errorf("zerofeed/invite: zerofeed URI missing 'code' parameter")
		}
		return &Invite{
			Code:            code,
			RelayAddr:       q.Get("relay"),
			TransportMode:   q.Get("transport"),
			SPKIFingerprint: q.Get("fingerprint"),
		}, nil
	}

	// 2. Check if input is a Web Landing Page URL (e.g. containing #join= or ?code=)
	if strings.HasPrefix(input, "http://") || strings.HasPrefix(input, "https://") {
		// Look for #join= in hash fragment
		if idx := strings.Index(input, "#join="); idx != -1 {
			fragment := input[idx+6:]
			if unescaped, err := url.QueryUnescape(fragment); err == nil {
				fragment = unescaped
			}
			return ParseInvite(fragment)
		}

		// Fallback to query params in HTTP URL
		u, err := url.Parse(input)
		if err == nil {
			q := u.Query()
			if code := q.Get("code"); code != "" {
				return &Invite{
					Code:            code,
					RelayAddr:       q.Get("relay"),
					TransportMode:   q.Get("transport"),
					SPKIFingerprint: q.Get("fingerprint"),
				}, nil
			}
		}
	}

	// 3. Fallback: Treat as plain channel passphrase / code
	return &Invite{
		Code: input,
	}, nil
}

// ToURI formats the invite into a native zerofeed:// URI string.
func (i *Invite) ToURI() string {
	v := url.Values{}
	v.Set("code", i.Code)
	if i.RelayAddr != "" {
		v.Set("relay", i.RelayAddr)
	}
	if i.TransportMode != "" {
		v.Set("transport", i.TransportMode)
	}
	if i.SPKIFingerprint != "" {
		v.Set("fingerprint", i.SPKIFingerprint)
	}
	return fmt.Sprintf("zerofeed://join?%s", v.Encode())
}

// ToWebURL formats the invite into a shareable web landing page URL with hash fragment.
func (i *Invite) ToWebURL() string {
	uri := i.ToURI()
	return fmt.Sprintf("%s#join=%s", DefaultLandingURL, url.PathEscape(uri))
}

// FormatBanner returns a human-friendly ASCII banner for terminal display.
func (i *Invite) FormatBanner() string {
	var b strings.Builder
	b.WriteString("====================================================\n")
	b.WriteString(" [ZeroFeed Client-Generated Stateless Invite]\n")
	b.WriteString(fmt.Sprintf(" Passphrase Code : %s\n", i.Code))
	if i.RelayAddr != "" {
		b.WriteString(fmt.Sprintf(" Target Relay   : %s\n", i.RelayAddr))
	}
	b.WriteString(fmt.Sprintf(" Web Link       : %s\n", i.ToWebURL()))
	b.WriteString(fmt.Sprintf(" Native URI     : %s\n", i.ToURI()))
	b.WriteString("====================================================")
	return b.String()
}
