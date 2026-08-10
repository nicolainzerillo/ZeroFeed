package feed

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/zerofeed/zerofeed/pkg/crypto"
)

const (
	// DefaultLandingURL is the official ZeroFeed Web Landing Page URL.
	DefaultLandingURL = "https://nicolainzerillo.github.io/ZeroFeed-Landing/"
)

// Invite encapsulates all client-generated parameters for zero-knowledge channel rendezvous.
type Invite struct {
	Code            string `json:"code"`
	RelayAddr       string `json:"relay_addr,omitempty"`
	TransportMode   string `json:"transport_mode,omitempty"`
	SPKIFingerprint string `json:"spki_fingerprint,omitempty"`
}

// GenerateInvite constructs a new Invite struct from parameters.
func GenerateInvite(code string, relayAddr string) *Invite {
	return &Invite{
		Code:      code,
		RelayAddr: relayAddr,
	}
}

// ParseInvite parses human passphrase codes, zerofeed:// URIs, or web landing page URLs.
func ParseInvite(raw string) (*Invite, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty invite string")
	}

	// Check if raw string is a Web URL containing a hash fragment #join=...
	if strings.Contains(raw, "#join=") {
		parts := strings.Split(raw, "#join=")
		if len(parts) == 2 {
			unescapedHash, err := url.QueryUnescape(parts[1])
			if err == nil {
				raw = unescapedHash
			} else {
				raw = parts[1]
			}
		}
	}

	// Parse zerofeed:// URI scheme
	if strings.HasPrefix(raw, "zerofeed://") {
		parsedURL, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid zerofeed URI: %w", err)
		}
		q := parsedURL.Query()
		code := q.Get("code")
		if code == "" {
			return nil, fmt.Errorf("missing code in zerofeed URI")
		}
		return &Invite{
			Code:            code,
			RelayAddr:       q.Get("relay"),
			TransportMode:   q.Get("transport"),
			SPKIFingerprint: q.Get("fingerprint"),
		}, nil
	}

	// Standard plain code
	return &Invite{
		Code: raw,
	}, nil
}

// ToURI formats the invite into a native zerofeed:// URI string.
func (i *Invite) ToURI() string {
	var params []string
	if i.Code != "" {
		params = append(params, "code="+url.QueryEscape(i.Code))
	}
	if i.RelayAddr != "" {
		params = append(params, "relay="+i.RelayAddr)
	}
	if i.TransportMode != "" {
		params = append(params, "transport="+url.QueryEscape(i.TransportMode))
	}
	if i.SPKIFingerprint != "" {
		params = append(params, "fingerprint="+url.QueryEscape(i.SPKIFingerprint))
	}
	return fmt.Sprintf("zerofeed://join?%s", strings.Join(params, "&"))
}

// ToWebURL formats the invite into a shareable web landing page URL with hash fragment.
func (i *Invite) ToWebURL() string {
	uri := i.ToURI()
	return fmt.Sprintf("%s#join=%s", DefaultLandingURL, url.QueryEscape(uri))
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
	hexSAS, emojiSAS := crypto.CalculateSAS([]byte(i.Code))
	b.WriteString(fmt.Sprintf(" Visual SAS      : %s [%s]\n", emojiSAS, hexSAS))
	b.WriteString("----------------------------------------------------\n")
	b.WriteString(fmt.Sprintf(" Native URI      : %s\n", i.ToURI()))
	b.WriteString(fmt.Sprintf(" Web Link        : %s\n", i.ToWebURL()))
	b.WriteString("====================================================\n")
	return b.String()
}
