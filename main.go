//go:build !js && !wasm

package main

import (
	"bufio"
	"context"
	cryptoRand "crypto/rand"
	"encoding/binary"
	"errors"
	"flag"

	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/zerofeed/zerofeed/pkg/crypto"
	"github.com/zerofeed/zerofeed/pkg/feed"
	"github.com/zerofeed/zerofeed/pkg/logger"
	"github.com/zerofeed/zerofeed/pkg/protocol"
	"github.com/zerofeed/zerofeed/pkg/relay"
	"github.com/zerofeed/zerofeed/pkg/transport"
	"github.com/zerofeed/zerofeed/pkg/version"
)

func initSecurity() {
	_ = crypto.LockMemory()
	_ = crypto.DisableCoreDumps()
}

func setupSignalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	signal.Ignore(syscall.SIGPIPE)

	go func() {
		<-sigChan
		crypto.WipeAll()
		cancel()
	}()

	return ctx, cancel
}

func main() {
	initSecurity()

	err := runMain()
	crypto.WipeAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runMain() error {
	if len(os.Args) < 2 {
		printUsage()
		return errors.New("no subcommand specified")
	}

	subcommand := os.Args[1]
	args := os.Args[2:]

	switch subcommand {
	case "publish", "pub":
		return runPublish(args)
	case "subscribe", "sub":
		return runSubscribe(args)
	case "invite":
		return runInvite(args)
	case "join":
		return runJoin(args)
	case "relay":
		return runRelay(args)
	case "gen", "generate":
		runGen()
		return nil
	case "version", "-v", "--version":
		fmt.Println(version.Info())
		return nil
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown subcommand: %s", subcommand)
	}
}

func logStderr(quiet bool, format string, a ...interface{}) {
	if quiet {
		return
	}
	fmt.Fprintf(os.Stderr, format, a...)
}

// parsePassphrase resolves the channel code from the CLI flag aliases, falling
// back to ZEROFEED_PASSPHRASE. Prefer the env var: process arguments are world
// readable via ps(1) on most systems, so a code passed with --passphrase is
// visible to every other local user for the lifetime of the process.
func parsePassphrase(p1, p2, p3, p4, p5 *string) string {
	for _, p := range []*string{p1, p2, p3, p4, p5} {
		if p != nil && *p != "" {
			return *p
		}
	}
	return os.Getenv("ZEROFEED_PASSPHRASE")
}

// maskSecret renders a code for terminal display without writing it verbatim to
// the scrollback: enough to tell two codes apart, not enough to reuse one read
// over a shoulder or captured in piped logs.
func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	r := []rune(s)
	if len(r) <= 4 {
		return strings.Repeat("*", len(r))
	}
	return string(r[:2]) + strings.Repeat("*", len(r)-4) + string(r[len(r)-2:])
}

func parseByteSize(s string) uint64 {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" || s == "0" {
		return 0
	}
	var mult uint64 = 1
	if strings.HasSuffix(s, "G") || strings.HasSuffix(s, "GB") {
		mult = 1024 * 1024 * 1024
		s = strings.TrimSuffix(strings.TrimSuffix(s, "GB"), "G")
	} else if strings.HasSuffix(s, "M") || strings.HasSuffix(s, "MB") {
		mult = 1024 * 1024
		s = strings.TrimSuffix(strings.TrimSuffix(s, "MB"), "M")
	} else if strings.HasSuffix(s, "K") || strings.HasSuffix(s, "KB") {
		mult = 1024
		s = strings.TrimSuffix(strings.TrimSuffix(s, "KB"), "K")
	}
	var val uint64
	_, _ = fmt.Sscanf(s, "%d", &val)
	return val * mult
}

// resolveRelayAddr resolves the effective relay address from CLI flags.
// Priority: -r flag > --relay flag > ZEROFEED_RELAY env > DNS lookup of DefaultRelayDNS.
// Supports comma-separated lists; probes each in order and returns first reachable address.
// The probe opens and immediately closes a TCP connection — no leak.
func resolveRelayAddr(r1, r2 string) (string, error) {
	raw := r2
	if raw == "" {
		raw = r1
	}
	if raw == "" {
		raw = os.Getenv("ZEROFEED_RELAY")
	}

	var list []string
	if raw == "" {
		// DNS fallback
		list = feed.ResolveDefaultRelays()
		if len(list) == 0 {
			return "", fmt.Errorf("no relay specified and DNS lookup of %s failed (use --relay <address> or set ZEROFEED_RELAY)", feed.DefaultRelayDNS)
		}
	} else {
		list = feed.ParseRelayList(raw)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr, err := feed.ProbeFirstAvailable(ctx, list, 2*time.Second)
	if err != nil {
		return "", fmt.Errorf("relay unreachable: %w", err)
	}
	return addr, nil
}

func runPublish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ContinueOnError)
	p1 := fs.String("passphrase", "", "Shared passphrase for E2EE PAKE session")
	p2 := fs.String("p", "", "Shared passphrase (shorthand)")
	p3 := fs.String("c", "", "Shared passphrase (alias)")
	p4 := fs.String("code", "", "Shared passphrase (alias)")
	p5 := fs.String("channel", "", "Shared passphrase (alias)")

	r1 := fs.String("relay", "", "Relay server address(es), comma-separated for fallback (e.g. relay1.example.com:8443,relay2.example.com:8443). Defaults to "+feed.DefaultRelayDNS+" if unset.")
	r2 := fs.String("r", "", "Relay server address (shorthand)")
	streamMode := fs.Bool("stream", false, "Continuous streaming mode")
	fs.BoolVar(streamMode, "s", false, "Continuous streaming mode (shorthand)")
	ttlStr := fs.String("ttl", "5m", "RAM Replay Buffer Session TTL duration (e.g. 1m, 5m, 15m)")
	quiet := fs.Bool("quiet", false, "Silence status banners and log output for clean Unix piping")
	fs.BoolVar(quiet, "q", false, "Silence status banners (shorthand)")
	f1 := fs.String("file", "", "File path to transmit automatically")
	f2 := fs.String("f", "", "File path to transmit automatically (shorthand)")
	quicMode := fs.Bool("quic", false, "Use QUIC UDP transport mode instead of TCP")
	fingerprint := fs.String("fingerprint", "", "Expected SPKI SHA-256 TLS certificate fingerprint for strict pinning")
	rekeyBytesStr := fs.String("rekey-bytes", "1G", "Payload byte threshold for in-stream key ratcheting (e.g. 500M, 1G, 0 to disable)")
	rekeyTimeStr := fs.String("rekey-time", "1h", "Time threshold for in-stream key ratcheting (e.g. 30m, 1h, 0 to disable)")
	logFormat := fs.String("log-format", "text", "Log format: 'text' (default) or 'json'")
	logLevel := fs.String("log-level", "info", "Log level: 'debug', 'info', 'warn', 'error'")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *quiet {
		logger.InitWithWriter(*logFormat, "error", io.Discard)
	} else {
		logger.Init(*logFormat, *logLevel)
	}

	passVal := parsePassphrase(p1, p2, p3, p4, p5)
	generatedCode := passVal == ""
	if generatedCode {
		passVal = generateChannelCode()
		logStderr(*quiet, "\n[!] No --channel specified. Generated High-Entropy Channel Code (~80 bits):\n")
		logStderr(*quiet, "    >>> %s <<<\n\n", passVal)
	} else if len(passVal) < 16 {
		logStderr(*quiet, "\n[!] WARNING: Custom passphrase has lower entropy (%d chars).\n", len(passVal))
		logStderr(*quiet, "    For maximum protection against active relay MITM attacks, use default 5-word generated codes.\n\n")
	}

	relayAddr, err := resolveRelayAddr(*r1, *r2)
	if err != nil {
		return err
	}

	fileToSend := *f1
	if *f2 != "" {
		fileToSend = *f2
	}

	ttlDuration, err := time.ParseDuration(*ttlStr)
	if err != nil {
		return fmt.Errorf("invalid --ttl format: %w", err)
	}

	passBytes := []byte(passVal)
	crypto.RegisterBuffer(passBytes)
	defer crypto.ZeroBytes(passBytes)

	pub, err := feed.NewPublisherEngine(passBytes, relayAddr)
	if err != nil {
		return err
	}

	rekeyByteLimit := parseByteSize(*rekeyBytesStr)
	rekeyTimeLimit, _ := time.ParseDuration(*rekeyTimeStr)
	pub.SetRekeyThresholds(rekeyByteLimit, rekeyTimeLimit)

	if *fingerprint != "" {
		pub.SetSPKIFingerprint(*fingerprint)
	}

	if *quicMode {
		pub.SetTransportMode(transport.ModeQUIC)
	}

	ctx, cancel := setupSignalContext()
	defer cancel()

	tModeStr := "TCP"
	if *quicMode {
		tModeStr = "QUIC (UDP)"
	}

	inv := feed.GenerateInvite(passVal, relayAddr)

	logStderr(*quiet, "====================================================\n")
	logStderr(*quiet, " [ZeroFeed Publisher] Active Session\n")
	// A freshly generated code is echoed once above and must stay readable here
	// so it can be shared; a code the caller already supplied is only masked.
	if generatedCode {
		logStderr(*quiet, " Code / Passphrase : %s\n", passVal)
	} else {
		logStderr(*quiet, " Code / Passphrase : %s (supplied)\n", maskSecret(passVal))
	}
	logStderr(*quiet, " Session ID        : %x\n", pub.SessionID())
	logStderr(*quiet, " Relay Server      : %s\n", relayAddr)
	logStderr(*quiet, " Transport Mode    : %s\n", tModeStr)
	logStderr(*quiet, " Web Link          : %s\n", inv.ToWebURL())
	logStderr(*quiet, " Native URI        : %s\n", inv.ToURI())
	logStderr(*quiet, " Session TTL       : %s\n", ttlDuration)
	logStderr(*quiet, " Stream Mode       : %t\n", *streamMode)
	logStderr(*quiet, "====================================================\n")

	if err := pub.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to relay: %w", err)
	}

	logStderr(*quiet, "Waiting for Subscriber connection...\n")
	if err := pub.CompleteHandshake(ttlDuration); err != nil {
		return fmt.Errorf("subscriber handshake failed: %w", err)
	}
	logStderr(*quiet, "[+] Authenticated PAKE session established! E2EE stream ready.\n")
	logStderr(*quiet, "    🛡️ SAS Verification Badge: %s [%s]\n", pub.SASEmoji(), pub.SASFingerprint())

	if fileToSend != "" {
		logStderr(*quiet, "[!] Transmitting file: %s...\n", fileToSend)
		if err := pub.SendFile(ctx, fileToSend); err != nil {
			return fmt.Errorf("error sending file: %w", err)
		}
		logStderr(*quiet, "[✓] File %s transmitted successfully!\n", filepath.Base(fileToSend))
		return nil
	}

	if fileToSend == "" && !*streamMode && isTerminal(os.Stdin) {
		logStderr(*quiet, "[i] Reading payload from terminal (press Ctrl+D when finished, or type /file <path>)...\n")
	}

	// Piped stdin is forwarded as raw chunks, so the engine must not infer a tag
	// from the first byte; interactive lines below are tagged explicitly.
	pub.SetUntaggedInput(!isTerminal(os.Stdin))

	inputChan := make(chan []byte, 10)
	go func() {
		defer close(inputChan)
		if !isTerminal(os.Stdin) {
			readBuf := make([]byte, 32768)
			for {
				n, rErr := os.Stdin.Read(readBuf)
				if n > 0 {
					chunk := make([]byte, n)
					copy(chunk, readBuf[:n])
					crypto.RegisterBuffer(chunk)
					inputChan <- chunk
				}
				if rErr != nil {
					break
				}
			}
			return
		}

		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "/send ") || strings.HasPrefix(line, "/file ") {
				parts := strings.SplitN(line, " ", 2)
				if len(parts) == 2 {
					filePath := strings.TrimSpace(parts[1])
					logStderr(*quiet, "[!] Transmitting file: %s...\n", filePath)
					if err := pub.SendFile(ctx, filePath); err != nil {
						logStderr(*quiet, "Error sending file %s: %v\n", filePath, err)
					} else {
						logStderr(*quiet, "[✓] File %s transmitted successfully!\n", filepath.Base(filePath))
					}
					continue
				}
			}

			msgBytes := append([]byte{protocol.TagText}, []byte(line+"\n")...)
			crypto.RegisterBuffer(msgBytes)
			inputChan <- msgBytes
		}
	}()

	if err := pub.PublishStream(ctx, inputChan); err != nil {
		logStderr(*quiet, "Publish stream closed: %v\n", err)
	}
	return nil
}

type wipingWriter struct {
	w io.Writer
}

func (ww *wipingWriter) Write(p []byte) (n int, err error) {
	n, err = ww.w.Write(p)
	// Scrub immediate write buffer after outputting
	crypto.ZeroBytes(p)
	if err != nil && (errors.Is(err, syscall.EPIPE) || strings.Contains(err.Error(), "broken pipe")) {
		return n, io.EOF
	}
	return n, err
}

func runSubscribe(args []string) error {
	fs := flag.NewFlagSet("subscribe", flag.ContinueOnError)
	p1 := fs.String("passphrase", "", "Shared passphrase for E2EE PAKE session")
	p2 := fs.String("p", "", "Shared passphrase (shorthand)")
	p3 := fs.String("c", "", "Shared passphrase (alias)")
	p4 := fs.String("code", "", "Shared passphrase (alias)")
	p5 := fs.String("channel", "", "Shared passphrase (alias)")

	r1 := fs.String("relay", "", "Relay server address(es), comma-separated for fallback (e.g. relay1.example.com:8443,relay2.example.com:8443). Defaults to "+feed.DefaultRelayDNS+" if unset.")
	r2 := fs.String("r", "", "Relay server address (shorthand)")
	streamMode := fs.Bool("stream", false, "Continuous streaming mode")
	fs.BoolVar(streamMode, "s", false, "Continuous streaming mode (shorthand)")
	quiet := fs.Bool("quiet", false, "Silence status banners and log output for clean Unix piping")
	fs.BoolVar(quiet, "q", false, "Silence status banners (shorthand)")
	quicMode := fs.Bool("quic", false, "Use QUIC UDP transport mode instead of TCP")
	fingerprint := fs.String("fingerprint", "", "Expected SPKI SHA-256 TLS certificate fingerprint for strict pinning")
	logFormat := fs.String("log-format", "text", "Log format: 'text' (default) or 'json'")
	logLevel := fs.String("log-level", "info", "Log level: 'debug', 'info', 'warn', 'error'")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *quiet {
		logger.InitWithWriter(*logFormat, "error", io.Discard)
	} else {
		logger.Init(*logFormat, *logLevel)
	}

	passVal := parsePassphrase(p1, p2, p3, p4, p5)
	if passVal == "" && len(fs.Args()) > 0 {
		passVal = fs.Args()[0]
	}
	if passVal == "" {
		fs.Usage()
		return errors.New("--passphrase (or -p, -c, --code, --channel or positional invite URI) is required")
	}

	var relayAddr string
	inv, invErr := feed.ParseInvite(passVal)
	if invErr == nil && inv != nil {
		passVal = inv.Code
		if inv.RelayAddr != "" && *r1 == "" && *r2 == "" {
			relayAddr = inv.RelayAddr
		} else {
			var err error
			relayAddr, err = resolveRelayAddr(*r1, *r2)
			if err != nil {
				return err
			}
		}
		if inv.TransportMode == "quic" {
			*quicMode = true
		}
		if inv.SPKIFingerprint != "" && *fingerprint == "" {
			*fingerprint = inv.SPKIFingerprint
		}
	} else {
		var err error
		relayAddr, err = resolveRelayAddr(*r1, *r2)
		if err != nil {
			return err
		}
	}

	codeBytes := []byte(passVal)
	crypto.RegisterBuffer(codeBytes)
	defer crypto.ZeroBytes(codeBytes)

	sub, err := feed.NewSubscriberEngine(codeBytes, relayAddr)
	if err != nil {
		return err
	}

	if *fingerprint != "" {
		sub.SetSPKIFingerprint(*fingerprint)
	}

	if *quicMode {
		sub.SetTransportMode(transport.ModeQUIC)
	}

	ctx, cancel := setupSignalContext()
	defer cancel()

	tModeStr := "TCP"
	if *quicMode {
		tModeStr = "QUIC (UDP)"
	}

	logStderr(*quiet, "====================================================\n")
	logStderr(*quiet, " [ZeroFeed Subscriber] Active Session\n")
	// The caller already holds this code, so echoing it verbatim only risks
	// leaking it into scrollback or captured logs.
	logStderr(*quiet, " Code / Passphrase : %s\n", maskSecret(passVal))
	logStderr(*quiet, " Session ID        : %x\n", sub.SessionID())
	logStderr(*quiet, " Relay Server      : %s\n", relayAddr)
	logStderr(*quiet, " Transport Mode    : %s\n", tModeStr)
	logStderr(*quiet, " Stream Mode       : %t\n", *streamMode)
	logStderr(*quiet, "====================================================\n")

	if err := sub.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to relay: %w", err)
	}

	if err := sub.CompleteHandshake(0); err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}
	logStderr(*quiet, "[+] Authenticated PAKE session established! Decrypting stream...\n")
	logStderr(*quiet, "    🛡️ SAS Verification Badge: %s [%s]\n", sub.SASEmoji(), sub.SASFingerprint())

	stdoutWiper := &wipingWriter{w: os.Stdout}
	if err := sub.SubscribeStream(ctx, stdoutWiper, nil); err != nil {
		if !errors.Is(err, io.EOF) {
			logStderr(*quiet, "Stream closed: %v\n", err)
		}
	}
	return nil
}

func runRelay(args []string) error {
	fs := flag.NewFlagSet("relay", flag.ContinueOnError)
	port := fs.Int("port", 8443, "Relay listening TCP/UDP port")
	fs.IntVar(port, "p", 8443, "Relay listening TCP/UDP port (shorthand)")
	quicMode := fs.Bool("quic", false, "Enable QUIC UDP listener alongside TCP")
	wsPort := fs.Int("ws-port", 8444, "WebSocket HTTP listening port for browser WASM subscribers")
	wsCert := fs.String("ws-cert", "", "Optional TLS certificate file path for WSS (WebSocket Secure)")
	wsKey := fs.String("ws-key", "", "Optional TLS private key file path for WSS (WebSocket Secure)")
	noRateLimit := fs.Bool("no-rate-limit", false, "Disable IP rate limiting (recommended when deployed behind reverse proxies like Fly.io)")
	trustProxy := fs.Bool("trust-proxy", false, "Enable PROXY Protocol v2 header parsing for trusted reverse proxies (e.g. HAProxy, AWS NLB)")
	metricsPort := fs.Int("metrics-port", 0, "Optional HTTP port for zero-knowledge Prometheus metrics exporter (e.g. 9090)")
	metricsAddr := fs.String("metrics-addr", "", "Optional HTTP address for zero-knowledge Prometheus metrics exporter (e.g. 127.0.0.1:9090)")
	logFormat := fs.String("log-format", "text", "Log format: 'text' (default) or 'json'")
	logLevel := fs.String("log-level", "info", "Log level: 'debug', 'info', 'warn', 'error'")

	if err := fs.Parse(args); err != nil {
		return err
	}

	logger.Init(*logFormat, *logLevel)

	mAddr := *metricsAddr
	if mAddr == "" && *metricsPort > 0 {
		mAddr = fmt.Sprintf("0.0.0.0:%d", *metricsPort)
	}

	listenAddr := fmt.Sprintf("0.0.0.0:%d", *port)
	srv := relay.NewServer(listenAddr)
	if *noRateLimit {
		srv.SetRateLimiting(false)
	}
	if *trustProxy {
		srv.SetTrustProxy(true)
	}
	crypto.RegisterWiper(func() {
		_ = srv.Close()
	})

	ctx, cancel := setupSignalContext()
	defer cancel()

	if mAddr != "" {
		_ = srv.StartMetricsServer(ctx, mAddr)
	}

	if *wsPort > 0 {
		_ = srv.StartWebSocketTLSServer(ctx, fmt.Sprintf("0.0.0.0:%d", *wsPort), *wsCert, *wsKey)
	}

	if *quicMode {
		go func() {
			_ = srv.StartQUIC(ctx)
		}()
	}

	modeStr := "TCP"
	if *quicMode {
		modeStr = "TCP + QUIC (UDP)"
	}

	if logger.Format() == logger.FormatJSON {
		logger.Info("ZeroFeed Standalone Relay Node starting",
			"port", *port,
			"mode", modeStr,
			"ws_port", *wsPort,
			"metrics_addr", mAddr,
			"trust_proxy", *trustProxy,
			"rate_limit", !*noRateLimit,
		)
	} else {
		fmt.Fprintln(os.Stderr, "====================================================")
		fmt.Fprintln(os.Stderr, " [ZeroFeed Standalone Relay Node]")
		fmt.Fprintf(os.Stderr, " Listening Port : %d (%s)\n", *port, modeStr)
		if *wsPort > 0 {
			fmt.Fprintf(os.Stderr, " WebSocket Port : %d (ws://)\n", *wsPort)
		}
		if mAddr != "" {
			fmt.Fprintf(os.Stderr, " Metrics Server : http://%s/metrics (Prometheus)\n", mAddr)
		}
		fmt.Fprintln(os.Stderr, " Mode           : Ephemeral RAM-Only Zero-Knowledge Relay")
		fmt.Fprintln(os.Stderr, "====================================================")
	}

	if err := srv.Start(ctx); err != nil {
		return fmt.Errorf("relay server failed: %w", err)
	}
	return nil
}

func runGen() {
	fmt.Println(generateChannelCode())
}

func generateChannelCode() string {
	words := []string{
		"quantum", "shield", "cipher", "falcon", "orbit", "phoenix", "pulse", "matrix",
		"vector", "horizon", "shadow", "starlight", "vortex", "cobalt", "emerald", "aurora",
		"hyper", "nebula", "zenith", "vertex", "nexus", "prism", "spectre", "titan",
		"argon", "beacon", "celestial", "dynasty", "eclipse", "frontier", "glacier", "helix",
		"impulse", "jupiter", "krypton", "lunar", "magnet", "neutron", "omega", "polaris",
		"quasar", "radiant", "solar", "tachyon", "uranium", "velocity", "wavelength", "xray",
		"yield", "zodiac", "anchor", "blaze", "cascade", "dragon", "echo", "frost",
		"granite", "haven", "iron", "jasper", "knight", "lotus", "mirage", "nova",
		"onyx", "phantom", "quartz", "raven", "sapphire", "thunder", "umbra", "valkyrie",
		"whisper", "xenon", "yeti", "zephyr", "abyss", "boulder", "comet", "dune",
		"element", "forge", "gargoyle", "harbor", "infinity", "jungle", "kinetic", "lightning",
		"monolith", "navig", "obsidian", "pyramid", "quest", "rift", "spire", "tempest",
		"utopia", "vanguard", "wildfire", "zenit", "asteroid", "blizzard", "cosmos", "dynamo",
		"entropy", "fissure", "gravity", "hurricane", "impact", "journey", "keystone", "leviathan",
		"maelstrom", "nadir", "oasis", "pulsar", "quarry", "resonance", "solstice", "typhoon",
		"ultravio", "vortexa", "vortexb", "whirlpool", "xiphos", "yggdrasil", "zenithal", "apex",
		"bastion", "citadel", "domain", "empire", "fortress", "guardian", "hyperion", "isotope",
		"juggernaut", "kryptonite", "labyrinth", "meridian", "nemesis", "oracle", "pathfinder", "quantumx",
		"renegade", "sentinel", "torpedo", "universe", "vanguardx", "warlord", "xenonite", "yottabyte",
		"zeus", "avalanche", "barrier", "chasm", "equinox", "firewall", "grid", "hyperdrive",
		"inferno", "jackhammer", "kilometer", "luminary", "meteor", "neutrino", "overload", "parsec",
		"qubit", "raytrace", "singularity", "thruster", "unifier", "vectorx", "warp", "xenonx",
		"yieldx", "zero-point", "arc", "bolt", "core", "disk", "flux", "gate",
		"hub", "ion", "jet", "kilobyte", "link", "mesh", "node", "overdrive",
		"port", "quad", "ram", "sync", "turboflow", "unit", "volt", "watt",
		"xenon z", "yaw", "zone", "alpha", "beta", "gamma", "delta", "epsilon",
		"zeta", "eta", "theta", "iota", "kappa", "lambda", "mu", "nu",
		"xi", "omicron", "pi", "rho", "sigma", "tau", "upsilon", "phi",
		"chi", "psi", "omega-core", "antimatter", "biome", "chronos", "darkmatter", "exoplanet",
	}

	b := make([]byte, 12)
	_, _ = cryptoRand.Read(b)

	n := uint32(len(words))
	maxVal := uint32(256) - (uint32(256) % n)

	getUnbiasedWord := func(rawByte byte) string {
		val := uint32(rawByte)
		if val >= maxVal {
			tb := make([]byte, 1)
			for {
				_, _ = cryptoRand.Read(tb)
				val = uint32(tb[0])
				if val < maxVal {
					break
				}
			}
		}
		return words[val%n]
	}

	w1 := getUnbiasedWord(b[0])
	w2 := getUnbiasedWord(b[1])
	w3 := getUnbiasedWord(b[2])
	w4 := getUnbiasedWord(b[3])
	w5 := getUnbiasedWord(b[4])
	num := binary.BigEndian.Uint32(b[5:])%900000 + 100000

	return fmt.Sprintf("%s-%s-%s-%s-%s-%d", w1, w2, w3, w4, w5, num)
}

func runInvite(args []string) error {
	fs := flag.NewFlagSet("invite", flag.ContinueOnError)
	p1 := fs.String("passphrase", "", "Shared passphrase for E2EE session")
	p2 := fs.String("code", "", "Shared passphrase (alias)")
	r1 := fs.String("relay", "", "Relay server address")
	r2 := fs.String("r", "", "Relay server address (shorthand)")
	quiet := fs.Bool("quiet", false, "Silence status banners for clean piping")
	fs.BoolVar(quiet, "q", false, "Silence status banners (shorthand)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	passVal := parsePassphrase(p1, p2, nil, nil, nil)
	if passVal == "" && len(fs.Args()) > 0 {
		passVal = fs.Args()[0]
	}
	if passVal == "" {
		passVal = generateChannelCode()
	}

	relayAddr := *r1
	if relayAddr == "" {
		relayAddr = *r2
	}
	if relayAddr == "" {
		relayAddr = os.Getenv("ZEROFEED_RELAY")
	}
	if relayAddr == "" {
		relayAddr = feed.DefaultRelayDNS + ":" + feed.DefaultRelayPort
	}
	inv := feed.GenerateInvite(passVal, relayAddr)

	if *quiet {
		fmt.Println(inv.ToURI())
	} else {
		fmt.Fprintln(os.Stderr, inv.FormatBanner())
	}
	return nil
}

func isTerminal(f *os.File) bool {
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func runJoin(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: zerofeed join <invite-code-or-uri-or-url>")
	}
	return runSubscribe(args)
}

func printUsage() {
	fmt.Println("ZeroFeed: Zero-Knowledge Ephemeral Pub/Sub Engine")
	fmt.Println("\nUsage:")
	fmt.Println("  zerofeed invite [code] [--relay <addr>]")
	fmt.Println("  zerofeed join <invite|code|uri>")
	fmt.Println("  zerofeed publish [--channel <code|passphrase>] [--ttl 5m] [--stream] [--quic] [--quiet]")
	fmt.Println("  zerofeed subscribe --code <code|passphrase|uri> [--stream] [--quic] [--quiet]")
	fmt.Println("  zerofeed relay [--port 8443] [--quic]")
	fmt.Println("  zerofeed gen")
	fmt.Println("  zerofeed version")
	fmt.Println("\nRun 'zerofeed <subcommand> --help' for details.")
}
