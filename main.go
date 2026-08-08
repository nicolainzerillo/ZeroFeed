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
	defer crypto.WipeAll()

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]
	args := os.Args[2:]

	switch subcommand {
	case "publish", "pub":
		runPublish(args)
	case "subscribe", "sub":
		runSubscribe(args)
	case "relay":
		runRelay(args)
	case "gen", "generate":
		runGen()
	case "version", "-v", "--version":
		fmt.Println(version.Info())
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n\n", subcommand)
		printUsage()
		os.Exit(1)
	}
}

func logStderr(quiet bool, format string, a ...interface{}) {
	if quiet {
		return
	}
	fmt.Fprintf(os.Stderr, format, a...)
}

func parsePassphrase(p1, p2, p3, p4, p5 *string) string {
	for _, p := range []*string{p1, p2, p3, p4, p5} {
		if p != nil && *p != "" {
			return *p
		}
	}
	return ""
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
// Supports comma-separated lists for fallback (tries each in order, returns first reachable).
func resolveRelayAddr(r1, r2 string) string {
	raw := r2
	if raw == "" {
		raw = r1
	}
	if raw == "" {
		raw = os.Getenv("ZEROFEED_RELAY")
	}
	if raw == "" {
		relays := feed.ResolveDefaultRelays()
		if len(relays) == 0 {
			fmt.Fprintf(os.Stderr, "Error: no relay specified and DNS lookup of %s failed.\n", feed.DefaultRelayDNS)
			fmt.Fprintf(os.Stderr, "Use --relay <address> or set ZEROFEED_RELAY.\n")
			os.Exit(1)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, addr, err := feed.DialFirstAvailable(ctx, relays, 2*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: all resolved relays unreachable: %v\n", err)
			os.Exit(1)
		}
		return addr
	}
	list := feed.ParseRelayList(raw)
	if len(list) == 1 {
		return list[0]
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, addr, err := feed.DialFirstAvailable(ctx, list, 2*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: relay fallback exhausted, using first: %s\n", list[0])
		return list[0]
	}
	return addr
}

func runPublish(args []string) {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
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

	_ = fs.Parse(args)

	passVal := parsePassphrase(p1, p2, p3, p4, p5)
	if passVal == "" {
		passVal = generateChannelCode()
		fmt.Fprintf(os.Stderr, "\n[!] No --channel specified. Generated High-Entropy Channel Code:\n")
		fmt.Fprintf(os.Stderr, "    >>> %s <<<\n\n", passVal)
	}

	relayAddr := resolveRelayAddr(*r1, *r2)

	fileToSend := *f1
	if *f2 != "" {
		fileToSend = *f2
	}

	ttlDuration, err := time.ParseDuration(*ttlStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid --ttl format: %v\n", err)
		os.Exit(1)
	}

	passBytes := []byte(passVal)
	crypto.RegisterBuffer(passBytes)
	defer crypto.ZeroBytes(passBytes)

	pub, err := feed.NewPublisherEngine(passBytes, relayAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
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

	logStderr(*quiet, "====================================================\n")
	logStderr(*quiet, " [ZeroFeed Publisher] Active Session\n")
	logStderr(*quiet, " Code / Passphrase : %s\n", passVal)
	logStderr(*quiet, " Session ID        : %x\n", pub.SessionID())
	logStderr(*quiet, " Relay Server      : %s\n", relayAddr)
	logStderr(*quiet, " Transport Mode    : %s\n", tModeStr)
	logStderr(*quiet, " Session TTL       : %s\n", ttlDuration)
	logStderr(*quiet, " Stream Mode       : %t\n", *streamMode)
	logStderr(*quiet, "====================================================\n")

	if err := pub.Connect(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to connect to relay: %v\n", err)
		os.Exit(1)
	}

	logStderr(*quiet, "Waiting for Subscriber connection...\n")
	if err := pub.CompleteHandshake(ttlDuration); err != nil {
		fmt.Fprintf(os.Stderr, "Error: subscriber handshake failed: %v\n", err)
		os.Exit(1)
	}
	logStderr(*quiet, "[+] Authenticated PAKE session established! E2EE stream ready.\n")
	logStderr(*quiet, "    🛡️ SAS Verification Badge: %s [%s]\n", pub.SASEmoji(), pub.SASFingerprint())

	if fileToSend != "" {
		logStderr(*quiet, "[!] Transmitting file: %s...\n", fileToSend)
		if err := pub.SendFile(ctx, fileToSend); err != nil {
			fmt.Fprintf(os.Stderr, "Error sending file: %v\n", err)
			os.Exit(1)
		}
		logStderr(*quiet, "[✓] File %s transmitted successfully!\n", filepath.Base(fileToSend))
		return
	}

	inputChan := make(chan []byte, 10)
	go func() {
		defer close(inputChan)
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "/send ") || strings.HasPrefix(line, "/file ") {
				parts := strings.SplitN(line, " ", 2)
				if len(parts) == 2 {
					filePath := strings.TrimSpace(parts[1])
					logStderr(*quiet, "[!] Transmitting file: %s...\n", filePath)
					if err := pub.SendFile(ctx, filePath); err != nil {
						fmt.Fprintf(os.Stderr, "Error sending file %s: %v\n", filePath, err)
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

		if err := scanner.Err(); err != nil {
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
		}
	}()

	if err := pub.PublishStream(ctx, inputChan); err != nil {
		fmt.Fprintf(os.Stderr, "Publish stream closed: %v\n", err)
	}
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

func runSubscribe(args []string) {
	fs := flag.NewFlagSet("subscribe", flag.ExitOnError)
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

	_ = fs.Parse(args)

	passVal := parsePassphrase(p1, p2, p3, p4, p5)
	if passVal == "" {
		fmt.Fprintln(os.Stderr, "Error: --passphrase (or -p, -c, --code, --channel) is required.")
		fs.Usage()
		os.Exit(1)
	}

	relayAddr := resolveRelayAddr(*r1, *r2)

	codeBytes := []byte(passVal)
	crypto.RegisterBuffer(codeBytes)
	defer crypto.ZeroBytes(codeBytes)

	sub, err := feed.NewSubscriberEngine(codeBytes, relayAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
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
	logStderr(*quiet, " Code / Passphrase : %s\n", passVal)
	logStderr(*quiet, " Session ID        : %x\n", sub.SessionID())
	logStderr(*quiet, " Relay Server      : %s\n", relayAddr)
	logStderr(*quiet, " Transport Mode    : %s\n", tModeStr)
	logStderr(*quiet, " Stream Mode       : %t\n", *streamMode)
	logStderr(*quiet, "====================================================\n")

	if err := sub.Connect(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to connect to relay: %v\n", err)
		os.Exit(1)
	}

	if err := sub.CompleteHandshake(0); err != nil {
		fmt.Fprintf(os.Stderr, "Error: handshake failed: %v\n", err)
		os.Exit(1)
	}
	logStderr(*quiet, "[+] Authenticated PAKE session established! Decrypting stream...\n")
	logStderr(*quiet, "    🛡️ SAS Verification Badge: %s [%s]\n", sub.SASEmoji(), sub.SASFingerprint())

	stdoutWiper := &wipingWriter{w: os.Stdout}
	if err := sub.SubscribeStream(ctx, stdoutWiper, nil); err != nil {
		if !errors.Is(err, io.EOF) {
			fmt.Fprintf(os.Stderr, "Stream closed: %v\n", err)
		}
	}
}

func runRelay(args []string) {
	fs := flag.NewFlagSet("relay", flag.ExitOnError)
	port := fs.Int("port", 8443, "Relay listening TCP/UDP port")
	fs.IntVar(port, "p", 8443, "Relay listening TCP/UDP port (shorthand)")
	quicMode := fs.Bool("quic", false, "Enable QUIC UDP listener alongside TCP")
	wsPort := fs.Int("ws-port", 8444, "WebSocket HTTP listening port for browser WASM subscribers")
	noRateLimit := fs.Bool("no-rate-limit", false, "Disable IP rate limiting (recommended when deployed behind reverse proxies like Fly.io)")
	trustProxy := fs.Bool("trust-proxy", false, "Enable PROXY Protocol v2 header parsing for trusted reverse proxies (e.g. HAProxy, AWS NLB)")
	metricsPort := fs.Int("metrics-port", 0, "Optional HTTP port for zero-knowledge Prometheus metrics exporter (e.g. 9090)")
	metricsAddr := fs.String("metrics-addr", "", "Optional HTTP address for zero-knowledge Prometheus metrics exporter (e.g. 127.0.0.1:9090)")

	_ = fs.Parse(args)

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
		_ = srv.StartWebSocketServer(ctx, fmt.Sprintf("0.0.0.0:%d", *wsPort))
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

	if err := srv.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error: relay server failed: %v\n", err)
		os.Exit(1)
	}
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
		"zeus", "avalanche", "barrier", "chasm", "eclipse", "firewall", "grid", "hyperdrive",
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

	b := make([]byte, 8)
	_, _ = cryptoRand.Read(b)

	w1 := words[int(b[0])%len(words)]
	w2 := words[int(b[1])%len(words)]
	w3 := words[int(b[2])%len(words)]
	w4 := words[int(b[3])%len(words)]
	w5 := words[int(b[4])%len(words)]
	num := binary.BigEndian.Uint32(b[4:])%900000 + 100000

	return fmt.Sprintf("%s-%s-%s-%s-%s-%d", w1, w2, w3, w4, w5, num)
}

func printUsage() {
	fmt.Println("ZeroFeed: Zero-Knowledge Ephemeral Pub/Sub Engine")
	fmt.Println("\nUsage:")
	fmt.Println("  zerofeed publish --channel <code|passphrase> [--ttl 5m] [--stream] [--quic] [--quiet]")
	fmt.Println("  zerofeed subscribe --code <code|passphrase> [--stream] [--quic] [--quiet]")
	fmt.Println("  zerofeed relay [--port 8443] [--quic]")
	fmt.Println("  zerofeed gen")
	fmt.Println("  zerofeed version")
	fmt.Println("\nRun 'zerofeed <subcommand> --help' for details.")
}
