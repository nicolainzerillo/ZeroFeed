package feed

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zerofeed/zerofeed/pkg/crypto"
	"github.com/zerofeed/zerofeed/pkg/protocol"
	"github.com/zerofeed/zerofeed/pkg/transport"
)

const (
	DefaultRekeyByteThreshold uint64        = 1024 * 1024 * 1024 // 1GB
	DefaultRekeyTimeThreshold time.Duration = 1 * time.Hour      // 1 hour
)

// PublisherEngine manages PAKE negotiation, sequence-numbered AEAD frame encryption, and RAM replay buffer sync.
type PublisherEngine struct {
	passphrase          []byte
	masterKey           []byte
	relayAddr           string
	sessionID           [protocol.SessionIDSize]byte
	pakePeer            *crypto.PAKEPeer
	cipher              *crypto.Cipher
	conn                net.Conn
	seqCounter          uint64
	replayBuffer        *RingBuffer
	chunkAckChan        chan struct{}
	expectedFingerprint string
	transportMode       transport.Mode
	sasHex              string
	sasEmoji            string
	bytesSinceRekey     uint64
	lastRekeyTime       time.Time
	rekeyByteLimit      uint64
	rekeyTimeLimit      time.Duration
	untaggedInput       bool
	mu                  sync.Mutex
	rekeyMu             sync.Mutex
	writeMu             sync.Mutex
	closed              bool
}

// SetSPKIFingerprint configures expected SPKI SHA-256 TLS certificate fingerprint for strict pinning.
func (p *PublisherEngine) SetSPKIFingerprint(fingerprint string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.expectedFingerprint = fingerprint
}

// SetUntaggedInput declares that PublishStream's input channel carries raw,
// untagged payloads, so every message is tagged as text instead of having its
// first byte inspected. Set this for byte streams (e.g. piped stdin) whose
// content can legitimately begin with a tag value.
func (p *PublisherEngine) SetUntaggedInput(untagged bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.untaggedInput = untagged
}

// SetRekeyThresholds configures custom byte and time thresholds for in-stream key ratcheting.
func (p *PublisherEngine) SetRekeyThresholds(byteLimit uint64, timeLimit time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rekeyByteLimit = byteLimit
	p.rekeyTimeLimit = timeLimit
}

// NewPublisherEngine initializes a Publisher instance with a 100-message RAM replay buffer.
func NewPublisherEngine(passphrase []byte, relayAddr string) (*PublisherEngine, error) {
	sessionID := DeriveSessionID(passphrase)

	pakePeer, err := crypto.NewPAKEPublisher(passphrase)
	if err != nil {
		return nil, err
	}

	passCopy := make([]byte, len(passphrase))
	copy(passCopy, passphrase)

	masterKey := make([]byte, crypto.KeySize)
	if _, err := io.ReadFull(rand.Reader, masterKey); err != nil {
		crypto.ZeroBytes(passCopy)
		return nil, fmt.Errorf("zerofeed/feed: failed to generate random master session key: %w", err)
	}

	ciph, err := crypto.NewCipher(masterKey)
	if err != nil {
		crypto.ZeroBytes(passCopy)
		crypto.ZeroBytes(masterKey)
		return nil, err
	}

	sasHex, sasEmoji := crypto.CalculateSAS(masterKey)

	pub := &PublisherEngine{
		passphrase:     passCopy,
		masterKey:      masterKey,
		cipher:         ciph,
		sasHex:         sasHex,
		sasEmoji:       sasEmoji,
		relayAddr:      relayAddr,
		sessionID:      sessionID,
		pakePeer:       pakePeer,
		replayBuffer:   NewRingBuffer(100),
		lastRekeyTime:  time.Now(),
		rekeyByteLimit: DefaultRekeyByteThreshold,
		rekeyTimeLimit: DefaultRekeyTimeThreshold,
	}

	crypto.RegisterWiper(func() {
		pub.Close()
	})

	return pub, nil
}

// SessionID returns the current session identifier.
func (p *PublisherEngine) SessionID() [protocol.SessionIDSize]byte {
	return p.sessionID
}

// ReplayBuffer returns the RAM replay ring buffer instance.
func (p *PublisherEngine) ReplayBuffer() *RingBuffer {
	return p.replayBuffer
}

func (p *PublisherEngine) getConn() net.Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.conn
}

func (p *PublisherEngine) getCipher() *crypto.Cipher {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cipher
}

// SetTransportMode configures the transport mode (ModeTCP or ModeQUIC).
func (p *PublisherEngine) SetTransportMode(mode transport.Mode) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.transportMode = mode
}

// Connect dials the Relay server and performs the initial PAKE step 1 exchange.
func (p *PublisherEngine) Connect(ctx context.Context) error {
	p.mu.Lock()
	tMode := p.transportMode
	p.mu.Unlock()

	var conn net.Conn
	var err error

	if tMode == transport.ModeQUIC {
		quicCtx, quicCancel := context.WithTimeout(ctx, 3*time.Second)
		var qErr error
		conn, qErr = transport.DialQUIC(quicCtx, p.relayAddr)
		quicCancel()

		if qErr != nil {
			// Automatic fallback to TCP (TLS) if QUIC UDP times out or is blocked by network/proxy
			conn, err = DialRelayWithPin(ctx, p.relayAddr, p.expectedFingerprint)
		}
	} else {
		conn, err = DialRelayWithPin(ctx, p.relayAddr, p.expectedFingerprint)
	}

	if err != nil {
		return fmt.Errorf("zerofeed/feed: failed to dial relay (%s) at %s: %w", tMode, p.relayAddr, err)
	}

	p.mu.Lock()
	p.conn = conn
	if p.pakePeer == nil {
		pakePeer, pErr := crypto.NewPAKEPublisher(p.passphrase)
		if pErr != nil {
			p.mu.Unlock()
			_ = conn.Close()
			return pErr
		}
		p.pakePeer = pakePeer
	}
	p.mu.Unlock()

	// Send PAKE Step 1 frame
	pakeStep1Env := &protocol.Envelope{
		Version:   protocol.Version,
		MsgType:   protocol.MsgTypePAKEInitPub,
		SessionID: p.sessionID,
		Payload:   p.pakePeer.Bytes(),
	}

	if err := protocol.Encode(conn, pakeStep1Env); err != nil {
		_ = conn.Close()
		return fmt.Errorf("zerofeed/feed: failed to send PAKE step 1: %w", err)
	}

	return nil
}

// CompleteHandshake waits for a Subscriber PAKE step 1 payload, finishes PAKE derivation, and builds the AEAD cipher.
func (p *PublisherEngine) CompleteHandshake(timeout time.Duration) error {
	conn := p.getConn()
	if conn == nil {
		return fmt.Errorf("zerofeed/feed: connection not initialized")
	}

	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		defer conn.SetReadDeadline(time.Time{})
	}

	// Read Subscriber's PAKE payload frame from relay
	env, err := protocol.Decode(conn)
	if err != nil {
		return fmt.Errorf("zerofeed/feed: failed to receive subscriber PAKE response: %w", err)
	}

	if env.MsgType == protocol.MsgTypeClose {
		return fmt.Errorf("zerofeed/feed: session closed by peer/relay: %s", string(env.Payload))
	}

	if env.Version < protocol.MinSupportedVersion {
		return fmt.Errorf("zerofeed/feed: subscriber is using incompatible protocol version 0x%02X (expected 0x%02X+)", env.Version, protocol.MinSupportedVersion)
	}

	if env.MsgType != protocol.MsgTypePAKEInitSub && env.MsgType != protocol.MsgTypePAKEStep2 {
		return fmt.Errorf("zerofeed/feed: unexpected frame type during handshake: %d", env.MsgType)
	}

	if err := p.pakePeer.Update(env.Payload); err != nil {
		return fmt.Errorf("zerofeed/feed: PAKE key exchange failed: %w", err)
	}

	p2pKey, err := p.pakePeer.SessionKey()
	if err != nil {
		return fmt.Errorf("zerofeed/feed: PAKE session key derivation failed: %w", err)
	}
	defer crypto.ZeroBytes(p2pKey)

	p.mu.Lock()
	masterKeyCopy := make([]byte, len(p.masterKey))
	copy(masterKeyCopy, p.masterKey)
	p.mu.Unlock()
	defer crypto.ZeroBytes(masterKeyCopy)

	wrappedKeyPayload, err := crypto.WrapSessionKey(p2pKey, masterKeyCopy)
	if err != nil {
		return fmt.Errorf("zerofeed/feed: failed to wrap session key: %w", err)
	}

	pubConfirmTag, err := p.pakePeer.ConfirmTag()
	if err != nil {
		return fmt.Errorf("zerofeed/feed: failed to generate publisher confirm tag: %w", err)
	}

	pakeRespPayload := append(append(append([]byte(nil), p.pakePeer.Bytes()...), wrappedKeyPayload...), pubConfirmTag...)

	pakeStep2Env := &protocol.Envelope{
		Version:   protocol.Version,
		MsgType:   protocol.MsgTypePAKEStep2,
		SessionID: p.sessionID,
		Payload:   pakeRespPayload,
	}
	if err := protocol.Encode(conn, pakeStep2Env); err != nil {
		return fmt.Errorf("zerofeed/feed: failed to send PAKE step 2: %w", err)
	}

	// Wait for the subscriber's confirmation frame. The relay multiplexes every
	// subscriber onto this single connection, so another frame (e.g. a second
	// subscriber's handshake init) may arrive first: skip non-confirmation
	// frames instead of aborting the whole session, and match on the type. A
	// mismatched tag, or no confirmation within the read deadline, stays fatal.
	confirmed := false
	for i := 0; i < 8; i++ {
		confirmFrame, err := protocol.Decode(conn)
		if err != nil {
			return fmt.Errorf("zerofeed/feed: failed to receive subscriber key confirmation frame: %w", err)
		}
		if confirmFrame.MsgType != protocol.MsgTypeKeyConfirm {
			continue
		}
		if err := p.pakePeer.VerifyPeerConfirm(confirmFrame.Payload); err != nil {
			return fmt.Errorf("zerofeed/feed: subscriber key confirmation tag mismatch: %w", err)
		}
		confirmed = true
		break
	}
	if !confirmed {
		return fmt.Errorf("zerofeed/feed: subscriber key confirmation frame not received")
	}

	return nil
}

// SASFingerprint returns the 4-character hex SAS fingerprint string.
func (p *PublisherEngine) SASFingerprint() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sasHex
}

// SASEmoji returns the 2-emoji SAS visual verification badge.
func (p *PublisherEngine) SASEmoji() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sasEmoji
}

// PublishStream maintains a continuous P2P session loop reading payloads from inputChan, assigning sequence numbers, sending heartbeats, and broadcasting encrypted frames.
func (p *PublisherEngine) PublishStream(ctx context.Context, inputChan <-chan []byte) error {
	defer p.Close()

	// Async listener for incoming SYNC_REQ and subscriber reconnect handshakes
	go p.handleSyncRequests(ctx)

	// Heartbeat ticker to keep TCP session alive
	heartbeatTicker := time.NewTicker(3 * time.Second)
	defer heartbeatTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-heartbeatTicker.C:
			hbEnv := &protocol.Envelope{
				Version:   protocol.Version,
				MsgType:   protocol.MsgTypeHeartbeat,
				SessionID: p.sessionID,
			}
			_ = p.sendFrame(hbEnv)

		case payload, ok := <-inputChan:
			if !ok {
				return nil
			}

			if len(payload) == 0 {
				continue
			}

			p.mu.Lock()
			untagged := p.untaggedInput
			p.mu.Unlock()

			// Callers that declare an untagged stream always get an explicit tag.
			// Sniffing payload[0] is only a fallback for callers that mix
			// pre-tagged frames into the channel: it misreads raw bytes that
			// happen to start with a tag value (e.g. piped binary beginning
			// 0x02) as an already-tagged frame and routes them as file metadata.
			var taggedPayload []byte
			if untagged || (payload[0] != protocol.TagText && payload[0] != protocol.TagFileStart && payload[0] != protocol.TagFileChunk && payload[0] != protocol.TagFileEnd) {
				taggedPayload = make([]byte, 1+len(payload))
				taggedPayload[0] = protocol.TagText
				copy(taggedPayload[1:], payload)
			} else {
				taggedPayload = payload
			}

			if err := p.PublishPayload(ctx, taggedPayload); err != nil {
				return fmt.Errorf("zerofeed/feed: failed to publish payload: %w", err)
			}
		}
	}
}

func (p *PublisherEngine) sendFrame(env *protocol.Envelope) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()

	conn := p.getConn()
	if conn == nil {
		return fmt.Errorf("zerofeed/feed: connection closed")
	}

	return protocol.Encode(conn, env)
}

func (p *PublisherEngine) getPassphrase() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.passphrase == nil {
		return nil
	}
	passCopy := make([]byte, len(p.passphrase))
	copy(passCopy, p.passphrase)
	return passCopy
}

// handleSyncRequests listens for reconnecting subscribers and SYNC_REQ frames.
func (p *PublisherEngine) handleSyncRequests(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			conn := p.getConn()
			if conn == nil {
				return
			}

			_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			env, err := protocol.Decode(conn)
			_ = conn.SetReadDeadline(time.Time{})
			if err != nil {
				var netErr net.Error
				if (errors.As(err, &netErr) && netErr.Timeout()) || errors.Is(err, os.ErrDeadlineExceeded) {
					continue
				}
				return
			}

			switch env.MsgType {
			case protocol.MsgTypePAKEInitSub:
				pass := p.getPassphrase()
				if pass != nil {
					pakePeerSub, err := crypto.NewPAKEPublisher(pass)
					crypto.ZeroBytes(pass)
					if err == nil {
						_ = pakePeerSub.Update(env.Payload)
						p2pKey, pErr := pakePeerSub.SessionKey()
						if pErr == nil {
							p.mu.Lock()
							masterKeyCopy := make([]byte, len(p.masterKey))
							copy(masterKeyCopy, p.masterKey)
							p.mu.Unlock()

							wrappedKeyPayload, wErr := crypto.WrapSessionKey(p2pKey, masterKeyCopy)
							crypto.ZeroBytes(p2pKey)
							crypto.ZeroBytes(masterKeyCopy)

							if wErr == nil {
								pubConfirmTag, cErr := pakePeerSub.ConfirmTag()
								if cErr == nil {
									pakeRespPayload := append(append(append([]byte(nil), pakePeerSub.Bytes()...), wrappedKeyPayload...), pubConfirmTag...)
									pakeStep2Env := &protocol.Envelope{
										Version:   protocol.Version,
										MsgType:   protocol.MsgTypePAKEStep2,
										SessionID: p.sessionID,
										Payload:   pakeRespPayload,
									}
									// Do not inline-read the confirmation here: this goroutine is the
									// sole reader of the multiplexed relay connection, so a blocking
									// read could swallow an unrelated frame (ChunkAck/SyncReq) from
									// another subscriber. The reconnecting subscriber's KeyConfirm
									// frame is delivered to the main loop below and harmlessly ignored.
									_ = p.sendFrame(pakeStep2Env)
								}
							}
						}
						pakePeerSub.Close()
					}
				}

			case protocol.MsgTypeSyncReq:
				if len(env.Payload) >= 8 {
					lastSeqNum := binary.BigEndian.Uint64(env.Payload[0:8])
					p.replaySyncForSubscriber(lastSeqNum)
				}

			case protocol.MsgTypeChunkAck:
				p.mu.Lock()
				ackChan := p.chunkAckChan
				p.mu.Unlock()
				if ackChan != nil {
					select {
					case ackChan <- struct{}{}:
					default:
					}
				}
			}
		}
	}
}

// replaySyncForSubscriber replays all RAM-buffered messages with SeqNum > lastSeqNum.
func (p *PublisherEngine) replaySyncForSubscriber(lastSeqNum uint64) {
	items := p.replayBuffer.GetAfter(lastSeqNum)
	ciph := p.getCipher()
	conn := p.getConn()

	if ciph == nil || conn == nil {
		for _, item := range items {
			putBuffer(item.Payload)
		}
		return
	}

	defer func() {
		for _, item := range items {
			putBuffer(item.Payload)
		}
	}()

	var sessionSalt [4]byte
	copy(sessionSalt[:], p.sessionID[:4])

	for _, item := range items {
		nonce := crypto.ConstructNonceRFC5116(sessionSalt, item.SeqNum)

		// Pad every frame uniformly so the subscriber can always unpad. Small
		// frames (text) fill the 1280B bucket for traffic-analysis resistance;
		// large frames (file chunks) only carry the 4-byte length prefix.
		payloadToEncrypt := protocol.PadPayload(item.Payload, protocol.DefaultPaddingTargetSize)

		framePayloadLen := uint32(8 + len(payloadToEncrypt) + 16)
		headerBytes := make([]byte, protocol.HeaderSize)
		protocol.SerializeHeader(headerBytes, protocol.Version, protocol.MsgTypeDataStream, p.sessionID, nonce, framePayloadLen)

		ciphertext, _, err := ciph.Encrypt(payloadToEncrypt, nonce[:], headerBytes)
		if err != nil {
			continue
		}

		framePayload := make([]byte, 8+len(ciphertext))
		binary.BigEndian.PutUint64(framePayload[0:8], item.SeqNum)
		copy(framePayload[8:], ciphertext)

		frameEnv := &protocol.Envelope{
			Version:   protocol.Version,
			MsgType:   protocol.MsgTypeDataStream,
			SessionID: p.sessionID,
			Nonce:     nonce,
			Payload:   framePayload,
		}

		_ = p.sendFrame(frameEnv)
	}
}

// Close gracefully terminates the publisher session, sends a CLOSE frame, and zeroes cryptographic key buffers and replay buffer.
func (p *PublisherEngine) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return
	}
	p.closed = true

	if p.conn != nil {
		closeEnv := &protocol.Envelope{
			Version:   protocol.Version,
			MsgType:   protocol.MsgTypeClose,
			SessionID: p.sessionID,
		}
		p.writeMu.Lock()
		_ = protocol.Encode(p.conn, closeEnv)
		p.writeMu.Unlock()
		time.Sleep(100 * time.Millisecond) // Allow TCP socket buffer flush before teardown
		_ = p.conn.Close()
		p.conn = nil
	}

	if p.cipher != nil {
		p.cipher.Close()
		p.cipher = nil
	}

	if p.pakePeer != nil {
		p.pakePeer.Close()
		p.pakePeer = nil
	}

	if p.masterKey != nil {
		crypto.ZeroBytes(p.masterKey)
		p.masterKey = nil
	}

	if p.passphrase != nil {
		crypto.ZeroBytes(p.passphrase)
		p.passphrase = nil
	}

	if p.replayBuffer != nil {
		p.replayBuffer.Wipe()
	}
}

// SendFile streams a file over the E2EE session with metadata headers and 32KB binary chunks.
func (p *PublisherEngine) SendFile(ctx context.Context, filePath string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("zerofeed/feed: failed to open file for sending: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("zerofeed/feed: failed to stat file: %w", err)
	}

	randomBytes := make([]byte, 8)
	_, _ = rand.Read(randomBytes)
	transferID := hex.EncodeToString(randomBytes)

	// Calculate SHA-256 checksum of source file
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return fmt.Errorf("zerofeed/feed: failed to calculate file SHA-256: %w", err)
	}
	_, _ = f.Seek(0, 0)
	sha256Sum := hex.EncodeToString(hasher.Sum(nil))

	header := protocol.FileHeader{
		TransferID: transferID,
		Filename:   filepath.Base(filePath),
		FileSize:   info.Size(),
		SHA256:     sha256Sum,
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return err
	}

	// 1. Send TagFileStart
	startPayload := append([]byte{protocol.TagFileStart}, headerBytes...)
	if err := p.PublishPayload(ctx, startPayload); err != nil {
		return err
	}

	// Prepare ACK channel for sliding window backpressure
	ackChan := make(chan struct{}, 10)
	p.mu.Lock()
	p.chunkAckChan = ackChan
	p.mu.Unlock()

	defer func() {
		p.mu.Lock()
		p.chunkAckChan = nil
		p.mu.Unlock()
	}()

	// 2. Stream TagFileChunk (Dynamic chunk sizing: 32KB for <10MB, 128KB for 10-100MB, 512KB for >100MB)
	chunkSize := 32768
	if info.Size() >= 100*1024*1024 {
		chunkSize = 524288
	} else if info.Size() >= 10*1024*1024 {
		chunkSize = 131072
	}

	readBuf := make([]byte, chunkSize)
	var unackedChunks int

	pb := NewProgressBar(info.Size(), false)

	for {
		n, err := f.Read(readBuf)
		if n > 0 {
			chunkPayload := append(append([]byte{protocol.TagFileChunk}, []byte(transferID)...), readBuf[:n]...)
			if pubErr := p.PublishPayload(ctx, chunkPayload); pubErr != nil {
				return pubErr
			}
			pb.Add(n)
			unackedChunks++

			// Flow control: if 16 chunks (512KB) unacknowledged, pause for ACK or timeout
			if unackedChunks >= 16 {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-ackChan:
					unackedChunks--
				case <-time.After(200 * time.Millisecond):
					unackedChunks = 0
				}
			}
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
	}

	pb.Finish()

	// 3. Send TagFileEnd
	endPayload := append([]byte{protocol.TagFileEnd}, []byte(transferID)...)
	return p.PublishPayload(ctx, endPayload)
}

// TriggerRekey generates an in-stream MsgTypeRekey frame, ratchets symmetric keys, and zeroizes parent key.
func (p *PublisherEngine) TriggerRekey(ctx context.Context) error {
	p.rekeyMu.Lock()
	defer p.rekeyMu.Unlock()

	p.mu.Lock()
	ciph := p.cipher
	if ciph == nil {
		p.mu.Unlock()
		return nil
	}

	currKey := ciph.GetKey()
	p.mu.Unlock()

	if currKey == nil {
		return nil
	}
	defer crypto.ZeroBytes(currKey)

	salt, err := crypto.GenerateNonce()
	if err != nil {
		return err
	}

	var sessionSalt [4]byte
	copy(sessionSalt[:], p.sessionID[:4])
	seqNum := atomic.AddUint64(&p.seqCounter, 1)
	nonce := crypto.ConstructNonceRFC5116(sessionSalt, seqNum)

	framePayloadLen := uint32(8 + len(salt) + 16)
	headerBytes := make([]byte, protocol.HeaderSize)
	protocol.SerializeHeader(headerBytes, protocol.Version, protocol.MsgTypeRekey, p.sessionID, nonce, framePayloadLen)

	ciphertext, _, err := ciph.Encrypt(salt, nonce[:], headerBytes)
	if err != nil {
		return err
	}

	framePayload := make([]byte, 8+len(ciphertext))
	binary.BigEndian.PutUint64(framePayload[0:8], seqNum)
	copy(framePayload[8:], ciphertext)

	rekeyEnv := &protocol.Envelope{
		Version:   protocol.Version,
		MsgType:   protocol.MsgTypeRekey,
		SessionID: p.sessionID,
		Nonce:     nonce,
		Payload:   framePayload,
	}

	if err := p.sendFrame(rekeyEnv); err != nil {
		return err
	}

	nextKey, err := crypto.RatchetKey(currKey, salt)
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(nextKey)

	p.mu.Lock()
	if err := p.cipher.UpdateKey(nextKey); err != nil {
		p.mu.Unlock()
		return err
	}
	// Advance the stored master key to the ratcheted key. A subscriber that
	// (re)connects after a rekey is handed p.masterKey via WrapSessionKey and
	// replaySyncForSubscriber re-encrypts buffered frames with the live cipher,
	// so the stored key must track the current cipher key or the peer cannot
	// decrypt the live stream.
	if p.masterKey != nil {
		crypto.ZeroBytes(p.masterKey)
	}
	p.masterKey = append([]byte(nil), nextKey...)
	sasHex, sasEmoji := crypto.CalculateSAS(nextKey)
	p.sasHex = sasHex
	p.sasEmoji = sasEmoji
	p.bytesSinceRekey = 0
	p.lastRekeyTime = time.Now()
	p.mu.Unlock()

	return nil
}

// PublishPayload enqueues a tagged payload frame for E2EE transmission.
func (p *PublisherEngine) PublishPayload(ctx context.Context, payload []byte) error {
	p.mu.Lock()
	p.bytesSinceRekey += uint64(len(payload))
	timeLimit := p.rekeyTimeLimit
	byteLimit := p.rekeyByteLimit
	shouldRekey := (byteLimit > 0 && p.bytesSinceRekey >= byteLimit) || (timeLimit > 0 && time.Since(p.lastRekeyTime) >= timeLimit)
	p.mu.Unlock()

	if shouldRekey {
		_ = p.TriggerRekey(ctx)
	}

	ciph := p.getCipher()
	if ciph == nil {
		return fmt.Errorf("zerofeed/feed: AEAD cipher not initialized")
	}

	seqNum := atomic.AddUint64(&p.seqCounter, 1)
	p.replayBuffer.Push(seqNum, payload)

	var sessionSalt [4]byte
	copy(sessionSalt[:], p.sessionID[:4])
	nonce := crypto.ConstructNonceRFC5116(sessionSalt, seqNum)

	// Pad every frame uniformly so the subscriber can always unpad. Small frames
	// (text) fill the 1280B bucket for traffic-analysis resistance; large frames
	// (file chunks) only carry the 4-byte length prefix.
	payloadToEncrypt := protocol.PadPayload(payload, protocol.DefaultPaddingTargetSize)

	framePayloadLen := uint32(8 + len(payloadToEncrypt) + 16)
	headerBytes := make([]byte, protocol.HeaderSize)
	protocol.SerializeHeader(headerBytes, protocol.Version, protocol.MsgTypeDataStream, p.sessionID, nonce, framePayloadLen)

	ciphertext, _, err := ciph.Encrypt(payloadToEncrypt, nonce[:], headerBytes)
	if err != nil {
		return fmt.Errorf("zerofeed/feed: failed to encrypt payload: %w", err)
	}

	framePayload := make([]byte, 8+len(ciphertext))
	binary.BigEndian.PutUint64(framePayload[0:8], seqNum)
	copy(framePayload[8:], ciphertext)

	env := &protocol.Envelope{
		Version:   protocol.Version,
		MsgType:   protocol.MsgTypeDataStream,
		SessionID: p.sessionID,
		Nonce:     nonce,
		Payload:   framePayload,
	}

	return p.sendFrame(env)
}
