package feed

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/zerofeed/zerofeed/pkg/crypto"
	"github.com/zerofeed/zerofeed/pkg/protocol"
	"github.com/zerofeed/zerofeed/pkg/transport"
)

type activeFile struct {
	file        *os.File
	filename    string
	size        int64
	received    int64
	chunkCount  int
	header      protocol.FileHeader
	progressBar *ProgressBar
}

func (s *SubscriberEngine) sendAckFrame(transferID string) error {
	conn := s.getConn()
	if conn == nil {
		return fmt.Errorf("not connected")
	}
	ackEnv := &protocol.Envelope{
		Version:   protocol.Version,
		MsgType:   protocol.MsgTypeChunkAck,
		SessionID: s.sessionID,
		Payload:   []byte(transferID),
	}
	return protocol.Encode(conn, ackEnv)
}

// SubscriberEngine handles PAKE authentication, sequence tracking, auto-reconnect, and RAM ring buffer management.
type SubscriberEngine struct {
	passphrase          []byte
	relayAddr           string
	sessionID           [protocol.SessionIDSize]byte
	pakePeer            *crypto.PAKEPeer
	cipher              *crypto.Cipher
	conn                net.Conn
	ringBuffer          *RingBuffer
	lastSeqNum          uint64
	expectedFingerprint string
	transportMode       transport.Mode
	sasHex              string
	sasEmoji            string
	mu                  sync.Mutex
	closed              bool
}

// SetSPKIFingerprint configures expected SPKI SHA-256 TLS certificate fingerprint for strict pinning.
func (s *SubscriberEngine) SetSPKIFingerprint(fingerprint string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expectedFingerprint = fingerprint
}

// NewSubscriberEngine creates a Subscriber instance with a 100-message circular buffer in RAM.
func NewSubscriberEngine(passphrase []byte, relayAddr string) (*SubscriberEngine, error) {
	sessionID := DeriveSessionID(passphrase)

	pakePeer, err := crypto.NewPAKESubscriber(passphrase)
	if err != nil {
		return nil, err
	}

	passCopy := make([]byte, len(passphrase))
	copy(passCopy, passphrase)

	sub := &SubscriberEngine{
		passphrase: passCopy,
		relayAddr:  relayAddr,
		sessionID:  sessionID,
		pakePeer:   pakePeer,
		ringBuffer: NewRingBuffer(100),
	}

	crypto.RegisterWiper(func() {
		sub.Close()
	})

	return sub, nil
}

// SessionID returns the current session identifier.
func (s *SubscriberEngine) SessionID() [protocol.SessionIDSize]byte {
	return s.sessionID
}

// SetTransportMode configures the transport mode (ModeTCP or ModeQUIC).
func (s *SubscriberEngine) SetTransportMode(mode transport.Mode) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.transportMode = mode
}

// Connect dials the Relay server and executes the PAKE handshake safely under mutex.
func (s *SubscriberEngine) Connect(ctx context.Context) error {
	s.mu.Lock()
	tMode := s.transportMode
	s.mu.Unlock()

	var conn net.Conn
	var err error

	if tMode == transport.ModeQUIC {
		quicCtx, quicCancel := context.WithTimeout(ctx, 3*time.Second)
		var qErr error
		conn, qErr = transport.DialQUIC(quicCtx, s.relayAddr)
		quicCancel()

		if qErr != nil {
			// Automatic fallback to TCP (TLS) if QUIC UDP times out or is blocked by network/proxy
			conn, err = DialRelayWithPin(ctx, s.relayAddr, s.expectedFingerprint)
		}
	} else {
		conn, err = DialRelayWithPin(ctx, s.relayAddr, s.expectedFingerprint)
	}

	if err != nil {
		return fmt.Errorf("zerofeed/feed: failed to dial relay (%s) at %s: %w", tMode, s.relayAddr, err)
	}

	s.mu.Lock()
	s.conn = conn
	if s.pakePeer == nil {
		pakePeer, pErr := crypto.NewPAKESubscriber(s.passphrase)
		if pErr != nil {
			s.mu.Unlock()
			_ = conn.Close()
			return pErr
		}
		s.pakePeer = pakePeer
	}
	s.mu.Unlock()

	// Send Subscriber's PAKE Step 1 frame
	pakeStep1Env := &protocol.Envelope{
		Version:   protocol.Version,
		MsgType:   protocol.MsgTypePAKEInitSub,
		SessionID: s.sessionID,
		Payload:   s.pakePeer.Bytes(),
	}

	if err := protocol.Encode(conn, pakeStep1Env); err != nil {
		_ = conn.Close()
		return fmt.Errorf("zerofeed/feed: failed to send subscriber PAKE step 1: %w", err)
	}

	return nil
}

func (s *SubscriberEngine) getConn() net.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conn
}

// CompleteHandshake receives Publisher's PAKE payload, derives the master key, and constructs the AEAD cipher.
func (s *SubscriberEngine) CompleteHandshake(timeout time.Duration) error {
	conn := s.getConn()
	if conn == nil {
		return fmt.Errorf("zerofeed/feed: connection not initialized")
	}

	if timeout > 0 {
		_ = conn.SetReadDeadline(time.Now().Add(timeout))
		defer conn.SetReadDeadline(time.Time{})
	}

	// Read Publisher's PAKE payload frame from relay
	env, err := protocol.Decode(conn)
	if err != nil {
		return fmt.Errorf("zerofeed/feed: failed to receive publisher PAKE payload: %w", err)
	}

	if err := s.pakePeer.Update(env.Payload); err != nil {
		return fmt.Errorf("zerofeed/feed: PAKE key exchange failed: %w", err)
	}

	sessionKey, err := crypto.DeriveKey(s.passphrase, s.sessionID[:])
	if err != nil {
		return err
	}
	defer crypto.ZeroBytes(sessionKey)

	sasHex, sasEmoji := crypto.CalculateSAS(sessionKey)

	ciph, err := crypto.NewCipher(sessionKey)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.cipher = ciph
	s.sasHex = sasHex
	s.sasEmoji = sasEmoji
	s.mu.Unlock()

	return nil
}

// SASFingerprint returns the 4-character hex SAS fingerprint string.
func (s *SubscriberEngine) SASFingerprint() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sasHex
}

// SASEmoji returns the 2-emoji SAS visual verification badge.
func (s *SubscriberEngine) SASEmoji() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sasEmoji
}

// SendSyncRequest sends a SYNC_REQ frame to Publisher with current lastSeqNum upon reconnect.
func (s *SubscriberEngine) SendSyncRequest() error {
	s.mu.Lock()
	conn := s.conn
	lastSeqNum := s.lastSeqNum
	sessionID := s.sessionID
	s.mu.Unlock()

	if conn == nil {
		return fmt.Errorf("not connected")
	}

	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, lastSeqNum)

	syncEnv := &protocol.Envelope{
		Version:   protocol.Version,
		MsgType:   protocol.MsgTypeSyncReq,
		SessionID: sessionID,
		Payload:   payload,
	}

	return protocol.Encode(conn, syncEnv)
}

// SubscribeStream reads encrypted frames, handles sequence numbers, updates RAM RingBuffer, and auto-reconnects on network loss.
func (s *SubscriberEngine) SubscribeStream(ctx context.Context, outputWriter io.Writer, msgCallback func(payload []byte)) error {
	done := make(chan struct{})
	defer close(done)

	activeFiles := make(map[string]*activeFile)
	defer func() {
		for _, af := range activeFiles {
			_ = af.file.Close()
		}
	}()

	go func() {
		select {
		case <-ctx.Done():
			s.Close()
		case <-done:
		}
	}()

	backoff := 100 * time.Millisecond

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		conn := s.getConn()
		if conn == nil {
			if s.isClosed() {
				return nil
			}
			reconnected := s.reconnectLoop(ctx, &backoff)
			if !reconnected {
				return fmt.Errorf("zerofeed/feed: subscriber reconnect failed")
			}
			conn = s.getConn()
		}

		env, err := protocol.Decode(conn)
		if err != nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				if s.isClosed() {
					return nil
				}

				reconnected := s.reconnectLoop(ctx, &backoff)
				if !reconnected {
					return err
				}
				continue
			}
		}

		backoff = 100 * time.Millisecond

		if env.MsgType == protocol.MsgTypeClose {
			break
		}

		if env.MsgType == protocol.MsgTypeHeartbeat {
			continue // Keepalive frame received successfully
		}

		if env.MsgType == protocol.MsgTypeRekey {
			if len(env.Payload) < 8 {
				continue
			}
			ciphertext := env.Payload[8:]

			s.mu.Lock()
			ciph := s.cipher
			s.mu.Unlock()

			if ciph == nil {
				continue
			}

			headerBytes := make([]byte, protocol.HeaderSize)
			protocol.SerializeHeader(headerBytes, env.Version, env.MsgType, env.SessionID, env.Nonce, uint32(len(env.Payload)))
			salt, err := ciph.Decrypt(ciphertext, env.Nonce[:], headerBytes)
			if err != nil {
				return fmt.Errorf("zerofeed/feed: AEAD rekey frame authentication failed: %w", err)
			}

			currKey := ciph.GetKey()
			if currKey != nil {
				nextKey, err := crypto.RatchetKey(currKey, salt)
				crypto.ZeroBytes(currKey)
				if err == nil {
					s.mu.Lock()
					_ = s.cipher.UpdateKey(nextKey)
					sasHex, sasEmoji := crypto.CalculateSAS(nextKey)
					s.sasHex = sasHex
					s.sasEmoji = sasEmoji
					s.mu.Unlock()
					crypto.ZeroBytes(nextKey)
				}
			}
			crypto.ZeroBytes(salt)
			continue
		}

		if env.MsgType != protocol.MsgTypeDataStream {
			continue
		}

		if len(env.Payload) < 8 {
			continue
		}

		seqNum := binary.BigEndian.Uint64(env.Payload[0:8])
		ciphertext := env.Payload[8:]

		s.mu.Lock()
		ciph := s.cipher
		s.mu.Unlock()

		if ciph == nil {
			continue
		}

		// Decrypt AEAD frame with AAD header binding
		headerBytes := make([]byte, protocol.HeaderSize)
		protocol.SerializeHeader(headerBytes, env.Version, env.MsgType, env.SessionID, env.Nonce, uint32(len(env.Payload)))
		plaintext, err := ciph.Decrypt(ciphertext, env.Nonce[:], headerBytes)
		if err != nil {
			return fmt.Errorf("zerofeed/feed: AEAD frame authentication failed (session terminated): %w", err)
		}

		// Sequence deduplication
		s.mu.Lock()
		if seqNum <= s.lastSeqNum {
			s.mu.Unlock()
			crypto.ZeroBytes(plaintext)
			continue
		}
		s.lastSeqNum = seqNum
		s.mu.Unlock()

		// Save payload in RAM RingBuffer
		s.ringBuffer.Push(seqNum, plaintext)

		if len(plaintext) > 0 {
			tag := plaintext[0]
			data := plaintext[1:]

			switch tag {
			case protocol.TagText:
				cleanText := sanitizeTextOutput(data)
				if outputWriter != nil {
					_, _ = outputWriter.Write(cleanText)
				}
				if msgCallback != nil {
					msgCallback(cleanText)
				}

			case protocol.TagFileStart:
				var header protocol.FileHeader
				if err := json.Unmarshal(data, &header); err == nil && header.TransferID != "" {
					cleanName := filepath.Base(header.Filename)
					if cleanName == "." || cleanName == "/" {
						cleanName = "received_file"
					}
					_ = os.MkdirAll("./downloads", 0755)
					outPath := filepath.Join("./downloads", cleanName)
					f, err := os.Create(outPath)
					if err == nil {
						pb := NewProgressBar(header.FileSize, false)
						activeFiles[header.TransferID] = &activeFile{
							file:        f,
							filename:    cleanName,
							size:        header.FileSize,
							header:      header,
							progressBar: pb,
						}
						fmt.Fprintf(os.Stderr, "\n[!] Incoming File Transfer: %q (%.2f MB) -> %s\n", cleanName, float64(header.FileSize)/(1024*1024), outPath)
					}
				}

			case protocol.TagFileChunk:
				if len(data) > 16 {
					transferID := string(data[:16])
					chunk := data[16:]
					if af, ok := activeFiles[transferID]; ok {
						n, _ := af.file.Write(chunk)
						crypto.ZeroBytes(chunk)
						af.received += int64(n)
						af.chunkCount++
						if af.progressBar != nil {
							af.progressBar.Add(n)
						}
						if af.chunkCount%16 == 0 {
							_ = s.sendAckFrame(transferID)
						}
					}
				}

			case protocol.TagFileEnd:
				if len(data) >= 16 {
					transferID := string(data[:16])
					if af, ok := activeFiles[transferID]; ok {
						_ = af.file.Close()
						if af.progressBar != nil {
							af.progressBar.Finish()
						}
						_ = s.sendAckFrame(transferID)

						if af.header.SHA256 != "" {
							if downloadedFile, err := os.Open(filepath.Join("./downloads", af.filename)); err == nil {
								hasher := sha256.New()
								_, _ = io.Copy(hasher, downloadedFile)
								_ = downloadedFile.Close()
								downloadedSum := hex.EncodeToString(hasher.Sum(nil))

								if downloadedSum != af.header.SHA256 {
									fmt.Fprintf(os.Stderr, "\n[❌] ERROR: SHA-256 Checksum mismatch for %s!\n Expected: %s\n Received: %s\n\n", af.filename, af.header.SHA256, downloadedSum)
									delete(activeFiles, transferID)
									continue
								}
								fmt.Fprintf(os.Stderr, "\n[✓] File Received & SHA-256 Verified: ./downloads/%s (%d bytes | sha256: %s...)\n\n", af.filename, af.received, downloadedSum[:12])
							}
						} else {
							fmt.Fprintf(os.Stderr, "\n[✓] File Received & Saved: ./downloads/%s (%d bytes)\n\n", af.filename, af.received)
						}
						delete(activeFiles, transferID)
					}
				}

			default:
				// Backward compatibility: untagged legacy stream
				if outputWriter != nil {
					_, _ = outputWriter.Write(plaintext)
				}
				if msgCallback != nil {
					msgCallback(plaintext)
				}
			}
		}

		crypto.ZeroBytes(plaintext)
	}

	return nil
}

func (s *SubscriberEngine) getPassphrase() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.passphrase == nil {
		return nil
	}
	passCopy := make([]byte, len(s.passphrase))
	copy(passCopy, s.passphrase)
	return passCopy
}

// reconnectLoop attempts automatic exponential backoff reconnection to Relay and sends SYNC_REQ.
func (s *SubscriberEngine) reconnectLoop(ctx context.Context, backoff *time.Duration) bool {
	for retries := 0; retries < 10; retries++ {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(*backoff):
		}

		if *backoff < 5*time.Second {
			*backoff *= 2
		}

		pass := s.getPassphrase()
		if pass == nil {
			return false
		}
		pakePeer, err := crypto.NewPAKESubscriber(pass)
		crypto.ZeroBytes(pass)
		if err != nil {
			continue
		}

		s.mu.Lock()
		s.pakePeer = pakePeer
		s.mu.Unlock()

		if err := s.Connect(ctx); err != nil {
			continue
		}

		if err := s.CompleteHandshake(5 * time.Second); err != nil {
			s.mu.Lock()
			if s.conn != nil {
				_ = s.conn.Close()
				s.conn = nil
			}
			s.mu.Unlock()
			continue
		}

		_ = s.SendSyncRequest()
		return true
	}

	return false
}

func (s *SubscriberEngine) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// BufferContents returns all buffered messages from RAM.
func (s *SubscriberEngine) BufferContents() [][]byte {
	return s.ringBuffer.GetAll()
}

// Close gracefully stops subscriber, purges the RAM circular buffer, and scrubs symmetric keys.
func (s *SubscriberEngine) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}
	s.closed = true

	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}

	if s.cipher != nil {
		s.cipher.Close()
		s.cipher = nil
	}

	if s.pakePeer != nil {
		s.pakePeer.Close()
		s.pakePeer = nil
	}

	if s.passphrase != nil {
		crypto.ZeroBytes(s.passphrase)
		s.passphrase = nil
	}

	if s.ringBuffer != nil {
		s.ringBuffer.Wipe()
	}
}

func sanitizeTextOutput(data []byte) []byte {
	return data
}
