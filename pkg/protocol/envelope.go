package protocol

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

var (
	ErrInvalidMagic    = errors.New("zerofeed/protocol: invalid magic header")
	ErrUnsupportedVer  = errors.New("zerofeed/protocol: unsupported protocol version")
	ErrPayloadTooLarge = errors.New("zerofeed/protocol: payload size exceeds maximum limit (32MB)")
)

const MaxPayloadSize uint32 = 32 * 1024 * 1024 // 32MB safety limit

// MaxHandshakePayload bounds the payload size accepted for the very first frame
// on an unauthenticated connection. Handshake frames (PAKE init 1280B, PAKE
// step2 ~1340B, sync req 8B) are small; capping here prevents a pre-auth peer
// from forcing large speculative allocations across many connections.
const MaxHandshakePayload uint32 = 8192

var framePool = sync.Pool{
	New: func() any {
		b := make([]byte, 64*1024) // 64KB pool buffer for standard frames
		return &b
	},
}

// Encode serializes an Envelope into binary frame format and writes it in a single atomic Write call
// to ensure WebSocket connections receive complete RFC 6455 binary frames.
func Encode(w io.Writer, env *Envelope) error {
	payloadLen := uint32(len(env.Payload))
	if payloadLen > MaxPayloadSize {
		return ErrPayloadTooLarge
	}

	fullSize := HeaderSize + int(payloadLen)
	var buf []byte
	var poolPtr *[]byte

	if fullSize <= 64*1024 {
		poolPtr = framePool.Get().(*[]byte)
		buf = (*poolPtr)[:fullSize]
		defer framePool.Put(poolPtr)
	} else {
		buf = make([]byte, fullSize)
	}

	SerializeHeader(buf, env.Version, env.MsgType, env.SessionID, env.Nonce, payloadLen)
	if payloadLen > 0 {
		copy(buf[HeaderSize:], env.Payload)
	}

	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("zerofeed/protocol: failed to write atomic frame: %w", err)
	}

	return nil
}

// DecodeEnvelope decodes a raw binary frame byte slice into a structured Envelope.
func DecodeEnvelope(data []byte) (*Envelope, error) {
	return Decode(bytes.NewReader(data))
}

// Decode reads a single frame from r, parses its header, and reads its payload bytes.
func Decode(r io.Reader) (*Envelope, error) {
	return DecodeWithMax(r, MaxPayloadSize)
}

// DecodeWithMax behaves like Decode but rejects any frame whose declared payload
// length exceeds maxPayload, before allocating the payload buffer. Use a small
// bound (e.g. MaxHandshakePayload) on unauthenticated connections.
func DecodeWithMax(r io.Reader, maxPayload uint32) (*Envelope, error) {
	headerBuf := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, headerBuf); err != nil {
		return nil, err
	}

	if !bytes.Equal(headerBuf[0:4], MagicHeader[:]) {
		return nil, ErrInvalidMagic
	}

	version := headerBuf[4]
	if version < MinSupportedVersion {
		return nil, fmt.Errorf("%w: version 0x%02X is below minimum 0x%02X", ErrUnsupportedVer, version, MinSupportedVersion)
	}

	msgType := headerBuf[5]

	var sessionID [SessionIDSize]byte
	copy(sessionID[:], headerBuf[6:22])

	var nonce [NonceSize]byte
	copy(nonce[:], headerBuf[22:34])

	payloadLen := binary.BigEndian.Uint32(headerBuf[34:38])
	if payloadLen > maxPayload {
		return nil, ErrPayloadTooLarge
	}

	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("zerofeed/protocol: failed to read frame payload (%d bytes): %w", payloadLen, err)
		}
	}

	return &Envelope{
		Version:   version,
		MsgType:   msgType,
		SessionID: sessionID,
		Nonce:     nonce,
		Payload:   payload,
	}, nil
}

var ErrInvalidPadding = errors.New("zerofeed/protocol: invalid frame payload padding")

const DefaultPaddingTargetSize = 1280 // IPv6 Min MTU size for uniform traffic padding

// lenPrefixSize is the byte width of the real-length header prepended by
// PadPayload. A 4-byte (uint32) prefix covers payloads up to MaxPayloadSize,
// so file chunks (up to hundreds of KB) can be padded without truncation.
const lenPrefixSize = 4

// PadPayload prepends a 4-byte big-endian uint32 real length and pads data up to targetSize with zeros.
func PadPayload(data []byte, targetSize int) []byte {
	realLen := len(data)
	needed := realLen + lenPrefixSize
	if needed > targetSize {
		targetSize = needed
	}
	out := make([]byte, targetSize)
	binary.BigEndian.PutUint32(out[0:lenPrefixSize], uint32(realLen))
	if realLen > 0 {
		copy(out[lenPrefixSize:], data)
	}
	return out
}

// UnpadPayload extracts the real payload from a padded data buffer using its 4-byte big-endian uint32 header.
func UnpadPayload(data []byte) ([]byte, error) {
	if len(data) < lenPrefixSize {
		return nil, ErrInvalidPadding
	}
	realLen := binary.BigEndian.Uint32(data[0:lenPrefixSize])
	// uint64 arithmetic avoids overflow on 32-bit targets (e.g. WASM).
	if uint64(realLen)+lenPrefixSize > uint64(len(data)) {
		return nil, ErrInvalidPadding
	}
	return data[lenPrefixSize : lenPrefixSize+realLen], nil
}
