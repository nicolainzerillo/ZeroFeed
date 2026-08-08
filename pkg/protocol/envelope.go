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
	headerBuf := make([]byte, HeaderSize)
	if _, err := io.ReadFull(r, headerBuf); err != nil {
		return nil, err
	}

	if !bytes.Equal(headerBuf[0:4], MagicHeader[:]) {
		return nil, ErrInvalidMagic
	}

	version := headerBuf[4]
	if version != Version {
		return nil, ErrUnsupportedVer
	}

	msgType := headerBuf[5]

	var sessionID [SessionIDSize]byte
	copy(sessionID[:], headerBuf[6:22])

	var nonce [NonceSize]byte
	copy(nonce[:], headerBuf[22:34])

	payloadLen := binary.BigEndian.Uint32(headerBuf[34:38])
	if payloadLen > MaxPayloadSize {
		return nil, ErrPayloadTooLarge
	}

	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		var readBytes uint32
		for readBytes < payloadLen {
			chunkSize := uint32(64 * 1024)
			if payloadLen-readBytes < chunkSize {
				chunkSize = payloadLen - readBytes
			}
			n, err := io.ReadFull(r, payload[readBytes:readBytes+chunkSize])
			readBytes += uint32(n)
			if err != nil {
				return nil, fmt.Errorf("zerofeed/protocol: failed to read frame payload (%d/%d bytes): %w", readBytes, payloadLen, err)
			}
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
