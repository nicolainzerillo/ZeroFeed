package protocol

import "encoding/binary"

const (
	// Protocol version
	Version             uint8 = 0x02
	MinSupportedVersion uint8 = 0x02

	// Frame Types
	MsgTypePAKEInitPub uint8 = 0x01 // Publisher initial handshake
	MsgTypePAKEInitSub uint8 = 0x02 // Subscriber initial handshake
	MsgTypePAKEStep2   uint8 = 0x03 // PAKE step 2 response
	MsgTypeDataStream  uint8 = 0x04 // Encrypted payload frame
	MsgTypeHeartbeat   uint8 = 0x05 // Keepalive ping
	MsgTypeClose       uint8 = 0x06 // Close session teardown
	MsgTypeSyncReq     uint8 = 0x07 // Sync request frame on reconnect
	MsgTypeChunkAck    uint8 = 0x08 // Sliding window flow control ACK frame
	MsgTypeRekey       uint8 = 0x09 // In-stream key rotation (Rekeying & Perfect Forward Secrecy)

	// Payload Tag Types (Inside E2EE DataStream Payload)
	TagText      uint8 = 0x01 // Text / Log Stream
	TagFileStart uint8 = 0x02 // File Transfer Header (Metadata)
	TagFileChunk uint8 = 0x03 // File Transfer Binary Chunk
	TagFileEnd   uint8 = 0x04 // File Transfer EOF Signal

	// Sizes
	MagicSize     = 4
	SessionIDSize = 16
	NonceSize     = 12
	HeaderSize    = MagicSize + 1 + 1 + SessionIDSize + NonceSize + 4 // 38 bytes header
)

// FileHeader contains metadata for zero-knowledge file transfers.
type FileHeader struct {
	TransferID string `json:"transfer_id"`
	Filename   string `json:"filename"`
	FileSize   int64  `json:"file_size"`
	SHA256     string `json:"sha256,omitempty"`
}

var MagicHeader = [4]byte{'Z', 'F', 'E', 'D'} // 0x5A464544

// Envelope represents a structured binary protocol frame header + payload.
type Envelope struct {
	Version   uint8
	MsgType   uint8
	SessionID [SessionIDSize]byte
	Nonce     [NonceSize]byte
	Payload   []byte
}

// SerializeHeader writes the fixed 38-byte binary frame header into buf.
func SerializeHeader(buf []byte, version uint8, msgType uint8, sessionID [SessionIDSize]byte, nonce [NonceSize]byte, payloadLen uint32) {
	_ = buf[HeaderSize-1] // bounds check elimination
	copy(buf[0:4], MagicHeader[:])
	buf[4] = version
	buf[5] = msgType
	copy(buf[6:22], sessionID[:])
	copy(buf[22:34], nonce[:])
	binary.BigEndian.PutUint32(buf[34:38], payloadLen)
}
