package relay

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

const wsMagicGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func isAllowedOrigin(origin string, host string) bool {
	if envAllowed := os.Getenv("ZEROFEED_ALLOWED_ORIGINS"); envAllowed != "" {
		if envAllowed == "*" {
			return true
		}
		for _, allowed := range strings.Split(envAllowed, ",") {
			if strings.EqualFold(strings.TrimSpace(allowed), origin) {
				return true
			}
		}
	}

	lowerOrigin := strings.ToLower(origin)
	if strings.HasPrefix(lowerOrigin, "http://localhost") ||
		strings.HasPrefix(lowerOrigin, "https://localhost") ||
		strings.HasPrefix(lowerOrigin, "http://127.0.0.1") ||
		strings.HasPrefix(lowerOrigin, "https://127.0.0.1") {
		return true
	}

	if lowerOrigin == "https://nicolainzerillo.github.io" || strings.HasSuffix(lowerOrigin, ".github.io") {
		return true
	}

	if host != "" {
		if lowerOrigin == "http://"+strings.ToLower(host) || lowerOrigin == "https://"+strings.ToLower(host) {
			return true
		}
	}

	return false
}

type wsConn struct {
	net.Conn
	reader  *bufio.Reader
	readBuf []byte
	readMu  sync.Mutex
	writeMu sync.Mutex
}

func computeAcceptKey(clientKey string) string {
	h := sha1.New()
	h.Write([]byte(clientKey + wsMagicGUID))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// Read unwraps RFC 6455 WebSocket frames sent by browser clients into raw ZeroFeed frame bytes,
// maintaining an internal read buffer to handle partial reads correctly.
func (c *wsConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.readBuf) == 0 {
		header, err := c.reader.ReadByte()
		if err != nil {
			return 0, err
		}
		opcode := header & 0x0F

		if opcode == 0x08 { // Close frame
			return 0, io.EOF
		}

		lenByte, err := c.reader.ReadByte()
		if err != nil {
			return 0, err
		}

		masked := (lenByte & 0x80) != 0
		payloadLen := uint64(lenByte & 0x7F)

		switch payloadLen {
		case 126:
			var l uint16
			if err := binary.Read(c.reader, binary.BigEndian, &l); err != nil {
				return 0, err
			}
			payloadLen = uint64(l)
		case 127:
			if err := binary.Read(c.reader, binary.BigEndian, &payloadLen); err != nil {
				return 0, err
			}
			if payloadLen > 64*1024*1024 {
				return 0, errors.New("zerofeed/ws: websocket frame payload exceeds 64MB safety limit")
			}
		}

		var maskKey [4]byte
		if masked {
			if _, err := io.ReadFull(c.reader, maskKey[:]); err != nil {
				return 0, err
			}
		}

		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(c.reader, payload); err != nil {
			return 0, err
		}

		if masked {
			for i := 0; i < len(payload); i++ {
				payload[i] ^= maskKey[i%4]
			}
		}

		if opcode == 0x09 { // Ping frame — MUST respond with Pong (opcode 0x0A) per RFC 6455 Section 5.5.2
			c.writeMu.Lock()
			pongHeader := []byte{0x8A}
			pLen := len(payload)
			if pLen <= 125 {
				pongHeader = append(pongHeader, byte(pLen))
			} else {
				pongHeader = append(pongHeader, 126, byte(pLen>>8), byte(pLen))
			}
			pongHeader = append(pongHeader, payload...)
			_, _ = c.Conn.Write(pongHeader)
			c.writeMu.Unlock()
			continue
		}

		if opcode == 0x01 || opcode == 0x02 || opcode == 0x00 { // Text or Binary or Continuation
			c.readBuf = payload
			break
		}
	}

	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

// Write wraps outgoing ZeroFeed binary frames into RFC 6455 WebSocket binary frames (opcode 0x02).
func (c *wsConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	var frame []byte
	length := len(p)

	frame = append(frame, 0x82) // FIN + Binary opcode

	if length <= 125 {
		frame = append(frame, byte(length))
	} else if length <= 65535 {
		frame = append(frame, 126)
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(length))
		frame = append(frame, buf...)
	} else {
		frame = append(frame, 127)
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(length))
		frame = append(frame, buf...)
	}

	frame = append(frame, p...)

	_, err := c.Conn.Write(frame)
	if err != nil {
		return 0, err
	}
	return length, nil
}

// UpgradeWebSocket upgrades an HTTP connection to a zero-dependency WebSocket net.Conn.
func UpgradeWebSocket(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return nil, errors.New("not a websocket request")
	}

	clientKey := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if clientKey == "" {
		return nil, errors.New("missing Sec-WebSocket-Key header")
	}

	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" && !isAllowedOrigin(origin, r.Host) {
		return nil, errors.New("websocket: origin not allowed")
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("webserver doesn't support hijacking")
	}

	conn, bufrw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}

	acceptKey := computeAcceptKey(clientKey)

	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + acceptKey + "\r\n\r\n"

	if _, err := bufrw.WriteString(response); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = bufrw.Flush()

	return &wsConn{
		Conn:   conn,
		reader: bufrw.Reader,
	}, nil
}
