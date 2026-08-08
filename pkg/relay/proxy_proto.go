package relay

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

var proxyV2Magic = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// ConnWithReader wraps a net.Conn with a bufio.Reader to allow transparent header stripping.
type ConnWithReader struct {
	net.Conn
	r io.Reader
}

func (c *ConnWithReader) Read(b []byte) (int, error) {
	return c.r.Read(b)
}

// ParseProxyHeaderV2 reads and strips a PROXY Protocol v2 header from conn if present.
func ParseProxyHeaderV2(conn net.Conn) (net.Conn, string, error) {
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	defer conn.SetReadDeadline(time.Time{})

	bufReader := bufio.NewReader(conn)
	magic, err := bufReader.Peek(12)
	if err != nil || !bytes.Equal(magic, proxyV2Magic) {
		// Not a PROXY v2 header
		return conn, conn.RemoteAddr().String(), nil
	}

	// Discard magic header
	_, _ = bufReader.Discard(12)

	var verCmd [1]byte
	if _, err := io.ReadFull(bufReader, verCmd[:]); err != nil {
		return conn, conn.RemoteAddr().String(), err
	}

	var familyBuf [1]byte
	if _, err := io.ReadFull(bufReader, familyBuf[:]); err != nil {
		return conn, conn.RemoteAddr().String(), err
	}

	var lenBuf [2]byte
	if _, err := io.ReadFull(bufReader, lenBuf[:]); err != nil {
		return conn, conn.RemoteAddr().String(), err
	}
	hdrLen := binary.BigEndian.Uint16(lenBuf[:])

	if hdrLen > 512 {
		return conn, conn.RemoteAddr().String(), errors.New("PROXY v2 header exceeds safety limit")
	}

	hdrPayload := make([]byte, hdrLen)
	if _, err := io.ReadFull(bufReader, hdrPayload); err != nil {
		return conn, conn.RemoteAddr().String(), err
	}

	clientAddr := conn.RemoteAddr().String()
	family := familyBuf[0] >> 4

	if family == 1 && len(hdrPayload) >= 12 { // AF_INET (IPv4)
		srcIP := net.IP(hdrPayload[0:4])
		srcPort := binary.BigEndian.Uint16(hdrPayload[8:10])
		clientAddr = fmt.Sprintf("%s:%d", srcIP.String(), srcPort)
	} else if family == 2 && len(hdrPayload) >= 36 { // AF_INET6 (IPv6)
		srcIP := net.IP(hdrPayload[0:16])
		srcPort := binary.BigEndian.Uint16(hdrPayload[32:34])
		clientAddr = fmt.Sprintf("[%s]:%d", srcIP.String(), srcPort)
	}

	wrappedConn := &ConnWithReader{
		Conn: conn,
		r:    bufReader,
	}

	return wrappedConn, clientAddr, nil
}
