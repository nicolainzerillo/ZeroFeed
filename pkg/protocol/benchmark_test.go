package protocol_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/zerofeed/zerofeed/pkg/protocol"
)

func BenchmarkEnvelopeEncode(b *testing.B) {
	env := &protocol.Envelope{
		Version:   protocol.Version,
		MsgType:   protocol.MsgTypeDataStream,
		SessionID: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Nonce:     [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		Payload:   []byte("BENCHMARK_PAYLOAD_DATA_STREAM_64B_TEST_STRING_FOR_ZEROFEED_ZFED"),
	}

	b.ReportAllocs()

	for b.Loop() {
		_ = protocol.Encode(io.Discard, env)
	}
}

func BenchmarkEnvelopeDecode(b *testing.B) {
	env := &protocol.Envelope{
		Version:   protocol.Version,
		MsgType:   protocol.MsgTypeDataStream,
		SessionID: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Nonce:     [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		Payload:   []byte("BENCHMARK_PAYLOAD_DATA_STREAM_64B_TEST_STRING_FOR_ZEROFEED_ZFED"),
	}

	var buf bytes.Buffer
	_ = protocol.Encode(&buf, env)
	rawBytes := buf.Bytes()

	b.ReportAllocs()

	for b.Loop() {
		r := bytes.NewReader(rawBytes)
		_, _ = protocol.Decode(r)
	}
}
