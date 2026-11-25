// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// marshalRawPacket builds a packet from chunks that are already marshaled,
// padding each one to a multiple of 4 bytes. It is used for chunks that
// chunk.marshal refuses to produce.
func marshalRawPacket(
	t *testing.T, sourcePort, destinationPort uint16, verificationTag uint32, chunks ...[]byte,
) []byte {
	t.Helper()

	raw := make([]byte, 0, packetHeaderSize)
	raw = binary.BigEndian.AppendUint16(raw, sourcePort)
	raw = binary.BigEndian.AppendUint16(raw, destinationPort)
	raw = binary.BigEndian.AppendUint32(raw, verificationTag)
	raw = append(raw, 0, 0, 0, 0) // checksum, filled in below
	for _, chunkRaw := range chunks {
		raw = append(raw, chunkRaw...)
		raw = padByte(raw, getPadding(len(chunkRaw)))
	}
	binary.LittleEndian.PutUint32(raw[8:], generatePacketChecksum(raw))

	return raw
}

func TestPacketUnmarshal(t *testing.T) {
	pkt := &packet{}

	assert.Error(t, pkt.unmarshal(true, []byte{}), "Unmarshal should fail when a packet is too small to be SCTP")

	headerOnly := []byte{0x13, 0x88, 0x13, 0x88, 0x00, 0x00, 0x00, 0x00, 0x06, 0xa9, 0x00, 0xe1}
	err := pkt.unmarshal(true, headerOnly)
	assert.NoError(t, err, "Unmarshal failed for SCTP packet with no chunks")

	assert.Equal(t, uint16(defaultSCTPSrcDstPort), pkt.sourcePort, "Unmarshal passed for SCTP packet, but got incorrect source port exp: %d act: %d", defaultSCTPSrcDstPort, pkt.sourcePort)
	assert.Equal(t, uint16(defaultSCTPSrcDstPort), pkt.destinationPort, "Unmarshal passed for SCTP packet, but got incorrect destination port exp: %d act: %d", defaultSCTPSrcDstPort, pkt.destinationPort)
	assert.Equal(t, uint32(0), pkt.verificationTag, "Unmarshal passed for SCTP packet, but got incorrect verification tag exp: %d act: %d", 0, pkt.verificationTag)

	rawChunk := []byte{
		0x13, 0x88, 0x13, 0x88, 0x00, 0x00, 0x00, 0x00, 0x81, 0x46, 0x9d, 0xfc, 0x01, 0x00, 0x00, 0x56, 0x55,
		0xb9, 0x64, 0xa5, 0x00, 0x02, 0x00, 0x00, 0x04, 0x00, 0x08, 0x00, 0xe8, 0x6d, 0x10, 0x30, 0xc0, 0x00,
		0x00, 0x04, 0x80, 0x08, 0x00, 0x09, 0xc0, 0x0f, 0xc1, 0x80, 0x82, 0x00, 0x00, 0x00, 0x80, 0x02, 0x00,
		0x24, 0x9f, 0xeb, 0xbb, 0x5c, 0x50, 0xc9, 0xbf, 0x75, 0x9c, 0xb1, 0x2c, 0x57, 0x4f, 0xa4, 0x5a, 0x51,
		0xba, 0x60, 0x17, 0x78, 0x27, 0x94, 0x5c, 0x31, 0xe6, 0x5d, 0x5b, 0x09, 0x47, 0xe2, 0x22, 0x06, 0x80,
		0x04, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x80, 0x03, 0x00, 0x06, 0x80, 0xc1, 0x00, 0x00,
	}

	assert.NoError(t, pkt.unmarshal(true, rawChunk))
}

// A malformed control chunk that the association rejects (or ignores) on its
// own must not discard the DATA bundled after it.
func TestPacketUnmarshalKeepsChunksAfterMalformedControlChunk(t *testing.T) {
	dataRaw, err := (&chunkPayloadData{
		beginningFragment: true,
		endingFragment:    true,
		tsn:               100,
		userData:          []byte{0x01},
	}).marshal()
	require.NoError(t, err)

	for name, chunkRaw := range map[string][]byte{
		"SACK with unsorted gap blocks": {
			byte(ctSack), 0x00, 0x00, 0x18, // chunk header: type, flags, length=24
			0x00, 0x00, 0x00, 0x63, // cumulative TSN ack = 99
			0x00, 0x01, 0x00, 0x00, // a_rwnd
			0x00, 0x02, 0x00, 0x00, // 2 gap blocks, 0 duplicate TSNs
			0x00, 0x05, 0x00, 0x06, // gap block 5-6
			0x00, 0x02, 0x00, 0x03, // gap block 2-3
		},
		"SACK with zero gap block start": {
			byte(ctSack), 0x00, 0x00, 0x14, // chunk header: type, flags, length=20
			0x00, 0x00, 0x00, 0x63, // cumulative TSN ack = 99
			0x00, 0x01, 0x00, 0x00, // a_rwnd
			0x00, 0x01, 0x00, 0x00, // 1 gap block, 0 duplicate TSNs
			0x00, 0x00, 0x00, 0x01, // gap block 0-1
		},
		"ERROR without causes":       {byte(ctError), 0x00, 0x00, 0x04},
		"COOKIE ACK with a value":    {byte(ctCookieAck), 0x00, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04},
		"COOKIE ECHO without cookie": {byte(ctCookieEcho), 0x00, 0x00, 0x04},
	} {
		t.Run(name, func(t *testing.T) {
			pkt := &packet{}
			require.NoError(t, pkt.unmarshal(true, marshalRawPacket(t, 5000, 5000, 1, chunkRaw, dataRaw)))
			require.Len(t, pkt.chunks, 2)
			data, ok := pkt.chunks[1].(*chunkPayloadData)
			require.True(t, ok)
			assert.Equal(t, uint32(100), data.tsn)
		})
	}
}

func TestPacketMarshal(t *testing.T) {
	pkt := &packet{}

	headerOnly := []byte{0x13, 0x88, 0x13, 0x88, 0x00, 0x00, 0x00, 0x00, 0x06, 0xa9, 0x00, 0xe1}
	assert.NoError(t, pkt.unmarshal(true, headerOnly), "Unmarshal failed for SCTP packet with no chunks")

	headerOnlyMarshaled, err := pkt.marshal(true)
	if assert.NoError(t, err, "Marshal failed for SCTP packet with no chunks") {
		assert.Equal(t, headerOnly, headerOnlyMarshaled, "Unmarshal/Marshaled header only packet did not match \nheaderOnly: % 02x \nheaderOnlyMarshaled % 02x", headerOnly, headerOnlyMarshaled)
	}
}

func BenchmarkPacketGenerateChecksum(b *testing.B) {
	var data [1024]byte

	for i := 0; i < b.N; i++ {
		_ = generatePacketChecksum(data[:])
	}
}
