// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPacketUnmarshal(t *testing.T) {
	pkt := &packet{}

	assert.Error(t, pkt.unmarshal(true, []byte{}), "Unmarshal should fail when a packet is too small to be SCTP")

	headerOnly := []byte{0x13, 0x88, 0x13, 0x88, 0x00, 0x00, 0x00, 0x00, 0x06, 0xa9, 0x00, 0xe1}
	err := pkt.unmarshal(true, headerOnly)
	assert.NoError(t, err, "Unmarshal failed for SCTP packet with no chunks")

	assert.Equal(t, uint16(defaultSCTPSrcDstPort), pkt.sourcePort,
		"Unmarshal passed for SCTP packet, but got incorrect source port exp: %d act: %d",
		defaultSCTPSrcDstPort, pkt.sourcePort)
	assert.Equal(t, uint16(defaultSCTPSrcDstPort), pkt.destinationPort,
		"Unmarshal passed for SCTP packet, but got incorrect destination port exp: %d act: %d",
		defaultSCTPSrcDstPort, pkt.destinationPort)
	assert.Equal(t, uint32(0), pkt.verificationTag,
		"Unmarshal passed for SCTP packet, but got incorrect verification tag exp: %d act: %d",
		0, pkt.verificationTag)

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

func TestPacketMarshal(t *testing.T) {
	pkt := &packet{}

	headerOnly := []byte{0x13, 0x88, 0x13, 0x88, 0x00, 0x00, 0x00, 0x00, 0x06, 0xa9, 0x00, 0xe1}
	assert.NoError(t, pkt.unmarshal(true, headerOnly), "Unmarshal failed for SCTP packet with no chunks")

	// Marshal in strict mode (RFC 9260) so we emit the real CRC32c.
	headerOnlyMarshaled, err := pkt.marshal(false)
	if assert.NoError(t, err, "Marshal failed for SCTP packet with no chunks") {
		assert.Equal(t, packetHeaderSize, len(headerOnlyMarshaled))

		// First 8 bytes (ports + vtag) must match the original header.
		assert.Equal(t, headerOnly[:8], headerOnlyMarshaled[:8])

		// The checksum we wrote must equal CRC32c over the header with the checksum field zeroed.
		cpy := make([]byte, len(headerOnlyMarshaled))
		copy(cpy, headerOnlyMarshaled)
		binary.LittleEndian.PutUint32(cpy[8:], 0)
		want := generatePacketChecksum(cpy)
		got := binary.LittleEndian.Uint32(headerOnlyMarshaled[8:])
		assert.Equal(t, want, got, "checksum must be correct CRC32c")
	}
}

func BenchmarkPacketGenerateChecksum(b *testing.B) {
	var data [1024]byte

	for i := 0; i < b.N; i++ {
		_ = generatePacketChecksum(data[:])
	}
}

func FuzzPacket_StrictRoundTrip(f *testing.F) {
	// Seed with a tiny valid strict packet.
	if raw, err := (&packet{
		sourcePort:      5000,
		destinationPort: 5000,
		verificationTag: 0x01020304,
		chunks:          []chunk{&chunkCookieAck{}},
	}).marshal(false); err == nil {
		f.Add(raw)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var p packet
		if err := p.unmarshal(false, data); err != nil {
			return // skip invalid packets
		}

		out, err := p.marshal(false)
		assert.NoError(t, err, "marshal(strict) after strict unmarshal")

		if err != nil {
			return
		}

		var q packet
		assert.NoError(t, q.unmarshal(false, out), "strict unmarshal after marshal")
	})
}

func FuzzPacket_ZeroChecksumAcceptance(f *testing.F) {
	// Seed with a simple non-restricted strict packet.
	if raw, err := (&packet{
		sourcePort:      9,
		destinationPort: 9,
		verificationTag: 1,
		chunks:          []chunk{&chunkCookieAck{}},
	}).marshal(false); err == nil {
		f.Add(raw)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var pak packet
		if err := pak.unmarshal(false, data); err != nil {
			return // only start from valid strict inputs
		}

		// Force checksum to zero.
		mut := make([]byte, len(data))
		copy(mut, data)
		binary.LittleEndian.PutUint32(mut[8:], 0)

		// Strict must reject zero checksum.
		assert.Error(t, pak.unmarshal(false, mut), "strict receiver should reject zero checksum")

		// ZCA must accept zero checksum.
		assert.NoError(t, pak.unmarshal(true, mut), "ZCA receiver should accept zero checksum")
	})
}

func FuzzPacket_TryMarshalUnmarshal_NoPanic(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})

	if raw, err := (&packet{
		sourcePort:      7,
		destinationPort: 7,
		verificationTag: 0xdeadbeef,
		chunks:          []chunk{&chunkCookieAck{}},
	}).marshal(false); err == nil {
		f.Add(raw)
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		assert.NotPanics(t, func() {
			_ = TryMarshalUnmarshal(b)
		})
	})
}
