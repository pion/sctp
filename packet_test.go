// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
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

	headerOnlyMarshaled, err := pkt.marshal(true)
	if assert.NoError(t, err, "Marshal failed for SCTP packet with no chunks") {
		assert.Equal(t, headerOnly, headerOnlyMarshaled,
			"Unmarshal/Marshaled header only packet did not match \nheaderOnly: % 02x \nheaderOnlyMarshaled % 02x",
			headerOnly, headerOnlyMarshaled)
	}
}

func BenchmarkPacketGenerateChecksum(b *testing.B) {
	var data [1024]byte

	for i := 0; i < b.N; i++ {
		_ = generatePacketChecksum(data[:])
	}
}
