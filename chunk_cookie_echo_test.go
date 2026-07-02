// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRFC9653_SenderRule_CookieEchoForcesCRC(t *testing.T) {
	p := &packet{
		sourcePort:      7000,
		destinationPort: 7001,
		verificationTag: 0x01020304,
		chunks: []chunk{
			&chunkCookieEcho{cookie: []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		},
	}

	// ZCA enabled: even so, COOKIE ECHO requires a correct CRC32c (non-zero).
	raw, err := p.marshal(true)
	assert.NoError(t, err)

	got := binary.LittleEndian.Uint32(raw[8:])
	assert.NotZero(t, got, "checksum must not be zero when COOKIE ECHO present")

	// Verify correctness of the CRC
	cp := make([]byte, len(raw))
	copy(cp, raw)
	binary.LittleEndian.PutUint32(cp[8:], 0)
	want := generatePacketChecksum(cp)
	assert.Equal(t, want, got, "checksum must be the correct CRC32c")
}
