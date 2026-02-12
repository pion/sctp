// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	crand "crypto/rand"
	"encoding/binary"
	"math/big"
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

func computeCRC(raw []byte) uint32 {
	cp := make([]byte, len(raw))
	copy(cp, raw)
	binary.LittleEndian.PutUint32(cp[8:], 0)

	return generatePacketChecksum(cp)
}

func TestRFC9653_SenderRule_InitForcesCRC(t *testing.T) {
	pak := &packet{
		sourcePort:      5000,
		destinationPort: 5001,
		verificationTag: 0,
		chunks: []chunk{
			&chunkInit{chunkInitCommon: minimalInitCommon()},
		},
	}
	// Even with ZCA enabled by caller, INIT must carry a correct CRC.
	raw, err := pak.marshal(true)
	assert.NoError(t, err)

	got := binary.LittleEndian.Uint32(raw[8:])
	assert.NotZero(t, got, "checksum must not be zero when INIT present")
	assert.Equal(t, computeCRC(raw), got, "checksum must be correct CRC32c")
}

func TestRFC9653_SenderRule_ZeroAllowedWhenNoRestrictedChunk(t *testing.T) {
	pak := &packet{
		sourcePort:      6000,
		destinationPort: 6001,
		verificationTag: 0x22222222,
		// No restricted chunks (e.g., no INIT/COOKIE-ECHO).
	}
	raw, err := pak.marshal(true) // ZCA enabled by caller
	assert.NoError(t, err)
	got := binary.LittleEndian.Uint32(raw[8:])
	assert.Zero(t, got, "checksum should be zero when allowed")

	// Receiver strict mode (no ZCA) must reject.
	assert.Error(t, (&packet{}).unmarshal(false, raw))
	// Receiver with ZCA must accept zero.
	assert.NoError(t, (&packet{}).unmarshal(true, raw))
}

func crandIntN(t *testing.T, n int) int {
	t.Helper()
	if n <= 0 {
		return 0
	}

	v, err := crand.Int(crand.Reader, big.NewInt(int64(n)))
	assert.NoError(t, err)

	return int(v.Int64())
}

func crandBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, err := crand.Read(b)
	assert.NoError(t, err)

	return b
}

func crandUint32(t *testing.T) uint32 {
	t.Helper()
	var b [4]byte
	_, err := crand.Read(b[:])
	assert.NoError(t, err)

	return binary.BigEndian.Uint32(b[:])
}

func crandUint16(t *testing.T) uint16 {
	t.Helper()
	v, err := crand.Int(crand.Reader, big.NewInt(65536)) // 0..65535
	assert.NoError(t, err)

	return uint16(v.Uint64()) //nolint:gosec // G115
}

func crandPort(t *testing.T) uint16 {
	t.Helper()
	v, err := crand.Int(crand.Reader, big.NewInt(65535)) // 0..65534
	assert.NoError(t, err)

	return uint16(v.Uint64() + 1) //nolint:gosec // G115
}

// randPacket builds a small packet. If includeRestricted is true, ensure a restricted chunk
// (COOKIE-ECHO or INIT, per RFC 9653 sender rules) is present.
func randPacket(t *testing.T, includeRestricted bool) *packet {
	t.Helper()

	pak := &packet{
		sourcePort:      crandPort(t),
		destinationPort: crandPort(t),
		verificationTag: crandUint32(t),
	}
	hasRestricted := false
	n := 1 + crandIntN(t, 3) // 1..3 chunks to keep inputs small

	for i := 0; i < n; i++ {
		switch crandIntN(t, 3) {
		case 0:
			pak.chunks = append(pak.chunks, &chunkCookieAck{}) // unrestricted control
		case 1:
			// single fragment
			sz := crandIntN(t, 64)
			buf := crandBytes(t, sz)
			pak.chunks = append(pak.chunks, &chunkPayloadData{
				streamIdentifier:     crandUint16(t),
				streamSequenceNumber: crandUint16(t),
				beginningFragment:    true,
				endingFragment:       true,
				userData:             buf,
			})
		default:
			hasRestricted = true
			c := crandBytes(t, 1+crandIntN(t, 16))
			pak.chunks = append(pak.chunks, &chunkCookieEcho{cookie: c}) // restricted
		}
	}

	if includeRestricted && !hasRestricted {
		pak.chunks = append(pak.chunks, &chunkCookieEcho{cookie: []byte{1}})
	}

	return pak
}

func FuzzRFC9653_SenderAndReceiverRules(f *testing.F) {
	f.Add(true, int64(1))
	f.Add(false, int64(2))

	f.Fuzz(func(t *testing.T, includeRestricted bool, seed int64) {
		pak := randPacket(t, includeRestricted)

		// Marshal with ZCA active (allowed to send zero unless restricted chunk present).
		raw, err := pak.marshal(true)
		if err != nil {
			t.Skip() // generator can produce combos some chunk marshal rejects

			return
		}
		sum := binary.LittleEndian.Uint32(raw[8:12])

		// check for restricted chunk
		hasRestricted := false
		for _, c := range pak.chunks {
			if _, ok := c.(*chunkCookieEcho); ok {
				hasRestricted = true

				break
			}

			if _, ok := c.(*chunkInit); ok {
				hasRestricted = true

				break
			}
		}

		// RFC 9653 sender rules
		if hasRestricted {
			assert.NotEqual(t, uint32(0), sum, "restricted chunk present => checksum MUST be real CRC32c")
			if sum == 0 {
				return
			}
		} else {
			assert.Equal(t, uint32(0), sum, "no restricted chunk => SHOULD send zero checksum when ZCA active")
			if sum != 0 {
				return
			}
		}

		// Receiver rules
		var q packet

		// ZCA active => must accept either zero or real checksum
		assert.NoError(t, q.unmarshal(true, raw), "ZCA receiver should accept")

		// Strict (RFC 9260) => zero checksum must be rejected; real checksum accepted
		if sum == 0 {
			assert.Error(t, q.unmarshal(false, raw), "strict receiver must reject zero checksum")
		} else {
			assert.NoError(t, q.unmarshal(false, raw), "strict receiver must accept real checksum")
		}
	})
}
