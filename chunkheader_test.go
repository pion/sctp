// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func buildChunkBytes(
	t *testing.T,
	typ chunkType,
	flags byte,
	value []byte,
	addPad bool,
	corruptPad bool,
	extra int,
) []byte {
	t.Helper()

	// header+value length placed in the Length field (no padding)
	hlen := chunkHeaderSize + len(value)
	pad := (4 - (hlen & 0x3)) & 0x3 // 0..3

	total := hlen
	if addPad {
		total += pad
	}
	total += extra

	b := make([]byte, total)

	b[0] = byte(typ)
	b[1] = flags
	binary.BigEndian.PutUint16(b[2:], uint16(hlen)) //nolint:gosec
	copy(b[chunkHeaderSize:], value)

	if addPad && pad > 0 {
		// default zeros already, optionally corrupt the first pad byte
		if corruptPad {
			b[hlen] = 0xFF
		}
	}

	// any "extra" bytes after padding are left as zero, the content does not matter
	return b
}

func TestChunkHeader_Unmarshal_Short(t *testing.T) {
	var ch chunkHeader
	err := ch.unmarshal([]byte{0x01, 0x00, 0x00}) // len < 4
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrChunkHeaderTooSmall)
}

func TestChunkHeader_Unmarshal_InvalidLengthField(t *testing.T) {
	// length field < 4
	raw := []byte{byte(ctAbort), 0x00, 0x00, 0x02}
	var ch chunkHeader
	err := ch.unmarshal(raw)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrChunkHeaderInvalidLength)
}

func TestChunkHeader_Unmarshal_NotEnoughSpace(t *testing.T) {
	// header says length=8, but only 6 bytes provided
	raw := []byte{byte(ctAbort), 0x00, 0x00, 0x08, 0x11, 0x22}
	var ch chunkHeader
	err := ch.unmarshal(raw)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrChunkHeaderNotEnoughSpace)
}

func TestChunkHeader_Unmarshal_PaddingZeroAccepted(t *testing.T) {
	// valueLen=1 -> hlen=5 -> pad=3. Provide 3 zero pad bytes.
	value := []byte{0xAB}
	raw := buildChunkBytes(t, ctAbort, 0xAA, value, true, false, 0)

	var ch chunkHeader
	err := ch.unmarshal(raw)
	assert.NoError(t, err)
	assert.Equal(t, ctAbort, ch.typ)
	assert.Equal(t, byte(0xAA), ch.flags)
	assert.Equal(t, value, ch.raw) // value only, padding ignored
}

func TestChunkHeader_Unmarshal_PaddingNonZeroError(t *testing.T) {
	// Same as above, but corrupt first pad byte -> error
	value := []byte{0xAB}
	raw := buildChunkBytes(t, ctAbort, 0x00, value, true, true, 0)

	var ch chunkHeader
	err := ch.unmarshal(raw)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrChunkHeaderPaddingNonZero)
}

func TestChunkHeader_Unmarshal_NoPad_ExtraBytesIgnored(t *testing.T) {
	// valueLen=4 -> hlen=8 -> pad=0. Append some non-zero "next chunk" bytes.
	value := []byte{0x01, 0x02, 0x03, 0x04}
	raw := buildChunkBytes(t, ctHeartbeat, 0x5A, value, false, false, 4)
	raw[len(raw)-4] = 0x99 // arbitrary non-zero after the chunk; should be ignored

	var ch chunkHeader
	err := ch.unmarshal(raw)
	assert.NoError(t, err)
	assert.Equal(t, ctHeartbeat, ch.typ)
	assert.Equal(t, byte(0x5A), ch.flags)
	assert.Equal(t, value, ch.raw)
}

func TestChunkHeader_Marshal_RoundTrip_NoPaddingInMarshal(t *testing.T) {
	// marshal does NOT add padding (packet builder is responsible).
	// valueLen=2 -> hlen=6 -> pad=2 (not emitted by marshal).
	in := chunkHeader{
		typ:   ctPayloadData,
		flags: 0x03,
		raw:   []byte{0xDE, 0xAD},
	}
	out, err := in.marshal()
	assert.NoError(t, err)
	assert.Equal(t, 6, len(out))
	assert.Equal(t, byte(ctPayloadData), out[0])
	assert.Equal(t, byte(0x03), out[1])
	assert.Equal(t, uint16(6), binary.BigEndian.Uint16(out[2:]))
	assert.Equal(t, []byte{0xDE, 0xAD}, out[4:])

	// Unmarshal the exact bytes (remain=0, pad=2 -> not checked).
	var ch chunkHeader
	err = ch.unmarshal(out)
	assert.NoError(t, err)
	assert.Equal(t, ctPayloadData, ch.typ)
	assert.Equal(t, byte(0x03), ch.flags)
	assert.Equal(t, []byte{0xDE, 0xAD}, ch.raw)
}

func TestChunkHeader_Unmarshal_RemainLessThanPad_AllZerosOK(t *testing.T) {
	// hlen=5 -> pad=3 but we only provide remain=2 bytes (common when slicing).
	// Only the available 2 bytes are validated as zeros.
	value := []byte{0x7F}
	raw := buildChunkBytes(t, ctError, 0x00, value, true, false, 0)
	// Trim to simulate slice that ends mid padding (remain=2 < pad=3)
	raw = raw[:len(raw)-1]

	var ch chunkHeader
	err := ch.unmarshal(raw)
	assert.NoError(t, err)
	assert.Equal(t, value, ch.raw)
}
