// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorCauseHeader_Marshal_Success(t *testing.T) {
	header := &errorCauseHeader{
		code: protocolViolation,
		raw:  []byte("oops"),
	}

	b, err := header.marshal()
	assert.NoError(t, err)

	// length should be header(4) + len(raw)
	wantLen := uint16(4 + len(header.raw)) // nolint:gosec
	assert.Equal(t, wantLen, header.len)
	assert.Equal(t, int(wantLen), len(b))

	// header fields
	gotCode := binary.BigEndian.Uint16(b)
	gotLen := binary.BigEndian.Uint16(b[2:])
	assert.Equal(t, uint16(protocolViolation), gotCode)
	assert.Equal(t, wantLen, gotLen)

	// value
	assert.Equal(t, header.raw, b[4:])
}

func TestErrorCauseHeader_Marshal_TooLargeValue(t *testing.T) {
	// one byte larger than the max allowed value length
	tooBig := make([]byte, maxErrorCauseValueLen+1)

	h := &errorCauseHeader{
		code: invalidMandatoryParameter,
		raw:  tooBig,
	}

	_, err := h.marshal()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrCauseLengthInvalid)
}

func TestErrorCauseHeader_Unmarshal_Success(t *testing.T) {
	// build a well-formed cause header by hand
	value := []byte{0xde, 0xad, 0xbe, 0xef}
	totalLen := uint16(4 + len(value)) // nolint:gosec

	raw := make([]byte, totalLen)
	binary.BigEndian.PutUint16(raw, uint16(userInitiatedAbort))
	binary.BigEndian.PutUint16(raw[2:], totalLen)
	copy(raw[4:], value)

	var h errorCauseHeader
	err := h.unmarshal(raw)
	assert.NoError(t, err)
	assert.Equal(t, userInitiatedAbort, h.code)
	assert.Equal(t, totalLen, h.len)
	assert.Equal(t, value, h.raw)
}

func TestErrorCauseHeader_Unmarshal_ShortInput(t *testing.T) {
	var h errorCauseHeader
	err := h.unmarshal([]byte{0x00, 0x01, 0x00}) // len < 4
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSCTPChunk)
}

func TestErrorCauseHeader_Unmarshal_BadLength_SmallerThanHeader(t *testing.T) {
	// declared length=3 (<4) but buffer has at least 4
	raw := make([]byte, 4)
	binary.BigEndian.PutUint16(raw, uint16(invalidMandatoryParameter))
	binary.BigEndian.PutUint16(raw[2:], 3)

	var h errorCauseHeader
	err := h.unmarshal(raw)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSCTPChunk)
}

func TestErrorCauseHeader_Unmarshal_BadLength_ClaimsMoreThanSlice(t *testing.T) {
	// declared length=10 but actual slice len=8
	raw := make([]byte, 8)
	binary.BigEndian.PutUint16(raw, uint16(unrecognizedChunkType))
	binary.BigEndian.PutUint16(raw[2:], 10)

	var h errorCauseHeader
	err := h.unmarshal(raw)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSCTPChunk)
}

func TestErrorCauseHeader_RoundTrip(t *testing.T) {
	orig := &errorCauseHeader{
		code: unresolvableAddress,
		raw:  []byte("addr-bad"),
	}

	b, err := orig.marshal()
	assert.NoError(t, err)

	var got errorCauseHeader
	err = got.unmarshal(b)
	assert.NoError(t, err)

	assert.Equal(t, orig.code, got.code)
	assert.Equal(t, orig.len, got.len)
	assert.Equal(t, orig.raw, got.raw)
}

func TestErrorCauseHeader_Unmarshal_IgnoresTrailingBytes(t *testing.T) {
	// declared length=8 (header+value), but provide 12 bytes total (4 extra trailing bytes).
	value := []byte{1, 2, 3, 4}
	totalLen := uint16(4 + len(value)) // nolint:gosec
	raw := make([]byte, 12)
	binary.BigEndian.PutUint16(raw, uint16(noUserData))
	binary.BigEndian.PutUint16(raw[2:], totalLen)
	copy(raw[4:], value)
	// trailing bytes (not considered padding here, header just selects the first 'len' bytes)
	copy(raw[8:], []byte{9, 9, 9, 9})

	var h errorCauseHeader
	err := h.unmarshal(raw)
	assert.NoError(t, err)
	assert.Equal(t, noUserData, h.code)
	assert.Equal(t, totalLen, h.len)
	assert.Equal(t, value, h.raw) // should not include trailing bytes
}

func TestErrorCauseHeader_String(t *testing.T) {
	h := errorCauseHeader{code: cookieReceivedWhileShuttingDown}
	assert.Equal(t, "Cookie Received While Shutting Down", h.String())
}
