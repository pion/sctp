// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorCauseValidation(t *testing.T) {
	for _, raw := range [][]byte{nil, {0}, {0, 13}, {0, 13, 0}, {0, 13, 0, 3}, {0, 13, 0, 5}} {
		_, err := buildErrorCause(raw)
		if len(raw) < errorCauseHeaderLength {
			assert.ErrorIs(t, err, ErrCauseTooShort)
		} else {
			assert.ErrorIs(t, err, ErrCauseLengthInvalid)
		}
		assert.ErrorIs(t, new(errorCauseHeader).unmarshal(raw), ErrInvalidSCTPChunk)
	}

	h := &errorCauseHeader{raw: make([]byte, maxErrorCauseValueLen+1)}
	_, err := h.marshal()
	assert.ErrorIs(t, err, ErrCauseLengthInvalid)
}

func TestChunkErrorUnrecognizedChunkType(t *testing.T) {
	const chunkFlags byte = 0x00
	orgUnrecognizedChunk := []byte{0xc0, 0x0, 0x0, 0x8, 0x0, 0x0, 0x0, 0x3}
	rawIn := append([]byte{byte(ctError), chunkFlags, 0x00, 0x10, 0x00, 0x06, 0x00, 0x0c}, orgUnrecognizedChunk...)

	t.Run("unmarshal", func(t *testing.T) {
		c := &chunkError{}
		err := c.unmarshal(rawIn)
		assert.Nil(t, err, "unmarshal should succeed")
		assert.Equal(t, ctError, c.typ, "chunk type should be ERROR")
		assert.Equal(t, 1, len(c.errorCauses), "there should be on errorCause")

		ec := c.errorCauses[0]
		assert.Equal(t, unrecognizedChunkType, ec.errorCauseCode(), "cause code should be unrecognizedChunkType")
		ecUnrecognizedChunkType, ok := ec.(*errorCauseUnrecognizedChunkType)
		assert.True(t, ok)
		unrecognizedChunk := ecUnrecognizedChunkType.unrecognizedChunk
		assert.True(t, reflect.DeepEqual(unrecognizedChunk, orgUnrecognizedChunk), "should have valid unrecognizedChunk")
	})

	t.Run("marshal", func(t *testing.T) {
		ecUnrecognizedChunkType := &errorCauseUnrecognizedChunkType{
			unrecognizedChunk: orgUnrecognizedChunk,
		}

		ec := &chunkError{
			errorCauses: []errorCause{errorCause(ecUnrecognizedChunkType)},
		}

		raw, err := ec.marshal()
		assert.Nil(t, err, "marshal should succeed")
		assert.True(t, reflect.DeepEqual(raw, rawIn), "unexpected serialization result")
	})

	t.Run("marshal with cause value being nil", func(t *testing.T) {
		expected := []byte{byte(ctError), chunkFlags, 0x00, 0x08, 0x00, 0x06, 0x00, 0x04}
		ecUnrecognizedChunkType := &errorCauseUnrecognizedChunkType{}

		ec := &chunkError{
			errorCauses: []errorCause{errorCause(ecUnrecognizedChunkType)},
		}

		raw, err := ec.marshal()
		assert.Nil(t, err, "marshal should succeed")
		assert.True(t, reflect.DeepEqual(raw, expected), "unexpected serialization result")
	})
}

func TestChunkErrorPadding(t *testing.T) {
	t.Run("non-zero padding between causes is ignored", func(t *testing.T) {
		raw := []byte{
			byte(ctError), 0x00, 0x00, 0x10, // chunk header: type, flags, length=16
			0xFF, 0xFF, 0x00, 0x05, 0xAA, // cause: code=0xFFFF, length=5, value=0xAA
			0x01, 0x02, 0x03, // padding, not zeroed by the sender
			0x00, 0x0D, 0x00, 0x04, // cause: protocolViolation, length=4
		}

		c := &chunkError{}
		require.NoError(t, c.unmarshal(raw))
		require.Len(t, c.errorCauses, 2)
		assert.Equal(t, errorCauseCode(0xFFFF), c.errorCauses[0].errorCauseCode())
		assert.Equal(t, protocolViolation, c.errorCauses[1].errorCauseCode())
	})

	t.Run("non-zero padding after the last cause is ignored", func(t *testing.T) {
		raw := []byte{
			byte(ctError), 0x00, 0x00, 0x0C, // chunk header: type, flags, length=12
			0xFF, 0xFF, 0x00, 0x05, 0xAA, // cause: code=0xFFFF, length=5, value=0xAA
			0x01, 0x02, 0x03, // padding counted in the chunk length
		}

		c := &chunkError{}
		require.NoError(t, c.unmarshal(raw))
		require.Len(t, c.errorCauses, 1)
	})

	t.Run("truncated padding after the last cause is ignored", func(t *testing.T) {
		raw := []byte{
			byte(ctError), 0x00, 0x00, 0x0B, // chunk header: type, flags, length=11
			0xFF, 0xFF, 0x00, 0x05, 0xAA, // cause: code=0xFFFF, length=5, value=0xAA
			0x01, 0x02, // only 2 of 3 padding bytes
			0x00, // chunk padding, outside the chunk length
		}

		c := &chunkError{}
		require.NoError(t, c.unmarshal(raw))
		require.Len(t, c.errorCauses, 1)
		assert.Equal(t, errorCauseCode(0xFFFF), c.errorCauses[0].errorCauseCode())
	})

	t.Run("trailing bytes shorter than a cause header are ignored", func(t *testing.T) {
		raw := []byte{
			byte(ctError), 0x00, 0x00, 0x0A, // chunk header: type, flags, length=10
			0x00, 0x0D, 0x00, 0x04, // cause: protocolViolation, length=4
			0xAB, 0xCD, // not enough for another cause header
			0x00, 0x00, // chunk padding, outside the chunk length
		}

		c := &chunkError{}
		require.NoError(t, c.unmarshal(raw))
		require.Len(t, c.errorCauses, 1)
		assert.Equal(t, protocolViolation, c.errorCauses[0].errorCauseCode())
	})
}

func TestChunkErrorNoCauses(t *testing.T) {
	_, err := (&chunkError{}).marshal()
	assert.ErrorIs(t, err, ErrErrorNoCauses)

	raw := []byte{byte(ctError), 0x00, 0x00, 0x04}
	assert.ErrorIs(t, (&chunkError{}).unmarshal(raw), ErrErrorNoCauses)
}
