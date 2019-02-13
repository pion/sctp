package sctp

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChunkErrorUnrecognizedChunkType(t *testing.T) {
	const chunkFlags byte = 0x00
	orgUnrecognizedChunk := []byte{0xc0, 0x0, 0x0, 0x8, 0x0, 0x0, 0x0, 0x3}
	rawIn := append([]byte{byte(ctError), chunkFlags, 0x00, 0x10, 0x00, 0x06, 0x00, 0x0c}, orgUnrecognizedChunk...)

	t.Run("unmarshal", func(t *testing.T) {
		c := &chunkError{}
		err := c.unmarshal(rawIn)
		assert.Nil(t, err, "unmarshal should suceed")
		assert.Equal(t, ctError, c.typ, "chunk type should be ERROR")
		assert.Equal(t, 1, len(c.errorCauses), "there should be on errorCause")

		ec := c.errorCauses[0]
		assert.Equal(t, unrecognizedChunkType, ec.errorCauseCode(), "cause code should be unrecognizedChunkType")
		ecUnrecognizedChunkType := ec.(*errorCauseUnrecognizedChunkType)
		unrecognizedChunk := ecUnrecognizedChunkType.unrecognizedChunk
		assert.True(t, reflect.DeepEqual(unrecognizedChunk, orgUnrecognizedChunk), "should have valid unrecognizedChunk")
	})

	t.Run("marshal", func(t *testing.T) {
		ecUnrecognizedChunkType := &errorCauseUnrecognizedChunkType{
			unrecognizedChunk: orgUnrecognizedChunk,
		}

		ec := &chunkError{
			errorCauses: []errorCause{
				errorCause(ecUnrecognizedChunkType),
			},
		}

		raw, err := ec.marshal()
		assert.Nil(t, err, "marshal should succeed")
		assert.True(t, reflect.DeepEqual(raw, rawIn), "unexpected serialization result")
	})

	t.Run("marshal with cause value being nil", func(t *testing.T) {
		expected := []byte{byte(ctError), chunkFlags, 0x00, 0x08, 0x00, 0x06, 0x00, 0x04}
		ecUnrecognizedChunkType := &errorCauseUnrecognizedChunkType{}

		ec := &chunkError{
			errorCauses: []errorCause{
				errorCause(ecUnrecognizedChunkType),
			},
		}

		raw, err := ec.marshal()
		assert.Nil(t, err, "marshal should succeed")
		assert.True(t, reflect.DeepEqual(raw, expected), "unexpected serialization result")
	})
}
