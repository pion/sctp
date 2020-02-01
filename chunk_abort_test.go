package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAbortChunk(t *testing.T) {
	t.Run("One error cause", func(t *testing.T) {
		abort1 := &chunkAbort{
			errorCauses: []errorCause{&errorCauseProtocolViolation{
				errorCauseHeader: errorCauseHeader{code: protocolViolation},
			}},
		}
		bytes, err := abort1.marshal()
		assert.NoError(t, err, "should succeed")

		abort2 := &chunkAbort{}
		err = abort2.unmarshal(bytes)
		assert.NoError(t, err, "should succeed")
		assert.Equal(t, 1, len(abort2.errorCauses), "should have only one cause")
		assert.Equal(t,
			abort1.errorCauses[0].errorCauseCode(),
			abort2.errorCauses[0].errorCauseCode(),
			"errorCause code should match")
	})

	t.Run("Many error causes", func(t *testing.T) {
		abort1 := &chunkAbort{
			errorCauses: []errorCause{
				&errorCauseProtocolViolation{
					errorCauseHeader: errorCauseHeader{code: invalidMandatoryParameter},
				},
				&errorCauseProtocolViolation{
					errorCauseHeader: errorCauseHeader{code: unrecognizedChunkType},
				},
				&errorCauseProtocolViolation{
					errorCauseHeader: errorCauseHeader{code: protocolViolation},
				},
			},
		}
		bytes, err := abort1.marshal()
		assert.NoError(t, err, "should succeed")

		abort2 := &chunkAbort{}
		err = abort2.unmarshal(bytes)
		assert.NoError(t, err, "should succeed")
		assert.Equal(t, 3, len(abort2.errorCauses), "should have only one cause")
		for i, errorCause := range abort1.errorCauses {
			assert.Equal(t,
				errorCause.errorCauseCode(),
				abort2.errorCauses[i].errorCauseCode(),
				"errorCause code should match")
		}
	})
}
