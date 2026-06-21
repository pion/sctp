// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

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

	t.Run("Unrecognized error cause code is accepted as opaque TLV", func(t *testing.T) {
		const unknownCode errorCauseCode = 0xFFFF

		// Build a raw ABORT with one unrecognized 4-byte cause (code=0xFFFF, len=4, no value).
		// chunkHeader: type(1) flags(1) length(2) = 4 bytes; cause TLV: 4 bytes → total 8.
		raw := []byte{
			byte(ctAbort), 0x00, 0x00, 0x08, // chunk header: type, flags, length=8
			0xFF, 0xFF, 0x00, 0x04, // cause: code=0xFFFF, length=4 (header only)
		}

		abort := &chunkAbort{}
		err := abort.unmarshal(raw)
		assert.NoError(t, err, "ABORT with unrecognized cause code should not fail")
		assert.Equal(t, 1, len(abort.errorCauses), "should have one error cause")
		assert.Equal(t, unknownCode, abort.errorCauses[0].errorCauseCode(), "cause code should be preserved")
	})

	t.Run("Unrecognized error cause code mixed with known causes", func(t *testing.T) {
		const unknownCode errorCauseCode = 0x00FF

		// ABORT containing: unknown cause first, followed by a known cause (protocolViolation=13).
		abort1 := &chunkAbort{
			errorCauses: []errorCause{
				// Unknown cause represented as an opaque errorCauseHeader.
				&errorCauseHeader{code: unknownCode},
				&errorCauseProtocolViolation{
					errorCauseHeader: errorCauseHeader{code: protocolViolation},
				},
			},
		}
		bytes, err := abort1.marshal()
		assert.NoError(t, err, "marshal should succeed")

		abort2 := &chunkAbort{}
		err = abort2.unmarshal(bytes)
		assert.NoError(t, err, "unmarshal with unknown cause code should not fail")
		assert.Equal(t, 2, len(abort2.errorCauses), "should have two error causes")
		assert.Equal(t, unknownCode, abort2.errorCauses[0].errorCauseCode(), "unknown cause code should be preserved")
		assert.Equal(t, protocolViolation, abort2.errorCauses[1].errorCauseCode(), "second cause code should match")
	})
}
