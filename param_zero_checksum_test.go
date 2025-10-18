// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParamZeroChecksum(t *testing.T) {
	tt := []struct {
		binary []byte
		parsed *paramZeroChecksumAcceptable
	}{
		{
			binary: []byte{0x80, 0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01},
			parsed: &paramZeroChecksumAcceptable{
				paramHeader: paramHeader{
					typ:                zeroChecksumAcceptable,
					unrecognizedAction: paramHeaderUnrecognizedActionSkip,
					len:                8,
					raw:                []byte{0x00, 0x00, 0x00, 0x01},
				},
				edmid: 1,
			},
		},
		{
			// Arbitrary EDMID should round-trip too (future methods allowed).
			binary: []byte{0x80, 0x01, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04},
			parsed: &paramZeroChecksumAcceptable{
				paramHeader: paramHeader{
					typ:                zeroChecksumAcceptable,
					unrecognizedAction: paramHeaderUnrecognizedActionSkip,
					len:                8,
					raw:                []byte{0x01, 0x02, 0x03, 0x04},
				},
				edmid: 0x01020304,
			},
		},
	}

	for i, tc := range tt {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			actual := &paramZeroChecksumAcceptable{}
			_, err := actual.unmarshal(tc.binary)
			assert.NoError(t, err)
			assert.Equal(t, tc.parsed, actual)
			b, err := actual.marshal()
			assert.NoError(t, err)
			assert.Equal(t, tc.binary, b)
		})
	}

	t.Run("invalid length field (must be 8)", func(t *testing.T) {
		// Length field set to 12 (0x000C); include 4 extra bytes to match.
		bad := []byte{
			0x80, 0x01, 0x00, 0x0C, // type=0x8001, len=12
			0x00, 0x00, 0x00, 0x01, // EDMID=1
			0x00, 0x00, 0x00, 0x00, // extra value bytes
		}
		_, err := (&paramZeroChecksumAcceptable{}).unmarshal(bad)
		assert.ErrorIs(t, err, ErrZeroChecksumParamInvalidLength)
	})
}
