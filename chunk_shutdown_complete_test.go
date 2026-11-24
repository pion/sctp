// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//nolint:dupl
package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChunkShutdownComplete_Success(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
		want   []byte // expected marshal output
	}{
		{"no-flags", []byte{0x0e, 0x00, 0x00, 0x04}, []byte{0x0e, 0x00, 0x00, 0x04}},
		{"t-bit-set", []byte{0x0e, 0x01, 0x00, 0x04}, []byte{0x0e, 0x01, 0x00, 0x04}},
		// RFC 9260 section 3.3.13: reserved bits are ignored on receipt and set to 0
		// on transmit; only the T bit is preserved.
		{"reserved-bits-set", []byte{0x0e, 0xFF, 0x00, 0x04}, []byte{0x0e, 0x01, 0x00, 0x04}},
	}

	for i, tc := range tt {
		actual := &chunkShutdownComplete{}
		err := actual.unmarshal(tc.binary)
		require.NoErrorf(t, err, "failed to unmarshal #%d", i)

		b, err := actual.marshal()
		require.NoError(t, err)
		assert.Equalf(t, tc.want, b, "test %d (%s) marshal mismatch", i, tc.name)
	}
}

func TestChunkShutdownComplete_Failure(t *testing.T) { //nolint:dupl
	tt := []struct {
		name   string
		binary []byte
	}{
		// Not enough bytes to even contain the 4-byte header
		{"length too short", []byte{0x0e, 0x00, 0x00}},
		// Wrong type
		{"invalid type", []byte{0x0f, 0x00, 0x00, 0x04}},
	}

	for i, tc := range tt {
		actual := &chunkShutdownComplete{}
		err := actual.unmarshal(tc.binary)
		require.Errorf(t, err, "expected unmarshal #%d: '%s' to fail.", i, tc.name)
	}
}
