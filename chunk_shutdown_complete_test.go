// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
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
	}{
		{"no-flags", []byte{0x0e, 0x00, 0x00, 0x04}},
		// RFC 9260: only T-bit is meaningful; others reserved. We accept either.
		{"t-bit-set", []byte{0x0e, 0x01, 0x00, 0x04}},
	}

	for i, tc := range tt {
		actual := &chunkShutdownComplete{}
		err := actual.unmarshal(tc.binary)
		require.NoErrorf(t, err, "failed to unmarshal #%d", i)

		b, err := actual.marshal()
		require.NoError(t, err)
		assert.Equalf(t, tc.binary, b, "test %d not equal", i)
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
