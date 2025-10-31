// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//nolint:dupl
package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChunkShutdownAck_Success(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{"no-flags", []byte{0x08, 0x00, 0x00, 0x04}},
		// Reserved flags are not defined for SHUTDOWN-ACK; receiver should ignore them.
		{"flags-set", []byte{0x08, 0x01, 0x00, 0x04}},
	}

	for i, tc := range tt {
		actual := &chunkShutdownAck{}
		err := actual.unmarshal(tc.binary)
		require.NoErrorf(t, err, "failed to unmarshal #%d (%s)", i, tc.name)

		b, err := actual.marshal()
		require.NoError(t, err)
		assert.Equalf(t, tc.binary, b, "test %d (%s) roundtrip mismatch", i, tc.name)
	}
}

func TestChunkShutdownAck_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{"length too short", []byte{0x08, 0x00, 0x00}},
		{"invalid type", []byte{0x0f, 0x00, 0x00, 0x04}},
	}

	for i, tc := range tt {
		actual := &chunkShutdownAck{}
		err := actual.unmarshal(tc.binary)
		assert.Errorf(t, err, "expected unmarshal #%d: '%s' to fail.", i, tc.name)
	}
}
