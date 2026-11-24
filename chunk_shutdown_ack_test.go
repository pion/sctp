// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
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
		want   []byte // expected marshal output
	}{
		{"no-flags", []byte{0x08, 0x00, 0x00, 0x04}, []byte{0x08, 0x00, 0x00, 0x04}},
		// RFC 9260 section 3.3.9: flags are ignored on receipt and set to 0 on transmit.
		{"flags-set", []byte{0x08, 0x01, 0x00, 0x04}, []byte{0x08, 0x00, 0x00, 0x04}},
	}

	for i, tc := range tt {
		actual := &chunkShutdownAck{}
		err := actual.unmarshal(tc.binary)
		require.NoErrorf(t, err, "failed to unmarshal #%d (%s)", i, tc.name)

		b, err := actual.marshal()
		require.NoError(t, err)
		assert.Equalf(t, tc.want, b, "test %d (%s) marshal mismatch", i, tc.name)
	}
}

func TestChunkShutdownAck_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
		err    error
	}{
		{"length too short", []byte{0x08, 0x00, 0x00}, ErrChunkHeaderTooSmall},
		{"invalid type", []byte{0x0f, 0x00, 0x00, 0x04}, ErrChunkTypeNotShutdownAck},
		{"unexpected value", []byte{0x08, 0x00, 0x00, 0x08, 0, 0, 0, 0}, ErrInvalidChunkSize},
	}

	for i, tc := range tt {
		actual := &chunkShutdownAck{}
		err := actual.unmarshal(tc.binary)
		assert.ErrorIsf(t, err, tc.err, "expected unmarshal #%d: '%s' to fail.", i, tc.name)
	}
}
