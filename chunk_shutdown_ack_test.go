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
		binary []byte
	}{
		{[]byte{0x08, 0x00, 0x00, 0x04}},
	}

	for i, tc := range tt {
		actual := &chunkShutdownAck{}
		err := actual.unmarshal(tc.binary)
		require.NoErrorf(t, err, "failed to unmarshal #%d", i)

		b, err := actual.marshal()
		require.NoError(t, err)
		assert.Equalf(t, tc.binary, b, "test %d not equal", i)
	}
}

func TestChunkShutdownAck_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{"length too short", []byte{0x08, 0x00, 0x00}},
		{"length too long", []byte{0x08, 0x00, 0x00, 0x04, 0x12}},
		{"invalid type", []byte{0x0f, 0x00, 0x00, 0x04}},
	}

	for i, tc := range tt {
		actual := &chunkShutdownAck{}
		err := actual.unmarshal(tc.binary)
		assert.Errorf(t, err, "expected unmarshal #%d: '%s' to fail.", i, tc.name)
	}
}
