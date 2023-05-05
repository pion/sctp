// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChunkShutdownComplete_Success(t *testing.T) {
	tt := []struct {
		binary []byte
	}{
		{[]byte{0x0e, 0x00, 0x00, 0x04}},
	}

	for i, tc := range tt {
		actual := &chunkShutdownComplete{}
		err := actual.unmarshal(tc.binary)
		require.NoError(t, err, "failed to unmarshal #%d: %v", i, err)

		b, err := actual.marshal()
		require.NoError(t, err, "failed to marshal: %v", err)
		assert.Equal(t, tc.binary, b, "test %d not equal", i)
	}
}

func TestChunkShutdownComplete_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{"length too short", []byte{0x0e, 0x00, 0x00}},
		{"length too long", []byte{0x0e, 0x00, 0x00, 0x04, 0x12}},
		{"invalid type", []byte{0x0f, 0x00, 0x00, 0x04}},
	}

	for i, tc := range tt {
		actual := &chunkShutdownComplete{}
		err := actual.unmarshal(tc.binary)
		require.Error(t, err, "expected unmarshal #%d: '%s' to fail.", i, tc.name)
	}
}
