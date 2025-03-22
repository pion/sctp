// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func testChunkForwardTSN() []byte {
	return []byte{0xc0, 0x0, 0x0, 0x8, 0x0, 0x0, 0x0, 0x3}
}

func TestChunkForwardTSN_Success(t *testing.T) {
	tt := []struct {
		binary []byte
	}{
		{testChunkForwardTSN()},
		{[]byte{0xc0, 0x0, 0x0, 0xc, 0x0, 0x0, 0x0, 0x3, 0x0, 0x4, 0x0, 0x5}},
		{[]byte{0xc0, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x3, 0x0, 0x4, 0x0, 0x5, 0x0, 0x6, 0x0, 0x7}},
	}

	for i, tc := range tt {
		actual := &chunkForwardTSN{}
		err := actual.unmarshal(tc.binary)
		assert.NoErrorf(t, err, "failed to unmarshal #%d", i)

		b, err := actual.marshal()
		assert.NoError(t, err)
		assert.Equalf(t, tc.binary, b, "test %d not equal", i)
	}
}

func TestChunkForwardTSNUnmarshal_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{"chunk header to short", []byte{0xc0}},
		{"missing New Cumulative TSN", []byte{0xc0, 0x0, 0x0, 0x4}},
		{"missing stream sequence", []byte{0xc0, 0x0, 0x0, 0xe, 0x0, 0x0, 0x0, 0x3, 0x0, 0x4, 0x0, 0x5, 0x0, 0x6}},
	}

	for i, tc := range tt {
		actual := &chunkForwardTSN{}
		err := actual.unmarshal(tc.binary)
		assert.Errorf(t, err, "expected unmarshal #%d: '%s' to fail.", i, tc.name)
	}
}
