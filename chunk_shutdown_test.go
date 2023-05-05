// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChunkShutdown_Success(t *testing.T) {
	tt := []struct {
		binary []byte
	}{
		{[]byte{0x07, 0x00, 0x00, 0x08, 0x12, 0x34, 0x56, 0x78}},
	}

	for i, tc := range tt {
		actual := &chunkShutdown{}
		err := actual.unmarshal(tc.binary)
		if err != nil {
			t.Fatalf("failed to unmarshal #%d: %v", i, err)
		}

		b, err := actual.marshal()
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}
		assert.Equal(t, tc.binary, b, "test %d not equal", i)
	}
}

func TestChunkShutdown_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{"length too short", []byte{0x07, 0x00, 0x00, 0x07, 0x12, 0x34, 0x56, 0x78}},
		{"length too long", []byte{0x07, 0x00, 0x00, 0x09, 0x12, 0x34, 0x56, 0x78}},
		{"payload too short", []byte{0x07, 0x00, 0x00, 0x08, 0x12, 0x34, 0x56}},
		{"payload too long", []byte{0x07, 0x00, 0x00, 0x08, 0x12, 0x34, 0x56, 0x78, 0x9f}},
		{"invalid type", []byte{0x08, 0x00, 0x00, 0x08, 0x12, 0x34, 0x56, 0x78}},
	}

	for i, tc := range tt {
		actual := &chunkShutdown{}
		err := actual.unmarshal(tc.binary)
		if err == nil {
			t.Errorf("expected unmarshal #%d: '%s' to fail.", i, tc.name)
		}
	}
}
