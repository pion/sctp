// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChunkReconfig_Success(t *testing.T) {
	tt := []struct {
		binary []byte
	}{
		{
			// Note: chunk trailing padding is added in packet.marshal
			append([]byte{0x82, 0x0, 0x0, 0x1a}, testChunkReconfigParamA()...),
		},
		{append([]byte{0x82, 0x0, 0x0, 0x14}, testChunkReconfigParamB()...)},
		{append([]byte{0x82, 0x0, 0x0, 0x10}, testChunkReconfigResponce()...)},
		{
			append(append([]byte{0x82, 0x0, 0x0, 0x2c}, padByte(testChunkReconfigParamA(), 2)...), testChunkReconfigParamB()...),
		},
		{
			// Note: chunk trailing padding is added in packet.marshal
			append(append([]byte{0x82, 0x0, 0x0, 0x2a}, testChunkReconfigParamB()...), testChunkReconfigParamA()...),
		},
	}

	for i, tc := range tt {
		actual := &chunkReconfig{}
		err := actual.unmarshal(tc.binary)
		assert.NoErrorf(t, err, "failed to unmarshal #%d: %v", i)

		b, err := actual.marshal()
		assert.NoError(t, err)
		assert.Equalf(t, tc.binary, b, "test %d not equal", i)
	}
}

func TestChunkReconfigUnmarshal_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
		err    error
	}{
		{"chunk header to short", []byte{0x82}, nil},
		{"no parameters", []byte{0x82, 0x0, 0x0, 0x4}, ErrChunkReconfigMissingParam},
		{"wrong param (A)", []byte{0x82, 0x0, 0x0, 0x8, 0x0, 0xd, 0x0, 0x0}, nil},
		{
			"wrong param (B)",
			append(append([]byte{0x82, 0x0, 0x0, 0x18}, testChunkReconfigParamB()...), []byte{0x0, 0xd, 0x0, 0x0}...),
			nil,
		},
		{
			"truncated param header (B)",
			append(append([]byte{0x82, 0x0, 0x0, 0x12}, testChunkReconfigResponce()...), []byte{0x0, 0x10}...),
			ErrChunkParseParamTypeFailed,
		},
		{
			"three parameters",
			append(append(append([]byte{0x82, 0x0, 0x0, 0x28},
				testChunkReconfigResponce()...), testChunkReconfigResponce()...), testChunkReconfigResponce()...),
			ErrChunkReconfigTooManyParams,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			actual := &chunkReconfig{}
			err := actual.unmarshal(tc.binary)
			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestChunkReconfigMarshal_MissingParam(t *testing.T) {
	for name, c := range map[string]*chunkReconfig{
		"no parameters":    {},
		"only parameter B": {paramB: &paramReconfigResponse{}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.marshal()
			assert.ErrorIs(t, err, ErrChunkReconfigMissingParam)
		})
	}
}
