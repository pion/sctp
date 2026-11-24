// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChunkReconfig_Success(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{
			// Note: chunk trailing padding is added in packet.marshal
			"outgoing reset request", append([]byte{0x82, 0x0, 0x0, 0x1a}, testChunkReconfigParamA()...),
		},
		{"outgoing reset request (no padding)", append([]byte{0x82, 0x0, 0x0, 0x14}, testChunkReconfigParamB()...)},
		{"response", append([]byte{0x82, 0x0, 0x0, 0x10}, testChunkReconfigResponce()...)},
		{
			"outgoing reset request, response",
			append(append([]byte{0x82, 0x0, 0x0, 0x28}, padByte(testChunkReconfigParamA(), 2)...), testChunkReconfigResponce()...),
		},
		{
			// Note: chunk trailing padding is added in packet.marshal
			"response, outgoing reset request",
			append(append([]byte{0x82, 0x0, 0x0, 0x26}, testChunkReconfigResponce()...), testChunkReconfigParamA()...),
		},
		{
			"response, response",
			append(append([]byte{0x82, 0x0, 0x0, 0x1c}, testChunkReconfigResponce()...), testChunkReconfigResponce()...),
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			actual := &chunkReconfig{}
			assert.NoError(t, actual.unmarshal(tc.binary))
			assert.NoError(t, actual.validateCombination())

			b, err := actual.marshal()
			assert.NoError(t, err)
			assert.Equal(t, tc.binary, b)
		})
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

func TestChunkReconfigValidateCombination(t *testing.T) {
	tt := []struct {
		name  string
		chunk *chunkReconfig
		err   error
	}{
		{"outgoing reset request", &chunkReconfig{paramA: &paramOutgoingResetRequest{}}, nil},
		{"response", &chunkReconfig{paramA: &paramReconfigResponse{}}, nil},
		{
			"outgoing reset request, response",
			&chunkReconfig{paramA: &paramOutgoingResetRequest{}, paramB: &paramReconfigResponse{}},
			nil,
		},
		{
			"response, outgoing reset request",
			&chunkReconfig{paramA: &paramReconfigResponse{}, paramB: &paramOutgoingResetRequest{}},
			nil,
		},
		{
			"response, response",
			&chunkReconfig{paramA: &paramReconfigResponse{}, paramB: &paramReconfigResponse{}},
			nil,
		},
		{"no parameters", &chunkReconfig{}, ErrChunkReconfigMissingParam},
		{"only parameter B", &chunkReconfig{paramB: &paramReconfigResponse{}}, ErrChunkReconfigMissingParam},
		{
			"outgoing reset request, outgoing reset request",
			&chunkReconfig{paramA: &paramOutgoingResetRequest{}, paramB: &paramOutgoingResetRequest{}},
			ErrChunkReconfigInvalidCombination,
		},
		{
			"non-reconfig parameter",
			&chunkReconfig{paramA: &paramForwardTSNSupported{}},
			ErrChunkReconfigInvalidCombination,
		},
		{
			"response, non-reconfig parameter",
			&chunkReconfig{paramA: &paramReconfigResponse{}, paramB: &paramForwardTSNSupported{}},
			ErrChunkReconfigInvalidCombination,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.chunk.validateCombination()
			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
