// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
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
			append(
				[]byte{0x82, 0x0, 0x0, 0x1a}, testChunkReconfigParamA()...,
			),
		},
		{append([]byte{0x82, 0x0, 0x0, 0x14}, testChunkReconfigParamB()...)},
		{append([]byte{0x82, 0x0, 0x0, 0x10}, testChunkReconfigResponce()...)},
		{
			append(
				append([]byte{0x82, 0x0, 0x0, 0x2c}, padByte(testChunkReconfigParamA(), 2)...),
				testChunkReconfigParamB()...),
		},
		{
			// Note: chunk trailing padding is added in packet.marshal
			append(
				append([]byte{0x82, 0x0, 0x0, 0x2a},
					testChunkReconfigParamB()...),
				testChunkReconfigParamA()...,
			),
		},
	}

	for i, tc := range tt {
		actual := &chunkReconfig{}
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

func TestChunkReconfigUnmarshal_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{"chunk header to short", []byte{0x82}},
		{"missing parse param type (A)", []byte{0x82, 0x0, 0x0, 0x4}},
		{"wrong param (A)", []byte{0x82, 0x0, 0x0, 0x8, 0x0, 0xd, 0x0, 0x0}},
		{
			"wrong param (B)",
			append(append([]byte{0x82, 0x0, 0x0, 0x18},
				testChunkReconfigParamB()...),
				[]byte{0x0, 0xd, 0x0, 0x0}...),
		},
	}

	for i, tc := range tt {
		actual := &chunkReconfig{}
		err := actual.unmarshal(tc.binary)
		if err == nil {
			t.Errorf("expected unmarshal #%d: '%s' to fail.", i, tc.name)
		}
	}
}
