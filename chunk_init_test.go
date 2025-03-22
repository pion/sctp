// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChunkInit_UnrecognizedParameters(t *testing.T) {
	initChunkHeader := []byte{
		0x55, 0xb9, 0x64, 0xa5, 0x00, 0x02, 0x00, 0x00,
		0x04, 0x00, 0x08, 0x00, 0xe8, 0x6d, 0x10, 0x30,
	}

	unrecognizedSkip := append([]byte{}, initChunkHeader...)
	unrecognizedSkip = append(unrecognizedSkip, byte(paramHeaderUnrecognizedActionSkip), 0xFF, 0x00, 0x04, 0x00)

	initCommonChunk := &chunkInitCommon{}
	assert.NoError(t, initCommonChunk.unmarshal(unrecognizedSkip))
	assert.Equal(t, 1, len(initCommonChunk.unrecognizedParams))
	assert.Equal(t, paramHeaderUnrecognizedActionSkip, initCommonChunk.unrecognizedParams[0].unrecognizedAction)

	unrecognizedStop := append([]byte{}, initChunkHeader...)
	unrecognizedStop = append(unrecognizedStop, byte(paramHeaderUnrecognizedActionStop), 0xFF, 0x00, 0x04, 0x00)

	initCommonChunk = &chunkInitCommon{}
	assert.NoError(t, initCommonChunk.unmarshal(unrecognizedStop))
	assert.Equal(t, 1, len(initCommonChunk.unrecognizedParams))
	assert.Equal(t, paramHeaderUnrecognizedActionStop, initCommonChunk.unrecognizedParams[0].unrecognizedAction)
}
