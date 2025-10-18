// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChunkInitAck_UnrecognizedParameters(t *testing.T) {
	// Same layout used in chunk_init_test.go
	initAckChunkHeader := []byte{
		0x55, 0xb9, 0x64, 0xa5, 0x00, 0x02, 0x00, 0x00,
		0x04, 0x00, 0x08, 0x00, 0xe8, 0x6d, 0x10, 0x30,
	}

	// One Unrecognized Param with action=Skip
	unrecognizedSkip := append([]byte{}, initAckChunkHeader...)
	unrecognizedSkip = append(unrecognizedSkip, byte(paramHeaderUnrecognizedActionSkip), 0xFF, 0x00, 0x04, 0x00)

	initCommonChunk := &chunkInitCommon{}
	assert.NoError(t, initCommonChunk.unmarshal(unrecognizedSkip))
	assert.Equal(t, 1, len(initCommonChunk.unrecognizedParams))
	assert.Equal(t, paramHeaderUnrecognizedActionSkip, initCommonChunk.unrecognizedParams[0].unrecognizedAction)

	// One Unrecognized Param with action=Stop
	unrecognizedStop := append([]byte{}, initAckChunkHeader...)
	unrecognizedStop = append(unrecognizedStop, byte(paramHeaderUnrecognizedActionStop), 0xFF, 0x00, 0x04, 0x00)

	initCommonChunk = &chunkInitCommon{}
	assert.NoError(t, initCommonChunk.unmarshal(unrecognizedStop))
	assert.Equal(t, 1, len(initCommonChunk.unrecognizedParams))
	assert.Equal(t, paramHeaderUnrecognizedActionStop, initCommonChunk.unrecognizedParams[0].unrecognizedAction)
}
