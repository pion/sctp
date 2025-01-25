// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"testing"
)

func TestChunkInit_UnrecognizedParameters(t *testing.T) {
	initChunkHeader := []byte{
		0x55, 0xb9, 0x64, 0xa5, 0x00, 0x02, 0x00, 0x00,
		0x04, 0x00, 0x08, 0x00, 0xe8, 0x6d, 0x10, 0x30,
	}

	unrecognizedSkip := append([]byte{}, initChunkHeader...)
	unrecognizedSkip = append(unrecognizedSkip, byte(paramHeaderUnrecognizedActionSkip), 0xFF, 0x00, 0x04, 0x00)

	initCommonChunk := &chunkInitCommon{}
	if err := initCommonChunk.unmarshal(unrecognizedSkip); err != nil {
		t.Errorf("Unmarshal init Chunk failed: %v", err)
	} else if len(initCommonChunk.unrecognizedParams) != 1 ||
		initCommonChunk.unrecognizedParams[0].unrecognizedAction != paramHeaderUnrecognizedActionSkip {
		t.Errorf("Unrecognized Param parsed incorrectly")
	}

	unrecognizedStop := append([]byte{}, initChunkHeader...)
	unrecognizedStop = append(unrecognizedStop, byte(paramHeaderUnrecognizedActionStop), 0xFF, 0x00, 0x04, 0x00)

	initCommonChunk = &chunkInitCommon{}
	if err := initCommonChunk.unmarshal(unrecognizedStop); err != nil {
		t.Errorf("Unmarshal init Chunk failed: %v", err)
	} else if len(initCommonChunk.unrecognizedParams) != 1 ||
		initCommonChunk.unrecognizedParams[0].unrecognizedAction != paramHeaderUnrecognizedActionStop {
		t.Errorf("Unrecognized Param parsed incorrectly")
	}
}
