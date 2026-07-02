// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
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

func minimalInitCommon() chunkInitCommon {
	return chunkInitCommon{
		initiateTag:                    0x11111111,
		advertisedReceiverWindowCredit: 1500,
		numOutboundStreams:             1,
		numInboundStreams:              1,
		initialTSN:                     0,
	}
}

func countZCA(b []byte, start int) (n int) {
	off := start

	for {
		if off+4 > len(b) {
			return
		}

		typ := binary.BigEndian.Uint16(b[off : off+2])
		length := int(binary.BigEndian.Uint16(b[off+2 : off+4]))

		if length < 4 || off+length > len(b) {
			return
		}

		if typ == uint16(zeroChecksumAcceptable) && length == 8 {
			n++
		}

		off += length

		if rem := length & 3; rem != 0 {
			off += 4 - rem
		}
	}
}

func TestINIT_ZCA_RoundTrip_NoDup(t *testing.T) {
	initChunk := &chunkInit{chunkInitCommon: minimalInitCommon()}
	initChunk.params = append(initChunk.params, &paramZeroChecksumAcceptable{edmid: dtlsErrorDetectionMethod})

	raw, err := initChunk.marshal()
	assert.NoError(t, err)

	var initChunk2 chunkInit
	assert.NoError(t, initChunk2.unmarshal(raw))

	raw2, err := initChunk2.marshal()
	assert.NoError(t, err)
	assert.Equal(t, 1, countZCA(raw2[chunkHeaderSize:], initChunkMinLength))
}
