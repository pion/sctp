// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChunkIDataMarshalUnmarshal(t *testing.T) {
	t.Run("beginning fragment", func(t *testing.T) {
		orig := &chunkPayloadData{
			iData:                  true,
			tsn:                    1,
			streamIdentifier:       2,
			messageIdentifier:      5,
			fragmentSequenceNumber: 0,
			payloadType:            PayloadTypeWebRTCBinary,
			userData:               []byte("abc"),
			beginningFragment:      true,
			endingFragment:         true,
		}

		raw, err := orig.marshal()
		assert.NoError(t, err)

		parsed := &chunkPayloadData{}
		err = parsed.unmarshal(raw)
		assert.NoError(t, err)
		assert.True(t, parsed.isIData())
		assert.Equal(t, orig.tsn, parsed.tsn)
		assert.Equal(t, orig.streamIdentifier, parsed.streamIdentifier)
		assert.Equal(t, orig.messageIdentifier, parsed.messageIdentifier)
		assert.Equal(t, orig.fragmentSequenceNumber, parsed.fragmentSequenceNumber)
		assert.Equal(t, orig.payloadType, parsed.payloadType)
		assert.Equal(t, orig.userData, parsed.userData)
		assert.True(t, parsed.beginningFragment)
		assert.True(t, parsed.endingFragment)
	})

	t.Run("middle fragment", func(t *testing.T) {
		orig := &chunkPayloadData{
			iData:                  true,
			tsn:                    2,
			streamIdentifier:       3,
			messageIdentifier:      7,
			fragmentSequenceNumber: 4,
			payloadType:            PayloadTypeWebRTCBinary,
			userData:               []byte("def"),
			beginningFragment:      false,
			endingFragment:         false,
		}

		raw, err := orig.marshal()
		assert.NoError(t, err)

		parsed := &chunkPayloadData{}
		err = parsed.unmarshal(raw)
		assert.NoError(t, err)
		assert.True(t, parsed.isIData())
		assert.Equal(t, orig.tsn, parsed.tsn)
		assert.Equal(t, orig.streamIdentifier, parsed.streamIdentifier)
		assert.Equal(t, orig.messageIdentifier, parsed.messageIdentifier)
		assert.Equal(t, orig.fragmentSequenceNumber, parsed.fragmentSequenceNumber)
		assert.Equal(t, PayloadTypeUnknown, parsed.payloadType)
		assert.Equal(t, orig.userData, parsed.userData)
		assert.False(t, parsed.beginningFragment)
		assert.False(t, parsed.endingFragment)
	})
}

func TestPayloadDataHeaderSizeAccounting(t *testing.T) {
	t.Run("header constants match marshaled chunks", func(t *testing.T) {
		data := &chunkPayloadData{
			beginningFragment: true,
			endingFragment:    true,
		}
		dataRaw, err := data.marshal()
		assert.NoError(t, err)
		assert.Equal(t, int(dataChunkHeaderSize), len(dataRaw))
		assert.Equal(t, int(dataChunkHeaderSize), data.chunkSize())

		iData := &chunkPayloadData{
			iData:             true,
			beginningFragment: true,
			endingFragment:    true,
		}
		iDataRaw, err := iData.marshal()
		assert.NoError(t, err)
		assert.Equal(t, int(iDataChunkHeaderSize), len(iDataRaw))
		assert.Equal(t, int(iDataChunkHeaderSize), iData.chunkSize())
	})

	t.Run("default MTU payload limits include padding", func(t *testing.T) {
		testCases := []struct {
			name            string
			useInterleaving bool
			expectedPayload uint32
		}{
			{
				name:            "DATA",
				useInterleaving: false,
				expectedPayload: 1160,
			},
			{
				name:            "I-DATA",
				useInterleaving: true,
				expectedPayload: 1156,
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				payloadSize := maxPayloadSizeForMTU(initialMTU, tc.useInterleaving)
				assert.Equal(t, tc.expectedPayload, payloadSize)

				chunkPayload := &chunkPayloadData{
					iData:             tc.useInterleaving,
					beginningFragment: true,
					endingFragment:    true,
					userData:          make([]byte, payloadSize),
				}
				p := &packet{chunks: []chunk{chunkPayload}}
				raw, err := p.marshal(false)
				assert.NoError(t, err)
				assert.LessOrEqual(t, len(raw), int(initialMTU))
			})
		}
	})
}
