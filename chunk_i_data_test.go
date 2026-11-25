// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// emptyPayloadChunk builds a DATA or I-DATA chunk that carries no user data,
// which chunkPayloadData.marshal refuses to produce.
func emptyPayloadChunk(t *testing.T, iData bool, tsn uint32) []byte {
	t.Helper()

	header := chunkHeader{
		typ:   ctPayloadData,
		flags: payloadDataBeginingFragmentBitmask | payloadDataEndingFragmentBitmask,
		raw:   make([]byte, payloadDataHeaderSize),
	}
	if iData {
		header.typ = ctIData
		header.raw = make([]byte, iDataHeaderSize)
	}
	binary.BigEndian.PutUint32(header.raw, tsn)

	raw, err := header.marshal()
	require.NoError(t, err)

	return raw
}

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
			userData:          []byte{0x01},
		}
		dataRaw, err := data.marshal()
		assert.NoError(t, err)
		assert.Equal(t, int(dataChunkHeaderSize)+len(data.userData), len(dataRaw))
		assert.Equal(t, int(dataChunkHeaderSize)+len(data.userData), data.chunkSize())

		iData := &chunkPayloadData{
			iData:             true,
			beginningFragment: true,
			endingFragment:    true,
			userData:          []byte{0x01},
		}
		iDataRaw, err := iData.marshal()
		assert.NoError(t, err)
		assert.Equal(t, int(iDataChunkHeaderSize)+len(iData.userData), len(iDataRaw))
		assert.Equal(t, int(iDataChunkHeaderSize)+len(iData.userData), iData.chunkSize())
	})

	t.Run("empty user data", func(t *testing.T) {
		for name, iData := range map[string]bool{"DATA": false, "I-DATA": true} {
			t.Run(name, func(t *testing.T) {
				// Sending an empty chunk is refused.
				_, err := (&chunkPayloadData{iData: iData, beginningFragment: true, endingFragment: true}).marshal()
				assert.ErrorIs(t, err, ErrDATAZeroUserData)

				// Receiving one is not, so that the association can abort with its TSN.
				parsed := &chunkPayloadData{}
				require.NoError(t, parsed.unmarshal(emptyPayloadChunk(t, iData, 7)))
				assert.Empty(t, parsed.userData)
				assert.Equal(t, uint32(7), parsed.tsn)
				assert.Equal(t, iData, parsed.isIData())
			})
		}
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
