// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReassemblyQueue(t *testing.T) { //nolint:maintidx
	t.Run("ordered fragments", func(t *testing.T) {
		rq := newReassemblyQueue(0)

		orgPpi := PayloadTypeWebRTCBinary

		var chunk *chunkPayloadData
		var complete bool

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			beginningFragment:    true,
			tsn:                  1,
			streamSequenceNumber: 0,
			userData:             []byte("ABC"),
		}

		complete = rq.push(chunk)
		assert.False(t, complete, "chunk set should not be complete yet")
		assert.Equal(t, 3, rq.getNumBytes(), "num bytes mismatch")

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			endingFragment:       true,
			tsn:                  2,
			streamSequenceNumber: 0,
			userData:             []byte("DEFG"),
		}

		complete = rq.push(chunk)
		assert.True(t, complete, "chunk set should be complete")
		assert.Equal(t, 7, rq.getNumBytes(), "num bytes mismatch")

		buf := make([]byte, 16)

		n, ppi, err := rq.read(buf)
		assert.Nil(t, err, "read() should succeed")
		assert.Equal(t, 7, n, "should received 7 bytes")
		assert.Equal(t, 0, rq.getNumBytes(), "num bytes mismatch")
		assert.Equal(t, ppi, orgPpi, "should have valid ppi")
		assert.Equal(t, string(buf[:n]), "ABCDEFG", "data should match")
	})

	t.Run("ordered fragments", func(t *testing.T) {
		rq := newReassemblyQueue(0)

		orgPpi := PayloadTypeWebRTCBinary

		var chunk *chunkPayloadData
		var complete bool

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			unordered:            true,
			beginningFragment:    true,
			tsn:                  1,
			streamSequenceNumber: 0,
			userData:             []byte("ABC"),
		}

		complete = rq.push(chunk)
		assert.False(t, complete, "chunk set should not be complete yet")
		assert.Equal(t, 3, rq.getNumBytes(), "num bytes mismatch")

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			unordered:            true,
			tsn:                  2,
			streamSequenceNumber: 0,
			userData:             []byte("DEFG"),
		}

		complete = rq.push(chunk)
		assert.False(t, complete, "chunk set should not be complete yet")
		assert.Equal(t, 7, rq.getNumBytes(), "num bytes mismatch")

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			unordered:            true,
			endingFragment:       true,
			tsn:                  3,
			streamSequenceNumber: 0,
			userData:             []byte("H"),
		}

		complete = rq.push(chunk)
		assert.True(t, complete, "chunk set should be complete")
		assert.Equal(t, 8, rq.getNumBytes(), "num bytes mismatch")

		buf := make([]byte, 16)

		n, ppi, err := rq.read(buf)
		assert.Nil(t, err, "read() should succeed")
		assert.Equal(t, 8, n, "should received 8 bytes")
		assert.Equal(t, 0, rq.getNumBytes(), "num bytes mismatch")
		assert.Equal(t, ppi, orgPpi, "should have valid ppi")
		assert.Equal(t, string(buf[:n]), "ABCDEFGH", "data should match")
	})

	t.Run("ordered and unordered in the mix", func(t *testing.T) {
		rq := newReassemblyQueue(0)

		orgPpi := PayloadTypeWebRTCBinary

		var chunk *chunkPayloadData
		var complete bool

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			beginningFragment:    true,
			endingFragment:       true,
			tsn:                  1,
			streamSequenceNumber: 0,
			userData:             []byte("ABC"),
		}

		complete = rq.push(chunk)
		assert.True(t, complete, "chunk set should be complete")
		assert.Equal(t, 3, rq.getNumBytes(), "num bytes mismatch")

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			unordered:            true,
			beginningFragment:    true,
			endingFragment:       true,
			tsn:                  2,
			streamSequenceNumber: 1,
			userData:             []byte("DEF"),
		}

		complete = rq.push(chunk)
		assert.True(t, complete, "chunk set should be complete")
		assert.Equal(t, 6, rq.getNumBytes(), "num bytes mismatch")

		//
		// Now we have two complete chunks ready to read in the reassemblyQueue.
		//

		buf := make([]byte, 16)

		// Should read unordered chunks first
		n, ppi, err := rq.read(buf)
		assert.Nil(t, err, "read() should succeed")
		assert.Equal(t, 3, n, "should received 3 bytes")
		assert.Equal(t, 3, rq.getNumBytes(), "num bytes mismatch")
		assert.Equal(t, ppi, orgPpi, "should have valid ppi")
		assert.Equal(t, string(buf[:n]), "DEF", "data should match")

		// Next should read ordered chunks
		n, ppi, err = rq.read(buf)
		assert.Nil(t, err, "read() should succeed")
		assert.Equal(t, 3, n, "should received 3 bytes")
		assert.Equal(t, 0, rq.getNumBytes(), "num bytes mismatch")
		assert.Equal(t, ppi, orgPpi, "should have valid ppi")
		assert.Equal(t, string(buf[:n]), "ABC", "data should match")
	})

	t.Run("unordered complete skips incomplete", func(t *testing.T) {
		rq := newReassemblyQueue(0)

		orgPpi := PayloadTypeWebRTCBinary

		var chunk *chunkPayloadData
		var complete bool

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			unordered:            true,
			beginningFragment:    true,
			tsn:                  10,
			streamSequenceNumber: 0,
			userData:             []byte("IN"),
		}

		complete = rq.push(chunk)
		assert.False(t, complete, "chunk set should not be complete yet")
		assert.Equal(t, 2, rq.getNumBytes(), "num bytes mismatch")

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			unordered:            true,
			endingFragment:       true,
			tsn:                  12, // <- incongiguous
			streamSequenceNumber: 1,
			userData:             []byte("COMPLETE"),
		}

		complete = rq.push(chunk)
		assert.False(t, complete, "chunk set should not be complete yet")
		assert.Equal(t, 10, rq.getNumBytes(), "num bytes mismatch")

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			unordered:            true,
			beginningFragment:    true,
			endingFragment:       true,
			tsn:                  13,
			streamSequenceNumber: 1,
			userData:             []byte("GOOD"),
		}

		complete = rq.push(chunk)
		assert.True(t, complete, "chunk set should be complete")
		assert.Equal(t, 14, rq.getNumBytes(), "num bytes mismatch")

		//
		// Now we have two complete chunks ready to read in the reassemblyQueue.
		//

		buf := make([]byte, 16)

		// Should pick the one that has "GOOD"
		n, ppi, err := rq.read(buf)
		assert.Nil(t, err, "read() should succeed")
		assert.Equal(t, 4, n, "should receive 4 bytes")
		assert.Equal(t, 10, rq.getNumBytes(), "num bytes mismatch")
		assert.Equal(t, ppi, orgPpi, "should have valid ppi")
		assert.Equal(t, string(buf[:n]), "GOOD", "data should match")
	})

	t.Run("ignores chunk with wrong SI", func(t *testing.T) {
		rq := newReassemblyQueue(123)

		orgPpi := PayloadTypeWebRTCBinary

		var chunk *chunkPayloadData
		var complete bool

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			streamIdentifier:     124,
			beginningFragment:    true,
			endingFragment:       true,
			tsn:                  10,
			streamSequenceNumber: 0,
			userData:             []byte("IN"),
		}

		complete = rq.push(chunk)
		assert.False(t, complete, "chunk should be ignored")
		assert.Equal(t, 0, rq.getNumBytes(), "num bytes mismatch")
	})

	t.Run("ignores chunk with stale SSN", func(t *testing.T) {
		rq := newReassemblyQueue(0)
		rq.nextSSN = 7 // forcibly set expected SSN to 7

		orgPpi := PayloadTypeWebRTCBinary

		var chunk *chunkPayloadData
		var complete bool

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			beginningFragment:    true,
			endingFragment:       true,
			tsn:                  10,
			streamSequenceNumber: 6, // <-- stale
			userData:             []byte("IN"),
		}

		complete = rq.push(chunk)
		assert.False(t, complete, "chunk should not be ignored")
		assert.Equal(t, 0, rq.getNumBytes(), "num bytes mismatch")
	})

	t.Run("should fail to read incomplete chunk", func(t *testing.T) {
		rq := newReassemblyQueue(0)

		orgPpi := PayloadTypeWebRTCBinary

		var chunk *chunkPayloadData
		var complete bool

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			beginningFragment:    true,
			tsn:                  123,
			streamSequenceNumber: 0,
			userData:             []byte("IN"),
		}

		complete = rq.push(chunk)
		assert.False(t, complete, "the set should not be complete")
		assert.Equal(t, 2, rq.getNumBytes(), "num bytes mismatch")

		buf := make([]byte, 16)
		_, _, err := rq.read(buf)
		assert.NotNil(t, err, "read() should not succeed")
		assert.Equal(t, 2, rq.getNumBytes(), "num bytes mismatch")
	})

	t.Run("should fail to read if the next SSN is not ready", func(t *testing.T) {
		rq := newReassemblyQueue(0)

		orgPpi := PayloadTypeWebRTCBinary

		var chunk *chunkPayloadData
		var complete bool

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			beginningFragment:    true,
			endingFragment:       true,
			tsn:                  123,
			streamSequenceNumber: 1,
			userData:             []byte("IN"),
		}

		complete = rq.push(chunk)
		assert.True(t, complete, "the set should be complete")
		assert.Equal(t, 2, rq.getNumBytes(), "num bytes mismatch")

		buf := make([]byte, 16)
		_, _, err := rq.read(buf)
		assert.NotNil(t, err, "read() should not succeed")
		assert.Equal(t, 2, rq.getNumBytes(), "num bytes mismatch")
	})

	t.Run("detect buffer too short", func(t *testing.T) {
		rq := newReassemblyQueue(0)
		orgPpi := PayloadTypeWebRTCBinary

		for _, chunk := range []*chunkPayloadData{
			{
				payloadType:          orgPpi,
				beginningFragment:    true,
				tsn:                  123,
				streamSequenceNumber: 0,
				userData:             []byte("0123"),
			},
			{
				payloadType:          orgPpi,
				tsn:                  124,
				streamSequenceNumber: 0,
				userData:             []byte("456"),
			},
			{
				payloadType:          orgPpi,
				endingFragment:       true,
				tsn:                  125,
				streamSequenceNumber: 0,
				userData:             []byte("789"),
			},
		} {
			rq.push(chunk)
		}

		assert.Equal(t, 10, rq.getNumBytes())

		buf := make([]byte, 6) // <- passing buffer too short
		n, ppi, err := rq.read(buf)
		assert.Equal(t, io.ErrShortBuffer, err)
		assert.Equal(t, PayloadTypeUnknown, ppi)
		assert.Equal(t, 10, n)

		buf = make([]byte, n)
		n, ppi, err = rq.read(buf)
		assert.NoError(t, err)
		assert.Equal(t, orgPpi, ppi)
		assert.Equal(t, 10, n)
	})

	t.Run("forwardTSN for ordered fragments", func(t *testing.T) {
		rq := newReassemblyQueue(0)

		orgPpi := PayloadTypeWebRTCBinary

		var chunk *chunkPayloadData
		var complete bool
		var ssnComplete uint16 = 5
		var ssnDropped uint16 = 6

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			beginningFragment:    true,
			endingFragment:       true,
			tsn:                  10,
			streamSequenceNumber: ssnComplete,
			userData:             []byte("123"),
		}

		complete = rq.push(chunk)
		assert.True(t, complete, "chunk set should be complete")
		assert.Equal(t, 3, rq.getNumBytes(), "num bytes mismatch")

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			beginningFragment:    true,
			tsn:                  11,
			streamSequenceNumber: ssnDropped,
			userData:             []byte("ABC"),
		}

		complete = rq.push(chunk)
		assert.False(t, complete, "chunk set should not be complete yet")
		assert.Equal(t, 6, rq.getNumBytes(), "num bytes mismatch")

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			tsn:                  12,
			streamSequenceNumber: ssnDropped,
			userData:             []byte("DEF"),
		}

		complete = rq.push(chunk)
		assert.False(t, complete, "chunk set should not be complete yet")
		assert.Equal(t, 9, rq.getNumBytes(), "num bytes mismatch")

		rq.forwardTSNForOrdered(ssnDropped)

		assert.Equal(t, 1, len(rq.ordered), "there should be one chunk left")
		assert.Equal(t, 3, rq.getNumBytes(), "num bytes mismatch")
	})

	t.Run("forwardTSN for unordered fragments", func(t *testing.T) {
		rq := newReassemblyQueue(0)

		orgPpi := PayloadTypeWebRTCBinary

		var chunk *chunkPayloadData
		var complete bool
		var ssnDropped uint16 = 6
		var ssnKept uint16 = 7

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			unordered:            true,
			beginningFragment:    true,
			tsn:                  11,
			streamSequenceNumber: ssnDropped,
			userData:             []byte("ABC"),
		}

		complete = rq.push(chunk)
		assert.False(t, complete, "chunk set should not be complete yet")
		assert.Equal(t, 3, rq.getNumBytes(), "num bytes mismatch")

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			unordered:            true,
			tsn:                  12,
			streamSequenceNumber: ssnDropped,
			userData:             []byte("DEF"),
		}

		complete = rq.push(chunk)
		assert.False(t, complete, "chunk set should not be complete yet")
		assert.Equal(t, 6, rq.getNumBytes(), "num bytes mismatch")

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			unordered:            true,
			tsn:                  14,
			beginningFragment:    true,
			streamSequenceNumber: ssnKept,
			userData:             []byte("SOS"),
		}

		complete = rq.push(chunk)
		assert.False(t, complete, "chunk set should not be complete yet")
		assert.Equal(t, 9, rq.getNumBytes(), "num bytes mismatch")

		// At this point, there are 3 chunks in the rq.unorderedChunks.
		// This call should remove chunks with tsn equals to 13 or older.
		rq.forwardTSNForUnordered(13)

		// As a result, there should be one chunk (tsn=14)
		assert.Equal(t, 1, len(rq.unorderedChunks), "there should be one chunk kept")
		assert.Equal(t, 3, rq.getNumBytes(), "num bytes mismatch")
	})

	t.Run("fragmented and unfragmented chunks with the same ssn", func(t *testing.T) {
		rq := newReassemblyQueue(0)

		orgPpi := PayloadTypeWebRTCBinary

		var chunk *chunkPayloadData
		var complete bool
		var ssn uint16 = 6

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			tsn:                  12,
			beginningFragment:    true,
			endingFragment:       true,
			streamSequenceNumber: ssn,
			userData:             []byte("DEF"),
		}

		complete = rq.push(chunk)
		assert.True(t, complete, "chunk set should be complete")
		assert.Equal(t, 3, rq.getNumBytes(), "num bytes mismatch")

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			beginningFragment:    true,
			tsn:                  11,
			streamSequenceNumber: ssn,
			userData:             []byte("ABC"),
		}

		complete = rq.push(chunk)
		assert.False(t, complete, "chunk set should not be complete yet")
		assert.Equal(t, 6, rq.getNumBytes(), "num bytes mismatch")

		assert.Equal(t, 2, len(rq.ordered), "there should be two chunks")
		assert.Equal(t, 6, rq.getNumBytes(), "num bytes mismatch")
	})

	t.Run("i-data ordered fragments by fsn", func(t *testing.T) {
		rq := newReassemblyQueue(0)
		orgPpi := PayloadTypeWebRTCBinary

		chunk1 := &chunkPayloadData{
			iData:                  true,
			messageIdentifier:      0,
			fragmentSequenceNumber: 1,
			endingFragment:         true,
			tsn:                    10,
			streamIdentifier:       0,
			userData:               []byte("B"),
		}

		complete := rq.push(chunk1)
		assert.False(t, complete, "chunk set should not be complete yet")

		chunk0 := &chunkPayloadData{
			iData:                  true,
			messageIdentifier:      0,
			fragmentSequenceNumber: 0,
			beginningFragment:      true,
			tsn:                    5,
			streamIdentifier:       0,
			payloadType:            orgPpi,
			userData:               []byte("A"),
		}

		complete = rq.push(chunk0)
		assert.True(t, complete, "chunk set should be complete")

		buf := make([]byte, 4)
		n, ppi, err := rq.read(buf)
		assert.NoError(t, err, "read() should succeed")
		assert.Equal(t, 2, n, "should receive 2 bytes")
		assert.Equal(t, orgPpi, ppi, "should have valid ppi")
		assert.Equal(t, "AB", string(buf[:n]), "data should match")
	})

	t.Run("forwardTSN for ordered i-data drops incomplete mids and advances nextMID", func(t *testing.T) {
		rq := newReassemblyQueue(0)
		orgPpi := PayloadTypeWebRTCBinary

		complete := rq.push(&chunkPayloadData{
			iData:             true,
			messageIdentifier: 0,
			beginningFragment: true,
			endingFragment:    true,
			tsn:               10,
			streamIdentifier:  0,
			payloadType:       orgPpi,
			userData:          []byte("OK"),
		})
		assert.True(t, complete)

		complete = rq.push(&chunkPayloadData{
			iData:             true,
			messageIdentifier: 1,
			beginningFragment: true,
			tsn:               11,
			streamIdentifier:  0,
			payloadType:       orgPpi,
			userData:          []byte("DROP"),
		})
		assert.False(t, complete, "MID 1 should remain incomplete")
		assert.Equal(t, 6, rq.getNumBytes(), "num bytes mismatch")

		rq.forwardTSNForOrderedMID(1)

		assert.Equal(t, uint32(2), rq.nextMID, "next MID should advance")
		if assert.Len(t, rq.orderedMID, 1, "only the complete MID should remain") {
			assert.Equal(t, uint32(0), rq.orderedMID[0].mid, "unexpected MID kept")
		}
		_, ok := rq.orderedMIDMap[0]
		assert.True(t, ok, "complete MID should still be mapped")
		_, ok = rq.orderedMIDMap[1]
		assert.False(t, ok, "forwarded incomplete MID should be removed from the map")
		assert.Equal(t, 2, rq.getNumBytes(), "only the kept MID bytes should remain")
		assert.True(t, rq.isReadable(), "kept complete MID should be readable")

		buf := make([]byte, 4)
		n, ppi, err := rq.read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 2, n, "should receive 2 bytes")
		assert.Equal(t, orgPpi, ppi, "should have valid ppi")
		assert.Equal(t, "OK", string(buf[:n]), "data should match")
		assert.Equal(t, 0, rq.getNumBytes(), "all bytes should be drained after read")
		assert.Equal(t, uint32(2), rq.nextMID, "next MID should remain forwarded")
	})

	t.Run("forwardTSN for unordered i-data drops old mids from queue and map", func(t *testing.T) {
		rq := newReassemblyQueue(0)
		orgPpi := PayloadTypeWebRTCBinary

		complete := rq.push(&chunkPayloadData{
			iData:             true,
			unordered:         true,
			messageIdentifier: 1,
			beginningFragment: true,
			endingFragment:    true,
			tsn:               10,
			streamIdentifier:  0,
			payloadType:       orgPpi,
			userData:          []byte("old"),
		})
		assert.True(t, complete, "MID 1 should be complete")

		complete = rq.push(&chunkPayloadData{
			iData:             true,
			unordered:         true,
			messageIdentifier: 2,
			beginningFragment: true,
			tsn:               11,
			streamIdentifier:  0,
			payloadType:       orgPpi,
			userData:          []byte("drop"),
		})
		assert.False(t, complete, "MID 2 should remain incomplete")

		complete = rq.push(&chunkPayloadData{
			iData:             true,
			unordered:         true,
			messageIdentifier: 4,
			beginningFragment: true,
			endingFragment:    true,
			tsn:               12,
			streamIdentifier:  0,
			payloadType:       orgPpi,
			userData:          []byte("keep"),
		})
		assert.True(t, complete, "MID 4 should be complete")

		complete = rq.push(&chunkPayloadData{
			iData:             true,
			unordered:         true,
			messageIdentifier: 5,
			beginningFragment: true,
			tsn:               13,
			streamIdentifier:  0,
			payloadType:       orgPpi,
			userData:          []byte("later"),
		})
		assert.False(t, complete, "MID 5 should remain incomplete")
		assert.Equal(t, 16, rq.getNumBytes(), "num bytes mismatch")

		rq.forwardTSNForUnorderedMID(2)

		if assert.Len(t, rq.unorderedMID, 1, "only newer complete MIDs should remain queued") {
			assert.Equal(t, uint32(4), rq.unorderedMID[0].mid, "unexpected MID kept")
		}
		_, ok := rq.unorderedMIDMap[2]
		assert.False(t, ok, "forwarded incomplete MID should be removed from the map")
		if assert.Len(t, rq.unorderedMIDMap, 1, "only newer incomplete MIDs should remain mapped") {
			_, ok = rq.unorderedMIDMap[5]
			assert.True(t, ok, "MID 5 should remain mapped")
		}
		assert.Equal(t, 9, rq.getNumBytes(), "bytes for forwarded MIDs should be removed")
		assert.True(t, rq.isReadable(), "newer complete unordered MID should still be readable")

		buf := make([]byte, 8)
		n, ppi, err := rq.read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 4, n, "should receive 4 bytes")
		assert.Equal(t, orgPpi, ppi, "should have valid ppi")
		assert.Equal(t, "keep", string(buf[:n]), "data should match")
		assert.Equal(t, 5, rq.getNumBytes(), "only the remaining incomplete MID bytes should remain")
		assert.False(t, rq.isReadable(), "only an incomplete MID should remain")
	})
}

func TestChunkSet(t *testing.T) {
	t.Run("Empty chunkSet", func(t *testing.T) {
		cset := newChunkSet(0, 0)
		assert.False(t, cset.isComplete(), "empty chunkSet cannot be complete")
	})

	t.Run("Push dup chunks to chunkSet", func(t *testing.T) {
		cset := newChunkSet(0, 0)
		cset.push(&chunkPayloadData{
			tsn:               100,
			beginningFragment: true,
		})
		complete := cset.push(&chunkPayloadData{
			tsn:            100,
			endingFragment: true,
		})
		assert.False(t, complete, "chunk with dup TSN is not complete")
		nChunks := len(cset.chunks)
		assert.Equal(t, 1, nChunks, "chunk with dup TSN should be ignored")
	})

	t.Run("Incomplete chunkSet: no beginning", func(t *testing.T) {
		cset := &chunkSet{
			ssn:    0,
			ppi:    0,
			chunks: []*chunkPayloadData{{}},
		}
		assert.False(t, cset.isComplete(),
			"chunkSet not starting with B=1 cannot be complete")
	})

	t.Run("Incomplete chunkSet: no contiguous tsn", func(t *testing.T) {
		cset := &chunkSet{
			ssn: 0,
			ppi: 0,
			chunks: []*chunkPayloadData{
				{
					tsn:               100,
					beginningFragment: true,
				},
				{
					tsn: 101,
				},
				{
					tsn:            103,
					endingFragment: true,
				},
			},
		}
		assert.False(t, cset.isComplete(),
			"chunkSet not starting with incontiguous tsn cannot be complete")
	})
}
