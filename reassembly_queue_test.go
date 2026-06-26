// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReassemblyQueue(t *testing.T) { //nolint:maintidx,cyclop
	t.Run("ordered fragments", func(t *testing.T) {
		rq := newReassemblyQueue(0, 0)

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
		rq := newReassemblyQueue(0, 0)

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
		rq := newReassemblyQueue(0, 0)

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
		rq := newReassemblyQueue(0, 0)

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
		rq := newReassemblyQueue(123, 0)

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
		rq := newReassemblyQueue(0, 0)
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
		rq := newReassemblyQueue(0, 0)

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
		rq := newReassemblyQueue(0, 0)

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
		rq := newReassemblyQueue(0, 0)
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
		rq := newReassemblyQueue(0, 0)

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
		rq := newReassemblyQueue(0, 0)

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
		rq := newReassemblyQueue(0, 0)

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

	t.Run("ordered data has no descriptor limit by default", func(t *testing.T) {
		const oldLimit = 3
		rq := newReassemblyQueue(0, 0)

		for i := range oldLimit + 1 {
			complete, err := rq.pushWithError(&chunkPayloadData{
				streamSequenceNumber: uint16(i), //nolint:gosec // bounded by oldLimit
				beginningFragment:    true,
				tsn:                  uint32(i + 1), //nolint:gosec // bounded by oldLimit
				streamIdentifier:     0,
				payloadType:          PayloadTypeWebRTCBinary,
			})
			assert.NoError(t, err)
			assert.False(t, complete, "SSN should remain incomplete")
		}

		assert.Len(t, rq.ordered, oldLimit+1)
	})

	t.Run("ordered data rejects new entries after descriptor limit", func(t *testing.T) {
		const limit = 3
		rq := newReassemblyQueue(0, limit)

		for i := range limit {
			complete, err := rq.pushWithError(&chunkPayloadData{
				streamSequenceNumber: uint16(i), //nolint:gosec // bounded by limit
				beginningFragment:    true,
				tsn:                  uint32(i*10 + 1), //nolint:gosec // bounded by limit
				streamIdentifier:     0,
				payloadType:          PayloadTypeWebRTCBinary,
			})
			assert.NoError(t, err)
			assert.False(t, complete, "SSN should remain incomplete")
		}

		complete, err := rq.pushWithError(&chunkPayloadData{
			streamSequenceNumber: 0,
			beginningFragment:    true,
			tsn:                  1,
			streamIdentifier:     0,
			payloadType:          PayloadTypeWebRTCBinary,
		})
		assert.NoError(t, err, "duplicate fragments should not be rejected at the limit")
		assert.False(t, complete, "duplicate fragments should not complete")

		complete, err = rq.pushWithError(&chunkPayloadData{
			streamSequenceNumber: 0,
			endingFragment:       true,
			tsn:                  2,
			streamIdentifier:     0,
			payloadType:          PayloadTypeWebRTCBinary,
		})
		assert.ErrorIs(t, err, errReassemblyQueueLimitExceeded)
		assert.False(t, complete, "new fragments for existing SSNs should be rejected at the limit")

		complete, err = rq.pushWithError(&chunkPayloadData{
			streamSequenceNumber: limit,
			beginningFragment:    true,
			tsn:                  limit*10 + 1,
			streamIdentifier:     0,
			payloadType:          PayloadTypeWebRTCBinary,
		})
		assert.ErrorIs(t, err, errReassemblyQueueLimitExceeded)
		assert.False(t, complete, "new SSN should be rejected")
		assert.Len(t, rq.ordered, limit)
		assert.Equal(t, limit, rq.orderedDataEntryCount())
	})

	t.Run("unordered data has no descriptor limit by default", func(t *testing.T) {
		const oldLimit = 3
		rq := newReassemblyQueue(0, 0)

		for i := range oldLimit + 1 {
			complete, err := rq.pushWithError(&chunkPayloadData{
				unordered:         true,
				beginningFragment: true,
				tsn:               uint32(i + 1), //nolint:gosec // bounded by oldLimit
				streamIdentifier:  0,
				payloadType:       PayloadTypeWebRTCBinary,
			})
			assert.NoError(t, err)
			assert.False(t, complete, "unordered DATA should remain incomplete")
		}

		assert.Len(t, rq.unorderedChunks, oldLimit+1)
		assert.Len(t, rq.unordered, 0)
	})

	t.Run("unordered data rejects new incomplete chunks after descriptor limit", func(t *testing.T) {
		const limit = 3
		rq := newReassemblyQueue(0, limit)

		for i := range limit {
			complete, err := rq.pushWithError(&chunkPayloadData{
				unordered:         true,
				beginningFragment: true,
				tsn:               uint32(i + 1), //nolint:gosec // bounded by limit
				streamIdentifier:  0,
				payloadType:       PayloadTypeWebRTCBinary,
			})
			assert.NoError(t, err)
			assert.False(t, complete, "unordered DATA should remain incomplete")
		}

		complete, err := rq.pushWithError(&chunkPayloadData{
			unordered:         true,
			beginningFragment: true,
			tsn:               limit + 1,
			streamIdentifier:  0,
			payloadType:       PayloadTypeWebRTCBinary,
		})
		assert.ErrorIs(t, err, errReassemblyQueueLimitExceeded)
		assert.False(t, complete, "new unordered DATA chunk should be rejected")
		assert.Len(t, rq.unorderedChunks, limit)
		assert.Len(t, rq.unordered, 0)
	})

	t.Run("unordered data counts complete queued sets against descriptor limit", func(t *testing.T) {
		const limit = 3
		rq := newReassemblyQueue(0, limit)

		for i := range limit {
			complete, err := rq.pushWithError(&chunkPayloadData{
				unordered:         true,
				beginningFragment: true,
				endingFragment:    true,
				tsn:               uint32(i + 1), //nolint:gosec // bounded by limit
				streamIdentifier:  0,
				payloadType:       PayloadTypeWebRTCBinary,
			})
			assert.NoError(t, err)
			assert.True(t, complete, "unordered DATA should complete")
		}

		complete, err := rq.pushWithError(&chunkPayloadData{
			unordered:         true,
			beginningFragment: true,
			endingFragment:    true,
			tsn:               limit + 1,
			streamIdentifier:  0,
			payloadType:       PayloadTypeWebRTCBinary,
		})
		assert.ErrorIs(t, err, errReassemblyQueueLimitExceeded)
		assert.False(t, complete, "new unordered DATA set should be rejected")
		assert.Len(t, rq.unorderedChunks, 0)
		assert.Len(t, rq.unordered, limit)
		assert.Equal(t, limit, rq.unorderedDataEntryCount())
	})

	t.Run("unordered data counts complete queued set fragments against descriptor limit", func(t *testing.T) {
		const limit = 3
		rq := newReassemblyQueue(0, limit)

		for i := range limit {
			complete, err := rq.pushWithError(&chunkPayloadData{
				unordered:         true,
				beginningFragment: i == 0,
				endingFragment:    i == limit-1,
				tsn:               uint32(i + 1), //nolint:gosec // bounded by limit
				streamIdentifier:  0,
				payloadType:       PayloadTypeWebRTCBinary,
			})
			assert.NoError(t, err)
			assert.Equal(t, i == limit-1, complete)
		}

		complete, err := rq.pushWithError(&chunkPayloadData{
			unordered:         true,
			beginningFragment: true,
			endingFragment:    true,
			tsn:               limit + 1,
			streamIdentifier:  0,
			payloadType:       PayloadTypeWebRTCBinary,
		})
		assert.ErrorIs(t, err, errReassemblyQueueLimitExceeded)
		assert.False(t, complete, "new unordered DATA set should be rejected")
		assert.Len(t, rq.unorderedChunks, 0)
		assert.Len(t, rq.unordered, 1)
		assert.Equal(t, limit, rq.unorderedDataEntryCount())
	})

	t.Run("i-data ordered fragments by fsn", func(t *testing.T) {
		rq := newReassemblyQueue(0, 0)
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

	t.Run("ordered i-data ignores duplicate fsn with different tsn", func(t *testing.T) {
		rq := newReassemblyQueue(0, 0)
		orgPpi := PayloadTypeWebRTCBinary

		complete := rq.push(&chunkPayloadData{
			iData:                  true,
			messageIdentifier:      0,
			fragmentSequenceNumber: 0,
			beginningFragment:      true,
			tsn:                    5,
			streamIdentifier:       0,
			payloadType:            orgPpi,
			userData:               []byte("A"),
		})
		assert.False(t, complete, "chunk set should not be complete yet")
		assert.Equal(t, 1, rq.getNumBytes(), "num bytes mismatch")

		complete = rq.push(&chunkPayloadData{
			iData:                  true,
			messageIdentifier:      0,
			fragmentSequenceNumber: 0,
			tsn:                    10,
			streamIdentifier:       0,
			payloadType:            orgPpi,
			userData:               []byte("duplicate"),
		})
		assert.False(t, complete, "duplicate FSN should be ignored")
		assert.Equal(t, 1, rq.getNumBytes(), "duplicate FSN must not count toward queued bytes")

		complete = rq.push(&chunkPayloadData{
			iData:                  true,
			messageIdentifier:      0,
			fragmentSequenceNumber: 1,
			endingFragment:         true,
			tsn:                    6,
			streamIdentifier:       0,
			payloadType:            orgPpi,
			userData:               []byte("B"),
		})
		assert.True(t, complete, "chunk set should be complete")
		assert.Equal(t, 2, rq.getNumBytes(), "num bytes mismatch")

		buf := make([]byte, 4)
		n, ppi, err := rq.read(buf)
		assert.NoError(t, err, "read() should succeed")
		assert.Equal(t, 2, n, "should receive 2 bytes")
		assert.Equal(t, orgPpi, ppi, "should have valid ppi")
		assert.Equal(t, "AB", string(buf[:n]), "data should match")
		assert.Equal(t, 0, rq.getNumBytes(), "num bytes mismatch")
	})

	t.Run("ordered i-data ignores stale incomplete mid after read advances nextMID", func(t *testing.T) {
		rq := newReassemblyQueue(0, 0)
		orgPpi := PayloadTypeWebRTCBinary

		complete, err := rq.pushWithError(&chunkPayloadData{
			iData:             true,
			messageIdentifier: 0,
			beginningFragment: true,
			endingFragment:    true,
			tsn:               1,
			streamIdentifier:  0,
			payloadType:       orgPpi,
			userData:          []byte("M0"),
		})
		assert.NoError(t, err)
		assert.True(t, complete, "MID 0 should be complete")

		buf := make([]byte, 4)
		n, ppi, err := rq.read(buf)
		assert.NoError(t, err, "read() should succeed")
		assert.Equal(t, 2, n, "should receive 2 bytes")
		assert.Equal(t, orgPpi, ppi, "should have valid ppi")
		assert.Equal(t, "M0", string(buf[:n]), "data should match")
		assert.Equal(t, uint32(1), rq.nextMID, "next MID should advance")
		assert.Equal(t, 0, rq.getNumBytes(), "queue should be empty after read")

		complete, err = rq.pushWithError(&chunkPayloadData{
			iData:                  true,
			messageIdentifier:      0,
			fragmentSequenceNumber: 0,
			beginningFragment:      true,
			tsn:                    2,
			streamIdentifier:       0,
			payloadType:            orgPpi,
			userData:               []byte("stale"),
		})
		assert.NoError(t, err)
		assert.False(t, complete, "stale MID should be ignored")
		assert.Len(t, rq.orderedMID, 0, "stale MID must not be queued")
		assert.Len(t, rq.orderedMIDMap, 0, "stale MID must not be mapped")
		assert.Equal(t, 0, rq.getNumBytes(), "stale MID must not count toward queued bytes")

		complete, err = rq.pushWithError(&chunkPayloadData{
			iData:             true,
			messageIdentifier: 1,
			beginningFragment: true,
			endingFragment:    true,
			tsn:               3,
			streamIdentifier:  0,
			payloadType:       orgPpi,
			userData:          []byte("M1"),
		})
		assert.NoError(t, err)
		assert.True(t, complete, "MID 1 should be complete")
		assert.True(t, rq.isReadable(), "current MID should not be blocked by stale MID")

		n, ppi, err = rq.read(buf)
		assert.NoError(t, err, "read() should succeed")
		assert.Equal(t, 2, n, "should receive 2 bytes")
		assert.Equal(t, orgPpi, ppi, "should have valid ppi")
		assert.Equal(t, "M1", string(buf[:n]), "data should match")
		assert.Equal(t, uint32(2), rq.nextMID, "next MID should advance")
		assert.Equal(t, 0, rq.getNumBytes(), "queue should be empty after read")
	})

	t.Run("ordered i-data ignores stale complete mid after read advances nextMID", func(t *testing.T) {
		rq := newReassemblyQueue(0, 0)
		orgPpi := PayloadTypeWebRTCBinary

		complete, err := rq.pushWithError(&chunkPayloadData{
			iData:             true,
			messageIdentifier: 0,
			beginningFragment: true,
			endingFragment:    true,
			tsn:               1,
			streamIdentifier:  0,
			payloadType:       orgPpi,
			userData:          []byte("M0"),
		})
		assert.NoError(t, err)
		assert.True(t, complete, "MID 0 should be complete")

		buf := make([]byte, 4)
		n, ppi, err := rq.read(buf)
		assert.NoError(t, err, "read() should succeed")
		assert.Equal(t, 2, n, "should receive 2 bytes")
		assert.Equal(t, orgPpi, ppi, "should have valid ppi")
		assert.Equal(t, "M0", string(buf[:n]), "data should match")
		assert.Equal(t, uint32(1), rq.nextMID, "next MID should advance")
		assert.Equal(t, 0, rq.getNumBytes(), "queue should be empty after read")

		complete, err = rq.pushWithError(&chunkPayloadData{
			iData:             true,
			messageIdentifier: 0,
			beginningFragment: true,
			endingFragment:    true,
			tsn:               2,
			streamIdentifier:  0,
			payloadType:       orgPpi,
			userData:          []byte("old"),
		})
		assert.NoError(t, err)
		assert.False(t, complete, "stale complete MID should be ignored")
		assert.False(t, rq.isReadable(), "stale complete MID must not become readable")
		assert.Len(t, rq.orderedMID, 0, "stale MID must not be queued")
		assert.Len(t, rq.orderedMIDMap, 0, "stale MID must not be mapped")
		assert.Equal(t, 0, rq.getNumBytes(), "stale MID must not count toward queued bytes")
	})

	t.Run("unordered i-data ignores duplicate fsn with different tsn", func(t *testing.T) {
		rq := newReassemblyQueue(0, 0)
		orgPpi := PayloadTypeWebRTCBinary

		complete := rq.push(&chunkPayloadData{
			iData:                  true,
			unordered:              true,
			messageIdentifier:      0,
			fragmentSequenceNumber: 0,
			beginningFragment:      true,
			tsn:                    5,
			streamIdentifier:       0,
			payloadType:            orgPpi,
			userData:               []byte("A"),
		})
		assert.False(t, complete, "chunk set should not be complete yet")
		assert.Equal(t, 1, rq.getNumBytes(), "num bytes mismatch")

		complete = rq.push(&chunkPayloadData{
			iData:                  true,
			unordered:              true,
			messageIdentifier:      0,
			fragmentSequenceNumber: 0,
			tsn:                    10,
			streamIdentifier:       0,
			payloadType:            orgPpi,
			userData:               []byte("duplicate"),
		})
		assert.False(t, complete, "duplicate FSN should be ignored")
		assert.Equal(t, 1, rq.getNumBytes(), "duplicate FSN must not count toward queued bytes")

		complete = rq.push(&chunkPayloadData{
			iData:                  true,
			unordered:              true,
			messageIdentifier:      0,
			fragmentSequenceNumber: 1,
			endingFragment:         true,
			tsn:                    6,
			streamIdentifier:       0,
			payloadType:            orgPpi,
			userData:               []byte("B"),
		})
		assert.True(t, complete, "chunk set should be complete")
		assert.Equal(t, 2, rq.getNumBytes(), "num bytes mismatch")

		complete = rq.push(&chunkPayloadData{
			iData:                  true,
			unordered:              true,
			messageIdentifier:      0,
			fragmentSequenceNumber: 1,
			endingFragment:         true,
			tsn:                    11,
			streamIdentifier:       0,
			payloadType:            orgPpi,
			userData:               []byte("late-duplicate"),
		})
		assert.False(t, complete, "duplicate for queued complete MID should be ignored")
		assert.Equal(t, 2, rq.getNumBytes(), "late duplicate must not count toward queued bytes")

		buf := make([]byte, 4)
		n, ppi, err := rq.read(buf)
		assert.NoError(t, err, "read() should succeed")
		assert.Equal(t, 2, n, "should receive 2 bytes")
		assert.Equal(t, orgPpi, ppi, "should have valid ppi")
		assert.Equal(t, "AB", string(buf[:n]), "data should match")
		assert.Equal(t, 0, rq.getNumBytes(), "num bytes mismatch")
	})

	t.Run("forwardTSN for ordered i-data drops incomplete mids and advances nextMID", func(t *testing.T) {
		rq := newReassemblyQueue(0, 0)
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

	t.Run("ordered i-data ignores stale mids after forwardTSN advances nextMID", func(t *testing.T) {
		rq := newReassemblyQueue(0, 0)
		orgPpi := PayloadTypeWebRTCBinary

		rq.forwardTSNForOrderedMID(1)
		assert.Equal(t, uint32(2), rq.nextMID, "next MID should advance")

		complete, err := rq.pushWithError(&chunkPayloadData{
			iData:                  true,
			messageIdentifier:      0,
			fragmentSequenceNumber: 0,
			beginningFragment:      true,
			tsn:                    1,
			streamIdentifier:       0,
			payloadType:            orgPpi,
			userData:               []byte("old0"),
		})
		assert.NoError(t, err)
		assert.False(t, complete, "stale MID 0 should be ignored")
		assert.Len(t, rq.orderedMID, 0, "stale MID must not be queued")
		assert.Len(t, rq.orderedMIDMap, 0, "stale MID must not be mapped")
		assert.Equal(t, 0, rq.getNumBytes(), "stale MID must not count toward queued bytes")

		complete, err = rq.pushWithError(&chunkPayloadData{
			iData:             true,
			messageIdentifier: 1,
			beginningFragment: true,
			endingFragment:    true,
			tsn:               2,
			streamIdentifier:  0,
			payloadType:       orgPpi,
			userData:          []byte("old1"),
		})
		assert.NoError(t, err)
		assert.False(t, complete, "stale MID 1 should be ignored")
		assert.Len(t, rq.orderedMID, 0, "stale MID must not be queued")
		assert.Len(t, rq.orderedMIDMap, 0, "stale MID must not be mapped")
		assert.Equal(t, 0, rq.getNumBytes(), "stale MID must not count toward queued bytes")

		complete, err = rq.pushWithError(&chunkPayloadData{
			iData:             true,
			messageIdentifier: 2,
			beginningFragment: true,
			endingFragment:    true,
			tsn:               3,
			streamIdentifier:  0,
			payloadType:       orgPpi,
			userData:          []byte("M2"),
		})
		assert.NoError(t, err)
		assert.True(t, complete, "MID 2 should be complete")
		assert.True(t, rq.isReadable(), "current MID should not be blocked by stale MIDs")

		buf := make([]byte, 4)
		n, ppi, err := rq.read(buf)
		assert.NoError(t, err, "read() should succeed")
		assert.Equal(t, 2, n, "should receive 2 bytes")
		assert.Equal(t, orgPpi, ppi, "should have valid ppi")
		assert.Equal(t, "M2", string(buf[:n]), "data should match")
		assert.Equal(t, uint32(3), rq.nextMID, "next MID should advance")
		assert.Equal(t, 0, rq.getNumBytes(), "queue should be empty after read")
	})

	t.Run("forwardTSN for unordered i-data keeps complete mids and drops old incomplete mids", func(t *testing.T) {
		rq := newReassemblyQueue(0, 0)
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

		if assert.Len(t, rq.unorderedMID, 2, "complete MIDs should remain queued") {
			assert.Equal(t, uint32(1), rq.unorderedMID[0].mid, "unexpected first MID kept")
			assert.Equal(t, uint32(4), rq.unorderedMID[1].mid, "unexpected second MID kept")
		}
		_, ok := rq.unorderedMIDMap[2]
		assert.False(t, ok, "forwarded incomplete MID should be removed from the map")
		if assert.Len(t, rq.unorderedMIDMap, 1, "only newer incomplete MIDs should remain mapped") {
			_, ok = rq.unorderedMIDMap[5]
			assert.True(t, ok, "MID 5 should remain mapped")
		}
		assert.Equal(t, 12, rq.getNumBytes(), "only incomplete forwarded MID bytes should be removed")
		assert.True(t, rq.isReadable(), "complete unordered MID should still be readable")

		buf := make([]byte, 8)
		n, ppi, err := rq.read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 3, n, "should receive 3 bytes")
		assert.Equal(t, orgPpi, ppi, "should have valid ppi")
		assert.Equal(t, "old", string(buf[:n]), "data should match")
		assert.Equal(t, 9, rq.getNumBytes(), "newer complete and incomplete MID bytes should remain")
		assert.True(t, rq.isReadable(), "newer complete unordered MID should still be readable")

		n, ppi, err = rq.read(buf)
		assert.NoError(t, err)
		assert.Equal(t, 4, n, "should receive 4 bytes")
		assert.Equal(t, orgPpi, ppi, "should have valid ppi")
		assert.Equal(t, "keep", string(buf[:n]), "data should match")
		assert.Equal(t, 5, rq.getNumBytes(), "only the remaining incomplete MID bytes should remain")
		assert.False(t, rq.isReadable(), "only an incomplete MID should remain")
	})

	t.Run("ordered i-data has no descriptor limit by default", func(t *testing.T) {
		const oldLimit = 3
		rq := newReassemblyQueue(0, 0)

		for i := range oldLimit + 1 {
			complete, err := rq.pushWithError(&chunkPayloadData{
				iData:                  true,
				messageIdentifier:      uint32(i), //nolint:gosec // bounded by oldLimit
				fragmentSequenceNumber: 0,
				beginningFragment:      true,
				tsn:                    uint32(i + 1), //nolint:gosec // bounded by oldLimit
				streamIdentifier:       0,
				payloadType:            PayloadTypeWebRTCBinary,
			})
			assert.NoError(t, err)
			assert.False(t, complete, "MID should remain incomplete")
		}

		assert.Len(t, rq.orderedMIDMap, oldLimit+1)
		assert.Len(t, rq.orderedMID, oldLimit+1)
	})

	t.Run("unordered i-data has no descriptor limit by default", func(t *testing.T) {
		const oldLimit = 3
		rq := newReassemblyQueue(0, 0)

		for i := range oldLimit + 1 {
			complete, err := rq.pushWithError(&chunkPayloadData{
				iData:                  true,
				unordered:              true,
				messageIdentifier:      uint32(i), //nolint:gosec // bounded by oldLimit
				fragmentSequenceNumber: 0,
				beginningFragment:      true,
				tsn:                    uint32(i + 1), //nolint:gosec // bounded by oldLimit
				streamIdentifier:       0,
				payloadType:            PayloadTypeWebRTCBinary,
			})
			assert.NoError(t, err)
			assert.False(t, complete, "MID should remain incomplete")
		}

		assert.Len(t, rq.unorderedMIDMap, oldLimit+1)
		assert.Len(t, rq.unorderedMID, 0)
	})

	t.Run("ordered i-data rejects new mids after descriptor limit", func(t *testing.T) {
		const limit = 3
		rq := newReassemblyQueue(0, limit)

		for i := range limit {
			complete, err := rq.pushWithError(&chunkPayloadData{
				iData:                  true,
				messageIdentifier:      uint32(i), //nolint:gosec // bounded by limit
				fragmentSequenceNumber: 0,
				beginningFragment:      true,
				tsn:                    uint32(i + 1), //nolint:gosec // bounded by limit
				streamIdentifier:       0,
				payloadType:            PayloadTypeWebRTCBinary,
			})
			assert.NoError(t, err)
			assert.False(t, complete, "MID should remain incomplete")
		}

		complete, err := rq.pushWithError(&chunkPayloadData{
			iData:                  true,
			messageIdentifier:      0,
			fragmentSequenceNumber: 1,
			endingFragment:         true,
			tsn:                    limit + 1,
			streamIdentifier:       0,
			payloadType:            PayloadTypeWebRTCBinary,
		})
		assert.NoError(t, err, "existing MIDs should still accept fragments at the limit")
		assert.True(t, complete, "existing MID should complete")

		complete, err = rq.pushWithError(&chunkPayloadData{
			iData:                  true,
			messageIdentifier:      limit,
			fragmentSequenceNumber: 0,
			beginningFragment:      true,
			tsn:                    limit + 2,
			streamIdentifier:       0,
			payloadType:            PayloadTypeWebRTCBinary,
		})
		assert.ErrorIs(t, err, errReassemblyQueueMIDLimitExceeded)
		assert.False(t, complete, "new MID should be rejected")
		assert.Len(t, rq.orderedMIDMap, limit)
		assert.Len(t, rq.orderedMID, limit)
		assert.Equal(t, 0, rq.getNumBytes(), "zero-byte fragments must not hide descriptor growth")
	})

	t.Run("ordered i-data inserts new mids in order", func(t *testing.T) {
		rq := newReassemblyQueue(0, 0)

		for i, mid := range []uint32{3, 1, 2} {
			complete, err := rq.pushWithError(&chunkPayloadData{
				iData:                  true,
				messageIdentifier:      mid,
				fragmentSequenceNumber: 0,
				beginningFragment:      true,
				tsn:                    uint32(i + 1), //nolint:gosec // test values are small
				streamIdentifier:       0,
				payloadType:            PayloadTypeWebRTCBinary,
			})
			assert.NoError(t, err)
			assert.False(t, complete, "MID should remain incomplete")
		}

		assert.Len(t, rq.orderedMID, 3)
		assert.Equal(t, []uint32{1, 2, 3}, []uint32{
			rq.orderedMID[0].mid,
			rq.orderedMID[1].mid,
			rq.orderedMID[2].mid,
		})
	})

	t.Run("unordered i-data rejects new incomplete mids after descriptor limit", func(t *testing.T) {
		const limit = 3
		rq := newReassemblyQueue(0, limit)

		for i := range limit {
			complete, err := rq.pushWithError(&chunkPayloadData{
				iData:                  true,
				unordered:              true,
				messageIdentifier:      uint32(i), //nolint:gosec // bounded by limit
				fragmentSequenceNumber: 0,
				beginningFragment:      true,
				tsn:                    uint32(i + 1), //nolint:gosec // bounded by limit
				streamIdentifier:       0,
				payloadType:            PayloadTypeWebRTCBinary,
			})
			assert.NoError(t, err)
			assert.False(t, complete, "MID should remain incomplete")
		}

		complete, err := rq.pushWithError(&chunkPayloadData{
			iData:                  true,
			unordered:              true,
			messageIdentifier:      limit,
			fragmentSequenceNumber: 0,
			beginningFragment:      true,
			tsn:                    limit + 1,
			streamIdentifier:       0,
			payloadType:            PayloadTypeWebRTCBinary,
		})
		assert.ErrorIs(t, err, errReassemblyQueueMIDLimitExceeded)
		assert.False(t, complete, "new MID should be rejected")
		assert.Len(t, rq.unorderedMIDMap, limit)
		assert.Len(t, rq.unorderedMID, 0)
		assert.Equal(t, 0, rq.getNumBytes(), "zero-byte fragments must not hide descriptor growth")
	})

	t.Run("unordered i-data counts complete queued mids against descriptor limit", func(t *testing.T) {
		const limit = 3
		rq := newReassemblyQueue(0, limit)

		for i := range limit {
			complete, err := rq.pushWithError(&chunkPayloadData{
				iData:                  true,
				unordered:              true,
				messageIdentifier:      uint32(i), //nolint:gosec // bounded by limit
				fragmentSequenceNumber: 0,
				beginningFragment:      true,
				endingFragment:         true,
				tsn:                    uint32(i + 1), //nolint:gosec // bounded by limit
				streamIdentifier:       0,
				payloadType:            PayloadTypeWebRTCBinary,
			})
			assert.NoError(t, err)
			assert.True(t, complete, "MID should complete")
		}

		complete, err := rq.pushWithError(&chunkPayloadData{
			iData:                  true,
			unordered:              true,
			messageIdentifier:      limit,
			fragmentSequenceNumber: 0,
			beginningFragment:      true,
			endingFragment:         true,
			tsn:                    limit + 1,
			streamIdentifier:       0,
			payloadType:            PayloadTypeWebRTCBinary,
		})
		assert.ErrorIs(t, err, errReassemblyQueueMIDLimitExceeded)
		assert.False(t, complete, "new MID should be rejected")
		assert.Len(t, rq.unorderedMIDMap, 0)
		assert.Len(t, rq.unorderedMID, limit)
		assert.Equal(t, 0, rq.getNumBytes(), "zero-byte messages must not hide descriptor growth")
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
