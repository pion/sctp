package sctp

import (
	//"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReassemblyQueue(t *testing.T) {
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

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			endingFragment:       true,
			tsn:                  2,
			streamSequenceNumber: 0,
			userData:             []byte("DEFG"),
		}

		complete = rq.push(chunk)
		assert.True(t, complete, "chunk set should be complete")

		buf := make([]byte, 16)

		n, ppi, err := rq.read(buf)
		assert.Nil(t, err, "read() should succeed")
		assert.Equal(t, 7, n, "should received 7 bytes")
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

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			unordered:            true,
			tsn:                  2,
			streamSequenceNumber: 0,
			userData:             []byte("DEFG"),
		}

		complete = rq.push(chunk)
		assert.False(t, complete, "chunk set should not be complete yet")

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

		buf := make([]byte, 16)

		n, ppi, err := rq.read(buf)
		assert.Nil(t, err, "read() should succeed")
		assert.Equal(t, 8, n, "should received 8 bytes")
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

		//
		// Now we have two complete chunks ready to read in the reassemblyQueue.
		//

		buf := make([]byte, 16)

		// Should read unordered chunks first
		n, ppi, err := rq.read(buf)
		assert.Nil(t, err, "read() should succeed")
		assert.Equal(t, 3, n, "should received 3 bytes")
		assert.Equal(t, ppi, orgPpi, "should have valid ppi")
		assert.Equal(t, string(buf[:n]), "DEF", "data should match")

		// Next should read ordered chunks
		n, ppi, err = rq.read(buf)
		assert.Nil(t, err, "read() should succeed")
		assert.Equal(t, 3, n, "should received 3 bytes")
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

		//
		// Now we have two complete chunks ready to read in the reassemblyQueue.
		//

		buf := make([]byte, 16)

		// Should pick the one that has "GOOD"
		n, ppi, err := rq.read(buf)
		assert.Nil(t, err, "read() should succeed")
		assert.Equal(t, 4, n, "should received 3 bytes")
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

		buf := make([]byte, 16)
		_, _, err := rq.read(buf)
		assert.NotNil(t, err, "read() should not succeed")
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

		buf := make([]byte, 16)
		_, _, err := rq.read(buf)
		assert.NotNil(t, err, "read() should not succeed")
	})

	t.Run("detect buffer too short", func(t *testing.T) {
		rq := newReassemblyQueue(0)

		orgPpi := PayloadTypeWebRTCBinary

		var chunk *chunkPayloadData
		var complete bool

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			beginningFragment:    true,
			endingFragment:       true,
			tsn:                  123,
			streamSequenceNumber: 0,
			userData:             []byte("0123456789"),
		}

		complete = rq.push(chunk)
		assert.True(t, complete, "the set should be complete")

		buf := make([]byte, 8) // <- passing buffer too short
		_, _, err := rq.read(buf)
		assert.Equal(t, io.ErrShortBuffer, err, "read() should not succeed")
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

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			beginningFragment:    true,
			tsn:                  11,
			streamSequenceNumber: ssnDropped,
			userData:             []byte("ABC"),
		}

		complete = rq.push(chunk)
		assert.False(t, complete, "chunk set should not be complete yet")

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			tsn:                  12,
			streamSequenceNumber: ssnDropped,
			userData:             []byte("DEF"),
		}

		complete = rq.push(chunk)
		assert.False(t, complete, "chunk set should not be complete yet")

		rq.forwardTSN(13, false, ssnDropped)

		assert.Equal(t, 1, len(rq.ordered), "there should be one chunk left")
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

		chunk = &chunkPayloadData{
			payloadType:          orgPpi,
			unordered:            true,
			tsn:                  12,
			streamSequenceNumber: ssnDropped,
			userData:             []byte("DEF"),
		}

		complete = rq.push(chunk)
		assert.False(t, complete, "chunk set should not be complete yet")

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

		// At this point, there are 3 chunks in the rq.unorderedChunks.
		// This call should remove chunks with tsn equals to 13 or older.
		rq.forwardTSN(13, true, ssnDropped)

		// As a result, there should be one chunk (tsn=14)
		assert.Equal(t, 1, len(rq.unorderedChunks), "there should be one chunk kept")
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
