package sctp

import (
	//"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReassemblyQueueOrderedFragmented(t *testing.T) {
	rq := newReassemblyQueue()

	orgPpi := PayloadTypeWebRTCBinary

	var chunk *chunkPayloadData
	var complete bool

	chunk = &chunkPayloadData{
		payloadType:          orgPpi,
		beginingFragment:     true,
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
	assert.True(t, complete, "chunk set should now be complete")

	buf := make([]byte, 16)

	n, ppi, err := rq.read(buf)
	assert.Nil(t, err, "read() should succeed")
	assert.Equal(t, 7, n, "should received 7 bytes")
	assert.Equal(t, ppi, orgPpi, "should have valid ppi")
	assert.Equal(t, string(buf[:n]), "ABCDEFG", "data should match")
}

func TestReassemblyQueueReorderedFragmented(t *testing.T) {
	rq := newReassemblyQueue()

	orgPpi := PayloadTypeWebRTCBinary

	var chunk *chunkPayloadData
	var complete bool

	chunk = &chunkPayloadData{
		payloadType:          orgPpi,
		unordered:            true,
		beginingFragment:     true,
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
	assert.True(t, complete, "chunk set should now be complete")

	buf := make([]byte, 16)

	n, ppi, err := rq.read(buf)
	assert.Nil(t, err, "read() should succeed")
	assert.Equal(t, 8, n, "should received 8 bytes")
	assert.Equal(t, ppi, orgPpi, "should have valid ppi")
	assert.Equal(t, string(buf[:n]), "ABCDEFGH", "data should match")
}

func TestReassemblyQueueOrderedUnorderedInMix(t *testing.T) {
	rq := newReassemblyQueue()

	orgPpi := PayloadTypeWebRTCBinary

	var chunk *chunkPayloadData
	var complete bool

	chunk = &chunkPayloadData{
		payloadType:          orgPpi,
		beginingFragment:     true,
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
		beginingFragment:     true,
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
}

func TestReassemblyQueueUnorderedIncomplete(t *testing.T) {
	rq := newReassemblyQueue()

	orgPpi := PayloadTypeWebRTCBinary

	var chunk *chunkPayloadData
	var complete bool

	chunk = &chunkPayloadData{
		payloadType:          orgPpi,
		unordered:            true,
		beginingFragment:     true,
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
		beginingFragment:     true,
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
}

func TestChunkSet(t *testing.T) {
	t.Run("Empty chunkSet", func(t *testing.T) {
		cset := newChunkSet(0, 0)
		assert.False(t, cset.isComplete(), "empty chunkSet cannot be complete")
	})

	t.Run("Push dup chunks to chunkSet", func(t *testing.T) {
		cset := newChunkSet(0, 0)
		cset.push(&chunkPayloadData{
			tsn:              100,
			beginingFragment: true,
		})
		complete := cset.push(&chunkPayloadData{
			tsn:            100,
			endingFragment: true,
		})
		assert.False(t, complete, "chunk with dup TSN is not complete")
		nChunks := len(cset.chunks)
		assert.Equal(t, 1, nChunks, "chunk with dup TSN should be ignored")
	})

	t.Run("Incomplete chunkSet: no begining", func(t *testing.T) {
		cset := &chunkSet{
			ssn:    0,
			ppi:    0,
			chunks: []*chunkPayloadData{&chunkPayloadData{}},
		}
		assert.False(t, cset.isComplete(),
			"chunkSet not starting with B=1 cannot be complete")
	})

	t.Run("Incomplete chunkSet: no contiguous tsn", func(t *testing.T) {
		cset := &chunkSet{
			ssn: 0,
			ppi: 0,
			chunks: []*chunkPayloadData{
				&chunkPayloadData{
					tsn:              100,
					beginingFragment: true,
				},
				&chunkPayloadData{
					tsn: 101,
				},
				&chunkPayloadData{
					tsn:            103,
					endingFragment: true,
				},
			},
		}
		assert.False(t, cset.isComplete(),
			"chunkSet not starting with incontiguous tsn cannot be complete")
	})
}
