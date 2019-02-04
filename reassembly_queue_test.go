package sctp

import (
	//"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReassemblyQueueOrderedFragmented(t *testing.T) {
	rq := newReassemblyQueue()

	orgPpi := PayloadTypeWebRTCBinary

	chunks := []*chunkPayloadData{
		&chunkPayloadData{
			payloadType:          orgPpi,
			beginingFragment:     true,
			tsn:                  1,
			streamSequenceNumber: 0,
			userData:             []byte("ABC"),
		},
		&chunkPayloadData{
			payloadType:          orgPpi,
			endingFragment:       true,
			tsn:                  2,
			streamSequenceNumber: 0,
			userData:             []byte("DEFG"),
		},
	}

	rq.push(chunks)

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

	chunks := []*chunkPayloadData{
		&chunkPayloadData{
			payloadType:          orgPpi,
			unordered:            true,
			beginingFragment:     true,
			tsn:                  1,
			streamSequenceNumber: 0,
			userData:             []byte("ABC"),
		},
		&chunkPayloadData{
			payloadType:          orgPpi,
			unordered:            true,
			tsn:                  2,
			streamSequenceNumber: 0,
			userData:             []byte("DEFG"),
		},
		&chunkPayloadData{
			payloadType:          orgPpi,
			unordered:            true,
			endingFragment:       true,
			tsn:                  3,
			streamSequenceNumber: 0,
			userData:             []byte("H"),
		},
	}

	rq.push(chunks)

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

	chunks := []*chunkPayloadData{
		&chunkPayloadData{
			payloadType:          orgPpi,
			beginingFragment:     true,
			endingFragment:       true,
			tsn:                  1,
			streamSequenceNumber: 0,
			userData:             []byte("ABC"),
		},
	}
	rq.push(chunks)

	chunks = []*chunkPayloadData{
		&chunkPayloadData{
			payloadType:          orgPpi,
			unordered:            true,
			beginingFragment:     true,
			endingFragment:       true,
			tsn:                  2,
			streamSequenceNumber: 1,
			userData:             []byte("DEF"),
		},
	}
	rq.push(chunks)

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
