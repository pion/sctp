package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	noFragment = iota
	fragBegin
	fragMiddle
	fragEnd
)

func makeDataChunk(tsn uint32, unordered bool, frag int) *chunkPayloadData {
	var b, e bool
	switch frag {
	case noFragment:
		b = true
		e = true
	case fragBegin:
		b = true
	case fragEnd:
		e = true
	}
	return &chunkPayloadData{
		tsn:               tsn,
		unordered:         unordered,
		beginningFragment: b,
		endingFragment:    e,
		userData:          make([]byte, 10), // always 10 bytes
	}
}

func TestPendingBaseQueue(t *testing.T) {
	t.Run("push and pop", func(t *testing.T) {
		pq := newPendingBaseQueue()
		pq.push(makeDataChunk(0, false, noFragment))
		pq.push(makeDataChunk(1, false, noFragment))
		pq.push(makeDataChunk(2, false, noFragment))

		for i := uint32(0); i < 3; i++ {
			c := pq.get(int(i))
			assert.NotNil(t, c, "should not be nil")
			assert.Equal(t, i, c.tsn, "TSN should match")
		}

		for i := uint32(0); i < 3; i++ {
			c := pq.pop()
			assert.NotNil(t, c, "should not be nil")
			assert.Equal(t, i, c.tsn, "TSN should match")
		}

		pq.push(makeDataChunk(3, false, noFragment))
		pq.push(makeDataChunk(4, false, noFragment))

		for i := uint32(3); i < 5; i++ {
			c := pq.pop()
			assert.NotNil(t, c, "should not be nil")
			assert.Equal(t, i, c.tsn, "TSN should match")
		}
	})

	t.Run("out of bounce", func(t *testing.T) {
		pq := newPendingBaseQueue()
		assert.Nil(t, pq.pop(), "should be nil")
		assert.Nil(t, pq.get(0), "should be nil")

		pq.push(makeDataChunk(0, false, noFragment))
		assert.Nil(t, pq.get(-1), "should be nil")
		assert.Nil(t, pq.get(1), "should be nil")
	})
}

func TestPendingQueue(t *testing.T) {
	// NOTE: TSN is not used in pendingQueue in the actual usage.
	//       Following tests use TSN field as a chunk ID.

	t.Run("push and pop", func(t *testing.T) {
		pq := newPendingQueue()
		pq.push(makeDataChunk(0, false, noFragment))
		assert.Equal(t, 10, pq.getNumBytes(), "total bytes mismatch")
		pq.push(makeDataChunk(1, false, noFragment))
		assert.Equal(t, 20, pq.getNumBytes(), "total bytes mismatch")
		pq.push(makeDataChunk(2, false, noFragment))
		assert.Equal(t, 30, pq.getNumBytes(), "total bytes mismatch")

		for i := uint32(0); i < 3; i++ {
			c := pq.peek()
			err := pq.pop(c)
			assert.Nil(t, err, "should not error")
			assert.Equal(t, i, c.tsn, "TSN should match")
		}

		assert.Equal(t, 0, pq.getNumBytes(), "total bytes mismatch")

		pq.push(makeDataChunk(3, false, noFragment))
		assert.Equal(t, 10, pq.getNumBytes(), "total bytes mismatch")
		pq.push(makeDataChunk(4, false, noFragment))
		assert.Equal(t, 20, pq.getNumBytes(), "total bytes mismatch")

		for i := uint32(3); i < 5; i++ {
			c := pq.peek()
			err := pq.pop(c)
			assert.Nil(t, err, "should not error")
			assert.Equal(t, i, c.tsn, "TSN should match")
		}

		assert.Equal(t, 0, pq.getNumBytes(), "total bytes mismatch")
	})

	t.Run("unordered wins", func(t *testing.T) {
		pq := newPendingQueue()
		pq.push(makeDataChunk(0, false, noFragment))
		assert.Equal(t, 10, pq.getNumBytes(), "total bytes mismatch")
		pq.push(makeDataChunk(1, true, noFragment))
		assert.Equal(t, 20, pq.getNumBytes(), "total bytes mismatch")
		pq.push(makeDataChunk(2, false, noFragment))
		assert.Equal(t, 30, pq.getNumBytes(), "total bytes mismatch")
		pq.push(makeDataChunk(3, true, noFragment))
		assert.Equal(t, 40, pq.getNumBytes(), "total bytes mismatch")

		c := pq.peek()
		err := pq.pop(c)
		assert.NoError(t, err, "should not error")
		assert.Equal(t, uint32(1), c.tsn, "TSN should match")

		c = pq.peek()
		err = pq.pop(c)
		assert.NoError(t, err, "should not error")
		assert.Equal(t, uint32(3), c.tsn, "TSN should match")

		c = pq.peek()
		err = pq.pop(c)
		assert.NoError(t, err, "should not error")
		assert.Equal(t, uint32(0), c.tsn, "TSN should match")

		c = pq.peek()
		err = pq.pop(c)
		assert.NoError(t, err, "should not error")
		assert.Equal(t, uint32(2), c.tsn, "TSN should match")

		assert.Equal(t, 0, pq.getNumBytes(), "total bytes mismatch")
	})

	t.Run("fragments", func(t *testing.T) {
		pq := newPendingQueue()
		pq.push(makeDataChunk(0, false, fragBegin))
		pq.push(makeDataChunk(1, false, fragMiddle))
		pq.push(makeDataChunk(2, false, fragEnd))
		pq.push(makeDataChunk(3, true, fragBegin))
		pq.push(makeDataChunk(4, true, fragMiddle))
		pq.push(makeDataChunk(5, true, fragEnd))

		expects := []uint32{3, 4, 5, 0, 1, 2}

		for _, exp := range expects {
			c := pq.peek()
			err := pq.pop(c)
			assert.NoError(t, err, "should not error")
			assert.Equal(t, exp, c.tsn, "TSN should match")
		}
	})

	// Once decided ordered or unordered, the decision should persist until
	// it pops a chunk with endingFragment flags set to true.
	t.Run("selection persistence", func(t *testing.T) {
		pq := newPendingQueue()
		pq.push(makeDataChunk(0, false, fragBegin))

		c := pq.peek()
		err := pq.pop(c)
		assert.NoError(t, err, "should not error")
		assert.Equal(t, uint32(0), c.tsn, "TSN should match")

		pq.push(makeDataChunk(1, true, noFragment))
		pq.push(makeDataChunk(2, false, fragMiddle))
		pq.push(makeDataChunk(3, false, fragEnd))

		expects := []uint32{2, 3, 1}

		for _, exp := range expects {
			c = pq.peek()
			err = pq.pop(c)
			assert.NoError(t, err, "should not error")
			assert.Equal(t, exp, c.tsn, "TSN should match")
		}
	})
}
