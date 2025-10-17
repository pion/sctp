// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

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
	var begin, end bool
	switch frag {
	case noFragment:
		begin = true
		end = true
	case fragBegin:
		begin = true
	case fragEnd:
		end = true
	}

	return &chunkPayloadData{
		tsn:               tsn,
		unordered:         unordered,
		beginningFragment: begin,
		endingFragment:    end,
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

	t.Run("out of bounds", func(t *testing.T) {
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

		chunkPayload := pq.peek()
		err := pq.pop(chunkPayload)
		assert.NoError(t, err, "should not error")
		assert.Equal(t, uint32(1), chunkPayload.tsn, "TSN should match")

		chunkPayload = pq.peek()
		err = pq.pop(chunkPayload)
		assert.NoError(t, err, "should not error")
		assert.Equal(t, uint32(3), chunkPayload.tsn, "TSN should match")

		chunkPayload = pq.peek()
		err = pq.pop(chunkPayload)
		assert.NoError(t, err, "should not error")
		assert.Equal(t, uint32(0), chunkPayload.tsn, "TSN should match")

		chunkPayload = pq.peek()
		err = pq.pop(chunkPayload)
		assert.NoError(t, err, "should not error")
		assert.Equal(t, uint32(2), chunkPayload.tsn, "TSN should match")

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

		chunkPayload := pq.peek()
		err := pq.pop(chunkPayload)
		assert.NoError(t, err, "should not error")
		assert.Equal(t, uint32(0), chunkPayload.tsn, "TSN should match")

		pq.push(makeDataChunk(1, true, noFragment))
		pq.push(makeDataChunk(2, false, fragMiddle))
		pq.push(makeDataChunk(3, false, fragEnd))

		expects := []uint32{2, 3, 1}

		for _, exp := range expects {
			chunkPayload = pq.peek()
			err = pq.pop(chunkPayload)
			assert.NoError(t, err, "should not error")
			assert.Equal(t, exp, chunkPayload.tsn, "TSN should match")
		}
	})
}

func TestPendingQueue_PopErrors(t *testing.T) {
	t.Run("ErrUnexpectedQState when not selected and not beginningFragment", func(t *testing.T) {
		pq := newPendingQueue()

		mid := makeDataChunk(100, false, fragMiddle)
		err := pq.pop(mid)
		assert.ErrorIs(t, err, ErrUnexpectedQState)
	})

	t.Run("ErrUnexpectedChunkPoppedUnordered (not selected path)", func(t *testing.T) {
		pq := newPendingQueue()

		u1 := makeDataChunk(1, true, noFragment)
		u2 := makeDataChunk(2, true, noFragment)
		pq.push(u1)
		pq.push(u2)

		err := pq.pop(u2)
		assert.ErrorIs(t, err, ErrUnexpectedChunkPoppedUnordered)
	})

	t.Run("ErrUnexpectedChunkPoppedOrdered (not selected path)", func(t *testing.T) {
		pq := newPendingQueue()

		o1 := makeDataChunk(10, false, noFragment)
		o2 := makeDataChunk(11, false, noFragment)
		pq.push(o1)
		pq.push(o2)

		err := pq.pop(o2)
		assert.ErrorIs(t, err, ErrUnexpectedChunkPoppedOrdered)
	})

	t.Run("ErrUnexpectedChunkPoppedUnordered (selected unordered path)", func(t *testing.T) {
		pq := newPendingQueue()

		uBegin := makeDataChunk(21, true, fragBegin)
		uMid := makeDataChunk(22, true, fragMiddle)
		uEnd := makeDataChunk(23, true, fragEnd)
		pq.push(uBegin)
		pq.push(uMid)
		pq.push(uEnd)

		err := pq.pop(uBegin)
		assert.NoError(t, err)

		err = pq.pop(uEnd)
		assert.ErrorIs(t, err, ErrUnexpectedChunkPoppedUnordered)
	})

	t.Run("ErrUnexpectedChunkPoppedOrdered (selected ordered path)", func(t *testing.T) {
		pq := newPendingQueue()

		oBegin := makeDataChunk(31, false, fragBegin)
		oMid := makeDataChunk(32, false, fragMiddle)
		oEnd := makeDataChunk(33, false, fragEnd)
		pq.push(oBegin)
		pq.push(oMid)
		pq.push(oEnd)

		err := pq.pop(oBegin)
		assert.NoError(t, err)

		err = pq.pop(oEnd)
		assert.ErrorIs(t, err, ErrUnexpectedChunkPoppedOrdered)
	})

	t.Run("nBytes guard clamps to zero when underflows", func(t *testing.T) {
		pq := newPendingQueue()

		c := makeDataChunk(40, false, noFragment)
		pq.push(c)

		pq.nBytes = 5

		peek := pq.peek()
		err := pq.pop(peek)
		assert.NoError(t, err)

		assert.Equal(t, 0, pq.getNumBytes())
	})
}
