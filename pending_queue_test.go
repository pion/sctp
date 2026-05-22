// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
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

func makeStreamDataChunk(tsn uint32, streamID uint16) *chunkPayloadData {
	chunk := makeDataChunk(tsn, false, 0)
	chunk.streamIdentifier = streamID

	return chunk
}

type lifoStreamScheduler struct {
	chunks     []StreamSchedulerChunk
	resetCount int
}

func (s *lifoStreamScheduler) Reset() {
	s.chunks = nil
	s.resetCount++
}

func (s *lifoStreamScheduler) Push(chunk StreamSchedulerChunk) {
	s.chunks = append(s.chunks, chunk)
}

func (s *lifoStreamScheduler) Peek() StreamSchedulerChunk {
	if len(s.chunks) == 0 {
		return nil
	}

	return s.chunks[len(s.chunks)-1]
}

func (s *lifoStreamScheduler) Pop(chunk StreamSchedulerChunk) error {
	if len(s.chunks) == 0 {
		return ErrUnexpectedQState
	}
	last := len(s.chunks) - 1
	if s.chunks[last] != chunk {
		return ErrUnexpectedChunkPoppedStream
	}
	s.chunks[last] = nil
	s.chunks = s.chunks[:last]

	return nil
}

func TestPendingBaseQueue(t *testing.T) {
	t.Run("push and pop", func(t *testing.T) {
		pq := newPendingBaseQueue()
		pq.push(makeDataChunk(0, false, noFragment))
		pq.push(makeDataChunk(1, false, noFragment))
		pq.push(makeDataChunk(2, false, noFragment))

		for i := range uint32(3) {
			c := pq.get(int(i))
			assert.NotNil(t, c, "should not be nil")
			assert.Equal(t, i, c.tsn, "TSN should match")
		}

		for i := range uint32(3) {
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
		pq := newPendingQueue(nil)
		pq.push(makeDataChunk(0, false, noFragment))
		assert.Equal(t, 10, pq.getNumBytes(), "total bytes mismatch")
		pq.push(makeDataChunk(1, false, noFragment))
		assert.Equal(t, 20, pq.getNumBytes(), "total bytes mismatch")
		pq.push(makeDataChunk(2, false, noFragment))
		assert.Equal(t, 30, pq.getNumBytes(), "total bytes mismatch")

		for i := range uint32(3) {
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
		pq := newPendingQueue(nil)
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
		pq := newPendingQueue(nil)
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
		pq := newPendingQueue(nil)
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

	t.Run("set interleaving rejects non-empty queue", func(t *testing.T) {
		pq := newPendingQueue(nil)
		pq.push(makeDataChunk(1, false, noFragment))

		err := pq.setInterleaving(true)
		assert.ErrorIs(t, err, ErrPendingQueueModeChangeNonEmpty)
		assert.False(t, pq.interleaving)

		chunkPayload := pq.peek()
		assert.NotNil(t, chunkPayload)
		assert.Equal(t, uint32(1), chunkPayload.tsn)
	})

	t.Run("set interleaving swaps policy when empty", func(t *testing.T) {
		pq := newPendingQueue(func() InterleavingStreamScheduler {
			return newWeightedFairQueueingPendingQueuePolicy(nil)
		})

		err := pq.setInterleaving(true)
		assert.NoError(t, err)
		assert.True(t, pq.interleaving)

		policy, ok := pq.policy.(*interleavingStreamSchedulerPolicy)
		assert.True(t, ok)
		_, ok = policy.scheduler.(*weightedFairQueueingPendingQueuePolicy)
		assert.True(t, ok)

		err = pq.setInterleaving(true)
		assert.NoError(t, err)

		err = pq.setInterleaving(false)
		assert.NoError(t, err)
		assert.False(t, pq.interleaving)

		_, ok = pq.policy.(*messagePendingQueuePolicy)
		assert.True(t, ok)
	})

	t.Run("set interleaving uses configured round robin scheduler", func(t *testing.T) {
		pq := newPendingQueue(func() InterleavingStreamScheduler {
			return newRoundRobinPendingQueuePolicy()
		})

		err := pq.setInterleaving(true)
		assert.NoError(t, err)

		policy, ok := pq.policy.(*interleavingStreamSchedulerPolicy)
		assert.True(t, ok)
		_, ok = policy.scheduler.(*roundRobinPendingQueuePolicy)
		assert.True(t, ok)
	})

	t.Run("set interleaving uses custom scheduler", func(t *testing.T) {
		scheduler := &lifoStreamScheduler{}
		pq := newPendingQueue(func() InterleavingStreamScheduler {
			return scheduler
		})

		err := pq.setInterleaving(true)
		assert.NoError(t, err)
		assert.Equal(t, 1, scheduler.resetCount)

		pq.push(makeStreamDataChunk(1, 1))
		pq.push(makeStreamDataChunk(2, 2))

		chunkPayload := pq.peek()
		assert.NotNil(t, chunkPayload)
		assert.Equal(t, uint32(2), chunkPayload.tsn)
		assert.NoError(t, pq.pop(chunkPayload))

		chunkPayload = pq.peek()
		assert.NotNil(t, chunkPayload)
		assert.Equal(t, uint32(1), chunkPayload.tsn)
		assert.NoError(t, pq.pop(chunkPayload))

		err = pq.setInterleaving(false)
		assert.NoError(t, err)
		assert.Equal(t, 2, scheduler.resetCount)
	})
}

func TestRoundRobinPendingQueuePolicy(t *testing.T) {
	t.Run("round robin across streams", func(t *testing.T) {
		pq := newRoundRobinPendingQueuePolicy()
		pq.Push(makeStreamDataChunk(1, 1))
		pq.Push(makeStreamDataChunk(2, 2))
		pq.Push(makeStreamDataChunk(3, 1))

		expects := []uint32{1, 2, 3}
		for _, exp := range expects {
			chunkPayload := pq.Peek()
			assert.NotNil(t, chunkPayload)
			assert.Equal(t, exp, chunkPayload.chunkPayloadData().tsn)

			err := pq.Pop(chunkPayload)
			assert.NoError(t, err)
		}

		assert.Nil(t, pq.Peek())
	})

	t.Run("peek keeps the selected stream until pop", func(t *testing.T) {
		pq := newRoundRobinPendingQueuePolicy()
		pq.Push(makeStreamDataChunk(10, 1))
		pq.Push(makeStreamDataChunk(20, 2))

		first := pq.Peek()
		second := pq.Peek()

		assert.Same(t, first, second)
		assert.Equal(t, uint16(1), pq.selectedStream)

		err := pq.Pop(first)
		assert.NoError(t, err)

		next := pq.Peek()
		assert.NotNil(t, next)
		assert.Equal(t, uint32(20), next.chunkPayloadData().tsn)
	})

	t.Run("pop errors", func(t *testing.T) {
		t.Run("requires selection", func(t *testing.T) {
			pq := newRoundRobinPendingQueuePolicy()
			err := pq.Pop(makeStreamDataChunk(30, 1))
			assert.ErrorIs(t, err, ErrUnexpectedQState)
		})

		t.Run("validates popped chunk", func(t *testing.T) {
			pq := newRoundRobinPendingQueuePolicy()
			first := makeStreamDataChunk(40, 1)
			second := makeStreamDataChunk(41, 1)
			pq.Push(first)
			pq.Push(second)

			assert.Same(t, first, pq.Peek())

			err := pq.Pop(second)
			assert.ErrorIs(t, err, ErrUnexpectedChunkPoppedStream)
		})
	})
}

func TestWeightedFairQueueingPendingQueuePolicy(t *testing.T) {
	t.Run("selects lowest virtual finish time", func(t *testing.T) {
		pq := newWeightedFairQueueingPendingQueuePolicy(nil)
		large1 := makeStreamDataChunk(1, 1)
		large1.userData = make([]byte, 100)
		large2 := makeStreamDataChunk(2, 1)
		large2.userData = make([]byte, 100)
		small := makeStreamDataChunk(3, 2)
		small.userData = make([]byte, 10)

		pq.Push(large1)
		pq.Push(large2)
		pq.Push(small)

		expects := []uint32{3, 1, 2}
		for _, exp := range expects {
			chunkPayload := pq.Peek()
			assert.NotNil(t, chunkPayload)
			assert.Equal(t, exp, chunkPayload.chunkPayloadData().tsn)

			err := pq.Pop(chunkPayload)
			assert.NoError(t, err)
		}

		assert.Nil(t, pq.Peek())
	})

	t.Run("applies stream weights", func(t *testing.T) {
		pq := newWeightedFairQueueingPendingQueuePolicy(map[uint16]uint16{1: 2})
		weighted := makeStreamDataChunk(1, 1)
		weighted.userData = make([]byte, 100)
		unweighted := makeStreamDataChunk(2, 2)
		unweighted.userData = make([]byte, 60)

		pq.Push(weighted)
		pq.Push(unweighted)

		chunkPayload := pq.Peek()
		assert.NotNil(t, chunkPayload)
		assert.Equal(t, uint32(1), chunkPayload.chunkPayloadData().tsn)
		assert.NoError(t, pq.Pop(chunkPayload))

		chunkPayload = pq.Peek()
		assert.NotNil(t, chunkPayload)
		assert.Equal(t, uint32(2), chunkPayload.chunkPayloadData().tsn)
		assert.NoError(t, pq.Pop(chunkPayload))
	})

	t.Run("pop errors", func(t *testing.T) {
		t.Run("requires selection", func(t *testing.T) {
			pq := newWeightedFairQueueingPendingQueuePolicy(nil)
			err := pq.Pop(makeStreamDataChunk(30, 1))
			assert.ErrorIs(t, err, ErrUnexpectedQState)
		})

		t.Run("validates popped chunk", func(t *testing.T) {
			pq := newWeightedFairQueueingPendingQueuePolicy(nil)
			first := makeStreamDataChunk(40, 1)
			second := makeStreamDataChunk(41, 1)
			pq.Push(first)
			pq.Push(second)

			assert.Same(t, first, pq.Peek())

			err := pq.Pop(second)
			assert.ErrorIs(t, err, ErrUnexpectedChunkPoppedStream)
		})
	})
}

func TestPendingQueue_PopErrors(t *testing.T) {
	t.Run("ErrUnexpectedQState when not selected and not beginningFragment", func(t *testing.T) {
		pq := newPendingQueue(nil)

		mid := makeDataChunk(100, false, fragMiddle)
		err := pq.pop(mid)
		assert.ErrorIs(t, err, ErrUnexpectedQState)
	})

	t.Run("ErrUnexpectedChunkPoppedUnordered (not selected path)", func(t *testing.T) {
		pq := newPendingQueue(nil)

		u1 := makeDataChunk(1, true, noFragment)
		u2 := makeDataChunk(2, true, noFragment)
		pq.push(u1)
		pq.push(u2)

		err := pq.pop(u2)
		assert.ErrorIs(t, err, ErrUnexpectedChunkPoppedUnordered)
	})

	t.Run("ErrUnexpectedChunkPoppedOrdered (not selected path)", func(t *testing.T) {
		pq := newPendingQueue(nil)

		o1 := makeDataChunk(10, false, noFragment)
		o2 := makeDataChunk(11, false, noFragment)
		pq.push(o1)
		pq.push(o2)

		err := pq.pop(o2)
		assert.ErrorIs(t, err, ErrUnexpectedChunkPoppedOrdered)
	})

	t.Run("ErrUnexpectedChunkPoppedUnordered (selected unordered path)", func(t *testing.T) {
		pq := newPendingQueue(nil)

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
		pq := newPendingQueue(nil)

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
		pq := newPendingQueue(nil)

		c := makeDataChunk(40, false, noFragment)
		pq.push(c)

		pq.nBytes = 5

		peek := pq.peek()
		err := pq.pop(peek)
		assert.NoError(t, err)

		assert.Equal(t, 0, pq.getNumBytes())
	})
}
