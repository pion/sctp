package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func makePayload(tsn uint32, nBytes int) *chunkPayloadData {
	return &chunkPayloadData{tsn: tsn, userData: make([]byte, nBytes)}
}

func TestPayloadQueue(t *testing.T) {
	t.Run("pushNoCheck", func(t *testing.T) {
		pq := newPayloadQueue()
		pq.pushNoCheck(makePayload(0, 10))
		assert.Equal(t, 10, pq.getNumBytes(), "total bytes mismatch")
		assert.Equal(t, 1, pq.size(), "item count mismatch")
		pq.pushNoCheck(makePayload(1, 11))
		assert.Equal(t, 21, pq.getNumBytes(), "total bytes mismatch")
		assert.Equal(t, 2, pq.size(), "item count mismatch")
		pq.pushNoCheck(makePayload(2, 12))
		assert.Equal(t, 33, pq.getNumBytes(), "total bytes mismatch")
		assert.Equal(t, 3, pq.size(), "item count mismatch")

		for i := uint32(0); i < 3; i++ {
			c, ok := pq.pop(i)
			assert.True(t, ok, "pop should succeed")
			if ok {
				assert.Equal(t, i, c.tsn, "TSN should match")
				assert.NotNil(t, pq.sorted, "should not be nil")
			}
		}

		assert.Equal(t, 0, pq.getNumBytes(), "total bytes mismatch")
		assert.Equal(t, 0, pq.size(), "item count mismatch")

		pq.pushNoCheck(makePayload(3, 13))
		assert.Nil(t, pq.sorted, "should be nil")
		assert.Equal(t, 13, pq.getNumBytes(), "total bytes mismatch")
		pq.pushNoCheck(makePayload(4, 14))
		assert.Nil(t, pq.sorted, "should be nil")
		assert.Equal(t, 27, pq.getNumBytes(), "total bytes mismatch")

		for i := uint32(3); i < 5; i++ {
			c, ok := pq.pop(i)
			assert.True(t, ok, "pop should succeed")
			if ok {
				assert.Equal(t, i, c.tsn, "TSN should match")
				assert.NotNil(t, pq.sorted, "should not be nil")
			}
		}

		assert.Equal(t, 0, pq.getNumBytes(), "total bytes mismatch")
		assert.Equal(t, 0, pq.size(), "item count mismatch")
	})

	t.Run("getGapAckBlocks", func(t *testing.T) {
		pq := newPayloadQueue()
		pq.push(makePayload(1, 0), 0)
		pq.push(makePayload(2, 0), 0)
		pq.push(makePayload(3, 0), 0)
		pq.push(makePayload(4, 0), 0)
		pq.push(makePayload(5, 0), 0)
		pq.push(makePayload(6, 0), 0)

		gab1 := []*gapAckBlock{{start: 1, end: 6}}
		gab2 := pq.getGapAckBlocks(0)
		assert.NotNil(t, gab2)
		assert.Len(t, gab2, 1)

		assert.Equal(t, gab1[0].start, gab2[0].start)
		assert.Equal(t, gab1[0].end, gab2[0].end)

		pq.push(makePayload(8, 0), 0)
		pq.push(makePayload(9, 0), 0)

		gab1 = []*gapAckBlock{{start: 1, end: 6}, {start: 8, end: 9}}
		gab2 = pq.getGapAckBlocks(0)
		assert.NotNil(t, gab2)
		assert.Len(t, gab2, 2)

		assert.Equal(t, gab1[0].start, gab2[0].start)
		assert.Equal(t, gab1[0].end, gab2[0].end)
		assert.Equal(t, gab1[1].start, gab2[1].start)
		assert.Equal(t, gab1[1].end, gab2[1].end)
	})

	t.Run("getLastTSNReceived", func(t *testing.T) {
		pq := newPayloadQueue()

		// empty queie should return false
		_, ok := pq.getLastTSNReceived()
		assert.False(t, ok, "should be false")

		ok = pq.push(makePayload(20, 0), 0)
		assert.True(t, ok, "should be true")
		tsn, ok := pq.getLastTSNReceived()
		assert.True(t, ok, "should be false")
		assert.Equal(t, uint32(20), tsn, "should match")

		// append should work
		ok = pq.push(makePayload(21, 0), 0)
		assert.True(t, ok, "should be true")
		tsn, ok = pq.getLastTSNReceived()
		assert.True(t, ok, "should be false")
		assert.Equal(t, uint32(21), tsn, "should match")

		// check if sorting applied
		ok = pq.push(makePayload(19, 0), 0)
		assert.True(t, ok, "should be true")
		tsn, ok = pq.getLastTSNReceived()
		assert.True(t, ok, "should be false")
		assert.Equal(t, uint32(21), tsn, "should match")
	})

	t.Run("markAllToRetrasmit", func(t *testing.T) {
		pq := newPayloadQueue()
		for i := 0; i < 3; i++ {
			pq.push(makePayload(uint32(i+1), 10), 0)
		}
		pq.markAsAcked(2)
		pq.markAllToRetrasmit()

		c, ok := pq.get(1)
		assert.True(t, ok, "should be true")
		assert.True(t, c.retransmit, "should be marked as retransmit")
		c, ok = pq.get(2)
		assert.True(t, ok, "should be true")
		assert.False(t, c.retransmit, "should NOT be marked as retransmit")
		c, ok = pq.get(3)
		assert.True(t, ok, "should be true")
		assert.True(t, c.retransmit, "should be marked as retransmit")
	})

	t.Run("reset retransmit flag on ack", func(t *testing.T) {
		pq := newPayloadQueue()
		for i := 0; i < 4; i++ {
			pq.push(makePayload(uint32(i+1), 10), 0)
		}

		pq.markAllToRetrasmit()
		pq.markAsAcked(2) // should cancel retransmission for TSN 2
		pq.markAsAcked(4) // should cancel retransmission for TSN 4

		c, ok := pq.get(1)
		assert.True(t, ok, "should be true")
		assert.True(t, c.retransmit, "should be marked as retransmit")
		c, ok = pq.get(2)
		assert.True(t, ok, "should be true")
		assert.False(t, c.retransmit, "should NOT be marked as retransmit")
		c, ok = pq.get(3)
		assert.True(t, ok, "should be true")
		assert.True(t, c.retransmit, "should be marked as retransmit")
		c, ok = pq.get(4)
		assert.True(t, ok, "should be true")
		assert.False(t, c.retransmit, "should NOT be marked as retransmit")
	})
}
