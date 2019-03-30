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
}
