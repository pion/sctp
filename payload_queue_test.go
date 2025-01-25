// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

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
			}
		}

		assert.Equal(t, 0, pq.getNumBytes(), "total bytes mismatch")
		assert.Equal(t, 0, pq.size(), "item count mismatch")

		pq.pushNoCheck(makePayload(3, 13))
		assert.Equal(t, 13, pq.getNumBytes(), "total bytes mismatch")
		pq.pushNoCheck(makePayload(4, 14))
		assert.Equal(t, 27, pq.getNumBytes(), "total bytes mismatch")

		for i := uint32(3); i < 5; i++ {
			c, ok := pq.pop(i)
			assert.True(t, ok, "pop should succeed")
			if ok {
				assert.Equal(t, i, c.tsn, "TSN should match")
			}
		}

		assert.Equal(t, 0, pq.getNumBytes(), "total bytes mismatch")
		assert.Equal(t, 0, pq.size(), "item count mismatch")
	})

	t.Run("markAllToRetrasmit", func(t *testing.T) {
		pq := newPayloadQueue()
		for i := 0; i < 3; i++ {
			pq.pushNoCheck(makePayload(uint32(i+1), 10)) //nolint:gosec // G115
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
			pq.pushNoCheck(makePayload(uint32(i+1), 10)) //nolint:gosec // G115
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
