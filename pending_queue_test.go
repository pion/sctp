package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// makePayload() is defined in payload_queue_test.go

func TestPendingBaseQueue(t *testing.T) {
	t.Run("push and pop", func(t *testing.T) {
		pq := newPendingBaseQueue()
		pq.push(makePayload(0, 10))
		pq.push(makePayload(1, 11))
		pq.push(makePayload(2, 12))

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

		pq.push(makePayload(3, 13))
		pq.push(makePayload(4, 14))

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

		pq.push(makePayload(0, 10))
		assert.Nil(t, pq.get(-1), "should be nil")
		assert.Nil(t, pq.get(1), "should be nil")
	})
}

func TestPendingQueue(t *testing.T) {
	t.Run("push and pop", func(t *testing.T) {
		pq := newPendingQueue()
		pq.push(makePayload(0, 10))
		assert.Equal(t, 10, pq.getNumBytes(), "total bytes mismatch")
		pq.push(makePayload(1, 11))
		assert.Equal(t, 21, pq.getNumBytes(), "total bytes mismatch")
		pq.push(makePayload(2, 12))
		assert.Equal(t, 33, pq.getNumBytes(), "total bytes mismatch")

		for i := uint32(0); i < 3; i++ {
			c := pq.peek()
			err := pq.pop(c)
			assert.Nil(t, err, "should not error")
			assert.Equal(t, i, c.tsn, "TSN should match")
		}

		assert.Equal(t, 0, pq.getNumBytes(), "total bytes mismatch")

		pq.push(makePayload(3, 13))
		assert.Equal(t, 13, pq.getNumBytes(), "total bytes mismatch")
		pq.push(makePayload(4, 14))
		assert.Equal(t, 27, pq.getNumBytes(), "total bytes mismatch")

		for i := uint32(3); i < 5; i++ {
			c := pq.peek()
			err := pq.pop(c)
			assert.Nil(t, err, "should not error")
			assert.Equal(t, i, c.tsn, "TSN should match")
		}

		assert.Equal(t, 0, pq.getNumBytes(), "total bytes mismatch")
	})
}
