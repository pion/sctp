package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestQueue(t *testing.T) {
	q := newQueue[int](32)
	assert.Panics(t, func() { q.PopFront() })
	assert.Panics(t, func() { q.Front() })
	assert.Zero(t, q.Len())

	// test push & pop
	for i := 1; i < 33; i++ {
		q.PushBack(i)
	}
	assert.Equal(t, 32, q.Len())
	assert.Equal(t, 5, q.At(4))
	for i := 1; i < 33; i++ {
		assert.Equal(t, i, q.Front())
		assert.Equal(t, i, q.PopFront())
	}
	assert.Zero(t, q.Len())

	q.PushBack(10)
	q.PushBack(11)
	assert.Equal(t, 2, q.Len())
	assert.Equal(t, 11, q.At(1))
	assert.Equal(t, 10, q.Front())
	assert.Panics(t, func() {
		q.At(33)
	})
	assert.Equal(t, 10, q.PopFront())
	assert.Equal(t, 11, q.PopFront())

	// test grow capacity
	for i := 0; i < 64; i++ {
		q.PushBack(i)
	}
	assert.Equal(t, 64, q.Len())
	assert.Equal(t, 2, q.At(2))
	for i := 0; i < 64; i++ {
		assert.Equal(t, i, q.Front())
		assert.Equal(t, i, q.PopFront())
	}
}
