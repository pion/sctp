// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"runtime"
	"runtime/debug"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestQueue(t *testing.T) {
	queu := newQueue[int](32)
	assert.Zero(t, queu.Len())

	// test push & pop
	for i := 1; i < 33; i++ {
		queu.PushBack(i)
	}
	assert.Equal(t, 32, queu.Len())
	assert.Equal(t, 5, queu.At(4))
	for i := 1; i < 33; i++ {
		assert.Equal(t, i, queu.Front())
		assert.Equal(t, i, queu.PopFront())
	}
	assert.Zero(t, queu.Len())

	queu.PushBack(10)
	queu.PushBack(11)
	assert.Equal(t, 2, queu.Len())
	assert.Equal(t, 11, queu.At(1))
	assert.Equal(t, 10, queu.Front())
	assert.Equal(t, 10, queu.PopFront())
	assert.Equal(t, 11, queu.PopFront())

	// test grow capacity
	for i := 0; i < 64; i++ {
		queu.PushBack(i)
	}
	assert.Equal(t, 64, queu.Len())
	assert.Equal(t, 2, queu.At(2))
	for i := 0; i < 64; i++ {
		assert.Equal(t, i, queu.Front())
		assert.Equal(t, i, queu.PopFront())
	}
}

// waitForFinalizers spins until at least target have run or timeout hits.
func waitForFinalizers(got *int32, target int32, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		runtime.GC()

		if atomic.LoadInt32(got) >= target {
			return true
		}

		time.Sleep(10 * time.Millisecond)
	}

	return atomic.LoadInt32(got) >= target
}

func TestPendingBaseQueuePopReleasesReferences(t *testing.T) {
	// Make GC more aggressive for the duration of this test.
	prev := debug.SetGCPercent(10)
	defer debug.SetGCPercent(prev)

	bufSize := 256 << 10
	queue := newPendingBaseQueue()
	var finalized int32

	// add 64 chunks, each with a finalizer to count collection.
	for i := 0; i < 64; i++ {
		c := &chunkPayloadData{
			userData: make([]byte, bufSize),
		}

		// count when the chunk struct becomes unreachable.
		runtime.SetFinalizer(c, func(*chunkPayloadData) {
			atomic.AddInt32(&finalized, 1)
		})
		queue.push(c)
	}

	// pop 63 chunks so only 1 is left
	for i := 0; i < 63; i++ {
		queue.pop()
	}

	assert.Equal(t, queue.size(), 1)

	wantAtLeast := int32(64 - 4) // wait for GC scheduling
	ok := waitForFinalizers(&finalized, wantAtLeast, 3*time.Second)
	assert.True(t, ok)

	// Now pop the last element; queue should be empty.
	queue.pop()
	assert.Equal(t, queue.size(), 0)
}
