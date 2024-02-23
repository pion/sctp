// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"errors"
	"sync"
	"sync/atomic"
)

// pendingBaseQueue

type pendingBaseQueue struct {
	mu    sync.RWMutex
	queue []*chunkPayloadData
}

func newPendingBaseQueue() *pendingBaseQueue {
	return &pendingBaseQueue{queue: []*chunkPayloadData{}}
}

func (q *pendingBaseQueue) push(c *chunkPayloadData) {
	q.mu.Lock()
	q.queue = append(q.queue, c)
	q.mu.Unlock()
}

func (q *pendingBaseQueue) pop() *chunkPayloadData {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.queue) == 0 {
		return nil
	}
	c := q.queue[0]
	q.queue = q.queue[1:]
	return c
}

func (q *pendingBaseQueue) get(i int) *chunkPayloadData {
	q.mu.RLock()
	defer q.mu.RUnlock()
	if len(q.queue) == 0 || i < 0 || i >= len(q.queue) {
		return nil
	}
	return q.queue[i]
}

func (q *pendingBaseQueue) size() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.queue)
}

// pendingQueue

type pendingQueue struct {
	unorderedQueue      *pendingBaseQueue
	orderedQueue        *pendingBaseQueue
	nBytes              uint64
	selected            bool
	unorderedIsSelected bool
}

// Pending queue errors
var (
	ErrUnexpectedChuckPoppedUnordered = errors.New("unexpected chunk popped (unordered)")
	ErrUnexpectedChuckPoppedOrdered   = errors.New("unexpected chunk popped (ordered)")
	ErrUnexpectedQState               = errors.New("unexpected q state (should've been selected)")
)

func newPendingQueue() *pendingQueue {
	return &pendingQueue{
		unorderedQueue: newPendingBaseQueue(),
		orderedQueue:   newPendingBaseQueue(),
	}
}

func (q *pendingQueue) push(c *chunkPayloadData) {
	if c.unordered {
		q.unorderedQueue.push(c)
	} else {
		q.orderedQueue.push(c)
	}
	atomic.AddUint64(&q.nBytes, uint64(len(c.userData)))
}

func (q *pendingQueue) peek() *chunkPayloadData {
	if q.selected {
		if q.unorderedIsSelected {
			return q.unorderedQueue.get(0)
		}
		return q.orderedQueue.get(0)
	}

	if c := q.unorderedQueue.get(0); c != nil {
		return c
	}
	return q.orderedQueue.get(0)
}

func (q *pendingQueue) pop(c *chunkPayloadData) error {
	if q.selected {
		var popped *chunkPayloadData
		if q.unorderedIsSelected {
			popped = q.unorderedQueue.pop()
			if popped != c {
				return ErrUnexpectedChuckPoppedUnordered
			}
		} else {
			popped = q.orderedQueue.pop()
			if popped != c {
				return ErrUnexpectedChuckPoppedOrdered
			}
		}
		if popped.endingFragment {
			q.selected = false
		}
	} else {
		if !c.beginningFragment {
			return ErrUnexpectedQState
		}
		if c.unordered {
			popped := q.unorderedQueue.pop()
			if popped != c {
				return ErrUnexpectedChuckPoppedUnordered
			}
			if !popped.endingFragment {
				q.selected = true
				q.unorderedIsSelected = true
			}
		} else {
			popped := q.orderedQueue.pop()
			if popped != c {
				return ErrUnexpectedChuckPoppedOrdered
			}
			if !popped.endingFragment {
				q.selected = true
				q.unorderedIsSelected = false
			}
		}
	}
	atomic.AddUint64(&q.nBytes, -uint64(len(c.userData)))
	return nil
}

func (q *pendingQueue) getNumBytes() int {
	return int(atomic.LoadUint64(&q.nBytes))
}

func (q *pendingQueue) size() int {
	return q.unorderedQueue.size() + q.orderedQueue.size()
}
