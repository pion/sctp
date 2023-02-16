package sctp

import (
	"container/list"
	"errors"
)

// pendingBaseQueue

type pendingBaseQueue struct {
	queue *list.List
}

func newPendingBaseQueue() *pendingBaseQueue {
	return &pendingBaseQueue{queue: list.New()}
}

func (q *pendingBaseQueue) push(c *chunkPayloadData) {
	q.queue.PushBack(c)
}

func (q *pendingBaseQueue) pop() *chunkPayloadData {
	c := q.queue.Front()
	q.queue.Remove(c)
	return c.Value.(*chunkPayloadData)
}

func (q *pendingBaseQueue) get(i int) *chunkPayloadData {
	if q.queue.Len() == 0 || i < 0 || i >= q.queue.Len() {
		return nil
	}
	c := q.queue.Front()
	for j := 0; j < i; j++ {
		c = c.Next()
	}
	return c.Value.(*chunkPayloadData)
}

func (q *pendingBaseQueue) size() int {
	return q.queue.Len()
}

// pendingQueue

type pendingQueue struct {
	unorderedQueue      *pendingBaseQueue
	orderedQueue        *pendingBaseQueue
	nBytes              int
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
	q.nBytes += len(c.userData)
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
	q.nBytes -= len(c.userData)
	return nil
}

func (q *pendingQueue) getNumBytes() int {
	return q.nBytes
}

func (q *pendingQueue) size() int {
	return q.unorderedQueue.size() + q.orderedQueue.size()
}
