// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"errors"
)

// pendingBaseQueue

type pendingBaseQueue struct {
	queue []*chunkPayloadData
}

func newPendingBaseQueue() *pendingBaseQueue {
	return &pendingBaseQueue{queue: []*chunkPayloadData{}}
}

func (q *pendingBaseQueue) push(c *chunkPayloadData) {
	q.queue = append(q.queue, c)
}

func (q *pendingBaseQueue) pop() *chunkPayloadData {
	if len(q.queue) == 0 {
		return nil
	}

	c := q.queue[0]
	q.queue[0] = nil

	if len(q.queue) == 0 {
		q.queue = nil
	} else {
		q.queue = q.queue[1:]
	}

	return c
}

func (q *pendingBaseQueue) get(i int) *chunkPayloadData {
	if len(q.queue) == 0 || i < 0 || i >= len(q.queue) {
		return nil
	}

	return q.queue[i]
}

func (q *pendingBaseQueue) size() int {
	return len(q.queue)
}

// pendingQueue

type pendingQueue struct {
	unorderedQueue      *pendingBaseQueue
	orderedQueue        *pendingBaseQueue
	nBytes              int
	nChunks             int
	selected            bool
	unorderedIsSelected bool
	interleaving        bool
	streamQueues        map[uint16]*pendingBaseQueue
	streamOrder         []uint16
	streamSelected      bool
	selectedStream      uint16
}

// Pending queue errors.
var (
	ErrUnexpectedChunkPoppedUnordered = errors.New("unexpected chunk popped (unordered)")
	ErrUnexpectedChunkPoppedOrdered   = errors.New("unexpected chunk popped (ordered)")
	ErrUnexpectedChunkPoppedStream    = errors.New("unexpected chunk popped (stream)")
	ErrUnexpectedQState               = errors.New("unexpected q state (should've been selected)")

	// Deprecated: use ErrUnexpectedChunkPoppedUnordered.
	ErrUnexpectedChuckPoppedUnordered = ErrUnexpectedChunkPoppedUnordered
	// Deprecated: use ErrUnexpectedChunkPoppedOrdered.
	ErrUnexpectedChuckPoppedOrdered = ErrUnexpectedChunkPoppedOrdered
)

func newPendingQueue() *pendingQueue {
	return &pendingQueue{
		unorderedQueue: newPendingBaseQueue(),
		orderedQueue:   newPendingBaseQueue(),
	}
}

func (q *pendingQueue) setInterleaving(enabled bool) {
	if q.interleaving == enabled {
		return
	}
	q.interleaving = enabled
	q.selected = false
	q.unorderedIsSelected = false
	q.streamSelected = false
	q.selectedStream = 0
	if enabled && q.streamQueues == nil {
		q.streamQueues = map[uint16]*pendingBaseQueue{}
	}
	if enabled {
		q.streamOrder = nil
	}
	if !enabled {
		q.streamQueues = nil
		q.streamOrder = nil
	}
}

func (q *pendingQueue) push(chunk *chunkPayloadData) {
	if q.interleaving {
		if q.streamQueues == nil {
			q.streamQueues = map[uint16]*pendingBaseQueue{}
		}
		streamQueue := q.streamQueues[chunk.streamIdentifier]
		wasEmpty := streamQueue == nil || streamQueue.size() == 0
		if streamQueue == nil {
			streamQueue = newPendingBaseQueue()
			q.streamQueues[chunk.streamIdentifier] = streamQueue
		}
		streamQueue.push(chunk)
		if wasEmpty {
			q.streamOrder = append(q.streamOrder, chunk.streamIdentifier)
		}
		q.nBytes += len(chunk.userData)
		q.nChunks++

		return
	}

	if chunk.unordered {
		q.unorderedQueue.push(chunk)
	} else {
		q.orderedQueue.push(chunk)
	}
	q.nBytes += len(chunk.userData)
	q.nChunks++
}

func (q *pendingQueue) peek() *chunkPayloadData {
	if q.interleaving { //nolint:nestif
		if q.streamSelected {
			if q.streamQueues == nil {
				return nil
			}

			return q.streamQueues[q.selectedStream].get(0)
		}
		if len(q.streamOrder) == 0 {
			return nil
		}
		q.streamSelected = true
		q.selectedStream = q.streamOrder[0]
		if q.streamQueues == nil {
			return nil
		}

		return q.streamQueues[q.selectedStream].get(0)
	}

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

func (q *pendingQueue) pop(chunkPayload *chunkPayloadData) error { //nolint:cyclop,gocognit
	if q.interleaving { //nolint:nestif
		if !q.streamSelected {
			return ErrUnexpectedQState
		}
		if q.streamQueues == nil {
			return ErrUnexpectedQState
		}
		streamQueue := q.streamQueues[q.selectedStream]
		if streamQueue == nil {
			return ErrUnexpectedQState
		}
		popped := streamQueue.pop()
		if popped != chunkPayload {
			return ErrUnexpectedChunkPoppedStream
		}
		if len(q.streamOrder) > 0 {
			q.streamOrder = q.streamOrder[1:]
		}
		if streamQueue.size() > 0 {
			q.streamOrder = append(q.streamOrder, q.selectedStream)
		} else {
			delete(q.streamQueues, q.selectedStream)
		}
		q.streamSelected = false
		q.nBytes -= len(chunkPayload.userData)
		q.nChunks--

		return nil
	}

	if q.selected { //nolint:nestif
		var popped *chunkPayloadData
		if q.unorderedIsSelected {
			popped = q.unorderedQueue.pop()
			if popped != chunkPayload {
				return ErrUnexpectedChunkPoppedUnordered
			}
		} else {
			popped = q.orderedQueue.pop()
			if popped != chunkPayload {
				return ErrUnexpectedChunkPoppedOrdered
			}
		}
		if popped.endingFragment {
			q.selected = false
		}
	} else {
		if !chunkPayload.beginningFragment {
			return ErrUnexpectedQState
		}
		if chunkPayload.unordered {
			popped := q.unorderedQueue.pop()
			if popped != chunkPayload {
				return ErrUnexpectedChunkPoppedUnordered
			}
			if !popped.endingFragment {
				q.selected = true
				q.unorderedIsSelected = true
			}
		} else {
			popped := q.orderedQueue.pop()
			if popped != chunkPayload {
				return ErrUnexpectedChunkPoppedOrdered
			}
			if !popped.endingFragment {
				q.selected = true
				q.unorderedIsSelected = false
			}
		}
	}

	// guard against negative values (should never happen, but just in case).
	q.nBytes -= len(chunkPayload.userData)
	if q.nBytes < 0 {
		q.nBytes = 0
	}
	q.nChunks--

	return nil
}

func (q *pendingQueue) getNumBytes() int {
	return q.nBytes
}

func (q *pendingQueue) size() int {
	return q.nChunks
}
