// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"errors"
	"math"
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

type pendingQueuePolicy interface {
	push(*chunkPayloadData)
	peek() *chunkPayloadData
	pop(*chunkPayloadData) error
}

type messagePendingQueuePolicy struct {
	unorderedQueue      *pendingBaseQueue
	orderedQueue        *pendingBaseQueue
	selected            bool
	unorderedIsSelected bool
}

func newMessagePendingQueuePolicy() *messagePendingQueuePolicy {
	return &messagePendingQueuePolicy{
		unorderedQueue: newPendingBaseQueue(),
		orderedQueue:   newPendingBaseQueue(),
	}
}

func (q *messagePendingQueuePolicy) push(chunk *chunkPayloadData) {
	if chunk.unordered {
		q.unorderedQueue.push(chunk)

		return
	}

	q.orderedQueue.push(chunk)
}

func (q *messagePendingQueuePolicy) peek() *chunkPayloadData {
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

func (q *messagePendingQueuePolicy) pop(chunkPayload *chunkPayloadData) error {
	if q.selected {
		return q.popSelected(chunkPayload)
	}
	if !chunkPayload.beginningFragment {
		return ErrUnexpectedQState
	}

	return q.popNewSelection(chunkPayload)
}

func (q *messagePendingQueuePolicy) popSelected(chunkPayload *chunkPayloadData) error {
	var (
		popped *chunkPayloadData
		err    error
	)

	if q.unorderedIsSelected {
		popped = q.unorderedQueue.pop()
		err = ErrUnexpectedChunkPoppedUnordered
	} else {
		popped = q.orderedQueue.pop()
		err = ErrUnexpectedChunkPoppedOrdered
	}
	if popped != chunkPayload {
		return err
	}
	if popped.endingFragment {
		q.selected = false
	}

	return nil
}

func (q *messagePendingQueuePolicy) popNewSelection(chunkPayload *chunkPayloadData) error {
	var (
		popped     *chunkPayloadData
		err        error
		isSelected bool
	)

	if chunkPayload.unordered {
		popped = q.unorderedQueue.pop()
		err = ErrUnexpectedChunkPoppedUnordered
		isSelected = true
	} else {
		popped = q.orderedQueue.pop()
		err = ErrUnexpectedChunkPoppedOrdered
	}
	if popped != chunkPayload {
		return err
	}
	if !popped.endingFragment {
		q.selected = true
		q.unorderedIsSelected = isSelected
	}

	return nil
}

type interleavingStreamSchedulerPolicy struct {
	scheduler InterleavingStreamScheduler
}

func (q *interleavingStreamSchedulerPolicy) push(chunk *chunkPayloadData) {
	q.scheduler.Push(chunk)
}

func (q *interleavingStreamSchedulerPolicy) peek() *chunkPayloadData {
	chunk := q.scheduler.Peek()
	if chunk == nil {
		return nil
	}

	return chunk.chunkPayloadData()
}

func (q *interleavingStreamSchedulerPolicy) pop(chunk *chunkPayloadData) error {
	return q.scheduler.Pop(chunk)
}

type roundRobinPendingQueuePolicy struct {
	streamQueues   map[uint16]*pendingBaseQueue
	streamOrder    []uint16
	streamSelected bool
	selectedStream uint16
}

func (q *roundRobinPendingQueuePolicy) Reset() {
	q.streamQueues = map[uint16]*pendingBaseQueue{}
	q.streamOrder = nil
	q.streamSelected = false
	q.selectedStream = 0
}

func newRoundRobinPendingQueuePolicy() *roundRobinPendingQueuePolicy {
	q := &roundRobinPendingQueuePolicy{}
	q.Reset()

	return q
}

func (q *roundRobinPendingQueuePolicy) Push(chunk StreamSchedulerChunk) {
	streamQueue := q.streamQueues[chunk.StreamIdentifier()]
	wasEmpty := streamQueue == nil || streamQueue.size() == 0
	if streamQueue == nil {
		streamQueue = newPendingBaseQueue()
		q.streamQueues[chunk.StreamIdentifier()] = streamQueue
	}
	streamQueue.push(chunk.chunkPayloadData())
	if wasEmpty {
		q.streamOrder = append(q.streamOrder, chunk.StreamIdentifier())
	}
}

func (q *roundRobinPendingQueuePolicy) Peek() StreamSchedulerChunk {
	if q.streamSelected {
		return q.streamQueues[q.selectedStream].get(0)
	}
	if len(q.streamOrder) == 0 {
		return nil
	}
	q.streamSelected = true
	q.selectedStream = q.streamOrder[0]

	return q.streamQueues[q.selectedStream].get(0)
}

func (q *roundRobinPendingQueuePolicy) Pop(chunkPayload StreamSchedulerChunk) error {
	if !q.streamSelected {
		return ErrUnexpectedQState
	}

	streamQueue := q.streamQueues[q.selectedStream]
	if streamQueue == nil {
		return ErrUnexpectedQState
	}

	popped := streamQueue.pop()
	if popped != chunkPayload.chunkPayloadData() {
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
	q.selectedStream = 0

	return nil
}

type weightedFairQueueingPendingQueuePolicy struct {
	streamQueues   map[uint16]*pendingBaseQueue
	streamFinish   map[uint16]float64
	chunkFinish    map[*chunkPayloadData]float64
	weights        map[uint16]uint16
	virtualTime    float64
	streamSelected bool
	selectedStream uint16
}

func (q *weightedFairQueueingPendingQueuePolicy) Reset() {
	q.streamQueues = map[uint16]*pendingBaseQueue{}
	q.streamFinish = map[uint16]float64{}
	q.chunkFinish = map[*chunkPayloadData]float64{}
	q.virtualTime = 0
	q.streamSelected = false
	q.selectedStream = 0
}

func newWeightedFairQueueingPendingQueuePolicy(weights map[uint16]uint16) *weightedFairQueueingPendingQueuePolicy {
	copiedWeights := map[uint16]uint16{}
	for streamID, weight := range weights {
		if weight != 0 {
			copiedWeights[streamID] = weight
		}
	}

	q := &weightedFairQueueingPendingQueuePolicy{
		weights: copiedWeights,
	}
	q.Reset()

	return q
}

func (q *weightedFairQueueingPendingQueuePolicy) Push(chunk StreamSchedulerChunk) {
	streamID := chunk.StreamIdentifier()
	streamQueue := q.streamQueues[streamID]
	if streamQueue == nil {
		streamQueue = newPendingBaseQueue()
		q.streamQueues[streamID] = streamQueue
	}

	weight := float64(q.weights[streamID])
	if weight == 0 {
		weight = 1
	}

	start := math.Max(q.virtualTime, q.streamFinish[streamID])
	finish := start + (float64(chunk.UserDataLen()) / weight)
	q.streamFinish[streamID] = finish
	q.chunkFinish[chunk.chunkPayloadData()] = finish
	streamQueue.push(chunk.chunkPayloadData())
}

func (q *weightedFairQueueingPendingQueuePolicy) Peek() StreamSchedulerChunk {
	if q.streamSelected {
		return q.streamQueues[q.selectedStream].get(0)
	}

	var (
		selectedChunk  *chunkPayloadData
		selectedStream uint16
		selectedFinish = math.Inf(1)
	)

	for streamID, streamQueue := range q.streamQueues {
		chunk := streamQueue.get(0)
		if chunk == nil {
			continue
		}
		finish := q.chunkFinish[chunk]
		if finish < selectedFinish || (finish == selectedFinish && streamID < selectedStream) {
			selectedChunk = chunk
			selectedStream = streamID
			selectedFinish = finish
		}
	}
	if selectedChunk == nil {
		return nil
	}

	q.streamSelected = true
	q.selectedStream = selectedStream

	return selectedChunk
}

func (q *weightedFairQueueingPendingQueuePolicy) Pop(chunkPayload StreamSchedulerChunk) error {
	if !q.streamSelected {
		return ErrUnexpectedQState
	}

	streamQueue := q.streamQueues[q.selectedStream]
	if streamQueue == nil {
		return ErrUnexpectedQState
	}

	popped := streamQueue.pop()
	if popped != chunkPayload.chunkPayloadData() {
		return ErrUnexpectedChunkPoppedStream
	}

	q.virtualTime = math.Max(q.virtualTime, q.chunkFinish[chunkPayload.chunkPayloadData()])
	delete(q.chunkFinish, chunkPayload.chunkPayloadData())
	if streamQueue.size() == 0 {
		delete(q.streamQueues, q.selectedStream)
	}

	q.streamSelected = false
	q.selectedStream = 0

	return nil
}

type pendingQueue struct {
	nBytes             int
	nChunks            int
	interleaving       bool
	newStreamScheduler InterleavingStreamSchedulerFactory
	policy             pendingQueuePolicy
}

// Pending queue errors.
var (
	ErrUnexpectedChunkPoppedUnordered = errors.New("unexpected chunk popped (unordered)")
	ErrUnexpectedChunkPoppedOrdered   = errors.New("unexpected chunk popped (ordered)")
	ErrUnexpectedChunkPoppedStream    = errors.New("unexpected chunk popped (stream)")
	ErrUnexpectedQState               = errors.New("unexpected q state (should've been selected)")
	ErrPendingQueueModeChangeNonEmpty = errors.New(
		"cannot change pending queue interleaving mode while queue is not empty",
	)

	// Deprecated: use ErrUnexpectedChunkPoppedUnordered.
	ErrUnexpectedChuckPoppedUnordered = ErrUnexpectedChunkPoppedUnordered
	// Deprecated: use ErrUnexpectedChunkPoppedOrdered.
	ErrUnexpectedChuckPoppedOrdered = ErrUnexpectedChunkPoppedOrdered
)

func newPendingQueue(newStreamScheduler InterleavingStreamSchedulerFactory) *pendingQueue {
	return &pendingQueue{
		newStreamScheduler: newStreamScheduler,
		policy:             newMessagePendingQueuePolicy(),
	}
}

func (q *pendingQueue) setInterleaving(enabled bool) error {
	if q.interleaving == enabled {
		return nil
	}
	if q.nChunks != 0 {
		return ErrPendingQueueModeChangeNonEmpty
	}

	q.interleaving = enabled
	if enabled {
		if q.newStreamScheduler == nil {
			return errNilStreamScheduler
		}
		streamScheduler := q.newStreamScheduler()
		if streamScheduler == nil {
			return errNilStreamScheduler
		}
		streamScheduler.Reset()
		q.policy = &interleavingStreamSchedulerPolicy{scheduler: streamScheduler}
	} else {
		if schedulerPolicy, ok := q.policy.(*interleavingStreamSchedulerPolicy); ok {
			schedulerPolicy.scheduler.Reset()
		}
		q.policy = newMessagePendingQueuePolicy()
	}

	return nil
}

func (q *pendingQueue) push(chunk *chunkPayloadData) {
	q.policy.push(chunk)
	q.nBytes += len(chunk.userData)
	q.nChunks++
}

func (q *pendingQueue) peek() *chunkPayloadData {
	return q.policy.peek()
}

func (q *pendingQueue) pop(chunkPayload *chunkPayloadData) error {
	if err := q.policy.pop(chunkPayload); err != nil {
		return err
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
