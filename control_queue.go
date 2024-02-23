// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"sync"
)

// control queue

type controlQueue struct {
	mu    sync.RWMutex
	queue []*packet
}

func newControlQueue() *controlQueue {
	return &controlQueue{queue: []*packet{}}
}

func (q *controlQueue) push(c *packet) {
	q.mu.Lock()
	q.queue = append(q.queue, c)
	q.mu.Unlock()
}

func (q *controlQueue) pushAll(packets []*packet) {
	q.mu.Lock()
	q.queue = append(q.queue, packets...)
	q.mu.Unlock()
}

func (q *controlQueue) popAll() []*packet {
	q.mu.Lock()
	packets := q.queue
	q.queue = []*packet{}
	q.mu.Unlock()
	return packets
}

func (q *controlQueue) size() int {
	q.mu.RLock()
	size := len(q.queue)
	q.mu.RUnlock()
	return size
}
