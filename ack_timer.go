// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"math"
	"sync"
	"time"
)

// RFC 9260 sections 6.2 and 16: SACK.Delay defaults to 200 ms and must not exceed 500 ms.
const ackInterval time.Duration = 200 * time.Millisecond

// ackTimerObserver is the interface to an ack timer observer.
type ackTimerObserver interface {
	onAckTimeout()
}

type ackTimerState uint8

const (
	ackTimerStopped ackTimerState = iota
	ackTimerStarted
	ackTimerClosed
)

// ackTimer implements delayed acknowledgements according to RFC 9260 section 6.2.
type ackTimer struct {
	timer    *time.Timer
	observer ackTimerObserver
	mutex    sync.Mutex
	state    ackTimerState
	pending  uint8
}

// newAckTimer creates a new acknowledgement timer used to enable delayed ack.
func newAckTimer(observer ackTimerObserver) *ackTimer {
	t := &ackTimer{observer: observer}
	t.timer = time.AfterFunc(math.MaxInt64, t.timeout)
	t.timer.Stop()

	return t
}

func (t *ackTimer) timeout() {
	t.mutex.Lock()
	if t.pending--; t.pending == 0 && t.state == ackTimerStarted {
		t.state = ackTimerStopped
		defer t.observer.onAckTimeout()
	}
	t.mutex.Unlock()
}

// start starts the timer.
func (t *ackTimer) start() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	// this timer is already closed or already running
	if t.state != ackTimerStopped {
		return false
	}

	t.state = ackTimerStarted
	t.pending++
	t.timer.Reset(ackInterval)

	return true
}

// stop stops the timer and keeps it reusable.
func (t *ackTimer) stop() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.state == ackTimerStarted {
		if t.timer.Stop() {
			t.pending--
		}
		t.state = ackTimerStopped
	}
}

// closes the timer. this is similar to stop() but subsequent start() call
// will fail (the timer is no longer usable).
func (t *ackTimer) close() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.state == ackTimerStarted && t.timer.Stop() {
		t.pending--
	}
	t.state = ackTimerClosed
}
