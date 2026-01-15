// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"math"
	"sync"
	"time"
)

const (
	// Default SACK delay per RFC 9260 (protocol parameter 'SACK.Delay').
	ackInterval time.Duration = 200 * time.Millisecond
	// Implementations MUST NOT allow SACK.Delay > 500ms (RFC 9260).
	ackMaxDelay time.Duration = 500 * time.Millisecond
)

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

// ackTimer provides the SACK.Delay according to RFC 9260 section 6.2.
type ackTimer struct {
	timer    *time.Timer
	observer ackTimerObserver

	mutex   sync.Mutex
	state   ackTimerState
	pending uint8

	// SACK delay clamped to (0, ackMaxDelay].
	interval time.Duration
}

// newAckTimer creates a new acknowledgement timer used to enable delayed ack.
// Default delay is 200ms (SACK.Delay). The maximum allowed by spec is 500ms.
func newAckTimer(observer ackTimerObserver) *ackTimer {
	t := &ackTimer{
		observer: observer,
		interval: ackInterval,
	}

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

// start starts the timer if not already running. Returns true if it started.
func (t *ackTimer) start() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	// this timer is already closed or already running
	if t.state != ackTimerStopped {
		return false
	}

	t.state = ackTimerStarted
	t.pending++

	// Clamp interval (0, ackMaxDelay].
	delay := t.interval
	if delay <= 0 {
		delay = ackInterval
	} else if delay > ackMaxDelay {
		delay = ackMaxDelay
	}

	t.timer.Reset(delay)

	return true
}

// stop stops the timer if running and keeps it reusable.
func (t *ackTimer) stop() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.state == ackTimerStarted {
		if t.timer.Stop() {
			if t.pending > 0 {
				t.pending--
			}
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
		if t.pending > 0 {
			t.pending--
		}
	}
	t.state = ackTimerClosed
}

// isRunning tests if the timer is running.
// Debug purpose only.
func (t *ackTimer) isRunning() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	return t.state == ackTimerStarted
}
