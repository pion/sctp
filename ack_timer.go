package sctp

import (
	"sync"
	"time"
)

const (
	ackInterval float64 = 200 // msec
)

// ackTimerObserver is the inteface to an ack timer observer.
type ackTimerObserver interface {
	onAckTimeout()
}

// ackTimer provides the retnransmission timer conforms with RFC 4960 Sec 6.3.1
type ackTimer struct {
	observer ackTimerObserver
	interval float64
	stopFunc stopAckTimerLoop
	closed   bool
	mutex    sync.RWMutex
}

type stopAckTimerLoop func()

// newAckTimer creates a new acknowledgement timer used to enable delayed ack.
func newAckTimer(observer ackTimerObserver) *ackTimer {
	return &ackTimer{
		observer: observer,
		interval: ackInterval,
	}
}

// start starts the timer.
func (t *ackTimer) start() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	// this timer is already closed
	if t.closed {
		return false
	}

	// this is a noop if the timer is always running
	if t.stopFunc != nil {
		return false
	}

	cancelCh := make(chan struct{})

	go func() {
		closing := false

		for !closing {
			timer := time.NewTimer(time.Duration(t.interval) * time.Millisecond)

			select {
			case <-timer.C:
				t.observer.onAckTimeout()
			case <-cancelCh:
				closing = true
				timer.Stop()
			}
		}
	}()

	t.stopFunc = func() {
		close(cancelCh)
	}

	return true
}

// stops the timer. this is similar to stop() but subsequent start() call
// will fail (the timer is no longer usable)
func (t *ackTimer) stop() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.stopFunc != nil {
		t.stopFunc()
		t.stopFunc = nil
	}
}

// closes the timer. this is similar to stop() but subsequent start() call
// will fail (the timer is no longer usable)
func (t *ackTimer) close() {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if t.stopFunc != nil {
		t.stopFunc()
		t.stopFunc = nil
	}

	t.closed = true
}

// isRunning tests if the timer is running.
// Debug purpose only
func (t *ackTimer) isRunning() bool {
	t.mutex.RLock()
	defer t.mutex.RUnlock()

	return (t.stopFunc != nil)
}
