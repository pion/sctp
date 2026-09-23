//go:build go1.25

// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT
package sctp

import (
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
)

type onAckTO func()

type testAckTimerObserver struct {
	onAckTO onAckTO
}

func (o *testAckTimerObserver) onAckTimeout() {
	o.onAckTO()
}

func TestAckTimer(t *testing.T) {
	t.Run("start and close", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			timedOut := make(chan struct{}, 1)
			rt := newAckTimer(&testAckTimerObserver{
				onAckTO: func() {
					t.Log("ack timed out")
					timedOut <- struct{}{}
				},
			})

			for range 2 {
				// should start ok
				ok := rt.start()
				assert.True(t, ok, "start() should succeed")
				assert.True(t, rt.isRunning(), "should be running")

				// subsequent start is a noop
				ok = rt.start()
				assert.False(t, ok, "start() should NOT succeed once closed")
				assert.True(t, rt.isRunning(), "should be running")

				select {
				case <-timedOut:
				case <-time.After(ackInterval * 2):
					assert.Fail(t, "should be called once")
				}

				select {
				case <-timedOut:
					assert.Fail(t, "should be called once")
				case <-time.After(ackInterval * 2):
				}
			}

			// should close ok
			rt.close()
			assert.False(t, rt.isRunning(), "should not be running")

			// once closed, it cannot start
			ok := rt.start()
			assert.False(t, ok, "start() should NOT succeed once closed")
			assert.False(t, rt.isRunning(), "should not be running")
		})
	})

	t.Run("start and stop", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			timedOut := make(chan struct{}, 1)
			rt := newAckTimer(&testAckTimerObserver{
				onAckTO: func() {
					t.Log("ack timed out")
					timedOut <- struct{}{}
				},
			})

			for range 2 {
				// should start ok
				ok := rt.start()
				assert.True(t, ok, "start() should succeed")
				assert.True(t, rt.isRunning(), "should be running")

				// stop immedidately
				rt.stop()
				assert.False(t, rt.isRunning(), "should not be running")
			}
			select {
			case <-timedOut:
				assert.Fail(t, "shoud not be timed out")
			case <-time.After(ackInterval + 50*time.Millisecond):
			}

			// can start again
			ok := rt.start()
			assert.True(t, ok, "start() should succeed again")
			assert.True(t, rt.isRunning(), "should be running")

			// should close ok
			rt.close()
			assert.False(t, rt.isRunning(), "should not be running")
		})
	})
}
