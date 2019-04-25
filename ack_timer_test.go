package sctp

import (
	"sync/atomic"
	"testing"
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
		var nCbs uint32
		rt := newAckTimer(&testAckTimerObserver{
			onAckTO: func() {
				t.Log("ack timed out")
				atomic.AddUint32(&nCbs, 1)
			},
		})

		for i := 0; i < 2; i++ {
			// should start ok
			ok := rt.start()
			assert.True(t, ok, "start() should succeed")
			assert.True(t, rt.isRunning(), "should be running")

			// subsequent start is a noop
			ok = rt.start()
			assert.False(t, ok, "start() should NOT succeed once closed")
			assert.True(t, rt.isRunning(), "should be running")

			// Sleep more than 2 * 200msec interval to test if it times out only once
			time.Sleep(ackInterval*2 + 50*time.Millisecond)

			assert.Equal(t, uint32(1), atomic.LoadUint32(&nCbs),
				"should be called once (actual: %d)", atomic.LoadUint32(&nCbs))

			atomic.StoreUint32(&nCbs, 0)
		}

		// should close ok
		rt.close()
		assert.False(t, rt.isRunning(), "should not be running")

		// once closed, it cannot start
		ok := rt.start()
		assert.False(t, ok, "start() should NOT succeed once closed")
		assert.False(t, rt.isRunning(), "should not be running")
	})

	t.Run("start and stop", func(t *testing.T) {
		var nCbs uint32
		rt := newAckTimer(&testAckTimerObserver{
			onAckTO: func() {
				t.Log("ack timed out")
				atomic.AddUint32(&nCbs, 1)
			},
		})

		// should start ok
		ok := rt.start()
		assert.True(t, ok, "start() should succeed")
		assert.True(t, rt.isRunning(), "should be running")

		// stop immedidately
		rt.stop()
		assert.False(t, rt.isRunning(), "should not be running")

		// Sleep more than 200msec of interval to test if it never times out
		time.Sleep(ackInterval + 50*time.Millisecond)

		assert.Equal(t, uint32(0), atomic.LoadUint32(&nCbs),
			"should not be timed out (actual: %d)", atomic.LoadUint32(&nCbs))

		// can start again
		ok = rt.start()
		assert.True(t, ok, "start() should succeed again")
		assert.True(t, rt.isRunning(), "should be running")

		// should close ok
		rt.close()
		assert.False(t, rt.isRunning(), "should not be running")
	})
}
