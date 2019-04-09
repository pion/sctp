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
				atomic.AddUint32(&nCbs, 1)
			},
		})

		// should start ok
		ok := rt.start()
		assert.True(t, ok, "start() should succeed")
		assert.True(t, rt.isRunning(), "should be running")

		// subsequent start is a noop
		ok = rt.start()
		assert.False(t, ok, "start() should NOT succeed once closed")
		assert.True(t, rt.isRunning(), "should be running")

		time.Sleep(250 * time.Millisecond)

		// should close ok
		rt.close()
		assert.False(t, rt.isRunning(), "should not be running")
		assert.Equal(t, uint32(1), atomic.LoadUint32(&nCbs),
			"should be called once (actual: %d)", atomic.LoadUint32(&nCbs))

		// once closed, it cannot start
		ok = rt.start()
		assert.False(t, ok, "start() should NOT succeed once closed")
		assert.False(t, rt.isRunning(), "should not be running")
	})

	t.Run("start and stop", func(t *testing.T) {
		rt := newAckTimer(&testAckTimerObserver{
			onAckTO: func() {},
		})

		// should start ok
		ok := rt.start()
		assert.True(t, ok, "start() should succeed")
		assert.True(t, rt.isRunning(), "should be running")

		// should stop ok
		rt.stop()
		assert.False(t, rt.isRunning(), "should not be running")

		// can start again
		ok = rt.start()
		assert.True(t, ok, "start() should succeed again")
		assert.True(t, rt.isRunning(), "should be running")

		// should close ok
		rt.close()
		assert.False(t, rt.isRunning(), "should not be running")
	})
}
