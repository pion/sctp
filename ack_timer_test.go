//go:build go1.25

// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT
package sctp

import (
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type onAckTO func()

type testAckTimerObserver struct {
	onAckTO onAckTO
}

func (o *testAckTimerObserver) onAckTimeout() {
	o.onAckTO()
}

// isRunning tests if the timer is running.
func (t *ackTimer) isRunning() bool {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	return t.state == ackTimerStarted
}

func TestAckTimer(t *testing.T) {
	t.Run("start and close", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var nCbs uint32
			rt := newAckTimer(&testAckTimerObserver{
				onAckTO: func() {
					t.Log("ack timed out")
					atomic.AddUint32(&nCbs, 1)
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

				time.Sleep(ackInterval*2 + 50*time.Millisecond)
				synctest.Wait()

				assert.Equalf(t, uint32(1), atomic.LoadUint32(&nCbs),
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
	})

	t.Run("start and stop", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			var nCbs uint32
			rt := newAckTimer(&testAckTimerObserver{
				onAckTO: func() {
					t.Log("ack timed out")
					atomic.AddUint32(&nCbs, 1)
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
			time.Sleep(ackInterval + 50*time.Millisecond)
			synctest.Wait()
			assert.Equalf(t, uint32(0), atomic.LoadUint32(&nCbs),
				"should not be timed out (actual: %d)", atomic.LoadUint32(&nCbs))

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

func TestAssociationSACKDelay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		assoc := newTimerTestAssociation(t, Config{})
		assoc.handleChunksStart()
		assoc.lock.Lock()
		assoc.handleData(&chunkPayloadData{
			tsn: 1, beginningFragment: true, endingFragment: true,
			payloadType: PayloadTypeWebRTCBinary, userData: []byte("data"),
		})
		assoc.lock.Unlock()
		assoc.handleChunksEnd()

		time.Sleep(200*time.Millisecond - time.Nanosecond)
		synctest.Wait()
		packets, _ := assoc.gatherOutbound()
		require.Empty(t, packets, "SACK must not be sent before its deadline")
		time.Sleep(time.Nanosecond)
		synctest.Wait()
		packets, _ = assoc.gatherOutbound()
		require.Len(t, packets, 1)
		pkt := &packet{}
		require.NoError(t, pkt.unmarshal(false, packets[0]))
		require.Len(t, pkt.chunks, 1)
		sack, ok := pkt.chunks[0].(*chunkSelectiveAck)
		require.True(t, ok)
		assert.Equal(t, uint32(1), sack.cumulativeTSNAck)
		assert.Equal(t, uint64(1), assoc.stats.getNumAckTimeouts())
	})
}
