// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"sync"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/stretchr/testify/assert"
)

func TestSessionBufferedAmount(t *testing.T) {
	t.Run("bufferedAmount", func(t *testing.T) {
		s := &Stream{
			lock: &sync.RWMutex{},
			log:  logging.NewDefaultLoggerFactory().NewLogger("sctp-test"),
		}

		assert.Equal(t, uint64(0), s.BufferedAmount())
		assert.Equal(t, uint64(0), s.BufferedAmountLowThreshold())

		s.bufferedAmount = 8192
		s.SetBufferedAmountLowThreshold(2048)
		assert.Equal(t, uint64(8192), s.BufferedAmount(), "unexpected bufferedAmount")
		assert.Equal(t, uint64(2048), s.BufferedAmountLowThreshold(), "unexpected threshold")
	})

	t.Run("OnBufferedAmountLow", func(t *testing.T) {
		stream := &Stream{
			lock: &sync.RWMutex{},
			log:  logging.NewDefaultLoggerFactory().NewLogger("sctp-test"),
		}

		stream.bufferedAmount = 4096
		stream.SetBufferedAmountLowThreshold(2048)

		nCbs := 0

		stream.OnBufferedAmountLow(func() {
			nCbs++
		})

		// Negative value should be ignored (by design)
		stream.onBufferReleased(-32) // bufferedAmount = 3072
		assert.Equal(t, uint64(4096), stream.BufferedAmount(), "unexpected bufferedAmount")
		assert.Equal(t, 0, nCbs, "callback count mismatch")

		// Above to above, no callback
		stream.onBufferReleased(1024) // bufferedAmount = 3072
		assert.Equal(t, uint64(3072), stream.BufferedAmount(), "unexpected bufferedAmount")
		assert.Equal(t, 0, nCbs, "callback count mismatch")

		// Above to equal, callback should be made
		stream.onBufferReleased(1024) // bufferedAmount = 2048
		assert.Equal(t, uint64(2048), stream.BufferedAmount(), "unexpected bufferedAmount")
		assert.Equal(t, 1, nCbs, "callback count mismatch")

		// Eaual to below, no callback
		stream.onBufferReleased(1024) // bufferedAmount = 1024
		assert.Equal(t, uint64(1024), stream.BufferedAmount(), "unexpected bufferedAmount")
		assert.Equal(t, 1, nCbs, "callback count mismatch")

		// Blow to below, no callback
		stream.onBufferReleased(1024) // bufferedAmount = 0
		assert.Equal(t, uint64(0), stream.BufferedAmount(), "unexpected bufferedAmount")
		assert.Equal(t, 1, nCbs, "callback count mismatch")

		// Capped at 0, no callback
		stream.onBufferReleased(1024) // bufferedAmount = 0
		assert.Equal(t, uint64(0), stream.BufferedAmount(), "unexpected bufferedAmount")
		assert.Equal(t, 1, nCbs, "callback count mismatch")
	})
}

func TestStreamWaitWithCopiedStream(t *testing.T) {
	stream := &Stream{lock: &sync.RWMutex{}}
	stream.readNotifier = sync.NewCond(stream.lock)

	streamCopy := *stream

	done := make(chan struct{})
	go func() {
		streamCopy.lock.Lock()
		streamCopy.readNotifier.Wait()
		streamCopy.lock.Unlock()
		close(done)
	}()

	time.Sleep(10 * time.Millisecond)

	stream.lock.Lock()
	stream.readNotifier.Signal()
	stream.lock.Unlock()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for readNotifier to unblock")
	}
}
