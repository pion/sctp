// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package sctp

import (
	"bytes"
	"io"
	"testing"
	"time"

	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/require"
)

func TestWithDiscardInboundAfterClose(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		assoc := createTestAssociationWithOptions(t, Config{}, WithDiscardInboundAfterClose(enabled))
		assoc.closeAllTimers()
		assoc.closeWriteLoopOnce.Do(func() { close(assoc.closeWriteLoopCh) })
		require.Equal(t, enabled, assoc.discardInboundAfterClose)
	}

	// The setting is kept, in both directions, when a Config built from
	// options is itself passed as an option.
	for _, enabled := range []bool{true, false} {
		var built Config
		require.NoError(t, WithDiscardInboundAfterClose(enabled).applyServer(&built))

		server, client := Config{discardInboundAfterClose: !enabled}, Config{discardInboundAfterClose: !enabled}
		require.NoError(t, built.applyServer(&server))
		require.NoError(t, built.applyClient(&client))
		require.Equal(t, enabled, server.discardInboundAfterClose)
		require.Equal(t, enabled, client.discardInboundAfterClose)
	}

	// A Config that never set the option leaves the destination alone.
	untouched := Config{discardInboundAfterClose: true}
	require.NoError(t, Config{}.applyServer(&untouched))
	require.True(t, untouched.discardInboundAfterClose)
}

// The SACK announcing the reopened window must not be downgraded to a delayed
// ack by the packet that is being processed while the stream is closed.
func TestStreamDiscardInboundKeepsImmediateAck(t *testing.T) {
	assoc := createTestAssociationWithOptions(t, Config{}, WithDiscardInboundAfterClose(true))
	t.Cleanup(func() {
		assoc.closeAllTimers()
		assoc.closeWriteLoopOnce.Do(func() { close(assoc.closeWriteLoopCh) })
	})
	assoc.setState(established)

	stream := assoc.createStream(1, false)
	require.NoError(t, stream.handleData(&chunkPayloadData{
		beginningFragment: true,
		endingFragment:    true,
		tsn:               1,
		streamIdentifier:  1,
		userData:          []byte("unread"),
	}))

	// The read loop is between chunks of an inbound packet that asked for a
	// delayed ack.
	assoc.handleChunksStart()
	assoc.lock.Lock()
	assoc.delayedAckTriggered = true
	assoc.lock.Unlock()

	require.NoError(t, stream.Close())
	assoc.handleChunksEnd()

	assoc.lock.RLock()
	defer assoc.lock.RUnlock()
	require.Equal(t, ackStateImmediate, assoc.ackState, "the reopened window was not announced immediately")
}

// Closing a stream after its association closed still drops the unread data
// but must not try to announce the reopened window.
func TestStreamDiscardInboundAfterAssociationClosed(t *testing.T) {
	assoc := createTestAssociationWithOptions(t, Config{}, WithDiscardInboundAfterClose(true))
	assoc.closeAllTimers()
	assoc.closeWriteLoopOnce.Do(func() { close(assoc.closeWriteLoopCh) })

	stream := assoc.createStream(1, false)
	require.NoError(t, stream.handleData(&chunkPayloadData{
		beginningFragment: true,
		endingFragment:    true,
		tsn:               1,
		streamIdentifier:  1,
		userData:          []byte("unread"),
	}))
	require.NotZero(t, stream.reassemblyQueue.getNumBytes())

	assoc.setState(closed)
	assoc.ackState = ackStateIdle
	require.ErrorIs(t, stream.Close(), ErrResetPacketInStateNotExist)
	require.Zero(t, stream.reassemblyQueue.getNumBytes(), "unread data was not discarded")
	require.Equal(t, ackStateIdle, assoc.ackState, "a closed association must not schedule a SACK")
}

// tickUntil forwards packets across br until cond holds.
func tickUntil(t *testing.T, br *test.Bridge, cond func() bool, msg string) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		require.True(t, time.Now().Before(deadline), msg)
		br.Tick()
		time.Sleep(time.Millisecond)
	}
}

func windowCredit(a *Association) uint32 {
	a.lock.RLock()
	defer a.lock.RUnlock()

	return a.getMyReceiverWindowCredit()
}

// TestAssocDiscardInboundAfterClose closes a stream without reading it while
// the peer keeps sending more than the receive buffer on it. By default the
// unread data holds the receive window until the peer resets its side, which
// it only does after sending everything, so the association stalls. With
// WithDiscardInboundAfterClose the data is dropped and other streams keep
// working.
func TestAssocDiscardInboundAfterClose(t *testing.T) {
	const maxReceiveBufferSize = 16 * 1024

	t.Run("closed stream does not hold the receive window", func(t *testing.T) {
		lim := test.TimeOut(15 * time.Second)
		defer lim.Stop()

		br := test.NewBridge()
		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, maxReceiveBufferSize)
		require.NoError(t, err)
		defer closeAssociationPair(br, a0, a1)
		a1.discardInboundAfterClose = true

		closed0, closed1, err := establishSessionPair(br, a0, a1, 1)
		require.NoError(t, err)
		other0, other1, err := establishSessionPair(br, a0, a1, 2)
		require.NoError(t, err)

		const msgSize = 8 * 1024
		msg := bytes.Repeat([]byte{'x'}, msgSize)
		for range 4 {
			_, err = closed0.WriteSCTP(msg, PayloadTypeWebRTCBinary)
			require.NoError(t, err)
		}
		tickUntil(t, br, func() bool { return windowCredit(a1) < msgSize },
			"receive window did not fill")

		require.NoError(t, closed1.Close())
		tickUntil(t, br, func() bool {
			a0.lock.RLock()
			defer a0.lock.RUnlock()

			return a0.pendingQueue.size() == 0 && a0.inflightQueue.size() == 0
		}, "data for the closed stream was not drained")
		tickUntil(t, br, func() bool { return windowCredit(a1) == maxReceiveBufferSize },
			"receive window did not reopen")

		_, err = other0.WriteSCTP([]byte("still alive"), PayloadTypeWebRTCBinary)
		require.NoError(t, err)
		flushBuffers(br, a0, a1)
		buf := make([]byte, 64)
		n, _, err := other1.ReadSCTP(buf)
		require.NoError(t, err)
		require.Equal(t, "still alive", string(buf[:n]))

		// Nothing is delivered on the closed stream, but the peer's reset
		// still ends it.
		readErr := make(chan error, 1)
		go func() {
			_, _, err := closed1.ReadSCTP(buf)
			readErr <- err
		}()
		require.NoError(t, closed0.Close())
		tickUntil(t, br, func() bool { return len(readErr) == 1 }, "read did not end after peer reset")
		require.ErrorIs(t, <-readErr, io.EOF)
	})

	t.Run("default keeps inbound data readable after close", func(t *testing.T) {
		lim := test.TimeOut(10 * time.Second)
		defer lim.Stop()

		br := test.NewBridge()
		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, maxReceiveBufferSize)
		require.NoError(t, err)
		defer closeAssociationPair(br, a0, a1)

		s0, s1, err := establishSessionPair(br, a0, a1, 1)
		require.NoError(t, err)

		_, err = s0.WriteSCTP([]byte("before close"), PayloadTypeWebRTCBinary)
		require.NoError(t, err)
		flushBuffers(br, a0, a1)
		require.NoError(t, s1.Close())
		_, err = s0.WriteSCTP([]byte("after close"), PayloadTypeWebRTCBinary)
		require.NoError(t, err)
		flushBuffers(br, a0, a1)

		buf := make([]byte, 64)
		for _, want := range []string{"before close", "after close"} {
			n, _, err := s1.ReadSCTP(buf)
			require.NoError(t, err)
			require.Equal(t, want, string(buf[:n]))
		}
	})
}
