// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package sctp

import (
	"testing"
	"time"

	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/require"
)

func resetResponseResult(t *testing.T, pkt *packet) reconfigResult {
	t.Helper()
	require.NotNil(t, pkt)
	require.Len(t, pkt.chunks, 1)
	reconfig, ok := pkt.chunks[0].(*chunkReconfig)
	require.True(t, ok)
	response, ok := reconfig.paramA.(*paramReconfigResponse)
	require.True(t, ok)

	return response.result
}

type streamResetEvent struct {
	id      uint16
	present bool
}

func waitForResetEvent(t *testing.T, bridge *test.Bridge, events <-chan streamResetEvent) streamResetEvent {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		bridge.Process()
		select {
		case event := <-events:
			return event
		default:
			time.Sleep(time.Millisecond)
		}
	}
	require.FailNow(t, "timed out waiting for stream reset completion")

	return streamResetEvent{}
}

// The handler fires once, only after the stream is removed and both the
// incoming and the outgoing reset have completed.
func TestStreamResetCompleteWaitsForRemovalAndFiresOnce(t *testing.T) {
	const streamID = uint16(7)
	assoc := createTestAssociation(t, Config{})
	t.Cleanup(func() {
		assoc.closeAllTimers()
		assoc.closeWriteLoopOnce.Do(func() { close(assoc.closeWriteLoopCh) })
	})
	assoc.setState(established)
	assoc.payloadQueue.init(100)
	stream := assoc.createStream(streamID, false)
	require.NotNil(t, stream)

	completed := make(chan uint16, 2)
	assoc.OnStreamResetComplete(func(id uint16) {
		assoc.lock.RLock()
		_, present := assoc.streams[id]
		assoc.lock.RUnlock()
		require.False(t, present)
		completed <- id
	})

	request := &paramOutgoingResetRequest{
		reconfigRequestSequenceNumber: 1,
		senderLastTSN:                 101,
		streamIdentifiers:             []uint16{streamID},
	}

	assoc.lock.Lock()
	response := assoc.resetStreamsIfAny(request)
	assoc.lock.Unlock()
	require.Equal(t, reconfigResultInProgress, resetResponseResult(t, response))
	select {
	case id := <-completed:
		require.FailNowf(t, "reset completion fired early", "stream %d", id)
	default:
	}

	assoc.payloadQueue.init(101)
	assoc.lock.Lock()
	response = assoc.resetStreamsIfAny(request)
	assoc.lock.Unlock()
	require.Equal(t, reconfigResultSuccessPerformed, resetResponseResult(t, response))
	select {
	case id := <-completed:
		require.FailNowf(t, "reset completion fired before outgoing reset", "stream %d", id)
	default:
	}

	const outgoingSequence = uint32(2)
	assoc.reconfigs[outgoingSequence] = &chunkReconfig{
		paramA: &paramOutgoingResetRequest{
			reconfigRequestSequenceNumber: outgoingSequence,
			streamIdentifiers:             []uint16{streamID},
		},
	}
	assoc.lock.Lock()
	_, err := assoc.handleReconfigParam(&paramReconfigResponse{
		reconfigResponseSequenceNumber: outgoingSequence,
		result:                         reconfigResultSuccessPerformed,
	})
	assoc.lock.Unlock()
	require.NoError(t, err)
	require.Equal(t, streamID, <-completed)

	assoc.lock.Lock()
	_, err = assoc.handleReconfigParam(&paramReconfigResponse{
		reconfigResponseSequenceNumber: outgoingSequence,
		result:                         reconfigResultSuccessPerformed,
	})
	assoc.lock.Unlock()
	require.NoError(t, err)
	select {
	case id := <-completed:
		require.FailNowf(t, "reset completion fired twice", "stream %d", id)
	default:
	}
}

// Both peers are notified once each side has closed its end of the stream.
func TestStreamResetCompleteNotifiesBothAssociations(t *testing.T) {
	const streamID = uint16(5)
	bridge := test.NewBridge()
	client, server, err := createNewAssociationPair(bridge, ackModeNoDelay, 0)
	require.NoError(t, err)
	clientStream, serverStream, err := establishSessionPair(bridge, client, server, streamID)
	require.NoError(t, err)

	clientCompleted := make(chan streamResetEvent, 1)
	serverCompleted := make(chan streamResetEvent, 1)
	client.OnStreamResetComplete(func(id uint16) {
		client.lock.RLock()
		_, present := client.streams[id]
		client.lock.RUnlock()
		clientCompleted <- streamResetEvent{id: id, present: present}
	})
	server.OnStreamResetComplete(func(id uint16) {
		server.lock.RLock()
		_, present := server.streams[id]
		server.lock.RUnlock()
		serverCompleted <- streamResetEvent{id: id, present: present}
	})

	require.NoError(t, clientStream.Close())
	require.NoError(t, serverStream.Close())
	serverEvent := waitForResetEvent(t, bridge, serverCompleted)
	require.Equal(t, streamResetEvent{id: streamID}, serverEvent)
	clientEvent := waitForResetEvent(t, bridge, clientCompleted)
	require.Equal(t, streamResetEvent{id: streamID}, clientEvent)

	closeAssociationPair(bridge, client, server)
}
