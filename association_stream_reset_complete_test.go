// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package sctp

import (
	"testing"
	"time"

	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/require"
)

// Both peers are notified once, after both reset directions completed and the
// stream is gone.
func TestStreamResetCompleteNotifiesBothAssociations(t *testing.T) {
	const streamID = uint16(5)
	bridge := test.NewBridge()
	client, server, err := createNewAssociationPair(bridge, ackModeNoDelay, 0)
	require.NoError(t, err)
	defer closeAssociationPair(bridge, client, server)
	clientStream, serverStream, err := establishSessionPair(bridge, client, server, streamID)
	require.NoError(t, err)

	completed := func(assoc *Association) chan uint16 {
		events := make(chan uint16, 2)
		assoc.OnStreamResetComplete(func(id uint16) {
			assoc.lock.RLock()
			_, present := assoc.streams[id]
			assoc.lock.RUnlock()
			require.False(t, present, "stream %d still registered", id)
			events <- id
		})

		return events
	}
	clientCompleted, serverCompleted := completed(client), completed(server)

	// Only one direction is reset: neither side may report completion.
	require.NoError(t, clientStream.Close())
	flushBuffers(bridge, client, server)
	require.Empty(t, serverCompleted, "server reported completion after one direction")
	require.Empty(t, clientCompleted, "client reported completion after one direction")

	require.NoError(t, serverStream.Close())
	for _, side := range []struct {
		name   string
		events chan uint16
	}{{"server", serverCompleted}, {"client", clientCompleted}} {
		deadline := time.Now().Add(5 * time.Second)
		for len(side.events) == 0 {
			require.True(t, time.Now().Before(deadline), "%s was not notified", side.name)
			bridge.Process()
		}
		require.Equal(t, streamID, <-side.events)
	}

	// The identifier is free again. Closing one direction of the next
	// stream using it must not report completion right away.
	reusedClient, err := client.OpenStream(streamID, PayloadTypeWebRTCBinary)
	require.NoError(t, err)
	_, err = reusedClient.WriteSCTP([]byte("reused"), PayloadTypeWebRTCBinary)
	require.NoError(t, err)
	flushBuffers(bridge, client, server)
	_, err = server.AcceptStream()
	require.NoError(t, err)

	require.NoError(t, reusedClient.Close())
	deadline := time.Now().Add(5 * time.Second)
	for {
		bridge.Process()
		server.lock.RLock()
		_, present := server.streams[streamID]
		server.lock.RUnlock()
		if !present {
			break
		}
		require.True(t, time.Now().Before(deadline), "server never saw the reset of the reused stream")
	}
	require.Empty(t, serverCompleted, "server reported completion after one direction")
	require.Empty(t, clientCompleted, "client reported completion after one direction")
}
