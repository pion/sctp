// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package sctp

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func restartNotificationAssociation(t *testing.T) *Association {
	t.Helper()
	assoc := newRackTestAssoc(t)
	t.Cleanup(func() {
		assoc.closeAllTimers()
		assoc.closeWriteLoopOnce.Do(func() { close(assoc.closeWriteLoopCh) })
	})

	return assoc
}

func restartNotificationCookie(t *testing.T, assoc *Association, tag, tsn uint32) (*packet, []byte) {
	t.Helper()
	assoc.lock.Lock()
	defer assoc.lock.Unlock()
	init := &chunkInit{chunkInitCommon: chunkInitCommon{
		initiateTag: tag, initialTSN: tsn, numInboundStreams: 4, numOutboundStreams: 6,
	}}
	pkt := &packet{sourcePort: assoc.destinationPort, destinationPort: assoc.sourcePort}
	response, err := assoc.handleInit(pkt, init)
	require.NoError(t, err)
	require.Len(t, response, 1)
	ack, ok := response[0].chunks[0].(*chunkInitAck)
	require.True(t, ok)
	cookie, ok := ack.params[0].(*paramStateCookie)
	require.True(t, ok)
	pkt.verificationTag = ack.initiateTag

	return pkt, append([]byte(nil), cookie.cookie...)
}

func TestAssociationRestartNotificationSnapshot(t *testing.T) {
	assoc := restartNotificationAssociation(t)
	open, err := assoc.OpenStream(0, PayloadTypeWebRTCBinary)
	require.NoError(t, err)
	closing, err := assoc.OpenStream(2, PayloadTypeWebRTCBinary)
	require.NoError(t, err)
	closing.lock.Lock()
	closing.state = StreamStateClosing
	closing.lock.Unlock()

	var events []AssociationRestartEvent
	var created *Stream
	assoc.OnAssociationRestart(func(event AssociationRestartEvent) {
		// Re-entering these methods proves the callback does not hold a.lock.
		_, ok := assoc.Metadata()
		require.True(t, ok)
		require.Equal(t, event.Generation, open.AssociationGeneration())
		require.Equal(t, StreamStateClosed, closing.State())
		var createErr error
		created, createErr = assoc.OpenStream(3, PayloadTypeWebRTCBinary)
		require.NoError(t, createErr)
		require.Equal(t, event.Generation, created.AssociationGeneration())
		events = append(events, event)
	})

	pkt, cookie := restartNotificationCookie(t, assoc, 3, 500)
	require.Empty(t, events, "INIT is not an authenticated restart")
	assoc.lock.Lock()
	response := assoc.handleCookieEcho(pkt, &chunkCookieEcho{cookie: cookie})
	assoc.lock.Unlock()
	require.Len(t, response, 1)
	require.Len(t, events, 1)
	require.Equal(t, uint64(1), events[0].Generation)
	require.Equal(t, uint16(6), events[0].NumInboundStreams)
	require.Equal(t, uint16(4), events[0].NumOutboundStreams)
	require.Equal(t, []*Stream{open}, events[0].RetainedStreams)
	require.NotContains(t, events[0].RetainedStreams, created, "snapshot excludes streams opened by the observer")
	_, _, err = closing.ReadSCTP(make([]byte, 1))
	require.ErrorIs(t, err, io.EOF)

	assoc.lock.Lock()
	response = assoc.handleCookieEcho(pkt, &chunkCookieEcho{cookie: cookie})
	assoc.lock.Unlock()
	require.Len(t, response, 1)
	require.Len(t, events, 1, "a retransmitted COOKIE ECHO must not repeat the event")
}

func TestAssociationRestartNotificationAuthenticationAndRemoval(t *testing.T) {
	assoc := restartNotificationAssociation(t)
	calls := 0
	assoc.OnAssociationRestart(func(AssociationRestartEvent) { calls++ })
	pkt, cookie := restartNotificationCookie(t, assoc, 3, 500)
	forged := append([]byte(nil), cookie...)
	forged[len(forged)-1] ^= 1
	assoc.lock.Lock()
	response := assoc.handleCookieEcho(pkt, &chunkCookieEcho{cookie: forged})
	assoc.lock.Unlock()
	require.Empty(t, response)
	require.Zero(t, calls)

	assoc.OnAssociationRestart(nil)
	assoc.lock.Lock()
	response = assoc.handleCookieEcho(pkt, &chunkCookieEcho{cookie: cookie})
	assoc.lock.Unlock()
	require.Len(t, response, 1)
	require.Zero(t, calls, "nil removes the handler")
}
