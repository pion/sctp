// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSackBundlingAssociation returns an association whose ack timer and
// queues are initialized, closed when the test ends.
func newSackBundlingAssociation(t *testing.T) *Association {
	t.Helper()
	ca, cb := net.Pipe()
	t.Cleanup(func() {
		_ = ca.Close()
		_ = cb.Close()
	})
	cfg, err := buildClientConfig(WithNetConn(ca))
	require.NoError(t, err)
	assoc := createAssociationFromConfigWithTsn(cfg, 1)
	t.Cleanup(func() { _ = assoc.close() })

	return assoc
}

func TestBundleDataChunksCarriesDelayedSack(t *testing.T) {
	assoc := newSackBundlingAssociation(t)
	assoc.lock.Lock()
	defer assoc.lock.Unlock()

	assoc.ackState = ackStateDelay
	assoc.ackTimer.start()
	sacksBefore := assoc.stats.getNumSACKsSent()

	packets := assoc.bundleDataChunksIntoPackets([]*chunkPayloadData{{userData: []byte{1}}})
	require.Len(t, packets, 1)
	require.Len(t, packets[0].chunks, 2)
	_, isSack := packets[0].chunks[0].(*chunkSelectiveAck)
	assert.True(t, isSack, "the delayed SACK must lead the first DATA packet")
	_, isData := packets[0].chunks[1].(*chunkPayloadData)
	assert.True(t, isData)
	assert.Equal(t, ackStateIdle, assoc.ackState)
	assert.Equal(t, ackTimerStopped, assoc.ackTimer.state)
	assert.Equal(t, sacksBefore+1, assoc.stats.getNumSACKsSent())
}

func TestBundleDataChunksWithoutPendingSack(t *testing.T) {
	assoc := newSackBundlingAssociation(t)
	assoc.lock.Lock()
	defer assoc.lock.Unlock()

	packets := assoc.bundleDataChunksIntoPackets([]*chunkPayloadData{{userData: []byte{1}}})
	require.Len(t, packets, 1)
	require.Len(t, packets[0].chunks, 1)
	_, isData := packets[0].chunks[0].(*chunkPayloadData)
	assert.True(t, isData, "no SACK is owed, so only DATA is sent")
}

func TestBundledSackKeepsPacketsWithinMTU(t *testing.T) {
	assoc := newSackBundlingAssociation(t)
	assoc.lock.Lock()
	defer assoc.lock.Unlock()

	assoc.ackState = ackStateImmediate
	chunks := make([]*chunkPayloadData, 300)
	for i := range chunks {
		chunks[i] = &chunkPayloadData{userData: make([]byte, 37)}
	}
	for _, p := range assoc.bundleDataChunksIntoPackets(chunks) {
		raw, err := p.marshal(false)
		require.NoError(t, err)
		assert.LessOrEqual(t, len(raw), int(assoc.MTU()), "packet too long")
	}
}
