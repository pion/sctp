// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package sctp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A delayed reset response must keep subsequent requests queued; otherwise
// reordering causes a bad RSN response and permanently loses stream closure.
func TestStreamResetsWaitForAcknowledgement(t *testing.T) {
	assoc := createTestAssociation(t, Config{})
	assoc.setState(established)
	defer assoc.tReconfig.stop()
	gather := func() [][]byte {
		assoc.lock.Lock()
		defer assoc.lock.Unlock()
		budget := int64(1 << 30)
		consumed := false

		return assoc.gatherOutboundDataAndReconfigPackets(nil, &budget, &consumed)
	}
	respond := func(rsn uint32, result reconfigResult) {
		assoc.lock.Lock()
		_, err := assoc.handleReconfigParam(&paramReconfigResponse{
			reconfigResponseSequenceNumber: rsn,
			result:                         result,
		})
		assoc.lock.Unlock()
		require.NoError(t, err)
	}
	require.NoError(t, assoc.sendResetRequest(1))
	require.Len(t, gather(), 1)
	var first uint32
	for rsn := range assoc.reconfigs {
		first = rsn
	}
	for _, id := range []uint16{3, 5, 7} {
		require.NoError(t, assoc.sendResetRequest(id))
	}
	require.Empty(t, gather(), "later resets must wait for the first response")
	require.Len(t, assoc.reconfigs, 1)
	respond(first, reconfigResultInProgress)
	require.Empty(t, gather(), "in-progress is not completion")
	assoc.willRetransmitReconfig = true
	require.Len(t, gather(), 1, "retransmit only the outstanding request")
	respond(first, reconfigResultSuccessPerformed)
	require.Len(t, gather(), 1)
	require.Len(t, assoc.reconfigs, 1)
	next, ok := assoc.reconfigs[first+1].paramA.(*paramOutgoingResetRequest)
	require.True(t, ok)
	require.Equal(t, []uint16{3, 5, 7}, next.streamIdentifiers)
}

func TestStreamResetBatchFitsMTU(t *testing.T) {
	assoc := createTestAssociation(t, Config{})
	assoc.setState(established)
	defer assoc.tReconfig.stop()
	for id := range uint16(2048) {
		require.NoError(t, assoc.sendResetRequest(id))
	}
	total := 0
	for total < 2048 {
		assoc.lock.Lock()
		budget := int64(1 << 30)
		consumed := false
		packets := assoc.gatherOutboundDataAndReconfigPackets(nil, &budget, &consumed)
		assoc.lock.Unlock()
		require.Len(t, packets, 1)
		require.LessOrEqual(t, len(packets[0]), int(assoc.MTU()))
		require.Len(t, assoc.reconfigs, 1)
		for rsn, request := range assoc.reconfigs {
			resetRequest, ok := request.paramA.(*paramOutgoingResetRequest)
			require.True(t, ok)
			total += len(resetRequest.streamIdentifiers)
			assoc.lock.Lock()
			_, err := assoc.handleReconfigParam(&paramReconfigResponse{
				reconfigResponseSequenceNumber: rsn,
				result:                         reconfigResultSuccessPerformed,
			})
			assoc.lock.Unlock()
			require.NoError(t, err)
		}
	}
	require.Equal(t, 2048, total)
}
