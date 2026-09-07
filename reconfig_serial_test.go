package sctp

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A delayed reset response must keep subsequent requests queued; otherwise
// reordering causes a bad RSN response and permanently loses stream closure.
func TestStreamResetsWaitForAcknowledgement(t *testing.T) {
	a := createTestAssociation(t, Config{})
	a.setState(established)
	defer a.tReconfig.stop()
	gather := func() [][]byte {
		a.lock.Lock()
		defer a.lock.Unlock()
		budget := int64(1 << 30)
		consumed := false
		return a.gatherOutboundDataAndReconfigPackets(nil, &budget, &consumed)
	}
	require.NoError(t, a.sendResetRequest(1))
	require.Len(t, gather(), 1)
	var first uint32
	for rsn := range a.reconfigs {
		first = rsn
	}
	for _, id := range []uint16{3, 5, 7} {
		require.NoError(t, a.sendResetRequest(id))
	}
	require.Empty(t, gather(), "later resets must wait for the first response")
	require.Len(t, a.reconfigs, 1)
	a.lock.Lock()
	_, err := a.handleReconfigParam(&paramReconfigResponse{reconfigResponseSequenceNumber: first, result: reconfigResultInProgress})
	a.lock.Unlock()
	require.NoError(t, err)
	require.Empty(t, gather(), "in-progress is not completion")
	a.willRetransmitReconfig = true
	require.Len(t, gather(), 1, "retransmit only the outstanding request")
	a.lock.Lock()
	_, err = a.handleReconfigParam(&paramReconfigResponse{reconfigResponseSequenceNumber: first, result: reconfigResultSuccessPerformed})
	a.lock.Unlock()
	require.NoError(t, err)
	require.Len(t, gather(), 1)
	require.Len(t, a.reconfigs, 1)
	next := a.reconfigs[first+1].paramA.(*paramOutgoingResetRequest)
	require.Equal(t, []uint16{3, 5, 7}, next.streamIdentifiers)
}

func TestStreamResetBatchFitsMTU(t *testing.T) {
	a := createTestAssociation(t, Config{})
	a.setState(established)
	defer a.tReconfig.stop()
	for id := uint16(0); id < 2048; id++ {
		require.NoError(t, a.sendResetRequest(id))
	}
	total := 0
	for total < 2048 {
		a.lock.Lock()
		budget := int64(1 << 30)
		consumed := false
		packets := a.gatherOutboundDataAndReconfigPackets(nil, &budget, &consumed)
		a.lock.Unlock()
		require.Len(t, packets, 1)
		require.LessOrEqual(t, len(packets[0]), int(a.MTU()))
		require.Len(t, a.reconfigs, 1)
		for rsn, request := range a.reconfigs {
			total += len(request.paramA.(*paramOutgoingResetRequest).streamIdentifiers)
			a.lock.Lock()
			_, err := a.handleReconfigParam(&paramReconfigResponse{reconfigResponseSequenceNumber: rsn, result: reconfigResultSuccessPerformed})
			a.lock.Unlock()
			require.NoError(t, err)
		}
	}
	require.Equal(t, 2048, total)
}
