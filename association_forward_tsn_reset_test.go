// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package sctp

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func reconfigResponseResult(t *testing.T, pkt *packet) reconfigResult {
	t.Helper()
	require.NotNil(t, pkt)
	require.Len(t, pkt.chunks, 1)
	reconfig, ok := pkt.chunks[0].(*chunkReconfig)
	require.True(t, ok)
	response, ok := reconfig.paramA.(*paramReconfigResponse)
	require.True(t, ok)

	return response.result
}

// A pending incoming reset request must be re-checked when FORWARD-TSN or
// I-FORWARD-TSN advances the cumulative TSN, not only when DATA does.
func TestForwardTSNCompletesPendingStreamReset(t *testing.T) {
	const streamID = uint16(7)
	for _, tc := range []struct {
		name    string
		forward func(a *Association) []*packet
	}{
		{name: "FORWARD-TSN", forward: func(a *Association) []*packet {
			a.useForwardTSN = true

			return a.handleForwardTSN(&chunkForwardTSN{newCumulativeTSN: 101})
		}},
		{name: "I-FORWARD-TSN", forward: func(a *Association) []*packet {
			a.useInterleaving = true
			a.useIForwardTSN = true

			return a.handleIForwardTSN(&chunkIForwardTSN{newCumulativeTSN: 101})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assoc := createTestAssociation(t, Config{})
			t.Cleanup(func() {
				assoc.closeAllTimers()
				assoc.closeWriteLoopOnce.Do(func() { close(assoc.closeWriteLoopCh) })
			})
			assoc.setState(established)
			assoc.payloadQueue.init(100)
			stream := assoc.createStream(streamID, false)
			require.NotNil(t, stream)

			assoc.lock.Lock()
			response, err := assoc.handleReconfigParam(&paramOutgoingResetRequest{
				reconfigRequestSequenceNumber: 1,
				senderLastTSN:                 101,
				streamIdentifiers:             []uint16{streamID},
			})
			require.NoError(t, err)
			require.Equal(t, reconfigResultInProgress, reconfigResponseResult(t, response))

			replies := tc.forward(assoc)
			assoc.lock.Unlock()
			require.Len(t, replies, 1)
			require.Equal(t, reconfigResultSuccessPerformed, reconfigResponseResult(t, replies[0]))
			assert.NotContains(t, assoc.streams, streamID)
			assert.Empty(t, assoc.reconfigRequests)

			_, _, err = stream.ReadSCTP(make([]byte, 16))
			require.ErrorIs(t, err, io.EOF)
		})
	}
}

// A peer closes a partially reliable stream whose last message lost its tail
// fragment. The reset request arrives "In progress" and the TSN gap is then
// closed by (I-)FORWARD-TSN rather than DATA; the reset must complete without
// waiting for the peer to retransmit the request.
func TestStreamResetCompletesAfterForwardTSNAbandonsTail(t *testing.T) {
	for _, tc := range []struct {
		name         string
		interleaving bool
		forwardType  chunkType
	}{
		{name: "FORWARD-TSN", interleaving: false, forwardType: ctForwardTSN},
		{name: "I-FORWARD-TSN", interleaving: true, forwardType: ctIForwardTSN},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testStreamResetCompletesAfterForwardTSN(t, tc.interleaving, tc.forwardType)
		})
	}
}

func testStreamResetCompletesAfterForwardTSN( //nolint:cyclop,gocognit
	t *testing.T,
	interleaving bool,
	forwardType chunkType,
) {
	t.Helper()
	lim := test.TimeOut(10 * time.Second)
	defer lim.Stop()

	const streamID = uint16(3)
	bridge := test.NewBridge()
	client, server, err := createNewAssociationPairWithInterleaving(
		bridge, ackModeNoDelay, 0, interleaving, interleaving,
	)
	require.NoError(t, err)
	defer closeAssociationPair(bridge, client, server)
	clientStream, serverStream, err := establishSessionPair(bridge, client, server, streamID)
	require.NoError(t, err)

	client.rtoMgr.setRTO(100.0, true)
	clientStream.SetReliabilityParams(false, ReliabilityTypeRexmit, 0)

	var (
		mu               sync.Mutex
		tailTSN          *uint32
		inProgress       bool
		forwardSeen      []chunkType
		resetRequestSent int
		performed        bool
	)
	// Client -> server: drop every transmission of the tail fragment so only
	// (I-)FORWARD-TSN can close the gap, hold back (I-)FORWARD-TSN until the
	// server has answered the reset "In progress", and drop RECONFIG
	// retransmissions so the reset cannot complete through them.
	bridge.Filter(0, func(raw []byte) bool {
		pkt := &packet{}
		if pkt.unmarshal(true, raw) != nil {
			return true
		}
		mu.Lock()
		defer mu.Unlock()
		for _, c := range pkt.chunks {
			switch chk := c.(type) {
			case *chunkPayloadData:
				if chk.streamIdentifier == streamID && chk.endingFragment && !chk.beginningFragment && tailTSN == nil {
					tsn := chk.tsn
					tailTSN = &tsn
				}
				if tailTSN != nil && chk.tsn == *tailTSN {
					return false
				}
			case *chunkForwardTSN:
				if !inProgress {
					return false
				}
				forwardSeen = append(forwardSeen, ctForwardTSN)
			case *chunkIForwardTSN:
				if !inProgress {
					return false
				}
				forwardSeen = append(forwardSeen, ctIForwardTSN)
			case *chunkReconfig:
				if _, ok := chk.paramA.(*paramOutgoingResetRequest); ok {
					resetRequestSent++
					if resetRequestSent > 1 {
						return false
					}
				}
			}
		}

		return true
	})
	bridge.Filter(1, func(raw []byte) bool {
		pkt := &packet{}
		if pkt.unmarshal(true, raw) != nil {
			return true
		}
		for _, c := range pkt.chunks {
			if chk, ok := c.(*chunkReconfig); ok {
				if resp, ok := chk.paramA.(*paramReconfigResponse); ok {
					mu.Lock()
					switch resp.result {
					case reconfigResultInProgress:
						inProgress = true
					case reconfigResultSuccessPerformed:
						performed = true
					default:
					}
					mu.Unlock()
				}
			}
		}

		return true
	})

	// Large enough to be fragmented into two DATA chunks.
	msg := make([]byte, 2000)
	_, err = clientStream.WriteSCTP(msg, PayloadTypeWebRTCBinary)
	require.NoError(t, err)

	deadline := time.Now().Add(5 * time.Second)
	for {
		bridge.Process()
		mu.Lock()
		dropped := tailTSN != nil
		mu.Unlock()
		if dropped {
			break
		}
		require.True(t, time.Now().Before(deadline), "tail fragment was never sent")
		time.Sleep(time.Millisecond)
	}

	require.NoError(t, clientStream.Close())

	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 4096)
		_, _, err := serverStream.ReadSCTP(buf)
		readErr <- err
	}()

	var gotErr error
	for gotErr == nil {
		bridge.Process()
		select {
		case gotErr = <-readErr:
		default:
			require.True(t, time.Now().Before(deadline), "server stream never observed the reset")
			time.Sleep(time.Millisecond)
		}
	}
	require.ErrorIs(t, gotErr, io.EOF)

	for {
		bridge.Process()
		mu.Lock()
		done := performed
		mu.Unlock()
		if done {
			break
		}
		require.True(t, time.Now().Before(deadline), "reset was never reported as performed")
		time.Sleep(time.Millisecond)
	}

	mu.Lock()
	require.True(t, inProgress, "reset request was not answered in progress")
	require.NotEmpty(t, forwardSeen, "gap was not closed by forward TSN")
	for _, typ := range forwardSeen {
		require.Equal(t, forwardType, typ)
	}
	mu.Unlock()

	server.lock.RLock()
	_, present := server.streams[streamID]
	server.lock.RUnlock()
	require.False(t, present, "reset stream was not removed")
}
