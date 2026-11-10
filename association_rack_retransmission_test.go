// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package sctp

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newRackRetransmissionTestAssociation(t *testing.T) *Association {
	t.Helper()
	association := newRackTestAssoc(t)
	conn, peer := net.Pipe()
	association.netConn = conn
	t.Cleanup(func() {
		shutdownTLRAssociationForTest(association, peer)
	})

	return association
}

func TestRACKLostRetransmission(t *testing.T) {
	for _, trigger := range []string{"sack", "timer"} {
		for _, test := range []struct {
			name                           string
			sends                          uint32
			age                            time.Duration
			queued, acked, abandoned, want bool
		}{
			{"original", 1, 100 * time.Millisecond, false, false, false, true},
			{"retry", 2, 100 * time.Millisecond, false, false, false, true},
			{"repeated-retry", 3, 100 * time.Millisecond, false, false, false, true},
			{"recent-retry", 2, 5 * time.Millisecond, false, false, false, false},
			{"already-queued", 2, 100 * time.Millisecond, true, false, false, true},
			{"already-acked", 2, 100 * time.Millisecond, false, true, false, false},
			{"abandoned", 2, 100 * time.Millisecond, false, false, true, false},
		} {
			t.Run(trigger+"/"+test.name, func(t *testing.T) {
				association := newRackRetransmissionTestAssociation(t)
				association.lock.Lock()
				defer association.lock.Unlock()
				now := time.Now()
				association.rackReorderingSeen = true
				association.rackReoWnd = 10 * time.Millisecond
				association.rackMinRTT = 40 * time.Millisecond
				chunk := mkChunk(100, now.Add(-test.age))
				chunk.nSent, chunk.retransmit, chunk.acked = test.sends, test.queued, test.acked
				if test.abandoned {
					chunk.setAbandoned(true)
					chunk.setAllInflight()
				}
				association.inflightQueue.pushNoCheck(chunk)
				association.rackInsert(chunk)
				delivered := now.Add(-50 * time.Millisecond)
				if trigger == "sack" {
					association.onRackAfterSACK(true, delivered, 101, &chunkSelectiveAck{})
				} else {
					association.rackDeliveredTime = delivered
					association.onRackTimeoutLocked()
				}
				require.Equal(t, test.want, chunk.retransmit)
				if test.queued {
					require.True(t, chunk.rackInList, "queued work must not be marked lost again")
					require.Empty(t, association.awakeWriteLoopCh, "queued work must not wake the writer again")
				}
			})
		}
	}
}

func TestRACKRetransmissionDeliveryEvidence(t *testing.T) {
	for _, selective := range []bool{false, true} {
		for _, test := range []struct {
			name        string
			sends       uint32
			minRTT, age time.Duration
			valid       bool
		}{
			{"original", 1, 40 * time.Millisecond, time.Millisecond, true},
			{"ambiguous-retry", 2, 40 * time.Millisecond, time.Millisecond, false},
			{"credible-retry", 2, 40 * time.Millisecond, 2 * time.Second, true},
			{"ambiguous-repeated-retry", 3, 40 * time.Millisecond, time.Millisecond, false},
			{"credible-repeated-retry", 3, 40 * time.Millisecond, 2 * time.Second, true},
			{"retry-without-rtt", 2, 0, 2 * time.Second, true},
		} {
			mode := "/cumulative"
			if selective {
				mode = "/selective"
			}
			t.Run(test.name+mode, func(t *testing.T) {
				association := newRackRetransmissionTestAssociation(t)
				association.lock.Lock()
				defer association.lock.Unlock()
				association.rackMinRTT = test.minRTT
				association.rackReorderingSeen = true
				association.rackReoWnd = 10 * time.Millisecond
				now := time.Now()
				retryTSN, otherTSN := uint32(100), uint32(101)
				if selective {
					retryTSN, otherTSN = otherTSN, retryTSN
				}
				retry := mkChunk(retryTSN, now.Add(-test.age))
				retry.nSent = test.sends
				other := mkChunk(otherTSN, now.Add(-3*time.Second))
				if selective {
					association.inflightQueue.pushNoCheck(other)
					association.inflightQueue.pushNoCheck(retry)
				} else {
					association.inflightQueue.pushNoCheck(retry)
					association.inflightQueue.pushNoCheck(other)
				}
				association.rackInsert(other)
				association.rackInsert(retry)
				sack := &chunkSelectiveAck{cumulativeTSNAck: 100, advertisedReceiverWindowCredit: 1024 * 1024}
				if selective {
					sack.cumulativeTSNAck = 99
					sack.gapAckBlocks = []gapAckBlock{{start: 2, end: 2}}
				}
				previousSRTT := association.SRTT()
				require.NoError(t, association.handleSack(sack))
				require.Equal(t, test.valid, !association.rackDeliveredTime.IsZero())
				require.Equal(t, test.valid, other.retransmit)
				// Timing ambiguity must not discard a valid delivery acknowledgement.
				acknowledged, found := association.inflightQueue.get(retryTSN)
				if selective {
					require.True(t, found)
					require.True(t, acknowledged.acked)
				} else {
					require.False(t, found)
				}
				if test.sends > 1 {
					require.Equal(t, previousSRTT, association.SRTT(), "Karn's rule still excludes retries from RTT samples")
					require.Zero(t, association.rack.rackMinRTTWnd.Len(), "delivery evidence must not create an RTT sample")
				}
			})
		}
	}
}

func TestRACKRetransmissionRejoinsLossScan(t *testing.T) {
	for _, trigger := range []string{"sack", "timer"} {
		t.Run(trigger, func(t *testing.T) {
			association := newRackRetransmissionTestAssociation(t)
			association.lock.Lock()
			defer association.lock.Unlock()
			association.rackReorderingSeen = true
			association.rackReoWnd = 10 * time.Millisecond
			association.rackMinRTT = 40 * time.Millisecond
			now := time.Now()
			chunk := mkChunk(100, now.Add(-100*time.Millisecond))
			chunk.nSent = 2
			association.inflightQueue.pushNoCheck(chunk)
			association.rackInsert(chunk)

			markLost := func(delivered time.Time) {
				if trigger == "sack" {
					association.onRackAfterSACK(true, delivered, 101, &chunkSelectiveAck{})
				} else {
					association.rackDeliveredTime = delivered
					association.onRackTimeoutLocked()
				}
			}
			markLost(now.Add(-50 * time.Millisecond))
			require.True(t, chunk.retransmit)
			require.False(t, chunk.rackInList)

			beforeSend := time.Now()
			var budget int64
			var consumed bool
			packets := association.getDataPacketsToRetransmit(&budget, &consumed)
			require.NotEmpty(t, packets)
			require.False(t, chunk.retransmit)
			require.Equal(t, uint32(3), chunk.nSent)
			require.False(t, chunk.since.Before(beforeSend))
			require.False(t, chunk.since.After(time.Now()))
			require.True(t, chunk.rackInList)
			require.Same(t, chunk, association.rackHead)
			require.Same(t, chunk, association.rackTail)

			// Model a later delivery relative to the actual retry timestamp;
			// scanning compares send times, so the test needs no wall-clock sleep.
			markLost(chunk.since.Add(2 * association.rackReoWnd))
			require.True(t, chunk.retransmit)
			require.False(t, chunk.rackInList)
			require.Equal(t, uint32(3), chunk.nSent, "marking loss must not count as sending")
		})
	}
}

func TestRACKRetryEvidenceUsesWholeSACKRTT(t *testing.T) {
	for _, mode := range []string{"cumulative", "selective"} {
		t.Run(mode, func(t *testing.T) {
			association := newRackRetransmissionTestAssociation(t)
			association.lock.Lock()
			defer association.lock.Unlock()
			association.minTSN2MeasureRTT = 100
			association.rackMinRTT = 40 * time.Millisecond
			now := time.Now()
			retry := mkChunk(100, now.Add(-100*time.Millisecond))
			retry.nSent = 2
			original := mkChunk(101, now.Add(-2*time.Second))
			association.inflightQueue.pushNoCheck(retry)
			association.inflightQueue.pushNoCheck(original)
			association.rackInsert(original)
			association.rackInsert(retry)

			sack := &chunkSelectiveAck{cumulativeTSNAck: 101, advertisedReceiverWindowCredit: 1024 * 1024}
			if mode == "selective" {
				sack.cumulativeTSNAck = 99
				sack.gapAckBlocks = []gapAckBlock{{start: 1, end: 2}}
			}
			require.NoError(t, association.handleSack(sack))
			// The later-visited original supplies a 2s RTT. The retry's 100ms
			// ACK is implausibly early even though it exceeded the cached 40ms.
			require.GreaterOrEqual(t, association.rackMinRTT, 2*time.Second)
			require.Equal(t, original.since, association.rackDeliveredTime)
		})
	}
}
