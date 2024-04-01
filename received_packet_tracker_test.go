// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReceivedPacketTrackerPushPop(t *testing.T) {
	q := newReceivedPacketTracker()
	for i := uint32(1); i < 100; i++ {
		q.push(i, 0)
	}
	// leave a gap at position 100
	for i := uint32(101); i < 200; i++ {
		q.push(i, 0)
	}
	for i := uint32(2); i < 200; i++ {
		require.False(t, q.pop(i)) // all pop will fail till we pop the first tsn
	}
	for i := uint32(1); i < 100; i++ {
		require.True(t, q.pop(i))
	}
	// 101 is the smallest value now
	for i := uint32(102); i < 200; i++ {
		require.False(t, q.pop(i))
	}
	q.push(100, 99)
	for i := uint32(100); i < 200; i++ {
		require.True(t, q.pop(i))
	}

	// q is empty now
	require.Equal(t, q.size(), 0)
	for i := uint32(0); i < 200; i++ {
		require.False(t, q.pop(i))
	}
}

func TestReceivedPacketTrackerGapACKBlocksStress(t *testing.T) {
	testChunks := func(chunks []uint32, st uint32) {
		if len(chunks) == 0 {
			return
		}
		expected := make([]gapAckBlock, 0, len(chunks))
		cr := ackRange{start: chunks[0], end: chunks[0]}
		for i := 1; i < len(chunks); i++ {
			if cr.end+1 != chunks[i] {
				expected = append(expected, gapAckBlock{
					start: uint16(cr.start - st),
					end:   uint16(cr.end - st),
				})
				cr = ackRange{start: chunks[i], end: chunks[i]}
			} else {
				cr.end++
			}
		}
		expected = append(expected, gapAckBlock{
			start: uint16(cr.start - st),
			end:   uint16(cr.end - st),
		})

		q := newReceivedPacketTracker()
		rand.Shuffle(len(chunks), func(i, j int) {
			chunks[i], chunks[j] = chunks[j], chunks[i]
		})
		for _, t := range chunks {
			q.push(t, 0)
		}
		res := q.getGapAckBlocks(0)
		require.Equal(t, expected, res, chunks)
	}
	chunks := make([]uint32, 0, 10)
	for i := 1; i < (1 << 10); i++ {
		for j := 0; j < 10; j++ {
			if i&(1<<j) != 0 {
				chunks = append(chunks, uint32(j+1))
			}
		}
		testChunks(chunks, 0)
		chunks = chunks[:0]
	}
}

func TestReceivedPacketTrackerGapACKBlocksStress2(t *testing.T) {

	tests := []struct {
		chunks         []uint32
		cummulativeTSN uint32
		result         []gapAckBlock
	}{
		{
			chunks:         []uint32{3, 4, 1, 2, 7, 8, 10000},
			cummulativeTSN: 3,
			result:         []gapAckBlock{{1, 1}, {4, 5}, {10000 - 3, 10000 - 3}},
		},
		{
			chunks:         []uint32{3, 5, 1, 2, 7, 8, 10000},
			cummulativeTSN: 3,
			result:         []gapAckBlock{{2, 2}, {4, 5}, {10000 - 3, 10000 - 3}},
		},
		{
			chunks:         []uint32{3, 4, 1, 2, 7, 8, 10000},
			cummulativeTSN: 0,
			result:         []gapAckBlock{{1, 4}, {7, 8}, {10000, 10000}},
		},
	}

	for i, tc := range tests {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			q := newReceivedPacketTracker()
			for _, t := range tc.chunks {
				q.push(t, 0)
			}
			res := q.getGapAckBlocks(tc.cummulativeTSN)
			require.Equal(t, tc.result, res)
		})
	}

}
