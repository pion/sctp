// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReceivePayloadQueue(t *testing.T) {
	maxOffset := uint32(512)
	payloadQueue := newReceivePayloadQueue(maxOffset)
	initTSN := uint32(math.MaxUint32 - 10)
	payloadQueue.init(initTSN - 2)
	assert.Equal(t, initTSN-2, payloadQueue.getcumulativeTSN())
	assert.Zero(t, payloadQueue.size())
	_, ok := payloadQueue.getLastTSNReceived()
	assert.False(t, ok)
	assert.Empty(t, payloadQueue.getGapAckBlocks())
	// force pop empy queue to advance cumulative TSN
	assert.False(t, payloadQueue.pop(true))
	assert.Equal(t, initTSN-1, payloadQueue.getcumulativeTSN())
	assert.Zero(t, payloadQueue.size())
	assert.Empty(t, payloadQueue.getGapAckBlocks())

	nextTSN := initTSN + maxOffset - 1
	assert.True(t, payloadQueue.push(nextTSN))
	assert.Equal(t, 1, payloadQueue.size())
	lastTSN, ok := payloadQueue.getLastTSNReceived()
	assert.True(t, lastTSN == nextTSN && ok, "lastTSN:%d, ok:%t", lastTSN, ok)
	assert.True(t, payloadQueue.hasChunk(nextTSN))

	assert.True(t, payloadQueue.push(initTSN))
	assert.False(t, payloadQueue.canPush(initTSN-1))
	assert.False(t, payloadQueue.canPush(initTSN+maxOffset))
	assert.False(t, payloadQueue.push(initTSN+maxOffset))
	assert.True(t, payloadQueue.canPush(nextTSN-1))
	assert.Equal(t, 2, payloadQueue.size())

	gaps := payloadQueue.getGapAckBlocks()
	assert.EqualValues(t, []gapAckBlock{
		{start: uint16(1), end: uint16(1)},
		{start: uint16(maxOffset), end: uint16(maxOffset)},
	}, gaps)

	assert.True(t, payloadQueue.pop(false))
	assert.Equal(t, 1, payloadQueue.size())
	assert.Equal(t, initTSN, payloadQueue.cumulativeTSN)
	assert.False(t, payloadQueue.pop(false))
	assert.Equal(t, initTSN, payloadQueue.cumulativeTSN)

	size := payloadQueue.size()
	// push tsn with two gap
	// tsnRange [[start,end]...]
	tsnRange := [][]uint32{
		{initTSN + 5, initTSN + 6},
		{initTSN + 9, initTSN + 140},
	}
	range0, range1 := tsnRange[0], tsnRange[1]
	for tsn := range0[0]; sna32LTE(tsn, range0[1]); tsn++ {
		assert.True(t, payloadQueue.push(tsn))
		assert.False(t, payloadQueue.pop(false))
		assert.True(t, payloadQueue.hasChunk(tsn))
	}
	size += int(range0[1] - range0[0] + 1)

	for tsn := range1[0]; sna32LTE(tsn, range1[1]); tsn++ {
		assert.True(t, payloadQueue.push(tsn))
		assert.False(t, payloadQueue.pop(false))
		assert.True(t, payloadQueue.hasChunk(tsn))
	}
	size += int(range1[1] - range1[0] + 1)

	assert.Equal(t, size, payloadQueue.size())
	gaps = payloadQueue.getGapAckBlocks()
	assert.EqualValues(t, []gapAckBlock{
		//nolint:gosec // G115
		{start: uint16(range0[0] - initTSN), end: uint16(range0[1] - initTSN)},
		//nolint:gosec // G115
		{start: uint16(range1[0] - initTSN), end: uint16(range1[1] - initTSN)},
		//nolint:gosec // G115
		{start: uint16(nextTSN - initTSN), end: uint16(nextTSN - initTSN)},
	}, gaps)

	// push duplicate tsns
	assert.False(t, payloadQueue.push(initTSN-2))
	assert.False(t, payloadQueue.push(range0[0]))
	assert.False(t, payloadQueue.push(range0[0]))
	assert.False(t, payloadQueue.push(nextTSN))
	assert.False(t, payloadQueue.push(initTSN+maxOffset+1))
	duplicates := payloadQueue.popDuplicates()
	assert.EqualValues(t, []uint32{initTSN - 2, range0[0], range0[0], nextTSN}, duplicates)

	// force pop to advance cumulativeTSN to fill the gap [initTSN, initTSN+4]
	for tsn := initTSN + 1; sna32LT(tsn, range0[0]); tsn++ {
		assert.False(t, payloadQueue.pop(true))
		assert.Equal(t, size, payloadQueue.size())
		assert.Equal(t, tsn, payloadQueue.cumulativeTSN)
	}

	for tsn := range0[0]; sna32LTE(tsn, range0[1]); tsn++ {
		assert.True(t, payloadQueue.pop(false))
		assert.Equal(t, tsn, payloadQueue.getcumulativeTSN())
	}
	assert.False(t, payloadQueue.pop(false))
	cumulativeTSN := payloadQueue.getcumulativeTSN()
	assert.Equal(t, range0[1], cumulativeTSN)
	gaps = payloadQueue.getGapAckBlocks()
	assert.EqualValues(t, []gapAckBlock{
		//nolint:gosec // G115
		{start: uint16(range1[0] - range0[1]), end: uint16(range1[1] - range0[1])},
		//nolint:gosec // G115
		{start: uint16(nextTSN - range0[1]), end: uint16(nextTSN - range0[1])},
	}, gaps)

	// fill the gap with received tsn
	for tsn := range0[1] + 1; sna32LT(tsn, range1[0]); tsn++ {
		assert.True(t, payloadQueue.push(tsn), tsn)
	}
	for tsn := range0[1] + 1; sna32LTE(tsn, range1[1]); tsn++ {
		assert.True(t, payloadQueue.pop(false))
		assert.Equal(t, tsn, payloadQueue.getcumulativeTSN())
	}
	assert.False(t, payloadQueue.pop(false))
	assert.Equal(t, range1[1], payloadQueue.getcumulativeTSN())
	gaps = payloadQueue.getGapAckBlocks()
	assert.EqualValues(t, []gapAckBlock{
		//nolint:gosec // G115
		{start: uint16(nextTSN - range1[1]), end: uint16(nextTSN - range1[1])},
	}, gaps)

	// gap block cross end tsn
	endTSN := maxOffset - 1
	for tsn := nextTSN + 1; sna32LTE(tsn, endTSN); tsn++ {
		assert.True(t, payloadQueue.push(tsn))
	}
	gaps = payloadQueue.getGapAckBlocks()
	assert.EqualValues(t, []gapAckBlock{
		//nolint:gosec // G115
		{start: uint16(nextTSN - range1[1]), end: uint16(endTSN - range1[1])},
	}, gaps)

	assert.NotEmpty(t, payloadQueue.getGapAckBlocksString())
}

func TestBitfunc(t *testing.T) {
	idx, ok := getFirstNonZeroBit(0xf, 0, 20)
	assert.True(t, ok)
	assert.Equal(t, 0, idx)
	_, ok = getFirstNonZeroBit(0xf<<20, 0, 20)
	assert.False(t, ok)
	idx, ok = getFirstNonZeroBit(0xf<<20, 5, 25)
	assert.True(t, ok)
	assert.Equal(t, 20, idx)
	_, ok = getFirstNonZeroBit(0xf<<20, 30, 40)
	assert.False(t, ok)
	_, ok = getFirstNonZeroBit(0, 0, 64)
	assert.False(t, ok)

	idx, ok = getFirstZeroBit(0xf, 0, 20)
	assert.True(t, ok)
	assert.Equal(t, 4, idx)
	idx, ok = getFirstZeroBit(0xf<<20, 0, 20)
	assert.True(t, ok)
	assert.Equal(t, 0, idx)
	_, ok = getFirstZeroBit(0xf<<20, 20, 24)
	assert.False(t, ok)
	idx, ok = getFirstZeroBit(0xf<<20, 30, 40)
	assert.True(t, ok)
	assert.Equal(t, 30, idx)
	_, ok = getFirstZeroBit(math.MaxUint64, 0, 64)
	assert.False(t, ok)
}
