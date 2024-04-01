// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"fmt"
	"strings"
)

// receivedChunkTracker tracks received chunks for maintaining ACK ranges
type receivedChunkTracker struct {
	chunks map[uint32]struct{}
	dupTSN []uint32
	ranges []ackRange
}

// ackRange is a contiguous range of chunks that we have received
type ackRange struct {
	start uint32
	end   uint32
}

func newReceivedPacketTracker() *receivedChunkTracker {
	return &receivedChunkTracker{chunks: make(map[uint32]struct{})}
}

func (q *receivedChunkTracker) canPush(tsn uint32, cumulativeTSN uint32) bool {
	_, ok := q.chunks[tsn]
	if ok || sna32LTE(tsn, cumulativeTSN) {
		return false
	}
	return true
}

// push pushes a payload data. If the payload data is already in our queue or
// older than our cumulativeTSN marker, it will be recorded as duplications,
// which can later be retrieved using popDuplicates.
func (q *receivedChunkTracker) push(tsn uint32, cumulativeTSN uint32) bool {
	_, ok := q.chunks[tsn]
	if ok || sna32LTE(tsn, cumulativeTSN) {
		// Found the packet, log in dups
		q.dupTSN = append(q.dupTSN, tsn)
		return false
	}
	q.chunks[tsn] = struct{}{}

	insert := true
	var pos int
	for pos = len(q.ranges) - 1; pos >= 0; pos-- {
		if tsn == q.ranges[pos].end+1 {
			q.ranges[pos].end++
			insert = false
			break
		}
		if tsn == q.ranges[pos].start-1 {
			q.ranges[pos].start--
			insert = false
			break
		}
		if tsn > q.ranges[pos].end {
			break
		}
	}
	if insert {
		// pos is at the element just before the insertion point
		pos++
		q.ranges = append(q.ranges, ackRange{})
		copy(q.ranges[pos+1:], q.ranges[pos:])
		q.ranges[pos] = ackRange{start: tsn, end: tsn}
	} else {
		// extended element at pos, check if we can merge it with adjacent elements
		if pos-1 >= 0 {
			if q.ranges[pos-1].end+1 == q.ranges[pos].start {
				q.ranges[pos-1] = ackRange{
					start: q.ranges[pos-1].start,
					end:   q.ranges[pos].end,
				}
				copy(q.ranges[pos:], q.ranges[pos+1:])
				q.ranges = q.ranges[:len(q.ranges)-1]
				// We have merged pos and pos-1 in to pos-1, update pos to reflect that.
				// Not updating this won't be an error but it's nice to maintain the invariant
				pos--
			}
		}
		if pos+1 < len(q.ranges) {
			if q.ranges[pos+1].start-1 == q.ranges[pos].end {
				q.ranges[pos+1] = ackRange{
					start: q.ranges[pos].start,
					end:   q.ranges[pos+1].end,
				}
				copy(q.ranges[pos:], q.ranges[pos+1:])
				q.ranges = q.ranges[:len(q.ranges)-1]
			}
		}
	}
	return true
}

// pop pops only if the oldest chunk's TSN matches the given TSN.
func (q *receivedChunkTracker) pop(tsn uint32) bool {
	if len(q.ranges) == 0 || q.ranges[0].start != tsn {
		return false
	}
	q.ranges[0].start++
	if q.ranges[0].start > q.ranges[0].end {
		q.ranges = q.ranges[1:]
	}
	delete(q.chunks, tsn)
	return true
}

// popDuplicates returns an array of TSN values that were found duplicate.
func (q *receivedChunkTracker) popDuplicates() []uint32 {
	dups := q.dupTSN
	q.dupTSN = []uint32{}
	return dups
}

// receivedPacketTracker getGapACKBlocks returns gapAckBlocks after the cummulative TSN
func (q *receivedChunkTracker) getGapAckBlocks(cumulativeTSN uint32) []gapAckBlock {
	gapAckBlocks := make([]gapAckBlock, 0, len(q.ranges))
	for _, ar := range q.ranges {
		if ar.end > cumulativeTSN {
			st := ar.start
			if st < cumulativeTSN {
				st = cumulativeTSN + 1
			}
			gapAckBlocks = append(gapAckBlocks, gapAckBlock{
				start: uint16(st - cumulativeTSN),
				end:   uint16(ar.end - cumulativeTSN),
			})
		}
	}
	return gapAckBlocks
}

func (q *receivedChunkTracker) getGapAckBlocksString(cumulativeTSN uint32) string {
	gapAckBlocks := q.getGapAckBlocks(cumulativeTSN)
	sb := strings.Builder{}
	sb.WriteString(fmt.Sprintf("cumTSN=%d", cumulativeTSN))
	for _, b := range gapAckBlocks {
		sb.WriteString(fmt.Sprintf(",%d-%d", b.start, b.end))
	}
	return sb.String()
}

func (q *receivedChunkTracker) getLastTSNReceived() (uint32, bool) {
	if len(q.ranges) == 0 {
		return 0, false
	}
	return q.ranges[len(q.ranges)-1].end, true
}

func (q *receivedChunkTracker) size() int {
	return len(q.chunks)
}
