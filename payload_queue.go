// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

type payloadQueue struct {
	chunkMap map[uint32]*chunkPayloadData
	tsns     []uint32
	nBytes   int
}

func newPayloadQueue() *payloadQueue {
	return &payloadQueue{chunkMap: map[uint32]*chunkPayloadData{}}
}

func (q *payloadQueue) push(p *chunkPayloadData) {
	if _, ok := q.chunkMap[p.tsn]; ok {
		return
	}
	q.chunkMap[p.tsn] = p
	q.nBytes += len(p.userData)
	var pos int
	for pos = len(q.tsns) - 1; pos >= 0; pos-- {
		if q.tsns[pos] < p.tsn {
			break
		}
	}
	pos++
	q.tsns = append(q.tsns, 0)
	copy(q.tsns[pos+1:], q.tsns[pos:])
	q.tsns[pos] = p.tsn
}

// pop pops only if the oldest chunk's TSN matches the given TSN.
func (q *payloadQueue) pop(tsn uint32) (*chunkPayloadData, bool) {
	if len(q.tsns) == 0 || q.tsns[0] != tsn {
		return nil, false
	}
	q.tsns = q.tsns[1:]
	if c, ok := q.chunkMap[tsn]; ok {
		delete(q.chunkMap, tsn)
		q.nBytes -= len(c.userData)
		return c, true
	}
	return nil, false
}

// get returns reference to chunkPayloadData with the given TSN value.
func (q *payloadQueue) get(tsn uint32) (*chunkPayloadData, bool) {
	c, ok := q.chunkMap[tsn]
	return c, ok
}

func (q *payloadQueue) markAsAcked(tsn uint32) int {
	var nBytesAcked int
	if c, ok := q.chunkMap[tsn]; ok {
		c.acked = true
		c.retransmit = false
		nBytesAcked = len(c.userData)
		q.nBytes -= nBytesAcked
		c.userData = []byte{}
	}

	return nBytesAcked
}

func (q *payloadQueue) markAllToRetrasmit() {
	for _, c := range q.chunkMap {
		if c.acked || c.abandoned() {
			continue
		}
		c.retransmit = true
	}
}

func (q *payloadQueue) getNumBytes() int {
	return q.nBytes
}

func (q *payloadQueue) size() int {
	return len(q.chunkMap)
}
