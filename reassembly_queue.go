// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"errors"
	"io"
	"sort"
	"sync/atomic"
)

func sortChunksByTSN(a []*chunkPayloadData) {
	sort.Slice(a, func(i, j int) bool {
		return sna32LT(a[i].tsn, a[j].tsn)
	})
}

// chunkSet is a set of chunks that share the same SSN.
type chunkSet struct {
	ssn    uint16 // used only with the ordered chunks
	ppi    PayloadProtocolIdentifier
	chunks []*chunkPayloadData
}

func newChunkSet(ssn uint16, ppi PayloadProtocolIdentifier) *chunkSet {
	return &chunkSet{
		ssn:    ssn,
		ppi:    ppi,
		chunks: []*chunkPayloadData{},
	}
}

func (set *chunkSet) push(chunk *chunkPayloadData) bool {
	// Enforce same PPI for all fragments of a user message (deliver one PPI). RFC 9260 sec 6.9.
	if chunk.payloadType != set.ppi {
		return false
	}

	// check if dup
	for _, c := range set.chunks {
		if c.tsn == chunk.tsn {
			return false
		}
	}

	// append and sort
	set.chunks = append(set.chunks, chunk)
	sortChunksByTSN(set.chunks)

	// Check if we now have a complete set
	return set.isComplete()
}

func (set *chunkSet) isComplete() bool {
	// Complete when:
	//   0) has at least one fragment
	//   1) first has beginningFragment=1, endingFragment=0
	//   2) last  has beginningFragment=0, endingFragment=1
	//   3) all TSNs are strictly sequential (monotonically increasing) RFC 9260 sec 6.9
	nChunks := len(set.chunks)
	if nChunks == 0 {
		return false
	}

	// 1.
	if !set.chunks[0].beginningFragment {
		return false
	}

	// 2.
	if !set.chunks[nChunks-1].endingFragment {
		return false
	}

	// 3.
	var lastTSN uint32
	for i, chunk := range set.chunks {
		if i > 0 {
			// RFC 9260 sec 3.3.1:
			// When a user message is fragmented into multiple chunks, the TSNs are
			// used by the receiver to reassemble the message. This means that the
			// TSNs for each fragment of a fragmented user message MUST be strictly
			// sequential.
			if chunk.tsn != lastTSN+1 {
				// mid or end fragment is missing
				return false
			}
		}

		lastTSN = chunk.tsn
	}

	return true
}

type reassemblyQueue struct {
	si      uint16
	nextSSN uint16 // expected SSN for next ordered message RFC 9260 sec 6.5, 6.6

	ordered []*chunkSet
	// Fast lookup for fragmented ordered messages by SSN (cleared once complete).
	orderedIndex map[uint16]*chunkSet

	unordered []*chunkSet
	// Fast duplicate filter for unordered chunks by TSN.
	unorderedIndex  map[uint32]*chunkPayloadData
	unorderedChunks []*chunkPayloadData

	nBytes uint64
}

var errTryAgain = errors.New("try again")

func newReassemblyQueue(si uint16) *reassemblyQueue {
	// From RFC 9260 sec 6.5:
	// The Stream Sequence Number in all the outgoing streams MUST start from 0 when
	// the association is established. The Stream Sequence Number of an outgoing
	// stream MUST be incremented by 1 for each ordered user message sent on that
	// outgoing stream. In particular, when the Stream Sequence Number reaches the
	// value 65535, the next Stream Sequence Number MUST be set to 0. For unordered
	// user messages, the Stream Sequence Number MUST NOT be changed.
	return &reassemblyQueue{
		si:             si,
		nextSSN:        0, // From RFC 9260 Sec 6.5:
		ordered:        make([]*chunkSet, 0),
		orderedIndex:   make(map[uint16]*chunkSet),
		unordered:      make([]*chunkSet, 0),
		unorderedIndex: make(map[uint32]*chunkPayloadData),
	}
}

// insertChunkByTSN keeps r.unorderedChunks sorted by TSN with a binary insertion.
func (r *reassemblyQueue) insertChunkByTSN(chunk *chunkPayloadData) {
	lo, hi := 0, len(r.unorderedChunks)
	for lo < hi {
		mid := (lo + hi) >> 1
		if sna32LT(r.unorderedChunks[mid].tsn, chunk.tsn) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}

	r.unorderedChunks = append(r.unorderedChunks, nil)
	copy(r.unorderedChunks[lo+1:], r.unorderedChunks[lo:])
	r.unorderedChunks[lo] = chunk
}

// insertSetBySSN keeps r.ordered sorted by SSN.
func (r *reassemblyQueue) insertSetBySSN(cs *chunkSet) {
	lo, hi := 0, len(r.ordered)
	for lo < hi {
		mid := (lo + hi) >> 1
		if sna16LT(r.ordered[mid].ssn, cs.ssn) {
			lo = mid + 1
		} else {
			hi = mid
		}
	}

	r.ordered = append(r.ordered, nil)
	copy(r.ordered[lo+1:], r.ordered[lo:])
	r.ordered[lo] = cs
}

func (r *reassemblyQueue) push(chunk *chunkPayloadData) bool { //nolint:cyclop
	var cset *chunkSet

	if chunk.streamIdentifier != r.si {
		return false
	}

	if chunk.unordered {
		// O(1) duplicate filter by TSN.
		if _, dup := r.unorderedIndex[chunk.tsn]; dup {
			return false
		}
		r.unorderedIndex[chunk.tsn] = chunk

		// Maintain TSN order without full re-sort each time.
		r.insertChunkByTSN(chunk)
		atomic.AddUint64(&r.nBytes, uint64(len(chunk.userData)))

		// Scan unorderedChunks that are contiguous (in TSN)
		cset = r.findCompleteUnorderedChunkSet()

		// If found, append the complete set to the unordered array
		if cset != nil {
			r.unordered = append(r.unordered, cset)

			return true
		}

		return false
	}

	// This is an ordered chunk
	if sna16LT(chunk.streamSequenceNumber, r.nextSSN) {
		return false
	}

	// Check if a fragmented chunkSet with the fragmented SSN already exists
	if chunk.isFragmented() {
		// O(1) lookup of an in-progress fragmented set.
		if set, ok := r.orderedIndex[chunk.streamSequenceNumber]; ok && len(set.chunks) > 0 && set.chunks[0].isFragmented() {
			cset = set
		}
	}

	// If not found, create a new chunkSet
	if cset == nil {
		cset = newChunkSet(chunk.streamSequenceNumber, chunk.payloadType)
		// Index only fragmented sequences, single-chunk messages don't need lookup.
		if chunk.isFragmented() {
			r.orderedIndex[cset.ssn] = cset
		}
		r.insertSetBySSN(cset)
	}

	atomic.AddUint64(&r.nBytes, uint64(len(chunk.userData)))

	complete := cset.push(chunk)
	if complete && chunk.isFragmented() {
		// No more fragments will be added, drop from index.
		delete(r.orderedIndex, cset.ssn)
	}

	return complete
}

func (r *reassemblyQueue) findCompleteUnorderedChunkSet() *chunkSet {
	startIdx := -1
	nChunks := 0
	var lastTSN uint32
	var ppi PayloadProtocolIdentifier
	var found bool

	for i, chunk := range r.unorderedChunks {
		// look for a beginning fragment
		if chunk.beginningFragment {
			startIdx = i
			nChunks = 1
			lastTSN = chunk.tsn
			ppi = chunk.payloadType

			if chunk.endingFragment {
				found = true

				break
			}

			continue
		}

		if startIdx < 0 {
			continue
		}

		// same PPI and strictly contiguous TSN required across fragments. RFC 9260 sec 6.9.
		if chunk.payloadType != ppi || chunk.tsn != lastTSN+1 {
			startIdx = -1

			continue
		}

		lastTSN = chunk.tsn
		nChunks++

		if chunk.endingFragment {
			found = true

			break
		}
	}

	if !found {
		return nil
	}

	// Extract the contiguous range [startIdx, startIdx+nChunks)
	chunks := append([]*chunkPayloadData(nil), r.unorderedChunks[startIdx:startIdx+nChunks]...)

	// Remove them from unorderedChunks
	r.unorderedChunks = append(
		r.unorderedChunks[:startIdx],
		r.unorderedChunks[startIdx+nChunks:]...)

	// Drop from index (all these TSNs are now consumed into a complete set).
	for _, c := range chunks {
		delete(r.unorderedIndex, c.tsn)
	}

	chunkSet := newChunkSet(0, chunks[0].payloadType) // SSN ignored for unordered (RFC 9260 sec 6.6)
	chunkSet.chunks = chunks

	return chunkSet
}

func (r *reassemblyQueue) isReadable() bool {
	// Unordered messages can be delivered as soon as a complete set exists. RFC 9260 sec 6.6.
	if len(r.unordered) > 0 {
		// The chunk sets in r.unordered should all be complete.
		return true
	}

	// Ordered delivery: only the complete set whose SSN == nextSSN is eligible. RFC 9260 sec 6.6.
	if len(r.ordered) > 0 {
		cset := r.ordered[0]
		if cset.isComplete() && sna16LTE(cset.ssn, r.nextSSN) {
			return true
		}
	}

	return false
}

func (r *reassemblyQueue) read(buf []byte) (int, PayloadProtocolIdentifier, error) { // nolint: cyclop
	var (
		cset        *chunkSet
		isUnordered bool
		nTotal      int
		err         error
	)

	switch {
	case len(r.unordered) > 0:
		cset = r.unordered[0]
		isUnordered = true
	case len(r.ordered) > 0:
		cset = r.ordered[0]

		if !cset.isComplete() {
			return 0, 0, errTryAgain
		}

		// For ordered, gate on exact SSN == nextSSN (hold higher SSNs). RFC 9260 sec 6.6.
		if sna16GT(cset.ssn, r.nextSSN) {
			return 0, 0, errTryAgain
		}
	default:
		return 0, 0, errTryAgain
	}

	for _, c := range cset.chunks {
		if len(buf)-nTotal < len(c.userData) {
			err = io.ErrShortBuffer
		} else {
			copy(buf[nTotal:], c.userData)
		}

		nTotal += len(c.userData)
	}

	switch {
	case err != nil:
		return nTotal, 0, err
	case isUnordered:
		r.unordered = r.unordered[1:]
	default:
		r.ordered = r.ordered[1:]

		// Advance only when we delivered the exact expected SSN
		if cset.ssn == r.nextSSN {
			r.nextSSN++
		}
	}

	r.subtractNumBytes(nTotal)

	return nTotal, cset.ppi, err
}

func (r *reassemblyQueue) forwardTSNForOrdered(lastSSN uint16) {
	// Only drop sets that are <= lastSSN and NOT complete (abandoned).
	keep := r.ordered[:0]
	for _, set := range r.ordered {
		if sna16LTE(set.ssn, lastSSN) && !set.isComplete() {
			// drop the set
			for _, c := range set.chunks {
				r.subtractNumBytes(len(c.userData))
			}

			// ensure index is clean too
			delete(r.orderedIndex, set.ssn)

			continue
		}
		keep = append(keep, set)
	}
	r.ordered = keep

	// Finally, forward nextSSN
	if sna16LTE(r.nextSSN, lastSSN) {
		r.nextSSN = lastSSN + 1
	}
}

func (r *reassemblyQueue) forwardTSNForUnordered(newCumulativeTSN uint32) {
	// Remove all fragments in the unordered sets that contains chunks
	// equal to or older than `newCumulativeTSN`.
	// We know all sets in the r.unordered are complete ones.
	// Just remove chunks that are equal to or older than newCumulativeTSN
	// from the unorderedChunks
	lastIdx := -1
	for i, c := range r.unorderedChunks {
		if sna32GT(c.tsn, newCumulativeTSN) {
			break
		}
		lastIdx = i
	}

	if lastIdx >= 0 {
		for _, c := range r.unorderedChunks[0 : lastIdx+1] {
			r.subtractNumBytes(len(c.userData))
			delete(r.unorderedIndex, c.tsn)
		}
		r.unorderedChunks = r.unorderedChunks[lastIdx+1:]
	}
}

func (r *reassemblyQueue) subtractNumBytes(nBytes int) {
	cur := atomic.LoadUint64(&r.nBytes)
	if int(cur) >= nBytes { //nolint:gosec // G115
		atomic.AddUint64(&r.nBytes, -uint64(nBytes)) //nolint:gosec // G115
	} else {
		atomic.StoreUint64(&r.nBytes, 0)
	}
}

func (r *reassemblyQueue) getNumBytes() int {
	return int(atomic.LoadUint64(&r.nBytes)) //nolint:gosec // G115
}
