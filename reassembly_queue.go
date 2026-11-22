// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"errors"
	"io"
	"slices"
	"sort"
	"sync/atomic"
)

func sortChunksByTSN(a []*chunkPayloadData) {
	sort.Slice(a, func(i, j int) bool {
		return sna32LT(a[i].tsn, a[j].tsn)
	})
}

func sortChunksByFSN(a []*chunkPayloadData) {
	sort.Slice(a, func(i, j int) bool {
		return sna32LT(a[i].fragmentSequenceNumber, a[j].fragmentSequenceNumber)
	})
}

func insertChunkSetByMID(a []*chunkSetMID, cset *chunkSetMID) []*chunkSetMID {
	insertAt := sort.Search(len(a), func(i int) bool {
		return !sna32LT(a[i].mid, cset.mid)
	})

	a = append(a, nil)
	copy(a[insertAt+1:], a[insertAt:])
	a[insertAt] = cset

	return a
}

// chunkSet is a set of chunks that share the same SSN.
type chunkSet struct {
	ssn    uint16 // used only with the ordered chunks
	chunks []*chunkPayloadData
}

func newChunkSet(ssn uint16) *chunkSet {
	return &chunkSet{
		ssn:    ssn,
		chunks: []*chunkPayloadData{},
	}
}

func (set *chunkSet) push(chunk *chunkPayloadData) bool {
	// check if dup
	if set.hasTSN(chunk.tsn) {
		return false
	}

	return set.pushNoDuplicate(chunk)
}

func (set *chunkSet) pushNoDuplicate(chunk *chunkPayloadData) bool {
	// append and sort
	set.chunks = append(set.chunks, chunk)
	sortChunksByTSN(set.chunks)

	// Check if we now have a complete set
	return set.isComplete()
}

func (set *chunkSet) hasTSN(tsn uint32) bool {
	for _, c := range set.chunks {
		if c.tsn == tsn {
			return true
		}
	}

	return false
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

// chunkSetMID is a set of chunks that share the same MID.
type chunkSetMID struct {
	mid    uint32
	ppi    PayloadProtocolIdentifier
	chunks []*chunkPayloadData
}

func newChunkSetMID(mid uint32, ppi PayloadProtocolIdentifier) *chunkSetMID {
	return &chunkSetMID{
		mid:    mid,
		ppi:    ppi,
		chunks: []*chunkPayloadData{},
	}
}

func (set *chunkSetMID) pushAndCheck(chunk *chunkPayloadData) (complete bool, accepted bool) {
	if set.isComplete() {
		return false, false
	}

	for _, c := range set.chunks {
		if c.fragmentSequenceNumber == chunk.fragmentSequenceNumber {
			return false, false
		}
	}

	set.chunks = append(set.chunks, chunk)
	if chunk.beginningFragment {
		set.ppi = chunk.payloadType
	}
	sortChunksByFSN(set.chunks)

	return set.isComplete(), true
}

func (set *chunkSetMID) isComplete() bool {
	nChunks := len(set.chunks)
	if nChunks == 0 {
		return false
	}

	if !set.chunks[0].beginningFragment {
		return false
	}

	if !set.chunks[nChunks-1].endingFragment {
		return false
	}

	if set.chunks[0].fragmentSequenceNumber != 0 {
		return false
	}

	lastFSN := set.chunks[0].fragmentSequenceNumber
	for i, chunk := range set.chunks {
		if i > 0 {
			if chunk.fragmentSequenceNumber != lastFSN+1 {
				return false
			}
		}
		lastFSN = chunk.fragmentSequenceNumber
	}

	return true
}

type reassemblyQueue struct {
	si              uint16
	nextSSN         uint16 // expected SSN for next ordered message RFC 9260 sec 6.5, 6.6
	nextMID         uint32 // expected MID for next ordered I-DATA
	ordered         []*chunkSet
	orderedIndex    map[uint16]*chunkSet // Fragmented sets, including those ready to read.
	unordered       []*chunkSet
	unorderedIndex  map[uint32]*chunkPayloadData
	unorderedChunks []*chunkPayloadData
	orderedMID      []*chunkSetMID
	unorderedMID    []*chunkSetMID
	orderedMIDMap   map[uint32]*chunkSetMID
	unorderedMIDMap map[uint32]*chunkSetMID
	useInterleaving bool
	nBytes          uint64
	maxEntries      uint32
}

var (
	errTryAgain = errors.New("try again")

	errReassemblyQueueLimitExceeded = errors.New("reassembly queue data limit exceeded")

	errReassemblyQueueMIDLimitExceeded = errors.New("reassembly queue i-data message identifier limit exceeded")
)

func newReassemblyQueue(si uint16, maxEntries uint32) *reassemblyQueue {
	// From RFC 9260 sec 6.5:
	// The Stream Sequence Number in all the outgoing streams MUST start from 0 when
	// the association is established. The Stream Sequence Number of an outgoing
	// stream MUST be incremented by 1 for each ordered user message sent on that
	// outgoing stream. In particular, when the Stream Sequence Number reaches the
	// value 65535, the next Stream Sequence Number MUST be set to 0. For unordered
	// user messages, the Stream Sequence Number MUST NOT be changed.
	return &reassemblyQueue{
		si:              si,
		nextSSN:         0,
		nextMID:         0,
		ordered:         make([]*chunkSet, 0),
		unordered:       make([]*chunkSet, 0),
		orderedMID:      make([]*chunkSetMID, 0),
		unorderedMID:    make([]*chunkSetMID, 0),
		orderedMIDMap:   map[uint32]*chunkSetMID{},
		unorderedMIDMap: map[uint32]*chunkSetMID{},
		orderedIndex:    make(map[uint16]*chunkSet),
		unorderedIndex:  make(map[uint32]*chunkPayloadData),
		maxEntries:      maxEntries,
	}
}

func isReassemblyQueueLimitReached(maxEntries uint32, nEntries int) bool {
	return maxEntries > 0 && int64(nEntries) >= int64(maxEntries)
}

func (r *reassemblyQueue) isDataLimitReached(nEntries int) bool {
	return isReassemblyQueueLimitReached(r.maxEntries, nEntries)
}

func (r *reassemblyQueue) hasDataLimit() bool {
	return r.maxEntries > 0
}

func (r *reassemblyQueue) isMIDLimitReached(nEntries int) bool {
	return isReassemblyQueueLimitReached(r.maxEntries, nEntries)
}

func (r *reassemblyQueue) orderedDataEntryCount() int {
	nEntries := 0
	for _, set := range r.ordered {
		nEntries += len(set.chunks)
	}

	return nEntries
}

func (r *reassemblyQueue) unorderedDataEntryCount() int {
	nEntries := len(r.unorderedChunks)
	for _, set := range r.unordered {
		nEntries += len(set.chunks)
	}

	return nEntries
}

func (r *reassemblyQueue) push(chunk *chunkPayloadData) bool {
	complete, _ := r.pushWithError(chunk)

	return complete
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

func (r *reassemblyQueue) pushWithError(chunk *chunkPayloadData) (bool, error) { //nolint:cyclop
	var cset *chunkSet

	if chunk.isIData() {
		r.useInterleaving = true

		return r.pushIData(chunk)
	}

	if chunk.streamIdentifier != r.si {
		return false, nil
	}

	if chunk.unordered {
		// O(1) duplicate filter by TSN.
		if _, dup := r.unorderedIndex[chunk.tsn]; dup {
			return false, nil
		}

		if r.hasDataLimit() && r.isDataLimitReached(r.unorderedDataEntryCount()) {
			return false, errReassemblyQueueLimitExceeded
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

			return true, nil
		}

		return false, nil
	}

	// This is an ordered chunk
	if sna16LT(chunk.streamSequenceNumber, r.nextSSN) {
		return false, nil
	}

	// Check if a fragmented chunkSet with the fragmented SSN already exists
	if chunk.isFragmented() {
		// O(1) lookup of a queued fragmented set.
		if set, ok := r.orderedIndex[chunk.streamSequenceNumber]; ok && len(set.chunks) > 0 && set.chunks[0].isFragmented() {
			cset = set
		}
	}

	// Reject a new queued DATA entry once the descriptor cap is reached.
	if cset != nil && cset.hasTSN(chunk.tsn) {
		return false, nil
	}
	if r.hasDataLimit() && r.isDataLimitReached(r.orderedDataEntryCount()) {
		return false, errReassemblyQueueLimitExceeded
	}
	if cset == nil {
		cset = newChunkSet(chunk.streamSequenceNumber)
		// Index only fragmented sequences, single-chunk messages don't need lookup.
		if chunk.isFragmented() {
			r.orderedIndex[cset.ssn] = cset
		}
		r.insertSetBySSN(cset)
	}

	atomic.AddUint64(&r.nBytes, uint64(len(chunk.userData)))

	return cset.push(chunk), nil
}

func (r *reassemblyQueue) pushIData(chunk *chunkPayloadData) (bool, error) {
	if chunk.streamIdentifier != r.si {
		return false, nil
	}

	if chunk.unordered {
		return r.pushUnorderedIData(chunk)
	}

	return r.pushOrderedIData(chunk)
}

func (r *reassemblyQueue) pushUnorderedIData(chunk *chunkPayloadData) (bool, error) {
	if r.hasQueuedUnorderedMID(chunk.messageIdentifier) {
		return false, nil
	}

	if r.unorderedMIDMap == nil {
		r.unorderedMIDMap = map[uint32]*chunkSetMID{}
	}
	cset := r.unorderedMIDMap[chunk.messageIdentifier]
	if cset == nil {
		if r.isMIDLimitReached(r.unorderedMIDEntryCount()) {
			return false, errReassemblyQueueMIDLimitExceeded
		}
		cset = newChunkSetMID(chunk.messageIdentifier, chunk.payloadType)
		r.unorderedMIDMap[chunk.messageIdentifier] = cset
	}

	complete, accepted := cset.pushAndCheck(chunk)
	if !accepted {
		return false, nil
	}

	atomic.AddUint64(&r.nBytes, uint64(len(chunk.userData)))
	if complete {
		delete(r.unorderedMIDMap, chunk.messageIdentifier)
		r.unorderedMID = append(r.unorderedMID, cset)

		return true, nil
	}

	return false, nil
}

func (r *reassemblyQueue) pushOrderedIData(chunk *chunkPayloadData) (bool, error) {
	if sna32LT(chunk.messageIdentifier, r.nextMID) {
		return false, nil
	}

	if r.orderedMIDMap == nil {
		r.orderedMIDMap = map[uint32]*chunkSetMID{}
	}
	cset := r.orderedMIDMap[chunk.messageIdentifier]
	if cset == nil {
		if r.isMIDLimitReached(len(r.orderedMIDMap)) {
			return false, errReassemblyQueueMIDLimitExceeded
		}
		cset = newChunkSetMID(chunk.messageIdentifier, chunk.payloadType)
		r.orderedMIDMap[chunk.messageIdentifier] = cset
		r.orderedMID = insertChunkSetByMID(r.orderedMID, cset)
	}

	complete, accepted := cset.pushAndCheck(chunk)
	if !accepted {
		return false, nil
	}

	atomic.AddUint64(&r.nBytes, uint64(len(chunk.userData)))

	return complete, nil
}

func (r *reassemblyQueue) unorderedMIDEntryCount() int {
	return len(r.unorderedMIDMap) + len(r.unorderedMID)
}

func (r *reassemblyQueue) hasQueuedUnorderedMID(mid uint32) bool {
	for _, set := range r.unorderedMID {
		if set.mid == mid {
			return true
		}
	}

	return false
}

func (r *reassemblyQueue) findCompleteUnorderedChunkSet() *chunkSet {
	startIdx := -1
	nChunks := 0
	var lastTSN uint32
	var found bool

	for i, chunk := range r.unorderedChunks {
		// look for a beginning fragment
		if chunk.beginningFragment {
			startIdx = i
			nChunks = 1
			lastTSN = chunk.tsn

			if chunk.endingFragment {
				found = true

				break
			}

			continue
		}

		if startIdx < 0 {
			continue
		}

		if chunk.tsn != lastTSN+1 {
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

	chunks := slices.Clone(r.unorderedChunks[startIdx : startIdx+nChunks])
	r.unorderedChunks = slices.Delete(r.unorderedChunks, startIdx, startIdx+nChunks)
	for _, chunk := range chunks {
		delete(r.unorderedIndex, chunk.tsn)
	}

	return &chunkSet{chunks: chunks}
}

func (r *reassemblyQueue) isReadable() bool {
	if r.useInterleaving {
		if len(r.unorderedMID) > 0 {
			return true
		}
		if len(r.orderedMID) > 0 {
			cset := r.orderedMID[0]
			if cset.isComplete() && sna32LTE(cset.mid, r.nextMID) {
				return true
			}
		}

		return false
	}

	// Unordered messages can be delivered as soon as a complete set exists. RFC 9260 sec 6.6.
	if len(r.unordered) > 0 {
		// The chunk sets in r.unordered should all be complete.
		return true
	}

	// FORWARD-TSN can leave complete messages with an SSN before nextSSN.
	if len(r.ordered) > 0 {
		cset := r.ordered[0]
		if cset.isComplete() && sna16LTE(cset.ssn, r.nextSSN) {
			return true
		}
	}

	return false
}

func (r *reassemblyQueue) read(buf []byte) (int, PayloadProtocolIdentifier, error) { // nolint: cyclop,gocognit
	var (
		cset        *chunkSet
		isUnordered bool
		nTotal      int
		err         error
	)

	if r.useInterleaving { //nolint:nestif
		var iSet *chunkSetMID
		switch {
		case len(r.unorderedMID) > 0:
			iSet = r.unorderedMID[0]
			isUnordered = true
		case len(r.orderedMID) > 0:
			iSet = r.orderedMID[0]
			if !iSet.isComplete() {
				return 0, 0, errTryAgain
			}
			if sna32GT(iSet.mid, r.nextMID) {
				return 0, 0, errTryAgain
			}
		default:
			return 0, 0, errTryAgain
		}

		for _, c := range iSet.chunks {
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
			r.unorderedMID = r.unorderedMID[1:]
		default:
			r.orderedMID = r.orderedMID[1:]
			delete(r.orderedMIDMap, iSet.mid)
			if iSet.mid == r.nextMID {
				r.nextMID++
			}
		}

		r.subtractNumBytes(nTotal)

		return nTotal, iSet.ppi, err
	}

	switch {
	case len(r.unordered) > 0:
		cset = r.unordered[0]
		isUnordered = true
	case len(r.ordered) > 0:
		cset = r.ordered[0]

		if !cset.isComplete() {
			return 0, 0, errTryAgain
		}

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
		r.unordered[0] = nil
		r.unordered = r.unordered[1:]
	default:
		if r.orderedIndex[cset.ssn] == cset {
			delete(r.orderedIndex, cset.ssn)
		}
		r.ordered[0] = nil
		r.ordered = r.ordered[1:]

		if cset.ssn == r.nextSSN {
			r.nextSSN++
		}
	}

	r.subtractNumBytes(nTotal)

	// Use the PPID from the beginning fragment regardless of arrival order.
	return nTotal, cset.chunks[0].payloadType, nil
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

			delete(r.orderedIndex, set.ssn)

			continue
		}
		keep = append(keep, set)
	}
	clear(r.ordered[len(keep):])
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
		dropped := r.unorderedChunks[:lastIdx+1]
		for _, c := range dropped {
			r.subtractNumBytes(len(c.userData))
			delete(r.unorderedIndex, c.tsn)
		}
		clear(dropped)
		r.unorderedChunks = r.unorderedChunks[lastIdx+1:]
	}
}

func (r *reassemblyQueue) forwardTSNForOrderedMID(lastMID uint32) {
	keep := []*chunkSetMID{}
	for _, set := range r.orderedMID {
		if sna32LTE(set.mid, lastMID) {
			if !set.isComplete() {
				for _, c := range set.chunks {
					r.subtractNumBytes(len(c.userData))
				}
				delete(r.orderedMIDMap, set.mid)

				continue
			}
		}
		keep = append(keep, set)
	}
	r.orderedMID = keep

	if sna32LTE(r.nextMID, lastMID) {
		r.nextMID = lastMID + 1
	}
}

func (r *reassemblyQueue) forwardTSNForUnorderedMID(lastMID uint32) {
	for mid, set := range r.unorderedMIDMap {
		if sna32LTE(mid, lastMID) {
			for _, c := range set.chunks {
				r.subtractNumBytes(len(c.userData))
			}
			delete(r.unorderedMIDMap, mid)
		}
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
