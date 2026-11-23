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

func chunkTSNInsertIndex(chunks []*chunkPayloadData, tsn uint32) int {
	if len(chunks) == 0 || sna32LT(chunks[len(chunks)-1].tsn, tsn) {
		return len(chunks)
	}

	return sort.Search(len(chunks), func(i int) bool {
		return !sna32LT(chunks[i].tsn, tsn)
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

// chunkSet holds the DATA chunks of one message in TSN order.
type chunkSet struct {
	ssn    uint16 // used only for ordered messages
	chunks []*chunkPayloadData
}

func (set *chunkSet) isComplete() bool {
	nChunks := len(set.chunks)
	if nChunks == 0 {
		return false
	}

	// A single chunk can have both flags set (RFC 9260 Section 3.3.1).
	if !set.chunks[0].beginningFragment || !set.chunks[nChunks-1].endingFragment {
		return false
	}

	// A fragmented message has consecutive TSNs (RFC 9260 Section 6.9).
	lastTSN := set.chunks[0].tsn
	for _, chunk := range set.chunks[1:] {
		if chunk.tsn != lastTSN+1 {
			return false
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
	unorderedIndex  map[uint32]struct{} // TSNs of unordered DATA awaiting reassembly.
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
		maxEntries:      maxEntries,
	}
}

func isReassemblyQueueLimitReached(maxEntries uint32, nEntries int) bool {
	return maxEntries > 0 && int64(nEntries) >= int64(maxEntries)
}

func (r *reassemblyQueue) isDataLimitReached(nEntries int) bool {
	return isReassemblyQueueLimitReached(r.maxEntries, nEntries)
}

func (r *reassemblyQueue) isOrderedDataLimitReached() bool {
	return r.maxEntries > 0 && r.isDataLimitReached(r.orderedDataEntryCount())
}

func (r *reassemblyQueue) isUnorderedDataLimitReached() bool {
	return r.maxEntries > 0 && r.isDataLimitReached(r.unorderedDataEntryCount())
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

// insertSetBySSN keeps r.ordered sorted by SSN.
func (r *reassemblyQueue) insertSetBySSN(set *chunkSet) {
	insertAt := sort.Search(len(r.ordered), func(i int) bool {
		return !sna16LT(r.ordered[i].ssn, set.ssn)
	})
	r.ordered = slices.Insert(r.ordered, insertAt, set)
}

func (r *reassemblyQueue) pushWithError(chunk *chunkPayloadData) (bool, error) {
	if chunk.isIData() {
		r.useInterleaving = true

		return r.pushIData(chunk)
	}

	if chunk.streamIdentifier != r.si {
		return false, nil
	}

	if chunk.unordered {
		return r.pushUnorderedData(chunk)
	}

	return r.pushOrderedData(chunk)
}

func (r *reassemblyQueue) pushOrderedData(chunk *chunkPayloadData) (bool, error) {
	ssn := chunk.streamSequenceNumber
	if sna16LT(ssn, r.nextSSN) {
		return false, nil
	}

	var (
		set      *chunkSet
		insertAt int
	)
	fragmented := chunk.isFragmented()
	if fragmented {
		set = r.orderedIndex[ssn]
	}
	if set != nil {
		insertAt = chunkTSNInsertIndex(set.chunks, chunk.tsn)
		if insertAt < len(set.chunks) && set.chunks[insertAt].tsn == chunk.tsn {
			return false, nil
		}
	}

	if r.isOrderedDataLimitReached() {
		return false, errReassemblyQueueLimitExceeded
	}
	if set == nil {
		set = &chunkSet{ssn: ssn}
		if fragmented {
			if r.orderedIndex == nil {
				r.orderedIndex = make(map[uint16]*chunkSet)
			}
			r.orderedIndex[ssn] = set
		}
		r.insertSetBySSN(set)
	}

	set.chunks = slices.Insert(set.chunks, insertAt, chunk)
	atomic.AddUint64(&r.nBytes, uint64(len(chunk.userData)))

	return set.isComplete(), nil
}

func (r *reassemblyQueue) pushUnorderedData(chunk *chunkPayloadData) (bool, error) {
	if _, duplicate := r.unorderedIndex[chunk.tsn]; duplicate {
		return false, nil
	}
	if r.isUnorderedDataLimitReached() {
		return false, errReassemblyQueueLimitExceeded
	}
	if r.unorderedIndex == nil {
		r.unorderedIndex = make(map[uint32]struct{})
	}
	r.unorderedIndex[chunk.tsn] = struct{}{}

	insertAt := chunkTSNInsertIndex(r.unorderedChunks, chunk.tsn)
	r.unorderedChunks = slices.Insert(r.unorderedChunks, insertAt, chunk)
	atomic.AddUint64(&r.nBytes, uint64(len(chunk.userData)))

	set := r.findCompleteUnorderedChunkSet()
	if set == nil {
		return false, nil
	}
	r.unordered = append(r.unordered, set)

	return true, nil
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
