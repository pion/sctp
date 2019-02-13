package sctp

import (
	"fmt"
	"io"
	"sort"
)

func sortChunksByTSN(a []*chunkPayloadData) {
	sort.Slice(a, func(i, j int) bool {
		return sna32LT(a[i].tsn, a[j].tsn)
	})
}

func sortChunksBySSN(a []*chunkSet) {
	sort.Slice(a, func(i, j int) bool {
		return sna16LT(a[i].ssn, a[j].ssn)
	})
}

// chunkSet is a set of chunks that share the same SSN
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
	complete := set.isComplete()
	return complete
}

func (set *chunkSet) isComplete() bool {
	// Condition for complete set
	//   0. Has at least one chunk.
	//   1. Begins with beginningFragment set to true
	//   2. Ends with endingFragment set to true
	//   3. TSN monotinically increase by 1 from beginning to end

	// 0.
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
	for i, c := range set.chunks {
		if i > 0 {
			// Fragments must have contiguous TSN
			// From RFC 4960 Section 3.3.1:
			//   When a user message is fragmented into multiple chunks, the TSNs are
			//   used by the receiver to reassemble the message.  This means that the
			//   TSNs for each fragment of a fragmented user message MUST be strictly
			//   sequential.
			if c.tsn != lastTSN+1 {
				// mid or end fragment is missing
				return false
			}
		}

		lastTSN = c.tsn
	}

	return true
}

type reassemblyQueue struct {
	si              uint16
	nextSSN         uint16 // expected SSN for next ordered chunk
	ordered         []*chunkSet
	unordered       []*chunkSet
	unorderedChunks []*chunkPayloadData
}

func newReassemblyQueue(si uint16) *reassemblyQueue {
	// From RFC 4960 Sec 6.5:
	//   The Stream Sequence Number in all the streams MUST start from 0 when
	//   the association is established.  Also, when the Stream Sequence
	//   Number reaches the value 65535 the next Stream Sequence Number MUST
	//   be set to 0.
	return &reassemblyQueue{
		si:        si,
		nextSSN:   0, // From RFC 4960 Sec 6.5:
		ordered:   make([]*chunkSet, 0),
		unordered: make([]*chunkSet, 0),
	}
}

func (r *reassemblyQueue) push(chunk *chunkPayloadData) bool {
	var cset *chunkSet

	if chunk.streamIdentifier != r.si {
		fmt.Printf("SI[%d]: pushed chunk for wrong SI %d != %d\n", r.si, chunk.streamIdentifier, r.si)
		return false
	}

	if chunk.unordered {
		// First, insert into unorderedChunks array
		r.unorderedChunks = append(r.unorderedChunks, chunk)
		sortChunksByTSN(r.unorderedChunks)

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

	//fmt.Printf("SI[%d]: push SSN %d Next SSN=%d\n", r.si, chunk.streamSequenceNumber, r.nextSSN)

	if sna16LT(chunk.streamSequenceNumber, r.nextSSN) {
		//fmt.Printf("SI[%d]: ignore stale SSN %d < %d\n", r.si, chunk.streamSequenceNumber, r.nextSSN)
		return false
	}

	// Check if a chunkSet with the SSN already exists
	for _, set := range r.ordered {
		if set.ssn == chunk.streamSequenceNumber {
			cset = set
			break
		}
	}

	// If not found, create a new chunkSet
	if cset == nil {
		cset = newChunkSet(chunk.streamSequenceNumber, chunk.payloadType)
		r.ordered = append(r.ordered, cset)
		if !chunk.unordered {
			sortChunksBySSN(r.ordered)
		}
	}

	return cset.push(chunk)
}

func (r *reassemblyQueue) findCompleteUnorderedChunkSet() *chunkSet {
	startIdx := -1
	nChunks := 0
	var lastTSN uint32
	var found bool

	for i, c := range r.unorderedChunks {
		// seek beigining
		if c.beginningFragment {
			startIdx = i
			nChunks = 1
			lastTSN = c.tsn

			if c.endingFragment {
				found = true
				break
			}
			continue
		}

		if startIdx < 0 {
			continue
		}

		// Check if contiguous in TSN
		if c.tsn != lastTSN+1 {
			startIdx = -1
			continue
		}

		lastTSN = c.tsn
		nChunks++

		if c.endingFragment {
			found = true
			break
		}
	}

	if !found {
		return nil
	}

	// Extract the range of chunks
	chunks := r.unorderedChunks[startIdx : startIdx+nChunks]
	r.unorderedChunks = append(
		r.unorderedChunks[:startIdx],
		r.unorderedChunks[startIdx+nChunks:]...)

	chunkSet := newChunkSet(0, chunks[0].payloadType)
	for _, c := range chunks {
		chunkSet.push(c)
	}

	return chunkSet
}

func (r *reassemblyQueue) isReadable() bool {
	// Check unordered first
	if len(r.unordered) > 0 {
		// The chunk sets in r.unordered should all be complete.
		return true
	}

	// Check ordered sets
	if len(r.ordered) > 0 {
		cset := r.ordered[0]
		if cset.isComplete() {
			if sna16LTE(cset.ssn, r.nextSSN) {
				return true
			}
		}
	}
	return false
}

func (r *reassemblyQueue) read(buf []byte) (int, PayloadProtocolIdentifier, error) {
	var cset *chunkSet
	// Check unordered first
	if len(r.unordered) > 0 {
		cset = r.unordered[0]
		r.unordered = r.unordered[1:]
	} else if len(r.ordered) > 0 {
		// Now, check ordered
		cset = r.ordered[0]
		if !cset.isComplete() {
			//fmt.Printf("SI[%d]: SSN %d in not ready. Next SSN=%d\n", r.si, cset.ssn, r.nextSSN)
			return 0, 0, fmt.Errorf("try again")
		}
		if sna16GT(cset.ssn, r.nextSSN) {
			//fmt.Printf("SI[%d]: SSN %d blocked. Next SSN=%d\n", r.si, cset.ssn, r.nextSSN)
			return 0, 0, fmt.Errorf("try again")
		}
		r.ordered = r.ordered[1:]
		if cset.ssn == r.nextSSN {
			r.nextSSN++
		}
		//fmt.Printf("SI[%d]: read SSN=%d, nextSSN=%d\n", r.si, cset.ssn, r.nextSSN)
	} else {
		return 0, 0, fmt.Errorf("try again")
	}

	// Concat all fragments into the buffer
	nWritten := 0
	ppi := cset.ppi
	for _, c := range cset.chunks {
		n := copy(buf[nWritten:], c.userData)
		nWritten += n
		if n < len(c.userData) {
			return nWritten, ppi, io.ErrShortBuffer
		}
	}

	return nWritten, ppi, nil
}

func (r *reassemblyQueue) forwardTSN(newCumulativeTSN uint32, unordered bool, lastSSN uint16) {
	if unordered {
		// This stream is configured to use unordered data. (The given SSN
		// has no significance)
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
			r.unorderedChunks = r.unorderedChunks[lastIdx+1:]
		}
	} else {
		// This stream is configured to use ordered data.
		// Use lastSSN to locate a chunkSet then remove it if the set has
		// not been complete
		keep := []*chunkSet{}
		for _, set := range r.ordered {
			if sna16LTE(set.ssn, lastSSN) {
				if !set.isComplete() {
					continue // drop
				}
			}
			keep = append(keep, set)
		}
		r.ordered = keep

		// Finally, forward nextSSN
		if sna16LTE(r.nextSSN, lastSSN) {
			r.nextSSN = lastSSN + 1
		}
	}
}
