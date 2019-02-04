package sctp

import (
	"fmt"
	"io"
	"sort"
)

func sortChunksBySSN(a [][]*chunkPayloadData) {
	sort.Slice(a, func(i, j int) bool {
		return a[i][0].streamSequenceNumber < a[j][0].streamSequenceNumber
	})
}

type reassemblyQueue struct {
	nextSSN   uint16 // expected SSN for next ordered chunk
	ordered   [][]*chunkPayloadData
	unordered [][]*chunkPayloadData
}

func newReassemblyQueue() *reassemblyQueue {
	return &reassemblyQueue{
		ordered:   make([][]*chunkPayloadData, 0),
		unordered: make([][]*chunkPayloadData, 0),
	}
}

func (r *reassemblyQueue) push(chunks []*chunkPayloadData) {
	if chunks[0].unordered {
		r.unordered = append(r.unordered, chunks)
		return
	}

	r.ordered = append(r.ordered, chunks)
	sortChunksBySSN(r.ordered)
}

func (r *reassemblyQueue) read(buf []byte) (int, PayloadProtocolIdentifier, error) {
	var chunks []*chunkPayloadData
	// Check unordered first
	if len(r.unordered) > 0 {
		chunks = r.unordered[0]
		r.unordered = r.unordered[1:]
	} else if len(r.ordered) > 0 {
		// Now, check ordered
		chunks = r.ordered[0]
		if chunks[0].streamSequenceNumber != r.nextSSN {
			return 0, 0, fmt.Errorf("try again")
		}
		r.ordered = r.ordered[1:]
		r.nextSSN++
	} else {
		return 0, 0, fmt.Errorf("try again")
	}

	// Concat all fragments into the buffer
	nWritten := 0
	ppi := chunks[0].payloadType
	for _, c := range chunks {
		n := copy(buf[nWritten:], c.userData)
		nWritten += n
		if n < len(c.userData) {
			return nWritten, ppi, io.ErrShortBuffer
		}
	}

	return nWritten, ppi, nil
}
