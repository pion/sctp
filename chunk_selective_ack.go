// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

/*
chunkSelectiveAck represents an SCTP Chunk of type SACK (RFC 9260 section 3.3.4).

This chunk is sent to the peer endpoint to acknowledge received DATA
chunks and to inform the peer endpoint of gaps in the received
subsequences of DATA chunks as represented by their TSNs.

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Type = 3    |Chunk  Flags   |      Chunk Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Cumulative TSN Ack                       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Advertised Receiver Window Credit (a_rwnd)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Number of Gap Ack Blocks = N  |  Number of Duplicate TSNs = X |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Gap Ack Block #1 Start       |   Gap Ack Block #1 End        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
\                              ...                              \
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Gap Ack Block #N Start      |  Gap Ack Block #N End         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Duplicate TSN 1                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/                                                               /
\                              ...                              \
/                                                               /
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Duplicate TSN X                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

type gapAckBlock struct {
	start uint16
	end   uint16
}

// Selective ack chunk errors.
var (
	ErrChunkTypeNotSack           = errors.New("ChunkType is not of type SACK")
	ErrSackSizeNotLargeEnoughInfo = errors.New("SACK Chunk size is not large enough to contain header")
	ErrSackSizeNotMatchPredicted  = errors.New("SACK Chunk size does not match predicted amount from header values")
	ErrSackGapBlockInvalidRange   = errors.New("SACK gap ack block has invalid Start/End range")
	ErrSackGapBlocksNotMonotonic  = errors.New("SACK gap ack blocks are not strictly increasing/non-overlapping")
)

// String makes gapAckBlock printable.
func (g gapAckBlock) String() string {
	return fmt.Sprintf("%d - %d", g.start, g.end)
}

type chunkSelectiveAck struct {
	chunkHeader
	cumulativeTSNAck               uint32
	advertisedReceiverWindowCredit uint32
	gapAckBlocks                   []gapAckBlock
	duplicateTSN                   []uint32
}

const (
	selectiveAckHeaderSize = 12
)

func (s *chunkSelectiveAck) unmarshal(raw []byte) error { //nolint:cyclop
	if err := s.chunkHeader.unmarshal(raw); err != nil {
		return err
	}

	if s.typ != ctSack {
		return fmt.Errorf("%w: actually is %s", ErrChunkTypeNotSack, s.typ.String())
	}

	if len(s.raw) < selectiveAckHeaderSize {
		return fmt.Errorf("%w: %v remaining, needs %v bytes", ErrSackSizeNotLargeEnoughInfo,
			len(s.raw), selectiveAckHeaderSize)
	}

	s.cumulativeTSNAck = binary.BigEndian.Uint32(s.raw[0:])
	s.advertisedReceiverWindowCredit = binary.BigEndian.Uint32(s.raw[4:])
	nGap := int(binary.BigEndian.Uint16(s.raw[8:]))
	nDup := int(binary.BigEndian.Uint16(s.raw[10:]))

	if len(s.raw) != selectiveAckHeaderSize+4*nGap+4*nDup {
		return ErrSackSizeNotMatchPredicted
	}

	offset := selectiveAckHeaderSize
	blocks := make([]gapAckBlock, nGap)
	var prevEnd uint16

	for i := 0; i < nGap; i++ {
		start := binary.BigEndian.Uint16(s.raw[offset:])
		end := binary.BigEndian.Uint16(s.raw[offset+2:])
		offset += 4

		if start == 0 || end < start {
			return ErrSackGapBlockInvalidRange
		}

		if i > 0 && start <= prevEnd { // must be strictly increasing, no overlap
			return ErrSackGapBlocksNotMonotonic
		}

		blocks[i] = gapAckBlock{start: start, end: end}
		prevEnd = end
	}

	s.gapAckBlocks = blocks
	s.duplicateTSN = make([]uint32, nDup)

	for i := 0; i < nDup; i++ {
		s.duplicateTSN[i] = binary.BigEndian.Uint32(s.raw[offset:])
		offset += 4
	}

	return nil
}

func (s *chunkSelectiveAck) marshal() ([]byte, error) { //nolint:cyclop
	// validate strictly increasing, non-overlapping (contiguous is ok)
	var prevEnd uint16
	for i, g := range s.gapAckBlocks {
		if g.start == 0 || g.end < g.start {
			return nil, ErrSackGapBlockInvalidRange
		}

		if i > 0 && g.start <= prevEnd {
			return nil, ErrSackGapBlocksNotMonotonic
		}

		prevEnd = g.end
	}

	sackRaw := make([]byte, selectiveAckHeaderSize+(4*len(s.gapAckBlocks))+(4*len(s.duplicateTSN)))
	offset := selectiveAckHeaderSize

	prevEnd = 0
	for i, g := range s.gapAckBlocks {
		if g.start == 0 || g.end < g.start {
			return nil, ErrSackGapBlockInvalidRange
		}

		if i > 0 && g.start <= prevEnd {
			return nil, ErrSackGapBlocksNotMonotonic
		}

		binary.BigEndian.PutUint16(sackRaw[offset:], g.start)
		binary.BigEndian.PutUint16(sackRaw[offset+2:], g.end)
		prevEnd = g.end
		offset += 4
	}

	for _, t := range s.duplicateTSN {
		binary.BigEndian.PutUint32(sackRaw[offset:], t)
		offset += 4
	}

	binary.BigEndian.PutUint32(sackRaw[0:], s.cumulativeTSNAck)
	binary.BigEndian.PutUint32(sackRaw[4:], s.advertisedReceiverWindowCredit)
	binary.BigEndian.PutUint16(sackRaw[8:], uint16(len(s.gapAckBlocks)))  //nolint:gosec // G115
	binary.BigEndian.PutUint16(sackRaw[10:], uint16(len(s.duplicateTSN))) //nolint:gosec // G115

	s.chunkHeader.typ = ctSack
	s.chunkHeader.flags = 0 // RFC 9260: SACK flags must be 0
	s.chunkHeader.raw = sackRaw

	return s.chunkHeader.marshal()
}

func (s *chunkSelectiveAck) check() (abort bool, err error) {
	return false, nil
}

// String makes chunkSelectiveAck printable.
func (s *chunkSelectiveAck) String() string {
	res := fmt.Sprintf("SACK cumTsnAck=%d arwnd=%d dupTsn=%v",
		s.cumulativeTSNAck,
		s.advertisedReceiverWindowCredit,
		s.duplicateTSN)

	for _, gap := range s.gapAckBlocks {
		res = fmt.Sprintf("%s\n gap ack: %s", res, gap)
	}

	return res
}
