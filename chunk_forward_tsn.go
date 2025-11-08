// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// This chunk is used by the sender to advance the cumulative TSN and
// indicate per-stream sequence numbers that were skipped (RFC 9260).

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Type = 192  |  Flags = 0x00 |        Length = Variable      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      New Cumulative TSN                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Stream-1              |       Stream Sequence-1       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// \                                                               /
// /                                                               \
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Stream-N              |       Stream Sequence-N       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

type chunkForwardTSN struct {
	chunkHeader

	// This indicates the new cumulative TSN to the data receiver.  Upon
	// the reception of this value, the data receiver MUST consider
	// any missing TSNs earlier than or equal to this value as received,
	// and stop reporting them as gaps in any subsequent SACKs.
	newCumulativeTSN uint32
	streams          []chunkForwardTSNStream
}

const (
	newCumulativeTSNLength = 4
	forwardTSNStreamLength = 4
)

// Forward TSN chunk errors.
var (
	ErrMarshalStreamFailed          = errors.New("failed to marshal stream")
	ErrChunkTooShort                = errors.New("chunk too short")
	ErrChunkTypeNotForwardTSN       = errors.New("ChunkType is not of type FORWARD TSN")
	ErrForwardTSNInvalidStreamBlock = errors.New("FORWARD TSN stream block section length invalid")
)

func (c *chunkForwardTSN) unmarshal(raw []byte) error {
	if err := c.chunkHeader.unmarshal(raw); err != nil {
		return err
	}

	if c.typ != ctForwardTSN {
		return fmt.Errorf("%w: actually is %s", ErrChunkTypeNotForwardTSN, c.typ.String())
	}

	// flags are reserved: sender sets 0, receiver ignores.

	if len(c.raw) < newCumulativeTSNLength {
		return ErrChunkTooShort
	}

	// remaining body MUST be a multiple of 4 (each stream block is 4 bytes).
	if (len(c.raw)-newCumulativeTSNLength)%forwardTSNStreamLength != 0 {
		return ErrForwardTSNInvalidStreamBlock
	}

	c.newCumulativeTSN = binary.BigEndian.Uint32(c.raw[0:4])

	c.streams = c.streams[:0]
	for off := newCumulativeTSNLength; off < len(c.raw); off += forwardTSNStreamLength {
		var s chunkForwardTSNStream
		if err := s.unmarshal(c.raw[off:]); err != nil {
			return fmt.Errorf("%w: %v", ErrMarshalStreamFailed, err) //nolint:errorlint
		}
		c.streams = append(c.streams, s)
	}

	return nil
}

func (c *chunkForwardTSN) marshal() ([]byte, error) {
	out := make([]byte, 0, newCumulativeTSNLength+len(c.streams)*forwardTSNStreamLength)

	var tsnBuf [4]byte
	binary.BigEndian.PutUint32(tsnBuf[:], c.newCumulativeTSN)
	out = append(out, tsnBuf[:]...)

	for _, s := range c.streams {
		b, err := s.marshal()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMarshalStreamFailed, err) //nolint:errorlint
		}
		out = append(out, b...)
	}

	c.chunkHeader.typ = ctForwardTSN
	c.chunkHeader.flags = 0 // sender MUST set to 0
	c.chunkHeader.raw = out

	return c.chunkHeader.marshal()
}

func (c *chunkForwardTSN) check() (abort bool, err error) {
	return false, nil
}

// String makes chunkForwardTSN printable.
func (c *chunkForwardTSN) String() string {
	res := fmt.Sprintf("New Cumulative TSN: %d\n", c.newCumulativeTSN)
	for _, s := range c.streams {
		res += fmt.Sprintf(" - si=%d, ssn=%d\n", s.identifier, s.sequence)
	}

	return res
}

type chunkForwardTSNStream struct {
	// This field holds a stream number that was skipped by this
	// FWD-TSN.
	identifier uint16

	// This field holds the sequence number associated with the stream
	// that was skipped.  The stream sequence field holds the largest
	// stream sequence number in this stream being skipped.  The receiver
	// of the FWD-TSN's can use the Stream-N and Stream Sequence-N fields
	// to enable delivery of any stranded TSN's that remain on the stream
	// re-ordering queues.  This field MUST NOT report TSN's corresponding
	// to DATA chunks that are marked as unordered.  For ordered DATA
	// chunks this field MUST be filled in.
	sequence uint16
}

func (s *chunkForwardTSNStream) length() int {
	return forwardTSNStreamLength
}

func (s *chunkForwardTSNStream) unmarshal(raw []byte) error {
	if len(raw) < forwardTSNStreamLength {
		return ErrChunkTooShort
	}
	s.identifier = binary.BigEndian.Uint16(raw[0:])
	s.sequence = binary.BigEndian.Uint16(raw[2:])

	return nil
}

func (s *chunkForwardTSNStream) marshal() ([]byte, error) { // nolint:unparam
	out := make([]byte, forwardTSNStreamLength)

	binary.BigEndian.PutUint16(out[0:], s.identifier)
	binary.BigEndian.PutUint16(out[2:], s.sequence)

	return out, nil
}
