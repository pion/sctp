// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// This chunk be used by the data sender to inform the data
// receiver to adjust its cumulative received TSN.
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Type = 194  |  Flags = 0x00 |        Length = Variable      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      New Cumulative TSN                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Stream Identifier    |       Reserved            |U| |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Message Identifier                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// \                                                               /
// /                                                               \
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Stream Identifier    |       Reserved            |U| |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Message Identifier                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// https://www.rfc-editor.org/rfc/rfc8260.html#section-2.3.1

type chunkIForwardTSN struct {
	chunkHeader

	// This indicates the new cumulative TSN to the data receiver.
	newCumulativeTSN uint32

	streams []chunkIForwardTSNStream
}

const (
	iForwardTSNEntryLength = 8
)

// I-FORWARD-TSN chunk errors.
var (
	ErrIForwardTSNChunkTooShort = errors.New("i-forward-tsn chunk too short")
)

func (c *chunkIForwardTSN) unmarshal(raw []byte) error {
	if err := c.chunkHeader.unmarshal(raw); err != nil {
		return err
	}

	if len(c.raw) < newCumulativeTSNLength {
		return ErrIForwardTSNChunkTooShort
	}

	c.newCumulativeTSN = binary.BigEndian.Uint32(c.raw[0:])

	offset := newCumulativeTSNLength
	remaining := len(c.raw) - offset
	for remaining > 0 {
		s := chunkIForwardTSNStream{}
		if err := s.unmarshal(c.raw[offset:]); err != nil {
			return fmt.Errorf("%w: %v", ErrMarshalStreamFailed, err) //nolint:errorlint
		}

		c.streams = append(c.streams, s)

		offset += s.length()
		remaining -= s.length()
	}

	return nil
}

func (c *chunkIForwardTSN) marshal() ([]byte, error) {
	out := make([]byte, newCumulativeTSNLength)
	binary.BigEndian.PutUint32(out[0:], c.newCumulativeTSN)

	for _, s := range c.streams {
		b, err := s.marshal()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMarshalStreamFailed, err) //nolint:errorlint
		}
		out = append(out, b...) //nolint:makezero // TODO: fix
	}

	c.typ = ctIForwardTSN
	c.raw = out

	return c.chunkHeader.marshal()
}

func (c *chunkIForwardTSN) check() (abort bool, err error) {
	return true, nil
}

// String makes chunkIForwardTSN printable.
func (c *chunkIForwardTSN) String() string {
	res := fmt.Sprintf("New Cumulative TSN: %d\n", c.newCumulativeTSN)
	for _, s := range c.streams {
		res += fmt.Sprintf(" - si=%d mid=%d unordered=%v\n", s.identifier, s.messageIdentifier, s.unordered)
	}

	return res
}

type chunkIForwardTSNStream struct {
	identifier        uint16
	unordered         bool
	messageIdentifier uint32
}

func (s *chunkIForwardTSNStream) length() int {
	return iForwardTSNEntryLength
}

func (s *chunkIForwardTSNStream) unmarshal(raw []byte) error {
	if len(raw) < iForwardTSNEntryLength {
		return ErrIForwardTSNChunkTooShort
	}
	s.identifier = binary.BigEndian.Uint16(raw[0:])
	flags := binary.BigEndian.Uint16(raw[2:])
	s.unordered = flags&0x1 != 0
	s.messageIdentifier = binary.BigEndian.Uint32(raw[4:])

	return nil
}

func (s *chunkIForwardTSNStream) marshal() ([]byte, error) { // nolint:unparam
	out := make([]byte, iForwardTSNEntryLength)

	binary.BigEndian.PutUint16(out[0:], s.identifier)
	if s.unordered {
		binary.BigEndian.PutUint16(out[2:], 0x1)
	} else {
		binary.BigEndian.PutUint16(out[2:], 0x0)
	}
	binary.BigEndian.PutUint32(out[4:], s.messageIdentifier)

	return out, nil
}
