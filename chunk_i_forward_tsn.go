// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
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
	maxIForwardTSNStreams  = ((1 << 16) - 1 - chunkHeaderSize - newCumulativeTSNLength) / iForwardTSNEntryLength
)

// I-FORWARD-TSN chunk errors.
var (
	errIForwardTSNChunkTooShort      = errors.New("i-forward-tsn chunk too short")
	errIForwardTSNChunkInvalidLength = errors.New("i-forward-tsn chunk invalid length")
	errIForwardTSNTooManyStreams     = errors.New("i-forward-tsn chunk contains too many streams")
)

type iForwardTSNStreamKey struct {
	identifier uint16
	unordered  bool
}

func (c *chunkIForwardTSN) unmarshal(raw []byte) error {
	if err := c.chunkHeader.unmarshal(raw); err != nil {
		return err
	}

	if len(c.raw) < newCumulativeTSNLength {
		return errIForwardTSNChunkTooShort
	}
	c.streams = nil

	c.newCumulativeTSN = binary.BigEndian.Uint32(c.raw[0:])

	streamBytes := len(c.raw) - newCumulativeTSNLength
	if streamBytes%iForwardTSNEntryLength != 0 {
		return fmt.Errorf("%w: %w", ErrMarshalStreamFailed, errIForwardTSNChunkInvalidLength)
	}

	streamCount := streamBytes / iForwardTSNEntryLength
	if streamCount > maxIForwardTSNStreams {
		return fmt.Errorf("%w: %d exceeds %d", errIForwardTSNTooManyStreams, streamCount, maxIForwardTSNStreams)
	}

	streams := make([]chunkIForwardTSNStream, 0, streamCount)
	for i := range streamCount {
		offset := newCumulativeTSNLength + i*iForwardTSNEntryLength
		s := chunkIForwardTSNStream{}
		if err := s.unmarshal(c.raw[offset : offset+iForwardTSNEntryLength]); err != nil {
			return fmt.Errorf("%w: %w", ErrMarshalStreamFailed, err)
		}

		streams = append(streams, s)
	}
	c.streams = normalizeIForwardTSNStreams(streams)

	return nil
}

func (c *chunkIForwardTSN) marshal() ([]byte, error) {
	c.streams = normalizeIForwardTSNStreams(c.streams)
	if _, err := c.check(); err != nil {
		return nil, err
	}

	out := make([]byte, newCumulativeTSNLength+len(c.streams)*iForwardTSNEntryLength)
	binary.BigEndian.PutUint32(out[0:], c.newCumulativeTSN)

	offset := newCumulativeTSNLength
	for _, s := range c.streams {
		b, err := s.marshal()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMarshalStreamFailed, err) //nolint:errorlint
		}

		copy(out[offset:], b)
		offset += len(b)
	}

	c.typ = ctIForwardTSN
	c.raw = out

	return c.chunkHeader.marshal()
}

func (c *chunkIForwardTSN) check() (abort bool, err error) {
	c.streams = normalizeIForwardTSNStreams(c.streams)

	if len(c.streams) > maxIForwardTSNStreams {
		return true, fmt.Errorf("%w: %d exceeds %d", errIForwardTSNTooManyStreams, len(c.streams), maxIForwardTSNStreams)
	}

	return false, nil
}

func normalizeIForwardTSNStreams(streams []chunkIForwardTSNStream) []chunkIForwardTSNStream {
	if len(streams) < 2 {
		return streams
	}

	normalized := make([]chunkIForwardTSNStream, 0, len(streams))
	forwarded := make(map[iForwardTSNStreamKey]int, len(streams))
	for _, stream := range streams {
		key := iForwardTSNStreamKey{
			identifier: stream.identifier,
			unordered:  stream.unordered,
		}
		if idx, ok := forwarded[key]; ok {
			if sna32LT(normalized[idx].messageIdentifier, stream.messageIdentifier) {
				normalized[idx].messageIdentifier = stream.messageIdentifier
			}

			continue
		}

		forwarded[key] = len(normalized)
		normalized = append(normalized, stream)
	}

	return normalized
}

// String makes chunkIForwardTSN printable.
func (c *chunkIForwardTSN) String() string {
	var res strings.Builder
	fmt.Fprintf(&res, "New Cumulative TSN: %d\n", c.newCumulativeTSN)
	for _, s := range c.streams {
		fmt.Fprintf(&res, " - si=%d mid=%d unordered=%v\n", s.identifier, s.messageIdentifier, s.unordered)
	}

	return res.String()
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
		return errIForwardTSNChunkTooShort
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
