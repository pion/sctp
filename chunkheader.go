// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

/*
chunkHeader represents an SCTP Chunk header per RFC 9260 section 3.2.

Each chunk is formatted with:
  - 1 byte  Chunk Type
  - 1 byte  Chunk Flags
  - 2 bytes Chunk Length (includes header + value, excludes trailing padding)

The sender MUST pad the chunk to a 4-byte boundary with zero bytes (up to 3).
The receiver MUST ignore padding.

Chunk header layout:

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|   Chunk Type  |  Chunk Flags  |        Chunk Length           |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Chunk value (follows header; variable length, may be followed by up to 3 bytes of zero padding):

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                           Chunk Value                         |
	|                               ...                             |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type chunkHeader struct {
	typ   chunkType
	flags byte
	raw   []byte
}

const (
	chunkHeaderSize = 4
)

// SCTP chunk header errors.
var (
	ErrChunkHeaderTooSmall       = errors.New("raw is too small for a SCTP chunk")
	ErrChunkHeaderNotEnoughSpace = errors.New("not enough data left in SCTP packet to satisfy requested length")
	ErrChunkHeaderPaddingNonZero = errors.New("chunk padding is non-zero at offset")
	ErrChunkHeaderInvalidLength  = errors.New("chunk length field smaller than header length")
)

func (c *chunkHeader) unmarshal(raw []byte) error { //nolint:cyclop
	if len(raw) < chunkHeaderSize {
		return fmt.Errorf(
			"%w: raw only %d bytes, %d is the minimum length",
			ErrChunkHeaderTooSmall, len(raw), chunkHeaderSize,
		)
	}

	c.typ = chunkType(raw[0])
	c.flags = raw[1]
	length := binary.BigEndian.Uint16(raw[2:])

	// RFC 9260 section 3.2: Chunk Length MUST be >= 4.
	if length < chunkHeaderSize {
		return fmt.Errorf("%w: length=%d", ErrChunkHeaderInvalidLength, length)
	}

	// Ensure we have the full (header+value) bytes available in this slice.
	if int(length) > len(raw) {
		return fmt.Errorf("%w: need %d bytes, have %d", ErrChunkHeaderNotEnoughSpace, length, len(raw))
	}

	valueLength := int(length) - chunkHeaderSize
	c.raw = raw[chunkHeaderSize : chunkHeaderSize+valueLength]

	// Sender pads to a 4-byte boundary with zeros, receiver MUST ignore padding.
	// If padding bytes are present in this slice, validate they are zero.
	pad := int((4 - (length & 0x3)) & 0x3) // 0..3 bytes
	remain := len(raw) - int(length)

	if pad > 0 && remain > 0 {
		for i := 0; i < min(remain, pad); i++ {
			if raw[int(length)+i] != 0 {
				return fmt.Errorf("%w: %d", ErrChunkHeaderPaddingNonZero, int(length)+i)
			}
		}
	}

	return nil
}

func (c *chunkHeader) marshal() ([]byte, error) {
	raw := make([]byte, chunkHeaderSize+len(c.raw))

	raw[0] = uint8(c.typ)
	raw[1] = c.flags
	binary.BigEndian.PutUint16(raw[2:], uint16(len(c.raw)+chunkHeaderSize)) //nolint:gosec // G115
	copy(raw[chunkHeaderSize:], c.raw)

	return raw, nil
}

func (c *chunkHeader) valueLength() int {
	return len(c.raw)
}

// String makes chunkHeader printable.
func (c chunkHeader) String() string {
	return c.typ.String()
}
