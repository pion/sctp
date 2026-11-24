// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

/*
chunkShutdown represents an SCTP Chunk of type SHUTDOWN (Type = 7), per RFC 9260 sec 3.3.8.

Each SHUTDOWN chunk has:
  - Chunk Flags: set to 0 on transmit and ignored on receipt
  - Chunk Length: MUST be 8 (header 4 + value 4)
  - Value: Cumulative TSN Ack (32 bits)

Chunk header layout:

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|   Type = 7    |  Chunk Flags  |        Chunk Length = 8       |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                      Cumulative TSN Ack                       |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type chunkShutdown struct {
	chunkHeader
	cumulativeTSNAck uint32
}

const (
	cumulativeTSNAckLength = 4
)

// Shutdown chunk errors.
var (
	ErrInvalidChunkSize     = errors.New("invalid chunk size")
	ErrChunkTypeNotShutdown = errors.New("ChunkType is not of type SHUTDOWN")
)

func (c *chunkShutdown) unmarshal(raw []byte) error {
	if err := c.chunkHeader.unmarshal(raw); err != nil {
		return err
	}

	if c.typ != ctShutdown {
		return fmt.Errorf("%w: actually is %s", ErrChunkTypeNotShutdown, c.typ.String())
	}

	// Flags are ignored on receipt (RFC 9260 section 3.3.8).
	// Chunk Length MUST be 8, so the value is exactly 4 bytes (Cumulative TSN Ack).
	// chunkHeader.unmarshal sizes c.raw from the Chunk Length field.
	if len(c.raw) != cumulativeTSNAckLength {
		return ErrInvalidChunkSize
	}

	c.cumulativeTSNAck = binary.BigEndian.Uint32(c.raw)

	return nil
}

func (c *chunkShutdown) marshal() ([]byte, error) {
	out := make([]byte, cumulativeTSNAckLength)
	binary.BigEndian.PutUint32(out, c.cumulativeTSNAck)

	c.typ = ctShutdown
	c.flags = 0 // set to 0 on transmit (RFC 9260 section 3.3.8)
	c.raw = out

	return c.chunkHeader.marshal()
}

func (c *chunkShutdown) check() (abort bool, err error) {
	return false, nil
}

// String makes chunkShutdown printable.
func (c *chunkShutdown) String() string {
	return c.chunkHeader.String()
}
