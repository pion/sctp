// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"errors"
	"fmt"
)

/*
chunkShutdownAck represents an SCTP Chunk of type SHUTDOWN-ACK.

RFC 9260 section 3.3.9:
  - Used to acknowledge a SHUTDOWN chunk.
  - Has NO parameters (length MUST be 4).
  - Flags are reserved (sender sets to 0; receiver ignores).

Header (no value follows):

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|   Type = 8    | Chunk  Flags  |          Length = 4           |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type chunkShutdownAck struct {
	chunkHeader
}

// Shutdown ack chunk errors.
var (
	ErrChunkTypeNotShutdownAck = errors.New("ChunkType is not of type SHUTDOWN-ACK")
)

func (c *chunkShutdownAck) unmarshal(raw []byte) error {
	if err := c.chunkHeader.unmarshal(raw); err != nil {
		return err
	}

	if c.typ != ctShutdownAck {
		return fmt.Errorf("%w: actually is %s", ErrChunkTypeNotShutdownAck, c.typ.String())
	}

	// RFC 9260 section 3.3.9: SHUTDOWN-ACK has no parameters => value length MUST be 0.
	if c.valueLength() != 0 {
		return ErrInvalidChunkSize
	}

	return nil
}

func (c *chunkShutdownAck) marshal() ([]byte, error) {
	c.typ = ctShutdownAck
	c.raw = nil // no value/parameters per RFC 9260 section 3.3.9

	return c.chunkHeader.marshal()
}

func (c *chunkShutdownAck) check() (abort bool, err error) {
	return false, nil
}

// String makes chunkShutdownAck printable.
func (c *chunkShutdownAck) String() string {
	return c.chunkHeader.String()
}
