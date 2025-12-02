// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"fmt"
)

/*
chunkShutdownComplete represents an SCTP Chunk of type SHUTDOWN-COMPLETE.

RFC 9260 section 3.3.13:
  - Used to acknowledge receipt of SHUTDOWN ACK at the end of shutdown.
  - Has NO parameters (length MUST be 4).
  - Flags: only the T bit is defined; other bits are reserved.

Header (no value follows):

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|   Type = 14   |Reserved     |T|      Length = 4               |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type chunkShutdownComplete struct {
	chunkHeader
}

// ErrChunkTypeNotShutdownComplete is returned when a non-SHUTDOWN-COMPLETE
// chunk is presented to this unmarshaller.
var (
	ErrChunkTypeNotShutdownComplete = fmt.Errorf("ChunkType is not of type %s", ctShutdownComplete.String())
)

func (c *chunkShutdownComplete) unmarshal(raw []byte) error {
	if err := c.chunkHeader.unmarshal(raw); err != nil {
		return err
	}

	if c.typ != ctShutdownComplete {
		return fmt.Errorf("%w: actually is %s", ErrChunkTypeNotShutdownComplete, c.typ.String())
	}

	// RFC 9260 section 3.3.13: no parameters => value length MUST be 0 (i.e., length == 4).
	if c.valueLength() != 0 {
		return ErrInvalidChunkSize
	}

	return nil
}

func (c *chunkShutdownComplete) marshal() ([]byte, error) {
	c.typ = ctShutdownComplete
	c.raw = nil // no value/parameters per RFC 9260 section 3.3.13

	return c.chunkHeader.marshal()
}

func (c *chunkShutdownComplete) check() (abort bool, err error) {
	return false, nil
}

// String makes chunkShutdownComplete printable.
func (c *chunkShutdownComplete) String() string {
	return c.chunkHeader.String()
}
