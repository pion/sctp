// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"errors"
	"fmt"
)

/*
chunkCookieAck represents an SCTP Chunk of type chunkCookieAck

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|   Type = 11   |  Chunk Flags  |     Length = 4                |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type chunkCookieAck struct {
	chunkHeader
}

// Cookie ack chunk errors.
var (
	ErrChunkTypeNotCookieAck = errors.New("ChunkType is not of type COOKIEACK")
)

func (c *chunkCookieAck) unmarshal(raw []byte) error {
	if err := c.chunkHeader.unmarshal(raw); err != nil {
		return err
	}

	if c.typ != ctCookieAck {
		return fmt.Errorf("%w: actually is %s", ErrChunkTypeNotCookieAck, c.typ.String())
	}

	// Flags are reserved: sender sets 0, receiver ignores. A value is not
	// expected but is ignored as well, so the rest of the packet is processed.
	return nil
}

func (c *chunkCookieAck) marshal() ([]byte, error) {
	c.chunkHeader.typ = ctCookieAck
	c.chunkHeader.flags = 0 // sender MUST set to 0
	c.chunkHeader.raw = nil // no body

	return c.chunkHeader.marshal()
}

func (c *chunkCookieAck) check() (abort bool, err error) {
	return false, nil
}

// String makes chunkCookieAck printable.
func (c *chunkCookieAck) String() string {
	return c.chunkHeader.String()
}
