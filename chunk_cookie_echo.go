// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"errors"
	"fmt"
)

/*
CookieEcho represents an SCTP Chunk of type CookieEcho

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|   Type = 10   |Chunk  Flags   |         Length                |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                     Cookie                                    |
	|                                                               |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type chunkCookieEcho struct {
	chunkHeader
	cookie []byte
}

// Cookie echo chunk errors.
var (
	ErrChunkTypeNotCookieEcho = errors.New("ChunkType is not of type COOKIEECHO")
)

func (c *chunkCookieEcho) unmarshal(raw []byte) error {
	if err := c.chunkHeader.unmarshal(raw); err != nil {
		return err
	}

	if c.typ != ctCookieEcho {
		return fmt.Errorf("%w: actually is %s", ErrChunkTypeNotCookieEcho, c.typ.String())
	}

	// RFC 9260: flags are reserved; sender sets 0, receiver ignores.
	// Do not fail if flags != 0.
	c.cookie = c.raw

	return nil
}

func (c *chunkCookieEcho) marshal() ([]byte, error) {
	c.chunkHeader.typ = ctCookieEcho
	c.chunkHeader.flags = 0 // sender sets 0 (reserved)
	c.chunkHeader.raw = c.cookie

	return c.chunkHeader.marshal()
}

func (c *chunkCookieEcho) check() (abort bool, err error) {
	return false, nil
}
