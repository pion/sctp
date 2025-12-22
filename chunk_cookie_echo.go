// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"errors"
	"fmt"
)

/*
CookieEcho represents an SCTP Chunk of type COOKIE ECHO (RFC 9260 section 3.3)

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Type = 10   |  Chunk Flags  |           Length              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Cookie                              |
|                        (opaque bytes)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

nolint:godot
*/
type chunkCookieEcho struct {
	chunkHeader
	cookie []byte
}

// Cookie echo chunk errors.
var (
	ErrChunkTypeNotCookieEcho = errors.New("ChunkType is not of type COOKIEECHO")
	ErrCookieEchoEmpty        = errors.New("COOKIE ECHO must contain a non-empty cookie")
)

func (c *chunkCookieEcho) unmarshal(raw []byte) error {
	if err := c.chunkHeader.unmarshal(raw); err != nil {
		return err
	}

	if c.typ != ctCookieEcho {
		return fmt.Errorf("%w: actually is %s", ErrChunkTypeNotCookieEcho, c.typ.String())
	}

	// flags are reserved: sender sets 0, receiver ignores.
	// body is the opaque cookie bytes.
	c.cookie = c.raw

	// RFC 9260: cookie MUST be present (non-empty).
	if len(c.cookie) == 0 {
		return ErrCookieEchoEmpty
	}

	return nil
}

func (c *chunkCookieEcho) marshal() ([]byte, error) {
	// Require a non-empty cookie.
	if len(c.cookie) == 0 {
		return nil, ErrCookieEchoEmpty
	}

	c.chunkHeader.typ = ctCookieEcho
	c.chunkHeader.flags = 0 // sender MUST set to 0
	c.chunkHeader.raw = append([]byte(nil), c.cookie...)

	return c.chunkHeader.marshal()
}

func (c *chunkCookieEcho) check() (abort bool, err error) {
	return false, nil
}
