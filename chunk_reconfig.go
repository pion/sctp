// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"errors"
	"fmt"
)

// https://www.rfc-editor.org/rfc/rfc6525#section-3.1
// chunkReconfig represents an SCTP Chunk used to reconfigure streams.
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Type=130    |  Chunk Flags  |        Chunk Length           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// \                                                               \
// /                 Re-configuration Parameter(s)                 /
// \                     (one or more TLVs)                        /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

type chunkReconfig struct {
	chunkHeader
	paramA param
	paramB param
	// Additional TLVs (RFC 6525 allows multiple).
	extras []param
}

// Reconfigure chunk errors.
var (
	ErrChunkParseParamTypeFailed             = errors.New("failed to parse param type")
	ErrChunkMarshalParamAReconfigFailed      = errors.New("unable to marshal parameter A for reconfig")
	ErrChunkMarshalParamBReconfigFailed      = errors.New("unable to marshal parameter B for reconfig")
	ErrChunkMarshalParamExtrasReconfigFailed = errors.New("unable to marshal parameter extras for reconfig")
)

func (c *chunkReconfig) unmarshal(raw []byte) error {
	if err := c.chunkHeader.unmarshal(raw); err != nil {
		return err
	}

	c.paramA = nil
	c.paramB = nil
	c.extras = nil

	data := c.raw
	// RFC 6525 requires one or more TLVs inside RE-CONFIG.
	// If there's nothing after the chunk header then fail.
	if len(data) < 4 { // need at least a param header (type,len)
		return fmt.Errorf("%w: empty RECONFIG body", ErrChunkParseParamTypeFailed)
	}

	offset := 0
	idx := 0

	for offset < len(data) {
		// Ensure we have a complete TLV header before parsing.
		if len(data)-offset < 4 {
			return fmt.Errorf("%w: truncated param header", ErrChunkParseParamTypeFailed)
		}

		pType, err := parseParamType(data[offset:])
		if err != nil {
			return fmt.Errorf("%w: %w", ErrChunkParseParamTypeFailed, err)
		}

		par, err := buildParam(pType, data[offset:])
		if err != nil {
			return err
		}

		switch idx {
		case 0:
			c.paramA = par
		case 1:
			c.paramB = par
		default:
			c.extras = append(c.extras, par)
		}
		idx++

		l := par.length()
		offset += l + getPadding(l)
	}

	return nil
}

func (c *chunkReconfig) marshal() ([]byte, error) {
	var list []param
	if c.paramA != nil {
		list = append(list, c.paramA)
	}

	if c.paramB != nil {
		list = append(list, c.paramB)
	}

	if len(c.extras) > 0 {
		list = append(list, c.extras...)
	}

	out := make([]byte, 0)
	for i, p := range list {
		b, err := p.marshal()
		if err != nil {
			// Preserve legacy error types for API stability.
			if i == 0 {
				return nil, fmt.Errorf("%w: %w", ErrChunkMarshalParamAReconfigFailed, err)
			}

			if i == 1 {
				return nil, fmt.Errorf("%w: %w", ErrChunkMarshalParamBReconfigFailed, err)
			}

			return nil, fmt.Errorf("%w: %w", ErrChunkMarshalParamExtrasReconfigFailed, err)
		}
		out = append(out, b...)
		// Pad between TLVs (no need to pad after the last one)
		if i != len(list)-1 {
			out = padByte(out, getPadding(len(b)))
		}
	}

	c.typ = ctReconfig
	c.raw = out

	return c.chunkHeader.marshal()
}

func (c *chunkReconfig) check() (abort bool, err error) {
	// Combinations/semantics are validated when handling individual params.
	return true, nil
}

// String makes chunkReconfig printable.
func (c *chunkReconfig) String() string {
	switch {
	case c.paramA == nil && c.paramB == nil && len(c.extras) == 0:
		return "RECONFIG: <no params>"
	default:
		res := "RECONFIG params:\n"
		i := 0
		if c.paramA != nil {
			res += fmt.Sprintf("  [%d] %s\n", i, c.paramA)
			i++
		}
		if c.paramB != nil {
			res += fmt.Sprintf("  [%d] %s\n", i, c.paramB)
			i++
		}
		for _, p := range c.extras {
			res += fmt.Sprintf("  [%d] %s\n", i, p)
			i++
		}

		return res
	}
}
