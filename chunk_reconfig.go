// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"errors"
	"fmt"
)

// https://www.rfc-editor.org/rfc/rfc6525#section-3.1
// chunkReconfig represents an SCTP Chunk used to reconfigure streams.
// It holds at least one parameter and at most two parameters.
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Type = 130    |  Chunk Flags  |      Chunk Length             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// \                                                               \
// /                  Re-configuration Parameter                   /
// \                                                               \
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// \                                                               \
// /             Re-configuration Parameter (optional)             /
// \                                                               \
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

type chunkReconfig struct {
	chunkHeader
	paramA param
	paramB param
}

// Reconfigure chunk errors.
var (
	ErrChunkParseParamTypeFailed        = errors.New("failed to parse param type")
	ErrChunkMarshalParamAReconfigFailed = errors.New("unable to marshal parameter A for reconfig")
	ErrChunkMarshalParamBReconfigFailed = errors.New("unable to marshal parameter B for reconfig")
	ErrChunkReconfigMissingParam        = errors.New("RE-CONFIG chunk is missing its first parameter")
	ErrChunkReconfigTooManyParams       = errors.New("RE-CONFIG chunk holds more than two parameters")
	ErrChunkReconfigInvalidCombination  = errors.New("RE-CONFIG chunk holds an invalid parameter combination")
)

// reconfigMaxParams is the most parameters a RE-CONFIG chunk may hold.
const reconfigMaxParams = 2

func (c *chunkReconfig) unmarshal(raw []byte) error {
	if err := c.chunkHeader.unmarshal(raw); err != nil {
		return err
	}

	c.paramA = nil
	c.paramB = nil

	offset := 0
	for count := 0; offset < len(c.raw); count++ {
		if count == reconfigMaxParams {
			return ErrChunkReconfigTooManyParams
		}

		// Ensure we have a complete TLV header before parsing.
		if len(c.raw)-offset < paramHeaderLength {
			return fmt.Errorf("%w: truncated param header", ErrChunkParseParamTypeFailed)
		}

		pType, err := parseParamType(c.raw[offset:])
		if err != nil {
			return fmt.Errorf("%w: %w", ErrChunkParseParamTypeFailed, err)
		}

		par, err := buildParam(pType, c.raw[offset:])
		if err != nil {
			return err
		}

		if count == 0 {
			c.paramA = par
		} else {
			c.paramB = par
		}

		l := par.length()
		offset += l + getPadding(l)
	}

	if c.paramA == nil {
		return ErrChunkReconfigMissingParam
	}

	return nil
}

func (c *chunkReconfig) marshal() ([]byte, error) {
	if c.paramA == nil {
		return nil, ErrChunkReconfigMissingParam
	}

	out, err := c.paramA.marshal()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrChunkMarshalParamAReconfigFailed, err)
	}
	if c.paramB != nil {
		// Pad param A
		out = padByte(out, getPadding(len(out)))

		outB, err := c.paramB.marshal()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrChunkMarshalParamBReconfigFailed, err)
		}

		out = append(out, outB...)
	}

	c.typ = ctReconfig
	c.raw = out

	return c.chunkHeader.marshal()
}

func (c *chunkReconfig) check() (abort bool, err error) {
	// Parameter combinations are validated by validateCombination in
	// Association.handleReconfig, which answers an invalid combination with an
	// ERROR chunk. Returning an error here would abort the association instead.
	return true, nil
}

// validateCombination reports whether the parameters form one of the
// combinations allowed by RFC 6525 Section 3.1. Only the Outgoing SSN Reset
// Request and Re-configuration Response parameters are implemented, which
// leaves these allowed combinations:
//
//   - Outgoing SSN Reset Request
//   - Re-configuration Response
//   - Re-configuration Response and Outgoing SSN Reset Request, in either order
//   - Re-configuration Response and Re-configuration Response
func (c *chunkReconfig) validateCombination() error {
	if c.paramA == nil {
		return ErrChunkReconfigMissingParam
	}

	requests := 0
	for _, p := range []param{c.paramA, c.paramB} {
		switch p.(type) {
		case nil:
		case *paramOutgoingResetRequest:
			requests++
		case *paramReconfigResponse:
		default:
			return fmt.Errorf("%w: unsupported parameter %T", ErrChunkReconfigInvalidCombination, p)
		}
	}

	if requests > 1 {
		return fmt.Errorf("%w: two Outgoing SSN Reset Requests", ErrChunkReconfigInvalidCombination)
	}

	return nil
}

// String makes chunkReconfig printable.
func (c *chunkReconfig) String() string {
	res := fmt.Sprintf("Param A:\n %s", c.paramA)
	if c.paramB != nil {
		res += fmt.Sprintf("Param B:\n %s", c.paramB)
	}

	return res
}
