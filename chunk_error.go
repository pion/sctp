// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp // nolint:dupl

import (
	"errors"
	"fmt"
	"strings"
)

/*
Operation Error (ERROR) (Type = 9) - RFC 9260 section 3.3

An endpoint sends this chunk to notify its peer of one or more error
conditions. Contains one or more Error Causes (TLVs). Flags are set to
0 on transmit and ignored on receipt.
*/
type chunkError struct {
	chunkHeader
	errorCauses []errorCause
}

// Error chunk errors.
var (
	ErrChunkTypeNotCtError   = errors.New("ChunkType is not of type ctError")
	ErrBuildErrorChunkFailed = errors.New("failed build Error Chunk")
	ErrErrorNoCauses         = errors.New("ERROR chunk contains no error causes")
)

func (a *chunkError) unmarshal(raw []byte) error {
	if err := a.chunkHeader.unmarshal(raw); err != nil {
		return err
	}

	if a.typ != ctError {
		return fmt.Errorf("%w, actually is %s", ErrChunkTypeNotCtError, a.typ.String())
	}

	// flags are reserved: sender sets to 0, receiver ignores.

	body := a.raw
	if len(body) == 0 {
		return ErrErrorNoCauses
	}

	a.errorCauses = a.errorCauses[:0]

	// Trailing bytes too short for another cause, including padding that
	// is cut short by the chunk length, are ignored.
	for offset := 0; len(body)-offset >= errorCauseHeaderLength; {
		ec, err := buildErrorCause(body[offset:])
		if err != nil {
			return fmt.Errorf("%w: %v", ErrBuildErrorChunkFailed, err) //nolint:errorlint
		}

		a.errorCauses = append(a.errorCauses, ec)

		// Skip alignment padding without interpreting its contents.
		clen := int(ec.length())
		offset += clen + getPadding(clen)
	}

	return nil
}

func (a *chunkError) marshal() ([]byte, error) {
	if len(a.errorCauses) == 0 {
		return nil, ErrErrorNoCauses
	}

	out := make([]byte, 0)
	for i, ec := range a.errorCauses {
		raw, err := ec.marshal()
		if err != nil {
			return nil, err
		}
		out = append(out, raw...)

		// Include padding for all but the last cause
		if i != len(a.errorCauses)-1 {
			out = padByte(out, getPadding(len(raw)))
		}
	}

	a.chunkHeader.typ = ctError
	a.chunkHeader.flags = 0x00 // sender MUST set to 0
	a.chunkHeader.raw = out

	return a.chunkHeader.marshal()
}

func (a *chunkError) check() (abort bool, err error) {
	return false, nil
}

// String makes chunkError printable.
func (a *chunkError) String() string {
	var res strings.Builder
	res.WriteString(a.chunkHeader.String())

	for _, cause := range a.errorCauses {
		fmt.Fprintf(&res, "\n - %s", cause)
	}

	return res.String()
}
