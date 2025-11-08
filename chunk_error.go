// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp // nolint:dupl

import (
	"errors"
	"fmt"
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

	// Stricter parsing/validation.
	ErrErrorNoCauses           = errors.New("ERROR chunk contains no error causes")
	ErrErrorCauseTooShort      = errors.New("remaining bytes smaller than error cause header")
	ErrErrorCauseLengthInvalid = errors.New("error cause length invalid or exceeds remaining bytes")
	ErrErrorTrailingNonZero    = errors.New("non-zero trailing bytes after last error cause")
)

func (a *chunkError) unmarshal(raw []byte) error { //nolint:cyclop
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

	offset := 0
	for {
		remaining := len(body) - offset
		if remaining == 0 {
			break
		}

		if remaining < 4 {
			return ErrErrorCauseTooShort
		}

		ec, err := buildErrorCause(body[offset:])
		if err != nil {
			return fmt.Errorf("%w: %v", ErrBuildErrorChunkFailed, err) //nolint:errorlint
		}

		clen := int(ec.length())
		if clen < 4 || clen > remaining {
			return ErrErrorCauseLengthInvalid
		}

		a.errorCauses = append(a.errorCauses, ec)
		offset += clen

		// skip inter-cause padding to 4-byte boundary.
		if offset < len(body) { //nolint:nestif
			pad := getPadding(clen)

			if pad != 0 {
				if offset+pad > len(body) {
					// not enough bytes for declared padding.
					return ErrErrorCauseLengthInvalid
				}

				// padding must be all zeros.
				if !allZero(body[offset : offset+pad]) {
					return ErrErrorTrailingNonZero
				}
				offset += pad
			}
		}
	}

	if len(a.errorCauses) == 0 {
		return ErrErrorNoCauses
	}

	return nil
}

func (a *chunkError) marshal() ([]byte, error) {
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
	res := a.chunkHeader.String()

	for _, cause := range a.errorCauses {
		res += fmt.Sprintf("\n - %s", cause)
	}

	return res
}
