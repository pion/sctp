// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp // nolint:dupl

import (
	"errors"
	"fmt"
)

/*
Abort represents an SCTP Chunk of type ABORT (RFC 9260).

The ABORT chunk closes the association. It may contain zero or more
Error Cause TLVs. DATA MUST NOT be bundled with ABORT. Control chunks
(except INIT, INIT ACK, and SHUTDOWN COMPLETE) MAY be bundled but MUST
precede the ABORT in the packet.
*/
type chunkAbort struct {
	chunkHeader
	errorCauses []errorCause
}

// Abort chunk errors.
var (
	ErrChunkTypeNotAbort     = errors.New("ChunkType is not of type ABORT")
	ErrBuildAbortChunkFailed = errors.New("failed build Abort Chunk")

	// Stricter parsing.
	ErrAbortCauseTooShort      = errors.New("remaining bytes smaller than error cause header")
	ErrAbortCauseLengthInvalid = errors.New("error cause length invalid or exceeds remaining bytes")
	ErrAbortTrailingNonZero    = errors.New("non-zero trailing bytes after last error cause")
)

func (a *chunkAbort) unmarshal(raw []byte) error { //nolint:cyclop
	if err := a.chunkHeader.unmarshal(raw); err != nil {
		return err
	}
	if a.typ != ctAbort {
		return fmt.Errorf("%w: actually is %s", ErrChunkTypeNotAbort, a.typ.String())
	}

	a.errorCauses = a.errorCauses[:0]

	body := a.raw

	offset := 0
	for {
		remaining := len(body) - offset
		if remaining == 0 {
			break
		}
		if remaining < 4 {
			return ErrAbortCauseTooShort
		}

		e, err := buildErrorCause(body[offset:])
		if err != nil {
			return fmt.Errorf("%w: %v", ErrBuildAbortChunkFailed, err) //nolint:errorlint
		}

		clen := int(e.length())
		if clen < 4 || clen > remaining {
			return ErrAbortCauseLengthInvalid
		}

		a.errorCauses = append(a.errorCauses, e)
		offset += clen

		// 4-byte inter-cause padding (not after last)
		if offset < len(body) { //nolint:nestif
			pad := getPadding(clen)
			if pad != 0 {
				if offset+pad > len(body) {
					return ErrAbortCauseLengthInvalid
				}

				if !allZero(body[offset : offset+pad]) {
					return ErrAbortTrailingNonZero
				}
				offset += pad
			}
		}
	}

	return nil
}

func (a *chunkAbort) marshal() ([]byte, error) {
	out := make([]byte, 0)
	for i, ec := range a.errorCauses {
		raw, err := ec.marshal()
		if err != nil {
			return nil, err
		}

		out = append(out, raw...)
		if i != len(a.errorCauses)-1 {
			out = padByte(out, getPadding(len(raw)))
		}
	}

	a.chunkHeader.typ = ctAbort
	// sender MUST only use the T bit, clear any other bits if set.
	a.chunkHeader.flags = a.flags & 0x01
	a.chunkHeader.raw = out

	return a.chunkHeader.marshal()
}

func (a *chunkAbort) check() (abort bool, err error) {
	return true, nil
}

// String makes chunkAbort printable.
func (a *chunkAbort) String() string {
	res := a.chunkHeader.String()

	for _, cause := range a.errorCauses {
		res += fmt.Sprintf("\n - %s", cause)
	}

	return res
}
