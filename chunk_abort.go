// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp // nolint:dupl

import (
	"errors"
	"fmt"
	"strings"
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
)

func (a *chunkAbort) unmarshal(raw []byte) error {
	if err := a.chunkHeader.unmarshal(raw); err != nil {
		return err
	}
	if a.typ != ctAbort {
		return fmt.Errorf("%w: actually is %s", ErrChunkTypeNotAbort, a.typ.String())
	}

	a.errorCauses = a.errorCauses[:0]

	// Trailing bytes too short for another cause, including padding that is
	// cut short by the chunk length, are ignored.
	body := a.raw
	for offset := 0; len(body)-offset >= errorCauseHeaderLength; {
		e, err := buildErrorCause(body[offset:])
		if err != nil {
			return fmt.Errorf("%w: %v", ErrBuildAbortChunkFailed, err) //nolint:errorlint
		}

		a.errorCauses = append(a.errorCauses, e)

		// Skip alignment padding without interpreting its contents.
		clen := int(e.length())
		offset += clen + getPadding(clen)
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
	var res strings.Builder
	res.WriteString(a.chunkHeader.String())

	for _, cause := range a.errorCauses {
		fmt.Fprintf(&res, "\n - %s", cause)
	}

	return res.String()
}
