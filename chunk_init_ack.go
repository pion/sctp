// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp // nolint:dupl

import (
	"errors"
	"fmt"
)

/*
chunkInitAck represents an SCTP Chunk of type INIT ACK (RFC 9260 section 3.3.2).

See chunkInitCommon for the fixed headers.

Variable Parameters                     Status     Type Value
-------------------------------------------------------------
State Cookie                            Mandatory  7
IPv4 Address                            Optional   5
IPv6 Address                            Optional   6
Unrecognized Parameter                  Optional   8
Reserved for ECN Capable                Optional   32768 (0x8000)
Host Name Address                       Optional   11
Supported Address Types                 Optional   12

nolint:godot
*/
type chunkInitAck struct {
	chunkHeader
	chunkInitCommon
}

// Init ack chunk errors.
var (
	ErrChunkTypeNotInitAck              = errors.New("ChunkType is not of type INIT ACK")
	ErrChunkNotLongEnoughForParams      = errors.New("chunk Value isn't long enough for mandatory parameters exp")
	ErrChunkTypeInitAckFlagZero         = errors.New("ChunkType of type INIT ACK flags must be all 0")
	ErrInitAckUnmarshalFailed           = errors.New("failed to unmarshal INIT body")
	ErrInitCommonDataMarshalFailed      = errors.New("failed marshaling INIT common data")
	ErrChunkTypeInitAckInitateTagZero   = errors.New("ChunkType of type INIT ACK InitiateTag must not be 0")
	ErrInitAckInboundStreamRequestZero  = errors.New("INIT ACK inbound stream request must be > 0")
	ErrInitAckOutboundStreamRequestZero = errors.New("INIT ACK outbound stream request must be > 0")
	ErrInitAckAdvertisedReceiver1500    = errors.New("INIT ACK Advertised Receiver Window Credit (a_rwnd) must be >= 1500")
)

func (i *chunkInitAck) unmarshal(raw []byte) error {
	if err := i.chunkHeader.unmarshal(raw); err != nil {
		return err
	}

	if i.typ != ctInitAck {
		return fmt.Errorf("%w: actually is %s", ErrChunkTypeNotInitAck, i.typ.String())
	}

	if len(i.raw) < initChunkMinLength {
		return fmt.Errorf("%w: %d actual: %d", ErrChunkNotLongEnoughForParams, initChunkMinLength, len(i.raw))
	}

	// RFC 9260: INIT ACK flags are reserved, sender sets to 0, receiver ignores.
	// Do NOT fail if flags are non-zero.

	if err := i.chunkInitCommon.unmarshal(i.raw); err != nil {
		return fmt.Errorf("%w: %v", ErrInitAckUnmarshalFailed, err) //nolint:errorlint
	}

	return nil
}

func (i *chunkInitAck) marshal() ([]byte, error) {
	initShared, err := i.chunkInitCommon.marshal()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInitCommonDataMarshalFailed, err) //nolint:errorlint
	}

	i.chunkHeader.typ = ctInitAck
	i.chunkHeader.flags = 0 // RFC 9260: sender MUST set INIT ACK flags to 0
	i.chunkHeader.raw = initShared

	return i.chunkHeader.marshal()
}

func (i *chunkInitAck) check() (abort bool, err error) {
	// Initiate Tag MUST NOT be 0.
	if i.initiateTag == 0 {
		return true, ErrChunkTypeInitAckInitateTagZero
	}

	// MIS (inbound streams requested) MUST NOT be 0.
	if i.numInboundStreams == 0 {
		return true, ErrInitAckInboundStreamRequestZero
	}

	// OS (outbound streams requested) MUST NOT be 0.
	// (Constraint "OS <= peer MIS from INIT" is enforced by association logic, not here.)
	if i.numOutboundStreams == 0 {
		return true, ErrInitAckOutboundStreamRequestZero
	}

	// a_rwnd MUST be >= 1500 bytes in INIT/INIT-ACK.
	if i.advertisedReceiverWindowCredit < 1500 {
		return true, ErrInitAckAdvertisedReceiver1500
	}

	return false, nil
}

// String makes chunkInitAck printable.
func (i *chunkInitAck) String() string {
	return fmt.Sprintf("%s\n%s", i.chunkHeader, i.chunkInitCommon)
}
