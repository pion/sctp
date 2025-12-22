// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp // nolint:dupl

import (
	"errors"
	"fmt"
)

/*
Init represents an SCTP Chunk of type INIT (RFC 9260 §3.3.2)

See chunkInitCommon for the fixed headers

	Variable Parameters               	Status     	Type Value
	-------------------------------------------------------------
	IPv4 IP (Note 1)               		Optional    5
	IPv6 IP (Note 1)               		Optional    6
	Cookie Preservative                 Optional    9
	Reserved for ECN Capable (Note 2)   Optional    32768 (0x8000)
	Host Name IP (Note 3)          		Optional    11
	Supported IP Types (Note 4)    		Optional    12
*/
type chunkInit struct {
	chunkHeader
	chunkInitCommon
}

// Init chunk errors.
var (
	ErrChunkTypeNotTypeInit          = errors.New("ChunkType is not of type INIT")
	ErrChunkValueNotLongEnough       = errors.New("chunk Value isn't long enough for mandatory parameters exp")
	ErrChunkTypeInitFlagZero         = errors.New("ChunkType of type INIT flags must be all 0")
	ErrChunkTypeInitUnmarshalFailed  = errors.New("failed to unmarshal INIT body")
	ErrChunkTypeInitMarshalFailed    = errors.New("failed marshaling INIT common data")
	ErrChunkTypeInitInitateTagZero   = errors.New("ChunkType of type INIT ACK InitiateTag must not be 0")
	ErrInitInboundStreamRequestZero  = errors.New("INIT ACK inbound stream request must be > 0")
	ErrInitOutboundStreamRequestZero = errors.New("INIT ACK outbound stream request must be > 0")
	ErrInitAdvertisedReceiver1500    = errors.New("INIT ACK Advertised Receiver Window Credit (a_rwnd) must be >= 1500")
	ErrInitUnknownParam              = errors.New("INIT with unknown param")
)

func (i *chunkInit) unmarshal(raw []byte) error {
	if err := i.chunkHeader.unmarshal(raw); err != nil {
		return err
	}

	if i.typ != ctInit {
		return fmt.Errorf("%w: actually is %s", ErrChunkTypeNotTypeInit, i.typ.String())
	} else if len(i.raw) < initChunkMinLength {
		return fmt.Errorf("%w: %d actual: %d", ErrChunkValueNotLongEnough, initChunkMinLength, len(i.raw))
	}

	// RFC 9260: INIT Chunk Flags are reserved; set to 0 by sender and
	// ignored by receiver. Do NOT fail if non-zero. (We still set them
	// to 0 on marshal.)

	if err := i.chunkInitCommon.unmarshal(i.raw); err != nil {
		return fmt.Errorf("%w: %v", ErrChunkTypeInitUnmarshalFailed, err) //nolint:errorlint
	}

	return nil
}

func (i *chunkInit) marshal() ([]byte, error) {
	initShared, err := i.chunkInitCommon.marshal()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrChunkTypeInitMarshalFailed, err) //nolint:errorlint
	}

	i.chunkHeader.typ = ctInit
	i.chunkHeader.flags = 0 // RFC 9260: sender MUST set INIT flags to 0
	i.chunkHeader.raw = initShared

	return i.chunkHeader.marshal()
}

func (i *chunkInit) check() (abort bool, err error) {
	// Initiate Tag MUST NOT be 0.
	if i.initiateTag == 0 {
		return true, ErrChunkTypeInitInitateTagZero
	}

	// MIS (inbound streams requested) MUST NOT be 0.
	if i.numInboundStreams == 0 {
		return true, ErrInitInboundStreamRequestZero
	}

	// OS (outbound streams requested) MUST NOT be 0.
	if i.numOutboundStreams == 0 {
		return true, ErrInitOutboundStreamRequestZero
	}

	// a_rwnd MUST be >= 1500 bytes in INIT/INIT-ACK.
	if i.advertisedReceiverWindowCredit < 1500 {
		return true, ErrInitAdvertisedReceiver1500
	}

	// Unknown parameter handling per Parameter Header semantics.
	for _, p := range i.unrecognizedParams {
		if p.unrecognizedAction == paramHeaderUnrecognizedActionStop ||
			p.unrecognizedAction == paramHeaderUnrecognizedActionStopAndReport {
			return true, ErrInitUnknownParam
		}
	}

	return false, nil
}

// String makes chunkInit printable.
func (i *chunkInit) String() string {
	return fmt.Sprintf("%s\n%s", i.chunkHeader, i.chunkInitCommon)
}
