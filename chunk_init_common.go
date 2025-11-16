// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

/*
chunkInitCommon represents an SCTP Chunk body of type INIT and INIT ACK (RFC 9260 section 3.3.2)

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Initiate Tag                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Advertised Receiver Window Credit (a_rwnd)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Number of Outbound Streams   |  Number of Inbound Streams    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                          Initial TSN                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|              Optional/Variable-Length Parameters              |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Fixed Parameters                     Status
----------------------------------------------
Initiate Tag                        Mandatory
Advertised Receiver Window Credit   Mandatory
Number of Outbound Streams          Mandatory
Number of Inbound Streams           Mandatory
Initial TSN                         Mandatory
*/

type chunkInitCommon struct {
	initiateTag                    uint32
	advertisedReceiverWindowCredit uint32
	numOutboundStreams             uint16
	numInboundStreams              uint16
	initialTSN                     uint32
	params                         []param
	unrecognizedParams             []paramHeader
}

const (
	initChunkMinLength          = 16
	initOptionalVarHeaderLength = 4
)

// Init chunk errors.
var (
	ErrInitChunkParseParamTypeFailed = errors.New("failed to parse param type")
	ErrInitAckMarshalParam           = errors.New("unable to marshal parameter for INIT/INITACK")

	// New stricter parsing errors (RFC 9260).
	ErrInitChunkMinLength      = errors.New("chunk init common body smaller than minimum length")
	ErrInitParamHeaderTooShort = errors.New("remaining bytes smaller than parameter header")
	ErrInitParamLengthInvalid  = errors.New("parameter length invalid or exceeds remaining bytes")
	ErrInitTrailingGarbage     = errors.New("trailing non-zero bytes after parameters")
)

func (i *chunkInitCommon) unmarshal(raw []byte) error { //nolint:cyclop
	if len(raw) < initChunkMinLength {
		return fmt.Errorf("%w: %d", ErrInitChunkMinLength, len(raw))
	}

	i.initiateTag = binary.BigEndian.Uint32(raw[0:])
	i.advertisedReceiverWindowCredit = binary.BigEndian.Uint32(raw[4:])
	i.numOutboundStreams = binary.BigEndian.Uint16(raw[8:])
	i.numInboundStreams = binary.BigEndian.Uint16(raw[10:])
	i.initialTSN = binary.BigEndian.Uint32(raw[12:])

	offset := initChunkMinLength
	for {
		remaining := len(raw) - offset
		if remaining == 0 {
			break // no params
		}

		if remaining < initOptionalVarHeaderLength {
			if !allZero(raw[offset:]) {
				return ErrInitParamHeaderTooShort
			}

			break
		}

		var pHeader paramHeader
		if err := pHeader.unmarshal(raw[offset:]); err != nil {
			return fmt.Errorf("%w: %w", ErrInitChunkParseParamTypeFailed, err)
		}

		plen := pHeader.length()
		if plen < initOptionalVarHeaderLength || plen > remaining {
			return ErrInitParamLengthInvalid
		}

		if p, err := buildParam(pHeader.typ, raw[offset:offset+plen]); err != nil {
			i.unrecognizedParams = append(i.unrecognizedParams, pHeader)
		} else {
			i.params = append(i.params, p)
		}

		offset += plen

		// parameters (except the last) are aligned to 4 bytes
		// move to next 4-byte boundary without overrunning the chunk body.
		if offset < len(raw) {
			pad := getPadding(offset)
			if pad != 0 {
				if offset+pad > len(raw) {
					// the last parameter wasn't padded and we reached end-of-body, so clamp it.
					offset = len(raw)
				} else {
					offset += pad
				}
			}
		}
	}

	// reject if anything remains and is not zero.
	if offset < len(raw) && !allZero(raw[offset:]) {
		return ErrInitTrailingGarbage
	}

	return nil
}

func (i *chunkInitCommon) marshal() ([]byte, error) {
	// Build fixed header separately
	hdr := make([]byte, initChunkMinLength)
	binary.BigEndian.PutUint32(hdr[0:], i.initiateTag)
	binary.BigEndian.PutUint32(hdr[4:], i.advertisedReceiverWindowCredit)
	binary.BigEndian.PutUint16(hdr[8:], i.numOutboundStreams)
	binary.BigEndian.PutUint16(hdr[10:], i.numInboundStreams)
	binary.BigEndian.PutUint32(hdr[12:], i.initialTSN)

	out := make([]byte, 0, initChunkMinLength)
	out = append(out, hdr...)

	for idx, p := range i.params {
		pp, err := p.marshal()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInitAckMarshalParam, err)
		}

		out = append(out, pp...)

		// pad every parameter except the last to a 4-byte boundary
		if idx != len(i.params)-1 {
			out = padByte(out, getPadding(len(pp)))
		}
	}

	return out, nil
}

// String makes chunkInitCommon printable.
func (i chunkInitCommon) String() string {
	format := `initiateTag: %d
	advertisedReceiverWindowCredit: %d
	numOutboundStreams: %d
	numInboundStreams: %d
	initialTSN: %d`

	res := fmt.Sprintf(format,
		i.initiateTag,
		i.advertisedReceiverWindowCredit,
		i.numOutboundStreams,
		i.numInboundStreams,
		i.initialTSN,
	)

	for i, param := range i.params {
		res += fmt.Sprintf("Param %d:\n %s", i, param)
	}

	return res
}

// allZero returns true if every byte is 0x00.
func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}

	return true
}
