// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"errors"
)

const (
	// Fixed value payload size before the (optional) stream list:
	// RSN(4) + ResponseRSN(4) + SenderLastTSN(4) = 12 bytes.
	paramOutgoingResetRequestStreamIdentifiersOffset = 12
)

// This parameter is used by the sender to request the reset of some or
// all outgoing streams. Defined in RFC 6525 section 4.1 and referenced by RFC 9260.
//
//	0                   1                   2                   3
//	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Parameter Type = 13       | Parameter Length = 16 + 2 * N |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Re-configuration Request Sequence Number            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Re-configuration Response Sequence Number           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                Sender's Last Assigned TSN                     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Stream Number 1 (optional)   |    Stream Number 2 (optional) |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                            ......                             /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Stream Number N-1 (optional) |    Stream Number N (optional) |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

type paramOutgoingResetRequest struct {
	paramHeader
	// reconfigRequestSequenceNumber is used to identify the request.  It is a monotonically
	// increasing number that is initialized to the same value as the
	// initial TSN. It is increased by 1 whenever sending a new Re-
	// configuration Request Parameter. (RFC 6525 section 4)
	reconfigRequestSequenceNumber uint32
	// When this Outgoing SSN Reset Request Parameter is sent in response
	// to an Incoming SSN Reset Request Parameter, this parameter is also
	// an implicit response to the incoming request.  This field then
	// holds the Re-configuration Request Sequence Number of the incoming
	// request. In other cases, it holds the next expected
	// Re-configuration Request Sequence Number minus 1.
	reconfigResponseSequenceNumber uint32
	// This value holds the next TSN minus 1 -- in other words, the last
	// TSN that this sender assigned.
	senderLastTSN uint32
	// This optional field, if included, is used to indicate specific
	// streams that are to be reset. If no streams are listed, then all
	// streams are to be reset.
	streamIdentifiers []uint16
}

// Outgoing reset request parameter errors.
var (
	ErrSSNResetRequestParamTooShort      = errors.New("outgoing SSN reset request parameter too short")
	ErrSSNResetRequestParamInvalidLength = errors.New("outgoing SSN reset request parameter invalid length")
)

func (r *paramOutgoingResetRequest) marshal() ([]byte, error) {
	r.typ = outSSNResetReq
	r.raw = make([]byte, paramOutgoingResetRequestStreamIdentifiersOffset+2*len(r.streamIdentifiers))
	binary.BigEndian.PutUint32(r.raw, r.reconfigRequestSequenceNumber)
	binary.BigEndian.PutUint32(r.raw[4:], r.reconfigResponseSequenceNumber)
	binary.BigEndian.PutUint32(r.raw[8:], r.senderLastTSN)

	for i, sID := range r.streamIdentifiers {
		binary.BigEndian.PutUint16(r.raw[paramOutgoingResetRequestStreamIdentifiersOffset+2*i:], sID)
	}

	return r.paramHeader.marshal()
}

func (r *paramOutgoingResetRequest) unmarshal(raw []byte) (param, error) {
	err := r.paramHeader.unmarshal(raw)
	if err != nil {
		return nil, err
	}

	// Need at least the fixed 12-byte value.
	if len(r.raw) < paramOutgoingResetRequestStreamIdentifiersOffset {
		return nil, ErrSSNResetRequestParamTooShort
	}

	// The remaining value length must be 2*N (each stream id is 2 bytes).
	rem := len(r.raw) - paramOutgoingResetRequestStreamIdentifiersOffset
	if rem%2 != 0 {
		return nil, ErrSSNResetRequestParamInvalidLength
	}

	r.reconfigRequestSequenceNumber = binary.BigEndian.Uint32(r.raw)
	r.reconfigResponseSequenceNumber = binary.BigEndian.Uint32(r.raw[4:])
	r.senderLastTSN = binary.BigEndian.Uint32(r.raw[8:])

	nIDs := rem / 2
	if nIDs == 0 {
		// N==0 means "reset all streams" (RFC 6525)
		r.streamIdentifiers = []uint16{}

		return r, nil
	}

	r.streamIdentifiers = make([]uint16, nIDs)
	for i := 0; i < nIDs; i++ {
		off := paramOutgoingResetRequestStreamIdentifiersOffset + 2*i
		r.streamIdentifiers[i] = binary.BigEndian.Uint16(r.raw[off:])
	}

	return r, nil
}
