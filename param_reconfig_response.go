// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// This parameter is used by the receiver of a Re-configuration Request
// Parameter to respond to the request. (RFC 6525, which is referenced by RFC 9260)
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Parameter Type = 16       |      Parameter Length         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Re-configuration Response Sequence Number             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                            Result                             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                   Sender's Next TSN (optional)                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                  Receiver's Next TSN (optional)               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

type paramReconfigResponse struct {
	paramHeader

	// This value is copied from the request parameter and is used by the
	// receiver of the Re-configuration Response Parameter to tie the
	// response to the request.
	reconfigResponseSequenceNumber uint32

	// This value describes the result of the processing of the request.
	result reconfigResult

	// Optional fields (RFC 6525).
	senderNextTSNPresent   bool
	senderNextTSN          uint32
	receiverNextTSNPresent bool
	receiverNextTSN        uint32
}

type reconfigResult uint32

const (
	reconfigResultSuccessNOP                    reconfigResult = 0
	reconfigResultSuccessPerformed              reconfigResult = 1
	reconfigResultDenied                        reconfigResult = 2
	reconfigResultErrorWrongSSN                 reconfigResult = 3
	reconfigResultErrorRequestAlreadyInProgress reconfigResult = 4
	reconfigResultErrorBadSequenceNumber        reconfigResult = 5
	reconfigResultInProgress                    reconfigResult = 6
)

// Reconfiguration response errors.
var (
	ErrReconfigRespParamTooShort      = errors.New("reconfig response parameter too short")
	ErrReconfigRespParamInvalidLength = errors.New("reconfig response parameter invalid length")
	ErrReconfigRespParamInvalidCombo  = errors.New("receiverNextTSN present requires senderNextTSN present")
)

func (t reconfigResult) String() string {
	switch t {
	case reconfigResultSuccessNOP:
		return "0: Success - Nothing to do"
	case reconfigResultSuccessPerformed:
		return "1: Success - Performed"
	case reconfigResultDenied:
		return "2: Denied"
	case reconfigResultErrorWrongSSN:
		return "3: Error - Wrong SSN"
	case reconfigResultErrorRequestAlreadyInProgress:
		return "4: Error - Request already in progress"
	case reconfigResultErrorBadSequenceNumber:
		return "5: Error - Bad Sequence Number"
	case reconfigResultInProgress:
		return "6: In progress"
	default:
		return fmt.Sprintf("Unknown reconfigResult: %d", t)
	}
}

func (r *paramReconfigResponse) marshal() ([]byte, error) {
	r.typ = reconfigResp

	// Enforce ordering: receiverNextTSN can only be present if senderNextTSN is present.
	if r.receiverNextTSNPresent && !r.senderNextTSNPresent {
		return nil, ErrReconfigRespParamInvalidCombo
	}

	valueLen := 8
	if r.senderNextTSNPresent {
		valueLen += 4
	}
	if r.receiverNextTSNPresent {
		valueLen += 4
	}

	r.raw = make([]byte, valueLen)
	binary.BigEndian.PutUint32(r.raw[0:], r.reconfigResponseSequenceNumber)
	binary.BigEndian.PutUint32(r.raw[4:], uint32(r.result))

	off := 8
	if r.senderNextTSNPresent {
		binary.BigEndian.PutUint32(r.raw[off:], r.senderNextTSN)
		off += 4
	}

	if r.receiverNextTSNPresent {
		binary.BigEndian.PutUint32(r.raw[off:], r.receiverNextTSN)
	}

	return r.paramHeader.marshal()
}

func (r *paramReconfigResponse) unmarshal(raw []byte) (param, error) {
	if err := r.paramHeader.unmarshal(raw); err != nil {
		return nil, err
	}

	if len(r.raw) < 8 {
		return nil, ErrReconfigRespParamTooShort
	}

	switch len(r.raw) {
	case 8, 12, 16:
	default:
		return nil, ErrReconfigRespParamInvalidLength
	}

	r.reconfigResponseSequenceNumber = binary.BigEndian.Uint32(r.raw)
	r.result = reconfigResult(binary.BigEndian.Uint32(r.raw[4:]))

	// Optional fields: Sender's Next TSN, Receiver's Next TSN.
	if len(r.raw) >= 12 {
		r.senderNextTSNPresent = true
		r.senderNextTSN = binary.BigEndian.Uint32(r.raw[8:])
	}

	if len(r.raw) == 16 {
		r.receiverNextTSNPresent = true
		r.receiverNextTSN = binary.BigEndian.Uint32(r.raw[12:])
	}

	return r, nil
}
