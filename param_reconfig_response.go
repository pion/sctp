package sctp

import (
	"encoding/binary"

	"errors"
)

// This parameter is used by the receiver of a Re-configuration Request
// Parameter to respond to the request.
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
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
}

type reconfigResult uint32

const (
	reconfigResultSuccessNOP                    = 0
	reconfigResultSuccessPerformed              = 1
	reconfigResultDenied                        = 2
	reconfigResultErrorWrongSSN                 = 3
	reconfigResultErrorRequestAlreadyInProgress = 4
	reconfigResultErrorBadSequenceNumber        = 5
	reconfigResultInProgress                    = 6
)

func (r *paramReconfigResponse) marshal() ([]byte, error) {
	r.typ = reconfigResp
	r.raw = make([]byte, 8)
	binary.BigEndian.PutUint32(r.raw, r.reconfigResponseSequenceNumber)
	binary.BigEndian.PutUint32(r.raw[4:], uint32(r.result))

	return r.paramHeader.marshal()
}

func (r *paramReconfigResponse) unmarshal(raw []byte) (param, error) {
	err := r.paramHeader.unmarshal(raw)
	if err != nil {
		return nil, err
	}
	if len(r.raw) < 8 {
		return nil, errors.New("reconfig response parameter too short")
	}
	r.reconfigResponseSequenceNumber = binary.BigEndian.Uint32(r.raw)
	r.result = reconfigResult(binary.BigEndian.Uint32(r.raw[4:]))

	return r, nil
}
