// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

/*
chunkPayloadData represents an SCTP Chunk of type DATA (RFC 9260 section 3.3.1)

	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|   Type = 0    | Res |I|U|B|E|            Length               |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                              TSN                              |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|      Stream Identifier S      |   Stream Sequence Number n    |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                  Payload Protocol Identifier                  |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                                                               |
	|                 User Data (seq n of Stream S)                 |
	|                                                               |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

An unfragmented user message MUST have both the B and E bits set to 1.
Setting both B and E to 0 indicates a middle fragment: see Table 4 in RFC 9260.
*/

type chunkPayloadData struct {
	chunkHeader

	unordered         bool
	beginningFragment bool
	endingFragment    bool
	immediateSack     bool

	tsn                  uint32
	streamIdentifier     uint16
	streamSequenceNumber uint16
	payloadType          PayloadProtocolIdentifier
	userData             []byte

	// Whether this data chunk was acknowledged (received by peer)
	acked         bool
	missIndicator uint32

	// Partial-reliability parameters used only by sender
	since        time.Time
	nSent        uint32 // number of transmissions made for this chunk
	_abandoned   bool
	_allInflight bool // valid only with the first fragment

	// Retransmission flag set when T1-RTX timeout occurred and this
	// chunk is still in the inflight queue
	retransmit bool

	head *chunkPayloadData // link to the head of the fragment
}

const (
	payloadDataEndingFragmentBitmask   = 1
	payloadDataBeginingFragmentBitmask = 2
	payloadDataUnorderedBitmask        = 4
	payloadDataImmediateSACK           = 8

	payloadDataHeaderSize = 12 // TSN(4) + SID(2) + SSN(2) + PPID(4)
)

// PayloadProtocolIdentifier is an enum for DataChannel payload types.
type PayloadProtocolIdentifier uint32

// PayloadProtocolIdentifier enums
// https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-25
const (
	PayloadTypeUnknown           PayloadProtocolIdentifier = 0
	PayloadTypeWebRTCDCEP        PayloadProtocolIdentifier = 50
	PayloadTypeWebRTCString      PayloadProtocolIdentifier = 51
	PayloadTypeWebRTCBinary      PayloadProtocolIdentifier = 53
	PayloadTypeWebRTCStringEmpty PayloadProtocolIdentifier = 56
	PayloadTypeWebRTCBinaryEmpty PayloadProtocolIdentifier = 57
)

// Data chunk errors.
var (
	ErrChunkPayloadSmall = errors.New("packet is smaller than the header size")
	// RFC 9260 section 3.3.1: Length MUST be 16 + L with L > 0 (exclude padding).
	ErrDATAZeroUserData = errors.New("DATA chunk carries no user data (L must be > 0)")
)

func (p PayloadProtocolIdentifier) String() string {
	switch p {
	case PayloadTypeWebRTCDCEP:
		return "WebRTC DCEP"
	case PayloadTypeWebRTCString:
		return "WebRTC String"
	case PayloadTypeWebRTCBinary:
		return "WebRTC Binary"
	case PayloadTypeWebRTCStringEmpty:
		return "WebRTC String (Empty)"
	case PayloadTypeWebRTCBinaryEmpty:
		return "WebRTC Binary (Empty)"
	default:
		return fmt.Sprintf("Unknown Payload Protocol Identifier: %d", p)
	}
}

func (p *chunkPayloadData) unmarshal(raw []byte) error {
	if err := p.chunkHeader.unmarshal(raw); err != nil {
		return err
	}

	p.immediateSack = p.flags&payloadDataImmediateSACK != 0
	p.unordered = p.flags&payloadDataUnorderedBitmask != 0
	p.beginningFragment = p.flags&payloadDataBeginingFragmentBitmask != 0
	p.endingFragment = p.flags&payloadDataEndingFragmentBitmask != 0

	if len(p.raw) < payloadDataHeaderSize {
		return ErrChunkPayloadSmall
	}

	p.tsn = binary.BigEndian.Uint32(p.raw[0:])
	p.streamIdentifier = binary.BigEndian.Uint16(p.raw[4:])
	p.streamSequenceNumber = binary.BigEndian.Uint16(p.raw[6:])
	p.payloadType = PayloadProtocolIdentifier(binary.BigEndian.Uint32(p.raw[8:]))

	// L > 0 (RFC 9260 section 3.3.1)
	p.userData = p.raw[payloadDataHeaderSize:]
	if len(p.userData) == 0 {
		return ErrDATAZeroUserData
	}

	return nil
}

func (p *chunkPayloadData) marshal() ([]byte, error) {
	// L > 0 (RFC 9260 section 3.3.1)
	if len(p.userData) == 0 {
		return nil, ErrDATAZeroUserData
	}

	payRaw := make([]byte, payloadDataHeaderSize+len(p.userData))

	binary.BigEndian.PutUint32(payRaw[0:], p.tsn)
	binary.BigEndian.PutUint16(payRaw[4:], p.streamIdentifier)
	binary.BigEndian.PutUint16(payRaw[6:], p.streamSequenceNumber)
	binary.BigEndian.PutUint32(payRaw[8:], uint32(p.payloadType))
	copy(payRaw[payloadDataHeaderSize:], p.userData)

	// Only set the defined bits; reserved bits implicitly 0 on transmit
	flags := uint8(0)
	if p.endingFragment {
		flags |= payloadDataEndingFragmentBitmask
	}

	if p.beginningFragment {
		flags |= payloadDataBeginingFragmentBitmask
	}

	if p.unordered {
		flags |= payloadDataUnorderedBitmask
	}

	if p.immediateSack {
		flags |= payloadDataImmediateSACK
	}

	p.chunkHeader.flags = flags
	p.chunkHeader.typ = ctPayloadData
	p.chunkHeader.raw = payRaw

	return p.chunkHeader.marshal()
}

func (p *chunkPayloadData) check() (abort bool, err error) {
	return false, nil
}

// String makes chunkPayloadData printable.
func (p *chunkPayloadData) String() string {
	return fmt.Sprintf("%s\n%d", p.chunkHeader, p.tsn)
}

func (p *chunkPayloadData) abandoned() bool {
	if p.head != nil {
		return p.head._abandoned && p.head._allInflight
	}

	return p._abandoned && p._allInflight
}

func (p *chunkPayloadData) setAbandoned(abandoned bool) {
	if p.head != nil {
		p.head._abandoned = abandoned

		return
	}
	p._abandoned = abandoned
}

func (p *chunkPayloadData) setAllInflight() {
	if p.endingFragment {
		if p.head != nil {
			p.head._allInflight = true
		} else {
			p._allInflight = true
		}
	}
}

func (p *chunkPayloadData) isFragmented() bool {
	return p.head != nil || !p.beginningFragment || !p.endingFragment
}
