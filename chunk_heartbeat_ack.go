// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"errors"
	"fmt"
)

/*
chunkHeartbeatAck represents an SCTP Chunk of type HEARTBEAT ACK (RFC 9260 section 3.3.6).

An endpoint sends this chunk in response to a HEARTBEAT. The chunk body MUST
contain exactly one variable-length parameter:

Variable Parameters                  Status     Type Value
-------------------------------------------------------------
Heartbeat Info                       Mandatory   1

nolint:godot
*/
type chunkHeartbeatAck struct {
	chunkHeader
	params []param
}

// Heartbeat ack chunk errors.
var (
	// Deprecated: this error is no longer used but is kept for compatibility.
	ErrUnimplemented                = errors.New("unimplemented")
	ErrChunkTypeNotHeartbeatAck     = errors.New("chunk type is not of type HEARTBEAT ACK")
	ErrHeartbeatAckParams           = errors.New("heartbeat Ack must have one param")
	ErrHeartbeatAckNotHeartbeatInfo = errors.New("heartbeat Ack must have one param, and it should be a HeartbeatInfo")
	ErrHeartbeatAckMarshalParam     = errors.New("unable to marshal parameter for Heartbeat Ack")
)

func (h *chunkHeartbeatAck) unmarshal(raw []byte) error { //nolint:cyclop
	if err := h.chunkHeader.unmarshal(raw); err != nil {
		return err
	}

	if h.typ != ctHeartbeatAck {
		return fmt.Errorf("%w %s", ErrChunkTypeNotHeartbeatAck, h.typ.String())
	}

	// Accept an empty acknowledgment for compatibility and leave the RTT estimate as is.
	if len(h.raw) == 0 {
		h.params = nil

		return nil
	}

	if len(h.raw) < initOptionalVarHeaderLength {
		return fmt.Errorf("%w: %d", ErrHeartbeatAckParams, len(h.raw))
	}

	pType, err := parseParamType(h.raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHeartbeatAckParams, err) //nolint:errorlint
	}
	if pType != heartbeatInfo {
		return fmt.Errorf("%w: instead have %s", ErrHeartbeatAckNotHeartbeatInfo, pType.String())
	}

	var pHeader paramHeader
	if e := pHeader.unmarshal(h.raw); e != nil {
		return fmt.Errorf("%w: %v", ErrHeartbeatAckParams, e) //nolint:errorlint
	}
	plen := pHeader.length()
	if plen < initOptionalVarHeaderLength || plen > len(h.raw) {
		return fmt.Errorf("%w: %d", ErrHeartbeatAckParams, plen)
	}

	p, err := buildParam(pType, h.raw[:plen])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHeartbeatAckMarshalParam, err) //nolint:errorlint
	}
	h.params = []param{p}

	// Any trailing bytes beyond the single param must be zero.
	if rem := h.raw[plen:]; len(rem) > 0 && !allZero(rem) {
		return ErrHeartbeatExtraNonZero
	}

	return nil
}

func (h *chunkHeartbeatAck) marshal() ([]byte, error) {
	if len(h.params) != 1 {
		return nil, ErrHeartbeatAckParams
	}
	if _, ok := h.params[0].(*paramHeartbeatInfo); !ok {
		return nil, ErrHeartbeatAckNotHeartbeatInfo
	}

	pp, err := h.params[0].marshal()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHeartbeatAckMarshalParam, err) //nolint:errorlint
	}

	// single TLV: no inter-parameter padding within the chunk body.
	h.chunkHeader.typ = ctHeartbeatAck
	h.chunkHeader.flags = 0 // sender MUST set to 0
	h.chunkHeader.raw = append([]byte(nil), pp...)

	return h.chunkHeader.marshal()
}

func (h *chunkHeartbeatAck) check() (abort bool, err error) {
	return false, nil
}
