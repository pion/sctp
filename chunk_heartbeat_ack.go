// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"errors"
	"fmt"
)

/*
chunkHeartbeatAck represents an SCTP Chunk of type HEARTBEAT ACK (RFC 9260 section 3.3.7)

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
	ErrUnimplemented                = errors.New("unimplemented")
	ErrHeartbeatAckParams           = errors.New("heartbeat Ack must have one param")
	ErrHeartbeatAckNotHeartbeatInfo = errors.New("heartbeat Ack must have one param, and it should be a HeartbeatInfo")
	ErrHeartbeatAckMarshalParam     = errors.New("unable to marshal parameter for Heartbeat Ack")

	// parsing/validation errors.
	ErrChunkTypeNotHeartbeatAck         = errors.New("ChunkType is not of type HEARTBEAT ACK")
	ErrHeartbeatAckNotLongEnoughInfo    = errors.New("heartbeat Ack is not long enough to contain Heartbeat Info")
	ErrHeartbeatAckParseParamTypeFailed = errors.New("failed to parse param type for Heartbeat Ack")
	ErrHeartbeatAckExtraNonZero         = errors.New("heartbeat Ack has non-zero trailing bytes after last parameter")
)

func (h *chunkHeartbeatAck) unmarshal(raw []byte) error { //nolint:cyclop
	if err := h.chunkHeader.unmarshal(raw); err != nil {
		return err
	}

	if h.typ != ctHeartbeatAck {
		return fmt.Errorf("%w: actually is %s", ErrChunkTypeNotHeartbeatAck, h.typ.String())
	}

	// flags: sender sets to 0; receiver ignores (RFC 9260).
	// need at least a parameter header present (TLV: 4 bytes minimum).
	if len(h.raw) < initOptionalVarHeaderLength {
		return fmt.Errorf("%w: %d", ErrHeartbeatAckNotLongEnoughInfo, len(h.raw))
	}

	pType, err := parseParamType(h.raw)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHeartbeatAckParseParamTypeFailed, err) //nolint:errorlint
	}

	if pType != heartbeatInfo {
		return ErrHeartbeatAckNotHeartbeatInfo
	}

	// now read full header to get TLV length and bounds-check it.
	var pHeader paramHeader
	if e := pHeader.unmarshal(h.raw); e != nil {
		return fmt.Errorf("%w: %v", ErrHeartbeatAckParseParamTypeFailed, e) //nolint:errorlint
	}

	plen := pHeader.length()
	if plen < initOptionalVarHeaderLength || plen > len(h.raw) {
		return ErrHeartbeatAckNotLongEnoughInfo
	}

	// build the single Heartbeat Info parameter.
	p, err := buildParam(pType, h.raw[:plen])
	if err != nil {
		return fmt.Errorf("%w: %v", ErrHeartbeatAckMarshalParam, err) //nolint:errorlint
	}
	h.params = append(h.params, p)

	// any trailing bytes beyond the single param must be all zeros (padding).
	if rem := h.raw[plen:]; len(rem) > 0 && !allZero(rem) {
		return ErrHeartbeatAckExtraNonZero
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
