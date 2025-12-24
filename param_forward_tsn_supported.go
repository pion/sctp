// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import "errors"

// At the initialization of the association, the sender of the INIT or
// INIT ACK chunk MAY include this OPTIONAL parameter to inform its peer
// that it supports the Forward TSN chunk (RFC 9260).
//
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |    Parameter Type = 49152     |  Parameter Length = 4         |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

type paramForwardTSNSupported struct {
	paramHeader
}

// Errors for Forward TSN Supported parameter.
var (
	ErrForwardTSNSupportedParamInvalidLength = errors.New("forward tsn supported parameter invalid length")
)

func (f *paramForwardTSNSupported) marshal() ([]byte, error) {
	f.typ = forwardTSNSupp
	f.raw = []byte{}

	return f.paramHeader.marshal()
}

func (f *paramForwardTSNSupported) unmarshal(raw []byte) (param, error) {
	err := f.paramHeader.unmarshal(raw)
	if err != nil {
		return nil, err
	}

	// Must have no value (header-only parameter).
	if len(f.raw) != 0 {
		return nil, ErrForwardTSNSupportedParamInvalidLength
	}

	return f, nil
}
