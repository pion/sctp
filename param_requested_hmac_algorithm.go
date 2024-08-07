// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

type hmacAlgorithm uint16

const (
	hmacResv1  hmacAlgorithm = 0
	hmacSHA128 hmacAlgorithm = 1
	hmacResv2  hmacAlgorithm = 2
	hmacSHA256 hmacAlgorithm = 3
)

// ErrInvalidAlgorithmType is returned if unknown auth algorithm is specified.
var ErrInvalidAlgorithmType = errors.New("invalid algorithm type")

// ErrInvalidChunkLength is returned if the chunk length is invalid.
var ErrInvalidChunkLength = errors.New("invalid chunk length")

func (c hmacAlgorithm) String() string {
	switch c {
	case hmacResv1:
		return "HMAC Reserved (0x00)"
	case hmacSHA128:
		return "HMAC SHA-128"
	case hmacResv2:
		return "HMAC Reserved (0x02)"
	case hmacSHA256:
		return "HMAC SHA-256"
	default:
		return fmt.Sprintf("Unknown HMAC Algorithm type: %d", c)
	}
}

type paramRequestedHMACAlgorithm struct {
	paramHeader
	availableAlgorithms []hmacAlgorithm
}

func (r *paramRequestedHMACAlgorithm) marshal() ([]byte, error) {
	r.typ = reqHMACAlgo
	r.raw = make([]byte, len(r.availableAlgorithms)*2)
	i := 0
	for _, a := range r.availableAlgorithms {
		binary.BigEndian.PutUint16(r.raw[i:], uint16(a))
		i += 2
	}

	return r.paramHeader.marshal()
}

func (r *paramRequestedHMACAlgorithm) unmarshal(raw []byte) (param, error) {
	err := r.paramHeader.unmarshal(raw)
	if err != nil {
		return nil, err
	}
	if len(r.raw)%2 == 1 {
		return nil, ErrInvalidChunkLength
	}

	i := 0
	for i < len(r.raw) {
		a := hmacAlgorithm(binary.BigEndian.Uint16(r.raw[i:]))
		switch a {
		case hmacSHA128:
			fallthrough
		case hmacSHA256:
			r.availableAlgorithms = append(r.availableAlgorithms, a)
		default:
			return nil, fmt.Errorf("%w: %v", ErrInvalidAlgorithmType, a)
		}

		i += 2
	}

	return r, nil
}
