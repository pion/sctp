// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"net"

	"github.com/pion/logging"
)

// AssociationOption represents a function that can be used to configure an Association.
type AssociationOption func(*Association) error

// WithLoggerFactory sets the logger factory for the association.
func WithLoggerFactory(loggerFactory logging.LoggerFactory) AssociationOption {
	return func(a *Association) error {
		a.log = loggerFactory.NewLogger("sctp")

		return nil
	}
}

// WithName sets the name of the association.
func WithName(name string) AssociationOption {
	return func(a *Association) error {
		a.name = name

		return nil
	}
}

// WithNetConn sets the net.Conn used by the association.
func WithNetConn(net net.Conn) AssociationOption {
	return func(a *Association) error {
		a.netConn = net

		return nil
	}
}

// WithBlockWrite sets whether the association should use blocking writes.
// By default this is false.
func WithBlockWrite(b bool) AssociationOption {
	return func(a *Association) error {
		a.blockWrite = b

		return nil
	}
}

// WithEnableZeroChecksum sets whether the association should accept zero as a valid checksum.
// By default this is false.
func WithEnableZeroChecksum(b bool) AssociationOption {
	return func(a *Association) error {
		a.recvZeroChecksum = b

		return nil
	}
}

// WithMTU sets the MTU size for the association.
// By default this is 1228.
func WithMTU(size uint32) AssociationOption {
	return func(a *Association) error {
		if size == 0 {
			return ErrZeroMTUOption
		}
		a.mtu = size

		return nil
	}
}

// Congestion control options //

// WithMaxReceiveBufferSize sets the maximum receive buffer size for the association.
// By default this is 1024 * 1024 = 1048576.
func WithMaxReceiveBufferSize(size uint32) AssociationOption {
	return func(a *Association) error {
		if size == 0 {
			return ErrZeroMaxReceiveBufferOption
		}
		a.maxReceiveBufferSize = size

		return nil
	}
}

// WithMaxMessageSize sets the maximum message size for the association.
// By default this is 65536.
func WithMaxMessageSize(size uint32) AssociationOption {
	return func(a *Association) error {
		if size == 0 {
			return ErrZeroMaxMessageSize
		}
		a.maxMessageSize = size

		return nil
	}
}

// WithRTOMax sets the max retransmission timeout in ms for the association.
func WithRTOMax(rtoMax float64) AssociationOption {
	return func(a *Association) error {
		if rtoMax <= 0 {
			return ErrInvalidRTOMax
		}
		a.rtoMax = rtoMax

		return nil
	}
}

// WithMinCwnd sets the minimum congestion window for the association.
func WithMinCwnd(minCwnd uint32) AssociationOption {
	return func(a *Association) error {
		a.minCwnd = minCwnd

		return nil
	}
}

// WithFastRtxWnd sets the fast retransmission window for the association.
func WithFastRtxWnd(fastRtxWnd uint32) AssociationOption {
	return func(a *Association) error {
		a.fastRtxWnd = fastRtxWnd

		return nil
	}
}

// WithCwndCAStep sets the congestion window congestion avoidance step for the association.
func WithCwndCAStep(cwndCAStep uint32) AssociationOption {
	return func(a *Association) error {
		a.cwndCAStep = cwndCAStep

		return nil
	}
}
