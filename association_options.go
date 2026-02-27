// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"net"

	"github.com/pion/logging"
)

// ServerOption configures a Server.
type ServerOption interface {
	applyServer(*Config) error
}

// ClientOption configures a Client.
type ClientOption interface {
	applyClient(*Config) error
}

// AssociationOption applies to both client and server.
type AssociationOption interface {
	ServerOption
	ClientOption
}

// sharedOption wraps an apply function that works for both client and server.
type sharedOption func(*Config) error

func (o sharedOption) applyServer(c *Config) error { return o(c) }
func (o sharedOption) applyClient(c *Config) error { return o(c) }

// WithLoggerFactory sets the logger factory for the association.
func WithLoggerFactory(loggerFactory logging.LoggerFactory) AssociationOption {
	return sharedOption(func(c *Config) error {
		if loggerFactory == nil {
			return errNilLoggerFactory // add if you don't already have it
		}
		c.LoggerFactory = loggerFactory

		return nil
	})
}

// WithName sets the name of the association.
func WithName(name string) AssociationOption {
	return sharedOption(func(c *Config) error {
		c.Name = name

		return nil
	})
}

// WithNetConn sets the net.Conn used by the association.
func WithNetConn(conn net.Conn) AssociationOption {
	return sharedOption(func(c *Config) error {
		if conn == nil {
			return errNilNetConn
		}
		c.NetConn = conn

		return nil
	})
}

// WithBlockWrite sets whether the association should use blocking writes.
// By default this is false.
func WithBlockWrite(b bool) AssociationOption {
	return sharedOption(func(c *Config) error {
		c.BlockWrite = b

		return nil
	})
}

// WithEnableZeroChecksum sets whether the association should accept zero as a valid checksum.
// By default this is false.
func WithEnableZeroChecksum(b bool) AssociationOption {
	return sharedOption(func(c *Config) error {
		c.EnableZeroChecksum = b

		return nil
	})
}

// WithMTU sets the MTU size for the association.
// By default this is 1228.
func WithMTU(size uint32) AssociationOption {
	return sharedOption(func(c *Config) error {
		if size == 0 {
			return errZeroMTUOption
		}
		c.MTU = size

		return nil
	})
}

// Congestion control options //

// WithMaxReceiveBufferSize sets the maximum receive buffer size for the association.
// By default this is 1024 * 1024 = 1048576.
func WithMaxReceiveBufferSize(size uint32) AssociationOption {
	return sharedOption(func(c *Config) error {
		if size == 0 {
			return errZeroMaxReceiveBufferOption
		}
		c.MaxReceiveBufferSize = size

		return nil
	})
}

// WithMaxMessageSize sets the maximum message size for the association.
// By default this is 65536.
func WithMaxMessageSize(size uint32) AssociationOption {
	return sharedOption(func(c *Config) error {
		if size == 0 {
			return errZeroMaxMessageSize
		}
		c.MaxMessageSize = size

		return nil
	})
}

// WithRTOMax sets the max retransmission timeout in ms for the association.
func WithRTOMax(rtoMax float64) AssociationOption {
	return sharedOption(func(c *Config) error {
		if rtoMax <= 0 {
			return errInvalidRTOMax
		}
		c.RTOMax = rtoMax

		return nil
	})
}

// WithMinCwnd sets the minimum congestion window for the association.
func WithMinCwnd(minCwnd uint32) AssociationOption {
	return sharedOption(func(c *Config) error {
		c.MinCwnd = minCwnd

		return nil
	})
}

// WithFastRtxWnd sets the fast retransmission window for the association.
func WithFastRtxWnd(fastRtxWnd uint32) AssociationOption {
	return sharedOption(func(c *Config) error {
		c.FastRtxWnd = fastRtxWnd

		return nil
	})
}

// WithCwndCAStep sets the congestion window congestion avoidance step for the association.
func WithCwndCAStep(cwndCAStep uint32) AssociationOption {
	return sharedOption(func(c *Config) error {
		c.CwndCAStep = cwndCAStep

		return nil
	})
}
