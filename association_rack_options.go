// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"time"
)

// rackSettings holds the optional RACK related settings for an association.
type rackSettings struct {
	// Optional: size of window used to determine minimum RTT for RACK (defaults to 30s)
	rackMinRTTWnd *windowedMin

	// Optional: cap the minimum reordering window: 0 = use quarter-RTT
	rackReoWndFloor time.Duration

	// Optional: receiver worst-case delayed-ACK for PTO when only one packet is in flight
	rackWCDelAck time.Duration
}

// AssociationRACKOption represents a function that can be used to configure an Association's RACK options.
type AssociationRACKOption func(*rackSettings) error

// RACK config options //

// WithRackMinRTTWnd sets the length of the local minimum window used to determine the minRTT.
// By default this is 30 seconds.
func WithRackMinRTTWnd(rackMinRTTWnd time.Duration) AssociationRACKOption {
	return func(a *rackSettings) error {
		if rackMinRTTWnd <= 0 {
			return errInvalidRackMinRTTWnd
		}
		a.rackMinRTTWnd = newWindowedMin(rackMinRTTWnd)

		return nil
	}
}

// WithRackReoWndFloor sets the RACK reordering window floor for the association.
// By default this is 0.
func WithRackReoWndFloor(rackReoWndFloor time.Duration) AssociationRACKOption {
	return func(a *rackSettings) error {
		if rackReoWndFloor < 0 {
			return errInvalidRackReoWndFloor
		}
		a.rackReoWndFloor = rackReoWndFloor

		return nil
	}
}

// WithRackWCDelAck sets the receiver worst-case delayed-ACK for PTO when only 1 packet is in flight.
// By default this is 200 ms.
func WithRackWCDelAck(rackWCDelAck time.Duration) AssociationRACKOption {
	return func(a *rackSettings) error {
		if rackWCDelAck <= 0 {
			return errInvalidRackWcDelAck
		}
		a.rackWCDelAck = rackWCDelAck

		return nil
	}
}

// WithRACKOptions configures optional RACK settings using the above options.
// This also creates the new windowedMin slice used for tracking the minRTT.
func WithRACKOptions(opts ...AssociationRACKOption) AssociationOption {
	return sharedOption(func(c *Config) error {
		cfg := c.rack
		for _, opt := range opts {
			if opt == nil {
				continue
			}

			if err := opt(&cfg); err != nil {
				return err
			}
		}

		c.rack = cfg

		return nil
	})
}
