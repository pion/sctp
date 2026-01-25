// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"errors"
)

var (
	errNilNetConn       = errors.New("netConn must not be nil")
	errNilLoggerFactory = errors.New("loggerFactory must not be nil")

	// errZeroMTUOption indicates that the MTU option was set to zero.
	errZeroMTUOption = errors.New("MTU option cannot be set to zero")

	// errZeroMaxReceiveBufferOption indicates that the MTU option was set to zero.
	errZeroMaxReceiveBufferOption = errors.New("MaxReceiveBuffer option cannot be set to zero")

	// errZeroMaxMessageSize indicates that the MTU option was set to zero.
	errZeroMaxMessageSize = errors.New("MaxMessageSize option cannot be set to zero")

	// errInvalidRTOMax indicates that the RTO max was set to 0 or a negative value.
	errInvalidRTOMax = errors.New("RTO max was set to <= 0")

	// errInvalidRackMinRTTWnd indicates the length of the local minimum window used to determine the
	// minRTT was set to <= 0.
	errInvalidRackMinRTTWnd = errors.New("RackMinRTT was set to <= 0")

	// errInvalidRackReoWndFloor indicates the length of the RACK reordering window floor was set to < 0.
	errInvalidRackReoWndFloor = errors.New("RackReoWndFloor was set to < 0")

	// errInvalidRackWcDelAck indicates the receiver worst-case delayed-ACK for PTO when only 1 packet in flight
	// was set to < 0.
	errInvalidRackWcDelAck = errors.New("RackWcDelAck was set to <= 0")
)
