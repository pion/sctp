// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"errors"
)

var (
	// ErrZeroMTUOption indicates that the MTU option was set to zero.
	ErrZeroMTUOption = errors.New("MTU option cannot be set to zero")

	// ErrZeroMaxReceiveBufferOption indicates that the MTU option was set to zero.
	ErrZeroMaxReceiveBufferOption = errors.New("MaxReceiveBuffer option cannot be set to zero")

	// ErrZeroMaxMessageSize indicates that the MTU option was set to zero.
	ErrZeroMaxMessageSize = errors.New("MaxMessageSize option cannot be set to zero")

	// ErrInvalidRTOMax indicates that the RTO max was set to 0 or a negative value.
	ErrInvalidRTOMax = errors.New("RTO max was set to <= 0")

	// ErrInvalidRackMinRTTWnd indicates the length of the local minimum window used to determine the
	// minRTT was set to <= 0.
	ErrInvalidRackMinRTTWnd = errors.New("RackMinRTT was set to <= 0")

	// ErrInvalidRackReoWndFloor indicates the length of the RACK reordering window floor was set to < 0.
	ErrInvalidRackReoWndFloor = errors.New("RackReoWndFloor was set to < 0")

	// ErrInvalidWcDelAck indicates the receiver worst-case delayed-ACK for PTO when only 1 packet in flight
	// was set to < 0.
	ErrInvalidRackWcDelAck = errors.New("RackWcDelAck was set to <= 0")
)
