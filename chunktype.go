// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import "fmt"

// chunkType identifies the kind of SCTP chunk carried in a packet.
type chunkType uint8

// Known chunk types (RFC 9260). Values include the unrecognized-action
// bits encoded in the high 2 bits of the type field.
const (
	ctPayloadData      chunkType = 0  // DATA
	ctInit             chunkType = 1  // INIT
	ctInitAck          chunkType = 2  // INIT-ACK
	ctSack             chunkType = 3  // SACK
	ctHeartbeat        chunkType = 4  // HEARTBEAT
	ctHeartbeatAck     chunkType = 5  // HEARTBEAT-ACK
	ctAbort            chunkType = 6  // ABORT
	ctShutdown         chunkType = 7  // SHUTDOWN
	ctShutdownAck      chunkType = 8  // SHUTDOWN-ACK
	ctError            chunkType = 9  // ERROR
	ctCookieEcho       chunkType = 10 // COOKIE-ECHO
	ctCookieAck        chunkType = 11 // COOKIE-ACK
	ctECNE             chunkType = 12 // ECN Echo (ECNE)
	ctCWR              chunkType = 13 // Congestion Window Reduced (CWR)
	ctShutdownComplete chunkType = 14 // SHUTDOWN-COMPLETE
	ctAuth             chunkType = 15 // AUTH (RFC 4895; referenced by RFC 9260)

	// Extension chunks (values embed "skip" unrecognized-action semantics).
	ctReconfig   chunkType = 130 // Re-configuration (RFC 6525)
	ctForwardTSN chunkType = 192 // FORWARD-TSN (RFC 3758)
)

func (c chunkType) String() string { //nolint:cyclop
	switch c {
	case ctPayloadData:
		return "DATA"
	case ctInit:
		return "INIT"
	case ctInitAck:
		return "INIT-ACK"
	case ctSack:
		return "SACK"
	case ctHeartbeat:
		return "HEARTBEAT"
	case ctHeartbeatAck:
		return "HEARTBEAT-ACK"
	case ctAbort:
		return "ABORT"
	case ctShutdown:
		return "SHUTDOWN"
	case ctShutdownAck:
		return "SHUTDOWN-ACK"
	case ctError:
		return "ERROR"
	case ctCookieEcho:
		return "COOKIE-ECHO"
	case ctCookieAck:
		return "COOKIE-ACK"
	case ctECNE:
		return "ECNE"
	case ctCWR:
		return "CWR"
	case ctShutdownComplete:
		return "SHUTDOWN-COMPLETE"
	case ctAuth:
		return "AUTH"
	case ctReconfig:
		return "RECONFIG"
	case ctForwardTSN:
		return "FORWARD-TSN"
	default:
		return fmt.Sprintf("Unknown ChunkType: %d", c)
	}
}
