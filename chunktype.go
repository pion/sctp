package sctp

import "fmt"

// chunkType is an enum for SCTP Chunk Type field
// This field identifies the type of information contained in the
// Chunk Value field.
type chunkType uint8

// List of known chunkType enums
const (
	PAYLOADDATA      chunkType = 0
	INIT             chunkType = 1
	INITACK          chunkType = 2
	SACK             chunkType = 3
	HEARTBEAT        chunkType = 4
	HEARTBEATACK     chunkType = 5
	ABORT            chunkType = 6
	SHUTDOWN         chunkType = 7
	SHUTDOWNACK      chunkType = 8
	ERROR            chunkType = 9
	COOKIEECHO       chunkType = 10
	COOKIEACK        chunkType = 11
	CWR              chunkType = 13
	SHUTDOWNCOMPLETE chunkType = 14
	RECONFIG         chunkType = 130
	FORWARDTSN       chunkType = 192
)

func (c chunkType) String() string {
	switch c {
	case PAYLOADDATA:
		return "Payload data"
	case INIT:
		return "Initiation"
	case INITACK:
		return "Initiation Acknowledgement"
	case SACK:
		return "Selective Acknowledgement"
	case HEARTBEAT:
		return "Heartbeat"
	case HEARTBEATACK:
		return "Heartbeat Acknowledgement"
	case ABORT:
		return "Abort"
	case SHUTDOWN:
		return "Shutdown"
	case SHUTDOWNACK:
		return "Shutdown Acknowledgement"
	case ERROR:
		return "Error"
	case COOKIEECHO:
		return "Cookie Echo"
	case COOKIEACK:
		return "Cookie Acknowledgement"
	case CWR:
		return "Congestion Window Reduced"
	case SHUTDOWNCOMPLETE:
		return "Shutdown Complete"
	case RECONFIG:
		return "Re-configuration Chunk (RE-CONFIG)"
	case FORWARDTSN:
		return "FORWARD TSN"
	default:
		return fmt.Sprintf("Unknown ChunkType: %d", c)
	}
}
