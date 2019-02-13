package sctp

import "fmt"

// chunkType is an enum for SCTP Chunk Type field
// This field identifies the type of information contained in the
// Chunk Value field.
type chunkType uint8

// List of known chunkType enums
const (
	ctPayloadData      chunkType = 0
	ctInit             chunkType = 1
	ctInitAck          chunkType = 2
	ctSack             chunkType = 3
	ctHeartbeat        chunkType = 4
	ctHeartbeatAck     chunkType = 5
	ctAbort            chunkType = 6
	ctShutdown         chunkType = 7
	ctShutdownAck      chunkType = 8
	ctError            chunkType = 9
	ctCookieEcho       chunkType = 10
	ctCookieAck        chunkType = 11
	ctCWR              chunkType = 13
	ctShutdownComplete chunkType = 14
	ctReconfig         chunkType = 130
	ctForwardTSN       chunkType = 192
)

func (c chunkType) String() string {
	switch c {
	case ctPayloadData:
		return "Payload data"
	case ctInit:
		return "Initiation"
	case ctInitAck:
		return "Initiation Acknowledgement"
	case ctSack:
		return "Selective Acknowledgement"
	case ctHeartbeat:
		return "Heartbeat"
	case ctHeartbeatAck:
		return "Heartbeat Acknowledgement"
	case ctAbort:
		return "Abort"
	case ctShutdown:
		return "Shutdown"
	case ctShutdownAck:
		return "Shutdown Acknowledgement"
	case ctError:
		return "Error"
	case ctCookieEcho:
		return "Cookie Echo"
	case ctCookieAck:
		return "Cookie Acknowledgement"
	case ctCWR:
		return "Congestion Window Reduced"
	case ctShutdownComplete:
		return "Shutdown Complete"
	case ctReconfig:
		return "Re-configuration Chunk (RE-CONFIG)"
	case ctForwardTSN:
		return "FORWARD TSN"
	default:
		return fmt.Sprintf("Unknown ChunkType: %d", c)
	}
}
