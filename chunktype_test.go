package sctp

import "testing"

func TestChunkType_String(t *testing.T) {
	tt := []struct {
		chunkType chunkType
		expected  string
	}{
		{ctPayloadData, "Payload data"},
		{ctInit, "Initiation"},
		{ctInitAck, "Initiation Acknowledgement"},
		{ctSack, "Selective Acknowledgement"},
		{ctHeartbeat, "Heartbeat"},
		{ctHeartbeatAck, "Heartbeat Acknowledgement"},
		{ctAbort, "Abort"},
		{ctShutdown, "Shutdown"},
		{ctShutdownAck, "Shutdown Acknowledgement"},
		{ctError, "Error"},
		{ctCookieEcho, "Cookie Echo"},
		{ctCookieAck, "Cookie Acknowledgement"},
		{ctCWR, "Congestion Window Reduced"},
		{ctShutdownComplete, "Shutdown Complete"},
		{ctReconfig, "Re-configuration Chunk (RE-CONFIG)"},
		{ctForwardTSN, "FORWARD TSN"},
		{chunkType(255), "Unknown ChunkType: 255"},
	}

	for _, tc := range tt {
		if tc.chunkType.String() != tc.expected {
			t.Errorf("failed to stringify chunkType %v, expected %s", tc.chunkType, tc.expected)
		}
	}
}
