package sctp

import "testing"

func TestChunkType_String(t *testing.T) {
	tt := []struct {
		chunkType chunkType
		expected  string
	}{
		{ctPayloadData, "DATA"},
		{ctInit, "INIT"},
		{ctInitAck, "INIT-ACK"},
		{ctSack, "SACK"},
		{ctHeartbeat, "HEARTBEAT"},
		{ctHeartbeatAck, "HEARTBEAT-ACK"},
		{ctAbort, "ABORT"},
		{ctShutdown, "SHUTDOWN"},
		{ctShutdownAck, "SHUTDOWN-ACK"},
		{ctError, "ERROR"},
		{ctCookieEcho, "COOKIE-ECHO"},
		{ctCookieAck, "COOKIE-ACK"},
		{ctCWR, "ECNE"},
		{ctShutdownComplete, "SHUTDOWN-COMPLETE"},
		{ctReconfig, "RECONFIG"},
		{ctForwardTSN, "FORWARD-TSN"},
		{chunkType(255), "Unknown ChunkType: 255"},
	}

	for _, tc := range tt {
		if tc.chunkType.String() != tc.expected {
			t.Errorf("failed to stringify chunkType %v, expected %s", tc.chunkType, tc.expected)
		}
	}
}
