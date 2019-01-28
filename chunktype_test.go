package sctp

import "testing"

func TestChunkType_String(t *testing.T) {
	tt := []struct {
		chunkType chunkType
		expected  string
	}{
		{PAYLOADDATA, "Payload data"},
		{INIT, "Initiation"},
		{INITACK, "Initiation Acknowledgement"},
		{SACK, "Selective Acknowledgement"},
		{HEARTBEAT, "Heartbeat"},
		{HEARTBEATACK, "Heartbeat Acknowledgement"},
		{ABORT, "Abort"},
		{SHUTDOWN, "Shutdown"},
		{SHUTDOWNACK, "Shutdown Acknowledgement"},
		{ERROR, "Error"},
		{COOKIEECHO, "Cookie Echo"},
		{COOKIEACK, "Cookie Acknowledgement"},
		{CWR, "Congestion Window Reduced"},
		{SHUTDOWNCOMPLETE, "Shutdown Complete"},
		{RECONFIG, "Re-configuration Chunk (RE-CONFIG)"},
		{FORWARDTSN, "FORWARD TSN"},
		{chunkType(255), "Unknown ChunkType: 255"},
	}

	for _, tc := range tt {
		if tc.chunkType.String() != tc.expected {
			t.Errorf("failed to stringify chunkType %v, expected %s", tc.chunkType, tc.expected)
		}
	}
}
