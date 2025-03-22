// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
		assert.Equalf(t, tc.expected, tc.chunkType.String(), "chunkType %v should be %s", tc.chunkType, tc.expected)
	}
}
