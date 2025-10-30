// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseParamType_Success(t *testing.T) {
	tt := []struct {
		binary   []byte
		expected paramType
	}{
		{[]byte{0x0, 0x1}, heartbeatInfo},
		{[]byte{0x0, 0xd}, outSSNResetReq},
	}

	for i, tc := range tt {
		pType, err := parseParamType(tc.binary)
		assert.NoErrorf(t, err, "failed to parse paramType #%d", i)
		assert.Equal(t, tc.expected, pType)
	}
}

func TestParseParamType_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{"empty packet", []byte{}},
	}

	for i, tc := range tt {
		_, err := parseParamType(tc.binary)
		assert.Errorf(t, err, "expected parseParamType #%d: '%s' to fail.", i, tc.name)
	}
}

func TestParamType_String(t *testing.T) {
	tests := []struct {
		name string
		in   paramType
		want string
	}{
		{"heartbeatInfo", heartbeatInfo, "Heartbeat Info"},
		{"ipV4Addr", ipV4Addr, "IPv4 IP"},
		{"ipV6Addr", ipV6Addr, "IPv6 IP"},
		{"stateCookie", stateCookie, "State Cookie"},
		{"unrecognizedParam", unrecognizedParam, "Unrecognized Parameters"},
		{"cookiePreservative", cookiePreservative, "Cookie Preservative"},
		{"hostNameAddr", hostNameAddr, "Host Name Address"},
		{"supportedAddrTypes", supportedAddrTypes, "Supported IP Types"},
		{"outSSNResetReq", outSSNResetReq, "Outgoing SSN Reset Request Parameter"},
		{"incSSNResetReq", incSSNResetReq, "Incoming SSN Reset Request Parameter"},
		{"ssnTSNResetReq", ssnTSNResetReq, "SSN/TSN Reset Request Parameter"},
		{"reconfigResp", reconfigResp, "Re-configuration Response Parameter"},
		{"addOutStreamsReq", addOutStreamsReq, "Add Outgoing Streams Request Parameter"},
		{"addIncStreamsReq", addIncStreamsReq, "Add Incoming Streams Request Parameter"},
		{"ecnCapable", ecnCapable, "ECN Capable"},
		{"zeroChecksumAcceptable", zeroChecksumAcceptable, "Zero Checksum Acceptable"},
		{"random", random, "Random"},
		{"chunkList", chunkList, "Chunk List"},
		{"reqHMACAlgo", reqHMACAlgo, "Requested HMAC Algorithm Parameter"},
		{"padding", padding, "Padding"},
		{"supportedExt", supportedExt, "Supported Extensions"},
		{"forwardTSNSupp", forwardTSNSupp, "Forward TSN supported"},
		{"addIPAddr", addIPAddr, "Add IP Address"},
		{"delIPAddr", delIPAddr, "Delete IP Address"},
		{"errClauseInd", errClauseInd, "Error Cause Indication"},
		{"setPriAddr", setPriAddr, "Set Primary IP"},
		{"successInd", successInd, "Success Indication"},
		{"adaptLayerInd", adaptLayerInd, "Adaptation Layer Indication"},
		{"unknownValue", paramType(0x4242), fmt.Sprintf("Unknown ParamType: %d", 0x4242)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.in.String()
			assert.Equal(t, tc.want, got)
		})
	}
}
