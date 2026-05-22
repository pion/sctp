// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorCauseCode_String(t *testing.T) {
	cases := []struct {
		code     errorCauseCode
		expected string
	}{
		{invalidStreamIdentifier, "Invalid Stream Identifier"},
		{missingMandatoryParameter, "Missing Mandatory Parameter"},
		{staleCookieError, "Stale Cookie Error"},
		{outOfResource, "Out of Resource"},
		{unresolvableAddress, "Unresolvable Address"},
		{unrecognizedChunkType, "Unrecognized Chunk Type"},
		{invalidMandatoryParameter, "Invalid Mandatory Parameter"},
		{unrecognizedParameters, "Unrecognized Parameters"},
		{noUserData, "No User Data"},
		{cookieReceivedWhileShuttingDown, "Cookie Received While Shutting Down"},
		{restartOfAnAssociationWithNewAddresses, "Restart of an Association with New Addresses"},
		{userInitiatedAbort, "User Initiated Abort"},
		{protocolViolation, "Protocol Violation"},
		{errorCauseCode(0xFFFF), "Unknown CauseCode: 65535"},
	}

	for _, tc := range cases {
		assert.Equalf(t, tc.expected, tc.code.String(), "stringer mismatch for code %d", tc.code)
	}
}

func TestBuildErrorCause_TooShort(t *testing.T) {
	_, err := buildErrorCause([]byte{0x00, 0x01, 0x00})
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrCauseTooShort)
}

func TestBuildErrorCause_LengthInvalid_TooSmallField(t *testing.T) {
	// Length field = 3 (<4) while slice has 4 bytes
	raw := make([]byte, 4)
	// code any
	binary.BigEndian.PutUint16(raw, 0)
	// length=3 -> invalid
	binary.BigEndian.PutUint16(raw[2:], 3)

	_, err := buildErrorCause(raw)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrCauseLengthInvalid)
}

func TestBuildErrorCause_LengthInvalid_ClaimsMoreThanSlice(t *testing.T) {
	// length field = 8, but slice is only 6
	raw := make([]byte, 6)
	binary.BigEndian.PutUint16(raw, 0)
	binary.BigEndian.PutUint16(raw[2:], 8)

	_, err := buildErrorCause(raw)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrCauseLengthInvalid)
}

func TestBuildErrorCause_UnknownCode(t *testing.T) {
	// valid 4-byte header, unknown code -> ErrBuildErrorCaseHandle
	raw := make([]byte, 4)
	binary.BigEndian.PutUint16(raw, uint16(0xFFFF))
	binary.BigEndian.PutUint16(raw[2:], 4)

	_, err := buildErrorCause(raw)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrBuildErrorCaseHandle)
}

func TestBuildErrorCause_Dispatch_ProtocolViolation_RoundTrip(t *testing.T) {
	orig := &errorCauseProtocolViolation{
		errorCauseHeader:      errorCauseHeader{code: protocolViolation},
		additionalInformation: []byte("violation: unexpected state"),
	}
	b, err := orig.marshal()
	assert.NoError(t, err)

	got, err := buildErrorCause(b)
	assert.NoError(t, err)
	assert.Equal(t, protocolViolation, got.errorCauseCode())

	epv, ok := got.(*errorCauseProtocolViolation)
	assert.True(t, ok, "built cause should be *errorCauseProtocolViolation")
	assert.Equal(t, orig.additionalInformation, epv.additionalInformation)

	b2, err := got.marshal()
	assert.NoError(t, err)
	assert.Equal(t, b, b2)
}

func TestBuildErrorCause_Dispatch_UserInitiatedAbort_RoundTrip(t *testing.T) {
	orig := &errorCauseUserInitiatedAbort{
		errorCauseHeader:      errorCauseHeader{code: userInitiatedAbort},
		upperLayerAbortReason: []byte("app-requested abort"),
	}
	b, err := orig.marshal()
	assert.NoError(t, err)

	got, err := buildErrorCause(b)
	assert.NoError(t, err)
	assert.Equal(t, userInitiatedAbort, got.errorCauseCode())

	euia, ok := got.(*errorCauseUserInitiatedAbort)
	assert.True(t, ok, "built cause should be *errorCauseUserInitiatedAbort")
	assert.Equal(t, orig.upperLayerAbortReason, euia.upperLayerAbortReason)

	// Round-trip again
	b2, err := got.marshal()
	assert.NoError(t, err)
	assert.Equal(t, b, b2)
}
