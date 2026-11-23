// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testChunkReconfigResponce() []byte {
	return []byte{0x0, 0x10, 0x0, 0xc, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1}
}

func TestParamReconfigResponse_Success(t *testing.T) {
	tt := []struct {
		binary []byte
		parsed *paramReconfigResponse
	}{
		{
			testChunkReconfigResponce(),
			&paramReconfigResponse{
				paramHeader: paramHeader{
					typ: reconfigResp,
					len: 12,
					raw: testChunkReconfigResponce()[4:],
				},
				reconfigResponseSequenceNumber: 1,
				result:                         reconfigResultSuccessPerformed,
			},
		},
	}

	for i, tc := range tt {
		actual := &paramReconfigResponse{}
		_, err := actual.unmarshal(tc.binary)
		assert.NoErrorf(t, err, "failed to unmarshal #%d: %v", i)
		assert.Equal(t, tc.parsed, actual)

		b, err := actual.marshal()
		assert.NoErrorf(t, err, "failed to marshal #%d: %v", i)
		assert.Equal(t, tc.binary, b)
	}
}

func TestParamReconfigResponse_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{"packet too short", testChunkReconfigParamA()[:8]},
		{"param too short", []byte{0x0, 0x10, 0x0, 0x4}},
	}

	for i, tc := range tt {
		actual := &paramReconfigResponse{}
		_, err := actual.unmarshal(tc.binary)
		assert.Errorf(t, err, "expected unmarshal #%d: '%s' to fail.", i, tc.name)
	}
}

func TestReconfigResultString(t *testing.T) {
	tt := []struct {
		result   reconfigResult
		expected string
	}{
		{reconfigResultSuccessNOP, "0: Success - Nothing to do"},
		{reconfigResultSuccessPerformed, "1: Success - Performed"},
		{reconfigResultDenied, "2: Denied"},
		{reconfigResultErrorWrongSSN, "3: Error - Wrong SSN"},
		{reconfigResultErrorRequestAlreadyInProgress, "4: Error - Request already in progress"},
		{reconfigResultErrorBadSequenceNumber, "5: Error - Bad Sequence Number"},
		{reconfigResultInProgress, "6: In progress"},
	}

	for i, tc := range tt {
		actual := tc.result.String()
		assert.Equalf(t, tc.expected, actual, "Test case %d", i)
	}
}

func TestParamReconfigResponse_OptionalFields(t *testing.T) {
	withTSNs := []byte{
		0x00, 0x10, 0x00, 0x14, // type and parameter length
		0x00, 0x00, 0x00, 0x07, // response sequence number
		0x00, 0x00, 0x00, 0x01, // result
		0xA1, 0xB2, 0xC3, 0xD4, // sender's next TSN
		0x0A, 0x0B, 0x0C, 0x0D, // receiver's next TSN
	}

	var response paramReconfigResponse
	_, err := response.unmarshal(withTSNs)
	require.NoError(t, err)
	assert.Equal(t, reconfigResp, response.typ)
	assert.Equal(t, 20, response.length())
	assert.Equal(t, withTSNs[4:], response.raw)
	assert.Equal(t, uint32(7), response.reconfigResponseSequenceNumber)
	assert.Equal(t, reconfigResultSuccessPerformed, response.result)
	assert.True(t, response.senderNextTSNPresent)
	assert.Equal(t, uint32(0xA1B2C3D4), response.senderNextTSN)
	assert.True(t, response.receiverNextTSNPresent)
	assert.Equal(t, uint32(0x0A0B0C0D), response.receiverNextTSN)

	out, err := response.marshal()
	require.NoError(t, err)
	assert.Equal(t, withTSNs, out)

	withoutTSNs := testChunkReconfigResponce()
	_, err = response.unmarshal(withoutTSNs)
	require.NoError(t, err)
	assert.False(t, response.senderNextTSNPresent)
	assert.Zero(t, response.senderNextTSN)
	assert.False(t, response.receiverNextTSNPresent)
	assert.Zero(t, response.receiverNextTSN)

	out, err = response.marshal()
	require.NoError(t, err)
	assert.Equal(t, withoutTSNs, out)
}

func TestParamReconfigResponse_OptionalFields_Roundtrip(t *testing.T) {
	tcs := []struct {
		name   string
		input  paramReconfigResponse
		valLen int // value length excluding the 4-byte header (8 or 16)
	}{
		{
			name: "NoOptionals",
			input: paramReconfigResponse{
				reconfigResponseSequenceNumber: 0x0A,
				result:                         reconfigResultSuccessPerformed,
			},
			valLen: 8,
		},
		{
			name: "SenderAndReceiver",
			input: paramReconfigResponse{
				reconfigResponseSequenceNumber: 0x0C,
				result:                         reconfigResultInProgress,
				senderNextTSNPresent:           true,
				senderNextTSN:                  0x11111111,
				receiverNextTSNPresent:         true,
				receiverNextTSN:                0x22222222,
			},
			valLen: 16,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			b, err := tc.input.marshal()
			require.NoError(t, err)
			require.GreaterOrEqual(t, len(b), 4)

			pt := binary.BigEndian.Uint16(b[0:2])
			pl := binary.BigEndian.Uint16(b[2:4])

			assert.Equal(t, uint16(reconfigResp), pt)
			assert.Equal(t, uint16(4+tc.valLen), pl) //nolint:gosec
			assert.Equal(t, int(pl), len(b))

			var out paramReconfigResponse
			p, err := out.unmarshal(b)

			require.NoError(t, err)
			got, ok := p.(*paramReconfigResponse)
			require.True(t, ok, "expected *paramReconfigResponse, got %T", p)

			assert.Equal(t, tc.input.reconfigResponseSequenceNumber, got.reconfigResponseSequenceNumber)
			assert.Equal(t, tc.input.result, got.result)
			assert.Equal(t, tc.input.senderNextTSNPresent, got.senderNextTSNPresent)
			assert.Equal(t, tc.input.senderNextTSN, got.senderNextTSN)
			assert.Equal(t, tc.input.receiverNextTSNPresent, got.receiverNextTSNPresent)
			assert.Equal(t, tc.input.receiverNextTSN, got.receiverNextTSN)

			b2, err := got.marshal()
			assert.NoError(t, err)
			assert.Equal(t, b, b2)
		})
	}
}

func TestParamReconfigResponse_Marshal_RejectsSingleTSN(t *testing.T) {
	tests := []struct {
		name            string
		senderPresent   bool
		receiverPresent bool
	}{
		{name: "SenderOnly", senderPresent: true},
		{name: "ReceiverOnly", receiverPresent: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := paramReconfigResponse{
				senderNextTSNPresent:   tt.senderPresent,
				receiverNextTSNPresent: tt.receiverPresent,
			}
			_, err := response.marshal()
			assert.ErrorIs(t, err, ErrReconfigRespParamInvalidCombo)
		})
	}
}

func TestParamReconfigResponse_Unmarshal_InvalidLengths(t *testing.T) {
	tests := []struct {
		name    string
		length  uint16
		wantErr error
	}{
		{"TooShort", 10, ErrReconfigRespParamTooShort},
		{"PartialTSN", 14, ErrReconfigRespParamInvalidLength},
		{"SenderOnly", 16, ErrReconfigRespParamInvalidLength},
		{"TooLong", 24, ErrReconfigRespParamInvalidLength},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := make([]byte, tt.length)
			binary.BigEndian.PutUint16(raw, uint16(reconfigResp))
			binary.BigEndian.PutUint16(raw[2:], tt.length)

			_, err := buildParam(reconfigResp, raw)
			assert.ErrorIs(t, err, tt.wantErr)
		})
	}
}
