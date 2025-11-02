// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
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
	type tc struct {
		name                string
		raw                 []byte
		wantRSN             uint32
		wantResult          reconfigResult
		wantSenderPresent   bool
		wantSender          uint32
		wantReceiverPresent bool
		wantReceiver        uint32
		wantParamHeaderLen  int
	}

	// build a parameter with optional fields.
	build := func(rsn uint32, res reconfigResult, sender *uint32, receiver *uint32) []byte {
		// +4 if sender and +4 if receiver)
		valLen := 8
		if sender != nil {
			valLen += 4
		}

		if receiver != nil {
			valLen += 4
		}

		total := 4 + valLen // header + value
		b := make([]byte, total)

		// header
		binary.BigEndian.PutUint16(b[0:], uint16(reconfigResp))
		binary.BigEndian.PutUint16(b[2:], uint16(total)) //nolint:gosec

		// value
		binary.BigEndian.PutUint32(b[4:], rsn)
		binary.BigEndian.PutUint32(b[8:], uint32(res))

		off := 12
		if sender != nil {
			binary.BigEndian.PutUint32(b[off:], *sender)
			off += 4
		}

		if receiver != nil {
			binary.BigEndian.PutUint32(b[off:], *receiver)
		}

		return b
	}

	senderOnly := uint32(0x01020304)
	bothSender := uint32(0xA1B2C3D4)
	bothReceiver := uint32(0x0A0B0C0D)

	tests := []tc{
		{
			name:                "sender_next_only",
			raw:                 build(0x0000002A, reconfigResultErrorWrongSSN, &senderOnly, nil),
			wantRSN:             0x0000002A,
			wantResult:          reconfigResultErrorWrongSSN,
			wantSenderPresent:   true,
			wantSender:          senderOnly,
			wantReceiverPresent: false,
			wantParamHeaderLen:  16, // 4 (hdr) + 12 (value)
		},
		{
			name:                "sender_and_receiver_next",
			raw:                 build(0x00000007, reconfigResultSuccessPerformed, &bothSender, &bothReceiver),
			wantRSN:             0x00000007,
			wantResult:          reconfigResultSuccessPerformed,
			wantSenderPresent:   true,
			wantSender:          bothSender,
			wantReceiverPresent: true,
			wantReceiver:        bothReceiver,
			wantParamHeaderLen:  20, // 4 (hdr) + 16 (value)
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var param paramReconfigResponse

			_, err := param.unmarshal(tt.raw)
			assert.NoError(t, err)

			assert.Equal(t, reconfigResp, param.paramHeader.typ)
			assert.Equal(t, tt.wantParamHeaderLen, param.paramHeader.len)
			// param.paramHeader.raw should equal just the value part
			assert.Equal(t, tt.raw[4:], param.paramHeader.raw)

			assert.Equal(t, tt.wantRSN, param.reconfigResponseSequenceNumber)
			assert.Equal(t, tt.wantResult, param.result)
			assert.Equal(t, tt.wantSenderPresent, param.senderNextTSNPresent)

			if tt.wantSenderPresent {
				assert.Equal(t, tt.wantSender, param.senderNextTSN)
			}

			assert.Equal(t, tt.wantReceiverPresent, param.receiverNextTSNPresent)

			if tt.wantReceiverPresent {
				assert.Equal(t, tt.wantReceiver, param.receiverNextTSN)
			}

			out, err := param.marshal()
			assert.NoError(t, err)
			assert.Equal(t, tt.raw, out)
		})
	}
}

func TestParamReconfigResponse_OptionalFields_Roundtrip(t *testing.T) {
	tcs := []struct {
		name   string
		input  paramReconfigResponse
		valLen int // value length excluding the 4-byte header (8/12/16)
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
			name: "SenderOnly",
			input: paramReconfigResponse{
				reconfigResponseSequenceNumber: 0x0B,
				result:                         reconfigResultDenied,
				senderNextTSNPresent:           true,
				senderNextTSN:                  0x12345678,
			},
			valLen: 12,
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
			assert.NoError(t, err)
			assert.GreaterOrEqual(t, len(b), 4)

			pt := binary.BigEndian.Uint16(b[0:2])
			pl := binary.BigEndian.Uint16(b[2:4])

			assert.Equal(t, uint16(reconfigResp), pt)
			assert.Equal(t, uint16(4+tc.valLen), pl) //nolint:gosec
			assert.Equal(t, int(pl), len(b))

			var out paramReconfigResponse
			p, err := out.unmarshal(b)

			assert.NoError(t, err)
			got, ok := p.(*paramReconfigResponse)
			assert.True(t, ok, "expected *paramReconfigResponse, got %T", p)

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

func TestParamReconfigResponse_Marshal_OrderingGuard(t *testing.T) {
	// receiver present without sender present must fail
	r := paramReconfigResponse{
		reconfigResponseSequenceNumber: 1,
		result:                         reconfigResultSuccessPerformed,
		receiverNextTSNPresent:         true,
		receiverNextTSN:                7,
	}

	_, err := r.marshal()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrReconfigRespParamInvalidCombo)
}

func TestParamReconfigResponse_Unmarshal_InvalidLengths(t *testing.T) {
	// too short
	badShort := make([]byte, 10)
	binary.BigEndian.PutUint16(badShort[0:], uint16(reconfigResp))
	binary.BigEndian.PutUint16(badShort[2:], uint16(10))

	var a paramReconfigResponse
	_, err := a.unmarshal(badShort)

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrReconfigRespParamTooShort)

	// invalid value length
	badLen := make([]byte, 14)
	binary.BigEndian.PutUint16(badLen[0:], uint16(reconfigResp))
	binary.BigEndian.PutUint16(badLen[2:], uint16(14))

	var b paramReconfigResponse
	_, err = b.unmarshal(badLen)

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrReconfigRespParamInvalidLength)
}
