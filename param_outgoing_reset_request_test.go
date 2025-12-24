// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func testChunkReconfigParamA() []byte {
	return []byte{
		0x00, 0x0d, 0x00, 0x16, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06,
	}
}

func testChunkReconfigParamB() []byte {
	return []byte{0x0, 0xd, 0x0, 0x10, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x3}
}

func TestParamOutgoingResetRequest_Success(t *testing.T) {
	tt := []struct {
		binary []byte
		parsed *paramOutgoingResetRequest
	}{
		{
			testChunkReconfigParamA(),
			&paramOutgoingResetRequest{
				paramHeader: paramHeader{
					typ: outSSNResetReq,
					len: 22,
					raw: testChunkReconfigParamA()[4:],
				},
				reconfigRequestSequenceNumber:  1,
				reconfigResponseSequenceNumber: 2,
				senderLastTSN:                  3,
				streamIdentifiers:              []uint16{4, 5, 6},
			},
		},
		{
			testChunkReconfigParamB(),
			&paramOutgoingResetRequest{
				paramHeader: paramHeader{
					typ: outSSNResetReq,
					len: 16,
					raw: testChunkReconfigParamB()[4:],
				},
				reconfigRequestSequenceNumber:  1,
				reconfigResponseSequenceNumber: 2,
				senderLastTSN:                  3,
				streamIdentifiers:              []uint16{},
			},
		},
	}

	for i, tc := range tt {
		actual := &paramOutgoingResetRequest{}
		_, err := actual.unmarshal(tc.binary)
		assert.NoErrorf(t, err, "failed to unmarshal #%d", i)
		assert.Equal(t, tc.parsed, actual)

		b, err := actual.marshal()
		assert.NoErrorf(t, err, "failed to marshal #%d", i)
		assert.Equal(t, tc.binary, b)
	}
}

func TestParamOutgoingResetRequest_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{"packet too short", testChunkReconfigParamA()[:8]},
		{"param too short", []byte{0x0, 0xd, 0x0, 0x4}},
	}

	for i, tc := range tt {
		actual := &paramOutgoingResetRequest{}
		_, err := actual.unmarshal(tc.binary)
		assert.Errorf(t, err, "expected unmarshal #%d: '%s' to fail.", i, tc.name)
	}
}

func makeOddLenOutgoingResetParam() []byte {
	// Build a value that's 12 (fixed) + 1 = 13 bytes (invalid; rem=1)
	val := make([]byte, 13)
	binary.BigEndian.PutUint32(val[0:], 1) // reconfigRequestSequenceNumber
	binary.BigEndian.PutUint32(val[4:], 2) // reconfigResponseSequenceNumber
	binary.BigEndian.PutUint32(val[8:], 3) // senderLastTSN
	val[12] = 0                            // stray odd byte

	raw := make([]byte, 4+len(val))
	binary.BigEndian.PutUint16(raw[0:], uint16(outSSNResetReq))
	binary.BigEndian.PutUint16(raw[2:], uint16(4+len(val))) // nolint:gosec
	copy(raw[4:], val)

	return raw
}

func TestParamOutgoingResetRequest_InvalidOddStreamListLength(t *testing.T) {
	b := makeOddLenOutgoingResetParam()

	var p paramOutgoingResetRequest
	_, err := p.unmarshal(b)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSSNResetRequestParamInvalidLength)
}

func TestParamOutgoingResetRequest_Marshal_LengthFormula(t *testing.T) {
	cases := []struct {
		name   string
		ids    []uint16
		expLen uint16 // header length field (includes 4-byte header)
	}{
		{"N=0 (reset all)", nil, 16},
		{"N=1", []uint16{4}, 18},
		{"N=2", []uint16{4, 5}, 20},
		{"N=5", []uint16{1, 2, 3, 4, 5}, 26},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &paramOutgoingResetRequest{
				paramHeader:                    paramHeader{typ: outSSNResetReq},
				reconfigRequestSequenceNumber:  1,
				reconfigResponseSequenceNumber: 2,
				senderLastTSN:                  3,
				streamIdentifiers:              tc.ids,
			}

			b, err := p.marshal()
			assert.NoError(t, err)

			gotLen := binary.BigEndian.Uint16(b[2:])
			assert.Equal(t, tc.expLen, gotLen, "header length must be 16 + 2*N")

			// Round trip to ensure unmarshal accepts these valid lengths.
			var q paramOutgoingResetRequest
			_, err = q.unmarshal(b)
			assert.NoError(t, err)

			// Expect same IDs back (empty or nil both acceptable; compare by length+content).
			assert.Equal(t, len(tc.ids), len(q.streamIdentifiers))
			assert.ElementsMatch(t, tc.ids, q.streamIdentifiers)
		})
	}
}
