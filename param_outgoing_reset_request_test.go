package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testChunkReconfigParamA = []byte{0x0, 0xd, 0x0, 0x16, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x3, 0x0, 0x4, 0x0, 0x5, 0x0, 0x6}
	testChunkReconfigParamB = []byte{0x0, 0xd, 0x0, 0x10, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x3}
)

func TestParamOutgoingResetRequest_Success(t *testing.T) {
	tt := []struct {
		binary []byte
		parsed *paramOutgoingResetRequest
	}{
		{testChunkReconfigParamA,
			&paramOutgoingResetRequest{
				paramHeader: paramHeader{
					typ: outSSNResetReq,
					len: 22,
					raw: testChunkReconfigParamA[4:],
				},
				reconfigRequestSequenceNumber:  1,
				reconfigResponseSequenceNumber: 2,
				senderLastTSN:                  3,
				streamIdentifiers:              []uint16{4, 5, 6},
			}},
		{testChunkReconfigParamB,
			&paramOutgoingResetRequest{
				paramHeader: paramHeader{
					typ: outSSNResetReq,
					len: 16,
					raw: testChunkReconfigParamB[4:],
				},
				reconfigRequestSequenceNumber:  1,
				reconfigResponseSequenceNumber: 2,
				senderLastTSN:                  3,
				streamIdentifiers:              []uint16{},
			}},
	}

	for i, tc := range tt {
		actual := &paramOutgoingResetRequest{}
		_, err := actual.unmarshal(tc.binary)
		if err != nil {
			t.Fatalf("failed to unmarshal #%d: %v", i, err)
		}
		assert.Equal(t, tc.parsed, actual)
		b, err := actual.marshal()
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}
		assert.Equal(t, tc.binary, b)
	}
}

func TestParamOutgoingResetRequest_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{"packet too short", testChunkReconfigParamA[:8]},
		{"param too short", []byte{0x0, 0xd, 0x0, 0x4}},
	}

	for i, tc := range tt {
		actual := &paramOutgoingResetRequest{}
		_, err := actual.unmarshal(tc.binary)
		if err == nil {
			t.Errorf("expected unmarshal #%d: '%s' to fail.", i, tc.name)
		}
	}
}
