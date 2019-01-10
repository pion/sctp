package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParamOutgoingResetRequest_Success(t *testing.T) {
	tt := []struct {
		binary []byte
		parsed *paramOutgoingResetRequest
	}{
		{[]byte{0x0, 0xd, 0x0, 0x14, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x3, 0x0, 0x4, 0x0, 0x5},
			&paramOutgoingResetRequest{
				paramHeader: paramHeader{
					typ: outSSNResetReq,
					len: 20,
					raw: []byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x3, 0x0, 0x4, 0x0, 0x5},
				},
				reconfigRequestSequenceNumber:  1,
				reconfigResponseSequenceNumber: 2,
				senderLastTSN:                  3,
				streamIdentifiers:              []uint16{4, 5},
			}},
		{[]byte{0x0, 0xd, 0x0, 0x10, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x3},
			&paramOutgoingResetRequest{
				paramHeader: paramHeader{
					typ: outSSNResetReq,
					len: 16,
					raw: []byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x3},
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
		assert.Equal(t, b, tc.binary)
	}
}

func TestParamOutgoingResetRequest_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{"packet too short", []byte{0x0, 0xd, 0x0, 0x14, 0x0, 0x0, 0x0, 0x1}},
	}

	for i, tc := range tt {
		actual := &paramOutgoingResetRequest{}
		_, err := actual.unmarshal(tc.binary)
		if err == nil {
			t.Errorf("expected unmarshal #%d: '%s' to fail.", i, tc.name)
		}
	}
}
