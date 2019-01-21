package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testChunkReconfigResponce = []byte{0x0, 0x10, 0x0, 0xc, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x1}
)

func TestParamReconfigResponse_Success(t *testing.T) {
	tt := []struct {
		binary []byte
		parsed *paramReconfigResponse
	}{
		{testChunkReconfigResponce,
			&paramReconfigResponse{
				paramHeader: paramHeader{
					typ: reconfigResp,
					len: 12,
					raw: testChunkReconfigResponce[4:],
				},
				reconfigResponseSequenceNumber: 1,
				result:                         reconfigResultSuccessPerformed,
			}},
	}

	for i, tc := range tt {
		actual := &paramReconfigResponse{}
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

func TestParamReconfigResponse_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{"packet too short", testChunkReconfigParamA[:8]},
		{"param too short", []byte{0x0, 0x10, 0x0, 0x4}},
	}

	for i, tc := range tt {
		actual := &paramReconfigResponse{}
		_, err := actual.unmarshal(tc.binary)
		if err == nil {
			t.Errorf("expected unmarshal #%d: '%s' to fail.", i, tc.name)
		}
	}
}

func TestReconfigResultStringer(t *testing.T) {
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
		assert.Equal(t, tc.expected, actual, "Test case %d", i)
	}
}
