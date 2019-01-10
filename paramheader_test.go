package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testParamHeader = []byte{0x0, 0x1, 0x0, 0x4}
)

func TestParamHeader_Success(t *testing.T) {
	tt := []struct {
		binary []byte
		parsed *paramHeader
	}{
		{testParamHeader,
			&paramHeader{
				typ: heartbeatInfo,
				len: 4,
				raw: []byte{},
			}},
	}

	for i, tc := range tt {
		actual := &paramHeader{}
		err := actual.unmarshal(tc.binary)
		if err != nil {
			t.Errorf("failed to unmarshal #%d: %v", i, err)
		}
		assert.Equal(t, tc.parsed, actual)
		b, err := actual.marshal()
		if err != nil {
			t.Errorf("failed to marshal: %v", err)
		}
		assert.Equal(t, tc.binary, b)
	}
}

func TestParamHeaderUnmarshal_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{"header too short", testParamHeader[:2]},
		// {"wrong param type", []byte{0x0, 0x0, 0x0, 0x4}}, // Not possible to fail parseParamType atm.
		{"reported length below header length", []byte{0x0, 0xd, 0x0, 0x3}},
		{"wrong reported length", testChunkReconfigParamA[:4]},
	}

	for i, tc := range tt {
		actual := &paramHeader{}
		err := actual.unmarshal(tc.binary)
		if err == nil {
			t.Errorf("expected unmarshal #%d: '%s' to fail.", i, tc.name)
		}
	}
}
