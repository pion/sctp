package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	testParamForwardTSNSupported = []byte{0xc0, 0x0, 0x0, 0x4}
)

func TestParamForwardTSNSupported_Success(t *testing.T) {
	tt := []struct {
		binary []byte
		parsed *paramForwardTSNSupported
	}{
		{testParamForwardTSNSupported,
			&paramForwardTSNSupported{
				paramHeader: paramHeader{
					typ: forwardTSNSupp,
					len: 4,
					raw: []byte{},
				},
			}},
	}

	for i, tc := range tt {
		actual := &paramForwardTSNSupported{}
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

func TestParamForwardTSNSupported_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{"param too short", []byte{0x0, 0xd, 0x0}},
	}

	for i, tc := range tt {
		actual := &paramForwardTSNSupported{}
		_, err := actual.unmarshal(tc.binary)
		if err == nil {
			t.Errorf("expected unmarshal #%d: '%s' to fail.", i, tc.name)
		}
	}
}
