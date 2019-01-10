package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParamHeader_Success(t *testing.T) {
	tt := []struct {
		binary []byte
		parsed *paramHeader
	}{
		{[]byte{0x0, 0x1, 0x0, 0x4},
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
		assert.Equal(t, b, tc.binary)
	}
}

func TestParamHeaderUnmarshal_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{"header too short", []byte{0x0, 0x1}},
		{"wrong reported length", []byte{0x0, 0x1, 0x0, 0x10}},
	}

	for i, tc := range tt {
		actual := &paramHeader{}
		err := actual.unmarshal(tc.binary)
		if err == nil {
			t.Errorf("expected unmarshal #%d: '%s' to fail.", i, tc.name)
		}
	}
}
