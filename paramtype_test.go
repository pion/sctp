package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseParamType_Success(t *testing.T) {
	tt := []struct {
		binary   []byte
		expected paramType
	}{
		{[]byte{0x0, 0x1}, heartbeatInfo},
		{[]byte{0x0, 0xd}, outSSNResetReq},
	}

	for i, tc := range tt {
		pType, err := parseParamType(tc.binary)
		if err != nil {
			t.Fatalf("failed to parse paramType %d: %v", i, err)
		}
		assert.Equal(t, tc.expected, pType)
	}
}

func TestParseParamType_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{"empty packet", []byte{}},
	}

	for i, tc := range tt {
		_, err := parseParamType(tc.binary)
		if err == nil {
			t.Errorf("expected parseParamType #%d: '%s' to fail.", i, tc.name)
		}
	}
}
