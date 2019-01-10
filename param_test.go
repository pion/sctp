package sctp

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildParam_Success(t *testing.T) {
	tt := []struct {
		binary []byte
	}{
		{[]byte{0x0, 0xd, 0x0, 0x10, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x2, 0x0, 0x0, 0x0, 0x3}},
	}

	for i, tc := range tt {
		pType := paramType(binary.BigEndian.Uint16(tc.binary))
		p, err := buildParam(pType, tc.binary)
		if err != nil {
			t.Fatalf("failed to unmarshal #%d: %v", i, err)
		}
		b, err := p.marshal()
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}
		assert.Equal(t, b, tc.binary)
	}
}

func TestBuildParam_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{"invalid ParamType", []byte{0x0, 0xd, 0x0, 0x14, 0x0, 0x0, 0x0, 0x1}},
	}

	for i, tc := range tt {
		pType := paramType(binary.BigEndian.Uint16(tc.binary))
		_, err := buildParam(pType, tc.binary)
		if err == nil {
			t.Errorf("expected unmarshal #%d: '%s' to fail.", i, tc.name)
		}
	}
}
