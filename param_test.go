package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildParam_Success(t *testing.T) {
	tt := []struct {
		binary []byte
	}{
		{testChunkReconfigParamA},
	}

	for i, tc := range tt {
		pType, err := parseParamType(tc.binary)
		if err != nil {
			t.Fatalf("failed to parse param type: %v", err)
		}
		p, err := buildParam(pType, tc.binary)
		if err != nil {
			t.Fatalf("failed to unmarshal #%d: %v", i, err)
		}
		b, err := p.marshal()
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}
		assert.Equal(t, tc.binary, b)
	}
}

func TestBuildParam_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{"invalid ParamType", []byte{0x0, 0x0}},
		{"build failure", testChunkReconfigParamA[:8]},
	}

	for i, tc := range tt {
		pType, err := parseParamType(tc.binary)
		if err != nil {
			t.Fatalf("failed to parse param type: %v", err)
		}
		_, err = buildParam(pType, tc.binary)
		if err == nil {
			t.Errorf("expected unmarshal #%d: '%s' to fail.", i, tc.name)
		}
	}
}
