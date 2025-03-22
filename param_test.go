// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildParam_Success(t *testing.T) {
	tt := []struct {
		binary []byte
	}{
		{testChunkReconfigParamA()},
	}

	for i, tc := range tt {
		pType, err := parseParamType(tc.binary)
		assert.NoErrorf(t, err, "failed to parse param type #%d", i)

		p, err := buildParam(pType, tc.binary)
		assert.NoErrorf(t, err, "failed to unmarshal #%d", i)

		b, err := p.marshal()
		assert.NoErrorf(t, err, "failed to marshal #%d", i)
		assert.Equal(t, tc.binary, b)
	}
}

func TestBuildParam_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{"invalid ParamType", []byte{0x0, 0x0}},
		{"build failure", testChunkReconfigParamA()[:8]},
	}

	for i, tc := range tt {
		pType, err := parseParamType(tc.binary)
		assert.NoErrorf(t, err, "failed to parse param type #%d", i)

		_, err = buildParam(pType, tc.binary)
		assert.Errorf(t, err, "expected buildParam #%d: '%s' to fail.", i, tc.name)
	}
}
