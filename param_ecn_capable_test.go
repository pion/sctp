// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp // nolint:dupl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func testParamECNCapabale() []byte {
	return []byte{0x80, 0x0, 0x0, 0x4}
}

func TestParamECNCapabale_Success(t *testing.T) {
	tt := []struct {
		binary []byte
		parsed *paramECNCapable
	}{
		{
			testParamECNCapabale(),
			&paramECNCapable{
				paramHeader: paramHeader{
					typ:                ecnCapable,
					unrecognizedAction: paramHeaderUnrecognizedActionSkip,
					len:                4,
					raw:                []byte{},
				},
			},
		},
	}

	for i, tc := range tt {
		actual := &paramECNCapable{}
		_, err := actual.unmarshal(tc.binary)
		assert.NoErrorf(t, err, "failed to unmarshal #%d", i)
		assert.Equal(t, tc.parsed, actual)

		b, err := actual.marshal()
		assert.NoErrorf(t, err, "failed to unmarshal #%d", i)
		assert.Equal(t, tc.binary, b)
	}
}

func TestParamECNCapabale_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{"param too short", []byte{0x0, 0xd, 0x0}},
	}

	for i, tc := range tt {
		actual := &paramECNCapable{}
		_, err := actual.unmarshal(tc.binary)
		assert.Errorf(t, err, "expected unmarshal #%d: '%s' to fail.", i, tc.name)
	}
}
