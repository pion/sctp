// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp // nolint:dupl

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func testParamForwardTSNSupported() []byte {
	return []byte{0xc0, 0x0, 0x0, 0x4}
}

func TestParamForwardTSNSupported_Success(t *testing.T) {
	tt := []struct {
		binary []byte
		parsed *paramForwardTSNSupported
	}{
		{
			testParamForwardTSNSupported(),
			&paramForwardTSNSupported{
				paramHeader: paramHeader{
					typ:                forwardTSNSupp,
					len:                4,
					unrecognizedAction: paramHeaderUnrecognizedActionSkipAndReport,
					raw:                []byte{},
				},
			},
		},
	}

	for i, tc := range tt {
		actual := &paramForwardTSNSupported{}
		_, err := actual.unmarshal(tc.binary)
		assert.NoErrorf(t, err, "failed to unmarshal #%d", i)
		assert.Equal(t, tc.parsed, actual)

		b, err := actual.marshal()
		assert.NoErrorf(t, err, "failed to unmarshal #%d", i)
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
		assert.Errorf(t, err, "expected unmarshal #%d: '%s' to fail.", i, tc.name)
	}
}
