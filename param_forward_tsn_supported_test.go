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

func TestParamForwardTSNSupported_Unmarshal_InvalidLength(t *testing.T) {
	// length says 6 (header + 2 bytes payload), which is invalid per RFC (must be 4 only).
	bad := []byte{0xC0, 0x00, 0x00, 0x06, 0xAA, 0xBB}

	var p paramForwardTSNSupported
	_, err := p.unmarshal(bad)

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrForwardTSNSupportedParamInvalidLength)
}

func TestParamForwardTSNSupported_Marshal_EnforcesEmptyValue(t *testing.T) {
	// even if raw is pre-filled, marshal must emit a header-only parameter (len=4).
	p := &paramForwardTSNSupported{
		paramHeader: paramHeader{
			raw: []byte{0xAA, 0xBB}, // should be ignored by marshal
		},
	}

	b, err := p.marshal()
	assert.NoError(t, err)
	assert.Equal(t, testParamForwardTSNSupported(), b, "marshal must emit header-only (len=4)")

	var q paramForwardTSNSupported
	_, err = q.unmarshal(b)
	assert.NoError(t, err)
	assert.Equal(t, forwardTSNSupp, q.typ)
	assert.Equal(t, 4, q.len)
	assert.Empty(t, q.raw)
	assert.Equal(t, paramHeaderUnrecognizedActionSkipAndReport, q.unrecognizedAction)
}
