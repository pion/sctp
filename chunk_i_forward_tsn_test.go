// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func testChunkIForwardTSN() []byte {
	return []byte{0xc2, 0x0, 0x0, 0x8, 0x0, 0x0, 0x0, 0x3}
}

func TestChunkIForwardTSN_Success(t *testing.T) {
	tt := []struct {
		binary []byte
	}{
		{testChunkIForwardTSN()},
		{[]byte{0xc2, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x3, 0x0, 0x4, 0x0, 0x1, 0x0, 0x0, 0x0, 0x5}},
		{[]byte{
			0xc2, 0x0, 0x0, 0x40, 0x0, 0x0, 0x0, 0x3,
			0x0, 0x4, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5,
			0x0, 0x6, 0x0, 0x1, 0x0, 0x0, 0x0, 0x7,
			0x0, 0x8, 0x0, 0x1, 0x0, 0x0, 0x0, 0x9,
			0x0, 0xa, 0x0, 0x1, 0x0, 0x0, 0x0, 0xb,
			0x0, 0xc, 0x0, 0x1, 0x0, 0x0, 0x0, 0xd,
			0x0, 0xe, 0x0, 0x1, 0x0, 0x0, 0x0, 0xf,
			0x0, 0x10, 0x0, 0x1, 0x0, 0x0, 0x0, 0x11,
		}},
	}

	for i, tc := range tt {
		actual := &chunkIForwardTSN{}
		err := actual.unmarshal(tc.binary)
		assert.NoErrorf(t, err, "failed to unmarshal #%d", i)

		b, err := actual.marshal()
		assert.NoError(t, err)
		assert.Equalf(t, tc.binary, b, "test %d not equal", i)
	}
}

func TestChunkIForwardTSNUnmarshal_Failure(t *testing.T) {
	tt := []struct {
		name   string
		binary []byte
	}{
		{"chunk header to short", []byte{0xc2}},
		{"missing New Cumulative TSN", []byte{0xc2, 0x0, 0x0, 0x4}},
		{"missing stream info", []byte{0xc2, 0x0, 0x0, 0x10, 0x0, 0x0, 0x0, 0x3, 0x0, 0x4, 0x0, 0x1}},
	}

	for i, tc := range tt {
		actual := &chunkIForwardTSN{}
		err := actual.unmarshal(tc.binary)
		assert.Errorf(t, err, "expected unmarshal #%d: '%s' to fail.", i, tc.name)
	}
}

func TestChunkIForwardTSNUnmarshal_FailureDoesNotKeepPartialStreams(t *testing.T) {
	actual := &chunkIForwardTSN{
		streams: []chunkIForwardTSNStream{{
			identifier:        1,
			messageIdentifier: 2,
		}},
	}
	err := actual.unmarshal([]byte{
		0xc2, 0x0, 0x0, 0x12, 0x0, 0x0, 0x0, 0x3,
		0x0, 0x4, 0x0, 0x1, 0x0, 0x0, 0x0, 0x5,
		0x0, 0x6,
	})

	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrMarshalStreamFailed)
	assert.ErrorIs(t, err, errIForwardTSNChunkInvalidLength)
	assert.Empty(t, actual.streams)
}

func TestChunkIForwardTSNCheck(t *testing.T) {
	tt := []struct {
		name      string
		chunk     *chunkIForwardTSN
		wantAbort bool
		wantErr   error
	}{
		{
			name: "valid with ordered and unordered forwards for same stream",
			chunk: &chunkIForwardTSN{
				newCumulativeTSN: 1,
				streams: []chunkIForwardTSNStream{
					{identifier: 1, unordered: false, messageIdentifier: 2},
					{identifier: 1, unordered: true, messageIdentifier: 3},
				},
			},
		},
		{
			name: "zero new cumulative tsn",
			chunk: &chunkIForwardTSN{
				newCumulativeTSN: 0,
				streams: []chunkIForwardTSNStream{
					{identifier: 1, messageIdentifier: 2},
				},
			},
		},
		{
			name: "too many streams",
			chunk: &chunkIForwardTSN{
				newCumulativeTSN: 1,
				streams:          make([]chunkIForwardTSNStream, maxIForwardTSNStreams+1),
			},
			wantAbort: true,
			wantErr:   errIForwardTSNTooManyStreams,
		},
		{
			name: "duplicate ordered stream forward",
			chunk: &chunkIForwardTSN{
				newCumulativeTSN: 1,
				streams: []chunkIForwardTSNStream{
					{identifier: 1, unordered: false, messageIdentifier: 2},
					{identifier: 1, unordered: false, messageIdentifier: 3},
				},
			},
			wantAbort: true,
			wantErr:   errIForwardTSNDuplicateStream,
		},
		{
			name: "duplicate unordered stream forward",
			chunk: &chunkIForwardTSN{
				newCumulativeTSN: 1,
				streams: []chunkIForwardTSNStream{
					{identifier: 1, unordered: true, messageIdentifier: 2},
					{identifier: 1, unordered: true, messageIdentifier: 3},
				},
			},
			wantAbort: true,
			wantErr:   errIForwardTSNDuplicateStream,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			abort, err := tc.chunk.check()
			assert.Equal(t, tc.wantAbort, abort)
			if tc.wantErr == nil {
				assert.NoError(t, err)

				return
			}

			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestChunkIForwardTSNMarshal_Failure(t *testing.T) {
	_, err := (&chunkIForwardTSN{
		newCumulativeTSN: 1,
		streams: []chunkIForwardTSNStream{
			{identifier: 1, messageIdentifier: 2},
			{identifier: 1, messageIdentifier: 3},
		},
	}).marshal()

	assert.ErrorIs(t, err, errIForwardTSNDuplicateStream)
}

func TestChunkIForwardTSNMarshal_ZeroCumulativeTSN(t *testing.T) {
	_, err := (&chunkIForwardTSN{
		newCumulativeTSN: 0,
		streams: []chunkIForwardTSNStream{{
			identifier:        1,
			messageIdentifier: 2,
		}},
	}).marshal()

	assert.NoError(t, err)
}
