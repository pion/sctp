package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPadByte_Success(t *testing.T) {
	tt := []struct {
		value    []byte
		padLen   int
		expected []byte
	}{
		{[]byte{0x1, 0x2}, 0, []byte{0x1, 0x2}},
		{[]byte{0x1, 0x2}, 1, []byte{0x1, 0x2, 0x0}},
		{[]byte{0x1, 0x2}, 2, []byte{0x1, 0x2, 0x0, 0x0}},
		{[]byte{0x1, 0x2}, 3, []byte{0x1, 0x2, 0x0, 0x0, 0x0}},
		{[]byte{0x1, 0x2}, -1, []byte{0x1, 0x2}},
	}

	for i, tc := range tt {
		actual := padByte(tc.value, tc.padLen)

		assert.Equal(t, tc.expected, actual, "test %d not equal", i)
	}
}
