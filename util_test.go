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

func TestSerialNumberArithmetic(t *testing.T) {
	const div int = 16

	t.Run("32-bit", func(t *testing.T) {
		const serialBits uint32 = 32
		const interval uint32 = uint32((uint64(1) << uint64(serialBits)) / uint64(div))
		const maxForwardDistance uint32 = 1<<(serialBits-1) - 1
		const maxBackwardDistance uint32 = 1 << (serialBits - 1)

		for i := uint32(0); i < uint32(div); i++ {
			s1 := i * interval
			s2f := s1 + maxForwardDistance
			s2b := s1 + maxBackwardDistance

			assert.True(t, sna32LT(s1, s2f), "s1 < s2 should be true: s1=0x%x s2=0x%x", s1, s2f)
			assert.False(t, sna32LT(s1, s2b), "s1 < s2 should be false: s1=0x%x s2=0x%x", s1, s2b)

			assert.False(t, sna32GT(s1, s2f), "s1 > s2 should be fales: s1=0x%x s2=0x%x", s1, s2f)
			assert.True(t, sna32GT(s1, s2b), "s1 > s2 should be true: s1=0x%x s2=0x%x", s1, s2b)

			assert.True(t, sna32LTE(s1, s2f), "s1 <= s2 should be true: s1=0x%x s2=0x%x", s1, s2f)
			assert.False(t, sna32LTE(s1, s2b), "s1 <= s2 should be false: s1=0x%x s2=0x%x", s1, s2b)

			assert.False(t, sna32GTE(s1, s2f), "s1 >= s2 should be fales: s1=0x%x s2=0x%x", s1, s2f)
			assert.True(t, sna32GTE(s1, s2b), "s1 >= s2 should be true: s1=0x%x s2=0x%x", s1, s2b)

			assert.True(t, sna32EQ(s1, s1), "s1 == s1 should be true: s1=0x%x s2=0x%x", s1, s1)
			assert.True(t, sna32EQ(s2b, s2b), "s2 == s2 should be true: s2=0x%x s2=0x%x", s2b, s2b)
			assert.False(t, sna32EQ(s1, s1+1), "s1 == s1+1 should be false: s1=0x%x s1+1=0x%x", s1, s1+1)
			assert.False(t, sna32EQ(s1, s1-1), "s1 == s1-1 hould be false: s1=0x%x s1-1=0x%x", s1, s1-1)

			assert.True(t, sna32LTE(s1, s1), "s1 == s1 should be true: s1=0x%x s2=0x%x", s1, s1)
			assert.True(t, sna32LTE(s2b, s2b), "s2 == s2 should be true: s2=0x%x s2=0x%x", s2b, s2b)

			assert.True(t, sna32GTE(s1, s1), "s1 == s1 should be true: s1=0x%x s2=0x%x", s1, s1)
			assert.True(t, sna32GTE(s2b, s2b), "s2 == s2 should be true: s2=0x%x s2=0x%x", s2b, s2b)
		}
	})

	t.Run("16-bit", func(t *testing.T) {
		const serialBits uint16 = 16
		const interval uint16 = uint16((uint64(1) << uint64(serialBits)) / uint64(div))
		const maxForwardDistance uint16 = 1<<(serialBits-1) - 1
		const maxBackwardDistance uint16 = 1 << (serialBits - 1)

		for i := uint16(0); i < uint16(div); i++ {
			s1 := i * interval
			s2f := s1 + maxForwardDistance
			s2b := s1 + maxBackwardDistance

			assert.True(t, sna16LT(s1, s2f), "s1 < s2 should be true: s1=0x%x s2=0x%x", s1, s2f)
			assert.False(t, sna16LT(s1, s2b), "s1 < s2 should be false: s1=0x%x s2=0x%x", s1, s2b)

			assert.False(t, sna16GT(s1, s2f), "s1 > s2 should be fales: s1=0x%x s2=0x%x", s1, s2f)
			assert.True(t, sna16GT(s1, s2b), "s1 > s2 should be true: s1=0x%x s2=0x%x", s1, s2b)

			assert.True(t, sna16LTE(s1, s2f), "s1 <= s2 should be true: s1=0x%x s2=0x%x", s1, s2f)
			assert.False(t, sna16LTE(s1, s2b), "s1 <= s2 should be false: s1=0x%x s2=0x%x", s1, s2b)

			assert.False(t, sna16GTE(s1, s2f), "s1 >= s2 should be fales: s1=0x%x s2=0x%x", s1, s2f)
			assert.True(t, sna16GTE(s1, s2b), "s1 >= s2 should be true: s1=0x%x s2=0x%x", s1, s2b)

			assert.True(t, sna16EQ(s1, s1), "s1 == s1 should be true: s1=0x%x s2=0x%x", s1, s1)
			assert.True(t, sna16EQ(s2b, s2b), "s2 == s2 should be true: s2=0x%x s2=0x%x", s2b, s2b)
			assert.False(t, sna16EQ(s1, s1+1), "s1 == s1+1 should be false: s1=0x%x s1+1=0x%x", s1, s1+1)
			assert.False(t, sna16EQ(s1, s1-1), "s1 == s1-1 hould be false: s1=0x%x s1-1=0x%x", s1, s1-1)

			assert.True(t, sna16LTE(s1, s1), "s1 == s1 should be true: s1=0x%x s2=0x%x", s1, s1)
			assert.True(t, sna16LTE(s2b, s2b), "s2 == s2 should be true: s2=0x%x s2=0x%x", s2b, s2b)

			assert.True(t, sna16GTE(s1, s1), "s1 == s1 should be true: s1=0x%x s2=0x%x", s1, s1)
			assert.True(t, sna16GTE(s2b, s2b), "s2 == s2 should be true: s2=0x%x s2=0x%x", s2b, s2b)
		}
	})
}
