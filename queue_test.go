// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestQueue(t *testing.T) {
	queu := newQueue[int](32)
	assert.Zero(t, queu.Len())

	// test push & pop
	for i := 1; i < 33; i++ {
		queu.PushBack(i)
	}
	assert.Equal(t, 32, queu.Len())
	assert.Equal(t, 5, queu.At(4))
	for i := 1; i < 33; i++ {
		assert.Equal(t, i, queu.Front())
		assert.Equal(t, i, queu.PopFront())
	}
	assert.Zero(t, queu.Len())

	queu.PushBack(10)
	queu.PushBack(11)
	assert.Equal(t, 2, queu.Len())
	assert.Equal(t, 11, queu.At(1))
	assert.Equal(t, 10, queu.Front())
	assert.Equal(t, 10, queu.PopFront())
	assert.Equal(t, 11, queu.PopFront())

	// test grow capacity
	for i := 0; i < 64; i++ {
		queu.PushBack(i)
	}
	assert.Equal(t, 64, queu.Len())
	assert.Equal(t, 2, queu.At(2))
	for i := 0; i < 64; i++ {
		assert.Equal(t, i, queu.Front())
		assert.Equal(t, i, queu.PopFront())
	}
}
