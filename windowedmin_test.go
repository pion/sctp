// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestWindowedMin_Basic(t *testing.T) {
	window := newWindowedMin(100 * time.Millisecond)
	base := time.Unix(0, 0)

	window.Push(base, 30*time.Millisecond)
	assert.Equal(t, 30*time.Millisecond, window.Min(base))

	window.Push(base.Add(10*time.Millisecond), 20*time.Millisecond)
	assert.Equal(t, 20*time.Millisecond, window.Min(base.Add(10*time.Millisecond)))

	// larger value shouldn't change min
	window.Push(base.Add(20*time.Millisecond), 40*time.Millisecond)
	assert.Equal(t, 20*time.Millisecond, window.Min(base.Add(20*time.Millisecond)))

	// decreasing again shrinks min
	window.Push(base.Add(30*time.Millisecond), 10*time.Millisecond)
	assert.Equal(t, 10*time.Millisecond, window.Min(base.Add(30*time.Millisecond)))
}

func TestWindowedMin_WindowExpiry(t *testing.T) {
	window := newWindowedMin(50 * time.Millisecond)
	base := time.Unix(0, 0)

	window.Push(base, 10*time.Millisecond)                          // t=0
	window.Push(base.Add(10*time.Millisecond), 20*time.Millisecond) // t=10ms

	// at t=60ms, first sample is expired, m becomes 20ms
	m := window.Min(base.Add(60 * time.Millisecond))
	assert.Equal(t, 20*time.Millisecond, m)

	// at t=200ms, all are expired -> 0
	m = window.Min(base.Add(200 * time.Millisecond))
	assert.Zero(t, m)
}

func TestWindowedMin_EqualValues(t *testing.T) {
	window := newWindowedMin(1 * time.Second)
	base := time.Unix(0, 0)

	window.Push(base, 15*time.Millisecond)
	window.Push(base.Add(1*time.Millisecond), 15*time.Millisecond)

	assert.Equal(t, 1, window.Len())
	assert.Equal(t, 15*time.Millisecond, window.Min(base.Add(2*time.Millisecond)))
}

func TestWindowedMin_DefaultWindow30s(t *testing.T) {
	zeroWnd := newWindowedMin(0)
	negativeWnd := newWindowedMin(-5 * time.Second)

	assert.Equal(t, 30*time.Second, zeroWnd.rackMinRTTWnd)
	assert.Equal(t, 30*time.Second, negativeWnd.rackMinRTTWnd)
}
