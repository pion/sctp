// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import "time"

// windowedMin maintains a monotonic deque of (time,value) to answer
// the minimum over a sliding window efficiently.
// Not thread-safe; caller must synchronize (Association already does).
type windowedMin struct {
	rackMinRTTWnd time.Duration
	deque         []entry
}

type entry struct {
	t time.Time
	v time.Duration
}

func newWindowedMin(window time.Duration) *windowedMin {
	if window <= 0 {
		window = 30 * time.Second
	}

	return &windowedMin{rackMinRTTWnd: window}
}

// prune removes elements older than (now - wnd).
func (window *windowedMin) prune(now time.Time) {
	cutoff := now.Add(-window.rackMinRTTWnd)
	i := 0
	for i < len(window.deque) && window.deque[i].t.Before(cutoff) {
		i++
	}

	if i > 0 {
		window.deque = window.deque[i:]
	}
}

// Push inserts a new sample and preserves monotonic non-increasing values.
// It maintains minimum values by removing larger entries.
func (window *windowedMin) Push(now time.Time, v time.Duration) {
	window.prune(now)

	for i := len(window.deque); i > 0 && window.deque[i-1].v >= v; i-- {
		window.deque = window.deque[:i-1]
	}

	window.deque = append(
		window.deque,
		entry{
			t: now,
			v: v,
		},
	)
}

// Min returns the minimum value in the current window or 0 if empty.
func (window *windowedMin) Min(now time.Time) time.Duration {
	window.prune(now)

	if len(window.deque) == 0 {
		return 0
	}

	return window.deque[0].v
}

// Len is only for tests/diagnostics.
func (window *windowedMin) Len() int {
	return len(window.deque)
}
