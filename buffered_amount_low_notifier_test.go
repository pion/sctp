// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"sync"
	"testing"
	"time"

	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/require"
)

func TestBufferedAmountLowNotifierStopsAfterClose(t *testing.T) {
	lim := test.TimeOut(time.Second)
	defer lim.Stop()

	notifier := newBufferedAmountLowNotifier()
	t.Cleanup(func() {
		notifier.close()
		notifier.wait()
	})
	firstStarted := make(chan struct{})
	firstReleaseCh := make(chan struct{})
	releaseFirst := sync.OnceFunc(func() { close(firstReleaseCh) })
	t.Cleanup(releaseFirst)
	queuedCallbackDone := make(chan struct{})
	firstStream := &Stream{}
	firstStream.OnBufferedAmountLow(func() {
		close(firstStarted)
		<-firstReleaseCh
	})
	notifier.notify(firstStream)
	requireNotifierSignal(t, firstStarted, "first callback was not called")
	queuedStream := &Stream{}
	queuedStream.OnBufferedAmountLow(func() {
		close(queuedCallbackDone)
	})
	notifier.notify(queuedStream)

	notifier.close()
	releaseFirst()
	requireNotifierSignal(t, queuedCallbackDone, "queued callback was not drained during shutdown")
	notifier.wait()
}

func requireNotifierSignal(t *testing.T, signal <-chan struct{}, message string) {
	t.Helper()

	select {
	case <-signal:
	case <-time.After(time.Second):
		require.FailNow(t, message)
	}
}
