// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import "sync"

// bufferedAmountLowNotifier runs callbacks serially without blocking the protocol
// goroutine that submitted them. Close rejects new callbacks and drains callbacks
// that were already queued.
type bufferedAmountLowNotifier struct {
	lock  sync.Mutex
	runWG sync.WaitGroup
	// Queued streams are deduplicated, so the queue is bounded by the number of
	// live streams and protocol loops never block on callback backpressure.
	streams       []*Stream
	queuedStreams map[*Stream]struct{}
	wakeCh        chan struct{}
	closeCh       chan struct{}
	started       bool
	closed        bool
}

func newBufferedAmountLowNotifier() *bufferedAmountLowNotifier {
	return &bufferedAmountLowNotifier{
		queuedStreams: make(map[*Stream]struct{}),
		wakeCh:        make(chan struct{}, 1),
		closeCh:       make(chan struct{}),
	}
}

func (n *bufferedAmountLowNotifier) notify(stream *Stream) {
	if stream == nil {
		return
	}

	n.lock.Lock()
	if n.closed {
		n.lock.Unlock()

		return
	}
	if _, ok := n.queuedStreams[stream]; ok {
		n.lock.Unlock()

		return
	}
	n.streams = append(n.streams, stream)
	n.queuedStreams[stream] = struct{}{}
	start := !n.started
	n.started = true
	if start {
		n.runWG.Add(1)
	}
	n.lock.Unlock()

	if start {
		go n.run()
	}
	select {
	case n.wakeCh <- struct{}{}:
	default:
	}
}

func (n *bufferedAmountLowNotifier) next() *Stream {
	n.lock.Lock()
	defer n.lock.Unlock()

	if len(n.streams) == 0 {
		return nil
	}

	stream := n.streams[0]
	n.streams[0] = nil
	delete(n.queuedStreams, stream)
	if len(n.streams) == 1 {
		n.streams = nil
	} else {
		n.streams = n.streams[1:]
	}

	return stream
}

func (n *bufferedAmountLowNotifier) run() {
	defer n.runWG.Done()

	for {
		select {
		case <-n.closeCh:
			for stream := n.next(); stream != nil; stream = n.next() {
				stream.invokeBufferedAmountLowCallback()
			}

			return
		case <-n.wakeCh:
			for stream := n.next(); stream != nil; stream = n.next() {
				stream.invokeBufferedAmountLowCallback()
			}
		}
	}
}

// close rejects new callbacks and starts draining the queue. It does not wait
// for the notifier goroutine to exit.
func (n *bufferedAmountLowNotifier) close() {
	n.lock.Lock()
	if n.closed {
		n.lock.Unlock()

		return
	}
	n.closed = true
	n.lock.Unlock()

	close(n.closeCh)
}

// wait is used by tests to join the notifier after close.
func (n *bufferedAmountLowNotifier) wait() {
	n.runWG.Wait()
}
