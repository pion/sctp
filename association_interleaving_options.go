// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import "maps"

type interleavingSettings struct {
	newStreamScheduler InterleavingStreamSchedulerFactory
	wfqWeights         map[uint16]uint16
}

func setWeightedFairQueueingStreamScheduler(s *interleavingSettings) {
	weights := maps.Clone(s.wfqWeights)
	s.newStreamScheduler = func() InterleavingStreamScheduler {
		return newWeightedFairQueueingPendingQueuePolicy(weights)
	}
}

func cloneInterleavingSettings(s *interleavingSettings) *interleavingSettings {
	if s == nil {
		return &interleavingSettings{}
	}

	clone := &interleavingSettings{
		newStreamScheduler: s.newStreamScheduler,
	}
	if len(s.wfqWeights) > 0 {
		clone.wfqWeights = make(map[uint16]uint16, len(s.wfqWeights))
		maps.Copy(clone.wfqWeights, s.wfqWeights)
	}

	return clone
}

// StreamSchedulerChunk is the scheduler-visible view of a DATA or I-DATA chunk.
// Stream reset chunks are control markers queued with data to preserve ordering.
type StreamSchedulerChunk interface {
	StreamIdentifier() uint16
	UserDataLen() int
	IsStreamReset() bool

	chunkPayloadData() *chunkPayloadData
}

// InterleavingStreamScheduler schedules I-DATA chunks across streams when RFC 8260
// user message interleaving is negotiated.
type InterleavingStreamScheduler interface {
	// Reset clears scheduler state before use and when the scheduler is detached.
	Reset()
	Push(StreamSchedulerChunk)
	Peek() StreamSchedulerChunk
	Pop(StreamSchedulerChunk) error
}

// InterleavingStreamSchedulerFactory creates an empty interleaving stream scheduler.
type InterleavingStreamSchedulerFactory func() InterleavingStreamScheduler

// AssociationInterleavingOption configures RFC 8260 user message interleaving.
type AssociationInterleavingOption func(*interleavingSettings) error

// WithInterleavingStreamSchedulerFactory selects a custom stream scheduler factory
// used when user message interleaving is negotiated.
func WithInterleavingStreamSchedulerFactory(
	newScheduler InterleavingStreamSchedulerFactory,
) AssociationInterleavingOption {
	return func(s *interleavingSettings) error {
		if newScheduler == nil {
			return errNilStreamScheduler
		}
		s.newStreamScheduler = newScheduler

		return nil
	}
}

// WithInterleavingWeightedFairQueueingScheduler selects the built-in RFC 8260
// weighted fair queueing stream scheduler.
func WithInterleavingWeightedFairQueueingScheduler() AssociationInterleavingOption {
	return func(s *interleavingSettings) error {
		setWeightedFairQueueingStreamScheduler(s)

		return nil
	}
}

// WithInterleavingWeightedFairQueueingWeight sets the WFQ weight for a stream.
// Larger weights receive proportionally more scheduling service when multiple
// streams are backlogged.
func WithInterleavingWeightedFairQueueingWeight(streamID uint16, weight uint16) AssociationInterleavingOption {
	return func(s *interleavingSettings) error {
		if weight == 0 {
			return errInvalidStreamSchedulerWeight
		}
		if s.wfqWeights == nil {
			s.wfqWeights = map[uint16]uint16{}
		}
		s.wfqWeights[streamID] = weight
		setWeightedFairQueueingStreamScheduler(s)

		return nil
	}
}

// WithInterleavingRoundRobinScheduler selects the built-in round-robin stream scheduler.
func WithInterleavingRoundRobinScheduler() AssociationInterleavingOption {
	return func(s *interleavingSettings) error {
		s.newStreamScheduler = func() InterleavingStreamScheduler {
			return newRoundRobinPendingQueuePolicy()
		}

		return nil
	}
}

// WithInterleavingOptions configures RFC 8260 user message interleaving options.
// The default interleaving stream scheduler is weighted fair queueing.
func WithInterleavingOptions(opts ...AssociationInterleavingOption) AssociationOption {
	return sharedOption(func(c *Config) error {
		cfg := cloneInterleavingSettings(c.interleaving)
		for _, opt := range opts {
			if opt == nil {
				continue
			}

			if err := opt(cfg); err != nil {
				return err
			}
		}

		c.interleaving = cfg

		return nil
	})
}
