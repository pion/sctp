// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInterleavingSettingsWeightedFairQueueingFactorySnapshotsWeights(t *testing.T) {
	settings := &interleavingSettings{}
	assert.NoError(t, WithInterleavingWeightedFairQueueingWeight(1, 2)(settings))

	settings.wfqWeights[1] = 5

	scheduler, ok := settings.newStreamScheduler().(*weightedFairQueueingPendingQueuePolicy)
	if !assert.True(t, ok) {
		return
	}
	assert.Equal(t, map[uint16]uint16{1: 2}, scheduler.weights)
}

func TestCloneInterleavingSettingsWeightedFairQueueingFactoryUsesClonedWeights(t *testing.T) {
	settings := &interleavingSettings{}
	assert.NoError(t, WithInterleavingWeightedFairQueueingWeight(1, 2)(settings))

	clone := cloneInterleavingSettings(settings)
	assert.NoError(t, WithInterleavingWeightedFairQueueingWeight(1, 5)(settings))

	scheduler, ok := clone.newStreamScheduler().(*weightedFairQueueingPendingQueuePolicy)
	if !assert.True(t, ok) {
		return
	}
	assert.Equal(t, map[uint16]uint16{1: 2}, clone.wfqWeights)
	assert.Equal(t, map[uint16]uint16{1: 2}, scheduler.weights)
}
