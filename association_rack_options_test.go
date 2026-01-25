// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRACKOptions_Validation(t *testing.T) {
	t.Run("min rtt wnd <= 0", func(t *testing.T) {
		var cfg Config
		err := WithRACKOptions(WithRackMinRTTWnd(0)).applyServer(&cfg)
		assert.Error(t, err)
		assert.ErrorIs(t, err, errInvalidRackMinRTTWnd)
	})

	t.Run("reo wnd floor < 0", func(t *testing.T) {
		var cfg Config
		err := WithRACKOptions(WithRackReoWndFloor(-1 * time.Millisecond)).applyServer(&cfg)
		assert.Error(t, err)
		assert.ErrorIs(t, err, errInvalidRackReoWndFloor)
	})

	t.Run("wc del ack <= 0", func(t *testing.T) {
		var cfg Config
		err := WithRACKOptions(WithRackWCDelAck(0)).applyServer(&cfg)
		assert.Error(t, err)
		assert.ErrorIs(t, err, errInvalidRackWcDelAck)
	})
}

func TestRACKOptions_AtomicApply_NoPartialMutationOnError(t *testing.T) {
	var cfg Config
	cfg.rack.rackWCDelAck = 123 * time.Millisecond

	err := WithRACKOptions(
		WithRackWCDelAck(50*time.Millisecond),
		WithRackWCDelAck(0), // invalid
	).applyServer(&cfg)

	assert.Error(t, err)
	assert.Equal(t, 123*time.Millisecond, cfg.rack.rackWCDelAck)
}

func TestRACKOptions_ApplyToConfig(t *testing.T) {
	var cfg Config

	err := WithRACKOptions(
		WithRackMinRTTWnd(10*time.Second),
		WithRackReoWndFloor(2*time.Millisecond),
		WithRackWCDelAck(50*time.Millisecond),
	).applyServer(&cfg)
	assert.NoError(t, err)

	assert.NotNil(t, cfg.rack.rackMinRTTWnd)
	assert.Equal(t, 2*time.Millisecond, cfg.rack.rackReoWndFloor)
	assert.Equal(t, 50*time.Millisecond, cfg.rack.rackWCDelAck)
}

func TestRACKOptions_EndToEnd_DefaultsAndOverrides(t *testing.T) {
	t.Run("defaults when not configured", func(t *testing.T) {
		aClient, aServer, err := association(t, udpPiper)
		assert.NoError(t, err)
		defer func() {
			_ = aClient.Close()
			_ = aServer.Close()
		}()

		assert.NotNil(t, aClient.rack.rackMinRTTWnd)
		assert.NotNil(t, aServer.rack.rackMinRTTWnd)

		assert.Equal(t, time.Duration(0), aClient.rack.rackReoWndFloor)
		assert.Equal(t, time.Duration(0), aServer.rack.rackReoWndFloor)

		assert.Equal(t, 200*time.Millisecond, aClient.rack.rackWCDelAck)
		assert.Equal(t, 200*time.Millisecond, aServer.rack.rackWCDelAck)
	})

	t.Run("overrides when configured", func(t *testing.T) {
		aClient, aServer, err := association(
			t,
			udpPiper,
			WithRACKOptions(
				WithRackMinRTTWnd(5*time.Second),
				WithRackReoWndFloor(3*time.Millisecond),
				WithRackWCDelAck(75*time.Millisecond),
			),
		)
		assert.NoError(t, err)
		defer func() {
			_ = aClient.Close()
			_ = aServer.Close()
		}()

		assert.NotNil(t, aClient.rack.rackMinRTTWnd)
		assert.NotNil(t, aServer.rack.rackMinRTTWnd)

		assert.Equal(t, 3*time.Millisecond, aClient.rack.rackReoWndFloor)
		assert.Equal(t, 3*time.Millisecond, aServer.rack.rackReoWndFloor)

		assert.Equal(t, 75*time.Millisecond, aClient.rack.rackWCDelAck)
		assert.Equal(t, 75*time.Millisecond, aServer.rack.rackWCDelAck)
	})
}
