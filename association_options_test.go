// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func udpPiper(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()

	return createUDPConnPair()
}

func TestAssociationOptions_ApplyBothSides(t *testing.T) {
	opt := WithName("x")

	var sCfg Config
	var cCfg Config

	assert.NoError(t, opt.applyServer(&sCfg))
	assert.NoError(t, opt.applyClient(&cCfg))

	assert.Equal(t, "x", sCfg.Name)
	assert.Equal(t, "x", cCfg.Name)
}

func TestAssociationOptions_Validation(t *testing.T) {
	t.Run("nil logger factory", func(t *testing.T) {
		var cfg Config
		err := WithLoggerFactory(nil).applyServer(&cfg)
		assert.ErrorIs(t, err, errNilLoggerFactory)
	})

	t.Run("nil net conn", func(t *testing.T) {
		var cfg Config
		err := WithNetConn(nil).applyServer(&cfg)
		assert.ErrorIs(t, err, errNilNetConn)
	})

	t.Run("mtu zero", func(t *testing.T) {
		var cfg Config
		err := WithMTU(0).applyServer(&cfg)
		assert.ErrorIs(t, err, errZeroMTUOption)
	})

	t.Run("max recv buf zero", func(t *testing.T) {
		var cfg Config
		err := WithMaxReceiveBufferSize(0).applyServer(&cfg)
		assert.ErrorIs(t, err, errZeroMaxReceiveBufferOption)
	})

	t.Run("max msg size zero", func(t *testing.T) {
		var cfg Config
		err := WithMaxMessageSize(0).applyServer(&cfg)
		assert.ErrorIs(t, err, errZeroMaxMessageSize)
	})

	t.Run("rto max <= 0", func(t *testing.T) {
		var cfg Config
		err := WithRTOMax(0).applyServer(&cfg)
		assert.ErrorIs(t, err, errInvalidRTOMax)
	})
}

func TestAssociationOptions_ClientAndServer(t *testing.T) {
	lf := customLogger{
		expectZeroChecksum: true,
		t:                  t,
	}

	aClient, aServer, err := association(
		t,
		udpPiper,
		WithName("opt-pair"),
		WithLoggerFactory(lf),

		WithMTU(1200),
		WithMaxReceiveBufferSize(7777),
		WithMaxMessageSize(30000),
		WithRTOMax(1000),
		WithMinCwnd(5000),
		WithFastRtxWnd(6000),
		WithCwndCAStep(7000),
		WithBlockWrite(true),
		WithEnableZeroChecksum(true),
	)
	assert.NoError(t, err)
	defer func() {
		_ = aClient.Close()
		_ = aServer.Close()
	}()

	_, ok := aClient.log.(customLogger)
	assert.True(t, ok, "client logger should be customLogger")
	_, ok = aServer.log.(customLogger)
	assert.True(t, ok, "server logger should be customLogger")

	assert.Equal(t, uint32(1200), aClient.MTU())
	assert.Equal(t, uint32(1200), aServer.MTU())

	assert.Equal(t, uint32(7777), aClient.maxReceiveBufferSize)
	assert.Equal(t, uint32(7777), aServer.maxReceiveBufferSize)

	assert.Equal(t, uint32(30000), aClient.MaxMessageSize())
	assert.Equal(t, uint32(30000), aServer.MaxMessageSize())

	assert.Equal(t, uint32(5000), aClient.minCwnd)
	assert.Equal(t, uint32(6000), aClient.fastRtxWnd)
	assert.Equal(t, uint32(7000), aClient.cwndCAStep)

	assert.True(t, aClient.blockWrite)
	assert.True(t, aServer.blockWrite)

	assert.True(t, aClient.recvZeroChecksum)
	assert.True(t, aServer.recvZeroChecksum)

	assert.Equal(t, uint32(1200)-(commonHeaderSize+dataChunkHeaderSize), aClient.maxPayloadSize)
	assert.Equal(t, uint32(1200)-(commonHeaderSize+dataChunkHeaderSize), aServer.maxPayloadSize)

	assert.Equal(t, "opt-pair", aClient.name)
	assert.Equal(t, "opt-pair", aServer.name)

	time.Sleep(10 * time.Millisecond)
}
