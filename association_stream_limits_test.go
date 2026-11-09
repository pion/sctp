// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package sctp

import (
	"fmt"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func associationWithClientServerOptions( //nolint:cyclop
	t *testing.T,
	piper piperFunc,
	clientExtra []ClientOption,
	serverExtra []ServerOption,
) (*Association, *Association, error) {
	t.Helper()

	ca, cb := piper(t)
	loggerFactory := logging.NewDefaultLoggerFactory()
	clientOpts := append([]ClientOption{WithNetConn(ca), WithLoggerFactory(loggerFactory)}, clientExtra...)
	serverOpts := append([]ServerOption{WithNetConn(cb), WithLoggerFactory(loggerFactory)}, serverExtra...)

	type result struct {
		side  bool
		assoc *Association
		err   error
	}
	results := make(chan result, 2)
	go func() {
		assoc, err := ClientWithOptions(clientOpts...)
		results <- result{side: true, assoc: assoc, err: err}
	}()
	go func() {
		assoc, err := ServerWithOptions(serverOpts...)
		results <- result{assoc: assoc, err: err}
	}()

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	var client, server *Association
	for client == nil || server == nil {
		select {
		case res := <-results:
			if res.err != nil {
				_ = ca.Close()
				_ = cb.Close()

				return nil, nil, res.err
			}
			if res.side {
				client = res.assoc
			} else {
				server = res.assoc
			}
		case <-timer.C:
			_ = ca.Close()
			_ = cb.Close()

			return nil, nil, fmt.Errorf("timeout establishing association") //nolint:err113
		}
	}

	return client, server, nil
}

func TestAssociationMetadataReportsNegotiatedStreamLimits(t *testing.T) {
	const (
		clientInbound  = uint16(3)
		clientOutbound = uint16(4)
		serverInbound  = uint16(11)
		serverOutbound = uint16(12)
	)

	client, server, err := associationWithClientServerOptions(
		t,
		pipeDump,
		[]ClientOption{WithNumStreams(clientInbound, clientOutbound)},
		[]ServerOption{WithNumStreams(serverInbound, serverOutbound)},
	)
	require.NoError(t, err)
	defer noErrorClose(t, client.Close)
	defer noErrorClose(t, server.Close)

	clientMetadata, ok := client.Metadata()
	require.True(t, ok)
	require.Equal(t, clientInbound, clientMetadata.NumInboundStreams)
	require.Equal(t, clientOutbound, clientMetadata.NumOutboundStreams)

	serverMetadata, ok := server.Metadata()
	require.True(t, ok)
	require.Equal(t, clientOutbound, serverMetadata.NumInboundStreams)
	require.Equal(t, clientInbound, serverMetadata.NumOutboundStreams)
}

func TestAssociationConfigCopiesStreamLimits(t *testing.T) {
	const (
		numInbound  = uint16(7)
		numOutbound = uint16(9)
	)
	config := Config{
		NetConn:            &dumbConn{},
		NumInboundStreams:  numInbound,
		NumOutboundStreams: numOutbound,
	}

	serverConfig, err := buildServerConfig(config)
	assert.NoError(t, err)
	assert.Equal(t, numInbound, serverConfig.NumInboundStreams)
	assert.Equal(t, numOutbound, serverConfig.NumOutboundStreams)

	clientConfig, err := buildClientConfig(config)
	assert.NoError(t, err)
	assert.Equal(t, numInbound, clientConfig.NumInboundStreams)
	assert.Equal(t, numOutbound, clientConfig.NumOutboundStreams)
}
