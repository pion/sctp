// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package sctp

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clientContextConn signals when the handshake starts and can block deadline updates.
type clientContextConn struct {
	net.Conn
	writeStarted    chan struct{}
	deadlineBlocked chan struct{}
	writeOnce       sync.Once
}

// Write signals that the client has started sending its handshake.
func (c *clientContextConn) Write(packet []byte) (int, error) {
	c.writeOnce.Do(func() { close(c.writeStarted) })

	return c.Conn.Write(packet)
}

// SetReadDeadline optionally waits before forwarding the deadline to the connection.
func (c *clientContextConn) SetReadDeadline(deadline time.Time) error {
	if c.deadlineBlocked != nil {
		<-c.deadlineBlocked
	}

	return c.Conn.SetReadDeadline(deadline)
}

// clientContextLoggerFactory runs a callback at a deterministic point during setup.
type clientContextLoggerFactory struct {
	logging.LoggerFactory
	onCreate func()
}

// NewLogger invokes the setup callback before creating the association logger.
func (f clientContextLoggerFactory) NewLogger(scope string) logging.LeveledLogger {
	f.onCreate()

	return f.LoggerFactory.NewLogger(scope)
}

// requirePipeClosed observes library cleanup without causing a read timeout itself.
func requirePipeClosed(t *testing.T, conn net.Conn) {
	t.Helper()

	require.Eventually(t, func() bool {
		return errors.Is(conn.SetReadDeadline(time.Time{}), io.ErrClosedPipe)
	}, time.Second, time.Millisecond, "ClientContext did not close the connection")
}

func TestClientContextAlreadyDone(t *testing.T) {
	checkGoroutineLeaks(t)

	init, err := GenerateOutOfBandToken(Config{})
	require.NoError(t, err)

	for _, snap := range []bool{false, true} {
		t.Run(map[bool]string{false: "handshake", true: "SNAP"}[snap], func(t *testing.T) {
			conn, peer := net.Pipe()
			t.Cleanup(func() { assert.NoError(t, conn.Close()) })
			t.Cleanup(func() { assert.NoError(t, peer.Close()) })

			created := false
			opts := []ClientOption{WithNetConn(conn), WithLoggerFactory(clientContextLoggerFactory{
				LoggerFactory: logging.NewDefaultLoggerFactory(),
				onCreate:      func() { created = true },
			})}
			if snap {
				opts = append(opts, WithSNAP(init, init))
			}

			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			assoc, err := ClientContext(ctx, opts...)
			assert.ErrorIs(t, err, context.Canceled)
			assert.Nil(t, assoc)
			assert.False(t, created, "a canceled context must not start an association")
			assert.NoError(t, conn.SetReadDeadline(time.Now()), "the caller still owns the connection")
		})
	}
}

func TestClientContextCancelBlockingConnection(t *testing.T) {
	for _, blockDeadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "Close", true: "SetReadDeadline"}[blockDeadline], func(t *testing.T) {
			checkGoroutineLeaks(t)

			underlying := newBlockingCloseConn()
			t.Cleanup(func() { close(underlying.closeBlocked) })
			conn := &clientContextConn{Conn: underlying, writeStarted: make(chan struct{})}
			if blockDeadline {
				conn.deadlineBlocked = make(chan struct{})
				t.Cleanup(func() { close(conn.deadlineBlocked) })
			}

			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			result := make(chan error, 1)
			optionCalls := 0
			go func() {
				assoc, err := ClientContext(ctx, WithNetConn(conn), sharedOption(func(*Config) error {
					optionCalls++

					return nil
				}))
				assert.Nil(t, assoc)
				result <- err
			}()

			select {
			case <-conn.writeStarted:
			case <-time.After(time.Second):
				require.FailNow(t, "the client did not start its handshake")
			}
			cancel()

			select {
			case err := <-result:
				assert.ErrorIs(t, err, context.Canceled)
				assert.Equal(t, 1, optionCalls, "client options must be applied once")
			case <-time.After(time.Second):
				require.FailNow(t, "ClientContext waited for a blocked connection")
			}
		})
	}
}

func TestClientContextSNAPCanceledDuringSetup(t *testing.T) {
	checkGoroutineLeaks(t)

	init, err := GenerateOutOfBandToken(Config{})
	require.NoError(t, err)
	conn, peer := net.Pipe()
	t.Cleanup(func() { assert.NoError(t, conn.Close()) })
	t.Cleanup(func() { assert.NoError(t, peer.Close()) })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	assoc, err := ClientContext(ctx, WithNetConn(conn), WithSNAP(init, init),
		WithLoggerFactory(clientContextLoggerFactory{
			LoggerFactory: logging.NewDefaultLoggerFactory(),
			onCreate:      cancel,
		}))
	if assoc != nil {
		t.Cleanup(func() { assert.NoError(t, assoc.Close()) })
	}
	assert.ErrorIs(t, err, context.Canceled)
	assert.Nil(t, assoc)
	requirePipeClosed(t, conn)
}

func TestClientContextDeadlineExceeded(t *testing.T) {
	checkGoroutineLeaks(t)

	conn, peer := net.Pipe()
	t.Cleanup(func() { assert.NoError(t, conn.Close()) })
	t.Cleanup(func() { assert.NoError(t, peer.Close()) })
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	assoc, err := ClientContext(ctx, WithNetConn(conn))
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Nil(t, assoc)
	requirePipeClosed(t, conn)
}
