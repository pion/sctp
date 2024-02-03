// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package main implements a simple ping-pong example
package main

import (
	"net"
	"sync"
	"time"
)

// Reference: https://github.com/pion/sctp/blob/master/association_test.go
// Since UDP is connectionless, as a server, it doesn't know how to reply
// simply using the `Write` method. So, to make it work, `disconnectedPacketConn`
// will infer the last packet that it reads as the reply address for `Write`

type disconnectedPacketConn struct { // nolint: unused
	mu    sync.RWMutex
	rAddr net.Addr
	pConn net.PacketConn
}

// Read
func (c *disconnectedPacketConn) Read(p []byte) (int, error) { //nolint:unused
	i, rAddr, err := c.pConn.ReadFrom(p)
	if err != nil {
		return 0, err
	}

	c.mu.Lock()
	c.rAddr = rAddr
	c.mu.Unlock()

	return i, err
}

// Write writes len(p) bytes from p to the DTLS connection
func (c *disconnectedPacketConn) Write(p []byte) (n int, err error) { //nolint:unused
	return c.pConn.WriteTo(p, c.RemoteAddr())
}

// Close closes the conn and releases any Read calls
func (c *disconnectedPacketConn) Close() error { //nolint:unused
	return c.pConn.Close()
}

// LocalAddr is a stub
func (c *disconnectedPacketConn) LocalAddr() net.Addr { //nolint:unused
	if c.pConn != nil {
		return c.pConn.LocalAddr()
	}
	return nil
}

// RemoteAddr is a stub
func (c *disconnectedPacketConn) RemoteAddr() net.Addr { //nolint:unused
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rAddr
}

// SetDeadline is a stub
func (c *disconnectedPacketConn) SetDeadline(time.Time) error { //nolint:unused
	return nil
}

// SetReadDeadline is a stub
func (c *disconnectedPacketConn) SetReadDeadline(time.Time) error { //nolint:unused
	return nil
}

// SetWriteDeadline is a stub
func (c *disconnectedPacketConn) SetWriteDeadline(time.Time) error { //nolint:unused
	return nil
}
