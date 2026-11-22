// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package sctp

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func newResourceLimitTestAssociation(t *testing.T, opts ...AssociationOption) *Association {
	t.Helper()
	c1, c2 := net.Pipe()
	a := createTestAssociationWithOptions(t, Config{NetConn: c1}, opts...)
	t.Cleanup(func() { require.NoError(t, a.close()); require.NoError(t, c2.Close()) })
	a.setState(established)
	a.payloadQueue.init(0)
	return a
}

func TestAssociationRetainedChunkLimitAndDuplicate(t *testing.T) {
	a := newResourceLimitTestAssociation(t, WithMaxRetainedPayloadChunks(1024))
	for tsn := uint32(1); tsn <= 1024; tsn++ {
		a.handleData(&chunkPayloadData{tsn: tsn, streamIdentifier: 0, streamSequenceNumber: uint16(tsn), userData: []byte{1}})
	}
	require.Equal(t, uint32(1024), a.retainedPayloadChunks.Load())
	require.False(t, a.willSendAbort)

	a.handleData(&chunkPayloadData{tsn: 1024, streamIdentifier: 0, streamSequenceNumber: 1024, userData: []byte{9}})
	require.Equal(t, uint32(1024), a.retainedPayloadChunks.Load())
	require.False(t, a.willSendAbort)

	a.handleData(&chunkPayloadData{tsn: 1025, streamIdentifier: 0, streamSequenceNumber: 1025, userData: []byte{1}})
	require.True(t, a.willSendAbort)
	cause, ok := a.willSendAbortCause.(*errorCauseProtocolViolation)
	require.True(t, ok)
	require.Equal(t, "association retained payload chunk limit exceeded", string(cause.additionalInformation))
}

func TestAssociationInboundMessageLimit(t *testing.T) {
	for _, tc := range []struct {
		name        string
		interleaved bool
	}{{"DATA", false}, {"I-DATA", true}} {
		t.Run(tc.name, func(t *testing.T) {
			a := newResourceLimitTestAssociation(t, WithMaxInboundMessageSize(16*1024))
			a.useInterleaving = tc.interleaved
			first := &chunkPayloadData{tsn: 1, streamIdentifier: 0, beginningFragment: true, userData: make([]byte, 16*1024)}
			if tc.interleaved {
				first.iData = true
				first.messageIdentifier = 7
			}
			a.handleData(first)
			require.False(t, a.willSendAbort)
			next := &chunkPayloadData{tsn: 2, streamIdentifier: 0, endingFragment: true, userData: []byte{1}}
			if tc.interleaved {
				next.iData = true
				next.messageIdentifier = 7
				next.fragmentSequenceNumber = 1
			}
			a.handleData(next)
			require.True(t, a.willSendAbort)
			cause := a.willSendAbortCause.(*errorCauseProtocolViolation)
			require.Equal(t, errInboundMessageLimitExceeded.Error(), string(cause.additionalInformation))
		})
	}
}

func TestAssociationStreamLimits(t *testing.T) {
	a := newResourceLimitTestAssociation(t, WithStreamLimits(2, 2))
	a.handleData(&chunkPayloadData{tsn: 1, streamIdentifier: 2, beginningFragment: true, endingFragment: true})
	require.NotContains(t, a.streams, uint16(2))
	require.True(t, a.willSendAbort)

	b := newResourceLimitTestAssociation(t, WithStreamLimits(2, 2))
	_, err := b.OpenStream(1, PayloadTypeWebRTCBinary)
	require.NoError(t, err)
	_, err = b.OpenStream(2, PayloadTypeWebRTCBinary)
	require.ErrorIs(t, err, ErrOutboundStreamLimitExceeded)
}

func TestAssociationRetainedChargesReleaseOnReadAndForwardTSN(t *testing.T) {
	a := newResourceLimitTestAssociation(t, WithMaxRetainedPayloadChunks(2))
	a.handleData(&chunkPayloadData{tsn: 1, streamIdentifier: 0, streamSequenceNumber: 0, beginningFragment: true, endingFragment: true, userData: []byte("ok")})
	require.Equal(t, uint32(1), a.retainedPayloadChunks.Load(), "complete unread message remains charged")
	s := a.streams[0]
	buf := make([]byte, 2)
	_, _, err := s.ReadSCTP(buf)
	require.NoError(t, err)
	require.Equal(t, uint32(0), a.retainedPayloadChunks.Load())

	a.handleData(&chunkPayloadData{tsn: 2, streamIdentifier: 0, streamSequenceNumber: 1, beginningFragment: true, userData: []byte("x")})
	require.Equal(t, uint32(1), a.retainedPayloadChunks.Load())
	s.handleForwardTSNForOrdered(1)
	require.Equal(t, uint32(0), a.retainedPayloadChunks.Load())
}

func TestResourceLimitOptionsApplyClientAndServer(t *testing.T) {
	opts := []AssociationOption{WithStreamLimits(2, 3), WithMaxInboundMessageSize(16), WithMaxRetainedPayloadChunks(8)}
	for _, server := range []bool{false, true} {
		cfg := &Config{}
		for _, opt := range opts {
			if server {
				require.NoError(t, opt.applyServer(cfg))
			} else {
				require.NoError(t, opt.applyClient(cfg))
			}
		}
		require.Equal(t, uint16(2), cfg.maxInboundStreams)
		require.Equal(t, uint16(3), cfg.maxOutboundStreams)
		require.Equal(t, uint32(16), cfg.maxInboundMessageSize)
		require.Equal(t, uint32(8), cfg.maxRetainedPayloadChunks)
	}
}
