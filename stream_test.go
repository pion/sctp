// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"sync"
	"testing"

	"github.com/pion/logging"
	"github.com/stretchr/testify/assert"
)

func newTestStream(t *testing.T) *Stream {
	t.Helper()

	s := &Stream{
		reassemblyQueue: newReassemblyQueue(0),
		log:             logging.NewDefaultLoggerFactory().NewLogger("sctp-test"),
	}
	s.readNotifier = sync.NewCond(&s.lock)

	return s
}

func newTestPacketizingStream(t *testing.T, useInterleaving bool, maxPayloadSize uint32) *Stream {
	t.Helper()

	logger := logging.NewDefaultLoggerFactory().NewLogger("sctp-test")
	assoc := &Association{
		useInterleaving: useInterleaving,
		maxPayloadSize:  maxPayloadSize,
		log:             logger,
		streams:         map[uint16]*Stream{},
	}
	assoc.SetMaxMessageSize(1024)

	return assoc.createStream(1, false)
}

func TestSessionBufferedAmount(t *testing.T) {
	t.Run("bufferedAmount", func(t *testing.T) {
		s := &Stream{
			log: logging.NewDefaultLoggerFactory().NewLogger("sctp-test"),
		}

		assert.Equal(t, uint64(0), s.BufferedAmount())
		assert.Equal(t, uint64(0), s.BufferedAmountLowThreshold())

		s.bufferedAmount = 8192
		s.SetBufferedAmountLowThreshold(2048)
		assert.Equal(t, uint64(8192), s.BufferedAmount(), "unexpected bufferedAmount")
		assert.Equal(t, uint64(2048), s.BufferedAmountLowThreshold(), "unexpected threshold")
	})

	t.Run("OnBufferedAmountLow", func(t *testing.T) {
		stream := &Stream{
			log: logging.NewDefaultLoggerFactory().NewLogger("sctp-test"),
		}

		stream.bufferedAmount = 4096
		stream.SetBufferedAmountLowThreshold(2048)

		nCbs := 0

		stream.OnBufferedAmountLow(func() {
			nCbs++
		})

		// Negative value should be ignored (by design)
		stream.onBufferReleased(-32) // bufferedAmount = 3072
		assert.Equal(t, uint64(4096), stream.BufferedAmount(), "unexpected bufferedAmount")
		assert.Equal(t, 0, nCbs, "callback count mismatch")

		// Above to above, no callback
		stream.onBufferReleased(1024) // bufferedAmount = 3072
		assert.Equal(t, uint64(3072), stream.BufferedAmount(), "unexpected bufferedAmount")
		assert.Equal(t, 0, nCbs, "callback count mismatch")

		// Above to equal, callback should be made
		stream.onBufferReleased(1024) // bufferedAmount = 2048
		assert.Equal(t, uint64(2048), stream.BufferedAmount(), "unexpected bufferedAmount")
		assert.Equal(t, 1, nCbs, "callback count mismatch")

		// Eaual to below, no callback
		stream.onBufferReleased(1024) // bufferedAmount = 1024
		assert.Equal(t, uint64(1024), stream.BufferedAmount(), "unexpected bufferedAmount")
		assert.Equal(t, 1, nCbs, "callback count mismatch")

		// Blow to below, no callback
		stream.onBufferReleased(1024) // bufferedAmount = 0
		assert.Equal(t, uint64(0), stream.BufferedAmount(), "unexpected bufferedAmount")
		assert.Equal(t, 1, nCbs, "callback count mismatch")

		// Capped at 0, no callback
		stream.onBufferReleased(1024) // bufferedAmount = 0
		assert.Equal(t, uint64(0), stream.BufferedAmount(), "unexpected bufferedAmount")
		assert.Equal(t, 1, nCbs, "callback count mismatch")
	})
}

func TestStreamHandleForwardTSNForMID(t *testing.T) {
	t.Run("ordered MID forward makes next complete message readable", func(t *testing.T) {
		stream := newTestStream(t)
		orgPpi := PayloadTypeWebRTCBinary

		complete := stream.reassemblyQueue.push(&chunkPayloadData{
			iData:             true,
			messageIdentifier: 0,
			beginningFragment: true,
			tsn:               10,
			streamIdentifier:  0,
			payloadType:       orgPpi,
			userData:          []byte("DROP"),
		})
		assert.False(t, complete, "MID 0 should remain incomplete")

		complete = stream.reassemblyQueue.push(&chunkPayloadData{
			iData:             true,
			messageIdentifier: 1,
			beginningFragment: true,
			endingFragment:    true,
			tsn:               11,
			streamIdentifier:  0,
			payloadType:       orgPpi,
			userData:          []byte("OK"),
		})
		assert.True(t, complete, "MID 1 should be complete")
		assert.False(t, stream.reassemblyQueue.isReadable(), "MID 1 should be blocked by missing MID 0")

		stream.handleForwardTSNForOrderedMID(0)

		assert.True(t, stream.reassemblyQueue.isReadable(), "forwarded MID should expose the next complete message")

		buf := make([]byte, 4)
		n, ppi, err := stream.ReadSCTP(buf)
		assert.NoError(t, err)
		assert.Equal(t, 2, n, "should read the kept MID")
		assert.Equal(t, orgPpi, ppi, "should preserve payload type")
		assert.Equal(t, "OK", string(buf[:n]), "unexpected payload")
		assert.Equal(t, uint32(2), stream.reassemblyQueue.nextMID, "next MID should stay advanced after read")
		assert.Equal(t, 0, stream.getNumBytesInReassemblyQueue(), "queue should be empty after read")
	})

	t.Run("unordered MID forward drops forwarded data and keeps newer complete message", func(t *testing.T) {
		stream := newTestStream(t)
		orgPpi := PayloadTypeWebRTCBinary

		complete := stream.reassemblyQueue.push(&chunkPayloadData{
			iData:             true,
			unordered:         true,
			messageIdentifier: 1,
			beginningFragment: true,
			endingFragment:    true,
			tsn:               10,
			streamIdentifier:  0,
			payloadType:       orgPpi,
			userData:          []byte("old"),
		})
		assert.True(t, complete, "MID 1 should be complete")

		complete = stream.reassemblyQueue.push(&chunkPayloadData{
			iData:             true,
			unordered:         true,
			messageIdentifier: 2,
			beginningFragment: true,
			tsn:               11,
			streamIdentifier:  0,
			payloadType:       orgPpi,
			userData:          []byte("drop"),
		})
		assert.False(t, complete, "MID 2 should remain incomplete")

		complete = stream.reassemblyQueue.push(&chunkPayloadData{
			iData:             true,
			unordered:         true,
			messageIdentifier: 4,
			beginningFragment: true,
			endingFragment:    true,
			tsn:               12,
			streamIdentifier:  0,
			payloadType:       orgPpi,
			userData:          []byte("keep"),
		})
		assert.True(t, complete, "MID 4 should be complete")

		complete = stream.reassemblyQueue.push(&chunkPayloadData{
			iData:             true,
			unordered:         true,
			messageIdentifier: 5,
			beginningFragment: true,
			tsn:               13,
			streamIdentifier:  0,
			payloadType:       orgPpi,
			userData:          []byte("later"),
		})
		assert.False(t, complete, "MID 5 should remain incomplete")

		stream.handleForwardTSNForUnorderedMID(2)

		if assert.Len(t, stream.reassemblyQueue.unorderedMID, 1, "only newer complete MID should remain queued") {
			assert.Equal(t, uint32(4), stream.reassemblyQueue.unorderedMID[0].mid, "unexpected queued MID")
		}
		if assert.Len(t, stream.reassemblyQueue.unorderedMIDMap, 1, "only newer incomplete MID should remain mapped") {
			_, ok := stream.reassemblyQueue.unorderedMIDMap[5]
			assert.True(t, ok, "MID 5 should remain mapped")
		}
		assert.True(t, stream.reassemblyQueue.isReadable(), "newer complete MID should stay readable")

		buf := make([]byte, 8)
		n, ppi, err := stream.ReadSCTP(buf)
		assert.NoError(t, err)
		assert.Equal(t, 4, n, "should read the kept MID")
		assert.Equal(t, orgPpi, ppi, "should preserve payload type")
		assert.Equal(t, "keep", string(buf[:n]), "unexpected payload")
		assert.Equal(t, 5, stream.getNumBytesInReassemblyQueue(), "only the remaining incomplete MID bytes should remain")
		assert.False(t, stream.reassemblyQueue.isReadable(), "only an incomplete MID should remain")
	})
}

func TestStreamPacketizeInterleavingMIDAllocation(t *testing.T) {
	stream := newTestPacketizingStream(t, true, 3)
	stream.unordered = true

	unorderedChunks, unordered := stream.packetize([]byte("abcdef"), PayloadTypeWebRTCBinary)
	assert.True(t, unordered)
	if assert.Len(t, unorderedChunks, 2) {
		assert.True(t, unorderedChunks[0].beginningFragment)
		assert.False(t, unorderedChunks[0].endingFragment)
		assert.False(t, unorderedChunks[1].beginningFragment)
		assert.True(t, unorderedChunks[1].endingFragment)

		for i, chunk := range unorderedChunks {
			assert.True(t, chunk.iData)
			assert.True(t, chunk.unordered)
			assert.Equal(t, uint32(0), chunk.messageIdentifier)
			assert.Equal(t, uint32(i), chunk.fragmentSequenceNumber)
			assert.Equal(t, uint16(0), chunk.streamSequenceNumber)
		}
	}

	secondUnorderedChunks, unordered := stream.packetize([]byte("xy"), PayloadTypeWebRTCBinary)
	assert.True(t, unordered)
	if assert.Len(t, secondUnorderedChunks, 1) {
		assert.True(t, secondUnorderedChunks[0].iData)
		assert.True(t, secondUnorderedChunks[0].unordered)
		assert.Equal(t, uint32(1), secondUnorderedChunks[0].messageIdentifier)
		assert.Equal(t, uint16(1), secondUnorderedChunks[0].streamSequenceNumber)
	}

	orderedChunks, unordered := stream.packetize([]byte("hi"), PayloadTypeWebRTCDCEP)
	assert.False(t, unordered)
	if assert.Len(t, orderedChunks, 1) {
		assert.True(t, orderedChunks[0].iData)
		assert.False(t, orderedChunks[0].unordered)
		assert.Equal(t, uint32(0), orderedChunks[0].messageIdentifier)
		assert.Equal(t, uint16(0), orderedChunks[0].streamSequenceNumber)
	}

	secondOrderedChunks, unordered := stream.packetize([]byte("ok"), PayloadTypeWebRTCDCEP)
	assert.False(t, unordered)
	if assert.Len(t, secondOrderedChunks, 1) {
		assert.True(t, secondOrderedChunks[0].iData)
		assert.False(t, secondOrderedChunks[0].unordered)
		assert.Equal(t, uint32(1), secondOrderedChunks[0].messageIdentifier)
		assert.Equal(t, uint16(1), secondOrderedChunks[0].streamSequenceNumber)
	}

	assert.Equal(t, uint16(0), stream.sequenceNumber, "interleaving should not advance SSN")
	assert.Equal(t, uint32(2), stream.nextOrderedMID, "ordered MID counter mismatch")
	assert.Equal(t, uint32(2), stream.nextUnorderedMID, "unordered MID counter mismatch")
}

func TestStreamWriteSCTPRollsBackInterleavingMIDsOnSendError(t *testing.T) {
	testCases := []struct {
		name      string
		ppi       PayloadProtocolIdentifier
		unordered bool
	}{
		{
			name:      "ordered",
			ppi:       PayloadTypeWebRTCDCEP,
			unordered: true,
		},
		{
			name:      "unordered",
			ppi:       PayloadTypeWebRTCBinary,
			unordered: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestPacketizingStream(t, true, 1200)
			s.unordered = tc.unordered

			n, err := s.WriteSCTP([]byte("test"), tc.ppi)
			assert.ErrorIs(t, err, ErrPayloadDataStateNotExist)
			assert.Equal(t, 0, n, "failed write should not report sent bytes")
			assert.Equal(t, uint16(0), s.sequenceNumber)
			assert.Equal(t, uint32(0), s.nextOrderedMID)
			assert.Equal(t, uint32(0), s.nextUnorderedMID)
			assert.Equal(t, uint64(0), s.BufferedAmount())
		})
	}
}
