// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"
)

// Create the crc32 table we'll use for the checksum.
var castagnoliTable = crc32.MakeTable(crc32.Castagnoli) // nolint:gochecknoglobals

// Allocate and zero this data once.
// We need to use it for the checksum and don't want to allocate/clear each time.
var fourZeroes [4]byte // nolint:gochecknoglobals

/*
Packet represents an SCTP packet, defined in https://www.rfc-editor.org/rfc/rfc9260.html#section-3.
An SCTP packet is composed of a common header and chunks.  A chunk
contains either control information or user data.

						SCTP Packet Format
	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                        Common Header                          |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                          Chunk #1                             |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                           ...                                 |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                          Chunk #n                             |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

					SCTP Common Header Format
	 0                   1                   2                   3
	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|     Source Port Number       |     Destination Port Number    |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                      Verification Tag                         |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                           Checksum                            |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type packet struct {
	sourcePort      uint16
	destinationPort uint16
	verificationTag uint32
	chunks          []chunk
}

const (
	packetHeaderSize = 12
)

// SCTP packet errors.
var (
	ErrPacketRawTooSmall           = errors.New("raw is smaller than the minimum length for a SCTP packet")
	ErrParseSCTPChunkNotEnoughData = errors.New("unable to parse SCTP chunk, not enough data for complete header")
	ErrUnmarshalUnknownChunkType   = errors.New("failed to unmarshal, contains unknown chunk type")
	ErrChecksumMismatch            = errors.New("checksum mismatch theirs")
)

// unmarshal parses an SCTP packet and verifies its checksum.
//
// With requireChecksum set, the packet must have a valid CRC32c (RFC 9260 section 6.8).
// The caller may clear requireChecksum if it advertised Zero Checksum Acceptable
// and the path uses the advertised error detection method (RFC 9653 section 5.3).
// Nonzero checksums and packets starting with INIT or COOKIE ECHO are always verified.
func (p *packet) unmarshal(requireChecksum bool, raw []byte) error { //nolint:cyclop
	if len(raw) < packetHeaderSize {
		return fmt.Errorf("%w: raw only %d bytes, %d is the minimum length", ErrPacketRawTooSmall, len(raw), packetHeaderSize)
	}

	offset := packetHeaderSize

	// INIT and COOKIE ECHO come first in their packets. SCTP AUTH is unsupported.
	if !requireChecksum && offset+chunkHeaderSize <= len(raw) {
		switch chunkType(raw[offset]) {
		case ctInit, ctCookieEcho:
			requireChecksum = true
		default:
		}
	}

	theirChecksum := binary.LittleEndian.Uint32(raw[8:])
	if theirChecksum != 0 || requireChecksum {
		ourChecksum := generatePacketChecksum(raw)
		if theirChecksum != ourChecksum {
			return fmt.Errorf("%w: %d ours: %d", ErrChecksumMismatch, theirChecksum, ourChecksum)
		}
	}

	p.sourcePort = binary.BigEndian.Uint16(raw[0:])
	p.destinationPort = binary.BigEndian.Uint16(raw[2:])
	p.verificationTag = binary.BigEndian.Uint32(raw[4:])

	for offset < len(raw) {
		// guaranteed to be safe by loop condition
		remaining := raw[offset:] // nolint:gosec

		// must have at least a full chunk header to continue.
		if len(remaining) < chunkHeaderSize {
			return fmt.Errorf("%w: offset %d remaining %d", ErrParseSCTPChunkNotEnoughData, offset, len(remaining))
		}

		ctype := chunkType(remaining[0])

		var dataChunk chunk
		switch ctype {
		case ctInit:
			dataChunk = &chunkInit{}
		case ctInitAck:
			dataChunk = &chunkInitAck{}
		case ctAbort:
			dataChunk = &chunkAbort{}
		case ctCookieEcho:
			dataChunk = &chunkCookieEcho{}
		case ctCookieAck:
			dataChunk = &chunkCookieAck{}
		case ctHeartbeat:
			dataChunk = &chunkHeartbeat{}
		case ctPayloadData:
			dataChunk = &chunkPayloadData{}
		case ctIData:
			dataChunk = &chunkPayloadData{}
		case ctSack:
			dataChunk = &chunkSelectiveAck{}
		case ctReconfig:
			dataChunk = &chunkReconfig{}
		case ctForwardTSN:
			dataChunk = &chunkForwardTSN{}
		case ctIForwardTSN:
			dataChunk = &chunkIForwardTSN{}
		case ctError:
			dataChunk = &chunkError{}
		case ctShutdown:
			dataChunk = &chunkShutdown{}
		case ctShutdownAck:
			dataChunk = &chunkShutdownAck{}
		case ctShutdownComplete:
			dataChunk = &chunkShutdownComplete{}
		default:
			return fmt.Errorf("%w: %s", ErrUnmarshalUnknownChunkType, ctype.String())
		}

		if err := dataChunk.unmarshal(remaining); err != nil {
			return err
		}

		p.chunks = append(p.chunks, dataChunk)
		chunkValuePadding := getPadding(dataChunk.valueLength())
		offset += chunkHeaderSize + dataChunk.valueLength() + chunkValuePadding
	}

	// if we overshot then should error.
	if offset != len(raw) {
		if offset > len(raw) {
			overshoot := offset - len(raw)

			return fmt.Errorf("%w: parsed past end of buffer by %d bytes (offset %d, length %d)",
				ErrParseSCTPChunkNotEnoughData, overshoot, offset, len(raw))
		}

		remaining := len(raw) - offset

		return fmt.Errorf("%w: unparsed data remaining: %d bytes (offset %d, length %d)",
			ErrParseSCTPChunkNotEnoughData, remaining, offset, len(raw))
	}

	return nil
}

// marshal builds an SCTP packet.
//
// The caller may clear requireChecksum for a peer that advertised Zero Checksum
// Acceptable when the path uses the advertised error detection method. Packets
// containing INIT or COOKIE ECHO always carry a computed CRC32c (RFC 9653 section 5.2).
func (p *packet) marshal(requireChecksum bool) ([]byte, error) {
	raw := make([]byte, packetHeaderSize)

	// Populate static headers
	// 8-12 is Checksum which will be populated when packet is complete
	binary.BigEndian.PutUint16(raw[0:], p.sourcePort)
	binary.BigEndian.PutUint16(raw[2:], p.destinationPort)
	binary.BigEndian.PutUint32(raw[4:], p.verificationTag)

	// Populate chunks
	for _, c := range p.chunks {
		chunkRaw, err := c.marshal()
		if err != nil {
			return nil, err
		}
		raw = append(raw, chunkRaw...) //nolint:makezero // todo:fix

		paddingNeeded := getPadding(len(raw))
		if paddingNeeded != 0 {
			raw = append(raw, make([]byte, paddingNeeded)...) //nolint:makezero // todo:fix
		}
	}

	if requireChecksum || chunkMandatoryChecksum(p.chunks) {
		// Go's reflected CRC32c is written in little-endian SCTP wire order.
		binary.LittleEndian.PutUint32(raw[8:], generatePacketChecksum(raw))
	}

	return raw, nil
}

func chunkMandatoryChecksum(chunks []chunk) bool {
	for _, c := range chunks {
		switch c.(type) {
		case *chunkInit, *chunkCookieEcho:
			return true
		}
	}

	return false
}

func generatePacketChecksum(raw []byte) (sum uint32) {
	// Fastest way to do a crc32 without allocating.
	sum = crc32.Update(sum, castagnoliTable, raw[0:8])
	sum = crc32.Update(sum, castagnoliTable, fourZeroes[:])
	sum = crc32.Update(sum, castagnoliTable, raw[12:])

	return sum
}

// String makes packet printable.
func (p *packet) String() string {
	format := `Packet:
	sourcePort: %d
	destinationPort: %d
	verificationTag: %d
	`
	var res strings.Builder
	fmt.Fprintf(&res, format,
		p.sourcePort,
		p.destinationPort,
		p.verificationTag,
	)
	for i, chunk := range p.chunks {
		fmt.Fprintf(&res, "Chunk %d:\n %s", i, chunk)
	}

	return res.String()
}

// TryMarshalUnmarshal attempts to marshal and unmarshal a message. Added for fuzzing.
func TryMarshalUnmarshal(msg []byte) int {
	p := &packet{}
	err := p.unmarshal(true, msg)
	if err != nil {
		return 0
	}

	_, err = p.marshal(true)
	if err != nil {
		return 0
	}

	return 1
}
