// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
)

// Create the crc32 table we'll use for the checksum.
var castagnoliTable = crc32.MakeTable(crc32.Castagnoli) // nolint:gochecknoglobals

// Allocate and zero this data once.
// We need to use it for the checksum and don't want to allocate/clear each time.
var fourZeroes [4]byte // nolint:gochecknoglobals

/*
Packet represents an SCTP packet, defined in https://tools.ietf.org/html/rfc9260#section-3
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
// RFC 9260 section 6.8: every packet MUST be protected with CRC32c; receivers verify it.
// RFC 9653 adds an extension (ZCA) that allows a receiver to accept a packet
// whose checksum is incorrect but equal to zero, when an alternate error
// detection method is active for the path (ex: SCTP-over-DTLS) and ZCA has
// been negotiated.
//
// doChecksum indicates whether ZCA is active for the *receiving path*:
//   - doChecksum == true  : accept a packet if the only checksum issue is that
//     it is exactly zero (ZCA + path constraints satisfied).
//   - doChecksum == false : strict 9260 verification; any checksum mismatch fails.
//
// Higher layers MUST only pass doChecksum=true if the peer advertised ZCA
// in INIT/INIT-ACK and the current path meets the method’s constraints
// (ex: DTLS). This function does not relax sender-side rules: packets that
// contain INIT or COOKIE ECHO MUST still carry a correct CRC32c (enforced in marshal()).
//
// See RFC 9653 section 5.1 and section 5.3.
func (p *packet) unmarshal(doChecksum bool, raw []byte) error { //nolint:cyclop
	if len(raw) < packetHeaderSize {
		return fmt.Errorf("%w: raw only %d bytes, %d is the minimum length", ErrPacketRawTooSmall, len(raw), packetHeaderSize)
	}

	offset := packetHeaderSize

	// always compute CRC32c (RFC 9260 section 6.8).
	theirChecksum := binary.LittleEndian.Uint32(raw[8:])
	ourChecksum := generatePacketChecksum(raw)
	if theirChecksum != ourChecksum {
		// RFC 9653: if (a) checksum is zero and (b) caller indicates ZCA is active
		// and method constraints are met, accept; otherwise error.
		if !doChecksum || theirChecksum != 0 {
			return fmt.Errorf("%w: %d ours: %d", ErrChecksumMismatch, theirChecksum, ourChecksum)
		}
	}

	p.sourcePort = binary.BigEndian.Uint16(raw[0:])
	p.destinationPort = binary.BigEndian.Uint16(raw[2:])
	p.verificationTag = binary.BigEndian.Uint32(raw[4:])

	for {
		// Exact match, no more chunks
		if offset == len(raw) {
			break
		} else if offset+chunkHeaderSize > len(raw) {
			return fmt.Errorf("%w: offset %d remaining %d", ErrParseSCTPChunkNotEnoughData, offset, len(raw))
		}

		var dataChunk chunk
		switch chunkType(raw[offset]) {
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
		case ctSack:
			dataChunk = &chunkSelectiveAck{}
		case ctReconfig:
			dataChunk = &chunkReconfig{}
		case ctForwardTSN:
			dataChunk = &chunkForwardTSN{}
		case ctError:
			dataChunk = &chunkError{}
		case ctShutdown:
			dataChunk = &chunkShutdown{}
		case ctShutdownAck:
			dataChunk = &chunkShutdownAck{}
		case ctShutdownComplete:
			dataChunk = &chunkShutdownComplete{}
		default:
			return fmt.Errorf("%w: %s", ErrUnmarshalUnknownChunkType, chunkType(raw[offset]).String())
		}

		if err := dataChunk.unmarshal(raw[offset:]); err != nil {
			return err
		}

		p.chunks = append(p.chunks, dataChunk)
		chunkValuePadding := getPadding(dataChunk.valueLength())
		offset += chunkHeaderSize + dataChunk.valueLength() + chunkValuePadding
	}

	return nil
}

// marshal builds an SCTP packet.
//
// If doChecksum == true, a zero checksum is written (RFC 9653) unless
// the packet contains a restricted chunk (INIT or COOKIE ECHO), in which case
// a correct CRC32c is always written (RFC 9653 section 5.2). If doChecksum == false,
// a correct CRC32c is always written (RFC 9260 section 6.8).
//
// The caller sets doChecksum=true only when the peer has advertised ZCA and
// the current path satisfies the alternate method’s constraints (e.g., DTLS).
// For OOTB responses and other control paths, always marshal with doChecksum=false.
func (p *packet) marshal(doChecksum bool) ([]byte, error) {
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

	if doChecksum && !hasRestrictedChunk(p.chunks) {
		binary.LittleEndian.PutUint32(raw[8:], 0)
	} else {
		binary.LittleEndian.PutUint32(raw[8:], generatePacketChecksum(raw))
	}

	return raw, nil
}

// restrictedChunks per RFC 9653 section 5.2: INIT and COOKIE ECHO.
func hasRestrictedChunk(chs []chunk) bool {
	for _, c := range chs {
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
	res := fmt.Sprintf(format,
		p.sourcePort,
		p.destinationPort,
		p.verificationTag,
	)
	for i, chunk := range p.chunks {
		res += fmt.Sprintf("Chunk %d:\n %s", i, chunk)
	}

	return res
}

// TryMarshalUnmarshal attempts to marshal and unmarshal a message. Added for fuzzing.
func TryMarshalUnmarshal(msg []byte) int {
	p := &packet{}
	// Strict mode first (RFC 9260): require valid CRC32c.
	err := p.unmarshal(false, msg)
	if err != nil {
		return 0
	}

	// Strict send (emit CRC32c).
	_, err = p.marshal(false)
	if err != nil {
		return 0
	}

	return 1
}
