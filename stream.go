package sctp

import (
	"math"
	"sync"

	"github.com/pkg/errors"
)

const (
	// ReliabilityTypeReliable is used for reliable transmission
	ReliabilityTypeReliable byte = 0
	// ReliabilityTypeRexmit is used for partial reliability by retransmission count
	ReliabilityTypeRexmit byte = 1
	// ReliabilityTypeTimed is used for partial reliability by retransmission duration
	ReliabilityTypeTimed byte = 2
)

// Stream represents an SCTP stream
type Stream struct {
	association *Association

	lock sync.RWMutex

	streamIdentifier   uint16
	defaultPayloadType PayloadProtocolIdentifier

	reassemblyQueue *reassemblyQueue
	sequenceNumber  uint16

	readNotifier *sync.Cond

	readErr  error
	writeErr error

	unordered        bool
	reliabilityType  byte
	reliabilityValue uint32
}

// StreamIdentifier returns the Stream identifier associated to the stream.
func (s *Stream) StreamIdentifier() uint16 {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.streamIdentifier
}

// SetDefaultPayloadType sets the default payload type used by Write.
func (s *Stream) SetDefaultPayloadType(defaultPayloadType PayloadProtocolIdentifier) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.setDefaultPayloadType(defaultPayloadType)
}

// setDefaultPayloadType sets the defaultPayloadType. The caller should hold the lock.
func (s *Stream) setDefaultPayloadType(defaultPayloadType PayloadProtocolIdentifier) {
	s.defaultPayloadType = defaultPayloadType
}

// SetReliabilityParams sets reliability parameters for this stream.
func (s *Stream) SetReliabilityParams(unordered bool, relType byte, relVal uint32) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.setReliabilityParams(unordered, relType, relVal)
}

// setReliabilityParams sets reliability parameters for this stream.
// The caller should hold the lock.
func (s *Stream) setReliabilityParams(unordered bool, relType byte, relVal uint32) {
	s.unordered = unordered
	s.reliabilityType = relType
	s.reliabilityValue = relVal
}

// Read reads a packet of len(p) bytes, dropping the Payload Protocol Identifier.
// Returns EOF when the stream is reset or an error if the stream is closed
// otherwise.
func (s *Stream) Read(p []byte) (int, error) {
	n, _, err := s.ReadSCTP(p)
	return n, err
}

// ReadSCTP reads a packet of len(p) bytes and returns the associated Payload Protocol Identifier.
// Returns EOF when the stream is reset or an error if the stream is closed
// otherwise.
func (s *Stream) ReadSCTP(p []byte) (int, PayloadProtocolIdentifier, error) {
	for {
		s.lock.Lock()
		n, ppi, err := s.reassemblyQueue.read(p)
		s.lock.Unlock()
		if err == nil {
			return n, ppi, nil
		}

		s.lock.RLock()
		err = s.readErr
		if err != nil {
			s.lock.RUnlock()
			return 0, PayloadProtocolIdentifier(0), err
		}

		notifier := s.readNotifier
		s.lock.RUnlock()
		// Wait for read notification
		if notifier != nil {
			notifier.L.Lock()
			notifier.Wait()
			notifier.L.Unlock()
		}
	}
}

func (s *Stream) handleData(pd *chunkPayloadData) {
	var readable bool
	s.lock.Lock()
	//fmt.Printf("stream[%d]: handleData ts=%d ssn=%d\n", s.streamIdentifier, pd.tsn, pd.streamSequenceNumber)
	if s.reassemblyQueue.push(pd) {
		readable = s.reassemblyQueue.isReadable()
	}
	//fmt.Printf("stream[%d]: handleData readable? %v\n", s.streamIdentifier, readable)
	s.lock.Unlock()

	// Notify the reader asynchronously if there's a data chunk to read.
	if readable {
		s.readNotifier.Signal()
	}
}

func (s *Stream) handleForwardTSN(newCumulativeTSN uint32, ssn uint16) {
	var readable bool
	s.lock.Lock()
	// Remove all chunks older than or equal to the new TSN from
	// the reassemblyQueue.
	//fmt.Printf("stream[%d]: handleForwardTSN newTSN=%d ssn=%d\n", s.streamIdentifier, newCumulativeTSN, ssn)
	s.reassemblyQueue.forwardTSN(newCumulativeTSN, s.unordered, ssn)
	readable = s.reassemblyQueue.isReadable()
	//fmt.Printf("stream[%d]: handleForwardTSN readable? %v\n", s.streamIdentifier, readable)
	s.lock.Unlock()

	// Notify the reader asynchronously if there's a data chunk to read.
	if readable {
		s.readNotifier.Signal()
	}
}

// Write writes len(p) bytes from p with the default Payload Protocol Identifier
func (s *Stream) Write(p []byte) (n int, err error) {
	return s.WriteSCTP(p, s.defaultPayloadType)
}

// WriteSCTP writes len(p) bytes from p to the DTLS connection
func (s *Stream) WriteSCTP(p []byte, ppi PayloadProtocolIdentifier) (n int, err error) {
	if len(p) > math.MaxUint16 {
		return 0, errors.Errorf("Outbound packet larger than maximum message size %v", math.MaxUint16)
	}

	s.lock.RLock()
	err = s.writeErr
	s.lock.RUnlock()
	if err != nil {
		return 0, err
	}

	chunks := s.packetize(p, ppi)

	return len(p), s.association.sendPayloadData(chunks)
}

func (s *Stream) packetize(raw []byte, ppi PayloadProtocolIdentifier) []*chunkPayloadData {
	s.lock.Lock()
	defer s.lock.Unlock()

	i := uint16(0)
	remaining := uint16(len(raw))

	// From draft-ietf-rtcweb-data-protocol-09, section 6:
	//   All Data Channel Establishment Protocol messages MUST be sent using
	//   ordered delivery and reliable transmission.
	unordered := ppi != PayloadTypeWebRTCDCEP && s.unordered

	var chunks []*chunkPayloadData
	for remaining != 0 {
		fragmentSize := min(s.association.myMaxMTU, remaining)

		// Copy the userdata since we'll have to store it until acked
		// and the caller may re-use the buffer in the mean time
		userData := make([]byte, fragmentSize)
		copy(userData, raw[i:i+fragmentSize])

		chunk := &chunkPayloadData{
			streamIdentifier:     s.streamIdentifier,
			userData:             userData,
			unordered:            unordered,
			beginningFragment:    i == 0,
			endingFragment:       remaining-fragmentSize == 0,
			immediateSack:        false,
			payloadType:          ppi,
			streamSequenceNumber: s.sequenceNumber,
		}

		chunks = append(chunks, chunk)

		remaining -= fragmentSize
		i += fragmentSize
	}

	// RFC 4960 Sec 6.6
	// Note: When transmitting ordered and unordered data, an endpoint does
	// not increment its Stream Sequence Number when transmitting a DATA
	// chunk with U flag set to 1.
	if !unordered {
		s.sequenceNumber++
	}

	return chunks
}

// Close closes the write-direction of the stream.
// Future calls to Write are not permitted after calling Close.
func (s *Stream) Close() error {
	s.lock.Lock()
	if s.writeErr != nil {
		s.lock.Unlock()
		return nil // already closed
	}
	s.writeErr = errors.New("Stream closed")

	a := s.association
	sid := s.streamIdentifier
	s.lock.Unlock()

	// Reset the outgoing stream
	// https://tools.ietf.org/html/rfc6525
	return a.sendResetRequest(sid)
}
