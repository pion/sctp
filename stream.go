package sctp

import (
	"io"
	"math"
	"sync"

	"github.com/pkg/errors"
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
		userData, ppi, ok := s.reassemblyQueue.pop() // TODO: pop into p?
		s.lock.Unlock()
		if ok {
			n := copy(p, userData)
			if n < len(userData) {
				return n, ppi, io.ErrShortBuffer
			}
			return n, ppi, nil
		}

		s.lock.RLock()
		err := s.readErr
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
	s.lock.Lock()
	s.reassemblyQueue.push(pd)
	s.lock.Unlock()

	// Notify the reader asynchronously
	s.readNotifier.Signal()
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

	var chunks []*chunkPayloadData
	for remaining != 0 {
		l := min(s.association.myMaxMTU, remaining)
		chunks = append(chunks, &chunkPayloadData{
			streamIdentifier:     s.streamIdentifier,
			userData:             raw[i : i+l],
			beginingFragment:     i == 0,
			endingFragment:       remaining-l == 0,
			immediateSack:        false,
			payloadType:          ppi,
			streamSequenceNumber: s.sequenceNumber,
		})
		remaining -= l
		i += l
	}

	s.sequenceNumber++

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
