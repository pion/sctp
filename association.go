package sctp

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/pkg/errors"
)

const receiveMTU = 8192

var errAssociationClosed = errors.New("The association is closed")

// associationState is an enum for the states that an Association will transition
// through while connecting
// https://tools.ietf.org/html/rfc4960#section-13.2
type associationState uint8

// associationState enums
const (
	closed associationState = iota + 1
	cookieEchoed
	cookieWait
	established
	shutdownAckSent
	shutdownPending
	shutdownReceived
	shutdownSent
)

// retransmission timer IDs
const (
	timerT1Init int = iota
	timerT1Cookie
	timerT3RTX
)

func (a associationState) String() string {
	switch a {
	case closed:
		return "Closed"
	case cookieEchoed:
		return "CookieEchoed"
	case cookieWait:
		return "CookieWait"
	case established:
		return "Established"
	case shutdownPending:
		return "ShutdownPending"
	case shutdownSent:
		return "ShutdownSent"
	case shutdownReceived:
		return "ShutdownReceived"
	case shutdownAckSent:
		return "ShutdownAckSent"
	default:
		return fmt.Sprintf("Invalid associationState %d", a)
	}
}

// Association represents an SCTP association
// 13.2.  Parameters Necessary per Association (i.e., the TCB)
// Peer        : Tag value to be sent in every packet and is received
// Verification: in the INIT or INIT ACK chunk.
// Tag         :
//
// My          : Tag expected in every inbound packet and sent in the
// Verification: INIT or INIT ACK chunk.
//
// Tag         :
// State       : A state variable indicating what state the association
//             : is in, i.e., COOKIE-WAIT, COOKIE-ECHOED, ESTABLISHED,
//             : SHUTDOWN-PENDING, SHUTDOWN-SENT, SHUTDOWN-RECEIVED,
//             : SHUTDOWN-ACK-SENT.
//
//               Note: No "CLOSED" state is illustrated since if a
//               association is "CLOSED" its TCB SHOULD be removed.
type Association struct {
	lock sync.RWMutex

	netConn net.Conn

	peerVerificationTag uint32
	myVerificationTag   uint32
	state               associationState
	//peerTransportList
	//primaryPath
	//overallErrorCount
	//overallErrorThreshold
	//peerReceiverWindow (peerRwnd)
	myNextTSN   uint32 // nextTSN
	peerLastTSN uint32 // lastRcvdTSN
	//peerMissingTSN (MappingArray)
	//ackState
	//inboundStreams
	//outboundStreams
	//localTransportAddressList
	//associationPTMU

	// Reconfig
	ongoingReconfigOutgoing *chunkReconfig // TODO: Re-transmission
	ongoingResetRequest     *paramOutgoingResetRequest
	myNextRSN               uint32

	// Non-RFC internal data
	sourcePort              uint16
	destinationPort         uint16
	myMaxNumInboundStreams  uint16
	myMaxNumOutboundStreams uint16
	myReceiverWindowCredit  uint32
	myCookie                *paramStateCookie
	payloadQueue            *payloadQueue
	inflightQueue           *payloadQueue
	myMaxMTU                uint16
	cumulativeTSNAckPoint   uint32
	advancedPeerTSNAckPoint uint32
	useForwardTSN           bool

	// RTX timer
	rtoMgr   *rtoManager
	t1Init   *rtxTimer
	t1Cookie *rtxTimer
	t3RTX    *rtxTimer

	// Chunks stored for retransmission
	storedInit       *chunkInit
	storedCookieEcho *chunkCookieEcho

	streams              map[uint16]*Stream
	acceptCh             chan *Stream
	closeCh              chan struct{}
	handshakeCompletedCh chan error
}

// Server accepts a SCTP stream over a conn
func Server(netConn net.Conn) (*Association, error) {
	a := createAssocation(netConn)
	go a.readLoop()

	select {
	case err := <-a.handshakeCompletedCh:
		if err != nil {
			return nil, err
		}
		return a, nil
	case <-a.closeCh:
		return nil, errors.Errorf("Assocation closed before connecting")
	}
}

// Client opens a SCTP stream over a conn
func Client(netConn net.Conn) (*Association, error) {
	a := createAssocation(netConn)
	go a.readLoop()
	a.init()

	select {
	case err := <-a.handshakeCompletedCh:
		if err != nil {
			return nil, err
		}
		return a, nil
	case <-a.closeCh:
		return nil, errors.Errorf("Assocation closed before connecting")
	}
}

func createAssocation(netConn net.Conn) *Association {
	rs := rand.NewSource(time.Now().UnixNano())
	r := rand.New(rs)

	tsn := r.Uint32()
	a := &Association{
		netConn:                 netConn,
		myMaxNumOutboundStreams: math.MaxUint16,
		myMaxNumInboundStreams:  math.MaxUint16,
		myReceiverWindowCredit:  10 * 1500, // 10 Max MTU packets buffer
		payloadQueue:            &payloadQueue{},
		inflightQueue:           &payloadQueue{},
		myMaxMTU:                1200,
		myVerificationTag:       r.Uint32(),
		myNextTSN:               tsn,
		myNextRSN:               tsn,
		state:                   closed,
		rtoMgr:                  newRTOManager(),
		streams:                 make(map[uint16]*Stream),
		acceptCh:                make(chan *Stream),
		closeCh:                 make(chan struct{}),
		handshakeCompletedCh:    make(chan error),
		cumulativeTSNAckPoint:   tsn - 1,
		advancedPeerTSNAckPoint: tsn - 1,
	}

	a.t1Init = newRTXTimer(timerT1Init, a, maxInitRetrans)
	a.t1Cookie = newRTXTimer(timerT1Cookie, a, maxInitRetrans)
	a.t3RTX = newRTXTimer(timerT3RTX, a, pathMaxRetrans)

	return a
}

func (a *Association) init() {
	a.lock.Lock()
	defer a.lock.Unlock()

	init := &chunkInit{}
	init.initialTSN = a.myNextTSN
	init.numOutboundStreams = a.myMaxNumOutboundStreams
	init.numInboundStreams = a.myMaxNumInboundStreams
	init.initiateTag = a.myVerificationTag
	init.advertisedReceiverWindowCredit = a.myReceiverWindowCredit
	setSupportedExtensions(&init.chunkInitCommon)
	a.storedInit = init

	err := a.sendInit()
	if err != nil {
		// TODO: use logging
		fmt.Printf("Failed to send init: %v\n", err)
	}

	//fmt.Println("starting T1-init timer")
	a.t1Init.start(a.rtoMgr.getRTO())

	a.setState(cookieWait)

}

// caller must hold a.lock
func (a *Association) sendInit() error {
	//fmt.Println("sending Init")

	if a.storedInit == nil {
		return fmt.Errorf("INIT not stored to send")
	}

	outbound := &packet{}
	outbound.verificationTag = a.peerVerificationTag
	a.sourcePort = 5000      // TODO: Spec??
	a.destinationPort = 5000 // TODO: Spec??
	outbound.sourcePort = a.sourcePort
	outbound.destinationPort = a.destinationPort

	outbound.chunks = []chunk{a.storedInit}

	a.lock.Unlock()
	err := a.send(outbound)
	a.lock.Lock()

	return err
}

// caller must hold a.lock
func (a *Association) sendCookieEcho() error {
	if a.storedCookieEcho == nil {
		return fmt.Errorf("cookieEcho not stored to send")
	}

	//fmt.Println("sending CookieEcho")

	outbound := &packet{}
	outbound.verificationTag = a.peerVerificationTag
	outbound.sourcePort = a.sourcePort
	outbound.destinationPort = a.destinationPort
	outbound.chunks = []chunk{a.storedCookieEcho}

	a.lock.Unlock()
	err := a.send(outbound)
	a.lock.Lock()

	return err
}

// Close ends the SCTP Association and cleans up any state
func (a *Association) Close() error {
	err := a.netConn.Close()
	if err != nil {
		return err
	}

	// Stop all retransmission timers
	a.t1Init.stop()
	a.t1Cookie.stop()
	a.t3RTX.stop()

	// Wait for readLoop to end
	<-a.closeCh

	return nil
}

func (a *Association) readLoop() {
	defer func() {
		a.lock.Lock()
		closeErr := errors.New("association closed")
		for _, s := range a.streams {
			a.unregisterStream(s, closeErr)
		}
		a.lock.Unlock()
		close(a.acceptCh)
		a.closeCh <- struct{}{}
	}()
	for {
		// buffer is recreated because the user data is
		// passed to the reassembly queue without copying
		buffer := make([]byte, receiveMTU)

		n, err := a.netConn.Read(buffer)
		if err != nil {
			return
		}

		if err = a.handleInbound(buffer[:n]); err != nil {
			fmt.Println(errors.Wrap(err, "Failed to push SCTP packet"))
		}
	}
}

// unregisterStream un-registers a stream from the association
// The caller should hold the association write lock.
func (a *Association) unregisterStream(s *Stream, err error) {
	s.lock.Lock()
	delete(a.streams, s.streamIdentifier)
	s.readErr = err
	n := s.readNotifier
	s.readNotifier = nil
	s.lock.Unlock()
	n.Broadcast()
}

// HandleInbound parses incoming raw packets
func (a *Association) handleInbound(raw []byte) error {
	p := &packet{}
	if err := p.unmarshal(raw); err != nil {
		return errors.Wrap(err, "Unable to parse SCTP packet")
	}

	if err := checkPacket(p); err != nil {
		return errors.Wrap(err, "Failed validating packet")
	}

	for _, c := range p.chunks {
		packets, err := a.handleChunk(p, c)
		if err != nil {
			return errors.Wrap(err, "Failed handling chunk")
		}
		for _, p := range packets {
			err = a.send(p)
			if err != nil {
				return errors.Wrap(err, "Failed sending reply")
			}
		}
	}

	return nil
}

func checkPacket(p *packet) error {
	// All packets must adhere to these rules

	// This is the SCTP sender's port number.  It can be used by the
	// receiver in combination with the source IP address, the SCTP
	// destination port, and possibly the destination IP address to
	// identify the association to which this packet belongs.  The port
	// number 0 MUST NOT be used.
	if p.sourcePort == 0 {
		return errors.New("SCTP Packet must not have a source port of 0")
	}

	// This is the SCTP port number to which this packet is destined.
	// The receiving host will use this port number to de-multiplex the
	// SCTP packet to the correct receiving endpoint/application.  The
	// port number 0 MUST NOT be used.
	if p.destinationPort == 0 {
		return errors.New("SCTP Packet must not have a destination port of 0")
	}

	// Check values on the packet that are specific to a particular chunk type
	for _, c := range p.chunks {
		switch c.(type) {
		case *chunkInit:
			// An INIT or INIT ACK chunk MUST NOT be bundled with any other chunk.
			// They MUST be the only chunks present in the SCTP packets that carry
			// them.
			if len(p.chunks) != 1 {
				return errors.New("INIT chunk must not be bundled with any other chunk")
			}

			// A packet containing an INIT chunk MUST have a zero Verification
			// Tag.
			if p.verificationTag != 0 {
				return errors.Errorf("INIT chunk expects a verification tag of 0 on the packet when out-of-the-blue")
			}
		}
	}

	return nil
}

func min(a, b uint16) uint16 {
	if a < b {
		return a
	}
	return b
}

// setState sets the state of the Association.
func (a *Association) setState(state associationState) {
	if a.state != state {
		//fmt.Printf("[%s] state change: '%s' => '%s'\n", a.name(), a.state.String(), state.String())
		a.state = state
	}
}

func setSupportedExtensions(init *chunkInitCommon) {
	// TODO RFC5061 https://tools.ietf.org/html/rfc6525#section-5.2
	// An implementation supporting this (Supported Extensions Parameter)
	// extension MUST list the ASCONF, the ASCONF-ACK, and the AUTH chunks
	// in its INIT and INIT-ACK parameters.
	init.params = append(init.params, &paramSupportedExtensions{
		ChunkTypes: []chunkType{ctReconfig, ctForwardTSN},
	})
}

// The caller should hold the lock.
func (a *Association) handleInit(p *packet, i *chunkInit) *packet {
	// Should we be setting any of these permanently until we've ACKed further?
	a.myMaxNumInboundStreams = min(i.numInboundStreams, a.myMaxNumInboundStreams)
	a.myMaxNumOutboundStreams = min(i.numOutboundStreams, a.myMaxNumOutboundStreams)
	a.peerVerificationTag = i.initiateTag
	a.sourcePort = p.destinationPort
	a.destinationPort = p.sourcePort

	// 13.2 This is the last TSN received in sequence.  This value
	// is set initially by taking the peer's initial TSN,
	// received in the INIT or INIT ACK chunk, and
	// subtracting one from it.
	a.peerLastTSN = i.initialTSN - 1

	outbound := &packet{}
	outbound.verificationTag = a.peerVerificationTag
	outbound.sourcePort = a.sourcePort
	outbound.destinationPort = a.destinationPort

	initAck := &chunkInitAck{}

	initAck.initialTSN = a.myNextTSN
	initAck.numOutboundStreams = a.myMaxNumOutboundStreams
	initAck.numInboundStreams = a.myMaxNumInboundStreams
	initAck.initiateTag = a.myVerificationTag
	initAck.advertisedReceiverWindowCredit = a.myReceiverWindowCredit

	if a.myCookie == nil {
		a.myCookie = newRandomStateCookie()
	}

	initAck.params = []param{a.myCookie}

	setSupportedExtensions(&initAck.chunkInitCommon)

	outbound.chunks = []chunk{initAck}

	return outbound
}

// The caller should hold the lock.
func (a *Association) handleInitAck(p *packet, i *chunkInitAck) error {
	a.myMaxNumInboundStreams = min(i.numInboundStreams, a.myMaxNumInboundStreams)
	a.myMaxNumOutboundStreams = min(i.numOutboundStreams, a.myMaxNumOutboundStreams)
	a.peerVerificationTag = i.initiateTag
	a.peerLastTSN = i.initialTSN - 1
	if a.sourcePort != p.destinationPort ||
		a.destinationPort != p.sourcePort {
		fmt.Println("handleInitAck: port mismatch")
	}

	// stop T1-init timer
	a.t1Init.stop()
	a.storedInit = nil

	var cookieParam *paramStateCookie
	for _, param := range i.params {
		switch v := param.(type) {
		case *paramStateCookie:
			cookieParam = v
		case *paramSupportedExtensions:
			for _, t := range v.ChunkTypes {
				if t == ctForwardTSN {
					a.useForwardTSN = true
				}
			}
		}
	}
	if cookieParam == nil {
		return errors.New("no cookie in InitAck")
	}

	a.storedCookieEcho = &chunkCookieEcho{}
	a.storedCookieEcho.cookie = cookieParam.cookie

	err := a.sendCookieEcho()
	if err != nil {
		// TODO: use logging
		fmt.Printf("Failed to send init: %v\n", err)
	}

	// start t1-cookie timer
	a.t1Cookie.start(a.rtoMgr.getRTO())

	return nil
}

// The caller should hold the lock.
func (a *Association) handleData(d *chunkPayloadData) []*packet {
	added := a.payloadQueue.push(d, a.peerLastTSN)
	if added {
		// Pass the new chunk to stream level as soon as it arrives
		s := a.getOrCreateStream(d.streamIdentifier)
		s.handleData(d)
	}

	reply := make([]*packet, 0)

	// Try to advance peerLastTSN
	_, popOk := a.payloadQueue.pop(a.peerLastTSN + 1)
	for popOk {
		if a.ongoingResetRequest != nil &&
			sna32LT(a.ongoingResetRequest.senderLastTSN, a.peerLastTSN) {
			resp := a.resetStreams()
			if resp != nil {
				fmt.Printf("RESET RESPONSE: %+v\n", resp)
				reply = append(reply, resp)
			}
			break
		}

		a.peerLastTSN++
		_, popOk = a.payloadQueue.pop(a.peerLastTSN + 1)
	}

	outbound := &packet{}
	outbound.verificationTag = a.peerVerificationTag
	outbound.sourcePort = a.sourcePort
	outbound.destinationPort = a.destinationPort

	sack := &chunkSelectiveAck{}

	sack.cumulativeTSNAck = a.peerLastTSN
	sack.advertisedReceiverWindowCredit = a.myReceiverWindowCredit
	sack.duplicateTSN = a.payloadQueue.popDuplicates()
	sack.gapAckBlocks = a.payloadQueue.getGapAckBlocks(a.peerLastTSN)
	outbound.chunks = []chunk{sack}
	reply = append(reply, outbound)

	return reply
}

// OpenStream opens a stream
func (a *Association) OpenStream(streamIdentifier uint16, defaultPayloadType PayloadProtocolIdentifier) (*Stream, error) {
	a.lock.Lock()
	defer a.lock.Unlock()

	if _, ok := a.streams[streamIdentifier]; ok {
		return nil, fmt.Errorf("there already exists a stream with identifier %d", streamIdentifier)
	}

	s := a.createStream(streamIdentifier, false)
	s.setDefaultPayloadType(defaultPayloadType)

	return s, nil
}

// AcceptStream accepts a stream
func (a *Association) AcceptStream() (*Stream, error) {
	s, ok := <-a.acceptCh
	if !ok {
		return nil, errAssociationClosed
	}
	return s, nil
}

// createStream creates a stream. The caller should hold the lock and check no stream exists for this id.
func (a *Association) createStream(streamIdentifier uint16, accept bool) *Stream {
	s := &Stream{
		association:      a,
		streamIdentifier: streamIdentifier,
		reassemblyQueue:  newReassemblyQueue(streamIdentifier),
		readNotifier:     sync.NewCond(&sync.Mutex{}),
	}

	a.streams[streamIdentifier] = s

	if accept {
		a.acceptCh <- s
	}

	return s
}

// getOrCreateStream gets or creates a stream. The caller should hold the lock.
func (a *Association) getOrCreateStream(streamIdentifier uint16) *Stream {
	if s, ok := a.streams[streamIdentifier]; ok {
		return s
	}

	return a.createStream(streamIdentifier, true)
}

// The caller should hold the lock.
func (a *Association) handleSack(d *chunkSelectiveAck) ([]*packet, error) {
	// i) If Cumulative TSN Ack is less than the Cumulative TSN Ack
	// Point, then drop the SACK.  Since Cumulative TSN Ack is
	// monotonically increasing, a SACK whose Cumulative TSN Ack is
	// less than the Cumulative TSN Ack Point indicates an out-of-
	// order SACK.

	// This is an old SACK, toss
	if sna32GT(a.cumulativeTSNAckPoint, d.cumulativeTSNAck) {
		return nil, errors.Errorf("SACK Cumulative ACK %v is older than ACK point %v",
			d.cumulativeTSNAck, a.cumulativeTSNAckPoint)
	}

	// New ack point, so pop all ACKed packets from inflightQueue
	// We add 1 because the "currentAckPoint" has already been popped from the inflight queue
	// For the first SACK we take care of this by setting the ackpoint to cumAck - 1
	for i := a.cumulativeTSNAckPoint + 1; sna32LTE(i, d.cumulativeTSNAck); i++ {
		if _, ok := a.inflightQueue.pop(i); !ok {
			return nil, errors.Errorf("TSN %v unable to be popped from inflight queue", i)
		}
	}

	a.cumulativeTSNAckPoint = d.cumulativeTSNAck

	// Mark selectively acknowledged chunks as "acked"
	for _, g := range d.gapAckBlocks {
		for i := g.start; i <= g.end; i++ {
			c, ok := a.inflightQueue.get(d.cumulativeTSNAck + uint32(i))
			if !ok {
				return nil, errors.Errorf("Requested non-existent TSN %v", d.cumulativeTSNAck+uint32(i))
			}

			//fmt.Printf("tsn=%d has been sacked\n", c.tsn)
			c.acked = true
		}
	}

	packets := []*packet{}

	if a.useForwardTSN {
		// RFC 3758 Sec 3.5 C1
		if sna32LT(a.advancedPeerTSNAckPoint, a.cumulativeTSNAckPoint) {
			a.advancedPeerTSNAckPoint = a.cumulativeTSNAckPoint
		}

		// RFC 3758 Sec 3.5 C2
		for i := a.advancedPeerTSNAckPoint + 1; ; i++ {
			c, ok := a.inflightQueue.get(i)
			if !ok {
				break
			}
			if !c.abandoned {
				break
			}
			a.advancedPeerTSNAckPoint = i
		}

		// RFC 3758 Sec 3.5 C3
		var fwdtsn *chunkForwardTSN
		if sna32GT(a.advancedPeerTSNAckPoint, a.cumulativeTSNAckPoint) {
			fwdtsn = a.createForwardTSN()
		}

		if fwdtsn != nil {
			packets = append(packets, a.createPacket([]chunk{fwdtsn}))
		}
	}

	// TODO: this should be trigged by T3-rtx timer
	packets = append(packets, a.getPayloadDataToSend(false)...)
	return packets, nil
}

// createForwardTSN generates ForwardTSN chunk.
// This method will be be called if useForwardTSN is set to false.
func (a *Association) createForwardTSN() *chunkForwardTSN {
	// RFC 3758 Sec 3.5 C4
	streamMap := map[uint16]uint16{} // to report only once per SI
	for i := a.cumulativeTSNAckPoint + 1; sna32LTE(i, a.advancedPeerTSNAckPoint); i++ {
		c, ok := a.inflightQueue.get(i)
		if !ok {
			break
		}
		if c.acked {
			continue
		}

		//fmt.Printf("building fwdtsn: si=%d ssn=%d tsn=%d acked=%v\n", c.streamIdentifier, c.streamSequenceNumber, c.tsn, c.acked)
		ssn, ok := streamMap[c.streamIdentifier]
		if !ok {
			streamMap[c.streamIdentifier] = c.streamSequenceNumber
		} else {
			// to report only once with greatest SSN
			if sna16LT(ssn, c.streamSequenceNumber) {
				streamMap[c.streamIdentifier] = c.streamSequenceNumber
			}
		}
	}

	fwdtsn := &chunkForwardTSN{
		newCumulativeTSN: a.advancedPeerTSNAckPoint,
		streams:          []chunkForwardTSNStream{},
	}

	for si, ssn := range streamMap {
		fwdtsn.streams = append(fwdtsn.streams, chunkForwardTSNStream{
			identifier: si,
			sequence:   ssn,
		})
	}

	return fwdtsn
}

// createPacket wraps chunks in a packet.
// The caller should hold the read lock.
func (a *Association) createPacket(cs []chunk) *packet {
	return &packet{
		verificationTag: a.peerVerificationTag,
		sourcePort:      a.sourcePort,
		destinationPort: a.destinationPort,
		chunks:          cs,
	}
}

func (a *Association) handleReconfig(c *chunkReconfig) ([]*packet, error) {
	pp := make([]*packet, 0)

	p, err := a.handleReconfigParam(c.paramA)
	if err != nil {
		return nil, err
	}
	if p != nil {
		pp = append(pp, p)
	}

	if c.paramB != nil {
		p, err = a.handleReconfigParam(c.paramB)
		if err != nil {
			return nil, err
		}
		if p != nil {
			pp = append(pp, p)
		}
	}
	return pp, nil
}

func (a *Association) handleForwardTSN(c *chunkForwardTSN) []*packet {
	//fmt.Printf("handleForward: %s\n", c.String())

	if !a.useForwardTSN {
		// Return an error chunk
		cerr := &chunkError{
			errorCauses: []errorCause{&errorCauseUnrecognizedChunkType{}},
		}
		outbound := &packet{}
		outbound.verificationTag = a.peerVerificationTag
		outbound.sourcePort = a.sourcePort
		outbound.destinationPort = a.destinationPort
		outbound.chunks = []chunk{cerr}
		return []*packet{outbound}
	}

	// From RFC 3758 Sec 3.6:
	//   the receiver MUST perform the same TSN handling, including duplicate
	//   detection, gap detection, SACK generation, cumulative TSN
	//   advancement, etc. as defined in RFC 2960 [2]---with the following
	//   exceptions and additions.

	//   When a FORWARD TSN chunk arrives, the data receiver MUST first update
	//   its cumulative TSN point to the value carried in the FORWARD TSN
	//   chunk,

	// Advance peerLastTSN
	for sna32LT(a.peerLastTSN, c.newCumulativeTSN) {
		a.payloadQueue.pop(a.peerLastTSN + 1) // may not exist
		a.peerLastTSN++
	}

	// From RFC 3758 Sec 3.6:
	//   .. and then MUST further advance its cumulative TSN point locally
	//   if possible
	// Meaning, if peerLastTSN+1 points to a chunk that is received,
	// advance peerLastTSN until peerLastTSN+1 points to unreceived chunk.
	for {
		if _, popOk := a.payloadQueue.pop(a.peerLastTSN + 1); !popOk {
			break
		}
		a.peerLastTSN++
	}

	// Report new peerLastTSN value and abandoned largest SSN value to
	// corresponding streams so that the abandoned chunks can be removed
	// from the reassemblyQueue.
	for _, forwarded := range c.streams {
		if s, ok := a.streams[forwarded.identifier]; ok {
			s.handleForwardTSN(c.newCumulativeTSN, forwarded.sequence)
		}
	}

	// From RFC 3758 Sec 3.6:
	//   Note, if the "New Cumulative TSN" value carried in the arrived
	//   FORWARD TSN chunk is found to be behind or at the current cumulative
	//   TSN point, the data receiver MUST treat this FORWARD TSN as out-of-
	//   date and MUST NOT update its Cumulative TSN.  The receiver SHOULD
	//   send a SACK to its peer (the sender of the FORWARD TSN) since such a
	//   duplicate may indicate the previous SACK was lost in the network.

	outbound := &packet{}
	outbound.verificationTag = a.peerVerificationTag
	outbound.sourcePort = a.sourcePort
	outbound.destinationPort = a.destinationPort

	sack := &chunkSelectiveAck{}

	sack.cumulativeTSNAck = a.peerLastTSN
	sack.advertisedReceiverWindowCredit = a.myReceiverWindowCredit
	sack.duplicateTSN = a.payloadQueue.popDuplicates()
	sack.gapAckBlocks = a.payloadQueue.getGapAckBlocks(a.peerLastTSN)
	outbound.chunks = []chunk{sack}

	return []*packet{outbound}
}

func (a *Association) sendResetRequest(streamIdentifier uint16) error {
	p := a.createResetPacket(streamIdentifier)
	return a.send(p)
}

func (a *Association) createResetPacket(streamIdentifier uint16) *packet {
	a.lock.RLock()
	lastTSN := a.myNextTSN - 1
	a.lock.RUnlock()

	// TODO: Re-transmission
	a.ongoingReconfigOutgoing = &chunkReconfig{

		paramA: &paramOutgoingResetRequest{
			reconfigRequestSequenceNumber: a.generateNextRSN(),
			senderLastTSN:                 lastTSN,
			streamIdentifiers:             []uint16{streamIdentifier},
		},
	}
	return a.createPacket([]chunk{a.ongoingReconfigOutgoing})

}

func (a *Association) handleReconfigParam(raw param) (*packet, error) {
	// TODO: Check RSN
	switch p := raw.(type) {
	case *paramOutgoingResetRequest:
		a.ongoingResetRequest = p
		resp := a.resetStreams()
		if resp != nil {
			return resp, nil
		}
		return nil, nil

	case *paramReconfigResponse:
		// Reset the ongoing config
		// TODO: Stop re-transmission
		a.ongoingReconfigOutgoing = nil

		return nil, nil
	default:
		return nil, errors.Errorf("unexpected parameter type %T", p)
	}
}

func (a *Association) resetStreams() *packet {
	result := reconfigResultSuccessPerformed
	p := a.ongoingResetRequest
	if sna32LTE(p.senderLastTSN, a.peerLastTSN) {
		for _, id := range p.streamIdentifiers {
			s, ok := a.streams[id]
			if !ok {
				continue
			}
			a.unregisterStream(s, io.EOF)
		}
		a.ongoingResetRequest = nil
	} else {
		result = reconfigResultInProgress
	}

	return a.createPacket([]chunk{&chunkReconfig{
		paramA: &paramReconfigResponse{
			reconfigResponseSequenceNumber: p.reconfigRequestSequenceNumber,
			result:                         result,
		},
	}})
}

// sendPayloadData sends the data chunks.
func (a *Association) sendPayloadData(chunks []*chunkPayloadData) error {
	a.lock.Lock()
	for _, c := range chunks {
		c.tsn = a.generateNextTSN()

		// Primarily for PR-SCTP timed partial-reliability. Timestamp all anyway.
		c.since = time.Now()

		// TODO: FIX THIS HACK, inflightQueue uses PayloadQueue which is
		// really meant for inbound SACK generation
		a.inflightQueue.pushNoCheck(c)
	}

	// TODO: Once T3-rtx becomes available, we should only call this if T3-rtx has not
	// been started.
	packets := a.getPayloadDataToSend(true)
	a.lock.Unlock()

	for _, p := range packets {
		if err := a.send(p); err != nil {
			return errors.Wrap(err, "Unable to send outbound packet")
		}
	}

	return nil
}

// getPayloadDataToSend updates chunk status and returns a list of packets we can send.
// The caller should hold the lock.
func (a *Association) getPayloadDataToSend(onlyUnsent bool) []*packet {
	var packets []*packet
	for i := 0; ; i++ {
		d, ok := a.inflightQueue.get(a.cumulativeTSNAckPoint + uint32(i) + 1)
		if !ok {
			break // end of pending data
		}

		// Remove this when T3-rtx becomes available
		if onlyUnsent && d.nSent > 0 {
			continue
		}

		if d.acked || d.abandoned {
			continue
		}

		d.nSent++

		if a.useForwardTSN {
			// PR-SCTP
			if s, ok := a.streams[d.streamIdentifier]; ok {
				if s.reliabilityType == ReliabilityTypeRexmit {
					if d.nSent >= s.reliabilityValue {
						d.abandoned = true
						//fmt.Printf("final (abandoned) tsn=%d (remix: %d)\n", d.tsn, d.nSent)
					}
				} else if s.reliabilityType == ReliabilityTypeTimed {
					elapsed := int64(time.Since(d.since).Seconds() * 1000)
					if elapsed >= int64(s.reliabilityValue) {
						d.abandoned = true
						//fmt.Printf("final (abandoned) tsn=%d (timed: %d)\n", d.tsn, elapsed)
					}
				}
			}
		}

		// TODO: aggregate chunks into a packet as many as the MTU allows
		// TODO: use congestion window to determine how much we should send

		//fmt.Printf("sending tsn=%d ssn=%d sent=%d\n", d.tsn, d.streamSequenceNumber, d.nSent)

		packets = append(packets, a.createPacket([]chunk{d}))
	}

	return packets
}

// generateNextTSN returns the myNextTSN and increases it. The caller should hold the lock.
func (a *Association) generateNextTSN() uint32 {
	tsn := a.myNextTSN
	a.myNextTSN++
	return tsn
}

// generateNextRSN returns the myNextRSN and increases it. The caller should hold the lock.
func (a *Association) generateNextRSN() uint32 {
	rsn := a.myNextRSN
	a.myNextRSN++
	return rsn
}

// send sends a packet over netConn. The caller should hold the lock.
func (a *Association) send(p *packet) error {
	a.lock.Lock()
	raw, err := p.marshal()
	a.lock.Unlock()
	if err != nil {
		return errors.Wrap(err, "Failed to send packet to outbound handler")
	}

	_, err = a.netConn.Write(raw)
	return err
}

func pack(p *packet) []*packet {
	return []*packet{p}
}

func (a *Association) handleChunk(p *packet, c chunk) ([]*packet, error) {
	a.lock.Lock()
	defer a.lock.Unlock()

	if _, err := c.check(); err != nil {
		return nil, errors.Wrap(err, "Failed validating chunk")
		// TODO: Create ABORT
	}

	switch c := c.(type) {
	case *chunkInit:
		//fmt.Printf("[%s] chunkInit received in state '%s'\n", a.name(), a.state.String())
		switch a.state {
		case closed:
			return pack(a.handleInit(p, c)), nil
		case cookieWait:
			// https://tools.ietf.org/html/rfc4960#section-5.2.1
			// Upon receipt of an INIT in the COOKIE-WAIT state, an endpoint MUST
			// respond with an INIT ACK using the same parameters it sent in its
			// original INIT chunk (including its Initiate Tag, unchanged).  When
			// responding, the endpoint MUST send the INIT ACK back to the same
			// address that the original INIT (sent by this endpoint) was sent.
			return pack(a.handleInit(p, c)), nil

		case cookieEchoed:
			// https://tools.ietf.org/html/rfc4960#section-5.2.1
			// Upon receipt of an INIT in the COOKIE-ECHOED state, an endpoint MUST
			// respond with an INIT ACK using the same parameters it sent in its
			// original INIT chunk (including its Initiate Tag, unchanged)
			return nil, errors.Errorf("TODO respond with original cookie %s", a.state.String())
		default:
			// 5.2.2.  Unexpected INIT in States Other than CLOSED, COOKIE-ECHOED,
			//        COOKIE-WAIT, and SHUTDOWN-ACK-SENT
			return nil, errors.Errorf("TODO Handle Init when in state %s", a.state.String())
		}

	case *chunkInitAck:
		//fmt.Printf("[%s] chunkInitAck received in state '%s'\n", a.name(), a.state.String())
		if a.state == cookieWait {
			err := a.handleInitAck(p, c)
			if err != nil {
				return nil, err
			}
			a.setState(cookieEchoed)
			return nil, nil
		}

		// RFC 4960
		// 5.2.3.  Unexpected INIT ACK
		//   If an INIT ACK is received by an endpoint in any state other than the
		//   COOKIE-WAIT state, the endpoint should discard the INIT ACK chunk.
		//   An unexpected INIT ACK usually indicates the processing of an old or
		//   duplicated INIT chunk.
		return nil, nil

	case *chunkAbort:
		fmt.Println("Abort chunk, with errors:")
		for _, e := range c.errorCauses {
			fmt.Printf("error cause: %s\n", e)
		}

	case *chunkError:
		fmt.Println("Error chunk, with errors:")
		for _, e := range c.errorCauses {
			fmt.Printf("error cause: %s\n", e)
		}

	case *chunkHeartbeat:
		hbi, ok := c.params[0].(*paramHeartbeatInfo)
		if !ok {
			fmt.Println("Failed to handle Heartbeat, no ParamHeartbeatInfo")
		}

		return pack(&packet{
			verificationTag: a.peerVerificationTag,
			sourcePort:      a.sourcePort,
			destinationPort: a.destinationPort,
			chunks: []chunk{&chunkHeartbeatAck{
				params: []param{
					&paramHeartbeatInfo{
						heartbeatInformation: hbi.heartbeatInformation,
					},
				},
			}},
		}), nil

	case *chunkCookieEcho:
		//fmt.Printf("[%s] chunkCookieEcho received in state '%s'\n", a.name(), a.state.String())
		if a.state == closed || a.state == cookieWait || a.state == cookieEchoed {
			if bytes.Equal(a.myCookie.cookie, c.cookie) {
				// stop T1-init timer
				a.t1Init.stop()
				a.storedInit = nil
				// stop T1-cookie timer
				a.t1Cookie.stop()
				a.storedCookieEcho = nil

				p := &packet{
					verificationTag: a.peerVerificationTag,
					sourcePort:      a.sourcePort,
					destinationPort: a.destinationPort,
					chunks:          []chunk{&chunkCookieAck{}},
				}
				a.setState(established)
				a.handshakeCompletedCh <- nil

				return pack(p), nil
			}
		}

	case *chunkCookieAck:
		//fmt.Printf("[%s] chunkCookieAck received in state '%s'\n", a.name(), a.state.String())
		if a.state == cookieEchoed {
			// stop T1-cookie timer
			a.t1Cookie.stop()
			a.storedCookieEcho = nil

			a.setState(established)
			a.handshakeCompletedCh <- nil
			return nil, nil
		}

		// RFC 4960
		// 5.2.5.  Handle Duplicate COOKIE-ACK.
		//   At any state other than COOKIE-ECHOED, an endpoint should silently
		//   discard a received COOKIE ACK chunk.
		return nil, nil

		// TODO Abort
	case *chunkPayloadData:
		return a.handleData(c), nil

	case *chunkSelectiveAck:
		p, err := a.handleSack(c)
		if err != nil {
			return nil, errors.Wrap(err, "failure handling SACK")
		}
		return p, nil

	case *chunkReconfig:
		p, err := a.handleReconfig(c)
		if err != nil {
			return nil, errors.Wrap(err, "failure handling reconfig")
		}
		return p, nil

	case *chunkForwardTSN:
		return a.handleForwardTSN(c), nil

	default:
		return nil, errors.New("unhandled chunk type")
	}

	return nil, nil
}

func (a *Association) onRetransmissionTimeout(id int, nRtos uint) {
	a.lock.Lock()
	defer a.lock.Unlock()

	if id == timerT1Init {
		err := a.sendInit()
		if err != nil {
			// TODO: use logging
			fmt.Printf("Failed to retransmit init (nRtos=%d): %v\n", nRtos, err)
		}
		return
	}

	if id == timerT1Cookie {
		err := a.sendCookieEcho()
		if err != nil {
			// TODO: use logging
			fmt.Printf("Failed to retransmit cookie-echo (nRtos=%d): %v\n", nRtos, err)
		}
		return
	}
}

func (a *Association) onRetransmissionFailure(id int) {
	a.lock.Lock()
	defer a.lock.Unlock()

	if id == timerT1Init {
		fmt.Println("RTX Failure: T1-init")
		a.handshakeCompletedCh <- fmt.Errorf("handshake failed (INIT ACK)")
		return
	}

	if id == timerT1Cookie {
		fmt.Println("RTX Failure: T1-cookie")
		a.handshakeCompletedCh <- fmt.Errorf("handshake failed (COOKIE ECHO)")
		return
	}
}

/*
func (a *Association) name() string {
	if a.netConn != nil && a.netConn.LocalAddr() != nil {
		return a.netConn.LocalAddr().String()
	}
	return fmt.Sprintf("%p", a)
}
*/
