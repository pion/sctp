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

	"github.com/pion/logging"
	"github.com/pkg/errors"
)

const (
	receiveMTU           uint32 = 8192 // MTU for inbound packet (from DTLS)
	initialMTU           uint32 = 1228 // initial MTU for outgoing packets (to DTLS)
	maxReceiveBufferSize uint32 = 128 * 1024
	commonHeaderSize     uint32 = 12
	dataChunkHeaderSize  uint32 = 16
)

var errAssociationClosed = errors.Errorf("The association is closed")

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

// other constants
const (
	acceptChSize = 16
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
	myNextTSN           uint32 // nextTSN
	peerLastTSN         uint32 // lastRcvdTSN
	minTSN2MeasureRTT   uint32 // for RTT measurement

	// Reconfig
	ongoingReconfigOutgoing *chunkReconfig // TODO: Re-transmission
	ongoingResetRequest     *paramOutgoingResetRequest
	myNextRSN               uint32

	// Non-RFC internal data
	sourcePort              uint16
	destinationPort         uint16
	myMaxNumInboundStreams  uint16
	myMaxNumOutboundStreams uint16
	myCookie                *paramStateCookie
	payloadQueue            *payloadQueue
	inflightQueue           *payloadQueue
	pendingQueue            *pendingQueue
	mtu                     uint32
	maxPayloadSize          uint32 // max DATA chunk payload size
	cumulativeTSNAckPoint   uint32
	advancedPeerTSNAckPoint uint32
	useForwardTSN           bool

	// Congestion control parameters
	cwnd                 uint32 // my congestion window size
	rwnd                 uint32 // calculated peer's receiver windows size
	ssthresh             uint32 // slow start threshold
	partialBytesAcked    uint32
	inFastRecovery       bool
	fastRecoverExitPoint uint32

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

	// local error
	silentError error

	log logging.LeveledLogger
}

// Config collects the arguments to createAssociation construction into
// a single structure
type Config struct {
	NetConn       net.Conn
	LoggerFactory logging.LoggerFactory
}

// Server accepts a SCTP stream over a conn
func Server(config Config) (*Association, error) {
	a := createAssociation(config)
	go a.readLoop()

	select {
	case err := <-a.handshakeCompletedCh:
		if err != nil {
			return nil, err
		}
		return a, nil
	case <-a.closeCh:
		return nil, errors.Errorf("association closed before connecting")
	}
}

// Client opens a SCTP stream over a conn
func Client(config Config) (*Association, error) {
	a := createAssociation(config)
	go a.readLoop()
	a.init()

	select {
	case err := <-a.handshakeCompletedCh:
		if err != nil {
			return nil, err
		}
		return a, nil
	case <-a.closeCh:
		return nil, errors.Errorf("association closed before connecting")
	}
}

func createAssociation(config Config) *Association {
	rs := rand.NewSource(time.Now().UnixNano())
	r := rand.New(rs)

	tsn := r.Uint32()
	a := &Association{
		netConn:                 config.NetConn,
		myMaxNumOutboundStreams: math.MaxUint16,
		myMaxNumInboundStreams:  math.MaxUint16,
		payloadQueue:            newPayloadQueue(),
		inflightQueue:           newPayloadQueue(),
		pendingQueue:            newPendingQueue(),
		mtu:                     initialMTU,
		maxPayloadSize:          initialMTU - (commonHeaderSize + dataChunkHeaderSize),
		myVerificationTag:       r.Uint32(),
		myNextTSN:               tsn,
		myNextRSN:               tsn,
		minTSN2MeasureRTT:       tsn,
		state:                   closed,
		rtoMgr:                  newRTOManager(),
		streams:                 make(map[uint16]*Stream),
		acceptCh:                make(chan *Stream, acceptChSize),
		closeCh:                 make(chan struct{}),
		handshakeCompletedCh:    make(chan error),
		cumulativeTSNAckPoint:   tsn - 1,
		advancedPeerTSNAckPoint: tsn - 1,
		silentError:             errors.Errorf("silently discard"),
		log:                     config.LoggerFactory.NewLogger("sctp"),
	}

	// RFC 4690 Sec 7.2.1
	//  o  The initial cwnd before DATA transmission or after a sufficiently
	//     long idle period MUST be set to min(4*MTU, max (2*MTU, 4380
	//     bytes)).
	a.cwnd = min32(4*a.mtu, max32(2*a.mtu, 4380))
	a.log.Tracef("updated cwnd=%d ssthresh=%d inflight=%d (INI)", a.cwnd, a.ssthresh, a.inflightQueue.getNumBytes())

	a.t1Init = newRTXTimer(timerT1Init, a, maxInitRetrans)
	a.t1Cookie = newRTXTimer(timerT1Cookie, a, maxInitRetrans)
	a.t3RTX = newRTXTimer(timerT3RTX, a, noMaxRetrans) // retransmit forever

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
	init.advertisedReceiverWindowCredit = maxReceiveBufferSize
	setSupportedExtensions(&init.chunkInitCommon)
	a.storedInit = init

	err := a.sendInit()
	if err != nil {
		a.log.Errorf("failed to send init: %v", err)
	}

	a.t1Init.start(a.rtoMgr.getRTO())

	a.setState(cookieWait)
}

// caller must hold a.lock
func (a *Association) sendInit() error {
	a.log.Debug("sending INIT")
	if a.storedInit == nil {
		return errors.Errorf("the init not stored to send")
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
		return errors.Errorf("cookieEcho not stored to send")
	}

	a.log.Debug("sending COOKIE-ECHO")

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
	a.log.Debugf("[%s] closing association..", a.name())

	// TODO: shutdown sequence
	a.lock.Lock()
	a.setState(closed)
	a.lock.Unlock()

	err := a.netConn.Close()
	if err != nil {
		return err
	}

	// Close all retransmission timers
	a.t1Init.close()
	a.t1Cookie.close()
	a.t3RTX.close()

	// Wait for readLoop to end
	<-a.closeCh

	a.log.Debugf("[%s] association closed", a.name())
	return nil
}

func (a *Association) readLoop() {
	var closeErr error
	defer func() {
		a.lock.Lock()
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
			closeErr = err
			return
		}

		if err = a.handleInbound(buffer[:n]); err != nil {
			a.log.Warn(errors.Wrap(err, "failed to push SCTP packet").Error())
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
		return errors.Wrap(err, "unable to parse SCTP packet")
	}

	if err := checkPacket(p); err != nil {
		return errors.Wrap(err, "failed validating packet")
	}

	for _, c := range p.chunks {
		packets, err := a.handleChunk(p, c)
		if err != nil {
			return errors.Wrap(err, "failed handling chunk")
		}
		for _, p := range packets {
			err = a.send(p)
			if err != nil {
				return errors.Wrap(err, "failed sending reply")
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
		return errors.Errorf("sctp packet must not have a source port of 0")
	}

	// This is the SCTP port number to which this packet is destined.
	// The receiving host will use this port number to de-multiplex the
	// SCTP packet to the correct receiving endpoint/application.  The
	// port number 0 MUST NOT be used.
	if p.destinationPort == 0 {
		return errors.Errorf("sctp packet must not have a destination port of 0")
	}

	// Check values on the packet that are specific to a particular chunk type
	for _, c := range p.chunks {
		switch c.(type) {
		case *chunkInit:
			// An INIT or INIT ACK chunk MUST NOT be bundled with any other chunk.
			// They MUST be the only chunks present in the SCTP packets that carry
			// them.
			if len(p.chunks) != 1 {
				return errors.Errorf("init chunk must not be bundled with any other chunk")
			}

			// A packet containing an INIT chunk MUST have a zero Verification
			// Tag.
			if p.verificationTag != 0 {
				return errors.Errorf("init chunk expects a verification tag of 0 on the packet when out-of-the-blue")
			}
		}
	}

	return nil
}

func min16(a, b uint16) uint16 {
	if a < b {
		return a
	}
	return b
}

func max32(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

func min32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

// setState sets the state of the Association.
// The caller should hold the lock.
func (a *Association) setState(state associationState) {
	if a.state != state {
		a.log.Debugf("[%s] state change: '%s' => '%s'", a.name(), a.state.String(), state.String())
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
	a.myMaxNumInboundStreams = min16(i.numInboundStreams, a.myMaxNumInboundStreams)
	a.myMaxNumOutboundStreams = min16(i.numOutboundStreams, a.myMaxNumOutboundStreams)
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
	initAck.advertisedReceiverWindowCredit = maxReceiveBufferSize

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
	a.myMaxNumInboundStreams = min16(i.numInboundStreams, a.myMaxNumInboundStreams)
	a.myMaxNumOutboundStreams = min16(i.numOutboundStreams, a.myMaxNumOutboundStreams)
	a.peerVerificationTag = i.initiateTag
	a.peerLastTSN = i.initialTSN - 1
	if a.sourcePort != p.destinationPort ||
		a.destinationPort != p.sourcePort {
		a.log.Warn("handleInitAck: port mismatch")
		return a.silentError
	}

	a.rwnd = i.advertisedReceiverWindowCredit
	a.log.Debugf("initial rwnd=%d", a.rwnd)

	// RFC 4690 Sec 7.2.1
	//  o  The initial value of ssthresh MAY be arbitrarily high (for
	//     example, implementations MAY use the size of the receiver
	//     advertised window).
	a.ssthresh = a.rwnd
	a.log.Tracef("updated cwnd=%d ssthresh=%d inflight=%d (INI)", a.cwnd, a.ssthresh, a.inflightQueue.getNumBytes())

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
		return errors.Errorf("no cookie in InitAck")
	}

	a.storedCookieEcho = &chunkCookieEcho{}
	a.storedCookieEcho.cookie = cookieParam.cookie

	err := a.sendCookieEcho()
	if err != nil {
		a.log.Errorf("failed to send init: %v", err)
	}

	a.t1Cookie.start(a.rtoMgr.getRTO())

	return nil
}

// The caller should hold the lock.
func (a *Association) handleHeartbeat(c *chunkHeartbeat) []*packet {
	a.log.Debug("chunkHeartbeat")
	hbi, ok := c.params[0].(*paramHeartbeatInfo)
	if !ok {
		a.log.Warn("failed to handle Heartbeat, no ParamHeartbeatInfo")
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
	})
}

// The caller should hold the lock.
func (a *Association) handleCookieEcho(c *chunkCookieEcho) []*packet {
	if !bytes.Equal(a.myCookie.cookie, c.cookie) {
		return nil
	}

	a.t1Init.stop()
	a.storedInit = nil

	a.t1Cookie.stop()
	a.storedCookieEcho = nil

	p := &packet{
		verificationTag: a.peerVerificationTag,
		sourcePort:      a.sourcePort,
		destinationPort: a.destinationPort,
		chunks:          []chunk{&chunkCookieAck{}},
	}

	return pack(p)
}

// The caller should hold the lock.
func (a *Association) handleCookieAck() []*packet {
	// stop T1-cookie timer
	a.t1Cookie.stop()
	a.storedCookieEcho = nil
	return nil
}

// The caller should hold the lock.
func (a *Association) handleData(d *chunkPayloadData) []*packet {
	canPush := a.payloadQueue.canPush(d, a.peerLastTSN)
	if canPush {
		if a.getMyReceiverWindowCredit() > 0 {
			s := a.getOrCreateStream(d.streamIdentifier)
			if s == nil {
				// silentely discard the data. (sender will retry on T3-rtx timeout)
				// see pion/sctp#30
				return nil
			}

			// Pass the new chunk to stream level as soon as it arrives
			a.payloadQueue.push(d, a.peerLastTSN)
			s.handleData(d)
		}
	}

	reply := make([]*packet, 0)

	// Try to advance peerLastTSN
	_, popOk := a.payloadQueue.pop(a.peerLastTSN + 1)
	for popOk {
		if a.ongoingResetRequest != nil &&
			sna32LT(a.ongoingResetRequest.senderLastTSN, a.peerLastTSN) {
			resp := a.resetStreams()
			if resp != nil {
				a.log.Debugf("RESET RESPONSE: %+v", resp)
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
	sack.advertisedReceiverWindowCredit = a.getMyReceiverWindowCredit()
	sack.duplicateTSN = a.payloadQueue.popDuplicates()
	sack.gapAckBlocks = a.payloadQueue.getGapAckBlocks(a.peerLastTSN)
	outbound.chunks = []chunk{sack}
	reply = append(reply, outbound)

	return reply
}

// The caller should hold the lock.
func (a *Association) getMyReceiverWindowCredit() uint32 {
	bytesQueued := uint32(a.payloadQueue.getNumBytes())
	if bytesQueued >= maxReceiveBufferSize {
		return 0
	}
	return maxReceiveBufferSize - bytesQueued
}

// OpenStream opens a stream
func (a *Association) OpenStream(streamIdentifier uint16, defaultPayloadType PayloadProtocolIdentifier) (*Stream, error) {
	a.lock.Lock()
	defer a.lock.Unlock()

	if _, ok := a.streams[streamIdentifier]; ok {
		return nil, errors.Errorf("there already exists a stream with identifier %d", streamIdentifier)
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
		log:              a.log,
	}

	if accept {
		select {
		case a.acceptCh <- s:
			a.streams[streamIdentifier] = s
			a.log.Debugf("accepted a new stream (streamIdentifier: %d)", streamIdentifier)
		default:
			a.log.Debugf("dropped a new stream (acceptCh size: %d)", len(a.acceptCh))
			return nil
		}
	} else {
		a.streams[streamIdentifier] = s
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
func (a *Association) processSelectiveAck(d *chunkSelectiveAck) (int, uint32, error) {
	var totalBytesAcked int

	// New ack point, so pop all ACKed packets from inflightQueue
	// We add 1 because the "currentAckPoint" has already been popped from the inflight queue
	// For the first SACK we take care of this by setting the ackpoint to cumAck - 1
	for i := a.cumulativeTSNAckPoint + 1; sna32LTE(i, d.cumulativeTSNAck); i++ {
		c, ok := a.inflightQueue.pop(i)
		if !ok {
			return 0, 0, errors.Errorf("tsn %v unable to be popped from inflight queue", i)
		}

		if !c.acked {
			// RFC 4096 sec 6.3.2.  Retransmission Timer Rules
			//   R3)  Whenever a SACK is received that acknowledges the DATA chunk
			//        with the earliest outstanding TSN for that address, restart the
			//        T3-rtx timer for that address with its current RTO (if there is
			//        still outstanding data on that address).
			if i == a.cumulativeTSNAckPoint+1 {
				// T3 timer needs to be reset. Stop it for now.
				a.t3RTX.stop()
			}

			nBytesAcked := len(c.userData)

			// Report the number of bytes acknowledged to the stream who sent this DATA
			// chunk.
			if s, ok := a.streams[c.streamIdentifier]; ok {
				a.lock.Unlock()
				s.onBufferReleased(nBytesAcked)
				a.lock.Lock()
			}

			totalBytesAcked += nBytesAcked

			// RFC 4960 sec 6.3.1.  RTO Calculation
			//   C4)  When data is in flight and when allowed by rule C5 below, a new
			//        RTT measurement MUST be made each round trip.  Furthermore, new
			//        RTT measurements SHOULD be made no more than once per round trip
			//        for a given destination transport address.
			//   C5)  Karn's algorithm: RTT measurements MUST NOT be made using
			//        packets that were retransmitted (and thus for which it is
			//        ambiguous whether the reply was for the first instance of the
			//        chunk or for a later instance)
			if c.nSent == 1 && sna32GTE(c.tsn, a.minTSN2MeasureRTT) {
				a.minTSN2MeasureRTT = a.myNextTSN
				rtt := time.Since(c.since).Seconds() * 1000.0
				a.rtoMgr.setNewRTT(rtt)
				a.log.Tracef("SACK: measured-rtt=%f new-rto=%f", rtt, a.rtoMgr.getRTO())
			}
		}

		if a.inFastRecovery && c.tsn == a.fastRecoverExitPoint {
			a.log.Debug("exit fast-recovery")
			a.inFastRecovery = false
		}
	}

	htna := d.cumulativeTSNAck

	// Mark selectively acknowledged chunks as "acked"
	for _, g := range d.gapAckBlocks {
		for i := g.start; i <= g.end; i++ {
			tsn := d.cumulativeTSNAck + uint32(i)
			c, ok := a.inflightQueue.get(tsn)
			if !ok {
				return 0, 0, errors.Errorf("requested non-existent TSN %v", tsn)
			}

			if !c.acked {
				nBytesAcked := a.inflightQueue.markAsAcked(tsn)

				// Report the number of bytes acknowledged to the stream who sent this DATA
				// chunk.
				if s, ok := a.streams[c.streamIdentifier]; ok {
					a.lock.Unlock()
					s.onBufferReleased(nBytesAcked)
					a.lock.Lock()
				}

				totalBytesAcked += nBytesAcked

				a.log.Tracef("tsn=%d has been sacked", c.tsn)

				if c.nSent == 1 {
					rtt := time.Since(c.since).Seconds() * 1000.0
					a.rtoMgr.setNewRTT(rtt)
					a.log.Tracef("SACK: measured-rtt=%f new-rto=%f", rtt, a.rtoMgr.getRTO())
				}

				if sna32LT(htna, tsn) {
					htna = tsn
				}
			}
		}
	}

	return totalBytesAcked, htna, nil
}

// The caller should hold the lock.
func (a *Association) onCumulativeTSNAckPointAdvanced(totalBytesAcked int) {
	// RFC 4096, sec 6.3.2.  Retransmission Timer Rules
	//   R2)  Whenever all outstanding data sent to an address have been
	//        acknowledged, turn off the T3-rtx timer of that address.
	if a.inflightQueue.size() == 0 {
		a.log.Tracef("SACK: no more packet in-flight (pending=%d)", a.pendingQueue.size())
		a.t3RTX.stop()
	} else {
		a.log.Tracef("[%s] T3-rtx timer start (pt2)", a.name())
		a.t3RTX.start(a.rtoMgr.getRTO())
	}

	// Update congestion control parameters
	if a.cwnd <= a.ssthresh {
		// RFC 4096, sec 7.2.1.  Slow-Start
		//   o  When cwnd is less than or equal to ssthresh, an SCTP endpoint MUST
		//		use the slow-start algorithm to increase cwnd only if the current
		//      congestion window is being fully utilized, an incoming SACK
		//      advances the Cumulative TSN Ack Point, and the data sender is not
		//      in Fast Recovery.  Only when these three conditions are met can
		//      the cwnd be increased; otherwise, the cwnd MUST not be increased.
		//		If these conditions are met, then cwnd MUST be increased by, at
		//      most, the lesser of 1) the total size of the previously
		//      outstanding DATA chunk(s) acknowledged, and 2) the destination's
		//      path MTU.
		if !a.inFastRecovery &&
			a.pendingQueue.size() > 0 {

			a.cwnd += min32(uint32(totalBytesAcked), a.mtu)
			a.log.Tracef("updated cwnd=%d ssthresh=%d inflight=%d (SS)", a.cwnd, a.ssthresh, a.inflightQueue.getNumBytes())
		}
	} else {
		// RFC 4096, sec 7.2.2.  Congestion Avoidance
		//   o  Whenever cwnd is greater than ssthresh, upon each SACK arrival
		//      that advances the Cumulative TSN Ack Point, increase
		//      partial_bytes_acked by the total number of bytes of all new chunks
		//      acknowledged in that SACK including chunks acknowledged by the new
		//      Cumulative TSN Ack and by Gap Ack Blocks.
		a.partialBytesAcked += uint32(totalBytesAcked)

		//   o  When partial_bytes_acked is equal to or greater than cwnd and
		//      before the arrival of the SACK the sender had cwnd or more bytes
		//      of data outstanding (i.e., before arrival of the SACK, flight size
		//      was greater than or equal to cwnd), increase cwnd by MTU, and
		//      reset partial_bytes_acked to (partial_bytes_acked - cwnd).
		if a.partialBytesAcked >= a.cwnd &&
			a.pendingQueue.size() > 0 {

			a.partialBytesAcked -= a.cwnd
			a.cwnd += a.mtu
			a.log.Tracef("updated cwnd=%d ssthresh=%d inflight=%d (CA)", a.cwnd, a.ssthresh, a.inflightQueue.getNumBytes())
		}
	}
}

// The caller should hold the lock.
func (a *Association) processFastRetransmission(cumTSNAckPoint, htna uint32, cumTSNAckPointAdvanced bool) ([]chunk, error) {
	toFastRetrans := []chunk{}
	fastRetransSize := commonHeaderSize

	// HTNA algorithm - RFC 4960 Sec 7.2.4
	// Increment missIndicator of each chunks that the SACK reported missing
	// when either of the following is met:
	// a)  Not in fast-recovery, or;
	// b)  In fast-recovery AND the Cumulative TSN Ack Point advanced
	if !a.inFastRecovery || (a.inFastRecovery && cumTSNAckPointAdvanced) {
		for tsn := cumTSNAckPoint + 1; sna32LTE(tsn, htna); tsn++ {
			c, ok := a.inflightQueue.get(tsn)
			if !ok {
				return nil, errors.Errorf("requested non-existent TSN %v", tsn)
			}
			if !c.acked && !c.abandoned && c.missIndicator < 3 {
				c.missIndicator++
				if c.missIndicator == 3 {
					dataChunkSize := dataChunkHeaderSize + uint32(len(c.userData))
					if a.mtu-fastRetransSize >= dataChunkSize {
						fastRetransSize += dataChunkSize
						toFastRetrans = append(toFastRetrans, c)
						a.log.Tracef("fast-retransmit: tsn=%d", tsn)
					}
				}
			}
		}
	}

	if len(toFastRetrans) > 0 && !a.inFastRecovery {
		a.inFastRecovery = true
		a.fastRecoverExitPoint = htna
		a.ssthresh = max32(a.cwnd/2, 4*a.mtu)
		a.cwnd = a.ssthresh
		a.partialBytesAcked = 0

		a.log.Tracef("updated cwnd=%d ssthresh=%d inflight=%d (FR)", a.cwnd, a.ssthresh, a.inflightQueue.getNumBytes())
	}

	return toFastRetrans, nil
}

// The caller should hold the lock.
func (a *Association) handleSack(d *chunkSelectiveAck) ([]*packet, error) {
	a.log.Tracef("SACK: cumTSN=%d a_rwnd=%d", d.cumulativeTSNAck, d.advertisedReceiverWindowCredit)

	if sna32GT(a.cumulativeTSNAckPoint, d.cumulativeTSNAck) {
		// RFC 4960 sec 6.2.1.  Processing a Received SACK
		// D)
		//   i) If Cumulative TSN Ack is less than the Cumulative TSN Ack
		//      Point, then drop the SACK.  Since Cumulative TSN Ack is
		//      monotonically increasing, a SACK whose Cumulative TSN Ack is
		//      less than the Cumulative TSN Ack Point indicates an out-of-
		//      order SACK.

		a.log.Debugf("SACK Cumulative ACK %v is older than ACK point %v",
			d.cumulativeTSNAck,
			a.cumulativeTSNAckPoint)

		return nil, nil
	}

	// Process selective ack
	totalBytesAcked, htna, err := a.processSelectiveAck(d)
	if err != nil {
		return nil, err
	}

	// New rwnd value
	// RFC 4960 sec 6.2.1.  Processing a Received SACK
	// D)
	//   ii) Set rwnd equal to the newly received a_rwnd minus the number
	//       of bytes still outstanding after processing the Cumulative
	//       TSN Ack and the Gap Ack Blocks.

	// bytes acked were already subtracted by markAsAcked() method
	bytesOutstanding := uint32(a.inflightQueue.getNumBytes())
	if bytesOutstanding >= d.advertisedReceiverWindowCredit {
		a.rwnd = 0
	} else {
		a.rwnd = d.advertisedReceiverWindowCredit - bytesOutstanding
	}

	cumTSNAckPointAdvanced := false
	if sna32LT(a.cumulativeTSNAckPoint, d.cumulativeTSNAck) {
		a.log.Tracef("SACK: cumTSN advanced: %d -> %d",
			a.cumulativeTSNAckPoint,
			d.cumulativeTSNAck)

		a.cumulativeTSNAckPoint = d.cumulativeTSNAck
		cumTSNAckPointAdvanced = true

		a.onCumulativeTSNAckPointAdvanced(totalBytesAcked)
	}

	toFastRetrans, err := a.processFastRetransmission(d.cumulativeTSNAck, htna, cumTSNAckPointAdvanced)
	if err != nil {
		return nil, err
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

	if len(toFastRetrans) > 0 {
		packets = append(packets, a.createPacket(toFastRetrans))
	}

	chunks := a.popPendingDataChunksToSend()
	if len(chunks) > 0 {
		// Start timer. (noop if already started)
		a.log.Tracef("[%s] T3-rtx timer start (pt3)", a.name())
		a.t3RTX.start(a.rtoMgr.getRTO())

		packets = append(packets, a.bundleDataChunksIntoPackets(chunks)...)
	}

	return packets, nil
}

// createForwardTSN generates ForwardTSN chunk.
// This method will be be called if useForwardTSN is set to false.
// The caller should hold the lock.
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

	a.log.Tracef("building fwdtsn: newCumulativeTSN=%d", fwdtsn.newCumulativeTSN)
	for si, ssn := range streamMap {
		a.log.Tracef(" - si=%d ssn=%d", si, ssn)
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

// The caller should hold the lock.
func (a *Association) handleReconfig(c *chunkReconfig) ([]*packet, error) {
	a.log.Debug("handleReconfig")

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

// The caller should hold the lock.
func (a *Association) handleForwardTSN(c *chunkForwardTSN) []*packet {
	a.log.Debugf("handleForward: %s", c.String())

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

	if sna32LT(a.peerLastTSN, c.newCumulativeTSN) {
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

		return nil
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
	sack.advertisedReceiverWindowCredit = a.getMyReceiverWindowCredit()
	sack.duplicateTSN = a.payloadQueue.popDuplicates()
	sack.gapAckBlocks = a.payloadQueue.getGapAckBlocks(a.peerLastTSN)
	outbound.chunks = []chunk{sack}

	return []*packet{outbound}
}

func (a *Association) sendResetRequest(streamIdentifier uint16) error {
	a.lock.Lock()
	p := a.createResetPacket(streamIdentifier)
	a.lock.Unlock()

	return a.send(p)
}

// The caller should hold the lock.
func (a *Association) createResetPacket(streamIdentifier uint16) *packet {
	lastTSN := a.myNextTSN - 1

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

// The caller should hold the lock.
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

// The caller should hold the lock.
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

// The caller should hold the lock.
func (a *Association) peekNextPendingData() *chunkPayloadData {
	return a.pendingQueue.peek()
}

// Move the chunk peeked with peekNextPendingData() to the inflightQueue.
// The caller should hold the lock.
func (a *Association) movePendingDataChunkToInflightQueue(c *chunkPayloadData) {
	if err := a.pendingQueue.pop(c); err != nil {
		a.log.Errorf("failed to pop from pending queue: %s", err.Error())
	}

	// Assign TSN
	c.tsn = a.generateNextTSN()

	c.since = time.Now() // use to calculate RTT and also for maxPacketLifeTime
	c.nSent = 1          // being sent for the first time

	a.checkPartialReliabilityStatus(c)

	a.log.Tracef("sending tsn=%d ssn=%d sent=%d", c.tsn, c.streamSequenceNumber, c.nSent)

	// Push it into the inflightQueue
	a.inflightQueue.pushNoCheck(c)
}

// popPendingDataChunksToSend pops chunks from the pending queues as many as
// the cwnd and rwnd allows to send.
// The caller should hold the lock.
func (a *Association) popPendingDataChunksToSend() []*chunkPayloadData {
	chunks := []*chunkPayloadData{}

	if a.pendingQueue.size() > 0 {

		// RFC 4960 sec 6.1.  Transmission of DATA Chunks
		//   A) At any given time, the data sender MUST NOT transmit new data to
		//      any destination transport address if its peer's rwnd indicates
		//      that the peer has no buffer space (i.e., rwnd is 0; see Section
		//      6.2.1).  However, regardless of the value of rwnd (including if it
		//      is 0), the data sender can always have one DATA chunk in flight to
		//      the receiver if allowed by cwnd (see rule B, below).

		for {
			c := a.peekNextPendingData()
			if c == nil {
				break // no more pending data
			}

			dataLen := uint32(len(c.userData))

			if uint32(a.inflightQueue.getNumBytes())+dataLen > a.cwnd {
				break // would exceeds cwnd
			}

			if dataLen > a.rwnd {
				break // no more rwnd
			}

			a.rwnd -= dataLen

			a.movePendingDataChunkToInflightQueue(c)
			chunks = append(chunks, c)
		}

		// the data sender can always have one DATA chunk in flight to the receiver
		if len(chunks) == 0 && a.inflightQueue.size() == 0 {
			// Send zero window probe
			c := a.peekNextPendingData()
			a.movePendingDataChunkToInflightQueue(c)
			chunks = append(chunks, c)
		}
	}

	return chunks
}

// bundleDataChunksIntoPackets packs DATA chunks into packets. It tries to bundle
// DATA chunks into a packet so long as the resulting packet size does not exceed
// the path MTU.
// The caller should hold the lock.
func (a *Association) bundleDataChunksIntoPackets(chunks []*chunkPayloadData) []*packet {
	packets := []*packet{}
	chunksToSend := []chunk{}
	bytesInPacket := int(commonHeaderSize)

	for _, c := range chunks {
		// RFC 4960 sec 6.1.  Transmission of DATA Chunks
		//   Multiple DATA chunks committed for transmission MAY be bundled in a
		//   single packet.  Furthermore, DATA chunks being retransmitted MAY be
		//   bundled with new DATA chunks, as long as the resulting packet size
		//   does not exceed the path MTU.
		if bytesInPacket+len(c.userData) > int(a.mtu) {
			packets = append(packets, a.createPacket(chunksToSend))
			chunksToSend = []chunk{}
			bytesInPacket = int(commonHeaderSize)
		}

		chunksToSend = append(chunksToSend, c)
		bytesInPacket += int(dataChunkHeaderSize) + len(c.userData)
	}

	if len(chunksToSend) > 0 {
		packets = append(packets, a.createPacket(chunksToSend))
	}

	return packets
}

// sendPayloadData sends the data chunks.
func (a *Association) sendPayloadData(chunks []*chunkPayloadData) error {
	packets := func() []*packet {
		a.lock.Lock()
		defer a.lock.Unlock()

		// Push the chunks into the pending queue first.
		for _, c := range chunks {
			a.pendingQueue.push(c)
		}

		// Pop unsent data chunks from the pending queue to send as much as
		// cwnd and rwnd allow.
		chunks := a.popPendingDataChunksToSend()
		if len(chunks) == 0 {
			return []*packet{}
		}

		// Start timer. (noop if already started)
		a.log.Tracef("[%s] T3-rtx timer start (pt1)", a.name())
		a.t3RTX.start(a.rtoMgr.getRTO())

		return a.bundleDataChunksIntoPackets(chunks)
	}()

	for _, p := range packets {
		if err := a.send(p); err != nil {
			return errors.Wrap(err, "unable to send outbound packet")
		}
	}

	return nil
}

// The caller should hold the lock.
func (a *Association) checkPartialReliabilityStatus(c *chunkPayloadData) {
	if !a.useForwardTSN {
		return
	}

	// PR-SCTP
	if s, ok := a.streams[c.streamIdentifier]; ok {
		s.lock.RLock()
		if s.reliabilityType == ReliabilityTypeRexmit {
			if c.nSent >= s.reliabilityValue {
				c.abandoned = true
				a.log.Debugf("final (abandoned) tsn=%d (remix: %d)", c.tsn, c.nSent)
			}
		} else if s.reliabilityType == ReliabilityTypeTimed {
			elapsed := int64(time.Since(c.since).Seconds() * 1000)
			if elapsed >= int64(s.reliabilityValue) {
				c.abandoned = true
				a.log.Debugf("final (abandoned) tsn=%d (timed: %d)", c.tsn, elapsed)
			}
		}
		s.lock.RUnlock()
	}
}

// retransmitPayloadData is called when T3-rtx is timed out and retransmit outstanding data chunks
// that are not acked or abandoned yet.
// The caller should hold the lock.
func (a *Association) retransmitPayloadData() error {
	awnd := min32(a.cwnd, a.rwnd)
	chunks := []*chunkPayloadData{}
	var bytesToSend int
	var done bool

	for i := 0; !done; i++ {
		c, ok := a.inflightQueue.get(a.cumulativeTSNAckPoint + uint32(i) + 1)
		if !ok {
			break // end of pending data
		}

		if c.acked || c.abandoned {
			continue
		}

		if i == 0 && int(a.rwnd) < len(c.userData) {
			// Send it as a zero window probe
			done = true
		} else if bytesToSend+len(c.userData) > int(awnd) {
			break
		}

		bytesToSend += len(c.userData)

		c.nSent++

		a.checkPartialReliabilityStatus(c)

		a.log.Tracef("retransmitting tsn=%d ssn=%d sent=%d", c.tsn, c.streamSequenceNumber, c.nSent)

		chunks = append(chunks, c)
	}

	packets := a.bundleDataChunksIntoPackets(chunks)

	a.lock.Unlock()
	var err error

	for _, p := range packets {
		if err = a.send(p); err != nil {
			err = errors.Wrap(err, "unable to send outbound packet")
			break
		}
	}

	a.lock.Lock()

	return err
}

// generateNextTSN returns the myNextTSN and increases it. The caller should hold the lock.
// The caller should hold the lock.
func (a *Association) generateNextTSN() uint32 {
	tsn := a.myNextTSN
	a.myNextTSN++
	return tsn
}

// generateNextRSN returns the myNextRSN and increases it. The caller should hold the lock.
// The caller should hold the lock.
func (a *Association) generateNextRSN() uint32 {
	rsn := a.myNextRSN
	a.myNextRSN++
	return rsn
}

// send sends a packet over netConn.
func (a *Association) send(p *packet) error {
	a.lock.Lock()
	raw, err := p.marshal()
	a.lock.Unlock()
	if err != nil {
		return errors.Wrap(err, "failed to send packet to outbound handler")
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
		return nil, errors.Wrap(err, "failed validating chunk")
		// TODO: Create ABORT
	}

	switch c := c.(type) {
	case *chunkInit:
		a.log.Debugf("[%s] chunkInit received in state '%s'", a.name(), a.state.String())
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
			return nil, errors.Errorf("todo: respond with original cookie %s", a.state.String())
		default:
			// 5.2.2.  Unexpected INIT in States Other than CLOSED, COOKIE-ECHOED,
			//        COOKIE-WAIT, and SHUTDOWN-ACK-SENT
			return nil, errors.Errorf("todo: handle Init when in state %s", a.state.String())
		}

	case *chunkInitAck:
		a.log.Debugf("[%s] chunkInitAck received in state '%s'", a.name(), a.state.String())
		if a.state == cookieWait {
			err := a.handleInitAck(p, c)
			if err != nil {
				if err == a.silentError {
					return nil, nil
				}
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
		a.log.Debugf("Abort chunk, with following errors:")
		for _, e := range c.errorCauses {
			a.log.Debugf(" - error cause: %s", e)
		}

	case *chunkError:
		a.log.Debug("Error chunk, with following errors:")
		for _, e := range c.errorCauses {
			a.log.Debugf(" - error cause: %s", e)
		}

	case *chunkHeartbeat:
		return a.handleHeartbeat(c), nil

	case *chunkCookieEcho:
		a.log.Debugf("[%s] chunkCookieEcho received in state '%s'", a.name(), a.state.String())
		if a.state == closed || a.state == cookieWait || a.state == cookieEchoed {
			p := a.handleCookieEcho(c)
			a.setState(established)
			a.handshakeCompletedCh <- nil
			return p, nil
		}

	case *chunkCookieAck:
		a.log.Debugf("[%s] chunkCookieAck received in state '%s'", a.name(), a.state.String())
		if a.state == cookieEchoed {
			p := a.handleCookieAck()
			a.setState(established)
			a.handshakeCompletedCh <- nil
			return p, nil
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
		if a.state == established {
			p, err := a.handleSack(c)
			if err != nil {
				return nil, errors.Wrap(err, "failure handling SACK")
			}
			return p, nil
		}

	case *chunkReconfig:
		p, err := a.handleReconfig(c)
		if err != nil {
			return nil, errors.Wrap(err, "failure handling reconfig")
		}
		return p, nil

	case *chunkForwardTSN:
		return a.handleForwardTSN(c), nil

	default:
		return nil, errors.Errorf("unhandled chunk type")
	}

	return nil, nil
}

func (a *Association) onRetransmissionTimeout(id int, nRtos uint) {
	a.lock.Lock()
	defer a.lock.Unlock()

	if id == timerT1Init {
		err := a.sendInit()
		if err != nil {
			a.log.Debugf("failed to retransmit init (nRtos=%d): %v", nRtos, err)
		}
		return
	}

	if id == timerT1Cookie {
		err := a.sendCookieEcho()
		if err != nil {
			a.log.Debugf("failed to retransmit cookie-echo (nRtos=%d): %v", nRtos, err)
		}
		return
	}

	if id == timerT3RTX {
		// RFC 4960 sec 6.3.3
		//  E1)  For the destination address for which the timer expires, adjust
		//       its ssthresh with rules defined in Section 7.2.3 and set the
		//       cwnd <- MTU.
		// RFC 4960 sec 7.2.3
		//   When the T3-rtx timer expires on an address, SCTP should perform slow
		//   start by:
		//      ssthresh = max(cwnd/2, 4*MTU)
		//      cwnd = 1*MTU

		a.ssthresh = max32(a.cwnd/2, 4*a.mtu)
		a.cwnd = a.mtu
		a.log.Tracef("updated cwnd=%d ssthresh=%d inflight=%d (RTO)", a.cwnd, a.ssthresh, a.inflightQueue.getNumBytes())

		a.log.Debugf("[%s] T3-rtx timed out: nRtos=%d cwnd=%d ssthresh=%d",
			a.name(), nRtos, a.cwnd, a.ssthresh)
		err := a.retransmitPayloadData()
		if err != nil {
			a.log.Debugf("failed to retransmit DATA chunks (nRtos=%d): %v", nRtos, err)
			return
		}
		return
	}
}

func (a *Association) onRetransmissionFailure(id int) {
	a.lock.Lock()
	defer a.lock.Unlock()

	if id == timerT1Init {
		a.log.Error("retransmission failure: T1-init")
		a.handshakeCompletedCh <- errors.Errorf("handshake failed (INIT ACK)")
		return
	}

	if id == timerT1Cookie {
		a.log.Error("retransmission failure: T1-cookie")
		a.handshakeCompletedCh <- errors.Errorf("handshake failed (COOKIE ECHO)")
		return
	}

	if id == timerT3RTX {
		// T3-rtx timer will not fail by design
		// Justifications:
		//  * ICE would fail if the connectivity is lost
		//  * WebRTC spec is not clear how this incident should be reported to ULP
		a.log.Error("retransmission failure: T3-rtx (DATA)")
		return
	}
}

// bufferedAmount returns total amount (in bytes) of currently buffered user data.
// This is used only by testing.
func (a *Association) bufferedAmount() int {
	a.lock.RLock()
	defer a.lock.RUnlock()

	return a.pendingQueue.getNumBytes() + a.inflightQueue.getNumBytes()
}

func (a *Association) name() string {
	return fmt.Sprintf("%p", a)
}
