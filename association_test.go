package sctp

import (
	cryptoRand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/test"
	"github.com/stretchr/testify/assert"
)

func TestAssocStressDuplex(t *testing.T) {
	// Limit runtime in case of deadlocks
	lim := test.TimeOut(time.Second * 20)
	defer lim.Stop()

	// Check for leaking routines
	report := test.CheckRoutines(t)
	defer report()

	stressDuplex(t)
}

func stressDuplex(t *testing.T) {
	ca, cb, stop, err := pipe(pipeDump)
	if err != nil {
		t.Fatal(err)
	}

	defer stop(t)

	// TODO: Increase once SCTP is more reliable in case of slow reader
	opt := test.Options{
		MsgSize:  2048, // 65535,
		MsgCount: 10,   // 1000,
	}

	err = test.StressDuplex(ca, cb, opt)
	if err != nil {
		t.Fatal(err)
	}
}

func pipe(piper piperFunc) (*Stream, *Stream, func(*testing.T), error) {
	var err error

	var aa, ab *Association
	aa, ab, err = association(piper)
	if err != nil {
		return nil, nil, nil, err
	}

	var sa, sb *Stream
	sa, err = aa.OpenStream(0, 0)
	if err != nil {
		return nil, nil, nil, err
	}

	sb, err = ab.OpenStream(0, 0)
	if err != nil {
		return nil, nil, nil, err
	}

	stop := func(t *testing.T) {
		err = sa.Close()
		if err != nil {
			t.Error(err)
		}
		err = sb.Close()
		if err != nil {
			t.Error(err)
		}
		err = aa.Close()
		if err != nil {
			t.Error(err)
		}
		err = ab.Close()
		if err != nil {
			t.Error(err)
		}
	}

	return sa, sb, stop, nil
}

func association(piper piperFunc) (*Association, *Association, error) {
	ca, cb := piper()

	type result struct {
		a   *Association
		err error
	}

	c := make(chan result)
	loggerFactory := logging.NewDefaultLoggerFactory()

	// Setup client
	go func() {
		client, err := Client(Config{
			NetConn:       ca,
			LoggerFactory: loggerFactory,
		})
		c <- result{client, err}
	}()

	// Setup server
	server, err := Server(Config{
		NetConn:       cb,
		LoggerFactory: loggerFactory,
	})
	if err != nil {
		return nil, nil, err
	}

	// Receive client
	res := <-c
	if res.err != nil {
		return nil, nil, res.err
	}

	return res.a, server, nil
}

type piperFunc func() (net.Conn, net.Conn)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func pipeDump() (net.Conn, net.Conn) {
	aConn := acceptDumbConn()

	bConn, err := net.DialUDP("udp4", nil, aConn.LocalAddr().(*net.UDPAddr))
	check(err)

	// Dumb handshake
	mgs := "Test"
	_, err = bConn.Write([]byte(mgs))
	check(err)

	b := make([]byte, 4)
	_, err = aConn.Read(b)
	check(err)

	if string(b) != mgs {
		panic("Dumb handshake failed")
	}

	return aConn, bConn
}

type dumbConn struct {
	mu    sync.RWMutex
	rAddr net.Addr
	pConn net.PacketConn
}

func acceptDumbConn() *dumbConn {
	pConn, err := net.ListenUDP("udp4", nil)
	check(err)
	return &dumbConn{
		pConn: pConn,
	}
}

// Read
func (c *dumbConn) Read(p []byte) (int, error) {
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
func (c *dumbConn) Write(p []byte) (n int, err error) {
	return c.pConn.WriteTo(p, c.RemoteAddr())
}

// Close closes the conn and releases any Read calls
func (c *dumbConn) Close() error {
	return c.pConn.Close()
}

// LocalAddr is a stub
func (c *dumbConn) LocalAddr() net.Addr {
	if c.pConn != nil {
		return c.pConn.LocalAddr()
	}
	return nil
}

// RemoteAddr is a stub
func (c *dumbConn) RemoteAddr() net.Addr {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.rAddr
}

// SetDeadline is a stub
func (c *dumbConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline is a stub
func (c *dumbConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline is a stub
func (c *dumbConn) SetWriteDeadline(t time.Time) error {
	return nil
}

////////////////////////////////////////////////////////////////////////////////

func createNewAssociationPair(br *test.Bridge, ackMode int) (*Association, *Association, error) {
	var a0, a1 *Association
	var err0, err1 error
	loggerFactory := logging.NewDefaultLoggerFactory()

	handshake0Ch := make(chan bool)
	handshake1Ch := make(chan bool)

	go func() {
		a0, err0 = Client(Config{
			NetConn:       br.GetConn0(),
			LoggerFactory: loggerFactory,
		})
		handshake0Ch <- true
	}()
	go func() {
		a1, err1 = Client(Config{
			NetConn:       br.GetConn1(),
			LoggerFactory: loggerFactory,
		})
		handshake1Ch <- true
	}()

	a0handshakeDone := false
	a1handshakeDone := false

loop1:
	for i := 0; i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
		br.Tick()

		select {
		case a0handshakeDone = <-handshake0Ch:
			if a1handshakeDone {
				break loop1
			}
		case a1handshakeDone = <-handshake1Ch:
			if a0handshakeDone {
				break loop1
			}
		default:
		}
	}

	if !a0handshakeDone || !a1handshakeDone {
		return nil, nil, fmt.Errorf("handshake failed")
	}

	if err0 != nil {
		return nil, nil, err0
	}
	if err1 != nil {
		return nil, nil, err1
	}

	a0.ackMode = ackMode
	a1.ackMode = ackMode

	return a0, a1, nil
}

func closeAssociationPair(br *test.Bridge, a0, a1 *Association) {
	close0Ch := make(chan bool)
	close1Ch := make(chan bool)

	go func() {
		//nolint:errcheck,gosec
		a0.Close()
		close0Ch <- true
	}()
	go func() {
		//nolint:errcheck,gosec
		a1.Close()
		close1Ch <- true
	}()

	a0closed := false
	a1closed := false
loop1:
	for i := 0; i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
		br.Tick()

		select {
		case a0closed = <-close0Ch:
			if a1closed {
				break loop1
			}
		case a1closed = <-close1Ch:
			if a0closed {
				break loop1
			}
		default:
		}
	}
}

func flushBuffers(br *test.Bridge, a0, a1 *Association) {
	for {
		for {
			n := br.Tick()
			if n == 0 {
				break
			}
		}

		if a0.bufferedAmount() == 0 && a1.bufferedAmount() == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func establishSessionPair(br *test.Bridge, a0, a1 *Association, si uint16) (*Stream, *Stream, error) {
	helloMsg := "Hello" // mimic datachannel.channelOpen
	s0, err := a0.OpenStream(si, PayloadTypeWebRTCBinary)
	if err != nil {
		return nil, nil, err
	}

	_, err = s0.WriteSCTP([]byte(helloMsg), PayloadTypeWebRTCDCEP)
	if err != nil {
		return nil, nil, err
	}

	br.Process()

	s1, err := a1.AcceptStream()
	if err != nil {
		return nil, nil, err
	}

	if s0.streamIdentifier != s1.streamIdentifier {
		return nil, nil, fmt.Errorf("SI should match")
	}

	br.Process()

	buf := make([]byte, 1024)
	n, ppi, err := s1.ReadSCTP(buf)
	if err != nil {
		return nil, nil, fmt.Errorf("faild to read data")
	}

	if n != len(helloMsg) {
		return nil, nil, fmt.Errorf("received data must by 3 bytes")
	}

	if ppi != PayloadTypeWebRTCDCEP {
		return nil, nil, fmt.Errorf("unexpected ppi")
	}

	if string(buf[:n]) != helloMsg {
		return nil, nil, fmt.Errorf("received data mismatch")
	}

	flushBuffers(br, a0, a1)

	return s0, s1, nil
}

func TestAssocReliable(t *testing.T) {
	// sbuf - small enogh not to be fragmented
	//        large enobh not to be bundled
	sbuf := make([]byte, 1000)
	for i := 0; i < len(sbuf); i++ {
		sbuf[i] = byte(i & 0xff)
	}
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(sbuf), func(i, j int) { sbuf[i], sbuf[j] = sbuf[j], sbuf[i] })

	// sbufL - large enogh to be fragmented into two chunks and each chunks are
	//        large enobh not to be bundled
	sbufL := make([]byte, 2000)
	for i := 0; i < len(sbufL); i++ {
		sbufL[i] = byte(i & 0xff)
	}
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(sbufL), func(i, j int) { sbufL[i], sbufL[j] = sbufL[j], sbufL[i] })

	t.Run("Simple", func(t *testing.T) {
		const si uint16 = 1
		const msg = "ABC"
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		assert.Equal(t, 0, a0.bufferedAmount(), "incorrect bufferedAmount")

		n, err := s0.WriteSCTP([]byte(msg), PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(msg), n, "unexpected length of received data")
		assert.Equal(t, len(msg), a0.bufferedAmount(), "incorrect bufferedAmount")

		br.Process()

		buf := make([]byte, 32)
		n, ppi, err := s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, n, len(msg), "unexpected length of received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		assert.False(t, s0.reassemblyQueue.isReadable(), "should no longer be readable")
		assert.Equal(t, 0, a0.bufferedAmount(), "incorrect bufferedAmount")

		closeAssociationPair(br, a0, a1)
	})

	t.Run("ordered reordered", func(t *testing.T) {
		const si uint16 = 2
		var n int
		var ppi PayloadProtocolIdentifier
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		binary.BigEndian.PutUint32(sbuf, 0)
		n, err = s0.WriteSCTP(sbuf, PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(sbuf), "unexpected length of received data")

		binary.BigEndian.PutUint32(sbuf, 1)
		n, err = s0.WriteSCTP(sbuf, PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(sbuf), "unexpected length of received data")

		time.Sleep(10 * time.Millisecond)
		err = br.Reorder(0)
		assert.Nil(t, err, "reorder failed")
		br.Process()

		buf := make([]byte, 2000)

		n, ppi, err = s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, n, len(sbuf), "unexpected length of received data")
		assert.Equal(t, uint32(0), binary.BigEndian.Uint32(buf[:n]),
			"unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		n, ppi, err = s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, n, len(sbuf), "unexpected length of received data")
		assert.Equal(t, uint32(1), binary.BigEndian.Uint32(buf[:n]),
			"unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.Process()
		assert.False(t, s0.reassemblyQueue.isReadable(), "should no longer be readable")
		closeAssociationPair(br, a0, a1)
	})

	t.Run("ordered fragmented then defragmented", func(t *testing.T) {
		const si uint16 = 3
		var n int
		var ppi PayloadProtocolIdentifier
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		s0.SetReliabilityParams(false, ReliabilityTypeReliable, 0)
		s1.SetReliabilityParams(false, ReliabilityTypeReliable, 0)

		n, err = s0.WriteSCTP(sbufL, PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(sbufL), "unexpected length of received data")

		br.Process()

		rbuf := make([]byte, 2000)

		br.Process()

		n, ppi, err = s1.ReadSCTP(rbuf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}

		assert.Equal(t, n, len(sbufL), "unexpected length of received data")
		assert.Equal(t, sbufL, rbuf[:n], "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.Process()
		assert.False(t, s0.reassemblyQueue.isReadable(), "should no longer be readable")
		closeAssociationPair(br, a0, a1)
	})

	t.Run("unordered fragmented then defragmented", func(t *testing.T) {
		const si uint16 = 4
		var n int
		var ppi PayloadProtocolIdentifier
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		s0.SetReliabilityParams(true, ReliabilityTypeReliable, 0)
		s1.SetReliabilityParams(true, ReliabilityTypeReliable, 0)

		n, err = s0.WriteSCTP(sbufL, PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(sbufL), "unexpected length of received data")

		br.Process()

		rbuf := make([]byte, 2000)

		br.Process()

		n, ppi, err = s1.ReadSCTP(rbuf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}

		assert.Equal(t, n, len(sbufL), "unexpected length of received data")
		assert.Equal(t, sbufL, rbuf[:n], "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.Process()
		assert.False(t, s0.reassemblyQueue.isReadable(), "should no longer be readable")
		closeAssociationPair(br, a0, a1)
	})

	t.Run("unordered reordered", func(t *testing.T) {
		const si uint16 = 5
		var n int
		var ppi PayloadProtocolIdentifier
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		s0.SetReliabilityParams(true, ReliabilityTypeReliable, 0)
		s1.SetReliabilityParams(true, ReliabilityTypeReliable, 0)

		br.ReorderNextNWrites(0, 2)

		binary.BigEndian.PutUint32(sbuf, 0)
		n, err = s0.WriteSCTP(sbuf, PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(sbuf), "unexpected length of received data")

		binary.BigEndian.PutUint32(sbuf, 1)
		n, err = s0.WriteSCTP(sbuf, PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(sbuf), "unexpected length of received data")

		br.Process()

		buf := make([]byte, 2000)

		n, ppi, err = s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, n, len(sbuf), "unexpected length of received data")
		assert.Equal(t, uint32(1), binary.BigEndian.Uint32(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.Process()

		n, ppi, err = s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}

		assert.Equal(t, n, len(sbuf), "unexpected length of received data")
		assert.Equal(t, uint32(0), binary.BigEndian.Uint32(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.Process()
		assert.False(t, s0.reassemblyQueue.isReadable(), "should no longer be readable")
		closeAssociationPair(br, a0, a1)
	})

	t.Run("retransmission", func(t *testing.T) {
		const si uint16 = 6
		const msg1 = "ABC"
		const msg2 = "DEFG"
		var n int
		var ppi PayloadProtocolIdentifier
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		// lock RTO value at 100 [msec]
		a0.rtoMgr.setRTO(100.0, true)

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		n, err = s0.WriteSCTP([]byte(msg1), PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(msg1), "unexpected length of received data")
		n, err = s0.WriteSCTP([]byte(msg2), PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(msg2), "unexpected length of received data")

		br.Drop(0, 0, 1) // drop the first packet (second one should be sacked)

		// process packets for 200 msec
		for i := 0; i < 20; i++ {
			br.Tick()
			time.Sleep(10 * time.Millisecond)
		}

		buf := make([]byte, 32)

		n, ppi, err = s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, n, len(msg1), "unexpected length of received data")
		assert.Equal(t, msg1, string(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		n, ppi, err = s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, n, len(msg2), "unexpected length of received data")
		assert.Equal(t, msg2, string(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.Process()
		assert.False(t, s0.reassemblyQueue.isReadable(), "should no longer be readable")
		closeAssociationPair(br, a0, a1)
	})
}

func TestAssocUnreliable(t *testing.T) {
	// sbuf1, sbuf2:
	//    large enogh to be fragmented into two chunks and each chunks are
	//    large enobh not to be bundled
	sbuf1 := make([]byte, 2000)
	sbuf2 := make([]byte, 2000)
	for i := 0; i < len(sbuf1); i++ {
		sbuf1[i] = byte(i & 0xff)
	}
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(sbuf1), func(i, j int) { sbuf1[i], sbuf1[j] = sbuf1[j], sbuf1[i] })
	for i := 0; i < len(sbuf2); i++ {
		sbuf2[i] = byte(i & 0xff)
	}
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(sbuf2), func(i, j int) { sbuf2[i], sbuf2[j] = sbuf2[j], sbuf2[i] })

	// sbuf - small enogh not to be fragmented
	//        large enobh not to be bundled
	sbuf := make([]byte, 1000)
	for i := 0; i < len(sbuf); i++ {
		sbuf[i] = byte(i & 0xff)
	}
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(sbuf), func(i, j int) { sbuf[i], sbuf[j] = sbuf[j], sbuf[i] })

	t.Run("Rexmit ordered no fragment", func(t *testing.T) {
		const si uint16 = 1
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		// When we set the reliability value to 0 [times], then it will cause
		// the chunk to be abandoned immediately after the first transmission.
		s0.SetReliabilityParams(false, ReliabilityTypeRexmit, 0)
		s1.SetReliabilityParams(false, ReliabilityTypeRexmit, 0) // doesn't matter

		br.DropNextNWrites(0, 1) // drop the first packet (second one should be sacked)

		var n int
		binary.BigEndian.PutUint32(sbuf, uint32(0))
		n, err = s0.WriteSCTP(sbuf, PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(sbuf), n, "unexpected length of written data")

		binary.BigEndian.PutUint32(sbuf, uint32(1))
		n, err = s0.WriteSCTP(sbuf, PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(sbuf), n, "unexpected length of written data")

		br.Process()

		buf := make([]byte, 2000)
		n, ppi, err := s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		// should receive the second one only
		assert.Equal(t, len(sbuf), n, "unexpected length of written data")
		assert.Equal(t, uint32(1), binary.BigEndian.Uint32(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.Process()
		assert.False(t, s0.reassemblyQueue.isReadable(), "should no longer be readable")
		closeAssociationPair(br, a0, a1)
	})

	t.Run("Rexmit ordered fragments", func(t *testing.T) {
		const si uint16 = 1
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		// lock RTO value at 100 [msec]
		a0.rtoMgr.setRTO(100.0, true)

		// When we set the reliability value to 0 [times], then it will cause
		// the chunk to be abandoned immediately after the first transmission.
		s0.SetReliabilityParams(false, ReliabilityTypeRexmit, 0)
		s1.SetReliabilityParams(false, ReliabilityTypeRexmit, 0) // doesn't matter

		br.DropNextNWrites(0, 1) // drop the first fragment of the first chunk (second chunk should be sacked)

		var n int
		n, err = s0.WriteSCTP(sbuf1, PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(sbuf1), n, "unexpected length of written data")

		n, err = s0.WriteSCTP(sbuf2, PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(sbuf2), n, "unexpected length of written data")

		br.Process()

		rbuf := make([]byte, 2000)
		n, ppi, err := s1.ReadSCTP(rbuf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		// should receive the second one only
		assert.Equal(t, sbuf2, rbuf[:n], "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.Process()

		assert.False(t, s0.reassemblyQueue.isReadable(), "should no longer be readable")
		assert.Equal(t, 0, len(s0.reassemblyQueue.ordered), "should be nothing in the ordered queue")
		closeAssociationPair(br, a0, a1)
	})

	t.Run("Rexmit unordered no fragment", func(t *testing.T) {
		const si uint16 = 2
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		// When we set the reliability value to 0 [times], then it will cause
		// the chunk to be abandoned immediately after the first transmission.
		s0.SetReliabilityParams(true, ReliabilityTypeRexmit, 0)
		s1.SetReliabilityParams(true, ReliabilityTypeRexmit, 0) // doesn't matter

		br.DropNextNWrites(0, 1) // drop the first packet (second one should be sacked)

		var n int
		binary.BigEndian.PutUint32(sbuf, uint32(0))
		n, err = s0.WriteSCTP(sbuf, PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(sbuf), n, "unexpected length of written data")

		binary.BigEndian.PutUint32(sbuf, uint32(1))
		n, err = s0.WriteSCTP(sbuf, PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(sbuf), n, "unexpected length of written data")

		br.Process()

		buf := make([]byte, 2000)
		n, ppi, err := s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		// should receive the second one only
		assert.Equal(t, len(sbuf), n, "unexpected length of written data")
		assert.Equal(t, uint32(1), binary.BigEndian.Uint32(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.Process()
		assert.False(t, s0.reassemblyQueue.isReadable(), "should no longer be readable")
		closeAssociationPair(br, a0, a1)
	})

	t.Run("Rexmit unordered fragments", func(t *testing.T) {
		const si uint16 = 1
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		// When we set the reliability value to 0 [times], then it will cause
		// the chunk to be abandoned immediately after the first transmission.
		s0.SetReliabilityParams(true, ReliabilityTypeRexmit, 0)
		s1.SetReliabilityParams(true, ReliabilityTypeRexmit, 0) // doesn't matter

		var n int
		n, err = s0.WriteSCTP(sbuf1, PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(sbuf1), n, "unexpected length of written data")

		n, err = s0.WriteSCTP(sbuf2, PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(sbuf2), n, "unexpected length of written data")

		time.Sleep(10 * time.Millisecond)
		br.Drop(0, 0, 2) // drop the second fragment of the first chunk (second chunk should be sacked)
		br.Process()

		rbuf := make([]byte, 2000)
		n, ppi, err := s1.ReadSCTP(rbuf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		// should receive the second one only
		assert.Equal(t, sbuf2, rbuf[:n], "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.Process()

		assert.False(t, s0.reassemblyQueue.isReadable(), "should no longer be readable")
		assert.Equal(t, 0, len(s0.reassemblyQueue.unordered), "should be nothing in the unordered queue")
		assert.Equal(t, 0, len(s0.reassemblyQueue.unorderedChunks), "should be nothing in the unorderedChunks list")
		closeAssociationPair(br, a0, a1)
	})

	t.Run("Timed ordered", func(t *testing.T) {
		const si uint16 = 3
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		// When we set the reliability value to 0 [msec], then it will cause
		// the chunk to be abandoned immediately after the first transmission.
		s0.SetReliabilityParams(false, ReliabilityTypeTimed, 0)
		s1.SetReliabilityParams(false, ReliabilityTypeTimed, 0) // doesn't matter

		br.DropNextNWrites(0, 1) // drop the first packet (second one should be sacked)

		var n int
		binary.BigEndian.PutUint32(sbuf, uint32(0))
		n, err = s0.WriteSCTP(sbuf, PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(sbuf), n, "unexpected length of written data")

		binary.BigEndian.PutUint32(sbuf, uint32(1))
		n, err = s0.WriteSCTP(sbuf, PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(sbuf), n, "unexpected length of written data")

		//br.Drop(0, 0, 1) // drop the first packet (second one should be sacked)
		br.Process()

		buf := make([]byte, 2000)
		n, ppi, err := s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		// should receive the second one only
		assert.Equal(t, len(sbuf), n, "unexpected length of written data")
		assert.Equal(t, uint32(1), binary.BigEndian.Uint32(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.Process()
		assert.False(t, s0.reassemblyQueue.isReadable(), "should no longer be readable")
		closeAssociationPair(br, a0, a1)
	})

	t.Run("Timed unordered", func(t *testing.T) {
		const si uint16 = 3
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		// When we set the reliability value to 0 [msec], then it will cause
		// the chunk to be abandoned immediately after the first transmission.
		s0.SetReliabilityParams(true, ReliabilityTypeTimed, 0)
		s1.SetReliabilityParams(true, ReliabilityTypeTimed, 0) // doesn't matter

		br.DropNextNWrites(0, 1) // drop the first packet (second one should be sacked)

		var n int
		binary.BigEndian.PutUint32(sbuf, uint32(0))
		n, err = s0.WriteSCTP(sbuf, PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(sbuf), n, "unexpected length of written data")

		binary.BigEndian.PutUint32(sbuf, uint32(1))
		n, err = s0.WriteSCTP(sbuf, PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(sbuf), n, "unexpected length of written data")

		br.Process()

		buf := make([]byte, 2000)
		n, ppi, err := s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		// should receive the second one only
		assert.Equal(t, len(sbuf), n, "unexpected length of written data")
		assert.Equal(t, uint32(1), binary.BigEndian.Uint32(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.Process()
		assert.False(t, s0.reassemblyQueue.isReadable(), "should no longer be readable")
		assert.Equal(t, 0, len(s0.reassemblyQueue.unordered), "should be nothing in the unordered queue")
		assert.Equal(t, 0, len(s0.reassemblyQueue.unorderedChunks), "should be nothing in the unorderedChunks list")
		closeAssociationPair(br, a0, a1)
	})
}

func TestCreateForwardTSN(t *testing.T) {
	loggerFactory := logging.NewDefaultLoggerFactory()

	t.Run("forward one abandoned", func(t *testing.T) {
		a := createAssociation(Config{
			NetConn:       &dumbConn{},
			LoggerFactory: loggerFactory,
		})

		a.cumulativeTSNAckPoint = 9
		a.advancedPeerTSNAckPoint = 10
		a.inflightQueue.pushNoCheck(&chunkPayloadData{
			beginningFragment:    true,
			endingFragment:       true,
			tsn:                  10,
			streamIdentifier:     1,
			streamSequenceNumber: 2,
			userData:             []byte("ABC"),
			nSent:                1,
			abandoned:            true,
		})

		fwdtsn := a.createForwardTSN()

		assert.Equal(t, uint32(10), fwdtsn.newCumulativeTSN, "should be able to serialize")
		assert.Equal(t, 1, len(fwdtsn.streams), "there should be one stream")
		assert.Equal(t, uint16(1), fwdtsn.streams[0].identifier, "si should be 1")
		assert.Equal(t, uint16(2), fwdtsn.streams[0].sequence, "ssn should be 2")
	})

	t.Run("forward two abandoned with the same SI", func(t *testing.T) {
		a := createAssociation(Config{
			NetConn:       &dumbConn{},
			LoggerFactory: loggerFactory,
		})

		a.cumulativeTSNAckPoint = 9
		a.advancedPeerTSNAckPoint = 12
		a.inflightQueue.pushNoCheck(&chunkPayloadData{
			beginningFragment:    true,
			endingFragment:       true,
			tsn:                  10,
			streamIdentifier:     1,
			streamSequenceNumber: 2,
			userData:             []byte("ABC"),
			nSent:                1,
			abandoned:            true,
		})
		a.inflightQueue.pushNoCheck(&chunkPayloadData{
			beginningFragment:    true,
			endingFragment:       true,
			tsn:                  11,
			streamIdentifier:     1,
			streamSequenceNumber: 3,
			userData:             []byte("DEF"),
			nSent:                1,
			abandoned:            true,
		})
		a.inflightQueue.pushNoCheck(&chunkPayloadData{
			beginningFragment:    true,
			endingFragment:       true,
			tsn:                  12,
			streamIdentifier:     2,
			streamSequenceNumber: 1,
			userData:             []byte("123"),
			nSent:                1,
			abandoned:            true,
		})

		fwdtsn := a.createForwardTSN()

		assert.Equal(t, uint32(12), fwdtsn.newCumulativeTSN, "should be able to serialize")
		assert.Equal(t, 2, len(fwdtsn.streams), "there should be two stream")

		si1OK := false
		si2OK := false
		for _, s := range fwdtsn.streams {
			if s.identifier == 1 {
				assert.Equal(t, uint16(3), s.sequence, "ssn should be 3")
				si1OK = true
			} else if s.identifier == 2 {
				assert.Equal(t, uint16(1), s.sequence, "ssn should be 1")
				si2OK = true
			} else {
				assert.Fail(t, "unexpected stream indentifier")
			}
		}
		assert.True(t, si1OK, "si=1 should be present")
		assert.True(t, si2OK, "si=2 should be present")
	})
}

func TestHandleForwardTSN(t *testing.T) {
	loggerFactory := logging.NewDefaultLoggerFactory()

	t.Run("forward 3 unreceived chunks", func(t *testing.T) {
		a := createAssociation(Config{
			NetConn:       &dumbConn{},
			LoggerFactory: loggerFactory,
		})
		a.useForwardTSN = true
		prevTSN := a.peerLastTSN

		fwdtsn := &chunkForwardTSN{
			newCumulativeTSN: a.peerLastTSN + 3,
			streams:          []chunkForwardTSNStream{{identifier: 0, sequence: 0}},
		}

		p := a.handleForwardTSN(fwdtsn)

		assert.Equal(t, a.peerLastTSN, prevTSN+3, "peerLastTSN should advance by 3 ")
		assert.Equal(t, ackStateDelay, a.ackState, "delayed sack should be requested")
		assert.Nil(t, p, "should return nil")
	})

	t.Run("forward 1 for 1 missing", func(t *testing.T) {
		a := createAssociation(Config{
			NetConn:       &dumbConn{},
			LoggerFactory: loggerFactory,
		})
		a.useForwardTSN = true
		prevTSN := a.peerLastTSN

		// this chunk is blocked by the missing chunk at tsn=1
		a.payloadQueue.push(&chunkPayloadData{
			beginningFragment:    true,
			endingFragment:       true,
			tsn:                  a.peerLastTSN + 2,
			streamIdentifier:     0,
			streamSequenceNumber: 1,
			userData:             []byte("ABC"),
		}, a.peerLastTSN)

		fwdtsn := &chunkForwardTSN{
			newCumulativeTSN: a.peerLastTSN + 1,
			streams: []chunkForwardTSNStream{
				{identifier: 0, sequence: 1},
			},
		}

		p := a.handleForwardTSN(fwdtsn)

		assert.Equal(t, a.peerLastTSN, prevTSN+2, "peerLastTSN should advance by 3")
		assert.Equal(t, ackStateDelay, a.ackState, "delayed sack should be requested")
		assert.Nil(t, p, "should return nil")
	})

	t.Run("forward 1 for 2 missing", func(t *testing.T) {
		a := createAssociation(Config{
			NetConn:       &dumbConn{},
			LoggerFactory: loggerFactory,
		})
		a.useForwardTSN = true
		prevTSN := a.peerLastTSN

		// this chunk is blocked by the missing chunk at tsn=1
		a.payloadQueue.push(&chunkPayloadData{
			beginningFragment:    true,
			endingFragment:       true,
			tsn:                  a.peerLastTSN + 3,
			streamIdentifier:     0,
			streamSequenceNumber: 1,
			userData:             []byte("ABC"),
		}, a.peerLastTSN)

		fwdtsn := &chunkForwardTSN{
			newCumulativeTSN: a.peerLastTSN + 1,
			streams: []chunkForwardTSNStream{
				{identifier: 0, sequence: 1},
			},
		}

		p := a.handleForwardTSN(fwdtsn)

		assert.Equal(t, a.peerLastTSN, prevTSN+1, "peerLastTSN should advance by 1")
		assert.Equal(t, ackStateImmediate, a.ackState, "immediate sack should be requested")
		assert.Nil(t, p, "should return nil")
	})

	t.Run("dup forward TSN chunk should generate sack", func(t *testing.T) {
		a := createAssociation(Config{
			NetConn:       &dumbConn{},
			LoggerFactory: loggerFactory,
		})
		a.useForwardTSN = true
		prevTSN := a.peerLastTSN

		fwdtsn := &chunkForwardTSN{
			newCumulativeTSN: a.peerLastTSN, // old TSN
			streams: []chunkForwardTSNStream{
				{identifier: 0, sequence: 1},
			},
		}

		p := a.handleForwardTSN(fwdtsn)

		assert.Equal(t, a.peerLastTSN, prevTSN, "peerLastTSN should not advance")
		assert.Equal(t, ackStateImmediate, a.ackState, "sack should be requested")
		assert.Nil(t, p, "should return nil")
	})
}

func TestAssocT1InitTimer(t *testing.T) {
	loggerFactory := logging.NewDefaultLoggerFactory()

	t.Run("Retransmission success", func(t *testing.T) {
		br := test.NewBridge()
		a0 := createAssociation(Config{
			NetConn:       br.GetConn0(),
			LoggerFactory: loggerFactory,
		})
		a1 := createAssociation(Config{
			NetConn:       br.GetConn1(),
			LoggerFactory: loggerFactory,
		})

		var err0, err1 error
		a0ReadyCh := make(chan bool)
		a1ReadyCh := make(chan bool)

		assert.Equal(t, rtoInitial, a0.rtoMgr.getRTO())
		assert.Equal(t, rtoInitial, a1.rtoMgr.getRTO())

		// modified rto for fast test
		a0.rtoMgr.setRTO(20, false)

		go func() {
			err0 = <-a0.handshakeCompletedCh
			a0ReadyCh <- true
		}()

		go func() {
			err1 = <-a1.handshakeCompletedCh
			a1ReadyCh <- true
		}()

		// Drop the first write
		br.DropNextNWrites(0, 1)

		// Start the handlshake
		a0.init(true)
		a1.init(true)

		a0Ready := false
		a1Ready := false
		for !a0Ready || !a1Ready {
			br.Process()

			select {
			case a0Ready = <-a0ReadyCh:
			case a1Ready = <-a1ReadyCh:
			default:
			}
		}

		assert.Nil(t, err0, "should be nil")
		assert.Nil(t, err1, "should be nil")

		_ = a0.Close() // #nosec
		_ = a1.Close() // #nosec
	})

	t.Run("Retransmission failure", func(t *testing.T) {
		br := test.NewBridge()
		a0 := createAssociation(Config{
			NetConn:       br.GetConn0(),
			LoggerFactory: loggerFactory,
		})
		a1 := createAssociation(Config{
			NetConn:       br.GetConn1(),
			LoggerFactory: loggerFactory,
		})

		var err0, err1 error
		a0ReadyCh := make(chan bool)
		a1ReadyCh := make(chan bool)

		assert.Equal(t, rtoInitial, a0.rtoMgr.getRTO())
		assert.Equal(t, rtoInitial, a1.rtoMgr.getRTO())

		// modified rto for fast test
		a0.rtoMgr.setRTO(20, false)
		a1.rtoMgr.setRTO(20, false)

		// fail after 4 retransmission
		a0.t1Init.maxRetrans = 4
		a1.t1Init.maxRetrans = 4

		go func() {
			err0 = <-a0.handshakeCompletedCh
			a0ReadyCh <- true
		}()

		go func() {
			err1 = <-a1.handshakeCompletedCh
			a1ReadyCh <- true
		}()

		// Drop all INIT
		br.DropNextNWrites(0, 99)
		br.DropNextNWrites(1, 99)

		// Start the handlshake
		a0.init(true)
		a1.init(true)

		a0Ready := false
		a1Ready := false
		for !a0Ready || !a1Ready {
			br.Process()

			select {
			case a0Ready = <-a0ReadyCh:
			case a1Ready = <-a1ReadyCh:
			default:
			}
		}

		assert.NotNil(t, err0, "should NOT be nil")
		assert.NotNil(t, err1, "should NOT be nil")

		_ = a0.Close() // #nosec
		_ = a1.Close() // #nosec
	})
}

func TestAssocT1CookieTimer(t *testing.T) {
	loggerFactory := logging.NewDefaultLoggerFactory()

	t.Run("Retransmission success", func(t *testing.T) {
		br := test.NewBridge()
		a0 := createAssociation(Config{
			NetConn:       br.GetConn0(),
			LoggerFactory: loggerFactory,
		})
		a1 := createAssociation(Config{
			NetConn:       br.GetConn1(),
			LoggerFactory: loggerFactory,
		})

		var err0, err1 error
		a0ReadyCh := make(chan bool)
		a1ReadyCh := make(chan bool)

		assert.Equal(t, rtoInitial, a0.rtoMgr.getRTO())
		assert.Equal(t, rtoInitial, a1.rtoMgr.getRTO())

		// modified rto for fast test
		a0.rtoMgr.setRTO(20, false)

		go func() {
			err0 = <-a0.handshakeCompletedCh
			a0ReadyCh <- true
		}()

		go func() {
			err1 = <-a1.handshakeCompletedCh
			a1ReadyCh <- true
		}()

		// Start the handlshake
		a0.init(true)
		a1.init(true)

		// Let the INIT go.
		br.Tick()

		// Drop COOKIE-ECHO
		br.DropNextNWrites(0, 1)

		a0Ready := false
		a1Ready := false
		for !a0Ready || !a1Ready {
			br.Process()

			select {
			case a0Ready = <-a0ReadyCh:
			case a1Ready = <-a1ReadyCh:
			default:
			}
		}

		assert.Nil(t, err0, "should be nil")
		assert.Nil(t, err1, "should be nil")

		_ = a0.Close() // #nosec
		_ = a1.Close() // #nosec
	})

	t.Run("Retransmission failure", func(t *testing.T) {
		br := test.NewBridge()
		a0 := createAssociation(Config{
			NetConn:       br.GetConn0(),
			LoggerFactory: loggerFactory,
		})
		a1 := createAssociation(Config{
			NetConn:       br.GetConn1(),
			LoggerFactory: loggerFactory,
		})

		var err0 error
		a0ReadyCh := make(chan bool)

		assert.Equal(t, rtoInitial, a0.rtoMgr.getRTO())
		assert.Equal(t, rtoInitial, a1.rtoMgr.getRTO())

		// modified rto for fast test
		a0.rtoMgr.setRTO(20, false)
		// fail after 4 retransmission
		a0.t1Cookie.maxRetrans = 4

		go func() {
			err0 = <-a0.handshakeCompletedCh
			a0ReadyCh <- true
		}()

		// Drop all COOKIE-ECHO
		br.Filter(0, func(raw []byte) bool {
			p := &packet{}
			err := p.unmarshal(raw)
			if !assert.Nil(t, err, "failed to parse packet") {
				return false // drop
			}
			for _, c := range p.chunks {
				switch c.(type) {
				case *chunkCookieEcho:
					return false // drop
				}
			}
			return true
		})

		// Start the handlshake
		a0.init(true)
		a1.init(false)

		a0Ready := false
		for !a0Ready {
			br.Process()

			select {
			case a0Ready = <-a0ReadyCh:
			default:
			}
		}

		assert.NotNil(t, err0, "should be an error")

		time.Sleep(1000 * time.Millisecond)
		br.Process()

		_ = a0.Close() // #nosec
		_ = a1.Close() // #nosec
	})
}

func TestAssocCreateNewStream(t *testing.T) {
	loggerFactory := logging.NewDefaultLoggerFactory()

	t.Run("acceptChSize", func(t *testing.T) {
		a := createAssociation(Config{
			NetConn:       &dumbConn{},
			LoggerFactory: loggerFactory,
		})

		for i := 0; i < acceptChSize; i++ {
			s := a.createStream(uint16(i), true)
			_, ok := a.streams[s.streamIdentifier]
			assert.True(t, ok, "should be in a.streams map")
		}

		newSI := uint16(acceptChSize)
		s := a.createStream(newSI, true)
		assert.Nil(t, s, "should be nil")
		_, ok := a.streams[newSI]
		assert.False(t, ok, "should NOT be in a.streams map")

		toBeIgnored := &chunkPayloadData{
			beginningFragment: true,
			endingFragment:    true,
			tsn:               a.peerLastTSN + 1,
			streamIdentifier:  newSI,
			userData:          []byte("ABC"),
		}

		p := a.handleData(toBeIgnored)
		assert.Nil(t, p, "should be nil")
	})
}

func TestAssocT3RtxTimer(t *testing.T) {
	// Send one packet, drop it, then retransmitted successfully.
	t.Run("Retransmission success", func(t *testing.T) {
		const si uint16 = 6
		const msg1 = "ABC"
		var n int
		var ppi PayloadProtocolIdentifier
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		// lock RTO value at 20 [msec]
		a0.rtoMgr.setRTO(20.0, false)
		a0.rtoMgr.noUpdate = true

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		n, err = s0.WriteSCTP([]byte(msg1), PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(msg1), "unexpected length of received data")

		br.Drop(0, 0, 1) // drop the first packet (second one should be sacked)

		// process packets for 100 msec
		for i := 0; i < 10; i++ {
			br.Tick()
			time.Sleep(10 * time.Millisecond)
		}

		buf := make([]byte, 32)

		n, ppi, err = s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, n, len(msg1), "unexpected length of received data")
		assert.Equal(t, msg1, string(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.Process()
		assert.False(t, s0.reassemblyQueue.isReadable(), "should no longer be readable")
		a0.lock.RLock()
		assert.Equal(t, 0, a0.pendingQueue.size(), "should be no packet pending")
		assert.Equal(t, 0, a0.inflightQueue.size(), "should be no packet inflight")
		a0.lock.RUnlock()

		closeAssociationPair(br, a0, a1)
	})
}

func TestAssocCongestionControl(t *testing.T) {
	// sbuf - large enobh not to be bundled
	sbuf := make([]byte, 1000)
	for i := 0; i < len(sbuf); i++ {
		sbuf[i] = byte(i & 0xcc)
	}

	// 1) Send 4 packets. drop the first one.
	// 2) Last 3 packet will be received, which triggers fast-retransmission
	// 3) The first one is retransmitted, which makes s1 readable
	// Above should be done before RTO occurs (fast recovery)
	t.Run("Fast retransmission", func(t *testing.T) {
		const si uint16 = 6
		var n int
		var ppi PayloadProtocolIdentifier
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNormal)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		br.DropNextNWrites(0, 1) // drop the next write

		for i := 0; i < 4; i++ {
			binary.BigEndian.PutUint32(sbuf, uint32(i)) // uint32 sequence number
			n, err = s0.WriteSCTP(sbuf, PayloadTypeWebRTCBinary)
			assert.Nil(t, err, "WriteSCTP failed")
			assert.Equal(t, n, len(sbuf), "unexpected length of received data")
		}

		// process packets for 500 msec, assuming that the fast retrans/recover
		// should complete within 500 msec.
		for i := 0; i < 50; i++ {
			br.Tick()
			time.Sleep(10 * time.Millisecond)
		}

		rbuf := make([]byte, 3000)

		// Try to read all 4 packets
		for i := 0; i < 4; i++ {
			// The receiver (s1) should be readable
			s1.lock.RLock()
			readable := s1.reassemblyQueue.isReadable()
			s1.lock.RUnlock()

			if !assert.True(t, readable, "should be readable") {
				return
			}

			n, ppi, err = s1.ReadSCTP(rbuf)
			if !assert.Nil(t, err, "ReadSCTP failed") {
				return
			}
			assert.Equal(t, len(sbuf), n, "unexpected length of received data")
			assert.Equal(t, i, int(binary.BigEndian.Uint32(rbuf)), "unexpected length of received data")
			assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")
		}

		a0.lock.RLock()
		inFastRecovery := a0.inFastRecovery
		a0.lock.RUnlock()
		assert.False(t, inFastRecovery, "should not be in fast-recovery")

		t.Logf("nDATAs      : %d\n", a1.stats.getNumDATAs())
		t.Logf("nSACKs      : %d\n", a0.stats.getNumSACKs())
		t.Logf("nAckTimeouts: %d\n", a1.stats.getNumAckTimeouts())
		t.Logf("nFastRetrans: %d\n", a0.stats.getNumFastRetrans())

		assert.Equal(t, uint64(1), a0.stats.getNumFastRetrans(), "should be 1")

		closeAssociationPair(br, a0, a1)
	})

	t.Run("Congestion Avoidance", func(t *testing.T) {
		const si uint16 = 6
		const nPacketsToSend = 2000
		var n int
		var nPacketsReceived int
		var ppi PayloadProtocolIdentifier
		rbuf := make([]byte, 3000)

		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNormal)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		a0.stats.reset()
		a1.stats.reset()

		for i := 0; i < nPacketsToSend; i++ {
			binary.BigEndian.PutUint32(sbuf, uint32(i)) // uint32 sequence number
			n, err = s0.WriteSCTP(sbuf, PayloadTypeWebRTCBinary)
			assert.Nil(t, err, "WriteSCTP failed")
			assert.Equal(t, n, len(sbuf), "unexpected length of received data")
		}

		// Repeat calling br.Tick() until the buffered amount becomes 0
		for s0.BufferedAmount() > 0 && nPacketsReceived < nPacketsToSend {
			for {
				n = br.Tick()
				if n == 0 {
					break
				}
			}

			for {
				s1.lock.RLock()
				readable := s1.reassemblyQueue.isReadable()
				s1.lock.RUnlock()
				if !readable {
					break
				}
				n, ppi, err = s1.ReadSCTP(rbuf)
				if !assert.Nil(t, err, "ReadSCTP failed") {
					return
				}
				assert.Equal(t, len(sbuf), n, "unexpected length of received data")
				assert.Equal(t, nPacketsReceived, int(binary.BigEndian.Uint32(rbuf)), "unexpected length of received data")
				assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

				nPacketsReceived++
			}
		}

		br.Process()

		a0.lock.RLock()
		inFastRecovery := a0.inFastRecovery
		cwnd := a0.cwnd
		ssthresh := a0.ssthresh
		a0.lock.RUnlock()
		assert.False(t, inFastRecovery, "should not be in fast-recovery")
		assert.True(t, cwnd > ssthresh, "should be in congestion avoidance mode")
		assert.True(t, ssthresh >= maxReceiveBufferSize, "should not be less than the initial size of 128KB")

		assert.Equal(t, nPacketsReceived, nPacketsToSend, "unexpected num of packets received")
		assert.Equal(t, 0, s1.getNumBytesInReassemblyQueue(), "reassembly queue should be empty")

		t.Logf("nDATAs      : %d\n", a1.stats.getNumDATAs())
		t.Logf("nSACKs      : %d\n", a0.stats.getNumSACKs())
		t.Logf("nT3Timeouts : %d\n", a0.stats.getNumT3Timeouts())

		assert.Equal(t, uint64(nPacketsToSend), a1.stats.getNumDATAs(), "packet count mismatch")
		assert.True(t, a0.stats.getNumSACKs() < nPacketsToSend/20, "too many sacks")
		assert.Equal(t, uint64(0), a0.stats.getNumT3Timeouts(), "should be no retransmit")

		closeAssociationPair(br, a0, a1)
	})

	// This is to test even rwnd becomes 0, sender should be able to send a zero window probe
	// on T3-rtx retramission timeout to complete receiving all the packets.
	t.Run("Slow reader", func(t *testing.T) {
		const si uint16 = 6
		nPacketsToSend := int(math.Floor(float64(maxReceiveBufferSize)/1000.0)) * 2
		var n int
		var nPacketsReceived int
		var ppi PayloadProtocolIdentifier
		rbuf := make([]byte, 3000)

		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		for i := 0; i < nPacketsToSend; i++ {
			binary.BigEndian.PutUint32(sbuf, uint32(i)) // uint32 sequence number
			n, err = s0.WriteSCTP(sbuf, PayloadTypeWebRTCBinary)
			assert.Nil(t, err, "WriteSCTP failed")
			assert.Equal(t, n, len(sbuf), "unexpected length of received data")
		}

		// 1. First forward packets to receiver until rwnd becomes 0
		// 2. Wait until the sender's cwnd becomes 1*MTU (RTO occurred)
		// 3. Stat reading a1's data
		var hasRTOed bool
		for s0.BufferedAmount() > 0 && nPacketsReceived < nPacketsToSend {
			for {
				n = br.Tick()
				if n == 0 {
					break
				}
			}

			if !hasRTOed {
				a1.lock.RLock()
				rwnd := a1.getMyReceiverWindowCredit()
				a1.lock.RUnlock()
				a0.lock.RLock()
				cwnd := a0.cwnd
				a0.lock.RUnlock()
				if cwnd > a0.mtu || rwnd > 0 {
					// Do not read until a1.getMyReceiverWindowCredit() becomes zero
					continue
				}

				hasRTOed = true
			}

			for {
				s1.lock.RLock()
				readable := s1.reassemblyQueue.isReadable()
				s1.lock.RUnlock()
				if !readable {
					break
				}
				n, ppi, err = s1.ReadSCTP(rbuf)
				if !assert.Nil(t, err, "ReadSCTP failed") {
					return
				}
				assert.Equal(t, len(sbuf), n, "unexpected length of received data")
				assert.Equal(t, nPacketsReceived, int(binary.BigEndian.Uint32(rbuf)), "unexpected length of received data")
				assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

				nPacketsReceived++
			}

			time.Sleep(4 * time.Millisecond)
		}

		br.Process()

		assert.Equal(t, nPacketsReceived, nPacketsToSend, "unexpected num of packets received")
		assert.Equal(t, 0, s1.getNumBytesInReassemblyQueue(), "reassembly queue should be empty")

		t.Logf("nDATAs      : %d\n", a1.stats.getNumDATAs())
		t.Logf("nSACKs      : %d\n", a0.stats.getNumSACKs())
		t.Logf("nAckTimeouts: %d\n", a1.stats.getNumAckTimeouts())

		closeAssociationPair(br, a0, a1)
	})
}

func TestAssocDelayedAck(t *testing.T) {
	t.Run("Ack all DATA chunks with one SACK", func(t *testing.T) {
		const si uint16 = 6
		var n int
		var nPacketsReceived int
		var ppi PayloadProtocolIdentifier
		sbuf := make([]byte, 4000) // size should be less than initial cwnd (4380)
		rbuf := make([]byte, 4000)

		_, err := cryptoRand.Read(sbuf)
		if !assert.Nil(t, err, "failed to create associations") {
			return
		}

		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeAlwaysDelay)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		a0.stats.reset()
		a1.stats.reset()

		// Writes data (will fragmented)
		n, err = s0.WriteSCTP(sbuf, PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(sbuf), "unexpected length of received data")

		// Repeat calling br.Tick() until the buffered amount becomes 0
		for s0.BufferedAmount() > 0 {
			for {
				n = br.Tick()
				if n == 0 {
					break
				}
			}

			for {
				s1.lock.RLock()
				readable := s1.reassemblyQueue.isReadable()
				s1.lock.RUnlock()
				if !readable {
					break
				}
				n, ppi, err = s1.ReadSCTP(rbuf)
				if !assert.Nil(t, err, "ReadSCTP failed") {
					return
				}
				assert.Equal(t, len(sbuf), n, "unexpected length of received data")
				assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

				nPacketsReceived++
			}
		}

		br.Process()

		assert.Equal(t, 1, nPacketsReceived, "should be one packet received")
		assert.Equal(t, 0, s1.getNumBytesInReassemblyQueue(), "reassembly queue should be empty")

		t.Logf("nDATAs      : %d\n", a1.stats.getNumDATAs())
		t.Logf("nSACKs      : %d\n", a0.stats.getNumSACKs())
		t.Logf("nAckTimeouts: %d\n", a1.stats.getNumAckTimeouts())

		assert.Equal(t, uint64(4), a1.stats.getNumDATAs(), "DATA chunk count mismatch")
		assert.Equal(t, uint64(1), a0.stats.getNumSACKs(), "sack count should be one")
		assert.Equal(t, uint64(1), a1.stats.getNumAckTimeouts(), "ackTimeout count mismatch")
		assert.Equal(t, uint64(0), a0.stats.getNumT3Timeouts(), "should be no retransmit")

		closeAssociationPair(br, a0, a1)
	})
}
