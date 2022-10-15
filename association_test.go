//go:build !js
// +build !js

package sctp

import (
	"context"
	cryptoRand "crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	errHandshakeFailed       = errors.New("handshake failed")
	errSINotMatch            = errors.New("SI should match")
	errReadData              = errors.New("failed to read data")
	errReceivedDataNot3Bytes = errors.New("received data must by 3 bytes")
	errPPIUnexpected         = errors.New("unexpected ppi")
	errReceivedDataMismatch  = errors.New("received data mismatch")
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

	// Need to Increase once SCTP is more reliable in case of slow reader
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

func createNewAssociationPair(br *test.Bridge, ackMode int, recvBufSize uint32) (*Association, *Association, error) {
	var a0, a1 *Association
	var err0, err1 error
	loggerFactory := logging.NewDefaultLoggerFactory()

	handshake0Ch := make(chan bool)
	handshake1Ch := make(chan bool)

	go func() {
		a0, err0 = Client(Config{
			NetConn:              br.GetConn0(),
			MaxReceiveBufferSize: recvBufSize,
			LoggerFactory:        loggerFactory,
		})
		handshake0Ch <- true
	}()
	go func() {
		a1, err1 = Client(Config{
			NetConn:              br.GetConn1(),
			MaxReceiveBufferSize: recvBufSize,
			LoggerFactory:        loggerFactory,
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
		return nil, nil, errHandshakeFailed
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
		// nolint:errcheck,gosec
		a0.Close()
		close0Ch <- true
	}()
	go func() {
		// nolint:errcheck,gosec
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

	flushBuffers(br, a0, a1)

	s1, err := a1.AcceptStream()
	if err != nil {
		return nil, nil, err
	}

	if s0.streamIdentifier != s1.streamIdentifier {
		return nil, nil, errSINotMatch
	}

	br.Process()

	buf := make([]byte, 1024)
	n, ppi, err := s1.ReadSCTP(buf)
	if err != nil {
		return nil, nil, errReadData
	}

	if n != len(helloMsg) {
		return nil, nil, errReceivedDataNot3Bytes
	}

	if ppi != PayloadTypeWebRTCDCEP {
		return nil, nil, errPPIUnexpected
	}

	if string(buf[:n]) != helloMsg {
		return nil, nil, errReceivedDataMismatch
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
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		const si uint16 = 1
		const msg = "ABC"
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, 0)
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

		flushBuffers(br, a0, a1)

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

	t.Run("ReadDeadline", func(t *testing.T) {
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		const si uint16 = 1
		const msg = "ABC"
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, 0)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		assert.Equal(t, 0, a0.bufferedAmount(), "incorrect bufferedAmount")

		assert.NoError(t, s1.SetReadDeadline(time.Now().Add(time.Millisecond)), "failed to set read deadline")
		buf := make([]byte, 32)
		// First fails
		n, ppi, err := s1.ReadSCTP(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, PayloadProtocolIdentifier(0), ppi)
		assert.True(t, errors.Is(err, os.ErrDeadlineExceeded))
		// Second too
		n, ppi, err = s1.ReadSCTP(buf)
		assert.Equal(t, 0, n)
		assert.Equal(t, PayloadProtocolIdentifier(0), ppi)
		assert.True(t, errors.Is(err, os.ErrDeadlineExceeded))
		assert.NoError(t, s1.SetReadDeadline(time.Time{}), "failed to disable read deadline")

		n, err = s0.WriteSCTP([]byte(msg), PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(msg), n, "unexpected length of received data")
		assert.Equal(t, len(msg), a0.bufferedAmount(), "incorrect bufferedAmount")

		flushBuffers(br, a0, a1)

		n, ppi, err = s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, n, len(msg), "unexpected length of received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		closeAssociationPair(br, a0, a1)
	})

	t.Run("ordered reordered", func(t *testing.T) {
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		const si uint16 = 2
		var n int
		var ppi PayloadProtocolIdentifier
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, 0)
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

	t.Run("ordered fragmented then defragmented", func(t *testing.T) { // nolint:dupl
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		const si uint16 = 3
		var n int
		var ppi PayloadProtocolIdentifier
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, 0)
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

		rbuf := make([]byte, 2000)
		flushBuffers(br, a0, a1)

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

	t.Run("unordered fragmented then defragmented", func(t *testing.T) { // nolint:dupl
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		const si uint16 = 4
		var n int
		var ppi PayloadProtocolIdentifier
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, 0)
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

		rbuf := make([]byte, 2000)
		flushBuffers(br, a0, a1)

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
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		const si uint16 = 5
		var n int
		var ppi PayloadProtocolIdentifier
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, 0)
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

		buf := make([]byte, 2000)
		flushBuffers(br, a0, a1)

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
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		const si uint16 = 6
		const msg1 = "ABC"
		const msg2 = "DEFG"
		var n int
		var ppi PayloadProtocolIdentifier
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, 0)
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

	t.Run("short buffer", func(t *testing.T) {
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		const si uint16 = 1
		const msg = "Hello"
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, 0)
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

		flushBuffers(br, a0, a1)

		buf := make([]byte, 3)
		n, ppi, err := s1.ReadSCTP(buf)
		assert.Equal(t, err, io.ErrShortBuffer, "expected error to be io.ErrShortBuffer")
		assert.Equal(t, n, 0, "unexpected length of received data")
		assert.Equal(t, ppi, PayloadProtocolIdentifier(0), "unexpected ppi")

		assert.False(t, s0.reassemblyQueue.isReadable(), "should no longer be readable")
		assert.Equal(t, 0, a0.bufferedAmount(), "incorrect bufferedAmount")

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

	t.Run("Rexmit ordered no fragment", func(t *testing.T) { // nolint:dupl
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		const si uint16 = 1
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, 0)
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

		flushBuffers(br, a0, a1)

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
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		const si uint16 = 1
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, 0)
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

		flushBuffers(br, a0, a1)

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

	t.Run("Rexmit unordered no fragment", func(t *testing.T) { // nolint:dupl
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		const si uint16 = 2
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, 0)
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

		flushBuffers(br, a0, a1)

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
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		const si uint16 = 1
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, 0)
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
		flushBuffers(br, a0, a1)

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

	t.Run("Timed ordered", func(t *testing.T) { // nolint:dupl
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		const si uint16 = 3
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, 0)
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

		// br.Drop(0, 0, 1) // drop the first packet (second one should be sacked)
		flushBuffers(br, a0, a1)

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
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		const si uint16 = 3
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, 0)
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

		flushBuffers(br, a0, a1)

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
			_abandoned:           true,
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
			_abandoned:           true,
		})
		a.inflightQueue.pushNoCheck(&chunkPayloadData{
			beginningFragment:    true,
			endingFragment:       true,
			tsn:                  11,
			streamIdentifier:     1,
			streamSequenceNumber: 3,
			userData:             []byte("DEF"),
			nSent:                1,
			_abandoned:           true,
		})
		a.inflightQueue.pushNoCheck(&chunkPayloadData{
			beginningFragment:    true,
			endingFragment:       true,
			tsn:                  12,
			streamIdentifier:     2,
			streamSequenceNumber: 1,
			userData:             []byte("123"),
			nSent:                1,
			_abandoned:           true,
		})

		fwdtsn := a.createForwardTSN()

		assert.Equal(t, uint32(12), fwdtsn.newCumulativeTSN, "should be able to serialize")
		assert.Equal(t, 2, len(fwdtsn.streams), "there should be two stream")

		si1OK := false
		si2OK := false
		for _, s := range fwdtsn.streams {
			switch s.identifier {
			case 1:
				assert.Equal(t, uint16(3), s.sequence, "ssn should be 3")
				si1OK = true
			case 2:
				assert.Equal(t, uint16(1), s.sequence, "ssn should be 1")
				si2OK = true
			default:
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

		a.lock.Lock()
		delayedAckTriggered := a.delayedAckTriggered
		immediateAckTriggered := a.immediateAckTriggered
		a.lock.Unlock()
		assert.Equal(t, a.peerLastTSN, prevTSN+3, "peerLastTSN should advance by 3 ")
		assert.True(t, delayedAckTriggered, "delayed sack should be triggered")
		assert.False(t, immediateAckTriggered, "immediate sack should NOT be triggered")
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

		a.lock.Lock()
		delayedAckTriggered := a.delayedAckTriggered
		immediateAckTriggered := a.immediateAckTriggered
		a.lock.Unlock()
		assert.Equal(t, a.peerLastTSN, prevTSN+2, "peerLastTSN should advance by 3")
		assert.True(t, delayedAckTriggered, "delayed sack should be triggered")
		assert.False(t, immediateAckTriggered, "immediate sack should NOT be triggered")
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

		a.lock.Lock()
		immediateAckTriggered := a.immediateAckTriggered
		a.lock.Unlock()
		assert.Equal(t, a.peerLastTSN, prevTSN+1, "peerLastTSN should advance by 1")
		assert.True(t, immediateAckTriggered, "immediate sack should be triggered")

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

		a.lock.Lock()
		ackState := a.ackState
		a.lock.Unlock()
		assert.Equal(t, a.peerLastTSN, prevTSN, "peerLastTSN should not advance")
		assert.Equal(t, ackStateImmediate, ackState, "sack should be requested")
		assert.Nil(t, p, "should return nil")
	})
}

func TestAssocT1InitTimer(t *testing.T) {
	loggerFactory := logging.NewDefaultLoggerFactory()

	t.Run("Retransmission success", func(t *testing.T) {
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

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
		flushBuffers(br, a0, a1)

		assert.Nil(t, err0, "should be nil")
		assert.Nil(t, err1, "should be nil")

		closeAssociationPair(br, a0, a1)
	})

	t.Run("Retransmission failure", func(t *testing.T) {
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

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

		closeAssociationPair(br, a0, a1)
	})
}

func TestAssocT1CookieTimer(t *testing.T) {
	loggerFactory := logging.NewDefaultLoggerFactory()

	t.Run("Retransmission success", func(t *testing.T) {
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

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

		closeAssociationPair(br, a0, a1)
	})

	t.Run("Retransmission failure", func(t *testing.T) {
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

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
				default:
					return true
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

		closeAssociationPair(br, a0, a1)
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
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		const si uint16 = 6
		const msg1 = "ABC"
		var n int
		var ppi PayloadProtocolIdentifier
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, 0)
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
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		const si uint16 = 6
		var n int
		var ppi PayloadProtocolIdentifier
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNormal, 0)
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
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		const maxReceiveBufferSize uint32 = 64 * 1024
		const si uint16 = 6
		const nPacketsToSend = 2000
		var n int
		var nPacketsReceived int
		var ppi PayloadProtocolIdentifier
		rbuf := make([]byte, 3000)

		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNormal, maxReceiveBufferSize)
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
		assert.True(t, a0.stats.getNumSACKs() <= nPacketsToSend/2, "too many sacks")
		assert.Equal(t, uint64(0), a0.stats.getNumT3Timeouts(), "should be no retransmit")

		closeAssociationPair(br, a0, a1)
	})

	// This is to test even rwnd becomes 0, sender should be able to send a zero window probe
	// on T3-rtx retramission timeout to complete receiving all the packets.
	t.Run("Slow reader", func(t *testing.T) {
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		const maxReceiveBufferSize uint32 = 64 * 1024
		const si uint16 = 6
		nPacketsToSend := int(math.Floor(float64(maxReceiveBufferSize)/1000.0)) * 2
		var n int
		var nPacketsReceived int
		var ppi PayloadProtocolIdentifier
		rbuf := make([]byte, 3000)

		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, maxReceiveBufferSize)
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
	t.Run("First DATA chunk gets acked with delay", func(t *testing.T) {
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		const si uint16 = 6
		var n int
		var nPacketsReceived int
		var ppi PayloadProtocolIdentifier
		sbuf := make([]byte, 1000) // size should be less than initial cwnd (4380)
		rbuf := make([]byte, 1500)

		_, err := cryptoRand.Read(sbuf)
		if !assert.Nil(t, err, "failed to create associations") {
			return
		}

		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeAlwaysDelay, 0)
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
		since := time.Now()
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
		delay := time.Since(since).Seconds()
		t.Logf("received in %.03f seconds", delay)
		assert.True(t, delay >= 0.2, "should be >= 200msec")

		br.Process()

		assert.Equal(t, 1, nPacketsReceived, "should be one packet received")
		assert.Equal(t, 0, s1.getNumBytesInReassemblyQueue(), "reassembly queue should be empty")

		t.Logf("nDATAs      : %d\n", a1.stats.getNumDATAs())
		t.Logf("nSACKs      : %d\n", a0.stats.getNumSACKs())
		t.Logf("nAckTimeouts: %d\n", a1.stats.getNumAckTimeouts())

		assert.Equal(t, uint64(1), a1.stats.getNumDATAs(), "DATA chunk count mismatch")
		assert.Equal(t, a0.stats.getNumSACKs(), a1.stats.getNumDATAs(), "sack count should be equal to the number of data chunks")
		assert.Equal(t, uint64(1), a1.stats.getNumAckTimeouts(), "ackTimeout count mismatch")
		assert.Equal(t, uint64(0), a0.stats.getNumT3Timeouts(), "should be no retransmit")

		closeAssociationPair(br, a0, a1)
	})
}

func TestAssocReset(t *testing.T) {
	t.Run("Close one way", func(t *testing.T) {
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		const si uint16 = 1
		const msg = "ABC"
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, 0)
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

		err = s0.Close() // send reset
		if err != nil {
			t.Error(err)
		}

		doneCh := make(chan error)
		buf := make([]byte, 32)

		go func() {
			for {
				var ppi PayloadProtocolIdentifier
				n, ppi, err = s1.ReadSCTP(buf)
				if err != nil {
					doneCh <- err
					return
				}

				assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")
				assert.Equal(t, n, len(msg), "unexpected length of received data")
			}
		}()

	loop:
		for {
			br.Process()
			select {
			case err = <-doneCh:
				assert.Equal(t, io.EOF, err, "should end with EOF")
				break loop
			default:
			}
		}

		closeAssociationPair(br, a0, a1)
	})

	t.Run("Close both ways", func(t *testing.T) {
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		const si uint16 = 1
		const msg = "ABC"
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, 0)
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

		err = s0.Close() // send reset
		if err != nil {
			t.Error(err)
		}

		doneCh := make(chan error)
		buf := make([]byte, 32)

		go func() {
			for {
				var ppi PayloadProtocolIdentifier
				n, ppi, err = s1.ReadSCTP(buf)
				if err != nil {
					doneCh <- err
					return
				}

				assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")
				assert.Equal(t, n, len(msg), "unexpected length of received data")
			}
		}()

	loop0:
		for {
			br.Process()
			select {
			case err = <-doneCh:
				assert.Equal(t, io.EOF, err, "should end with EOF")
				break loop0
			default:
			}
		}

		err = s1.Close() // send reset
		if err != nil {
			t.Error(err)
		}

		go func() {
			for {
				_, _, err = s0.ReadSCTP(buf)
				assert.Equal(t, io.EOF, err, "should be EOF")
				doneCh <- err
			}
		}()

	loop1:
		for {
			br.Process()
			select {
			case <-doneCh:
				break loop1
			default:
			}
		}

		time.Sleep(2 * time.Second)

		closeAssociationPair(br, a0, a1)
	})
}

func TestAssocAbort(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	const si uint16 = 1
	br := test.NewBridge()

	a0, a1, err := createNewAssociationPair(br, ackModeNoDelay, 0)
	assert.NoError(t, err)

	abort := &chunkAbort{
		errorCauses: []errorCause{&errorCauseProtocolViolation{
			errorCauseHeader: errorCauseHeader{code: protocolViolation},
		}},
	}
	packet, err := a0.createPacket([]chunk{abort}).marshal()
	assert.NoError(t, err)

	_, _, err = establishSessionPair(br, a0, a1, si)
	assert.NoError(t, err)

	// Both associations are established
	assert.Equal(t, established, a0.getState())
	assert.Equal(t, established, a1.getState())

	_, err = a0.netConn.Write(packet)
	assert.NoError(t, err)
	flushBuffers(br, a0, a1)

	// There is a little delay before changing the state to closed
	time.Sleep(10 * time.Millisecond)

	// The receiving association should be closed because it got an ABORT
	assert.Equal(t, established, a0.getState())
	assert.Equal(t, closed, a1.getState())

	closeAssociationPair(br, a0, a1)
}

type fakeEchoConn struct {
	echo     chan []byte
	done     chan struct{}
	closed   chan struct{}
	once     sync.Once
	errClose error
	mu       sync.Mutex

	bytesSent     uint64
	bytesReceived uint64
}

func newFakeEchoConn(errClose error) *fakeEchoConn {
	return &fakeEchoConn{
		echo:     make(chan []byte, 1),
		done:     make(chan struct{}),
		closed:   make(chan struct{}),
		errClose: errClose,
	}
}

func (c *fakeEchoConn) Read(b []byte) (int, error) {
	r, ok := <-c.echo
	if ok {
		copy(b, r)
		c.once.Do(func() { close(c.done) })

		c.mu.Lock()
		c.bytesReceived += uint64(len(r))
		c.mu.Unlock()

		return len(r), nil
	}
	return 0, io.EOF
}

func (c *fakeEchoConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return 0, io.EOF
	default:
	}
	c.echo <- b
	c.bytesSent += uint64(len(b))
	return len(b), nil
}

func (c *fakeEchoConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	close(c.echo)
	close(c.closed)
	return c.errClose
}
func (c *fakeEchoConn) LocalAddr() net.Addr                { return nil }
func (c *fakeEchoConn) RemoteAddr() net.Addr               { return nil }
func (c *fakeEchoConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakeEchoConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakeEchoConn) SetWriteDeadline(t time.Time) error { return nil }

func TestRoutineLeak(t *testing.T) {
	loggerFactory := logging.NewDefaultLoggerFactory()
	t.Run("Close failed", func(t *testing.T) {
		runtime.GC()
		n0 := runtime.NumGoroutine()

		conn := newFakeEchoConn(io.EOF)
		a, err := Client(Config{NetConn: conn, LoggerFactory: loggerFactory})
		assert.Equal(t, nil, err, "errored to initialize Client")

		<-conn.done

		err = a.Close()
		assert.Equal(t, io.EOF, err, "Close() should fail with EOF")

		select {
		case _, ok := <-a.closeWriteLoopCh:
			if ok {
				t.Errorf("closeWriteLoopCh is expected to be closed, but received signal")
			}
		default:
			t.Errorf("closeWriteLoopCh is expected to be closed, but not")
		}
		_ = a
		runtime.GC()
		assert.Equal(t, n0, runtime.NumGoroutine(), "goroutine is leaked")
	})
	t.Run("Connection closed by remote host", func(t *testing.T) {
		runtime.GC()
		n0 := runtime.NumGoroutine()

		conn := newFakeEchoConn(nil)
		a, err := Client(Config{NetConn: conn, LoggerFactory: loggerFactory})
		assert.Equal(t, nil, err, "errored to initialize Client")

		<-conn.done

		err = conn.Close() // close connection
		assert.Equal(t, nil, err, "fake connection returned unexpected error")
		<-conn.closed
		<-time.After(10 * time.Millisecond) // switch context to make read/write loops finished

		select {
		case _, ok := <-a.closeWriteLoopCh:
			if ok {
				t.Errorf("closeWriteLoopCh is expected to be closed, but received signal")
			}
		default:
			t.Errorf("closeWriteLoopCh is expected to be closed, but not")
		}
		runtime.GC()
		assert.Equal(t, n0, runtime.NumGoroutine(), "goroutine is leaked")
	})
}

func TestStats(t *testing.T) {
	loggerFactory := logging.NewDefaultLoggerFactory()

	conn := newFakeEchoConn(nil)
	a, err := Client(Config{NetConn: conn, LoggerFactory: loggerFactory})
	assert.Equal(t, nil, err, "errored to initialize Client")

	<-conn.done

	assert.NoError(t, conn.Close())

	conn.mu.Lock()
	defer conn.mu.Unlock()
	assert.Equal(t, conn.bytesReceived, a.BytesReceived())
	assert.Equal(t, conn.bytesSent, a.BytesSent())
}

func TestAssocHandleInit(t *testing.T) {
	loggerFactory := logging.NewDefaultLoggerFactory()

	handleInitTest := func(t *testing.T, initialState uint32, expectErr bool) {
		a := createAssociation(Config{
			NetConn:       &dumbConn{},
			LoggerFactory: loggerFactory,
		})
		a.setState(initialState)
		pkt := &packet{
			sourcePort:      5001,
			destinationPort: 5002,
		}
		init := &chunkInit{}
		init.initialTSN = 1234
		init.numOutboundStreams = 1001
		init.numInboundStreams = 1002
		init.initiateTag = 5678
		init.advertisedReceiverWindowCredit = 512 * 1024
		setSupportedExtensions(&init.chunkInitCommon)

		_, err := a.handleInit(pkt, init)
		if expectErr {
			assert.Error(t, err, "should fail")
			return
		}
		assert.NoError(t, err, "should succeed")
		assert.Equal(t, init.initialTSN-1, a.peerLastTSN, "should match")
		assert.Equal(t, uint16(1001), a.myMaxNumOutboundStreams, "should match")
		assert.Equal(t, uint16(1002), a.myMaxNumInboundStreams, "should match")
		assert.Equal(t, uint32(5678), a.peerVerificationTag, "should match")
		assert.Equal(t, pkt.sourcePort, a.destinationPort, "should match")
		assert.Equal(t, pkt.destinationPort, a.sourcePort, "should match")
		assert.True(t, a.useForwardTSN, "should be set to true")
	}

	t.Run("normal", func(t *testing.T) {
		handleInitTest(t, closed, false)
	})

	t.Run("unexpected state established", func(t *testing.T) {
		handleInitTest(t, established, true)
	})

	t.Run("unexpected state shutdownAckSent", func(t *testing.T) {
		handleInitTest(t, shutdownAckSent, true)
	})

	t.Run("unexpected state shutdownPending", func(t *testing.T) {
		handleInitTest(t, shutdownPending, true)
	})

	t.Run("unexpected state shutdownReceived", func(t *testing.T) {
		handleInitTest(t, shutdownReceived, true)
	})

	t.Run("unexpected state shutdownSent", func(t *testing.T) {
		handleInitTest(t, shutdownSent, true)
	})
}

func TestAssocMaxMessageSize(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		loggerFactory := logging.NewDefaultLoggerFactory()
		a := createAssociation(Config{
			LoggerFactory: loggerFactory,
		})
		assert.NotNil(t, a, "should succeed")
		assert.Equal(t, uint32(65536), a.MaxMessageSize(), "should match")

		s := a.createStream(1, false)
		assert.NotNil(t, s, "should succeed")

		p := make([]byte, 65537)
		var err error
		_, err = s.WriteSCTP(p[:65536], s.defaultPayloadType)
		assert.False(t, strings.Contains(err.Error(), "larger than maximum"), "should be false")

		_, err = s.WriteSCTP(p[:65537], s.defaultPayloadType)
		assert.True(t, strings.Contains(err.Error(), "larger than maximum"), "should be false")
	})

	t.Run("explicit", func(t *testing.T) {
		loggerFactory := logging.NewDefaultLoggerFactory()
		a := createAssociation(Config{
			MaxMessageSize: 30000,
			LoggerFactory:  loggerFactory,
		})
		assert.NotNil(t, a, "should succeed")
		assert.Equal(t, uint32(30000), a.MaxMessageSize(), "should match")

		s := a.createStream(1, false)
		assert.NotNil(t, s, "should succeed")

		p := make([]byte, 30001)
		var err error
		_, err = s.WriteSCTP(p[:30000], s.defaultPayloadType)
		assert.False(t, strings.Contains(err.Error(), "larger than maximum"), "should be false")

		_, err = s.WriteSCTP(p[:30001], s.defaultPayloadType)
		assert.True(t, strings.Contains(err.Error(), "larger than maximum"), "should be false")
	})

	t.Run("set value", func(t *testing.T) {
		loggerFactory := logging.NewDefaultLoggerFactory()
		a := createAssociation(Config{
			LoggerFactory: loggerFactory,
		})
		assert.NotNil(t, a, "should succeed")
		assert.Equal(t, uint32(65536), a.MaxMessageSize(), "should match")
		a.SetMaxMessageSize(20000)
		assert.Equal(t, uint32(20000), a.MaxMessageSize(), "should match")
	})
}

func createAssocs(t *testing.T) (a1, a2 *Association) {
	addr1 := &net.UDPAddr{
		IP:   net.IP{127, 0, 0, 1},
		Port: 1234,
	}

	addr2 := &net.UDPAddr{
		IP:   net.IP{127, 0, 0, 1},
		Port: 5678,
	}

	udp1, err := net.DialUDP("udp", addr1, addr2)
	if err != nil {
		panic(err)
	}

	udp2, err := net.DialUDP("udp", addr2, addr1)
	if err != nil {
		panic(err)
	}

	loggerFactory := logging.NewDefaultLoggerFactory()

	a1Chan := make(chan *Association)
	a2Chan := make(chan *Association)

	go func() {
		a, err := Client(Config{
			NetConn:       udp1,
			LoggerFactory: loggerFactory,
		})
		require.NoError(t, err)

		a1Chan <- a
	}()

	go func() {
		a, err := Client(Config{
			NetConn:       udp2,
			LoggerFactory: loggerFactory,
		})
		require.NoError(t, err)

		a2Chan <- a
	}()

	select {
	case a1 = <-a1Chan:
	case <-time.After(time.Second):
		assert.Fail(t, "timed out waiting for a1")
	}

	select {
	case a2 = <-a2Chan:
	case <-time.After(time.Second):
		assert.Fail(t, "timed out waiting for a2")
	}

	return a1, a2
}

func TestAssociation_Shutdown(t *testing.T) {
	runtime.GC()
	n0 := runtime.NumGoroutine()

	defer func() {
		runtime.GC()
		assert.Equal(t, n0, runtime.NumGoroutine(), "goroutine is leaked")
	}()

	a1, a2 := createAssocs(t)

	s11, err := a1.OpenStream(1, PayloadTypeWebRTCString)
	require.NoError(t, err)

	s21, err := a2.OpenStream(1, PayloadTypeWebRTCString)
	require.NoError(t, err)

	testData := []byte("test")

	i, err := s11.Write(testData)
	assert.Equal(t, len(testData), i)
	assert.NoError(t, err)

	buf := make([]byte, len(testData))
	i, err = s21.Read(buf)
	assert.Equal(t, len(testData), i)
	assert.NoError(t, err)
	assert.Equal(t, testData, buf)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err = a1.Shutdown(ctx)
	require.NoError(t, err)

	// Wait for close read loop channels to prevent flaky tests.
	select {
	case <-a2.readLoopCloseCh:
	case <-time.After(1 * time.Second):
		assert.Fail(t, "timed out waiting for a2 read loop to close")
	}
}

func TestAssociation_ShutdownDuringWrite(t *testing.T) {
	runtime.GC()
	n0 := runtime.NumGoroutine()

	defer func() {
		runtime.GC()
		assert.Equal(t, n0, runtime.NumGoroutine(), "goroutine is leaked")
	}()

	a1, a2 := createAssocs(t)

	s11, err := a1.OpenStream(1, PayloadTypeWebRTCString)
	require.NoError(t, err)

	s21, err := a2.OpenStream(1, PayloadTypeWebRTCString)
	require.NoError(t, err)

	writingDone := make(chan struct{})

	go func() {
		defer close(writingDone)

		var i byte

		for {
			i++

			if i%100 == 0 {
				time.Sleep(20 * time.Millisecond)
			}

			_, writeErr := s21.Write([]byte{i})
			if writeErr != nil {
				return
			}
		}
	}()

	testData := []byte("test")

	i, err := s11.Write(testData)
	assert.Equal(t, len(testData), i)
	assert.NoError(t, err)

	buf := make([]byte, len(testData))
	i, err = s21.Read(buf)
	assert.Equal(t, len(testData), i)
	assert.NoError(t, err)
	assert.Equal(t, testData, buf)

	// running this test with -race flag is very slow so timeout needs to be high.
	timeout := 5 * time.Minute

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	err = a1.Shutdown(ctx)
	require.NoError(t, err, "timed out waiting for a1 shutdown to complete")

	select {
	case <-writingDone:
	case <-time.After(timeout):
		assert.Fail(t, "timed out waiting writing goroutine to exit")
	}

	// Wait for close read loop channels to prevent flaky tests.
	select {
	case <-a2.readLoopCloseCh:
	case <-time.After(timeout):
		assert.Fail(t, "timed out waiting for a2 read loop to close")
	}
}

func TestAssociation_HandlePacketInCookieWaitState(t *testing.T) {
	loggerFactory := logging.NewDefaultLoggerFactory()

	testCases := map[string]struct {
		inputPacket *packet
		skipClose   bool
	}{
		"InitAck": {
			inputPacket: &packet{
				sourcePort:      1,
				destinationPort: 1,
				chunks: []chunk{
					&chunkInitAck{
						chunkInitCommon: chunkInitCommon{
							initiateTag:                    1,
							numInboundStreams:              1,
							numOutboundStreams:             1,
							advertisedReceiverWindowCredit: 1500,
						},
					},
				},
			},
		},
		"Abort": {
			inputPacket: &packet{
				sourcePort:      1,
				destinationPort: 1,
				chunks:          []chunk{&chunkAbort{}},
			},
			// Prevent "use of close network connection" error on close.
			skipClose: true,
		},
		"CoockeEcho": {
			inputPacket: &packet{
				sourcePort:      1,
				destinationPort: 1,
				chunks:          []chunk{&chunkCookieEcho{}},
			},
		},
		"HeartBeat": {
			inputPacket: &packet{
				sourcePort:      1,
				destinationPort: 1,
				chunks:          []chunk{&chunkHeartbeat{}},
			},
		},
		"PayloadData": {
			inputPacket: &packet{
				sourcePort:      1,
				destinationPort: 1,
				chunks:          []chunk{&chunkPayloadData{}},
			},
		},
		"Sack": {
			inputPacket: &packet{
				sourcePort:      1,
				destinationPort: 1,
				chunks: []chunk{&chunkSelectiveAck{
					cumulativeTSNAck:               1000,
					advertisedReceiverWindowCredit: 1500,
					gapAckBlocks: []gapAckBlock{
						{start: 100, end: 200},
					},
				}},
			},
		},
		"Reconfig": {
			inputPacket: &packet{
				sourcePort:      1,
				destinationPort: 1,
				chunks: []chunk{&chunkReconfig{
					paramA: &paramOutgoingResetRequest{},
					paramB: &paramReconfigResponse{},
				}},
			},
		},
		"ForwardTSN": {
			inputPacket: &packet{
				sourcePort:      1,
				destinationPort: 1,
				chunks: []chunk{&chunkForwardTSN{
					newCumulativeTSN: 100,
				}},
			},
		},
		"Error": {
			inputPacket: &packet{
				sourcePort:      1,
				destinationPort: 1,
				chunks:          []chunk{&chunkError{}},
			},
		},
		"Shutdown": {
			inputPacket: &packet{
				sourcePort:      1,
				destinationPort: 1,
				chunks:          []chunk{&chunkShutdown{}},
			},
		},
		"ShutdownAck": {
			inputPacket: &packet{
				sourcePort:      1,
				destinationPort: 1,
				chunks:          []chunk{&chunkShutdownAck{}},
			},
		},
		"ShutdownComplete": {
			inputPacket: &packet{
				sourcePort:      1,
				destinationPort: 1,
				chunks:          []chunk{&chunkShutdownComplete{}},
			},
		},
	}

	for name, testCase := range testCases {
		testCase := testCase
		t.Run(name, func(t *testing.T) {
			aConn, charlieConn := pipeDump()
			a := createAssociation(Config{
				NetConn:              aConn,
				MaxReceiveBufferSize: 0,
				LoggerFactory:        loggerFactory,
			})
			a.init(true)

			if !testCase.skipClose {
				defer func() {
					assert.NoError(t, a.close())
				}()
			}

			packet, err := testCase.inputPacket.marshal()
			assert.NoError(t, err)
			_, err = charlieConn.Write(packet)
			assert.NoError(t, err)

			// Should not panic.
			time.Sleep(100 * time.Millisecond)
		})
	}
}

func TestAssociation_Abort(t *testing.T) {
	runtime.GC()
	n0 := runtime.NumGoroutine()

	defer func() {
		runtime.GC()
		assert.Equal(t, n0, runtime.NumGoroutine(), "goroutine is leaked")
	}()

	a1, a2 := createAssocs(t)

	s11, err := a1.OpenStream(1, PayloadTypeWebRTCString)
	require.NoError(t, err)

	s21, err := a2.OpenStream(1, PayloadTypeWebRTCString)
	require.NoError(t, err)

	testData := []byte("test")

	i, err := s11.Write(testData)
	assert.Equal(t, len(testData), i)
	assert.NoError(t, err)

	buf := make([]byte, len(testData))
	i, err = s21.Read(buf)
	assert.Equal(t, len(testData), i)
	assert.NoError(t, err)
	assert.Equal(t, testData, buf)

	a1.Abort("1234")

	// Wait for close read loop channels to prevent flaky tests.
	select {
	case <-a2.readLoopCloseCh:
	case <-time.After(1 * time.Second):
		assert.Fail(t, "timed out waiting for a2 read loop to close")
	}

	i, err = s21.Read(buf)
	assert.Equal(t, i, 0, "expected no data read")
	assert.Error(t, err, "User Initiated Abort: 1234", "expected abort reason")
}
