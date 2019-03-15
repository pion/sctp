package sctp

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pions/transport/test"
	"github.com/stretchr/testify/assert"
)

func TestAssocInit(t *testing.T) {
	rawPkt := []byte{0x13, 0x88, 0x13, 0x88, 0x00, 0x00, 0x00, 0x00, 0x81, 0x46, 0x9d, 0xfc, 0x01, 0x00, 0x00, 0x56, 0x55,
		0xb9, 0x64, 0xa5, 0x00, 0x02, 0x00, 0x00, 0x04, 0x00, 0x08, 0x00, 0xe8, 0x6d, 0x10, 0x30, 0xc0, 0x00, 0x00, 0x04, 0x80,
		0x08, 0x00, 0x09, 0xc0, 0x0f, 0xc1, 0x80, 0x82, 0x00, 0x00, 0x00, 0x80, 0x02, 0x00, 0x24, 0x9f, 0xeb, 0xbb, 0x5c, 0x50,
		0xc9, 0xbf, 0x75, 0x9c, 0xb1, 0x2c, 0x57, 0x4f, 0xa4, 0x5a, 0x51, 0xba, 0x60, 0x17, 0x78, 0x27, 0x94, 0x5c, 0x31, 0xe6,
		0x5d, 0x5b, 0x09, 0x47, 0xe2, 0x22, 0x06, 0x80, 0x04, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00, 0x80, 0x03, 0x00, 0x06, 0x80, 0xc1, 0x00, 0x00}

	assoc := &Association{}
	if err := assoc.handleInbound(rawPkt); err != nil {
		// TODO
		fmt.Println(err)
		// t.Error(errors.Wrap(err, "Failed to HandleInbound"))
	}
}

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

	// Setup client
	go func() {
		client, err := Client(ca)
		c <- result{client, err}
	}()

	// Setup server
	server, err := Server(cb)
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
	return c.pConn.LocalAddr()
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

func createNewAssociationPair(br *test.Bridge) (*Association, *Association, error) {
	var a0, a1 *Association
	var err0, err1 error

	handshake0Ch := make(chan bool)
	handshake1Ch := make(chan bool)

	go func() {
		a0, err0 = Client(br.GetConn0())
		handshake0Ch <- true
	}()
	go func() {
		a1, err1 = Client(br.GetConn1())
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
			//fmt.Println("a0 handshake complete")
			if a1handshakeDone {
				break loop1
			}
		case a1handshakeDone = <-handshake1Ch:
			//fmt.Println("a1 handshake complete")
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

	return a0, a1, nil
}

func closeAssociationPair(br *test.Bridge, a0, a1 *Association) {
	close0Ch := make(chan bool)
	close1Ch := make(chan bool)

	go func() {
		//fmt.Println("closing a0..")
		//nolint:errcheck,gosec
		a0.Close()
		close0Ch <- true
	}()
	go func() {
		//fmt.Println("closing a1..")
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
			//fmt.Println("a0 closed")
			if a1closed {
				break loop1
			}
		case a1closed = <-close1Ch:
			//fmt.Println("a1 closed")
			if a0closed {
				break loop1
			}
		default:
		}
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

	return s0, s1, nil
}

func TestAssocReliable(t *testing.T) {

	t.Run("Simple", func(t *testing.T) {
		const si uint16 = 1
		const msg = "ABC"
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		n, err := s0.WriteSCTP([]byte(msg), PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, n, len(msg), "unexpected length of received data")

		br.Process()

		buf := make([]byte, 32)
		n, ppi, err := s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, n, len(msg), "unexpected length of received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.Process()
		assert.False(t, s0.reassemblyQueue.isReadable(), "should no longer be readable")
		closeAssociationPair(br, a0, a1)
	})

	t.Run("ordered reordered", func(t *testing.T) {
		const si uint16 = 2
		const msg1 = "ABC"
		const msg2 = "DEFG"
		var n int
		var ppi PayloadProtocolIdentifier
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		n, err = s0.WriteSCTP([]byte(msg1), PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(msg1), "unexpected length of received data")
		n, err = s0.WriteSCTP([]byte(msg2), PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(msg2), "unexpected length of received data")

		err = br.Reorder(0)
		assert.Nil(t, err, "reorder failed")
		br.Process()

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

	t.Run("ordered fragmentated then defragmented", func(t *testing.T) {
		const si uint16 = 3
		const msg = "ABCDEFG"
		var n int
		var ppi PayloadProtocolIdentifier
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		s0.SetReliabilityParams(false, ReliabilityTypeReliable, 0)
		s1.SetReliabilityParams(false, ReliabilityTypeReliable, 0)

		a0.myMaxMTU = 4

		n, err = s0.WriteSCTP([]byte(msg), PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(msg), "unexpected length of received data")

		br.Process()

		buf := make([]byte, 32)

		br.Process()

		n, ppi, err = s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}

		assert.Equal(t, n, len(msg), "unexpected length of received data")
		assert.Equal(t, msg, string(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.Process()
		assert.False(t, s0.reassemblyQueue.isReadable(), "should no longer be readable")
		closeAssociationPair(br, a0, a1)
	})

	t.Run("unordered fragmentated then defragmented", func(t *testing.T) {
		const si uint16 = 4
		const msg = "ABCDEFG"
		var n int
		var ppi PayloadProtocolIdentifier
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		s0.SetReliabilityParams(true, ReliabilityTypeReliable, 0)
		s1.SetReliabilityParams(true, ReliabilityTypeReliable, 0)

		a0.myMaxMTU = 4

		n, err = s0.WriteSCTP([]byte(msg), PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(msg), "unexpected length of received data")

		err = br.Reorder(0)
		assert.Nil(t, err, "reorder failed")
		br.Process()

		buf := make([]byte, 32)

		br.Process()

		n, ppi, err = s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}

		assert.Equal(t, n, len(msg), "unexpected length of received data")
		assert.Equal(t, msg, string(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.Process()
		assert.False(t, s0.reassemblyQueue.isReadable(), "should no longer be readable")
		closeAssociationPair(br, a0, a1)
	})

	t.Run("unordered", func(t *testing.T) {
		const si uint16 = 5
		const msg1 = "ABC"
		const msg2 = "DEFG"
		var n int
		var ppi PayloadProtocolIdentifier
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		s0.SetReliabilityParams(true, ReliabilityTypeReliable, 0)
		s1.SetReliabilityParams(true, ReliabilityTypeReliable, 0)

		n, err = s0.WriteSCTP([]byte(msg1), PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(msg1), "unexpected length of received data")
		n, err = s0.WriteSCTP([]byte(msg2), PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(msg2), "unexpected length of received data")

		err = br.Reorder(0)
		assert.Nil(t, err, "reorder failed")
		br.Process()

		buf := make([]byte, 32)

		n, ppi, err = s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, n, len(msg2), "unexpected length of received data")
		assert.Equal(t, msg2, string(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.Process()

		n, ppi, err = s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}

		assert.Equal(t, n, len(msg1), "unexpected length of received data")
		assert.Equal(t, msg1, string(buf[:n]), "unexpected received data")
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

		a0, a1, err := createNewAssociationPair(br)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		n, err = s0.WriteSCTP([]byte(msg1), PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(msg1), "unexpected length of received data")
		n, err = s0.WriteSCTP([]byte(msg2), PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(msg2), "unexpected length of received data")

		br.Drop(0, 0, 1) // drop the first packet (second one should be sacked)
		br.Process()

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
	const msg1 = "ABCDEFGHIJ"
	const msg2 = "KLMNOPQRST"

	t.Run("Rexmit ordered", func(t *testing.T) {
		const si uint16 = 1
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		// When we set the reliability value to 0 [times], then it will cause
		// the chunk to be abandoned immediately after the first transmission.
		s0.SetReliabilityParams(false, ReliabilityTypeRexmit, 0)
		s1.SetReliabilityParams(false, ReliabilityTypeRexmit, 0) // doesn't matter

		var n int
		n, err = s0.WriteSCTP([]byte(msg1), PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(msg1), n, "unexpected length of written data")

		n, err = s0.WriteSCTP([]byte(msg2), PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(msg2), n, "unexpected length of written data")

		br.Drop(0, 0, 1) // drop the first packet (second one should be sacked)
		br.Process()

		buf := make([]byte, 32)
		n, ppi, err := s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		// should receive the second one only
		assert.Equal(t, msg2, string(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.Process()
		assert.False(t, s0.reassemblyQueue.isReadable(), "should no longer be readable")
		closeAssociationPair(br, a0, a1)
	})

	t.Run("Rexmit ordered fragments", func(t *testing.T) {
		const si uint16 = 1
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		a0.myMaxMTU = 4

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		// When we set the reliability value to 0 [times], then it will cause
		// the chunk to be abandoned immediately after the first transmission.
		s0.SetReliabilityParams(false, ReliabilityTypeRexmit, 0)
		s1.SetReliabilityParams(false, ReliabilityTypeRexmit, 0) // doesn't matter

		var n int
		n, err = s0.WriteSCTP([]byte(msg1), PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(msg1), n, "unexpected length of written data")

		n, err = s0.WriteSCTP([]byte(msg2), PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(msg2), n, "unexpected length of written data")

		br.Drop(0, 0, 2) // drop the second fragment of the first chunk (second chunk should be sacked)
		br.Process()

		buf := make([]byte, 32)
		n, ppi, err := s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		// should receive the second one only
		assert.Equal(t, msg2, string(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.Process()

		assert.False(t, s0.reassemblyQueue.isReadable(), "should no longer be readable")
		assert.Equal(t, 0, len(s0.reassemblyQueue.ordered), "should be nothing in the ordered queue")
		closeAssociationPair(br, a0, a1)
	})

	t.Run("Rexmit unordered", func(t *testing.T) {
		const si uint16 = 2
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br)
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
		n, err = s0.WriteSCTP([]byte(msg1), PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(msg1), n, "unexpected length of written data")

		n, err = s0.WriteSCTP([]byte(msg2), PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(msg2), n, "unexpected length of written data")

		br.Drop(0, 0, 1) // drop the first packet (second one should be sacked)
		br.Process()

		buf := make([]byte, 32)
		n, ppi, err := s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		// should receive the second one only
		assert.Equal(t, msg2, string(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.Process()
		assert.False(t, s0.reassemblyQueue.isReadable(), "should no longer be readable")
		closeAssociationPair(br, a0, a1)
	})

	t.Run("Rexmit unordered fragments", func(t *testing.T) {
		const si uint16 = 1
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		a0.myMaxMTU = 4

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		// When we set the reliability value to 0 [times], then it will cause
		// the chunk to be abandoned immediately after the first transmission.
		s0.SetReliabilityParams(true, ReliabilityTypeRexmit, 0)
		s1.SetReliabilityParams(true, ReliabilityTypeRexmit, 0) // doesn't matter

		var n int
		n, err = s0.WriteSCTP([]byte(msg1), PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(msg1), n, "unexpected length of written data")

		n, err = s0.WriteSCTP([]byte(msg2), PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(msg2), n, "unexpected length of written data")

		br.Drop(0, 0, 2) // drop the second fragment of the first chunk (second chunk should be sacked)
		br.Process()

		buf := make([]byte, 32)
		n, ppi, err := s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		// should receive the second one only
		assert.Equal(t, msg2, string(buf[:n]), "unexpected received data")
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

		a0, a1, err := createNewAssociationPair(br)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		// When we set the reliability value to 0 [msec], then it will cause
		// the chunk to be abandoned immediately after the first transmission.
		s0.SetReliabilityParams(false, ReliabilityTypeTimed, 0)
		s1.SetReliabilityParams(false, ReliabilityTypeTimed, 0) // doesn't matter

		var n int
		n, err = s0.WriteSCTP([]byte(msg1), PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(msg1), n, "unexpected length of written data")

		n, err = s0.WriteSCTP([]byte(msg2), PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(msg2), n, "unexpected length of written data")

		br.Drop(0, 0, 1) // drop the first packet (second one should be sacked)
		br.Process()

		buf := make([]byte, 32)
		n, ppi, err := s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		// should receive the second one only
		assert.Equal(t, msg2, string(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.Process()
		assert.False(t, s0.reassemblyQueue.isReadable(), "should no longer be readable")
		closeAssociationPair(br, a0, a1)
	})

	t.Run("Timed unordered", func(t *testing.T) {
		const si uint16 = 3
		br := test.NewBridge()

		a0, a1, err := createNewAssociationPair(br)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		// When we set the reliability value to 0 [msec], then it will cause
		// the chunk to be abandoned immediately after the first transmission.
		s0.SetReliabilityParams(true, ReliabilityTypeTimed, 0)
		s1.SetReliabilityParams(true, ReliabilityTypeTimed, 0) // doesn't matter

		var n int
		n, err = s0.WriteSCTP([]byte(msg1), PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(msg1), n, "unexpected length of written data")

		n, err = s0.WriteSCTP([]byte(msg2), PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, len(msg2), n, "unexpected length of written data")

		br.Drop(0, 0, 1) // drop the first packet (second one should be sacked)
		br.Process()

		buf := make([]byte, 32)
		n, ppi, err := s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		// should receive the second one only
		assert.Equal(t, msg2, string(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.Process()
		assert.False(t, s0.reassemblyQueue.isReadable(), "should no longer be readable")
		assert.Equal(t, 0, len(s0.reassemblyQueue.unordered), "should be nothing in the unordered queue")
		assert.Equal(t, 0, len(s0.reassemblyQueue.unorderedChunks), "should be nothing in the unorderedChunks list")
		closeAssociationPair(br, a0, a1)
	})
}

func TestCreateForwardTSN(t *testing.T) {

	t.Run("forward one abandoned", func(t *testing.T) {
		conn := &dumbConn{}

		a := createAssocation(conn)

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
		conn := &dumbConn{}

		a := createAssocation(conn)

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
	t.Run("forward 3 unreceived chunks", func(t *testing.T) {
		conn := &dumbConn{}
		a := createAssocation(conn)
		a.useForwardTSN = true
		prevTSN := a.peerLastTSN

		fwdtsn := &chunkForwardTSN{
			newCumulativeTSN: a.peerLastTSN + 3,
			streams:          []chunkForwardTSNStream{{identifier: 0, sequence: 0}},
		}

		a.handleForwardTSN(fwdtsn)

		assert.Equal(t, a.peerLastTSN, prevTSN+3, "peerLastTSN should advance by 3 ")
	})

	t.Run("forward 1 then one more for received chunk", func(t *testing.T) {
		conn := &dumbConn{}
		a := createAssocation(conn)
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

		a.handleForwardTSN(fwdtsn)

		assert.Equal(t, a.peerLastTSN, prevTSN+2, "peerLastTSN should advance by 3 ")
	})
}

func TestAssocT1InitTimer(t *testing.T) {
	t.Run("Retransmission success", func(t *testing.T) {
		br := test.NewBridge()
		a0 := createAssocation(br.GetConn0())
		go a0.readLoop()
		a1 := createAssocation(br.GetConn1())
		go a1.readLoop()

		var err0, err1 error
		a0ReadyCh := make(chan bool)
		a1ReadyCh := make(chan bool)

		assert.Equal(t, rtoInitial, a0.rtoMgr.getRTO())
		assert.Equal(t, rtoInitial, a1.rtoMgr.getRTO())

		// modified rto for fast test
		a0.rtoMgr.rto = 20

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
		a0.init()

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
		a0 := createAssocation(br.GetConn0())
		go a0.readLoop()
		a1 := createAssocation(br.GetConn1())
		go a1.readLoop()

		var err0, err1 error
		a0ReadyCh := make(chan bool)
		a1ReadyCh := make(chan bool)

		assert.Equal(t, rtoInitial, a0.rtoMgr.getRTO())
		assert.Equal(t, rtoInitial, a1.rtoMgr.getRTO())

		// modified rto for fast test
		a0.rtoMgr.rto = 20
		a1.rtoMgr.rto = 20

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
		a0.init()
		a1.init()

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
	t.Run("Retransmission success", func(t *testing.T) {
		br := test.NewBridge()
		a0 := createAssocation(br.GetConn0())
		go a0.readLoop()
		a1 := createAssocation(br.GetConn1())
		go a1.readLoop()

		var err0, err1 error
		a0ReadyCh := make(chan bool)
		a1ReadyCh := make(chan bool)

		assert.Equal(t, rtoInitial, a0.rtoMgr.getRTO())
		assert.Equal(t, rtoInitial, a1.rtoMgr.getRTO())

		// modified rto for fast test
		a0.rtoMgr.rto = 20

		go func() {
			err0 = <-a0.handshakeCompletedCh
			a0ReadyCh <- true
		}()

		go func() {
			err1 = <-a1.handshakeCompletedCh
			a1ReadyCh <- true
		}()

		// Start the handlshake
		a0.init()

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
		a0 := createAssocation(br.GetConn0())
		go a0.readLoop()
		a1 := createAssocation(br.GetConn1())
		go a1.readLoop()

		var err0 error
		a0ReadyCh := make(chan bool)

		assert.Equal(t, rtoInitial, a0.rtoMgr.getRTO())
		assert.Equal(t, rtoInitial, a1.rtoMgr.getRTO())

		// modified rto for fast test
		a0.rtoMgr.rto = 20
		// fail after 4 retransmission
		a0.t1Cookie.maxRetrans = 4

		go func() {
			err0 = <-a0.handshakeCompletedCh
			a0ReadyCh <- true
		}()

		// Start the handlshake
		a0.init()

		// Let the INIT go.
		br.Tick()

		// Drop COOKIE-ECHO
		br.DropNextNWrites(0, 99)

		a0Ready := false
		for !a0Ready {
			br.Process()

			select {
			case a0Ready = <-a0ReadyCh:
			default:
			}
		}

		assert.NotNil(t, err0, "should an error")

		_ = a0.Close() // #nosec
		_ = a1.Close() // #nosec
	})
}
