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
// testConn, connBridge for emulating dtls.Conn

type testConn struct {
	br     *connBridge
	id     int
	readCh chan []byte
}

func (conn *testConn) Read(b []byte) (int, error) {
	select {
	case data, ok := <-conn.readCh:
		if !ok {
			return 0, fmt.Errorf("testConn closed")
		}
		n := copy(b, data)
		return n, nil
	}
}

func (conn *testConn) Write(b []byte) (int, error) {
	n := len(b)
	conn.br.push(b, conn.id)
	return n, nil
}

func (conn *testConn) Close() error {
	close(conn.readCh)
	return nil
}

// Unused
func (conn *testConn) LocalAddr() net.Addr                { return nil }
func (conn *testConn) RemoteAddr() net.Addr               { return nil }
func (conn *testConn) SetDeadline(t time.Time) error      { return nil }
func (conn *testConn) SetReadDeadline(t time.Time) error  { return nil }
func (conn *testConn) SetWriteDeadline(t time.Time) error { return nil }

type connBridge struct {
	mutex sync.RWMutex
	conn0 *testConn
	conn1 *testConn

	queue0to1 [][]byte
	queue1to0 [][]byte
}

func inverse(s [][]byte) error {
	if len(s) < 2 {
		return fmt.Errorf("inverse requires more than one item in the array")
	}

	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return nil
}

// drop n packets from the slice starting from offset
func drop(s [][]byte, offset, n int) [][]byte {
	if offset+n > len(s) {
		n = len(s) - offset
	}
	return append(s[:offset], s[offset+n:]...)
}

func newConnBridge() *connBridge {
	br := &connBridge{
		queue0to1: make([][]byte, 0),
		queue1to0: make([][]byte, 0),
	}

	br.conn0 = &testConn{
		br:     br,
		id:     0,
		readCh: make(chan []byte),
	}
	br.conn1 = &testConn{
		br:     br,
		id:     1,
		readCh: make(chan []byte),
	}

	return br
}

func (br *connBridge) push(d []byte, fromID int) {
	br.mutex.Lock()
	defer br.mutex.Unlock()

	if fromID == 0 {
		br.queue0to1 = append(br.queue0to1, d)
	} else {
		br.queue1to0 = append(br.queue1to0, d)
	}
}

func (br *connBridge) reorder(fromID int) error {
	br.mutex.Lock()
	defer br.mutex.Unlock()

	var err error

	if fromID == 0 {
		err = inverse(br.queue0to1)
	} else {
		err = inverse(br.queue1to0)
	}

	return err
}

func (br *connBridge) drop(fromID, offset, n int) {
	br.mutex.Lock()
	defer br.mutex.Unlock()

	if fromID == 0 {
		br.queue0to1 = drop(br.queue0to1, offset, n)
	} else {
		br.queue1to0 = drop(br.queue1to0, offset, n)
	}
}

func (br *connBridge) tick() int {
	br.mutex.Lock()
	defer br.mutex.Unlock()

	var n int

	if len(br.queue0to1) > 0 {
		select {
		case br.conn1.readCh <- br.queue0to1[0]:
			n++
			//fmt.Printf("conn1 received data (%d bytes)\n", len(br.queue0to1[0]))
			br.queue0to1 = br.queue0to1[1:]
		default:
		}
	}

	if len(br.queue1to0) > 0 {
		select {
		case br.conn0.readCh <- br.queue1to0[0]:
			n++
			//fmt.Printf("conn0 received data (%d bytes)\n", len(br.queue1to0[0]))
			br.queue1to0 = br.queue1to0[1:]
		default:
		}
	}

	//  if n > 0 {
	//		fmt.Printf("tick: processed %d packet(s)\n", n)
	//	}

	return n
}

// Repeat tick() call until no more outstanding inflight packet
func (br *connBridge) process() {
	for {
		time.Sleep(10 * time.Millisecond)
		n := br.tick()
		if n == 0 {
			break
		}
	}
}

func createNewAssociationPair(br *connBridge) (*Association, *Association, error) {
	var a0 *Association
	var a1 *Association
	var err error

	handshake0Ch := make(chan bool)
	handshake1Ch := make(chan bool)

	go func() {
		a0, err = Client(br.conn0)
		handshake0Ch <- true
	}()
	go func() {
		a1, err = Client(br.conn1)
		handshake1Ch <- true
	}()

	a0handshakeDone := false
	a1handshakeDone := false
loop1:
	for i := 0; i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
		br.tick()

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

	if err != nil {
		return nil, nil, err
	}
	return a0, a1, nil
}

func closeAssociationPair(br *connBridge, a0, a1 *Association) error {
	close0Ch := make(chan bool)
	close1Ch := make(chan bool)

	go func() {
		//fmt.Println("closing a0..")
		a0.Close()
		close0Ch <- true
	}()
	go func() {
		//fmt.Println("closing a1..")
		a1.Close()
		close1Ch <- true
	}()

	a0closed := false
	a1closed := false
loop1:
	for i := 0; i < 100; i++ {
		time.Sleep(10 * time.Millisecond)
		br.tick()

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

	return nil
}

func establishSessionPair(br *connBridge, a0, a1 *Association, si uint16) (*Stream, *Stream, error) {
	helloMsg := "Hello" // mimic datachannel.channelOpen
	s0, err := a0.OpenStream(si, PayloadTypeWebRTCBinary)
	if err != nil {
		return nil, nil, err
	}

	_, err = s0.WriteSCTP([]byte(helloMsg), PayloadTypeWebRTCDCEP)
	if err != nil {
		return nil, nil, err
	}

	br.process()

	s1, err := a1.AcceptStream()
	if err != nil {
		return nil, nil, err
	}

	if s0.streamIdentifier != s1.streamIdentifier {
		return nil, nil, fmt.Errorf("SI should match")
	}

	br.process()

	buf := make([]byte, 1024)
	n, ppi, err := s1.ReadSCTP(buf)
	if err != nil {
		return nil, nil, fmt.Errorf("faild to read data")
	}

	if n != len(helloMsg) {
		return nil, nil, fmt.Errorf("received data must by 3 bytes")
	}

	if ppi != PayloadTypeWebRTCDCEP {
		fmt.Errorf("unexpected ppi")
	}

	if string(buf[:n]) != helloMsg {
		return nil, nil, fmt.Errorf("received data mismatch")
	}

	return s0, s1, nil
}

func TestAssocReliable(t *testing.T) {
	const si uint16 = 123

	t.Run("Simple", func(t *testing.T) {
		br := newConnBridge()

		a0, a1, err := createNewAssociationPair(br)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		msg := "ABC"

		n, err := s0.WriteSCTP([]byte(msg), PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, n, len(msg), "unexpected length of received data")

		br.process()

		buf := make([]byte, 32)
		n, ppi, err := s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, n, len(msg), "unexpected length of received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.process()
		err = closeAssociationPair(br, a0, a1)
	})

	t.Run("ordered reordered", func(t *testing.T) {
		var n int
		var ppi PayloadProtocolIdentifier
		br := newConnBridge()

		a0, a1, err := createNewAssociationPair(br)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		msg1 := "ABC"
		n, err = s0.WriteSCTP([]byte(msg1), PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(msg1), "unexpected length of received data")
		msg2 := "DEFG"
		n, err = s0.WriteSCTP([]byte(msg2), PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(msg2), "unexpected length of received data")

		err = br.reorder(0)
		assert.Nil(t, err, "reorder failed")
		br.process()

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

		br.process()
		err = closeAssociationPair(br, a0, a1)
	})

	t.Run("ordered fragmentated then defragmented", func(t *testing.T) {
		var n int
		var ppi PayloadProtocolIdentifier
		br := newConnBridge()

		a0, a1, err := createNewAssociationPair(br)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		s0.SetReliabilityParams(false, ReliabilityTypeReliable, 0)
		s1.SetReliabilityParams(false, ReliabilityTypeReliable, 0)

		a0.myMaxMTU = 4

		msg := "ABCDEFG"
		n, err = s0.WriteSCTP([]byte(msg), PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(msg), "unexpected length of received data")

		br.process()

		buf := make([]byte, 32)

		br.process()

		n, ppi, err = s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}

		assert.Equal(t, n, len(msg), "unexpected length of received data")
		assert.Equal(t, msg, string(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.process()
		err = closeAssociationPair(br, a0, a1)
	})

	t.Run("unordered fragmentated then defragmented", func(t *testing.T) {
		var n int
		var ppi PayloadProtocolIdentifier
		br := newConnBridge()

		a0, a1, err := createNewAssociationPair(br)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		s0.SetReliabilityParams(true, ReliabilityTypeReliable, 0)
		s1.SetReliabilityParams(true, ReliabilityTypeReliable, 0)

		a0.myMaxMTU = 4

		msg := "ABCDEFG"
		n, err = s0.WriteSCTP([]byte(msg), PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(msg), "unexpected length of received data")

		err = br.reorder(0)
		assert.Nil(t, err, "reorder failed")
		br.process()

		buf := make([]byte, 32)

		br.process()

		n, ppi, err = s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}

		assert.Equal(t, n, len(msg), "unexpected length of received data")
		assert.Equal(t, msg, string(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.process()
		err = closeAssociationPair(br, a0, a1)
	})

	t.Run("unordered", func(t *testing.T) {
		var n int
		var ppi PayloadProtocolIdentifier
		br := newConnBridge()

		a0, a1, err := createNewAssociationPair(br)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		s0.SetReliabilityParams(true, ReliabilityTypeReliable, 0)
		s1.SetReliabilityParams(true, ReliabilityTypeReliable, 0)

		msg1 := "ABC"
		n, err = s0.WriteSCTP([]byte(msg1), PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(msg1), "unexpected length of received data")
		msg2 := "DEFG"
		n, err = s0.WriteSCTP([]byte(msg2), PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(msg2), "unexpected length of received data")

		err = br.reorder(0)
		assert.Nil(t, err, "reorder failed")
		br.process()

		buf := make([]byte, 32)

		n, ppi, err = s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		fmt.Printf("First data received: %s\n", string(buf[:n]))
		assert.Equal(t, n, len(msg2), "unexpected length of received data")
		assert.Equal(t, msg2, string(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.process()

		n, ppi, err = s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}

		assert.Equal(t, n, len(msg1), "unexpected length of received data")
		assert.Equal(t, msg1, string(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.process()
		err = closeAssociationPair(br, a0, a1)
	})

	t.Run("retransmission", func(t *testing.T) {
		var n int
		var ppi PayloadProtocolIdentifier
		br := newConnBridge()

		a0, a1, err := createNewAssociationPair(br)
		if !assert.Nil(t, err, "failed to create associations") {
			assert.FailNow(t, "failed due to earlier error")
		}

		s0, s1, err := establishSessionPair(br, a0, a1, si)
		assert.Nil(t, err, "failed to establish session pair")

		msg1 := "ABC"
		n, err = s0.WriteSCTP([]byte(msg1), PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(msg1), "unexpected length of received data")
		msg2 := "DEFG"
		n, err = s0.WriteSCTP([]byte(msg2), PayloadTypeWebRTCBinary)
		assert.Nil(t, err, "WriteSCTP failed")
		assert.Equal(t, n, len(msg2), "unexpected length of received data")

		br.drop(0, 0, 1) // drop the first packet (second one should be sacked)
		br.process()

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

		br.process()
		err = closeAssociationPair(br, a0, a1)
	})
}

func TestAssocUnreliable(t *testing.T) {
	const si uint16 = 123

	t.Run("Rexmit ordered", func(t *testing.T) {
		br := newConnBridge()

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
		n, err = s0.WriteSCTP([]byte("ABC"), PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, n, 3, "unexpected length of written data")

		n, err = s0.WriteSCTP([]byte("DEFG"), PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, n, 4, "unexpected length of written data")

		br.drop(0, 0, 1) // drop the first packet (second one should be sacked)
		br.process()

		buf := make([]byte, 32)
		n, ppi, err := s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		// should receive the second one only
		assert.Equal(t, "DEFG", string(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.process()
		err = closeAssociationPair(br, a0, a1)
	})

	t.Run("Rexmit unordered", func(t *testing.T) {
		br := newConnBridge()

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
		n, err = s0.WriteSCTP([]byte("ABC"), PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, n, 3, "unexpected length of written data")

		n, err = s0.WriteSCTP([]byte("DEFG"), PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, n, 4, "unexpected length of written data")

		br.drop(0, 0, 1) // drop the first packet (second one should be sacked)
		br.process()

		buf := make([]byte, 32)
		n, ppi, err := s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		// should receive the second one only
		assert.Equal(t, "DEFG", string(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.process()
		err = closeAssociationPair(br, a0, a1)
	})

	t.Run("Timed ordered", func(t *testing.T) {
		br := newConnBridge()

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
		n, err = s0.WriteSCTP([]byte("ABC"), PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, n, 3, "unexpected length of written data")

		n, err = s0.WriteSCTP([]byte("DEFG"), PayloadTypeWebRTCBinary)
		if err != nil {
			assert.FailNow(t, "failed due to earlier error")
		}
		assert.Equal(t, n, 4, "unexpected length of written data")

		br.drop(0, 0, 1) // drop the first packet (second one should be sacked)
		br.process()

		buf := make([]byte, 32)
		n, ppi, err := s1.ReadSCTP(buf)
		if !assert.Nil(t, err, "ReadSCTP failed") {
			assert.FailNow(t, "failed due to earlier error")
		}
		// should receive the second one only
		assert.Equal(t, "DEFG", string(buf[:n]), "unexpected received data")
		assert.Equal(t, ppi, PayloadTypeWebRTCBinary, "unexpected ppi")

		br.process()
		err = closeAssociationPair(br, a0, a1)
	})
}

func TestCreateForwardTSN(t *testing.T) {

	t.Run("forward one abndoned", func(t *testing.T) {
		conn := &testConn{
			br:     nil,
			id:     0,
			readCh: nil,
		}

		a := createAssocation(conn)

		a.cumulativeTSNAckPoint = 9
		a.advancedPeerTSNAckPoint = 10
		a.inflightQueue.pushNoCheck(&chunkPayloadData{
			beginingFragment:     true,
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

	t.Run("forward two abndoned with the same SI", func(t *testing.T) {
		conn := &testConn{
			br:     nil,
			id:     0,
			readCh: nil,
		}

		a := createAssocation(conn)

		a.cumulativeTSNAckPoint = 9
		a.advancedPeerTSNAckPoint = 12
		a.inflightQueue.pushNoCheck(&chunkPayloadData{
			beginingFragment:     true,
			endingFragment:       true,
			tsn:                  10,
			streamIdentifier:     1,
			streamSequenceNumber: 2,
			userData:             []byte("ABC"),
			nSent:                1,
			abandoned:            true,
		})
		a.inflightQueue.pushNoCheck(&chunkPayloadData{
			beginingFragment:     true,
			endingFragment:       true,
			tsn:                  11,
			streamIdentifier:     1,
			streamSequenceNumber: 3,
			userData:             []byte("DEF"),
			nSent:                1,
			abandoned:            true,
		})
		a.inflightQueue.pushNoCheck(&chunkPayloadData{
			beginingFragment:     true,
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
		conn := &testConn{br: nil, id: 0, readCh: nil}
		a := createAssocation(conn)
		a.useForwardTSN = true
		prevTSN := a.peerLastTSN

		fwdtsn := &chunkForwardTSN{
			newCumulativeTSN: a.peerLastTSN + 3,
			streams: []chunkForwardTSNStream{
				chunkForwardTSNStream{identifier: 0, sequence: 0},
			},
		}

		a.handleForwardTSN(fwdtsn)

		assert.Equal(t, a.peerLastTSN, prevTSN+3, "peerLastTSN should advance by 3 ")
	})

	t.Run("forward 1 then one more for received chunk", func(t *testing.T) {
		conn := &testConn{br: nil, id: 0, readCh: nil}
		a := createAssocation(conn)
		a.useForwardTSN = true
		prevTSN := a.peerLastTSN

		// this chunk is blocked by the missing chunk at tsn=1
		a.payloadQueue.push(&chunkPayloadData{
			beginingFragment:     true,
			endingFragment:       true,
			tsn:                  a.peerLastTSN + 2,
			streamIdentifier:     0,
			streamSequenceNumber: 1,
			userData:             []byte("ABC"),
		}, a.peerLastTSN)

		fwdtsn := &chunkForwardTSN{
			newCumulativeTSN: a.peerLastTSN + 1,
			streams: []chunkForwardTSNStream{
				chunkForwardTSNStream{identifier: 0, sequence: 1},
			},
		}

		a.handleForwardTSN(fwdtsn)

		assert.Equal(t, a.peerLastTSN, prevTSN+2, "peerLastTSN should advance by 3 ")
	})
}
