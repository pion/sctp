// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"bytes"
	crand "crypto/rand"
	"fmt"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/v3/test"
	"github.com/pion/transport/v3/vnet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type vNetEnvConfig struct {
	minDelay      time.Duration
	loggerFactory logging.LoggerFactory
	log           logging.LeveledLogger
}

type vNetEnv struct {
	wan                 *vnet.Router
	net0                *vnet.Net
	net1                *vnet.Net
	numToDropData       int
	numToDropReconfig   int
	numToDropCookieEcho int
	numToDropCookieAck  int
}

func (venv *vNetEnv) dropNextDataChunk(numToDrop int) {
	venv.numToDropData = numToDrop
}

func (venv *vNetEnv) dropNextReconfigChunk(numToDrop int) { // nolint:unused
	venv.numToDropReconfig = numToDrop
}

func (venv *vNetEnv) dropNextCookieEchoChunk(numToDrop int) {
	venv.numToDropCookieEcho = numToDrop
}

func (venv *vNetEnv) dropNextCookieAckChunk(numToDrop int) {
	venv.numToDropCookieAck = numToDrop
}

func buildVNetEnv(t *testing.T, cfg *vNetEnvConfig) (*vNetEnv, error) { //nolint:cyclop
	t.Helper()
	log := cfg.log

	var venv *vNetEnv
	serverIP := "1.1.1.1"
	clientIP := "2.2.2.2"

	wan, err := vnet.NewRouter(&vnet.RouterConfig{
		CIDR:          "0.0.0.0/0",
		MinDelay:      cfg.minDelay,
		MaxJitter:     0 * time.Millisecond,
		LoggerFactory: cfg.loggerFactory,
	})
	if err != nil {
		return nil, err
	}

	tsnAutoLockOnFilter := func() func(vnet.Chunk) bool {
		var lockedOnTSN bool
		var tsn uint32

		return func(c vnet.Chunk) bool {
			var toDrop bool
			p := &packet{}
			assert.NoError(t, p.unmarshal(true, c.UserData()))

		loop:
			for i := 0; i < len(p.chunks); i++ {
				switch chunk := p.chunks[i].(type) {
				case *chunkPayloadData:
					if venv.numToDropData > 0 {
						if !lockedOnTSN {
							tsn = chunk.tsn
							lockedOnTSN = true
							log.Infof("Chunk filter: lock on TSN %d", tsn)
						}
						if chunk.tsn == tsn {
							toDrop = true
							venv.numToDropData--
							log.Infof("Chunk filter:  drop TSN %d", tsn)

							break loop
						}
					}
				case *chunkReconfig:
					if venv.numToDropReconfig > 0 {
						toDrop = true
						venv.numToDropReconfig--
						log.Infof("Chunk filter:  drop RECONFIG %s", chunk.String())

						break loop
					}
				case *chunkCookieEcho:
					if venv.numToDropCookieEcho > 0 {
						toDrop = true
						venv.numToDropCookieEcho--
						log.Infof("Chunk filter:  drop %s", chunk.String())

						break loop
					}
				case *chunkCookieAck:
					if venv.numToDropCookieAck > 0 {
						toDrop = true
						venv.numToDropCookieAck--
						log.Infof("Chunk filter:  drop %s", chunk.String())

						break loop
					}
				}
			}

			return !toDrop
		}
	}
	wan.AddChunkFilter(tsnAutoLockOnFilter())

	net0, err := vnet.NewNet(&vnet.NetConfig{
		StaticIPs: []string{serverIP},
	})
	if err != nil {
		return nil, err
	}

	err = wan.AddNet(net0)
	if err != nil {
		return nil, err
	}

	net1, err := vnet.NewNet(&vnet.NetConfig{
		StaticIPs: []string{clientIP},
	})
	if err != nil {
		return nil, err
	}

	err = wan.AddNet(net1)
	if err != nil {
		return nil, err
	}

	err = wan.Start()
	if err != nil {
		return nil, err
	}

	venv = &vNetEnv{
		wan:  wan,
		net0: net0,
		net1: net1,
	}

	return venv, nil
}

func testRwndFull(t *testing.T, unordered bool) { //nolint:cyclop
	t.Helper()

	loggerFactory := logging.NewDefaultLoggerFactory()
	log := loggerFactory.NewLogger("test")

	venv, err := buildVNetEnv(t, &vNetEnvConfig{
		minDelay:      200 * time.Millisecond,
		loggerFactory: loggerFactory,
		log:           log,
	})
	require.NoError(t, err, "should succeed")
	require.NotNil(t, venv, "should not be nil")
	defer venv.wan.Stop() // nolint:errcheck

	serverHandshakeDone := make(chan struct{})
	clientHandshakeDone := make(chan struct{})
	serverStreamReady := make(chan struct{})
	clientStreamReady := make(chan struct{})
	clientStartWrite := make(chan struct{})
	serverRecvBufFull := make(chan struct{})
	serverStartRead := make(chan struct{})
	serverReadAll := make(chan struct{})
	clientShutDown := make(chan struct{})
	serverShutDown := make(chan struct{})
	shutDownClient := make(chan struct{})
	shutDownServer := make(chan struct{})

	maxReceiveBufferSize := uint32(64 * 1024)
	msgSize := int(float32(maxReceiveBufferSize)/2) + int(initialMTU)
	msg := make([]byte, msgSize)
	n, err := crand.Read(msg)
	require.NoError(t, err, "failed to read random bytes")
	require.Equal(t, len(msg), n, "short random read")

	go func() {
		defer close(serverShutDown)
		// connected UDP conn for server
		conn, err := venv.net0.DialUDP("udp4",
			&net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: defaultSCTPSrcDstPort},
			&net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: defaultSCTPSrcDstPort},
		)
		if !assert.NoError(t, err, "should succeed") {
			return
		}
		defer conn.Close() // nolint:errcheck

		// server association
		assoc, err := Server(Config{
			NetConn:              conn,
			MaxReceiveBufferSize: maxReceiveBufferSize,
			LoggerFactory:        loggerFactory,
		})
		if !assert.NoError(t, err, "should succeed") {
			return
		}
		defer assoc.Close() // nolint:errcheck

		log.Info("server handshake complete")
		close(serverHandshakeDone)

		stream, err := assoc.AcceptStream()
		if !assert.NoError(t, err, "should succeed") {
			return
		}
		defer stream.Close() // nolint:errcheck

		// Expunge the first HELLO packet
		buf := make([]byte, 64*1024)
		n, err := stream.Read(buf)
		if !assert.NoError(t, err, "should succeed") {
			return
		}
		assert.Equal(t, "HELLO", string(buf[:n]), "should match")

		stream.SetReliabilityParams(unordered, ReliabilityTypeReliable, 0)

		log.Info("server stream ready")
		close(serverStreamReady)

		for {
			assoc.lock.RLock()
			rbufSize := assoc.getMyReceiverWindowCredit()
			log.Infof("rbufSize = %d", rbufSize)
			assoc.lock.RUnlock()
			if rbufSize == 0 {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		close(serverRecvBufFull)

		<-serverStartRead
		for i := 0; i < 2; i++ {
			n, err = stream.Read(buf)
			if !assert.NoError(t, err, "should succeed") {
				return
			}
			if !assert.NoError(t, err, "should succeed") {
				return
			}
			log.Infof("server read %d bytes", n)
			assert.Truef(t, reflect.DeepEqual(msg, buf[:n]), "msg %d should match", i)
		}

		close(serverReadAll)
		<-shutDownServer
		log.Info("server closing")
	}()

	go func() {
		defer close(clientShutDown)
		// connected UDP conn for client
		conn, err := venv.net1.DialUDP("udp4",
			&net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: defaultSCTPSrcDstPort},
			&net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: defaultSCTPSrcDstPort},
		)
		if !assert.NoError(t, err, "should succeed") {
			return
		}

		// client association
		assoc, err := Client(Config{
			NetConn:              conn,
			MaxReceiveBufferSize: maxReceiveBufferSize,
			LoggerFactory:        loggerFactory,
		})
		if !assert.NoError(t, err, "should succeed") {
			return
		}
		defer assoc.Close() // nolint:errcheck

		log.Info("client handshake complete")
		close(clientHandshakeDone)

		stream, err := assoc.OpenStream(777, PayloadTypeWebRTCBinary)
		if !assert.NoError(t, err, "should succeed") {
			return
		}
		defer stream.Close() // nolint:errcheck

		// Send a message to let server side stream to open
		_, err = stream.Write([]byte("HELLO"))
		if !assert.NoError(t, err, "should succeed") {
			return
		}

		stream.SetReliabilityParams(unordered, ReliabilityTypeReliable, 0)

		log.Info("client stream ready")
		close(clientStreamReady)

		<-clientStartWrite

		// Set the cwnd and rwnd to the size large enough to send the large messages
		// right away
		assoc.lock.Lock()
		assoc.cwnd = 2 * maxReceiveBufferSize
		assoc.rwnd = 2 * maxReceiveBufferSize
		assoc.lock.Unlock()

		// Send two large messages so that the second one will
		// cause receiver side buffer full
		for i := 0; i < 2; i++ {
			_, err = stream.Write(msg)
			if !assert.NoError(t, err, "should succeed") {
				return
			}
		}

		<-shutDownClient
		log.Info("client closing")
	}()

	//
	// Scenario
	//

	// wait until both handshake complete
	<-clientHandshakeDone
	<-serverHandshakeDone

	log.Info("handshake complete")

	// wait until both establish a stream
	<-clientStreamReady
	<-serverStreamReady

	log.Info("stream ready")

	// drop next 1 DATA chunk sent to the server
	venv.dropNextDataChunk(1)

	// let client begin writing
	log.Info("client start writing")
	close(clientStartWrite)

	// wait until the server's receive buffer becomes full
	<-serverRecvBufFull

	// let server start reading
	close(serverStartRead)

	// wait until the server receives all data
	log.Info("let server start reading")
	<-serverReadAll

	log.Info("server received all data")

	close(shutDownClient)
	<-clientShutDown
	close(shutDownServer)
	<-serverShutDown
	log.Info("all done")
}

func TestRwndFull(t *testing.T) {
	t.Run("Ordered", func(t *testing.T) {
		// Limit runtime in case of deadlocks
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		testRwndFull(t, false)
	})

	t.Run("Unordered", func(t *testing.T) {
		// Limit runtime in case of deadlocks
		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		testRwndFull(t, true)
	})
}

func TestStreamClose(t *testing.T) { //nolint:cyclop
	loopBackTest := func(t *testing.T, dropReconfigChunk bool) {
		t.Helper()

		lim := test.TimeOut(time.Second * 10)
		defer lim.Stop()

		loggerFactory := logging.NewDefaultLoggerFactory()
		log := loggerFactory.NewLogger("test")

		venv, err := buildVNetEnv(t, &vNetEnvConfig{
			loggerFactory: loggerFactory,
			log:           log,
		})
		require.NoError(t, err, "should succeed")
		require.NotNil(t, venv, "should not be nil")
		defer venv.wan.Stop() // nolint:errcheck

		clientShutDown := make(chan struct{})
		serverShutDown := make(chan struct{})

		const numMessages = 10
		const messageSize = 1024
		var messages [][]byte
		var numServerReceived int
		var numClientReceived int

		for i := 0; i < numMessages; i++ {
			bytes := make([]byte, messageSize)
			messages = append(messages, bytes)
		}

		go func() {
			defer close(serverShutDown)
			// connected UDP conn for server
			conn, innerErr := venv.net0.DialUDP("udp4",
				&net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: defaultSCTPSrcDstPort},
				&net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: defaultSCTPSrcDstPort},
			)
			if !assert.NoError(t, innerErr, "should succeed") {
				return
			}
			defer conn.Close() // nolint:errcheck

			// server association
			assoc, innerErr := Server(Config{
				NetConn:       conn,
				LoggerFactory: loggerFactory,
			})
			if !assert.NoError(t, innerErr, "should succeed") {
				return
			}
			defer assoc.Close() // nolint:errcheck

			log.Info("server handshake complete")

			stream, innerErr := assoc.AcceptStream()
			if !assert.NoError(t, innerErr, "should succeed") {
				return
			}
			assert.Equal(t, StreamStateOpen, stream.State())

			buf := make([]byte, 1500)
			for {
				n, errRead := stream.Read(buf)
				if errRead != nil {
					log.Infof("server: Read returned %v", errRead)
					_ = stream.Close() // nolint:errcheck
					assert.Equal(t, StreamStateClosed, stream.State())

					break
				}

				log.Infof("server: received %d bytes (%d)", n, numServerReceived)
				assert.Equal(t, 0, bytes.Compare(buf[:n], messages[numServerReceived]), "should receive HELLO")

				_, err2 := stream.Write(buf[:n])
				assert.NoError(t, err2, "should succeed")

				numServerReceived++
			}
			// don't close association until the client's stream routine is complete
			<-clientShutDown
		}()

		// connected UDP conn for client
		conn, err := venv.net1.DialUDP("udp4",
			&net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: defaultSCTPSrcDstPort},
			&net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: defaultSCTPSrcDstPort},
		)
		if !assert.NoError(t, err, "should succeed") {
			return
		}
		defer conn.Close() // nolint:errcheck

		// client association
		assoc, err := Client(Config{
			NetConn:       conn,
			LoggerFactory: loggerFactory,
		})
		if !assert.NoError(t, err, "should succeed") {
			return
		}
		defer assoc.Close() // nolint:errcheck

		log.Info("client handshake complete")

		stream, err := assoc.OpenStream(777, PayloadTypeWebRTCBinary)
		if !assert.NoError(t, err, "should succeed") {
			return
		}
		assert.Equal(t, StreamStateOpen, stream.State())
		stream.SetReliabilityParams(false, ReliabilityTypeReliable, 0)

		// begin client read-loop
		buf := make([]byte, 1500)
		go func() {
			defer close(clientShutDown)
			for {
				n, err2 := stream.Read(buf)
				if err2 != nil {
					log.Infof("client: Read returned %v", err2)
					assert.Equal(t, StreamStateClosed, stream.State())

					break
				}

				log.Infof("client: received %d bytes (%d)", n, numClientReceived)
				assert.Equal(t, 0, bytes.Compare(buf[:n], messages[numClientReceived]), "should receive HELLO")
				numClientReceived++
			}
		}()

		// Send messages to the server
		for i := 0; i < numMessages; i++ {
			_, err = stream.Write(messages[i])
			assert.NoError(t, err, "should succeed")
		}

		if dropReconfigChunk {
			venv.dropNextReconfigChunk(1)
		}

		// Immediately close the stream
		err = stream.Close()
		assert.NoError(t, err, "should succeed")
		assert.Equal(t, StreamStateClosing, stream.State())

		log.Info("client wait for exit reading..")
		<-clientShutDown

		assert.Equal(t, numMessages, numServerReceived, "all messages should be received")
		assert.Equal(t, numMessages, numClientReceived, "all messages should be received")

		_, err = stream.Write([]byte{1})

		assert.Equal(t, err, ErrStreamClosed, "after closed should not allow write")
		// Check if RECONFIG was actually dropped
		assert.Equal(t, 0, venv.numToDropReconfig, "should be zero")

		// Sleep enough time for reconfig response to come back
		time.Sleep(100 * time.Millisecond)

		// Verify there's no more pending reconfig
		assoc.lock.RLock()
		pendingReconfigs := len(assoc.reconfigs)
		assoc.lock.RUnlock()
		assert.Equal(t, 0, pendingReconfigs, "should be zero")
	}

	t.Run("without dropping Reconfig", func(t *testing.T) {
		loopBackTest(t, false)
	})

	t.Run("with dropping Reconfig", func(t *testing.T) {
		loopBackTest(t, true)
	})
}

// this test case reproduces the issue mentioned in
// https://github.com/pion/webrtc/issues/1270#issuecomment-653953743
// and confirmes the fix.
// To reproduce the case mentioned above:
// * Use simultaneous-open (SCTP)
// * Drop both of the first COOKIE-ECHO and COOKIE-ACK.
func TestCookieEchoRetransmission(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	loggerFactory := logging.NewDefaultLoggerFactory()
	log := loggerFactory.NewLogger("test")

	venv, err := buildVNetEnv(t, &vNetEnvConfig{
		minDelay:      200 * time.Millisecond,
		loggerFactory: loggerFactory,
		log:           log,
	})
	require.NoError(t, err, "should succeed")
	require.NotNil(t, venv, "should not be nil")
	defer venv.wan.Stop() // nolint:errcheck

	// To cause the cookie echo retransmission, both COOKIE-ECHO
	// and COOKIE-ACK chunks need to be dropped at the same time.
	venv.dropNextCookieEchoChunk(1)
	venv.dropNextCookieAckChunk(1)

	serverHandshakeDone := make(chan struct{})
	clientHandshakeDone := make(chan struct{})
	waitAllHandshakeDone := make(chan struct{})
	clientShutDown := make(chan struct{})
	serverShutDown := make(chan struct{})

	maxReceiveBufferSize := uint32(64 * 1024)

	// Go routine for Server
	go func() {
		defer close(serverShutDown)
		// connected UDP conn for server
		conn, err := venv.net0.DialUDP("udp4",
			&net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: defaultSCTPSrcDstPort},
			&net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: defaultSCTPSrcDstPort},
		)
		if !assert.NoError(t, err, "should succeed") {
			return
		}
		defer conn.Close() // nolint:errcheck

		// server association
		// using Client for simultaneous open
		assoc, err := Client(Config{
			NetConn:              conn,
			MaxReceiveBufferSize: maxReceiveBufferSize,
			LoggerFactory:        loggerFactory,
		})
		if !assert.NoError(t, err, "should succeed") {
			return
		}
		defer assoc.Close() // nolint:errcheck

		log.Info("server handshake complete")
		close(serverHandshakeDone)
		<-waitAllHandshakeDone
	}()

	// Go routine for Client
	go func() {
		defer close(clientShutDown)
		// connected UDP conn for client
		conn, err := venv.net1.DialUDP("udp4",
			&net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: defaultSCTPSrcDstPort},
			&net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: defaultSCTPSrcDstPort},
		)
		if !assert.NoError(t, err, "should succeed") {
			return
		}

		// client association
		assoc, err := Client(Config{
			NetConn:              conn,
			MaxReceiveBufferSize: maxReceiveBufferSize,
			LoggerFactory:        loggerFactory,
		})
		if !assert.NoError(t, err, "should succeed") {
			return
		}
		defer assoc.Close() // nolint:errcheck

		log.Info("client handshake complete")
		close(clientHandshakeDone)
		<-waitAllHandshakeDone
	}()

	//
	// Scenario
	//

	// wait until both handshake complete
	<-clientHandshakeDone
	<-serverHandshakeDone
	close(waitAllHandshakeDone)

	log.Info("handshake complete")

	<-clientShutDown
	<-serverShutDown
	log.Info("all done")
}

// Simulate an RTT switch (high -> low) by delaying early DATA, then disabling delay so
// later DATA arrives before earlier DATA. Under a RACK regression, rackMinRTT would never increases,
// causing reoWnd to be too small and marking packets sent at high RTT as spuriously lost.
func TestRACK_RTTSwitch_Reordering_NoDrop(t *testing.T) { //nolint:gocyclo,cyclop,maintidx
	lim := test.TimeOut(10 * time.Second)
	defer lim.Stop()

	loggerFactory := logging.NewDefaultLoggerFactory()
	log := loggerFactory.NewLogger("test-rack-rtt-switch")

	venv, err := buildVNetEnv(t, &vNetEnvConfig{
		minDelay:      0,
		loggerFactory: loggerFactory,
		log:           log,
	})
	require.NoError(t, err)
	require.NotNil(t, venv)

	defer venv.wan.Stop() // nolint:errcheck

	var delayOn atomic.Value
	delayOn.Store(true)
	venv.wan.AddChunkFilter(func(c vnet.Chunk) bool {
		p := &packet{}
		if err := p.unmarshal(true, c.UserData()); err != nil {
			return true
		}
		v := delayOn.Load()
		if val, ok := v.(bool); ok && !val {
			return true
		}
		for i := 0; i < len(p.chunks); i++ {
			if _, ok := p.chunks[i].(*chunkPayloadData); ok {
				time.Sleep(100 * time.Millisecond)

				break
			}
		}

		return true
	})

	const (
		numMessages = 40
		messageSize = 256
	)

	makeMessages := func() [][]byte {
		msgs := make([][]byte, numMessages)
		for i := 0; i < numMessages; i++ {
			b := bytes.Repeat([]byte{byte(i % 251)}, messageSize)
			msgs[i] = b
		}

		return msgs
	}

	type statsResult struct {
		fr uint64
		ok bool
	}

	errCh := make(chan error, 16)
	clientDone := make(chan struct{})
	serverDone := make(chan struct{})
	clientStatsCh := make(chan statsResult, 1)
	serverStatsCh := make(chan statsResult, 1)

	go func() {
		defer close(serverDone)

		fail := func(e error) {
			if e != nil {
				errCh <- e
			}
		}

		conn, err := venv.net0.DialUDP("udp4",
			&net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: defaultSCTPSrcDstPort},
			&net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: defaultSCTPSrcDstPort},
		)
		if err != nil {
			fail(fmt.Errorf("server DialUDP: %w", err))
			serverStatsCh <- statsResult{ok: false}

			return
		}

		defer conn.Close() // nolint:errcheck

		assoc, err := Server(Config{
			NetConn:       conn,
			LoggerFactory: loggerFactory,
		})
		if err != nil {
			fail(fmt.Errorf("server assoc: %w", err))
			serverStatsCh <- statsResult{ok: false}

			return
		}

		defer func() {
			var fr uint64
			if assoc != nil {
				fr = assoc.stats.getNumFastRetrans()
			}
			serverStatsCh <- statsResult{fr: fr, ok: assoc != nil}
			_ = assoc.Close()
		}()

		stream, err := assoc.AcceptStream()
		if err != nil {
			fail(fmt.Errorf("server AcceptStream: %w", err))

			return
		}
		defer stream.Close() // nolint:errcheck
		stream.SetReliabilityParams(false, ReliabilityTypeReliable, 0)

		buf := make([]byte, 1500)
		for {
			_ = stream.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			n, rerr := stream.Read(buf)
			if rerr != nil {
				return
			}
			if n > 0 {
				_, _ = stream.Write(buf[:n])
			}
		}
	}()

	go func() {
		defer close(clientDone)

		fail := func(e error) {
			if e != nil {
				errCh <- e
			}
		}

		conn, err := venv.net1.DialUDP("udp4",
			&net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: defaultSCTPSrcDstPort},
			&net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: defaultSCTPSrcDstPort},
		)
		if err != nil {
			fail(fmt.Errorf("client DialUDP: %w", err))
			clientStatsCh <- statsResult{ok: false}

			return
		}
		defer conn.Close() // nolint:errcheck

		assoc, err := Client(Config{
			NetConn:       conn,
			LoggerFactory: loggerFactory,
		})
		if err != nil {
			fail(fmt.Errorf("client assoc: %w", err))
			clientStatsCh <- statsResult{ok: false}

			return
		}

		defer func() {
			var fr uint64
			if assoc != nil {
				fr = assoc.stats.getNumFastRetrans()
			}
			clientStatsCh <- statsResult{fr: fr, ok: assoc != nil}
			_ = assoc.Close()
		}()

		stream, err := assoc.OpenStream(777, PayloadTypeWebRTCBinary)
		if err != nil {
			fail(fmt.Errorf("client OpenStream: %w", err))

			return
		}
		defer stream.Close() // nolint:errcheck
		stream.SetReliabilityParams(false, ReliabilityTypeReliable, 0)

		msgs := makeMessages()

		// phase 1: high-RTT emulation we send 25 messages and drop a DATA chunk for one time.
		delayOn.Store(true)
		venv.dropNextDataChunk(1)
		for i := 0; i < 25; i++ {
			if _, werr := stream.Write(msgs[i]); werr != nil {
				fail(fmt.Errorf("client write phase1 i=%d: %w", i, werr))

				return
			}
		}

		// phase 2 we switch to low-RTT, newer datea should arrive before older.
		delayOn.Store(false)
		for i := 25; i < numMessages; i++ {
			if _, werr := stream.Write(msgs[i]); werr != nil {
				fail(fmt.Errorf("client write phase2 i=%d: %w", i, werr))

				return
			}
		}

		seen := make(map[byte]bool, numMessages)
		buf := make([]byte, 4096)
		deadline := time.Now().Add(10 * time.Second)

		for len(seen) < numMessages && time.Now().Before(deadline) {
			_ = stream.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
			n, rerr := stream.Read(buf)
			if rerr != nil || n == 0 {
				continue
			}
			if n < messageSize {
				fail(fmt.Errorf("short echo read: got=%d want=%d", n, messageSize)) //nolint:err113

				return
			}
			id := buf[0]
			if seen[id] {
				// dups are harmless, keep reading
				continue
			}

			expected := bytes.Repeat([]byte{id}, messageSize)
			if !bytes.Equal(buf[:messageSize], expected) {
				fail(fmt.Errorf("payload mismatch for id=%d", int(id))) //nolint:err113

				return
			}
			seen[id] = true
		}

		if len(seen) != numMessages {
			fail(fmt.Errorf("missing echoes: got=%d want=%d", len(seen), numMessages)) //nolint:err113

			return
		}
	}()

	<-clientDone
	<-serverDone

	// drain and assert errors, well if any :)
	close(errCh)
	for e := range errCh {
		assert.NoError(t, e)
	}

	// check FR stats reported.
	cs := <-clientStatsCh
	ss := <-serverStatsCh

	if assert.True(t, cs.ok, "client assoc/stats unavailable") {
		assert.LessOrEqual(t, cs.fr, uint64(2),
			"client fast retransmits should be low")
	}

	if assert.True(t, ss.ok, "server assoc/stats unavailable") {
		assert.LessOrEqual(t, ss.fr, uint64(2),
			"server fast retransmits should be low")
	}
}
