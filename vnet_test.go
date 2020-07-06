package sctp

import (
	"fmt"
	"math/rand"
	"net"
	"reflect"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/test"
	"github.com/pion/transport/vnet"
	"github.com/stretchr/testify/assert"
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

func (venv *vNetEnv) dropNextReconfigChunk(numToDrop int) {
	venv.numToDropReconfig = numToDrop
}

func (venv *vNetEnv) dropNextCookieEchoChunk(numToDrop int) {
	venv.numToDropCookieEcho = numToDrop
}

func (venv *vNetEnv) dropNextCookieAckChunk(numToDrop int) {
	venv.numToDropCookieAck = numToDrop
}

func buildVNetEnv(cfg *vNetEnvConfig) (*vNetEnv, error) {
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
			if err2 := p.unmarshal(c.UserData()); err2 != nil {
				panic(fmt.Errorf("unable to parse SCTP packet"))
			}

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

	net0 := vnet.NewNet(&vnet.NetConfig{
		StaticIPs: []string{serverIP},
	})
	err = wan.AddNet(net0)
	if err != nil {
		return nil, err
	}

	net1 := vnet.NewNet(&vnet.NetConfig{
		StaticIPs: []string{clientIP},
	})
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

func testRwndFull(t *testing.T, unordered bool) {
	loggerFactory := logging.NewDefaultLoggerFactory()
	log := loggerFactory.NewLogger("test")

	venv, err := buildVNetEnv(&vNetEnvConfig{
		minDelay:      200 * time.Millisecond,
		loggerFactory: loggerFactory,
		log:           log,
	})
	if !assert.NoError(t, err, "should succeed") {
		return
	}
	if !assert.NotNil(t, venv, "should not be nil") {
		return
	}
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
	rand.Read(msg) // nolint:errcheck,gosec

	go func() {
		defer close(serverShutDown)
		// connected UDP conn for server
		conn, err := venv.net0.DialUDP("udp4",
			&net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 5000},
			&net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 5000},
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
			assert.True(t, reflect.DeepEqual(msg, buf[:n]), "msg %d should match", i)
		}

		close(serverReadAll)
		<-shutDownServer
		log.Info("server closing")
	}()

	go func() {
		defer close(clientShutDown)
		// connected UDP conn for client
		conn, err := venv.net1.DialUDP("udp4",
			&net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 5000},
			&net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 5000},
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

func testStreamClose(t *testing.T, dropReconfig bool) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	loggerFactory := logging.NewDefaultLoggerFactory()
	log := loggerFactory.NewLogger("test")

	venv, err := buildVNetEnv(&vNetEnvConfig{
		loggerFactory: loggerFactory,
		log:           log,
	})
	if !assert.NoError(t, err, "should succeed") {
		return
	}
	if !assert.NotNil(t, venv, "should not be nil") {
		return
	}
	defer venv.wan.Stop() // nolint:errcheck

	serverStreamReady := make(chan struct{})
	clientStreamReady := make(chan struct{})
	clientStartClose := make(chan struct{})
	serverStreamClosed := make(chan struct{})
	shutDownClient := make(chan struct{})
	clientShutDown := make(chan struct{})
	serverShutDown := make(chan struct{})

	go func() {
		defer close(serverShutDown)
		// connected UDP conn for server
		conn, err := venv.net0.DialUDP("udp4",
			&net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 5000},
			&net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 5000},
		)
		if !assert.NoError(t, err, "should succeed") {
			return
		}
		defer conn.Close() // nolint:errcheck

		// server association
		assoc, err := Server(Config{
			NetConn:       conn,
			LoggerFactory: loggerFactory,
		})
		if !assert.NoError(t, err, "should succeed") {
			return
		}
		defer assoc.Close() // nolint:errcheck

		log.Info("server handshake complete")

		stream, err := assoc.AcceptStream()
		if !assert.NoError(t, err, "should succeed") {
			return
		}
		defer stream.Close() // nolint:errcheck

		buf := make([]byte, 1500)
		for {
			n, err := stream.Read(buf)
			if err != nil {
				t.Logf("server: Read returned %v", err)
				break
			}

			if !assert.Equal(t, "HELLO", string(buf[:n]), "should receive HELLO") {
				continue
			}

			log.Info("server stream ready")
			close(serverStreamReady)
		}

		close(serverStreamClosed)
		log.Info("server closing")
	}()

	go func() {
		defer close(clientShutDown)
		// connected UDP conn for client
		conn, err := venv.net1.DialUDP("udp4",
			&net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 5000},
			&net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 5000},
		)
		if !assert.NoError(t, err, "should succeed") {
			return
		}

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

		stream.SetReliabilityParams(false, ReliabilityTypeReliable, 0)

		// Send a message to let server side stream to open
		_, err = stream.Write([]byte("HELLO"))
		if !assert.NoError(t, err, "should succeed") {
			return
		}

		buf := make([]byte, 1500)
		done := make(chan struct{})
		go func() {
			for {
				log.Info("client read")
				_, err2 := stream.Read(buf)
				if err2 != nil {
					t.Logf("client: Read returned %v", err2)
					break
				}
			}
			close(done)
		}()

		log.Info("client stream ready")
		close(clientStreamReady)

		<-clientStartClose

		// drop next 1 RECONFIG chunk
		venv.dropNextReconfigChunk(1)

		err = stream.Close()
		assert.NoError(t, err, "should succeed")

		log.Info("client wait for exit reading..")
		<-done

		<-shutDownClient

		// Check if RECONFIG was actually dropped
		assert.Equal(t, 0, venv.numToDropReconfig, "should be zero")

		// Sleep enough time for reconfig response to come back
		time.Sleep(100 * time.Millisecond)

		// Verify there's no more pending reconfig
		assoc.lock.RLock()
		pendingReconfigs := len(assoc.reconfigs)
		assoc.lock.RUnlock()
		assert.Equal(t, 0, pendingReconfigs, "should be zero")

		log.Info("client closing")
	}()

	// wait until both establish a stream
	<-clientStreamReady
	<-serverStreamReady

	log.Info("stream ready")

	// let client begin writing
	log.Info("client start closing")
	close(clientStartClose)

	<-serverStreamClosed
	close(shutDownClient)

	<-clientShutDown
	<-serverShutDown
	log.Info("all done")
}

func TestStreamClose(t *testing.T) {
	t.Run("Normal close", func(t *testing.T) {
		testStreamClose(t, false)
	})

	t.Run("Drop reconfig packet", func(t *testing.T) {
		testStreamClose(t, true)
	})
}

// this test case reproduces the issue mentioned in
// https://github.com/pion/webrtc/issues/1270#issuecomment-653953743
// and confirmes the fix.
// To reproduce the case mentioned above:
// * Use simultaneous-open (SCTP)
// * Drop both of the first COOKIE-ECHO and COOKIE-ACK
func TestCookieEchoRetransmission(t *testing.T) {
	lim := test.TimeOut(time.Second * 10)
	defer lim.Stop()

	loggerFactory := logging.NewDefaultLoggerFactory()
	log := loggerFactory.NewLogger("test")

	venv, err := buildVNetEnv(&vNetEnvConfig{
		minDelay:      200 * time.Millisecond,
		loggerFactory: loggerFactory,
		log:           log,
	})
	if !assert.NoError(t, err, "should succeed") {
		return
	}
	if !assert.NotNil(t, venv, "should not be nil") {
		return
	}
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
			&net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 5000},
			&net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 5000},
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
			&net.UDPAddr{IP: net.ParseIP("2.2.2.2"), Port: 5000},
			&net.UDPAddr{IP: net.ParseIP("1.1.1.1"), Port: 5000},
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
