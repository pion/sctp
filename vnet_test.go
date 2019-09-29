package sctp

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/vnet"
	"github.com/stretchr/testify/assert"
)

type vNetEnvConfig struct {
	loggerFactory logging.LoggerFactory
}

type vNetEnv struct {
	wan       *vnet.Router
	net0      *vnet.Net
	net1      *vnet.Net
	numToDrop int
}

func (venv *vNetEnv) dropNextDataChunk(numToDrop int) {
	venv.numToDrop = numToDrop
}

func buildVNetEnv(cfg *vNetEnvConfig) (*vNetEnv, error) {
	var venv *vNetEnv
	serverIP := "1.1.1.1"
	clientIP := "2.2.2.2"

	wan, err := vnet.NewRouter(&vnet.RouterConfig{
		CIDR:          "0.0.0.0/0",
		MinDelay:      200 * time.Millisecond,
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
			var hasDataChunkToDrop bool
			if venv.numToDrop > 0 {
				p := &packet{}
				if err2 := p.unmarshal(c.UserData()); err2 != nil {
					panic(fmt.Errorf("unable to parse SCTP packet"))
				}

			loop:
				for i := 0; i < len(p.chunks); i++ {
					switch chunk := p.chunks[i].(type) {
					case *chunkPayloadData:
						if !lockedOnTSN {
							tsn = chunk.tsn
							lockedOnTSN = true
						}
						if chunk.tsn == tsn {
							hasDataChunkToDrop = true
							venv.numToDrop--
							break loop
						}
					}
				}
			}
			return !hasDataChunkToDrop
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

func TestRwndFull(t *testing.T) {
	loggerFactory := logging.NewDefaultLoggerFactory()
	log := loggerFactory.NewLogger("test")

	venv, err := buildVNetEnv(&vNetEnvConfig{
		loggerFactory: loggerFactory,
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

		log.Info("server handlshake complete")
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
			NetConn:       conn,
			LoggerFactory: loggerFactory,
		})
		if !assert.NoError(t, err, "should succeed") {
			return
		}
		defer assoc.Close() // nolint:errcheck

		log.Info("client handlshake complete")
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

		log.Info("client stream ready")
		close(clientStreamReady)

		<-clientStartWrite

		// Set the cwnd and rwnd to the size large enough to send the large messages
		// right away
		assoc.lock.Lock()
		assoc.cwnd = 2 * maxReceiveBufferSize
		assoc.rwnd = 2 * maxReceiveBufferSize
		assoc.lock.Unlock()

		msgSize := int(float32(maxReceiveBufferSize) * 0.75)
		buf := make([]byte, msgSize)

		// Send two large messages so that the second one will
		// cause receiver side buffer full
		for i := 0; i < 2; i++ {
			_, err = stream.Write(buf)
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
