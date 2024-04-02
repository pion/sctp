package sctp

import (
	"io"
	"net"
	"testing"

	"github.com/pion/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type netConnWrapper struct {
	net.PacketConn
	remoteAddr net.Addr
}

func (c *netConnWrapper) Read(b []byte) (int, error) {
	n, _, err := c.PacketConn.ReadFrom(b)
	return n, err
}

func (c *netConnWrapper) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *netConnWrapper) Write(b []byte) (n int, err error) {
	return c.PacketConn.WriteTo(b, c.remoteAddr)
}

var _ net.Conn = &netConnWrapper{}

func newNetConnPair(p1 net.PacketConn, p2 net.PacketConn) (net.Conn, net.Conn) {
	return &netConnWrapper{
			PacketConn: p1,
			remoteAddr: p2.LocalAddr(),
		},
		&netConnWrapper{
			PacketConn: p2,
			remoteAddr: p1.LocalAddr(),
		}
}

func BenchmarkSCTPThroughput(b *testing.B) {
	b.ReportAllocs()
	p1, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(b, err)
	p2, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(b, err)

	c1, c2 := newNetConnPair(p1, p2)
	var server *Association
	done := make(chan bool)
	go func() {
		var err error
		server, err = Server(Config{
			Name:                 "server",
			NetConn:              c1,
			MaxReceiveBufferSize: 1024 * 1024,
			LoggerFactory:        &logging.DefaultLoggerFactory{},
		})
		require.NoError(b, err)
		done <- true
	}()

	var client *Association
	go func() {
		var err error
		client, err = Client(Config{
			Name:                 "client",
			NetConn:              c2,
			MaxReceiveBufferSize: 1024 * 1024,
			LoggerFactory:        &logging.DefaultLoggerFactory{},
		})
		require.NoError(b, err)
		done <- true
	}()
	<-done
	<-done
	serverBuf := make([]byte, 16*(1<<10))
	clientBuf := make([]byte, 16*(1<<10))
	for i := 0; i < b.N; i++ {
		s, err := client.OpenStream(uint16(i), PayloadTypeWebRTCBinary)
		require.NoError(b, err)
		go func() {
			s, err := server.AcceptStream()
			assert.NoError(b, err)
			for {
				_, err := s.Read(serverBuf)
				if err != nil {
					if err == io.EOF {
						s.Close()
						break
					} else {
						b.Error("invalid err", err)
					}
				}
			}
			done <- true
		}()
		for i := 0; i < 1000; i++ {
			_, err := s.Write(clientBuf)
			require.NoError(b, err)
		}
		s.Close()
		<-done
	}
}
