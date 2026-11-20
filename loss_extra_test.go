package sctp

import (
	"log"
	"sync"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/transport/v5/test"
	"github.com/stretchr/testify/assert"
)

func TestDropRetransmission(t *testing.T) {
	br := test.NewBridge()
	var lock1 sync.Mutex
	shouldDrop := false
	dropped := 0
	br.Filter(1, func(raw []byte) bool {
		lock1.Lock()
		defer lock1.Unlock()
		if shouldDrop && dropped < 2 {
			p := &packet{}
			err := p.unmarshal(false, raw)
			if err != nil {
				return true
			}
			for _, c := range p.chunks {
				if pd, ok := c.(*chunkPayloadData); ok {
					if len(pd.userData) >= 1 {
						if pd.userData[0] == 1 {
							dropped += 1
							return false
						}
					}
				}
			}
		}
		return true
	})
	numT3Timeouts := make(chan uint64)
	shutLoop := make(chan bool, 1)
	go func() {
		for {
			select {
			case <-shutLoop:
				return
			default:
			}
			br.Process()
			time.Sleep(time.Millisecond)
		}
	}()

	go func() {
		server, err := ServerWithOptions(
			WithNetConn(br.GetConn0()),
			WithLoggerFactory(logging.NewDefaultLoggerFactory()),
		)
		if err != nil {
			log.Panic(err)
		}
		defer server.Close()

		s, _ := server.AcceptStream()
		var buf [3000]byte
		for {
			_, err = s.Read(buf[:])
			if err != nil {
				return
			}
		}
	}()

	go func() {
		client, err := ClientWithOptions(
			WithNetConn(br.GetConn1()),
			WithLoggerFactory(logging.NewDefaultLoggerFactory()),
		)
		if err != nil {
			log.Panic(err)
		}
		defer client.Close()

		s, _ := client.OpenStream(0, PayloadTypeWebRTCBinary)
		defer s.Close()
		var buf [3000]byte
		for _ = range 50 {
			_, _ = s.Write(buf[:])
		}

		time.Sleep(1 * time.Millisecond)
		lock1.Lock()
		shouldDrop = true
		lock1.Unlock()
		buf[0] = 1
		s.Write(buf[:64])

		time.Sleep(1 * time.Millisecond)
		buf[0] = 0
		s.Write(buf[:])

		time.Sleep(10000 * time.Millisecond)
		numT3Timeouts <- client.stats.getNumT3Timeouts()
	}()

	assert.True(t, <-numT3Timeouts == 0) //RTO Expiration should not happen
	lock1.Lock()
	assert.True(t, dropped >= 2)
	lock1.Unlock()
	shutLoop <- true
}
