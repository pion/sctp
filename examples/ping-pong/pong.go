// +build pong

package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/pion/logging"
	"github.com/pion/sctp"
)

func main() {
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}

	config := sctp.Config{
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	}
	l, err := sctp.ListenAssociation("udp", addr, config)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	fmt.Println("created a listener")

	// Note: You should accept all incoming associations in a loop.
	a, err := l.Accept()
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	fmt.Println("accepted an association")

	// Note: You should accept all incoming streams in a loop.
	stream, err := a.AcceptStream()
	if err != nil {
		log.Fatal(err)
	}
	defer stream.Close()
	fmt.Println("accepted a stream")

	// set unordered = true and 10ms treshold for dropping packets
	stream.SetReliabilityParams(true, sctp.ReliabilityTypeTimed, 10)
	var pongSeqNum int
	for {
		buff := make([]byte, 1024)
		_, err = stream.Read(buff)
		if err != nil {
			log.Fatal(err)
		}
		pingMsg := string(buff)
		fmt.Println("received:", pingMsg)

		fmt.Sscanf(pingMsg, "ping %d", &pongSeqNum)
		pongMsg := fmt.Sprintf("pong %d", pongSeqNum)
		_, err = stream.Write([]byte(pongMsg))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("sent:", pongMsg)

		time.Sleep(time.Second)
	}
}
