// +build pong

package main

import (
	"fmt"
	"log"
	"net"

	"github.com/pion/sctp"
)

func main() {
	addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5678}

	l, err := sctp.Listen("udp", addr)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	fmt.Println("created a listener")

	// Note: You should accept all incoming associations in a loop.
	stream, err := l.Accept()
	if err != nil {
		log.Fatal(err)
	}
	defer stream.Close()
	fmt.Println("accepted a stream")

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
	}
}
