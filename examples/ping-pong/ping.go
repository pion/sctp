// +build !pong

package main

import (
	"fmt"
	"log"
	"net"

	"github.com/pion/sctp"
)

func main() {
	// Prepare the IP to connect to
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 5678}

	// Open SCTP stream
	stream, err := sctp.Dial("udp", addr, 0)
	if err != nil {
		log.Fatal(err)
	}
	defer stream.Close()
	fmt.Println("opened a stream")

	// set unordered = true and 10ms treshold for dropping packets
	stream.SetReliabilityParams(true, sctp.ReliabilityTypeTimed, 10)

	go func() {
		var pingSeqNum int
		for {
			pingMsg := fmt.Sprintf("ping %d", pingSeqNum)
			_, err = stream.Write([]byte(pingMsg))
			if err != nil {
				log.Fatal(err)
			}
			fmt.Println("sent:", pingMsg)
			pingSeqNum++
		}
	}()

	for {
		buff := make([]byte, 1024)
		_, err = stream.Read(buff)
		if err != nil {
			log.Fatal(err)
		}
		pongMsg := string(buff)
		fmt.Println("received:", pongMsg)
	}
}
