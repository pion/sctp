// +build !pong

package main

import (
	"fmt"
	"log"
	"net"

	"github.com/pion/logging"
	"github.com/pion/sctp"
)

func main() {
	conn, err := net.Dial("udp", "127.0.0.1:5678")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	fmt.Println("dialed udp ponger")

	config := sctp.Config{
		NetConn:       conn,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	}
	a, err := sctp.Client(config)
	if err != nil {
		log.Fatal(err)
	}
	defer a.Close()
	fmt.Println("created a client")

	stream, err := a.OpenStream(0, sctp.PayloadTypeWebRTCString)
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
