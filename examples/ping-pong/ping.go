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
		log.Panic(err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			panic(err)
		}
	}()
	fmt.Println("dialed udp ponger")

	config := sctp.Config{
		NetConn:       conn,
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	}
	a, err := sctp.Client(config)
	if err != nil {
		log.Panic(err)
	}
	defer func() {
		if closeErr := a.Close(); closeErr != nil {
			panic(err)
		}
	}()
	fmt.Println("created a client")

	stream, err := a.OpenStream(0, sctp.PayloadTypeWebRTCString)
	if err != nil {
		log.Panic(err)
	}
	defer func() {
		if closeErr := stream.Close(); closeErr != nil {
			panic(err)
		}
	}()
	fmt.Println("opened a stream")

	// set unordered = true and 10ms treshold for dropping packets
	stream.SetReliabilityParams(true, sctp.ReliabilityTypeTimed, 10)

	go func() {
		var pingSeqNum int
		for {
			pingMsg := fmt.Sprintf("ping %d", pingSeqNum)
			_, err = stream.Write([]byte(pingMsg))
			if err != nil {
				log.Panic(err)
			}
			fmt.Println("sent:", pingMsg)
			pingSeqNum++
		}
	}()

	for {
		buff := make([]byte, 1024)
		_, err = stream.Read(buff)
		if err != nil {
			log.Panic(err)
		}
		pongMsg := string(buff)
		fmt.Println("received:", pongMsg)
	}
}
