// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/pion/logging"
	"github.com/pion/sctp"
)

func main() { //nolint:cyclop
	addr := net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 9899,
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Panic(err)
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			log.Panic(closeErr)
		}
	}()
	fmt.Println("created a udp listener")

	assoc, err := sctp.ServerWithOptions(
		sctp.WithNetConn(&disconnectedPacketConn{pConn: conn}),
		sctp.WithLoggerFactory(logging.NewDefaultLoggerFactory()),
	)
	if err != nil {
		log.Panic(err)
	}
	defer func() {
		if closeErr := assoc.Close(); closeErr != nil {
			log.Panic(closeErr)
		}
	}()
	defer fmt.Println("created a server")

	stream, err := assoc.AcceptStream()
	if err != nil {
		log.Panic(err)
	}
	defer func() {
		if closeErr := stream.Close(); closeErr != nil {
			log.Panic(closeErr)
		}
	}()
	fmt.Println("accepted a stream")

	// set unordered = true and 10ms treshold for dropping packets
	stream.SetReliabilityParams(true, sctp.ReliabilityTypeTimed, 10)
	var pongSeqNum int
	for {
		buff := make([]byte, 1024)
		_, err = stream.Read(buff)
		if err != nil {
			log.Panic(err)
		}
		pingMsg := string(buff)
		fmt.Println("received:", pingMsg)

		_, err = fmt.Sscanf(pingMsg, "ping %d", &pongSeqNum)
		if err != nil {
			log.Panic(err)
		}

		pongMsg := fmt.Sprintf("pong %d", pongSeqNum)
		_, err = stream.Write([]byte(pongMsg))
		if err != nil {
			log.Panic(err)
		}
		fmt.Println("sent:", pongMsg)

		time.Sleep(time.Second)
	}
}
