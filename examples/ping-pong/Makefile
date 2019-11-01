all: ping pong

ping: ping.go conn.go
	go build -o $@

pong: pong.go conn.go
	go build -o $@ -tags $@