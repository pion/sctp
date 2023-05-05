# SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
# SPDX-License-Identifier: MIT

all: ping pong

ping: ping.go conn.go
	go build -o $@

pong: pong.go conn.go
	go build -o $@ -tags $@