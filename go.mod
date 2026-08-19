module github.com/pion/sctp

require (
	github.com/pion/logging v0.2.4
	github.com/pion/randutil v0.1.0
	github.com/pion/transport/v4 v4.1.0
	github.com/stretchr/testify v1.12.1
)

require (
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/time v0.14.0 // indirect
)

go 1.24.0

// Retract version with ZeroChecksum misinterpretation (bi-directional/global handling)
retract v1.8.12
