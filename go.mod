module github.com/pion/sctp

require (
	github.com/pion/logging v0.2.4
	github.com/pion/randutil v0.1.0
	github.com/pion/transport/v3 v3.1.0
	github.com/stretchr/testify v1.11.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/pretty v0.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/check.v1 v1.0.0-20190902080502-41f04d3bba15 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

go 1.21

// Retract version with ZeroChecksum misinterpretation (bi-directional/global handling)
retract v1.8.12
