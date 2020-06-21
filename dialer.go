package sctp

import (
	"net"

	"github.com/pion/logging"
)

// Dial connects to the given network address and establishes a
// SCTP stream on top. For more control use DialAssociation.
func Dial(network string, raddr *net.UDPAddr, streamIdentifier uint16) (*Stream, error) {
	return (&Dialer{}).Dial(network, raddr, streamIdentifier)
}

// A Dialer contains options for connecting to an address.
//
// The zero value for each field is equivalent to dialing without that option.
// Dialing with the zero value of Dialer is therefore equivalent
// to just calling the Dial function.
//
// The net.Conn in the config is ignored.
type Dialer struct {
	// PayloadType determines the PayloadProtocolIdentifier used
	PayloadType PayloadProtocolIdentifier

	// Config holds common config
	Config *Config
}

// Dial connects to the given network address and establishes a
// SCTP stream on top. The net.Conn in the config is ignored.
func (d *Dialer) Dial(network string, raddr *net.UDPAddr, streamIdentifier uint16) (*Stream, error) {
	if d.Config == nil {
		d.Config = &Config{
			LoggerFactory: logging.NewDefaultLoggerFactory(),
		}
	}
	a, err := DialAssociation(network, raddr, *d.Config)
	if err != nil {
		return nil, err
	}

	return a.OpenStream(streamIdentifier, d.PayloadType)
}
