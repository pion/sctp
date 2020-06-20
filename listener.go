package sctp

import (
	"net"

	"github.com/pion/udp"
)

// ListenAssociation creates a SCTP association listener
func ListenAssociation(network string, laddr *net.UDPAddr, config Config) (*AssociationListener, error) {
	lc := udp.ListenConfig{}
	parent, err := lc.Listen(network, laddr)
	if err != nil {
		return nil, err
	}
	return &AssociationListener{
		config: config,
		parent: parent,
	}, nil
}

// NewAssociationListener creates a SCTP association listener
// which accepts connections from an inner Listener.
// The net.Conn in the config is ignored.
func NewAssociationListener(inner net.Listener, config Config) (*AssociationListener, error) {
	return &AssociationListener{
		config: config,
		parent: inner,
	}, nil
}

// AssociationListener represents a SCTP association listener
type AssociationListener struct {
	config Config
	parent net.Listener
}

// Accept waits for and returns the next association to the listener.
// You have to either close or read on all connection that are created.
func (l *AssociationListener) Accept() (*Association, error) {
	c, err := l.parent.Accept()
	if err != nil {
		return nil, err
	}
	l.config.NetConn = c
	return Server(l.config)
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
// Already Accepted connections are not closed.
func (l *AssociationListener) Close() error {
	return l.parent.Close()
}

// Addr returns the listener's network address.
func (l *AssociationListener) Addr() net.Addr {
	return l.parent.Addr()
}
