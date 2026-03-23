package elstack

import (
	"net"

	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/elstack/el_stack"
)

type ElStackUdpConn struct {
	*el_stack.ElStackUdpConn
}

// ListenELUDP directly creates an el_stack UDP connection and adapts it to discover.UDPConn.
func ListenELUDP(network string, addr *net.UDPAddr) (discover.UDPConn, error) {
	c, err := el_stack.NewElStackUdpConn(network, addr)
	if err != nil {
		return nil, err
	}
	return &ElStackUdpConn{ElStackUdpConn: c}, nil
}
