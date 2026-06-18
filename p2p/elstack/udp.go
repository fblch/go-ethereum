package elstack

import (
	"net"

	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/elstack/el_stack"
)

// ListenELUDP directly creates an el_stack.NewElStackUdpConn
// and casts returned el_stack.ElStackUdpConn pointer to discover.UDPConn interface.
func ListenELUDP(network string, addr *net.UDPAddr) (discover.UDPConn, error) {
	return el_stack.NewElStackUdpConn(network, addr)
}
