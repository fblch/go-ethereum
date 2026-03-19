package elstack

import (
	"fmt"
	"net"
	"net/netip"

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

func (c *ElStackUdpConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	n, udpAddr, err := c.ReadFromUDP(b)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if udpAddr == nil {
		return 0, netip.AddrPort{}, fmt.Errorf("el_stack returned nil UDP address")
	}
	return n, udpAddr.AddrPort(), nil
}

func (c *ElStackUdpConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	return c.WriteToUDP(b, net.UDPAddrFromAddrPort(addr))
}
