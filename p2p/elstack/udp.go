package elstack

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/elstack/el_stack"
)

type ElStackUdpConn struct {
	inner *el_stack.ElStackUdpConn
	laddr net.Addr
}

// ListenELUDP is a thin wrapper around el_stack.NewElStackUdpConn.
func ListenELUDP(network string, addr *net.UDPAddr) (discover.UDPConn, error) {
	if strings.TrimSpace(network) == "" {
		return nil, fmt.Errorf("network is empty")
	}
	c, err := el_stack.NewElStackUdpConn(network, addr)
	if err != nil {
		return nil, err
	}
	return &ElStackUdpConn{inner: c, laddr: c.LocalAddr()}, nil
}

func (c *ElStackUdpConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	if c == nil || c.inner == nil {
		return 0, netip.AddrPort{}, net.ErrClosed
	}
	n, udpAddr, err := c.inner.ReadFromUDP(b)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	if udpAddr == nil {
		return 0, netip.AddrPort{}, fmt.Errorf("el_stack returned nil UDP address")
	}
	return n, udpAddr.AddrPort(), nil
}

func (c *ElStackUdpConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	if c == nil || c.inner == nil {
		return 0, net.ErrClosed
	}
	return c.inner.WriteToUDP(b, net.UDPAddrFromAddrPort(addr))
}

func (c *ElStackUdpConn) Close() error {
	if c == nil || c.inner == nil {
		return net.ErrClosed
	}
	return c.inner.Close()
}

func (c *ElStackUdpConn) LocalAddr() net.Addr {
	if c == nil {
		return nil
	}
	if c.laddr != nil {
		return c.laddr
	}
	if c.inner == nil {
		return nil
	}
	return c.inner.LocalAddr()
}
