package elstack

import (
	"el_stack"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/p2p/discover"
)

type ElStackUdpConn struct {
	inner     *el_stack.ElStackUdpConn
	laddr     net.Addr
	closeOnce sync.Once
	closeErr  error
}

func ListenELUDP(network string, addr *net.UDPAddr) (discover.UDPConn, error) {
	c, err := el_stack.NewElStackUdpConn(network, addr)
	if err != nil {
		elLog.Error("UDP Bind FAILED", "err", err)
		return &ElStackUdpConn{}, err
	}
	localAddr := c.LocalAddr()
	return &ElStackUdpConn{inner: c, laddr: localAddr}, nil
}

func (c *ElStackUdpConn) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	// Set read deadline and ensure reset after read.
	for {
		_ = c.inner.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, udpAddr, uerr := c.inner.ReadFromUDP(b)
		_ = c.inner.SetReadDeadline(time.Time{})

		if uerr != nil {
			// el_stack signals a timeout via the string below; treat it as a retryable
			// condition instead of bubbling an opaque error up the stack.
			if strings.Contains(uerr.Error(), "SocketError: UdpRecvTimeout") {
				time.Sleep(400 * time.Millisecond)
				continue
			}
			return 0, netip.AddrPort{}, &net.OpError{Op: "read", Net: "udp", Source: c.laddr, Addr: nil, Err: uerr}
		}
		return n, udpAddr.AddrPort(), nil
	}
}

func (c *ElStackUdpConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (n int, err error) {
	n, uerr := c.inner.WriteToUDP(b, net.UDPAddrFromAddrPort(addr))
	if uerr != nil {
		// Wrap the el_stack error so callers still observe the familiar net.Error
		// surface that the discovery stack already knows how to handle.
		return n, &net.OpError{Op: "write", Net: "udp", Source: c.laddr, Addr: net.UDPAddrFromAddrPort(addr), Err: uerr}
	}
	return n, nil
}

// discover.UDPConn の要件を満たすためのラッパーメソッド
func (c *ElStackUdpConn) Close() error {
	if c.inner != nil {
		c.closeOnce.Do(func() {
			// Make Close idempotent because geth can close the socket from multiple
			// goroutines during shutdown.
			c.closeErr = c.inner.Close()
		})
	}
	return c.closeErr
}

func (c *ElStackUdpConn) LocalAddr() net.Addr { return c.laddr }
