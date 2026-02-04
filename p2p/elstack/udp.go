package elstack

import (
	"net"
	"net/netip"
	"os"
	"sync"

	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/elstack/el_stack" // if you copied el_stack directory directly below elstack directory, use it.
)

type ElStackUdpConn struct {
	inner     *el_stack.ElStackUdpConn
	laddr     net.Addr
	closeOnce sync.Once
	closeErr  error
	closeCh   chan struct{}
}

func ListenELUDP(network string, addr *net.UDPAddr) (discover.UDPConn, error) {
	c, err := el_stack.NewElStackUdpConn(network, addr)
	if err != nil {
		elLog.Error("UDP Bind FAILED", "err", err)
		return &ElStackUdpConn{closeCh: make(chan struct{})}, err
	}
	localAddr := c.LocalAddr()
	elLog.Info("ListenELUDP ok", "network", network, "addr", addr, "local", localAddr)
	return &ElStackUdpConn{inner: c, laddr: localAddr, closeCh: make(chan struct{})}, nil
}

func (c *ElStackUdpConn) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	type readResult struct {
		n    int
		addr netip.AddrPort
		err  error
	}

	resCh := make(chan readResult, 1)

	go func() {
		defer close(resCh)
		n, udpAddr, err := c.inner.ReadFromUDP(b)
		if err != nil {
			elLog.Error("ElStackUdpConn ReadFromUDP failed", "err", err)
			resCh <- readResult{err: err}
			return
		}
		resCh <- readResult{
			n:    n,
			addr: udpAddr.AddrPort(),
			err:  nil,
		}
	}()

	select {
	case res := <-resCh:
		return res.n, res.addr, res.err
	case <-c.closeCh:
		return 0, netip.AddrPort{}, os.ErrClosed
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
			if c.closeCh != nil {
				close(c.closeCh)
			}
		})
	}
	return c.closeErr
}

func (c *ElStackUdpConn) LocalAddr() net.Addr { return c.laddr }
