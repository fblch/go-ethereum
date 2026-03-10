package elstack

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/p2p/elstack/el_stack" // if you copied el_stack directory directly below elstack directory, use it.
	"github.com/ethereum/go-ethereum/p2p/enode"
)

type ElStackTcpListener struct {
	inner     net.Listener
	close     chan struct{}
	closeOnce sync.Once
}

var ElStackTcpListenerClosedErr = errors.New("EL stack TCP listener is already closed.")

// el経由の処理を本ファイルにまとめるためのラッパ関数
func ListenELTCP(network, addr string) (net.Listener, error) {
	ln, err := el_stack.NewElStackTcpListener(network, addr)
	if err != nil {
		elLog.Error("ListenELTCP failed", "network", network, "addr", addr, "err", err)
		return nil, err
	}
	elLog.Info("ListenELTCP ok", "network", network, "addr", addr, "local", ln.Addr())
	listener := &ElStackTcpListener{
		inner: ln,
		close: make(chan struct{}),
	}
	return listener, nil
}

// net.Listener interface 実装
// Accept proxies the el_stack listener while adding timing logs so we can
func (ln *ElStackTcpListener) Accept() (net.Conn, error) {
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	resCh := make(chan acceptResult, 1)

	go func() {
		c, err := ln.inner.Accept()
		elLog.Debug("el_stack.Accept returned")
		resCh <- acceptResult{conn: c, err: err}
	}()

	select {
	case res := <-resCh:
		if res.err != nil {
			elLog.Error("Accept failed", "err", res.err)
			return nil, res.err
		}
		elLog.Debug("Accept success", "ip", res.conn.RemoteAddr())
		return newElStackTcpConn(res.conn), nil
	case <-ln.close:
		elLog.Debug("Accept STOP", "reason", "listener closed")
		return nil, ElStackTcpListenerClosedErr
	}
}

func (ln *ElStackTcpListener) Close() error {
	var err error
	ln.closeOnce.Do(func() {
		err = ln.inner.Close()
		close(ln.close)
	})
	return err
}

func (ln *ElStackTcpListener) Addr() net.Addr { return ln.inner.Addr() }

type ElStackTcpDialer struct {
	dialTimeout time.Duration
}

func NewElStackTcpDialer(timeout time.Duration) *ElStackTcpDialer {
	return &ElStackTcpDialer{dialTimeout: timeout}
}

func (d *ElStackTcpDialer) ensureDialContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, nil
	}
	return context.WithTimeout(ctx, d.dialTimeout)
}

func (d *ElStackTcpDialer) Dial(ctx context.Context, dest *enode.Node) (net.Conn, error) {
	start := time.Now()
	addr, _ := dest.TCPEndpoint()
	addrStr := addr.String()
	elLog.Debug("Dial start", "node", dest.ID(), "addr", addrStr)

	ctx, cancel := d.ensureDialContext(ctx)
	if cancel != nil {
		defer cancel()
	}

	type dialResult struct {
		conn net.Conn
		err  error
	}

	resCh := make(chan dialResult, 1)

	go func() {
		defer close(resCh)
		// Run the potentially long el_stack dial in its own goroutine so the
		// context timeout can cancel it without blocking the caller.
		c, err := el_stack.NewElStackTcpConn("tcp", addr.String())
		if err != nil {
			resCh <- dialResult{err: err}
			return
		}
		resCh <- dialResult{conn: c}
	}()

	select {
	case <-ctx.Done():
		go func() {
			if res, ok := <-resCh; ok && res.conn != nil {
				_ = res.conn.Close()
			}
		}()
		elLog.Error("Dial timeout", "node", dest.ID(), "addr", addrStr, "err", ctx.Err())
		return nil, ctx.Err()
	case res := <-resCh:
		if res.err != nil {
			elLog.Error("Dial failed", "node", dest.ID(), "addr", addrStr, "err", res.err)
			return nil, res.err
		}
		elLog.Trace("Dial success", "node", dest.ID(), "addr", addrStr, "elapsed", time.Since(start))
		return newElStackTcpConn(res.conn), nil
	}
}

type ElStackTcpConn struct {
	inner     net.Conn
	laddr     net.Addr
	raddr     net.Addr
	closeOnce sync.Once
	closeErr  error
	closeCh   chan struct{}
}

func newElStackTcpConn(c net.Conn) *ElStackTcpConn {
	return &ElStackTcpConn{
		inner:   c,
		raddr:   c.RemoteAddr(),
		laddr:   c.LocalAddr(),
		closeCh: make(chan struct{}),
	}
}

// net.Conn interface 実装
func (c *ElStackTcpConn) Read(b []byte) (n int, err error) {
	if c == nil || c.inner == nil {
		return 0, net.ErrClosed
	}

	type readResult struct {
		n   int
		err error
	}
	resCh := make(chan readResult, 1)
	go func() {
		n, err := c.inner.Read(b)
		resCh <- readResult{n: n, err: err}
	}()

	select {
	case <-c.closeCh:
		return 0, net.ErrClosed
	case res := <-resCh:
		return res.n, res.err
	}
}

func (c *ElStackTcpConn) Write(b []byte) (n int, err error) {
	if c == nil || c.inner == nil {
		return 0, net.ErrClosed
	}
	return c.inner.Write(b)
}

func (c *ElStackTcpConn) Close() error {
	c.closeOnce.Do(func() {
		elLog.Trace("ElStackTcpConn Close", "peer", c.raddr)
		c.closeErr = c.inner.Close()
		close(c.closeCh)
	})
	return c.closeErr
}

func (c *ElStackTcpConn) LocalAddr() net.Addr                { return c.laddr }
func (c *ElStackTcpConn) RemoteAddr() net.Addr               { return c.raddr }
func (c *ElStackTcpConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *ElStackTcpConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *ElStackTcpConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }
