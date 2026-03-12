package elstack

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
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
		return nil, err
	}
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
		resCh <- acceptResult{conn: c, err: err}
	}()

	select {
	case res := <-resCh:
		if res.err != nil {
			return nil, res.err
		}
		return newElStackTcpConn(res.conn), nil
	case <-ln.close:
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
	addr, _ := dest.TCPEndpoint()

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
		return nil, ctx.Err()
	case res := <-resCh:
		if res.err != nil {
			return nil, res.err
		}
		return newElStackTcpConn(res.conn), nil
	}
}

type ElStackTcpConn struct {
	inner     net.Conn
	laddr     net.Addr
	raddr     net.Addr
	readMu    sync.Mutex
	readOnce  sync.Once
	readBuf   []byte
	recvCh    chan []byte
	recvErrCh chan error
	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error
	closeCh   chan struct{}
}

func newElStackTcpConn(c net.Conn) *ElStackTcpConn {
	conn := &ElStackTcpConn{
		inner:     c,
		raddr:     c.RemoteAddr(),
		laddr:     c.LocalAddr(),
		recvCh:    make(chan []byte, 128),
		recvErrCh: make(chan error, 1),
		closeCh:   make(chan struct{}),
	}
	conn.startReader()
	return conn
}

func (c *ElStackTcpConn) startReader() {
	c.readOnce.Do(func() {
		go func() {
			defer close(c.recvCh)

			buf := make([]byte, 64*1024)
			for {
				n, err := c.inner.Read(buf)
				if err != nil {
					select {
					case c.recvErrCh <- err:
					default:
					}
					return
				}
				if n == 0 {
					continue
				}
				p := make([]byte, n)
				copy(p, buf[:n])

				select {
				case c.recvCh <- p:
				case <-c.closeCh:
					return
				}
			}
		}()
	})
}

// net.Conn interface 実装
func (c *ElStackTcpConn) Read(b []byte) (n int, err error) {
	if c == nil || c.inner == nil {
		return 0, net.ErrClosed
	}
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	select {
	case <-c.closeCh:
		return 0, net.ErrClosed
	case err := <-c.recvErrCh:
		return 0, err
	case pkt, ok := <-c.recvCh:
		if !ok {
			select {
			case err := <-c.recvErrCh:
				return 0, err
			default:
				return 0, io.EOF
			}
		}
		if len(pkt) <= len(b) {
			n := copy(b, pkt)
			return n, nil
		}
		n := copy(b, pkt[:len(b)])
		c.readBuf = append(c.readBuf[:0], pkt[n:]...)
		return n, nil
	}
}

func (c *ElStackTcpConn) Write(b []byte) (n int, err error) {
	if c == nil || c.inner == nil {
		return 0, net.ErrClosed
	}
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return c.inner.Write(b)
}

func (c *ElStackTcpConn) Close() error {
	c.closeOnce.Do(func() {
		c.closed.Store(true)
		close(c.closeCh)
		c.closeErr = c.inner.Close()
	})
	return c.closeErr
}

func (c *ElStackTcpConn) LocalAddr() net.Addr                { return c.laddr }
func (c *ElStackTcpConn) RemoteAddr() net.Addr               { return c.raddr }
func (c *ElStackTcpConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *ElStackTcpConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *ElStackTcpConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }
