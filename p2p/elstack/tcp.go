package elstack

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
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
	inner        net.Conn
	laddr        net.Addr
	raddr        net.Addr
	readMu       sync.Mutex
	readOnce     sync.Once
	pending      readPacket
	hasPacket    bool
	recvCh       chan readPacket
	recvErrCh    chan error
	readDLmu     sync.Mutex
	readDeadline time.Time
	readDLCh     chan struct{}
	closed       atomic.Bool
	closeOnce    sync.Once
	closeErr     error
	closeCh      chan struct{}
}

type readPacket struct {
	buf []byte
	off int
	n   int
}

const elStackReadChunkSize = 64 * 1024

var elStackReadBufPool = sync.Pool{
	New: func() any {
		return make([]byte, elStackReadChunkSize)
	},
}

func newElStackTcpConn(c net.Conn) *ElStackTcpConn {
	conn := &ElStackTcpConn{
		inner:     c,
		raddr:     c.RemoteAddr(),
		laddr:     c.LocalAddr(),
		recvCh:    make(chan readPacket, 128),
		recvErrCh: make(chan error, 1),
		readDLCh:  make(chan struct{}),
		closeCh:   make(chan struct{}),
	}
	conn.startReader()
	return conn
}

func (c *ElStackTcpConn) startReader() {
	c.readOnce.Do(func() {
		go func() {
			defer close(c.recvCh)
			for {
				buf := elStackReadBufPool.Get().([]byte)
				n, err := c.inner.Read(buf)

				if n > 0 {
					pkt := readPacket{buf: buf, n: n}
					select {
					case c.recvCh <- pkt:
					case <-c.closeCh:
						elStackReadBufPool.Put(buf)
						return
					}
				} else {
					elStackReadBufPool.Put(buf)
				}

				if err != nil {
					select {
					case c.recvErrCh <- err:
					default:
					}
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

	if c.hasPacket {
		n := copy(b, c.pending.buf[c.pending.off:c.pending.n])
		c.pending.off += n
		if c.pending.off >= c.pending.n {
			elStackReadBufPool.Put(c.pending.buf)
			c.pending = readPacket{}
			c.hasPacket = false
		}
		return n, nil
	}

	for {
		deadline, deadlineChanged := c.snapshotReadDeadline()
		timer := newReadDeadlineTimer(deadline)

		select {
		case <-c.closeCh:
			stopReadDeadlineTimer(timer)
			return 0, net.ErrClosed
		case <-deadlineChanged:
			stopReadDeadlineTimer(timer)
			continue
		case <-readDeadlineTimerC(timer):
			return 0, os.ErrDeadlineExceeded
		case err := <-c.recvErrCh:
			stopReadDeadlineTimer(timer)
			return 0, err
		case pkt, ok := <-c.recvCh:
			stopReadDeadlineTimer(timer)
			if !ok {
				select {
				case err := <-c.recvErrCh:
					return 0, err
				default:
					return 0, io.EOF
				}
			}
			if pkt.n <= len(b) {
				n := copy(b, pkt.buf[:pkt.n])
				elStackReadBufPool.Put(pkt.buf)
				return n, nil
			}
			n := copy(b, pkt.buf[:pkt.n])
			pkt.off = n
			c.pending = pkt
			c.hasPacket = true
			return n, nil
		}
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

func (c *ElStackTcpConn) LocalAddr() net.Addr  { return c.laddr }
func (c *ElStackTcpConn) RemoteAddr() net.Addr { return c.raddr }
func (c *ElStackTcpConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *ElStackTcpConn) SetReadDeadline(t time.Time) error {
	if c == nil || c.inner == nil {
		return net.ErrClosed
	}
	if c.closed.Load() {
		return net.ErrClosed
	}
	c.readDLmu.Lock()
	c.readDeadline = t
	close(c.readDLCh)
	c.readDLCh = make(chan struct{})
	c.readDLmu.Unlock()
	return nil
}

func (c *ElStackTcpConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

func (c *ElStackTcpConn) snapshotReadDeadline() (time.Time, <-chan struct{}) {
	c.readDLmu.Lock()
	defer c.readDLmu.Unlock()
	return c.readDeadline, c.readDLCh
}

func newReadDeadlineTimer(deadline time.Time) *time.Timer {
	if deadline.IsZero() {
		return nil
	}
	timeout := time.Until(deadline)
	if timeout <= 0 {
		return time.NewTimer(0)
	}
	return time.NewTimer(timeout)
}

func stopReadDeadlineTimer(timer *time.Timer) {
	if timer == nil {
		return
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func readDeadlineTimerC(timer *time.Timer) <-chan time.Time {
	if timer == nil {
		return nil
	}
	return timer.C
}
