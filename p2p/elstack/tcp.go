package elstack

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/p2p/elstack/el_stack"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

var (
	ErrELStackDialDestinationNil = errors.New("EL stack dial destination is nil")
	ErrELStackDialDestinationTCP = errors.New("EL stack dial destination has no TCP endpoint")
)

type elStackTcpListener struct {
	inner net.Listener
}

func (l *elStackTcpListener) Accept() (net.Conn, error) {
	conn, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}
	return newElStackTcpConn(conn), nil
}

func (l *elStackTcpListener) Close() error {
	return l.inner.Close()
}

func (l *elStackTcpListener) Addr() net.Addr {
	return l.inner.Addr()
}

type ElStackTcpConn struct {
	inner      net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

func newElStackTcpConn(conn net.Conn) net.Conn {
	if conn == nil {
		return nil
	}
	return &ElStackTcpConn{
		inner:      conn,
		localAddr:  conn.LocalAddr(),
		remoteAddr: conn.RemoteAddr(),
	}
}

func (c *ElStackTcpConn) Read(b []byte) (int, error) {
	return c.inner.Read(b)
}

func (c *ElStackTcpConn) Write(b []byte) (int, error) {
	return c.inner.Write(b)
}

func (c *ElStackTcpConn) Close() error {
	return c.inner.Close()
}

func (c *ElStackTcpConn) LocalAddr() net.Addr {
	if c.localAddr != nil {
		return c.localAddr
	}
	return c.inner.LocalAddr()
}

func (c *ElStackTcpConn) RemoteAddr() net.Addr {
	if c.remoteAddr != nil {
		return c.remoteAddr
	}
	return c.inner.RemoteAddr()
}

func (c *ElStackTcpConn) SetDeadline(t time.Time) error {
	return c.inner.SetDeadline(t)
}

func (c *ElStackTcpConn) SetReadDeadline(t time.Time) error {
	return c.inner.SetReadDeadline(t)
}

func (c *ElStackTcpConn) SetWriteDeadline(t time.Time) error {
	return c.inner.SetWriteDeadline(t)
}

// ListenELTCP is a thin wrapper around el_stack.NewElStackTcpListener.
func ListenELTCP(network, addr string) (net.Listener, error) {
	if strings.TrimSpace(network) == "" {
		return nil, fmt.Errorf("network is empty")
	}
	if strings.TrimSpace(addr) == "" {
		return nil, fmt.Errorf("address is empty")
	}
	ln, err := el_stack.NewElStackTcpListener(network, addr)
	if err != nil {
		return nil, err
	}
	return &elStackTcpListener{inner: ln}, nil
}

type ElStackTcpDialer struct {
	dialTimeout time.Duration
}

func NewElStackTcpDialer(timeout time.Duration) *ElStackTcpDialer {
	return &ElStackTcpDialer{dialTimeout: timeout}
}

func (d *ElStackTcpDialer) ensureDialContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); ok || d == nil || d.dialTimeout <= 0 {
		return ctx, nil
	}
	return context.WithTimeout(ctx, d.dialTimeout)
}

func (d *ElStackTcpDialer) Dial(ctx context.Context, dest *enode.Node) (net.Conn, error) {
	if dest == nil {
		return nil, ErrELStackDialDestinationNil
	}
	addr, ok := dest.TCPEndpoint()
	if !ok {
		return nil, ErrELStackDialDestinationTCP
	}

	ctx, cancel := d.ensureDialContext(ctx)
	if cancel != nil {
		defer cancel()
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	conn, err := el_stack.NewElStackTcpConn("tcp", addr.String())
	if err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		_ = conn.Close()
		return nil, ctx.Err()
	default:
		return newElStackTcpConn(conn), nil
	}
}
