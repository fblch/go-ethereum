package elstack

import (
	"context"
	"net"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/p2p/elstack/el_stack"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

// ListenELTCP directly calls el_stack.NewElStackTcpListener.
func ListenELTCP(network, addr string) (net.Listener, error) {
	return el_stack.NewElStackTcpListener(network, addr)
}

// ElStackTcpDialer implements NodeDialer using EL tunneled TCP connections.
type ElStackTcpDialer struct {
	Timeout time.Duration
}

// Dial implements NodeDialer interface using EL tunneled TCP connections.
func (d ElStackTcpDialer) Dial(ctx context.Context, dest *enode.Node) (net.Conn, error) {
	// net.Dailer.DialContext also panics if ctx is nil, so we do the same here for consistency.
	if ctx == nil {
		panic("nil context")
	}

	// Choose the smaller value from the dialer's Timeout and the context's deadline, if any.
	// Zero means no timeout, values smallert than a millisecond cause immediate timeout.
	timeout := d.Timeout
	if timeout < 0 || timeout > 0 && timeout < time.Second {
		return nil, os.ErrDeadlineExceeded
	}
	if deadline, ok := ctx.Deadline(); ok {
		timeUntilDeadline := time.Until(deadline)
		if timeUntilDeadline < time.Second {
			return nil, os.ErrDeadlineExceeded
		}
		if timeout == 0 || timeUntilDeadline < timeout {
			timeout = timeUntilDeadline
		}
	}

	// p2p.tcpDialer.Dial only gets the TCPEndpoint and calls net.Dailer.DialContext,
	// so we do the same here for consistency, but call el_stack.NewElStackTcpConn instead.
	addr, _ := dest.TCPEndpoint()
	return el_stack.NewElStackTcpConn("tcp", addr.String(), timeout.Seconds())
}