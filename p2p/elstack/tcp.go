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

// ListenELTCP is a thin wrapper around el_stack.NewElStackTcpListener.
func ListenELTCP(network, addr string) (net.Listener, error) {
	if strings.TrimSpace(network) == "" {
		return nil, fmt.Errorf("network is empty")
	}
	if strings.TrimSpace(addr) == "" {
		return nil, fmt.Errorf("address is empty")
	}
	return el_stack.NewElStackTcpListener(network, addr)
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
		return conn, nil
	}
}
