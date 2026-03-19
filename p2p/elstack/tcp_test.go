package elstack

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

func TestListenELTCPRejectsEmptyInputs(t *testing.T) {
	if _, err := ListenELTCP("", "127.0.0.1:30303"); err == nil {
		t.Fatal("expected error for empty network")
	}
	if _, err := ListenELTCP("tcp", ""); err == nil {
		t.Fatal("expected error for empty address")
	}
}

func TestEnsureDialContextKeepsExistingDeadline(t *testing.T) {
	dialer := NewElStackTcpDialer(3 * time.Second)
	base, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ctx, release := dialer.ensureDialContext(base)
	if release != nil {
		t.Fatal("expected nil cancel func when context already has deadline")
	}
	baseDeadline, _ := base.Deadline()
	ctxDeadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected deadline to exist")
	}
	if !ctxDeadline.Equal(baseDeadline) {
		t.Fatalf("deadline changed unexpectedly: base=%v ctx=%v", baseDeadline, ctxDeadline)
	}
}

func TestEnsureDialContextAddsTimeoutWhenMissing(t *testing.T) {
	dialer := NewElStackTcpDialer(2 * time.Second)
	ctx, cancel := dialer.ensureDialContext(context.Background())
	if cancel == nil {
		t.Fatal("expected cancel func for context without deadline")
	}
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected deadline to be added")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > 3*time.Second {
		t.Fatalf("unexpected timeout window: %v", remaining)
	}
}

func TestDialRejectsNilDestination(t *testing.T) {
	dialer := NewElStackTcpDialer(time.Second)
	_, err := dialer.Dial(context.Background(), nil)
	if !errors.Is(err, ErrELStackDialDestinationNil) {
		t.Fatalf("expected ErrELStackDialDestinationNil, got %v", err)
	}
}

func TestDialRejectsNodeWithoutTCPEndpoint(t *testing.T) {
	key, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	node := enode.NewV4(&key.PublicKey, net.ParseIP("127.0.0.1"), 0, 30303)

	dialer := NewElStackTcpDialer(time.Second)
	_, err = dialer.Dial(context.Background(), node)
	if !errors.Is(err, ErrELStackDialDestinationTCP) {
		t.Fatalf("expected ErrELStackDialDestinationTCP, got %v", err)
	}
}
