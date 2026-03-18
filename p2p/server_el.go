package p2p

import (
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/p2p/elstack"
)

const initialELResultsBufferSize = 8

func (srv *Server) setupEL() error {
	if err := elstack.ValidateELConfig(srv.EL); err != nil {
		return err
	}

	baseListen := srv.ListenAddr
	results := make(chan elstack.LinkedResult, initialELResultsBufferSize)
	setupQuit := make(chan struct{})
	var stopELOnce sync.Once
	stopEL := func() {
		stopELOnce.Do(func() {
			close(setupQuit)
		})
	}

	// Start EL stack and wait synchronously for the first IP before binding listeners.
	go func() {
		select {
		case <-srv.quit:
			stopEL()
		case <-setupQuit:
		}
	}()
	go elstack.SetupEL(srv.EL, results, setupQuit)
	addr, err := elstack.WaitInitialEL(results)
	if err != nil {
		stopEL()
		return err
	}

	if err := srv.applyELBindings(addr, baseListen); err != nil {
		stopEL()
		return err
	}
	go srv.monitorEL(results)

	return nil
}

func (srv *Server) applyELBindings(addr net.IP, baseListen string) error {
	if strings.TrimSpace(baseListen) == "" {
		return fmt.Errorf("EL enabled requires non-empty ListenAddr")
	}
	_, port, err := net.SplitHostPort(baseListen)
	if err != nil {
		return fmt.Errorf("invalid base ListenAddr %q: %w", baseListen, err)
	}

	srv.localnode.SetStaticIP(addr) // update staticIP to el_stack IPAddr
	srv.ListenAddr = net.JoinHostPort(addr.String(), port)
	srv.listenFunc = elstack.ListenELTCP
	srv.Dialer = elstack.NewElStackTcpDialer(defaultDialTimeout)
	srv.listenUDPFunc = elstack.ListenELUDP
	return nil
}

func (srv *Server) monitorEL(results chan elstack.LinkedResult) {
	for {
		select {
		case result, ok := <-results:
			if !ok {
				srv.log.Error("LinkedResult channel is disabled")
				return
			}
			if result.Err != nil {
				srv.log.Error("EL link disconnected", "reason", result.Err)
			}
		case <-srv.quit:
			return
		}
	}
}
