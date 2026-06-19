package p2p

import (
	"net"
	"sync"

	"github.com/ethereum/go-ethereum/p2p/elstack"
)

const initialELResultsBufferSize = 8

func (srv *Server) setupEL() error {
	// Don't do anything if EL is not configured or disabled.
	if srv.EL == nil || !srv.EL.Use {
		return nil
	}

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

	if err := srv.applyELBindings(addr); err != nil {
		stopEL()
		return err
	}
	go elstack.MonitorEL(results, srv.quit)

	return nil
}

func (srv *Server) applyELBindings(addr net.IP) error {
	_, port, err := net.SplitHostPort(srv.ListenAddr)
	if err != nil {
		return err
	}
	srv.localnode.SetStaticIP(addr) // update staticIP to el_stack IPAddr
	srv.ListenAddr = net.JoinHostPort(addr.String(), port)
	srv.listenFunc = elstack.ListenELTCP
	srv.Dialer = elstack.ElStackTcpDialer{Timeout: defaultDialTimeout}
	srv.listenUDPFunc = elstack.ListenELUDP
	return nil
}
