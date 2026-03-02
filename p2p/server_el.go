package p2p

import (
	"net"

	"github.com/ethereum/go-ethereum/p2p/elstack"
)

func (srv *Server) setupEL() error {
	if err := elstack.ValidateELConfig(srv.EL); err != nil {
		return err
	}

	baseListen := srv.ListenAddr
	results := make(chan elstack.LinkedResult, 1)

	// Start EL stack and wait synchronously for the first IP before binding listeners.
	go elstack.SetupEL(srv.EL, results, srv.quit)
	addr, err := elstack.WaitInitialEL(results)
	if err != nil {
		return err
	}

	srv.applyELBindings(addr, baseListen)
	go srv.monitorEL(results)

	return nil
}

func (srv *Server) applyELBindings(addr net.IP, baseListen string) {
	srv.localnode.SetStaticIP(addr) // update staticIP to el_stack IPAddr
	srv.ListenAddr = addr.String() + baseListen
	srv.listenFunc = elstack.ListenELTCP
	srv.Dialer = elstack.NewElStackTcpDialer(defaultDialTimeout)
	srv.listenUDPFunc = elstack.ListenELUDP
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