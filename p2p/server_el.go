package p2p

import (
	"errors"
	"fmt"
	"net"

	"github.com/ethereum/go-ethereum/p2p/elstack"
)

func (srv *Server) setupEL() error {
	if err := elstack.ValidateELConfig(srv.EL); err != nil {
		if errors.Is(err, elstack.ErrELDisabled) || errors.Is(err, elstack.ErrELConfigNil) {
			return nil
		}
		return err
	}

	updates := make(chan elstack.VpnDelegate, 1)
	baseListen := srv.ListenAddr
	elstack.SetupEL(srv.EL, updates, srv.quit) // initial sync (returns immediately if config invalid)

	// Wait synchronously for the first result to align bindings before listeners start.
	first, ok := <-updates
	if !ok {
		return fmt.Errorf("EL setup terminated before initial link")
	}
	if first.Err != nil {
		return first.Err
	}
	if first.Addr == nil {
		return fmt.Errorf("EL setup returned nil IP")
	}
	srv.applyELBindings(first.Addr, baseListen)
	return nil
}

func (srv *Server) applyELBindings(addr net.IP, baseListen string) {
	srv.localnode.SetStaticIP(addr) // update staticIP to el_stack IPAddr
	srv.ListenAddr = addr.String() + baseListen
	srv.listenFunc = elstack.ListenELTCP
	srv.Dialer = elstack.NewElStackTcpDialer(defaultDialTimeout)
	srv.listenUDPFunc = elstack.ListenELUDP
}
