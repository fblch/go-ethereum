package p2p

import (
	"errors"
	"net"
	"time"

	"github.com/ethereum/go-ethereum/p2p/elstack"
)

func (srv *Server) setupEL() error {
	if err := elstack.ValidateELConfig(srv.EL); err != nil {
		if errors.Is(err, elstack.ErrELDisabled) || errors.Is(err, elstack.ErrELConfigNil) {
			return nil
		}
		return err
	}

	baseListen := srv.ListenAddr
	// Wait synchronously for the first result to align bindings before listeners start.
	addr, err := elstack.StartAndWait(srv.EL, srv.quit)
	if err != nil {
		return err
	}
	srv.applyELBindings(addr, baseListen)
	return nil
}

func (srv *Server) applyELBindings(addr net.IP, baseListen string) {
	srv.localnode.SetStaticIP(addr) // update staticIP to el_stack IPAddr
	srv.ListenAddr = addr.String() + baseListen
	srv.listenFunc = elstack.ListenELTCP
	srv.Dialer = elstack.NewElStackTcpDialer(defaultDialTimeout + 5 * time.Second)
	srv.listenUDPFunc = elstack.ListenELUDP
}
