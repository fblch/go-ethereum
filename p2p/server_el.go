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
	srv.applyELBindings(first.Addr, baseListen, false)

	// Continue to watch for subsequent updates asynchronously.
	go func() {
		for {
			select {
			case upd, ok := <-updates:
				if !ok {
					return
				}
				if upd.Err != nil {
					srv.log.Info("setupEL failed", "reason", upd.Err)
					continue
				}
				if upd.Addr == nil {
					srv.log.Info("setupEL missing IP")
					continue
				}
				srv.applyELBindings(upd.Addr, baseListen, true)
			case <-srv.quit:
				return
			}
		}
	}()
	return nil
}

func (srv *Server) applyELBindings(addr net.IP, baseListen string, restart bool) {
	srv.localnode.SetStaticIP(addr) // update staticIP to el_stack IPAddr
	srv.ListenAddr = addr.String() + baseListen
	srv.listenFunc = elstack.ListenELTCP
	srv.Dialer = elstack.NewElStackTcpDialer(defaultDialTimeout)
	srv.listenUDPFunc = elstack.ListenELUDP

	if !restart {
		return
	}

	// If listeners/discovery are already running, close and rebind on EL.
	listening := srv.listener != nil || srv.discv4 != nil || srv.discv5 != nil
	if listening {
		if srv.listener != nil {
			srv.listener.Close()
			srv.listener = nil
		}
		if srv.discv4 != nil {
			srv.discv4.Close()
			srv.discv4 = nil
		}
		if srv.discv5 != nil {
			srv.discv5.Close()
			srv.discv5 = nil
		}
	}

	// If the server has a listen address, ensure listeners are (re)started with EL bindings.
	if srv.ListenAddr != "" {
		if err := srv.setupListening(); err != nil {
			srv.log.Error("failed to (re)bind EL listener", "err", err)
		}
	}
	if err := srv.setupDiscovery(); err != nil {
		srv.log.Error("failed to (re)start discovery with EL", "err", err)
	}
}
