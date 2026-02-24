package p2p

import (
	"errors"
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

	baseListen := srv.ListenAddr
	updates := make(chan elstack.VpnDelegate, 16)

	// Start EL stack and wait synchronously for the first IP before binding listeners.
	elstack.SetupEL(srv.EL, updates, srv.quit)
	addr, err := elstack.WaitInitialEL(updates)
	if err != nil {
		return err
	}
	srv.applyELBindings(addr, baseListen)
	go srv.monitorEL(updates)
	return nil
}

func (srv *Server) applyELBindings(addr net.IP, baseListen string) {
	srv.localnode.SetStaticIP(addr) // update staticIP to el_stack IPAddr
	srv.ListenAddr = addr.String() + baseListen
	srv.listenFunc = elstack.ListenELTCP
	srv.Dialer = elstack.NewElStackTcpDialer(defaultDialTimeout)
	srv.listenUDPFunc = elstack.ListenELUDP
}

// monitorEL watches EL status updates and enforces a timeout when disconnected.
func (srv *Server) monitorEL(updates <-chan elstack.VpnDelegate) {
	currentIP := net.IP(nil)
	if srv.localnode != nil {
		if n := srv.localnode.Node(); n != nil {
			currentIP = n.IP()
		}
	}
	for {
		select {
		case <-srv.quit:
			return
		case u, ok := <-updates:
			if !ok {
				return
			}
			if u.Addr != nil {
				if !u.Addr.Equal(currentIP) {
					srv.log.Info("EL IP updated", "old", currentIP, "new", u.Addr)
					// Re-use whatever port is currently in ListenAddr. If none, default to empty suffix.
					suffix := ""
					if _, port, err := net.SplitHostPort(srv.ListenAddr); err == nil && port != "" {
						suffix = ":" + port
					}
					srv.applyELBindings(u.Addr, suffix)
					currentIP = u.Addr
				} else {
					srv.log.Debug("EL IP unchanged", "ip", u.Addr)
				}
			}
		}
	}
}
