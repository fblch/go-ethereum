package p2p

import (
	"errors"

	"github.com/ethereum/go-ethereum/p2p/elstack"
)

func (srv *Server) setupEL() {
	if err := elstack.ValidateELConfig(srv.EL); err != nil {
		if errors.Is(err, elstack.ErrELDisabled) || errors.Is(err, elstack.ErrELConfigNil) {
			return
		}
		srv.log.Error("EL config invalid", "err", err)
		return
	}

	updates := make(chan elstack.VpnDelegate, 1)
	baseListen := srv.ListenAddr
	go elstack.SetupEL(srv.EL, updates, srv.quit)

	go func() {
		for {
			select {
			case upd := <-updates:
				if upd.Err != nil {
					srv.log.Info("setupEL failed", "reason", upd.Err)
					continue
				}
				if upd.Addr == nil {
					srv.log.Info("setupEL missing IP")
					continue
				}
				srv.localnode.SetStaticIP(upd.Addr) // update staticIP to el_stack IPAddr
				srv.ListenAddr = upd.Addr.String() + baseListen
				srv.listenFunc = elstack.ListenELTCP
				srv.Dialer = elstack.NewElStackTcpDialer(defaultDialTimeout)
				srv.listenUDPFunc = elstack.ListenELUDP
			case <-srv.quit:
				return
			}
		}
	}()
}
