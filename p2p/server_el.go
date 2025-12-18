package p2p

import "github.com/ethereum/go-ethereum/p2p/elstack"

func (srv *Server) setupELVpnDelegate() {
	srv.log.Info("Server.setupVpnDelegate START")
	if srv.EL == nil {
		return
	}
	if !srv.EL.Use {
		return
	}
	if vpnDelegate := elstack.SetupELVpnDelegate(srv.EL); vpnDelegate != nil {
		srv.vpnDelegate = vpnDelegate
		srv.ListenAddr = srv.vpnDelegate.IPAddr() + srv.ListenAddr
		srv.listenFunc = elstack.ListenELTCP
		srv.Dialer = elstack.NewElStackTcpDialer(defaultDialTimeout)
		srv.listenUDPFunc = elstack.ListenELUDP
	}
}
