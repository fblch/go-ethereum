package p2p

import (
	"net"

	"github.com/ethereum/go-ethereum/p2p/elstack"
)

func (srv *Server) setupEL() {
	if srv.EL == nil {
		return
	}
	if !srv.EL.Use {
		return
	}
	if ipAddr, err := elstack.SetupEL(srv.EL); err == nil {
		if ipAddr != "" {
			ip := net.ParseIP(ipAddr)
			if ip == nil {
				srv.log.Error("invalid IP", "str", ipAddr)
				return
			}
			srv.localnode.SetStaticIP(ip) // update staticIP to el_stack IPAddr
			srv.ListenAddr = ipAddr + srv.ListenAddr
			srv.listenFunc = elstack.ListenELTCP
			srv.Dialer = elstack.NewElStackTcpDialer(defaultDialTimeout)
			srv.listenUDPFunc = elstack.ListenELUDP
		}
	}
}
