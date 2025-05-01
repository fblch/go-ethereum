package goupnp

import (
	"io"
	"net"

	"github.com/ethereum/go-ethereum/p2p/nat/goupnp/httpu"
)

// httpuClient creates a HTTPU client that multiplexes to all multicast-capable
// IPv4 addresses on the host. Returns a function to clean up once the client is
// no longer required.
// MODIFIED by Jakub Pajek (x/mobile: Calling net.Interfaces() fails on Android SDK 30+)
// func httpuClient() (httpu.ClientInterface, func(), error) {
func httpuClient(localIPv4MCastAddr net.IP) (httpu.ClientInterface, func(), error) {
	// MODIFIED by Jakub Pajek (x/mobile: Calling net.Interfaces() fails on Android SDK 30+)
	//addrs, err := localIPv4MCastAddrs()
	addrs, err := localIPv4MCastAddrs(localIPv4MCastAddr)
	if err != nil {
		return nil, nil, ctxError(err, "requesting host IPv4 addresses")
	}

	closers := make([]io.Closer, 0, len(addrs))
	delegates := make([]httpu.ClientInterface, 0, len(addrs))
	for _, addr := range addrs {
		c, err := httpu.NewHTTPUClientAddr(addr)
		if err != nil {
			return nil, nil, ctxErrorf(err,
				"creating HTTPU client for address %s", addr)
		}
		closers = append(closers, c)
		delegates = append(delegates, c)
	}

	closer := func() {
		for _, c := range closers {
			c.Close()
		}
	}

	return httpu.NewMultiClient(delegates), closer, nil
}

// localIPv2MCastAddrs returns the set of IPv4 addresses on multicast-able
// network interfaces.
// MODIFIED by Jakub Pajek (x/mobile: Calling net.Interfaces() fails on Android SDK 30+)
// func localIPv4MCastAddrs() ([]string, error) {
func localIPv4MCastAddrs(localIPv4MCastAddr net.IP) ([]string, error) {
	// ADDED by Jakub Pajek BEG (x/mobile: Calling net.Interfaces() fails on Android SDK 30+)
	if localIPv4MCastAddr != nil && localIPv4MCastAddr.To4() != nil {
		return []string{localIPv4MCastAddr.String()}, nil
	}
	// ADDED by Jakub Pajek END (x/mobile: Calling net.Interfaces() fails on Android SDK 30+)
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, ctxError(err, "requesting host interfaces")
	}

	// Find the set of addresses to listen on.
	var addrs []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagMulticast == 0 || iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			// Does not support multicast or is a loopback address.
			continue
		}
		ifaceAddrs, err := iface.Addrs()
		if err != nil {
			return nil, ctxErrorf(err,
				"finding addresses on interface %s", iface.Name)
		}
		for _, netAddr := range ifaceAddrs {
			addr, ok := netAddr.(*net.IPNet)
			if !ok {
				// Not an IPNet address.
				continue
			}
			if addr.IP.To4() == nil {
				// Not IPv4.
				continue
			}
			addrs = append(addrs, addr.IP.String())
		}
	}

	return addrs, nil
}
