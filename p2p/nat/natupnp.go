// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package nat

import (
	"errors"
	"fmt"
	"math"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/p2p/nat/goupnp"
	"github.com/ethereum/go-ethereum/p2p/nat/goupnp/dcps/internetgateway1"
	"github.com/ethereum/go-ethereum/p2p/nat/goupnp/dcps/internetgateway2"
)

const (
	soapRequestTimeout = 3 * time.Second
	rateLimit          = 200 * time.Millisecond
)

type upnp struct {
	// ADDED by Jakub Pajek (x/mobile: Calling net.Interfaces() fails on Android SDK 30+)
	local, gw   net.IP
	dev         *goupnp.RootDevice
	service     string
	client      upnpClient
	mu          sync.Mutex
	lastReqTime time.Time
	rand        *rand.Rand
}

type upnpClient interface {
	GetExternalIPAddress() (string, error)
	AddPortMapping(string, uint16, string, uint16, string, bool, string, uint32) error
	DeletePortMapping(string, uint16, string) error
	GetNATRSIPStatus() (sip bool, nat bool, err error)
}

func (n *upnp) natEnabled() bool {
	var ok bool
	var err error
	n.withRateLimit(func() error {
		_, ok, err = n.client.GetNATRSIPStatus()
		return err
	})
	return err == nil && ok
}

func (n *upnp) ExternalIP() (addr net.IP, err error) {
	var ipString string
	n.withRateLimit(func() error {
		ipString, err = n.client.GetExternalIPAddress()
		return err
	})

	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(ipString)
	if ip == nil {
		return nil, errors.New("bad IP in response")
	}
	return ip, nil
}

func (n *upnp) AddMapping(protocol string, extport, intport int, desc string, lifetime time.Duration) (uint16, error) {
	// MODIFIED by Jakub Pajek BEG (x/mobile: Calling net.Interfaces() fails on Android SDK 30+)
	/*
		ip, err := n.internalAddress()
		if err != nil {
			return 0, err
		}
	*/
	var ip net.IP
	var err error
	if n.local == nil {
		ip, err = n.internalAddress(false)
		if err != nil {
			return 0, err
		}
	} else {
		ip = n.local
	}
	// MODIFIED by Jakub Pajek END (x/mobile: Calling net.Interfaces() fails on Android SDK 30+)
	protocol = strings.ToUpper(protocol)
	lifetimeS := uint32(lifetime / time.Second)

	if extport == 0 {
		extport = intport
	} else {
		// Only delete port mapping if the external port was already used by geth.
		n.DeleteMapping(protocol, extport, intport)
	}

	// Try to add port mapping, preferring the specified external port.
	err = n.withRateLimit(func() error {
		p, err := n.addAnyPortMapping(protocol, extport, intport, ip, desc, lifetimeS)
		if err == nil {
			extport = int(p)
		}
		return err
	})
	return uint16(extport), err
}

// addAnyPortMapping tries to add a port mapping with the specified external port.
// If the external port is already in use, it will try to assign another port.
func (n *upnp) addAnyPortMapping(protocol string, extport, intport int, ip net.IP, desc string, lifetimeS uint32) (uint16, error) {
	if client, ok := n.client.(*internetgateway2.WANIPConnection2); ok {
		return client.AddAnyPortMapping("", uint16(extport), protocol, uint16(intport), ip.String(), true, desc, lifetimeS)
	}
	// For IGDv1 and v1 services we should first try to add with extport.
	err := n.client.AddPortMapping("", uint16(extport), protocol, uint16(intport), ip.String(), true, desc, lifetimeS)
	if err == nil {
		return uint16(extport), nil
	}

	// If above fails, we retry with a random port.
	// We retry several times because of possible port conflicts.
	for i := 0; i < 3; i++ {
		extport = n.randomPort()
		err := n.client.AddPortMapping("", uint16(extport), protocol, uint16(intport), ip.String(), true, desc, lifetimeS)
		if err == nil {
			return uint16(extport), nil
		}
	}
	return 0, err
}

func (n *upnp) randomPort() int {
	if n.rand == nil {
		n.rand = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	return n.rand.Intn(math.MaxUint16-10000) + 10000
}

// MODIFIED by Jakub Pajek (x/mobile: Calling net.Interfaces() fails on Android SDK 30+)
// func (n *upnp) internalAddress() (net.IP, error) {
func (n *upnp) internalAddress(dummy bool) (net.IP, error) {
	devaddr, err := net.ResolveUDPAddr("udp4", n.dev.URLBase.Host)
	if err != nil {
		return nil, err
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, addr := range addrs {
			if x, ok := addr.(*net.IPNet); ok && x.Contains(devaddr.IP) {
				return x.IP, nil
			}
		}
	}
	return nil, fmt.Errorf("could not find local address in same net as %v", devaddr)
}

func (n *upnp) DeleteMapping(protocol string, extport, intport int) error {
	return n.withRateLimit(func() error {
		return n.client.DeletePortMapping("", uint16(extport), strings.ToUpper(protocol))
	})
}

func (n *upnp) String() string {
	// MODIFIED by Jakub Pajek (x/mobile: Calling net.Interfaces() fails on Android SDK 30+)
	//return "UPNP " + n.service
	if n.gw != nil {
		return fmt.Sprintf("UPNP %s(%v,%v)", n.service, n.gw, n.local)
	} else {
		return "UPNP " + n.service
	}
}

// ADDED by Jakub Pajek (x/mobile: Calling net.Interfaces() fails on Android SDK 30+)
func (n *upnp) MarshalText() ([]byte, error) {
	if n.gw != nil {
		return fmt.Appendf(nil, "upnp:%v,%v", n.gw, n.local), nil
	} else {
		return []byte("upnp"), nil
	}
}

func (n *upnp) withRateLimit(fn func() error) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	lastreq := time.Since(n.lastReqTime)
	if lastreq < rateLimit {
		time.Sleep(rateLimit - lastreq)
	}
	err := fn()
	n.lastReqTime = time.Now()
	return err
}

// discoverUPnP searches for Internet Gateway Devices
// and returns the first one it can find on the local network.
// MODIFIED by Jakub Pajek (x/mobile: Calling net.Interfaces() fails on Android SDK 30+)
// func discoverUPnP() Interface {
func discoverUPnP(local net.IP, gateway net.IP) Interface {
	found := make(chan *upnp, 2)
	// IGDv1
	// MODIFIED by Jakub Pajek (x/mobile: Calling net.Interfaces() fails on Android SDK 30+)
	//go discover(found, internetgateway1.URN_WANConnectionDevice_1, func(sc goupnp.ServiceClient) *upnp {
	go discover(found, local, gateway, internetgateway1.URN_WANConnectionDevice_1, func(sc goupnp.ServiceClient) *upnp {
		switch sc.Service.ServiceType {
		case internetgateway1.URN_WANIPConnection_1:
			// MODIFIED by Jakub Pajek (x/mobile: Calling net.Interfaces() fails on Android SDK 30+)
			//return &upnp{service: "IGDv1-IP1", client: &internetgateway1.WANIPConnection1{ServiceClient: sc}}
			return &upnp{local: local, gw: gateway, service: "IGDv1-IP1", client: &internetgateway1.WANIPConnection1{ServiceClient: sc}}
		case internetgateway1.URN_WANPPPConnection_1:
			// MODIFIED by Jakub Pajek (x/mobile: Calling net.Interfaces() fails on Android SDK 30+)
			//return &upnp{service: "IGDv1-PPP1", client: &internetgateway1.WANPPPConnection1{ServiceClient: sc}}
			return &upnp{local: local, gw: gateway, service: "IGDv1-PPP1", client: &internetgateway1.WANPPPConnection1{ServiceClient: sc}}
		}
		return nil
	})
	// IGDv2
	// MODIFIED by Jakub Pajek (x/mobile: Calling net.Interfaces() fails on Android SDK 30+)
	//go discover(found, internetgateway2.URN_WANConnectionDevice_2, func(sc goupnp.ServiceClient) *upnp {
	go discover(found, local, gateway, internetgateway2.URN_WANConnectionDevice_2, func(sc goupnp.ServiceClient) *upnp {
		switch sc.Service.ServiceType {
		case internetgateway2.URN_WANIPConnection_1:
			// MODIFIED by Jakub Pajek (x/mobile: Calling net.Interfaces() fails on Android SDK 30+)
			//return &upnp{service: "IGDv2-IP1", client: &internetgateway2.WANIPConnection1{ServiceClient: sc}}
			return &upnp{local: local, gw: gateway, service: "IGDv2-IP1", client: &internetgateway2.WANIPConnection1{ServiceClient: sc}}
		case internetgateway2.URN_WANIPConnection_2:
			// MODIFIED by Jakub Pajek (x/mobile: Calling net.Interfaces() fails on Android SDK 30+)
			//return &upnp{service: "IGDv2-IP2", client: &internetgateway2.WANIPConnection2{ServiceClient: sc}}
			return &upnp{local: local, gw: gateway, service: "IGDv2-IP2", client: &internetgateway2.WANIPConnection2{ServiceClient: sc}}
		case internetgateway2.URN_WANPPPConnection_1:
			// MODIFIED by Jakub Pajek (x/mobile: Calling net.Interfaces() fails on Android SDK 30+)
			//return &upnp{service: "IGDv2-PPP1", client: &internetgateway2.WANPPPConnection1{ServiceClient: sc}}
			return &upnp{local: local, gw: gateway, service: "IGDv2-PPP1", client: &internetgateway2.WANPPPConnection1{ServiceClient: sc}}
		}
		return nil
	})
	for i := 0; i < cap(found); i++ {
		if c := <-found; c != nil {
			return c
		}
	}
	return nil
}

// discover finds devices matching the given target and calls matcher for
// all advertised services of each device. The first non-nil service found
// is sent into out. If no service matched, nil is sent.
// MODIFIED by Jakub Pajek (x/mobile: Calling net.Interfaces() fails on Android SDK 30+)
// func discover(out chan<- *upnp, target string, matcher func(goupnp.ServiceClient) *upnp) {
func discover(out chan<- *upnp, local, _ net.IP, target string, matcher func(goupnp.ServiceClient) *upnp) {
	// MODIFIED by Jakub Pajek (x/mobile: Calling net.Interfaces() fails on Android SDK 30+)
	// devs, err := goupnp.DiscoverDevices(target)
	devs, err := goupnp.DiscoverDevices(local, target)
	if err != nil {
		out <- nil
		return
	}
	found := false
	for i := 0; i < len(devs) && !found; i++ {
		if devs[i].Root == nil {
			continue
		}
		devs[i].Root.Device.VisitServices(func(service *goupnp.Service) {
			if found {
				return
			}
			// check for a matching IGD service
			sc := goupnp.ServiceClient{
				SOAPClient: service.NewSOAPClient(),
				RootDevice: devs[i].Root,
				Location:   devs[i].Location,
				Service:    service,
			}
			sc.SOAPClient.HTTPClient.Timeout = soapRequestTimeout
			upnp := matcher(sc)
			if upnp == nil {
				return
			}
			upnp.dev = devs[i].Root

			// check whether port mapping is enabled
			if upnp.natEnabled() {
				out <- upnp
				found = true
			}
		})
	}
	if !found {
		out <- nil
	}
}
