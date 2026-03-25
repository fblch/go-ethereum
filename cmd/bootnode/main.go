// Copyright 2015 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// bootnode runs a bootstrap node for the Ethereum Discovery Protocol.
package main

import (
	"crypto/ecdsa"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/p2p/elstack"
	"github.com/ethereum/go-ethereum/p2p/enode"
	"github.com/ethereum/go-ethereum/p2p/nat"
	"github.com/ethereum/go-ethereum/p2p/netutil"
)

const initialELResultsBufferSize = 8

func main() {
	var (
		listenAddr  = flag.String("addr", ":30301", "listen address")
		genKey      = flag.String("genkey", "", "generate a node key")
		writeAddr   = flag.Bool("writeaddress", false, "write out the node's public key and quit")
		nodeKeyFile = flag.String("nodekey", "", "private key filename")
		nodeKeyHex  = flag.String("nodekeyhex", "", "private key as hex (for testing)")
		// MODIFIED by Jakub Pajek BEG (x/mobile: Calling net.Interfaces() fails on Android SDK 30+)
		//natdesc     = flag.String("nat", "none", "port mapping mechanism (any|none|upnp|pmp|pmp:<IP>|extip:<IP>)")
		natdesc     = flag.String("nat", "none", "port mapping mechanism (any|any:<GW,LOCAL>|none|upnp|upnp:<GW,LOCAL>|pmp|pmp:<IP>|extip:<IP>|stun:<IP:PORT>)")
		netrestrict = flag.String("netrestrict", "", "restrict network communication to the given IP networks (CIDR masks)")
		runv5       = flag.Bool("v5", false, "run a v5 topic discovery bootnode")
		verbosity   = flag.Int("verbosity", int(log.LvlInfo), "log verbosity (0-5)")
		vmodule     = flag.String("vmodule", "", "log verbosity pattern")
		// ADDED by Hinata AWAIISHIMA (el settings)
		elUse          = flag.Bool("el.use", false, "enable emotion link support")
		elHolderVC     = flag.String("el.vc", "", "emotion link verifiable credential file path")
		elHolderPriv   = flag.String("el.vcprivkey", "", "emotion link VC holder private key file path")
		elAntiOverlap  = flag.String("el.antioverlap", "", "emotion link anti overlap token file path")
		elIssuerPub    = flag.String("el.issuerpubkey", "", "emotion link issuer public key file path")
		elServerAddr   = flag.String("el.host", "", "emotion link server host")
		elServerPort   = flag.Int("el.port", 0, "emotion link server service port")
		elServerCACert = flag.String("el.servercacert", "", "using server CA certificate")

		nodeKey *ecdsa.PrivateKey
		err     error
	)
	flag.Parse()

	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	glogger.Verbosity(log.Lvl(*verbosity))
	glogger.Vmodule(*vmodule)
	log.Root().SetHandler(glogger)

	natm, err := nat.Parse(*natdesc)
	if err != nil {
		utils.Fatalf("-nat: %v", err)
	}
	switch {
	case *genKey != "":
		nodeKey, err = crypto.GenerateKey()
		if err != nil {
			utils.Fatalf("could not generate key: %v", err)
		}
		if err = crypto.SaveECDSA(*genKey, nodeKey); err != nil {
			utils.Fatalf("%v", err)
		}
		if !*writeAddr {
			return
		}
	case *nodeKeyFile == "" && *nodeKeyHex == "":
		utils.Fatalf("Use -nodekey or -nodekeyhex to specify a private key")
	case *nodeKeyFile != "" && *nodeKeyHex != "":
		utils.Fatalf("Options -nodekey and -nodekeyhex are mutually exclusive")
	case *nodeKeyFile != "":
		if nodeKey, err = crypto.LoadECDSA(*nodeKeyFile); err != nil {
			utils.Fatalf("-nodekey: %v", err)
		}
	case *nodeKeyHex != "":
		if nodeKey, err = crypto.HexToECDSA(*nodeKeyHex); err != nil {
			utils.Fatalf("-nodekeyhex: %v", err)
		}
	}

	if *writeAddr {
		fmt.Printf("%x\n", crypto.FromECDSAPub(&nodeKey.PublicKey)[1:])
		os.Exit(0)
	}

	var restrictList *netutil.Netlist
	if *netrestrict != "" {
		restrictList, err = netutil.ParseNetlist(*netrestrict)
		if err != nil {
			utils.Fatalf("-netrestrict: %v", err)
		}
	}

	// ADDED by Hinata AWAIISHIMA BEG
	listenUDPFunc := net.ListenUDP
	if *elUse {
		cert, err := elstack.ReadCertFile(*elServerCACert)
		if err != nil {
			log.Warn("boot without a specified cert file", "reason", err)
			cert = ""
		}
		vc, err := elstack.ReadSecretFile(*elHolderVC)
		if err != nil {
			utils.Fatalf("EL vc: %v", err)
		}
		vcPriv, err := elstack.ReadSecretFile(*elHolderPriv)
		if err != nil {
			utils.Fatalf("EL vcprivkey: %v", err)
		}
		issuerPub, err := elstack.ReadSecretFile(*elIssuerPub)
		if err != nil {
			utils.Fatalf("EL issuerpubkey: %v", err)
		}
		antiOverlap, err := elstack.ReadOrCreateAntiOverlap(*elAntiOverlap)
		if err != nil {
			utils.Fatalf("EL antiOverlap: %v", err)
		}
		elCfg := &elstack.ELConfig{
			Use:           true,
			HolderVC:      vc,
			HolderPrivKey: vcPriv,
			AntiOverlap:   antiOverlap,
			IssuerPubKey:  issuerPub,
			ServerAddr:    *elServerAddr,
			ServerPort:    *elServerPort,
			ServerCACert:  cert,
		}
		results := make(chan elstack.LinkedResult, initialELResultsBufferSize)
		go elstack.SetupEL(elCfg, results, nil)
		addr, err := elstack.WaitInitialEL(results)
		if err != nil {
			utils.Fatalf("EL setup failed: %v", err)
		}
		baseListen := *listenAddr
		if baseListen == "" {
			utils.Fatalf("EL enabled requires non-empty -addr")
		}
		_, port, err := net.SplitHostPort(baseListen)
		if err != nil {
			utils.Fatalf("invalid -addr %q: %v", baseListen, err)
		}
		*listenAddr = net.JoinHostPort(addr.String(), port)
		go monitorEL(results)
		listenUDPFunc = elstack.ListenELUDP
	}
	// ADDED by Hinata AWAIISHIMA END

	addr, err := net.ResolveUDPAddr("udp", *listenAddr)
	if err != nil {
		utils.Fatalf("-ResolveUDPAddr: %v", err)
	}
	conn, err := listenUDPFunc("udp", addr)
	if err != nil {
		utils.Fatalf("-ListenUDP: %v", err)
	}
	defer conn.Close()

	db, _ := enode.OpenDB("")
	ln := enode.NewLocalNode(db, nodeKey)

	listenerAddr := conn.LocalAddr().(*net.UDPAddr)
	if natm != nil && !listenerAddr.IP.IsLoopback() {
		natAddr := doPortMapping(natm, ln, listenerAddr)
		if natAddr != nil {
			listenerAddr = natAddr
		}
	}

	printNotice(&nodeKey.PublicKey, *listenerAddr)
	cfg := discover.Config{
		PrivateKey:  nodeKey,
		NetRestrict: restrictList,
	}
	if *runv5 {
		if _, err := discover.ListenV5(conn, ln, cfg); err != nil {
			utils.Fatalf("%v", err)
		}
	} else {
		if _, err := discover.ListenUDP(conn, ln, cfg); err != nil {
			utils.Fatalf("%v", err)
		}
	}

	select {}
}

func printNotice(nodeKey *ecdsa.PublicKey, addr net.UDPAddr) {
	if addr.IP.IsUnspecified() {
		addr.IP = net.IP{127, 0, 0, 1}
	}
	n := enode.NewV4(nodeKey, addr.IP, 0, addr.Port)
	fmt.Println(n.URLv4())
	fmt.Println("Note: you're using cmd/bootnode, a developer tool.")
	fmt.Println("We recommend using a regular node as bootstrap node for production deployments.")
}

func monitorEL(results <-chan elstack.LinkedResult) {
	for result := range results {
		if result.Err != nil {
			log.Error("EL link disconnected", "reason", result.Err)
		}
	}
	log.Error("LinkedResult channel is disabled")
}

func doPortMapping(natm nat.Interface, ln *enode.LocalNode, addr *net.UDPAddr) *net.UDPAddr {
	const (
		protocol = "udp"
		name     = "ethereum discovery"
	)
	newLogger := func(external int, internal int) log.Logger {
		return log.New("proto", protocol, "extport", external, "intport", internal, "interface", natm)
	}

	var (
		intport    = addr.Port
		extaddr    = &net.UDPAddr{IP: addr.IP, Port: addr.Port}
		mapTimeout = nat.DefaultMapTimeout
		log        = newLogger(addr.Port, intport)
	)
	addMapping := func() {
		// Get the external address.
		var err error
		extaddr.IP, err = natm.ExternalIP()
		if err != nil {
			log.Debug("Couldn't get external IP", "err", err)
			return
		}
		// Create the mapping.
		p, err := natm.AddMapping(protocol, extaddr.Port, intport, name, mapTimeout)
		if err != nil {
			log.Debug("Couldn't add port mapping", "err", err)
			return
		}
		if p != uint16(extaddr.Port) {
			extaddr.Port = int(p)
			log = newLogger(extaddr.Port, intport)
			log.Info("NAT mapped alternative port")
		} else {
			log.Info("NAT mapped port")
		}
		// Update IP/port information of the local node.
		ln.SetStaticIP(extaddr.IP)
		ln.SetFallbackUDP(extaddr.Port)
	}

	// Perform mapping once, synchronously.
	log.Info("Attempting port mapping")
	addMapping()

	// Refresh the mapping periodically.
	go func() {
		refresh := time.NewTimer(mapTimeout)
		defer refresh.Stop()
		for range refresh.C {
			addMapping()
			refresh.Reset(mapTimeout)
		}
	}()

	return extaddr
}
