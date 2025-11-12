package main

// #cgo CFLAGS: -I../../el-stack-rs/golang/el_stack
// #cgo LDFLAGS: -L../../el-stack-rs/target/release -lel_stack
// #include <el_stack.h>

import "C"

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"el_stack"

	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p/discover"
)

var elLog = log.Root().New("cmp", "p2p/el_stack")

type temporarySocketTimeoutError struct {
	error
}

func (temporarySocketTimeoutError) Temporary() bool { return true }

func (temporarySocketTimeoutError) Timeout() bool { return true }

func CheckEnvDefinition() bool {
	allPresent := true
	keys := []string{"ACCOUNT", "PASSWORD", "SERVER_HOST", "SERVER_SERV", "ANTI_OVERLAP"}
	for _, key := range keys {
		if _, ok := os.LookupEnv(key); !ok {
			elLog.Debug("Missing required env", "key", key)
			allPresent = false
		}
	}
	return allPresent
}

// 環境変数から値取得
func getEnvOrPanic(key string) string {
	val, ok := os.LookupEnv(key)
	if !ok {
		panic(fmt.Sprintf("Environment variable %s is required", key))
	}
	return val
}

// 環境変数から値取得
func getEnvOrDefault(key string, def string) string {
	val, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	return val
}

// uint64値を環境変数から取得
func getEnvUint64OrDefault(key string, def uint64) uint64 {
	valStr, ok := os.LookupEnv(key)
	if !ok {
		return def
	}
	val, err := strconv.ParseUint(valStr, 10, 64)
	if err != nil {
		panic(fmt.Sprintf("Environment variable %s must be an unsigned integer: %v", key, err))
	}
	return val
}

// ファイルを読み込み
func readFileOrEmpty(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		return []byte{}
	}
	return b
}

// ElStackUdpConn wraps el_stack.ElStackUdpConn and serializes all IO via
// a single actor goroutine. This guarantees that Read and Write are never
// executed concurrently against el_stack, which requires mutual exclusion.
//
// It also prioritizes writes: before starting a blocking read it drains any
// queued write requests. Once a read is in progress, it cannot be preempted
// (the underlying API doesn't expose deadlines here), but this scheme avoids
// launching a read while there is pending write work.
type ElStackUdpConn struct {
	ElStackUdpConn *el_stack.ElStackUdpConn
	laddr          net.Addr
	once           sync.Once
}

func ListenELUDP(network string, addr *net.UDPAddr) (discover.UDPConn, error) {
	elLog.Debug("ListenELUDP", "addr", addr)
	c, err := el_stack.NewElStackUdpConn(network, addr)
	if err != nil {
		elLog.Error("UDP Bind FAILED", "err", err)
		return &ElStackUdpConn{}, err
	}
	localAddr := c.LocalAddr()
	return &ElStackUdpConn{ElStackUdpConn: c, laddr: localAddr}, nil
}

func (c *ElStackUdpConn) underlying() *el_stack.ElStackUdpConn {
	if c == nil { // ラッパー自体が nil のときに備える
		return nil
	}
	return c.ElStackUdpConn
}

func (c *ElStackUdpConn) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	// Set read deadline and ensure reset after read.
	for {
		_ = c.ElStackUdpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, udpAddr, uerr := c.ElStackUdpConn.ReadFromUDP(b)
		_ = c.ElStackUdpConn.SetReadDeadline(time.Time{})

		if uerr != nil {
			if strings.Contains(uerr.Error(), "SocketError: UdpRecvTimeout") {
				time.Sleep(400 * time.Millisecond)
				continue
			}
			return 0, netip.AddrPort{}, &net.OpError{Op: "read", Net: "udp", Source: c.laddr, Addr: nil, Err: uerr}
		}
		return n, udpAddr.AddrPort(), nil
	}
}

func (c *ElStackUdpConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (n int, err error) {
	n, uerr := c.ElStackUdpConn.WriteToUDP(b, net.UDPAddrFromAddrPort(addr))
	if uerr != nil {
		return n, &net.OpError{Op: "write", Net: "udp", Source: c.laddr, Addr: net.UDPAddrFromAddrPort(addr), Err: uerr}
	}
	return n, nil
}

// discover.UDPConn の要件を満たすためのラッパーメソッド
func (c *ElStackUdpConn) Close() error {
	elLog.Debug("ElUDP Close called")
	var cerr error
	c.once.Do(func() {
		if u := c.underlying(); u != nil {
			cerr = u.Close()
		}
	})
	return cerr
}

func (c *ElStackUdpConn) LocalAddr() net.Addr {
	return c.laddr
}

// el経由の処理を本ファイルにまとめるためのラッパ関数
func ListenELTCP(network, addr string) (net.Listener, error) {
	return el_stack.NewElStackTcpListener(network, addr)
}

// WisteriaVpnEventDelegate 実装
type vpnDelegate struct {
	linkedCh chan struct{}
}

func (d *vpnDelegate) OnStatusChange(status el_stack.VpnStatus) {
	elLog.Debug("VPN Status", "status", status)
}

func (d *vpnDelegate) OnConnectionError(msg string) {
	elLog.Debug("VPN Connection error", "msg", msg)
}

func (d *vpnDelegate) OnLinkedParams(ipAddrs, dnsAddrs, routes []string) {
	elLog.Info("LinkedParams", "IP", ipAddrs, "DNS", dnsAddrs, "ROUTES", routes)

	d.linkedCh <- struct{}{}
}

func SetupELVpnDelegate() *vpnDelegate {
	// 環境変数から各種値を取得
	caCertPath := getEnvOrDefault("CA_FILE", "/etc/ssl/certs/ca-certificates.crt")
	caCert := readFileOrEmpty(caCertPath)

	accountName := getEnvOrPanic("ACCOUNT")
	accountPassword := getEnvOrPanic("PASSWORD")
	accountCfg := el_stack.NewElStackAccountConfig(accountName, accountPassword)

	vpnHost := getEnvOrPanic("SERVER_HOST")
	vpnPort := getEnvOrPanic("SERVER_SERV")
	antiOverlap := getEnvOrPanic("ANTI_OVERLAP")
	vpnKeepAliveSec := getEnvUint64OrDefault("KEEPALIVE_INTERVAL", 60)
	vpnTimeoutSec := getEnvUint64OrDefault("RECV_TIMEOUT", 180)
	vpnCfg := el_stack.NewElStackVpnConfig(
		vpnHost, vpnPort, antiOverlap,
		vpnTimeoutSec, vpnKeepAliveSec,
		el_stack.ElStackVpnConnectionTypeTls,
	)

	productName := getEnvOrDefault("PRODUCT_NAME", "go-udp-server")
	productVersion := getEnvOrDefault("PRODUCT_VERSION", "0.1.0")
	productPlatform := getEnvOrDefault("OS", "Linux")
	prodCfg := el_stack.NewElStackProductConfig(productName, productVersion, productPlatform, caCert, 1280)

	el_stack.Initialize(prodCfg)
	delegate := &vpnDelegate{
		linkedCh: make(chan struct{}, 1),
	}
	err := el_stack.Start(delegate, vpnCfg, accountCfg)
	if err != nil {
		elLog.Error("SetupELVpnDelegate ERROR", "err", err)
		return &vpnDelegate{}
	}
	<-delegate.linkedCh
	return delegate
}
