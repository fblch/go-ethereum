package p2p

/*
#cgo linux CFLAGS:  -I${SRCDIR}/../../el-stack-rs/golang/el_stack
#cgo linux LDFLAGS: -L${SRCDIR}/../../el-stack-rs/target/release -lel_stack -Wl,-rpath,${SRCDIR}/../../el-stack-rs/target/release

#cgo darwin CFLAGS:  -I${SRCDIR}/../../el-stack-rs/golang/el_stack
#cgo darwin LDFLAGS: -L${SRCDIR}/../../el-stack-rs/target/release -lel_stack -Wl,-rpath,${SRCDIR}/../../el-stack-rs/target/release

#include "el_stack.h"
*/
import "C"

import (
	"context"
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
	"github.com/ethereum/go-ethereum/p2p/enode"
)

var elLog = log.Root().New("cmp", "p2p/el_stack")

// CheckEnvDefinition ensures all VPN related env vars exist so we know whether
// to fall back to the standard net stack or bootstrap el_stack.
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

type ElStackUdpConn struct {
	inner     *el_stack.ElStackUdpConn
	laddr     net.Addr
	closeOnce sync.Once
	closeErr  error
}

func ListenELUDP(network string, addr *net.UDPAddr) (discover.UDPConn, error) {
	c, err := el_stack.NewElStackUdpConn(network, addr)
	if err != nil {
		elLog.Error("UDP Bind FAILED", "err", err)
		return &ElStackUdpConn{}, err
	}
	localAddr := c.LocalAddr()
	return &ElStackUdpConn{inner: c, laddr: localAddr}, nil
}

func (c *ElStackUdpConn) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	// Set read deadline and ensure reset after read.
	for {
		_ = c.inner.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, udpAddr, uerr := c.inner.ReadFromUDP(b)
		_ = c.inner.SetReadDeadline(time.Time{})

		if uerr != nil {
			// el_stack signals a timeout via the string below; treat it as a retryable
			// condition instead of bubbling an opaque error up the stack.
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
	n, uerr := c.inner.WriteToUDP(b, net.UDPAddrFromAddrPort(addr))
	if uerr != nil {
		// Wrap the el_stack error so callers still observe the familiar net.Error
		// surface that the discovery stack already knows how to handle.
		return n, &net.OpError{Op: "write", Net: "udp", Source: c.laddr, Addr: net.UDPAddrFromAddrPort(addr), Err: uerr}
	}
	return n, nil
}

// discover.UDPConn の要件を満たすためのラッパーメソッド
func (c *ElStackUdpConn) Close() error {
	if c.inner != nil {
		c.closeOnce.Do(func() {
			// Make Close idempotent because geth can close the socket from multiple
			// goroutines during shutdown.
			c.closeErr = c.inner.Close()
		})
	}
	return c.closeErr
}

func (c *ElStackUdpConn) LocalAddr() net.Addr { return c.laddr }

type ElStackTcpListener struct {
	inner net.Listener
}

// el経由の処理を本ファイルにまとめるためのラッパ関数
func ListenELTCP(network, addr string) (net.Listener, error) {
	ln, err := el_stack.NewElStackTcpListener(network, addr)
	listener := &ElStackTcpListener{
		inner: ln,
	}
	return listener, err
}

// net.Listener interface 実装
// Accept proxies the el_stack listener while adding timing logs so we can
// diagnose stalls similar to the Go stdlib listener.
func (ln *ElStackTcpListener) Accept() (net.Conn, error) {
	start := time.Now()
	elLog.Trace("ElStackTcpListener waiting on Accept", "laddr", ln.Addr())
	c, err := ln.inner.Accept()
	if err != nil {
		elLog.Warn("ElStackTcpListener Accept failed", "err", err, "elapsed", time.Since(start))
		return nil, err
	}
	elLog.Trace("ElStackTcpListener Accept success", "raddr", c.RemoteAddr(), "elapsed", time.Since(start))
	conn := newElStackTcpConn(c)
	return conn, nil
}

func (ln *ElStackTcpListener) Close() error   { return ln.inner.Close() }
func (ln *ElStackTcpListener) Addr() net.Addr { return ln.inner.Addr() }

type ElStackTcpDialer struct{}

func ensureDialContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, nil
	}
	return context.WithTimeout(ctx, defaultDialTimeout)
}

func (*ElStackTcpDialer) Dial(ctx context.Context, dest *enode.Node) (net.Conn, error) {
	start := time.Now()
	elLog.Trace("ElStackTcpDialer Dial start", "node", dest.ID(), "addr", dest.IP())
	addr, _ := dest.TCPEndpoint()

	ctx, cancel := ensureDialContext(ctx)
	if cancel != nil {
		defer cancel()
	}

	type dialResult struct {
		conn net.Conn
		err  error
	}

	resCh := make(chan dialResult, 1)

	go func() {
		defer close(resCh)
		// Run the potentially long el_stack dial in its own goroutine so the
		// context timeout can cancel it without blocking the caller.
		c, err := el_stack.NewElStackTcpConn("tcp", addr.String())
		if err != nil {
			resCh <- dialResult{err: err}
			return
		}
		resCh <- dialResult{conn: c}
	}()

	select {
	case <-ctx.Done():
		go func() {
			if res, ok := <-resCh; ok && res.conn != nil {
				_ = res.conn.Close()
			}
		}()
		return nil, ctx.Err()
	case res := <-resCh:
		if res.err != nil {
			elLog.Warn("ElStackTcpDialer Dial failed", "node", dest.ID(), "err", res.err)
			return nil, res.err
		}
		elLog.Trace("ElStackTcpDialer Dial success", "node", dest.ID(), "elapsed", time.Since(start))
		return newElStackTcpConn(res.conn), nil
	}
}

type ElStackTcpConn struct {
	inner     net.Conn
	laddr     net.Addr
	raddr     net.Addr
	closeOnce sync.Once
	closeErr  error
}

func newElStackTcpConn(c net.Conn) *ElStackTcpConn {
	return &ElStackTcpConn{
		inner: c,
		raddr: c.RemoteAddr(),
		laddr: c.LocalAddr(),
	}
}

// net.Conn interface 実装
func (c *ElStackTcpConn) Read(b []byte) (n int, err error)  { return c.inner.Read(b) }
func (c *ElStackTcpConn) Write(b []byte) (n int, err error) { return c.inner.Write(b) }

func (c *ElStackTcpConn) Close() error {
	c.closeOnce.Do(func() {
		elLog.Trace("ElStackTcpConn Close", "peer", c.raddr)
		c.closeErr = c.inner.Close()
	})
	return c.closeErr
}

func (c *ElStackTcpConn) LocalAddr() net.Addr                { return c.laddr }
func (c *ElStackTcpConn) RemoteAddr() net.Addr               { return c.raddr }
func (c *ElStackTcpConn) SetDeadline(t time.Time) error      { return c.inner.SetDeadline(t) }
func (c *ElStackTcpConn) SetReadDeadline(t time.Time) error  { return c.inner.SetReadDeadline(t) }
func (c *ElStackTcpConn) SetWriteDeadline(t time.Time) error { return c.inner.SetWriteDeadline(t) }

// WisteriaVpnEventDelegate 実装
type vpnDelegate struct {
	ipAddr   string
	linkedCh chan struct{}
}

func (d *vpnDelegate) OnStatusChange(status el_stack.VpnStatus) {
	elLog.Debug("VPN Status", "status", status)
}

func (d *vpnDelegate) OnConnectionError(msg string) {
	elLog.Error("VPN Connection error", "msg", msg)
}

func (d *vpnDelegate) OnLinkedParams(ipAddrs, dnsAddrs, routes []string) {
	elLog.Info("LinkedParams", "IP", ipAddrs, "DNS", dnsAddrs, "ROUTES", routes)
	ipAddr := ipAddrs[0][:len(ipAddrs[0])-3] // trim subnet
	d.ipAddr = ipAddr
	d.linkedCh <- struct{}{}
}

func SetupELVpnDelegate() *vpnDelegate {
	// 環境変数から各種値を取得
	// We intentionally panic on missing required values earlier so failures are
	// loud during startup rather than surfacing deep in the networking stack.
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
