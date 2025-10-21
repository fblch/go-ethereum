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
	localAddr      net.Addr
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
	// conn := wrap(c)
	// return conn, nil
	return &ElStackUdpConn{ElStackUdpConn: c, localAddr: localAddr}, nil
}

func wrap(raw *el_stack.ElStackUdpConn) *ElStackUdpConn {
	if raw == nil {
		return nil // ラッパーの「非存在」を素直に表現
	}
	c := &ElStackUdpConn{
		ElStackUdpConn: raw,
	}
	return c
}

func (c *ElStackUdpConn) underlying() *el_stack.ElStackUdpConn {
	if c == nil { // ラッパー自体が nil のときに備える
		return nil
	}
	return c.ElStackUdpConn
}

func (c *ElStackUdpConn) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	elLog.Debug("ElUDP sync: read", "len", len(b))
	// Set read deadline and ensure reset after read.
	_ = c.ElStackUdpConn.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	n, udpAddr, uerr := c.ElStackUdpConn.ReadFromUDP(b)
	elLog.Debug("(ElStackUdpConn).ReadFromUDPAddrPort result", "n", n)
	elLog.Debug("(ElStackUdpConn).ReadFromUDPAddrPort result", "udpaddr", udpAddr)
	elLog.Debug("(ElStackUdpConn).ReadFromUDPAddrPort result", "uerr", uerr)
	_ = c.ElStackUdpConn.SetReadDeadline(time.Time{})
	if uerr != nil {
		elLog.Error("(*ElStackUdpConn).ReadFromUDPAddrPort ERROR", "err", uerr)
		if strings.Contains(uerr.Error(), "SocketError: UdpRecvTimeout") {
			return 0, netip.AddrPort{}, nil
		}
		return n, netip.AddrPort{}, &net.OpError{Op: "read", Net: "udp", Source: c.LocalAddr(), Addr: nil, Err: uerr}
	}
	if udpAddr == nil {
		return n, netip.AddrPort{}, nil
	}
	return n, udpAddr.AddrPort(), nil
}

func (c *ElStackUdpConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (n int, err error) {
	elLog.Debug("(*ElStackUdpConn).WriteToUDPAddrPort START")
	elLog.Debug("ElUDP sync: write", "len", len(b), "to", addr.String())
	n, uerr := c.ElStackUdpConn.WriteToUDP(b, net.UDPAddrFromAddrPort(addr))
	if uerr != nil {
		return n, &net.OpError{Op: "write", Net: "udp", Source: c.LocalAddr(), Addr: net.UDPAddrFromAddrPort(addr), Err: uerr}
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
	u := c.underlying()
	if u == nil {
		elLog.Debug("ElUDP LocalAddr", "addr", "<nil>")
		return nil
	}
	a := u.LocalAddr()
	elLog.Debug("ElUDP LocalAddr", "addr", func() string {
		if a != nil {
			return a.String()
		}
		return "<nil>"
	}())
	return a
}

type ElStackTcpListener struct {
	inner net.Listener
	// laddr net.Addr
}

// el経由の処理を本ファイルにまとめるためのラッパ関数
func ListenELTCP(network, addr string) (net.Listener, error) {
	// return el_stack.NewElStackTcpListener(network, addr)
	ln, err := el_stack.NewElStackTcpListener(network, addr)
	listener := &ElStackTcpListener{
		inner: ln,
		// laddr: ln.Addr(),
	}
	return listener, err
}

// net.Listener interface 実装
func (ln *ElStackTcpListener) Accept() (net.Conn, error) {
	elLog.Debug("(*ElStackTcpListener).Accept() START")
	c, err := ln.inner.Accept()
	if err != nil {
		elLog.Error("(*ElStackTcpListener).Accept ERROR", "err", err)
		return nil, err
	}
	conn := newElStackTcpConn(c)
	return conn, nil
}

func (ln *ElStackTcpListener) Close() error   { return ln.inner.Close() }
func (ln *ElStackTcpListener) Addr() net.Addr { return ln.inner.Addr() }

// func (ln *ElStackTcpListener) localAddr() net.Addr { return ln.laddr }

type ElStackTcpDialer struct{}

func ensureDialContext(ctx context.Context) (context.Context, context.CancelFunc) {
    if _, ok := ctx.Deadline(); ok {
        return ctx, nil
    }
    return context.WithTimeout(ctx, defaultDialTimeout)
}

func (*ElStackTcpDialer) Dial(ctx context.Context, dest *enode.Node) (net.Conn, error) {
	elLog.Debug("(*ElStackTcpDialer).Dial START")
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
            elLog.Error("(*ElStackTcpDialer).Dial ERROR", "err", res.err)
            return nil, res.err
        }
        return newElStackTcpConn(res.conn), nil
    }
}

type ElStackTcpConn struct {
	inner net.Conn
	laddr net.Addr
	raddr net.Addr
}

func newElStackTcpConn(c net.Conn) (*ElStackTcpConn) {
	return &ElStackTcpConn{
		inner: c,
		raddr: c.RemoteAddr(),
		laddr: c.LocalAddr(),
	}
}

// net.Conn interface 実装
func (c *ElStackTcpConn) Read(b []byte) (n int, err error)   { return c.inner.Read(b) }
func (c *ElStackTcpConn) Write(b []byte) (n int, err error)  { return c.inner.Write(b) }
func (c *ElStackTcpConn) Close() error                       { return c.inner.Close() }
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
	elLog.Debug("(*vpnDelegate).OnLinkedParams()", "ips", ipAddrs)
	elLog.Debug("(*vpnDelegate).OnLinkedParams()", "dns", dnsAddrs)
	elLog.Debug("(*vpnDelegate).OnLinkedParams()", "routes", routes)

	ipAddr := ipAddrs[0][:len(ipAddrs[0])-3] // trim subnet
	elLog.Debug("(*vpnDelegate).OnLinkedParams()", "ip", ipAddr)
	d.ipAddr = ipAddr
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
