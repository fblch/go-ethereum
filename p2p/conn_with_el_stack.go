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
)

var elLog = log.Root().New("cmp", "p2p/el_stack")

type temporarySocketTimeoutError struct {
	error
}

func (temporarySocketTimeoutError) Temporary() bool { return true }

func (temporarySocketTimeoutError) Timeout() bool { return true }

func CheckEnvDefinition(keys []string) bool {
	allPresent := true
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
	*el_stack.ElStackUdpConn
	mu   sync.Mutex
	once sync.Once
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
		elLog.Debug("(*ElStackUdpConn).ReadFromUDPAddrPort ERROR", "err", uerr)
		if strings.Contains(uerr.Error(), "SocketError: UdpRecvTimeout") {
			elLog.Debug("(*ElStackUdpConn).ReadFromUDPAddrPort uerr exchange to Temporary Error")
			uerr = temporarySocketTimeoutError{error: uerr}
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

// WisteriaVpnEventDelegate 実装
type vpnDelegate struct {
	core *el_stack.ElStackCore
	conn *ElStackUdpConn // *el_stack.ElStackUdpConn wrapper
	done chan struct{}
	// preferred UDP bind port provided by server (0 means auto)
	preferPort int
	// server context for accessing keys and local node
	srv *Server
}

func (d *vpnDelegate) OnStatusChange(status el_stack.VpnStatus) {
	fmt.Println("Status:", status)
	elLog.Debug("VPN Status", "status", status)
}

func (d *vpnDelegate) OnConnectionError(msg string) {
	fmt.Println("Connection error:", msg)
	elLog.Debug("VPN Connection error", "msg", msg)
}

func (d *vpnDelegate) OnLinkedParams(ipAddrs, dnsAddrs, routes []string) {
	// fmt.Println("IP:", ipAddrs)
	// fmt.Println("DNS:", dnsAddrs)
	// fmt.Println("Routes:", routes)
	elLog.Debug("(*vpnDelegate).OnLinkedParams()", "ips", ipAddrs)
	elLog.Debug("(*vpnDelegate).OnLinkedParams()", "dns", dnsAddrs)
	elLog.Debug("(*vpnDelegate).OnLinkedParams()", "routes", routes)

	go func() {
		// UDPソケットを取得
		// BIND_ADDRが"auto"または未設定なら、付与されたIPv4の最初のアドレスに:0でバインド
		bindCfg := getEnvOrDefault("BIND_ADDR", "auto")
		bindAddr := bindCfg
		if bindCfg == "auto" {
			// ipAddrsの中からIPv4を優先して選ぶ
			chosen := ""
			for _, ip := range ipAddrs {
				if parsed := net.ParseIP(ip); parsed != nil && parsed.To4() != nil {
					chosen = ip
					break
				}
			}
			if chosen == "" && len(ipAddrs) > 0 {
				chosen = ipAddrs[0] // IPv4が無ければ最初のもの
			}
			if chosen == "" {
				fmt.Println("No IP assigned by VPN; cannot bind UDP")
				elLog.Debug("No VPN IP available for UDP bind")
				return
			}
			port := 0
			if d.preferPort > 0 {
				port = d.preferPort
			}
			bindAddr = fmt.Sprintf("%s:%d", chosen, port)
		}
		fmt.Println("Binding UDP via el_stack to:", bindAddr)
		elLog.Debug("ElUDP Binding", "bind", bindAddr)
		socket, err2 := d.core.UdpBind(bindAddr)
		if err2 != nil {
			fmt.Println("Udp bind failed:", err2)
			elLog.Debug("ElUDP Bind failed", "err", err2)
			return
		}

		conn := el_stack.NewElStackUdpConn(socket)
		// *el_stack.ElStackUdpConn型をラッパー用の型であるElStackUdpConnに変換
		d.conn = wrap(conn)

		// 即時送信テスト: discoveryのPingと同形式のパケットを 10.0.12.10:30310 へ送信
		// エラーは致命ではないため、ログ出力のみに留める
		// func() {
		// 	defer func() { recover() }()
		// 	if d.srv == nil || d.srv.PrivateKey == nil {
		// 		elLog.Debug("Immediate Ping skipped: no server/private key")
		// 		return
		// 	}
		// 	laddr, _ := d.conn.LocalAddr().(*net.UDPAddr)
		// 	if laddr == nil || laddr.IP == nil {
		// 		elLog.Debug("Immediate Ping skipped: no local UDP addr")
		// 		return
		// 	}
		// 	toIP := "10.0.12.10"
		// 	toPort := uint16(30310)
		// 	ip, errParse := netip.ParseAddr(toIP)
		// 	if errParse != nil {
		// 		elLog.Debug("Immediate Ping skipped: bad dest IP", "ip", toIP, "err", errParse)
		// 		return
		// 	}
		// 	toAddr := netip.AddrPortFrom(ip, toPort)
		// 	// 推定TCPポート（存在しない場合は0）
		// 	var tcpPort uint16
		// 	if d.srv.ListenAddr != "" {
		// 		if _, pstr, err := net.SplitHostPort(d.srv.ListenAddr); err == nil {
		// 			if p, e := strconv.Atoi(pstr); e == nil && p >= 0 && p <= 65535 {
		// 				tcpPort = uint16(p)
		// 			}
		// 		}
		// 	}
		// 	fromEP := v4wire.NewEndpoint(netip.AddrPortFrom(netutil.IPToAddr(laddr.IP), uint16(laddr.Port)), tcpPort)
		// 	req := &v4wire.Ping{
		// 		Version:    4,
		// 		From:       fromEP,
		// 		To:         v4wire.NewEndpoint(toAddr, 0),
		// 		Expiration: uint64(time.Now().Add(20 * time.Second).Unix()),
		// 		ENRSeq:     d.srv.localnode.Node().Seq(),
		// 	}
		// 	elLog.Debug("Ping packet of immediatelly test", "packet", req)
		// 	packet, _, encErr := v4wire.Encode(d.srv.PrivateKey, req)
		// 	if encErr != nil {
		// 		elLog.Debug("Immediate Ping encode failed", "err", encErr)
		// 		return
		// 	}
		// 	if _, werr := d.conn.WriteToUDPAddrPort(packet, toAddr); werr != nil {
		// 		elLog.Debug("Immediate Ping send failed", "err", werr, "to", toAddr)
		// 	} else {
		// 		elLog.Debug("Immediate Ping sent", "to", toAddr, "bytes", len(packet))
		// 	}
		// }()

		elLog.Debug("ElUDP conn ready, signaling done")
		d.done <- struct{}{}
		// defer conn.Close()

		// for {
		// buf := make([]byte, 1500)
		// n, from, err := conn.ReadFromUDP(buf)
		// if err != nil {
		// 	fmt.Println("Udp RecvFrom failed:", err)
		// 	// break
		// }
		// fmt.Println("recv from: ", from)
		// fmt.Println("recved: ", buf[:n])

		// buf = append(buf, byte)

		// _, err = conn.WriteToUDP(buf[:n], from)
		// if err != nil {
		// 	fmt.Println("Udp SendTo failed:", err)
		// 	// break
		// }
		// fmt.Println("sent: ", n)
		// }
	}()
}

func ListenElUDP(srv *Server, conn chan *ElStackUdpConn, preferPort int) {
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
	prodCfg := el_stack.NewElStackProductConfig(productName, productVersion, productPlatform, caCert, 1400)

	core := el_stack.NewElStackCore(prodCfg)
	delegate := &vpnDelegate{
		core:       core,
		done:       make(chan struct{}, 1),
		preferPort: preferPort,
		srv:        srv,
	}
	err := core.Start(delegate, vpnCfg, accountCfg)
	if err != nil {
		fmt.Println("start failed:", err)
		return
	}
	defer core.Stop()
	defer delegate.conn.Close()

	<-delegate.done
	conn <- delegate.conn

	// select {}
	<-srv.quit
}
