package main

// #cgo CFLAGS: -I../../el-stack-rs/golang/el_stack
// #cgo LDFLAGS: -L../../el-stack-rs/target/release -lel_stack
// #include <el_stack.h>

import (
    "fmt"
    "net"
    "net/netip"
    "os"
    "strconv"
    "sync"

	"el_stack"

	"github.com/ethereum/go-ethereum/log"
    "github.com/ethereum/go-ethereum/p2p/discover/v4wire"
)

var elLog = log.Root().New("cmp", "p2p/el_stack")

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

type ElStackUdpConn struct {
    *el_stack.ElStackUdpConn
    mu sync.Mutex
    rwOnce  sync.Once
    rdReqCh chan readReq
    wrReqCh chan writeReq
    quitCh  chan struct{}
}

type readReq struct {
    buf []byte
    ret chan readRes
}
type readRes struct {
    n   int
    addr *net.UDPAddr
    err error
}
type writeReq struct {
    b   []byte
    addr *net.UDPAddr
    ret chan writeRes
}
type writeRes struct {
    n   int
    err error
}

func wrap(raw *el_stack.ElStackUdpConn) *ElStackUdpConn {
    if raw == nil {
        return nil // ラッパーの「非存在」を素直に表現
    }
    c := &ElStackUdpConn{
        ElStackUdpConn: raw,
        rdReqCh:        make(chan readReq),
        wrReqCh:        make(chan writeReq),
        quitCh:         make(chan struct{}),
    }
    c.startIOLoop()
    return c
}

func (c *ElStackUdpConn) underlying() *el_stack.ElStackUdpConn {
	if c == nil { // ラッパー自体が nil のときに備える
		return nil
	}
	return c.ElStackUdpConn
}

func (c *ElStackUdpConn) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
    elLog.Debug("(*ElStackUdpConn).ReadFromUDPAddrPort() START")
    rr := readReq{buf: b, ret: make(chan readRes, 1)}
    select {
    case c.rdReqCh <- rr:
    case <-c.quitCh:
        return 0, netip.AddrPort{}, fmt.Errorf("conn closed")
    }
    res := <-rr.ret
    n, udpAddr, err := res.n, res.addr, res.err
    if err != nil {
        elLog.Debug("ElUDP ReadFromUDP error", "err", err)
    }
    // 返ってきたudpAddrがnilの場合、空のnetip.AddrPor{}を返す
    if udpAddr == nil {
	    elLog.Debug("(*ElStackUdpConn).ReadFromUDPAddrPort() 1")
        return n, netip.AddrPort{}, err
    }
    // 先頭のヘクスダンプと簡易デコード
    if n > 0 {
        preview := n
        if preview > 256 {
            preview = 256
        }
        if pkt, _, _, derr := v4wire.Decode(b[:n]); derr == nil && pkt != nil {
            elLog.Debug("ElUDP ReadFromUDP decoded", "kind", pkt.Name())
        }
    }
	elLog.Debug("(*ElStackUdpConn).ReadFromUDPAddrPort() 2")
	return n, udpAddr.AddrPort(), err
}

func (c *ElStackUdpConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (n int, err error) {
    elLog.Debug("(*ElStackUdpConn).WriteToUDPAddrPort() START")
    // netip.AddrPortをnet.UDPAddrに変換
    addr2 := net.UDPAddrFromAddrPort(addr)
    wr := writeReq{b: b, addr: addr2, ret: make(chan writeRes, 1)}
    select {
    case c.wrReqCh <- wr:
    case <-c.quitCh:
        return 0, fmt.Errorf("conn closed")
    }
    wres := <-wr.ret
    n, err = wres.n, wres.err
    if err != nil {
        elLog.Debug("ElUDP WriteToUDP error", "err", err, "to", addr.String(), "n", n)
    }
    elLog.Debug("(*ElStackUdpConn).WriteToUDPAddrPort() 1")
    return n, err
}

func (c *ElStackUdpConn) startIOLoop() {
    c.rwOnce.Do(func() {
        go func() {
            for {
                select {
                case rr := <-c.rdReqCh:
                    n, udpAddr, err := c.ReadFromUDP(rr.buf)
                    rr.ret <- readRes{n: n, addr: udpAddr, err: err}
                case wr := <-c.wrReqCh:
                    n, err := c.WriteToUDP(wr.b, wr.addr)
                    wr.ret <- writeRes{n: n, err: err}
                case <-c.quitCh:
                    return
                }
            }
        }()
    })
}

// discover.UDPConn の要件を満たすためのラッパーメソッド
func (c *ElStackUdpConn) Close() error {
    elLog.Debug("ElUDP Close called")
    u := c.underlying()
    if u == nil {
        return nil
    }
    close(c.quitCh)
    return u.Close()
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
	fmt.Println("IP:", ipAddrs)
	fmt.Println("DNS:", dnsAddrs)
	fmt.Println("Routes:", routes)
	elLog.Debug("VPN LinkedParams", "ips", ipAddrs, "dns", dnsAddrs, "routes", routes)

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
		elLog.Debug("ElUDP conn ready, signaling done")
		d.done <- struct{}{}
		// defer conn.Close()

		// for {
		// 	buf := make([]byte, 1500)
		// 	n, from, err := conn.ReadFromUDP(buf)
		// 	if err != nil {
		// 		fmt.Println("Udp RecvFrom failed:", err)
		// 		break
		// 	}
		// 	fmt.Println("recv from: ", from)
		// 	fmt.Println("recved: ", buf[:n])

		// 	_, err = conn.WriteToUDP(buf[:n], from)
		// 	if err != nil {
		// 		fmt.Println("Udp SendTo failed:", err)
		// 		break
		// 	}
		// 	fmt.Println("sent: ", n)
		// }
	}()
}

func ListenElUDP(conn chan *ElStackUdpConn, preferPort int) {
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
	prodCfg := el_stack.NewElStackProductConfig(productName, productVersion, productPlatform, caCert)

	core := el_stack.NewElStackCore(accountCfg, vpnCfg, prodCfg)
    delegate := &vpnDelegate{
        core:       core,
        done:       make(chan struct{}, 1),
        preferPort: preferPort,
    }
	err := core.Start(delegate)
	if err != nil {
		fmt.Println("start failed:", err)
		return
	}
	defer core.Stop()

	<-delegate.done
	conn <- delegate.conn

	select {}
}
