package p2p

// #cgo CFLAGS: -I../../el-stack-rs/golang/el_stack
// #cgo LDFLAGS: -L../../el-stack-rs/target/release -lel_stack
// #include <el_stack.h>

import (
    "fmt"
    "net"
    "net/netip"
    "os"
    "strconv"

    "el_stack"
)

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
}

func wrap(raw *el_stack.ElStackUdpConn) *ElStackUdpConn {
    if raw == nil {
        return nil // ラッパーの「非存在」を素直に表現
    }
    return &ElStackUdpConn{ElStackUdpConn: raw}
}

func (c *ElStackUdpConn) underlying() *el_stack.ElStackUdpConn {
    if c == nil { // ラッパー自体が nil のときに備える
        return nil
    }
    return c.ElStackUdpConn
}

func (c *ElStackUdpConn) ReadFromUDPAddrPort(b []byte) (n int, addr netip.AddrPort, err error) {
	n, udpAddr, err := c.ReadFromUDP(b)
	// 返ってきたudpAddrがnilの場合、空のnetip.AddrPor{}を返す
	if udpAddr == nil {
		return n, netip.AddrPort{}, err
	}
	return n, udpAddr.AddrPort(), err
}


func (c *ElStackUdpConn) WriteToUDPAddrPort(b []byte, addr netip.AddrPort) (n int, err error) {
    // netip.AddrPortをnet.UDPAddrに変換
    addr2 := net.UDPAddrFromAddrPort(addr)
    return c.WriteToUDP(b, addr2)
}

// discover.UDPConn の要件を満たすためのラッパーメソッド
func (c *ElStackUdpConn) Close() error {
    return c.underlying().Close()
}

func (c *ElStackUdpConn) LocalAddr() net.Addr {
    return c.underlying().LocalAddr()
}

// WisteriaVpnEventDelegate 実装
type vpnDelegate struct {
	core *el_stack.ElStackCore
	conn *ElStackUdpConn	// *el_stack.ElStackUdpConn wrapper
	done chan struct{}
}

func (d *vpnDelegate) OnStatusChange(status el_stack.VpnStatus) {
	fmt.Println("Status:", status)
}

func (d *vpnDelegate) OnConnectionError(msg string) {
	fmt.Println("Connection error:", msg)
}

func (d *vpnDelegate) OnLinkedParams(ipAddrs, dnsAddrs, routes []string) {
	fmt.Println("IP:", ipAddrs)
	fmt.Println("DNS:", dnsAddrs)
	fmt.Println("Routes:", routes)

	go func() {
		// UDPソケットを取得
		bindAddr := getEnvOrPanic("BIND_ADDR")
		socket, err2 := d.core.UdpBind(bindAddr)
		if err2 != nil {
			fmt.Println("Udp bind failed:", err2)
			return
		}

		conn := el_stack.NewElStackUdpConn(socket)
		// *el_stack.ElStackUdpConn型をラッパー用の型であるElStackUdpConnに変換
		wrappedConn := wrap(conn)
		d.conn = wrappedConn
		d.done <-struct{}{}
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

func ListenElUDP(srv *Server, conn chan *ElStackUdpConn) {
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
		vpnKeepAliveSec, vpnTimeoutSec,
		el_stack.ElStackVpnConnectionTypeTls,
	)

	productName := getEnvOrDefault("PRODUCT_NAME", "go-udp-server")
	productVersion := getEnvOrDefault("PRODUCT_VERSION", "0.1.0")
	productPlatform := getEnvOrDefault("OS", "Linux")
	prodCfg := el_stack.NewElStackProductConfig(productName, productVersion, productPlatform, caCert)

	core := el_stack.NewElStackCore(accountCfg, vpnCfg, prodCfg)
	delegate := &vpnDelegate{
		core: core,
		done: make(chan struct{}, 1),
	}
	err := core.Start(delegate)
	if err != nil {
		fmt.Println("start failed:", err)
		return
	}
	defer core.Stop()
	defer delegate.conn.Close()

	<-delegate.done
	conn <-delegate.conn

	// select {}
	<-srv.quit
}
