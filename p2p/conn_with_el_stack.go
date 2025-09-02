package p2p

// #cgo CFLAGS: -I../../el-stack-rs/golang/el_stack
// #cgo LDFLAGS: -L../../el-stack-rs/target/release -lel_stack
// #include <el_stack.h>

import (
	"fmt"
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

// WisteriaVpnEventDelegate 実装
type vpnDelegate struct {
	core *el_stack.ElStackCore
	conn *el_stack.ElStackUdpConn
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
		d.conn = conn
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

func ListenElUDP(conn chan *el_stack.ElStackUdpConn) {
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

	<-delegate.done
	conn <-delegate.conn

	select {}
}
