package elstack

import (
	"el_stack"
	"fmt"
	"os"
	"strconv"
)

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

// WisteriaVpnEventDelegate 実装
type VpnDelegate struct {
	ipAddr   string
	linkedCh chan struct{}
}

func (d *VpnDelegate) IPAddr() string { return d.ipAddr }

func (d *VpnDelegate) OnStatusChange(status el_stack.VpnStatus) {
	elLog.Debug("VPN Status", "status", status)
}

func (d *VpnDelegate) OnConnectionError(msg string) {
	elLog.Error("VPN Connection error", "msg", msg)
}

func (d *VpnDelegate) OnLinkedParams(ipAddrs, dnsAddrs, routes []string) {
	elLog.Info("LinkedParams", "IP", ipAddrs, "DNS", dnsAddrs, "ROUTES", routes)
	ipAddr := ipAddrs[0][:len(ipAddrs[0])-3] // trim subnet
	d.ipAddr = ipAddr
	d.linkedCh <- struct{}{}
}

func SetupELVpnDelegate() *VpnDelegate {
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
	delegate := &VpnDelegate{
		linkedCh: make(chan struct{}, 1),
	}
	err := el_stack.Start(delegate, vpnCfg, accountCfg)
	if err != nil {
		elLog.Error("SetupELVpnDelegate ERROR", "err", err)
		return &VpnDelegate{}
	}
	<-delegate.linkedCh
	return delegate
}
