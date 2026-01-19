package elstack

import (
	// "el_stack"

	"fmt"
	"os"
	"strconv"

	"github.com/ethereum/go-ethereum/p2p/elstack/el_stack" // if you copied el_stack directory directly below elstack directory, use it.
)

// // 環境変数から値取得
// func getEnvOrPanic(key string) string {
// 	val, err := getEnv(key)
// 	if err != nil {
// 		panic(err)
// 	}
// 	return val
// }

func getEnv(key string) (string, error) {
	val, ok := os.LookupEnv(key)
	if !ok {
		return "", fmt.Errorf("environment variable %s is required", key)
	}
	return val, nil
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
// func getEnvUint64OrDefault(key string, def uint64) uint64 {
func getEnvUint64OrDefault(key string, def uint64) (uint64, error) {
	valStr, ok := os.LookupEnv(key)
	if !ok {
		return def, nil
	}
	val, err := strconv.ParseUint(valStr, 10, 64)
	if err != nil {
		// panic(fmt.Sprintf("Environment variable %s must be an unsigned integer: %v", key, err))
		return 0, fmt.Errorf("environment variable %s must be an unsigned integer: %v", key, err)
	}
	return val, nil
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
	ipAddr string
	linked chan bool
}

func (d *VpnDelegate) IPAddr() string { return d.ipAddr }

func (d *VpnDelegate) OnStatusChange(status el_stack.VpnStatus) {
	elLog.Debug("VPN Status", "status", status)
}

func (d *VpnDelegate) OnConnectionError(msg string) {
	elLog.Error("VPN Connection error", "msg", msg)
	d.linked <- false
}

func (d *VpnDelegate) OnLinkedParams(ipAddrs, dnsAddrs, routes []string) {
	elLog.Info("LinkedParams", "IP", ipAddrs, "DNS", dnsAddrs, "ROUTES", routes)
	ipAddr := ipAddrs[0][:len(ipAddrs[0])-3] // trim subnet
	d.ipAddr = ipAddr
	d.linked <- true
}

func SetupEL(cfg *ELConfig) (string, error) {
	// We intentionally panic on missing required values earlier so failures are
	// loud during startup rather than surfacing deep in the networking stack.
	elLog.Info("SetupEL arg", "cfg.Account", cfg.Account)
	elLog.Info("SetupEL arg", "cfg.Password", cfg.Password)
	elLog.Info("SetupEL arg", "cfg.Host", cfg.Host)
	elLog.Info("SetupEL arg", "cfg.Port", cfg.Port)

	certPath := cfg.CertPath
	if certPath == "" {
		certPath = "/etc/ssl/certs/ca-certificates.crt"
	}
	caCert := readFileOrEmpty(certPath)

	if cfg.Account == "" {
		return "", fmt.Errorf("EL Account is not set")
	}

	if cfg.Password == "" {
		return "", fmt.Errorf("EL Password is not set")
	}

	vpnHost := cfg.Host
	if vpnHost == "" {
		vpnHost = "ec2-57-181-8-159.ap-northeast-1.compute.amazonaws.com"
	}

	vpnPort := cfg.Port
	if vpnPort == "" {
		vpnPort = "443"
	}

	antiOverlap := cfg.AntiOverlap
	if antiOverlap == "" {
		antiOverlap = "12345678901234567890123456789012"
	}

	vpnKeepAliveSec := uint64(60)
	vpnTimeoutSec := uint64(180)

	accountCfg := el_stack.NewElStackAccountConfig(cfg.Account, cfg.Password)

	vpnCfg := el_stack.NewElStackVpnConfig(
		vpnHost, vpnPort, antiOverlap,
		vpnTimeoutSec, vpnKeepAliveSec,
		el_stack.ElStackVpnConnectionTypeTls,
	)

	productName := "go-ethereum-el"
	productVersion := "0.1.0"
	productPlatform := "Linux"

	prodCfg := el_stack.NewElStackProductConfig(productName, productVersion, productPlatform, caCert, 1280)

	el_stack.Initialize(prodCfg)
	delegate := &VpnDelegate{
		linked: make(chan bool, 1),
	}

	if err := el_stack.Start(delegate, vpnCfg, accountCfg); err != nil {
		el_stack.Stop()
		elLog.Error("SetupEL ERROR", "err", err)
		return "", err
	}

	stats := <-delegate.linked
	if !stats {
		elLog.Error("el_stack.Stop() called")
		el_stack.Stop()
		return "", fmt.Errorf("failed to connect to EL server")
	}
	if delegate.ipAddr == "" {
		err := fmt.Errorf("set no ipAddr to vpnDelegate")
		elLog.Error("SetupEL", "err", err)
		el_stack.Stop()
		return "", err
	}

	return delegate.ipAddr, nil
}

func StopElStack() {
	elLog.Trace("StopElStack START")
	el_stack.Stop()
	elLog.Trace("StopElStack DONE")
}
