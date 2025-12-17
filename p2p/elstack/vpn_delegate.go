package elstack

import (
	"el_stack"
	"fmt"
	"os"
	"strconv"
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

func SetupELVpnDelegate(path, account, password, host, port, antioverlap string) (*VpnDelegate, error) {
	elLog.Info("SetupVpnDelegate START")
	// 環境変数から各種値を取得
	// We intentionally panic on missing required values earlier so failures are
	// loud during startup rather than surfacing deep in the networking stack.
	// caCertPath := getEnvOrDefault("CA_FILE", "/etc/ssl/certs/ca-certificates.crt")
	// caCert := readFileOrEmpty(caCertPath)
	certPath := path
	if certPath == "" {
		certPath = "/etc/ssl/certs/ca-certificates.crt"
	}
	caCert := readFileOrEmpty(certPath)

	// accountName := getEnvOrPanic("ACCOUNT")
	// accountName, err := getEnv("ACCOUNT")
	// if err != nil {
	// 	elLog.Error("SetupVpnDelegate ERROR 1")
	// 	return nil, err
	// }
	if account == "" {
		return nil, fmt.Errorf("SetupELVpnDelegate ERROR 1")
	}

	// accountPassword := getEnvOrPanic("PASSWORD")
	// accountPassword, err := getEnv("PASSWORD")
	// if err != nil {
	// 	elLog.Error("SetupVpnDelegate ERROR 2")
	// 	return nil, err
	// }
	if password == "" {
		return nil, fmt.Errorf("SetupVpnDelegate ERROR 2")
	}

	// accountCfg := el_stack.NewElStackAccountConfig(accountName, accountPassword)

	// vpnHost := getEnvOrPanic("SERVER_HOST")
	// vpnHost, err := getEnv("SERVER_HOST")
	// if err != nil {
	// 	return &VpnDelegate{}, err
	// }
	// vpnHost := getEnvOrDefault("SERVER_HOST", "ec2-57-181-8-159.ap-northeast-1.compute.amazonaws.com")
	vpnHost := host
	if vpnHost == "" {
		vpnHost = "ec2-57-181-8-159.ap-northeast-1.compute.amazonaws.com"
	}

	// vpnPort := getEnvOrPanic("SERVER_SERV")
	// vpnPort, err := getEnv("SERVER_SERV")
	// if err != nil {
	// 	return &VpnDelegate{}, err
	// }
	// vpnPort := getEnvOrDefault("SERVER_SERV", "443")
	vpnPort := port
	if vpnPort == "" {
		vpnPort = "443"
	}

	// antiOverlap := getEnvOrPanic("ANTI_OVERLAP")
	// antiOverlap, err := getEnv("ANTI_OVERLAP")
	// if err != nil {
	// 	return nil, err
	// }
	// antiOverlap := getEnvOrDefault("ANTI_OVERLAP", "12345678901234567890123456789012")
	antiOverlap := antioverlap
	if antiOverlap == "" {
		antiOverlap = "12345678901234567890123456789012"
	}

	vpnKeepAliveSec, err := getEnvUint64OrDefault("KEEPALIVE_INTERVAL", 60)
	if err != nil {
		elLog.Error("SetupVpnDelegate ERROR 3")
		return nil, err
	}

	vpnTimeoutSec, err := getEnvUint64OrDefault("RECV_TIMEOUT", 180)
	if err != nil {
		elLog.Error("SetupVpnDelegate ERROR 4")
		return nil, err
	}

	// accountCfg := el_stack.NewElStackAccountConfig(accountName, accountPassword)
	accountCfg := el_stack.NewElStackAccountConfig(account, password)

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

	if err := el_stack.Start(delegate, vpnCfg, accountCfg); err != nil {
		elLog.Error("SetupELVpnDelegate ERROR", "err", err)
		return nil, err
	}
	<-delegate.linkedCh
	return delegate, nil
}

func StopElStack() {
	elLog.Trace("StopElStack START")
	el_stack.Stop()
	elLog.Trace("StopElStack DONE")
}
