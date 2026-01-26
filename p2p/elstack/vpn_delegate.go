package elstack

import (
	// "el_stack"

	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

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

func readRequiredFile(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("required file path is empty")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read required file %s: %w", path, err)
	}
	val := strings.TrimSpace(string(content))
	if val == "" {
		return "", fmt.Errorf("required file %s is empty", path)
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
	Addr    net.IP
	Err     error
	updates chan VpnDelegate
}

// sendUpdate delivers a delegate update without blocking callers. If the channel
// is full or already closed, the update is dropped.
func sendUpdate(updates chan VpnDelegate, v VpnDelegate) {
	if updates == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			elLog.Debug("drop EL update", "reason", r)
		}
	}()
	select {
	case updates <- v:
	default:
		elLog.Debug("drop EL update", "reason", "channel full")
	}
}

var (
	ErrELConfigNil = errors.New("EL config is nil")
	ErrELDisabled  = errors.New("EL is disabled")
)

// ValidateELConfig checks that required fields are present before starting EL.
func ValidateELConfig(cfg *ELConfig) error {
	if cfg == nil {
		return ErrELConfigNil
	}
	if !cfg.Use {
		return ErrELDisabled
	}
	if strings.TrimSpace(cfg.VC) == "" {
		return fmt.Errorf("VC content is empty")
	}
	if strings.TrimSpace(cfg.VCPrivKey) == "" {
		return fmt.Errorf("VCPrivKey content is empty")
	}
	if strings.TrimSpace(cfg.IssuerPubkey) == "" {
		return fmt.Errorf("IssuerPubkey content is empty")
	}
	if strings.TrimSpace(cfg.Host) == "" {
		return fmt.Errorf("EL server hostname is not set")
	}
	if strings.TrimSpace(cfg.Port) == "" {
		return fmt.Errorf("EL server port is not set")
	}
	if strings.TrimSpace(cfg.AntiOverlap) == "" {
		return fmt.Errorf("AntiOverlap token is empty")
	}
	return nil
}

func (d *VpnDelegate) OnStatusChange(status el_stack.VpnStatus) {
	elLog.Debug("VPN Status", "status", status)
}

func (d *VpnDelegate) OnConnectionError(msg string) {
	elLog.Error("VPN Connection error", "msg", msg)
	sendUpdate(d.updates, VpnDelegate{Err: fmt.Errorf(msg)})
}

func (d *VpnDelegate) OnLinkedParams(ipAddrs, dnsAddrs, routes []string) {
	elLog.Info("LinkedParams", "IP", ipAddrs, "DNS", dnsAddrs, "ROUTES", routes)
	ipAddr := ipAddrs[0][:strings.Index(ipAddrs[0], "/")]
	elLog.Info("get ip address", "address", ipAddr)
	if d.updates == nil {
		return
	}
	addr := net.ParseIP(ipAddr)
	if addr == nil {
		sendUpdate(d.updates, VpnDelegate{Err: fmt.Errorf("invalid IP from EL: %s", ipAddr)})
		return
	}
	sendUpdate(d.updates, VpnDelegate{Addr: addr})
}

func SetupEL(cfg *ELConfig, updates chan VpnDelegate, quit <-chan struct{}) {
	if err := ValidateELConfig(cfg); err != nil {
		sendUpdate(updates, VpnDelegate{Err: err})
		return
	}
	// We intentionally panic on missing required values earlier so failures are
	// loud during startup rather than surfacing deep in the networking stack.
	elLog.Info("SetupEL arg", "cfg.Host", cfg.Host)
	elLog.Info("SetupEL arg", "cfg.Port", cfg.Port)

	vc := strings.TrimSpace(cfg.VC)
	vcPrivKey := strings.TrimSpace(cfg.VCPrivKey)
	issuerPubkey := strings.TrimSpace(cfg.IssuerPubkey)

	certPath := cfg.CertPath
	if certPath == "" {
		certPath = "/etc/ssl/certs/ca-certificates.crt"
	}
	caCert := readFileOrEmpty(certPath)

	vpnHost := cfg.Host
	vpnPort := cfg.Port

	antiOverlap := strings.TrimSpace(cfg.AntiOverlap)

	vpnKeepAliveSec := uint64(10)
	vpnTimeoutSec := uint64(30)

	vpnCfg := el_stack.NewElStackVpnConfig(
		vpnHost, vpnPort, antiOverlap,
		vpnTimeoutSec, vpnKeepAliveSec,
		el_stack.ElStackVpnConnectionTypeQuic,
	)

	productName := "go-ethereum-el"
	productVersion := "0.1.0"
	productPlatform := "Linux"

	prodCfg := el_stack.NewElStackProductConfig(productName, productVersion, productPlatform, caCert, 1280)

	defaultBurstSize := uint64(1024)
	defaultTCPBuffer := uint64(16384)
	defaultUDPBuffer := uint64(8192)
	defaultMetaDataSize := uint64(32)
	buffCfg := el_stack.NewElStackSocketBufferConfig(defaultBurstSize, &defaultTCPBuffer, &defaultUDPBuffer, &defaultMetaDataSize)

	el_stack.Initialize(prodCfg, buffCfg)
	delegate := &VpnDelegate{
		updates: updates,
	}

	vcCfg := el_stack.NewElStackVcConfig(vc, vcPrivKey, issuerPubkey)

	if err := el_stack.Start(delegate, vpnCfg, vcCfg, nil); err != nil {
		el_stack.Stop()
		elLog.Error("SetupEL ERROR", "err", err)
		sendUpdate(updates, VpnDelegate{Err: err})
		return
	}

	if quit != nil {
		go func() {
			<-quit
			elLog.Trace("StopElStack by quit signal")
			el_stack.Stop()
			if updates != nil {
				close(updates)
			}
		}()
	}
}

// StartAndWait sets up EL and waits for the first delegate update, returning the
// assigned IP on success. The quit channel can be nil if no shutdown signal is needed.
func StartAndWait(cfg *ELConfig, quit <-chan struct{}) (net.IP, error) {
	updates := make(chan VpnDelegate, 1)
	SetupEL(cfg, updates, quit)

	first, ok := <-updates
	if !ok {
		return nil, fmt.Errorf("EL setup terminated before initial link")
	}
	if first.Err != nil {
		return nil, first.Err
	}
	if first.Addr == nil {
		return nil, fmt.Errorf("EL setup returned nil IP")
	}
	return first.Addr, nil
}

// StopElStack stops the EL stack.
func StopElStack() {
	elLog.Trace("StopElStack START")
	el_stack.Stop()
	elLog.Trace("StopElStack DONE")
}

// StopElStackSafe stops the EL stack and closes the updates channel if provided.
func StopElStackSafe(updates chan VpnDelegate) {
	StopElStack()
	if updates != nil {
		close(updates)
	}
}
