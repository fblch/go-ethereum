package elstack

import (
	// "el_stack"

	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
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

func isAlphaNumeric32(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			continue
		}
		return false
	}
	return true
}

func randomAlphaNumeric32() (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	buf := make([]byte, 32)
	max := big.NewInt(int64(len(letters)))
	for i := 0; i < len(buf); i++ {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("generate random antiOverlap: %w", err)
		}
		buf[i] = letters[n.Int64()]
	}
	return string(buf), nil
}

func loadOrCreateAntiOverlap(path string) (string, error) {
	val := strings.TrimSpace(path)
	if val == "" {
		return "", fmt.Errorf("antiOverlap path is not set")
	}

	content, err := os.ReadFile(val)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read antiOverlap file: %w", err)
	}

	token := strings.TrimSpace(string(content))
	if !isAlphaNumeric32(token) {
		token, err = randomAlphaNumeric32()
		if err != nil {
			return "", err
		}

		if err := os.MkdirAll(filepath.Dir(val), 0o755); err != nil {
			return "", fmt.Errorf("create antiOverlap directory: %w", err)
		}
		if err := os.WriteFile(val, []byte(token), 0o600); err != nil {
			return "", fmt.Errorf("write antiOverlap file: %w", err)
		}
	}
	return token, nil
}

// WisteriaVpnEventDelegate 実装
type VpnDelegate struct {
	Addr    net.IP
	Err     error
	updates chan VpnDelegate
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
	if _, err := loadOrCreateAntiOverlap(cfg.AntiOverlap); err != nil {
		return err
	}
	return nil
}

func (d *VpnDelegate) OnStatusChange(status el_stack.VpnStatus) {
	elLog.Debug("VPN Status", "status", status)
}

func (d *VpnDelegate) OnConnectionError(msg string) {
	elLog.Error("VPN Connection error", "msg", msg)
	if d.updates != nil {
		d.updates <- VpnDelegate{Err: fmt.Errorf(msg)}
	}
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
		d.updates <- VpnDelegate{Err: fmt.Errorf("invalid IP from EL: %s", ipAddr)}
		return
	}
	d.updates <- VpnDelegate{Addr: addr}
}

func SetupEL(cfg *ELConfig, updates chan VpnDelegate, quit <-chan struct{}) {
	if err := ValidateELConfig(cfg); err != nil {
		if updates != nil {
			updates <- VpnDelegate{Err: err}
		}
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

	antiOverlap, err := loadOrCreateAntiOverlap(cfg.AntiOverlap)
	if err != nil {
		if updates != nil {
			updates <- VpnDelegate{Err: err}
		}
		return
	}

	vpnKeepAliveSec := uint64(60)
	vpnTimeoutSec := uint64(180)

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
		if updates != nil {
			updates <- VpnDelegate{Err: err}
		}
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
