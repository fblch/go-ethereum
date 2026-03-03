package elstack

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/p2p/elstack/el_stack" // if you copied el_stack directory directly below elstack directory, use it.
)

// LinkedResult represents the initial link outcome from EL.
type LinkedResult struct {
	Addr net.IP
	Err  error
}

// WisteriaVpnEventDelegate 実装
type VpnDelegate struct {
	results chan LinkedResult
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
	if strings.TrimSpace(cfg.HolderVC) == "" {
		return fmt.Errorf("HolderVC content is empty")
	}
	if strings.TrimSpace(cfg.HolderPrivKey) == "" {
		return fmt.Errorf("HolderPrivKey content is empty")
	}
	if strings.TrimSpace(cfg.IssuerPubKey) == "" {
		return fmt.Errorf("IssuerPubKey content is empty")
	}
	if strings.TrimSpace(cfg.ServerAddr) == "" {
		return fmt.Errorf("EL server hostname is not set")
	}
	if cfg.ServerPort <= 0 {
		return fmt.Errorf("EL server port must be positive")
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
	if d.results == nil {
		return
	}
	d.results <- LinkedResult{Err: fmt.Errorf(msg)}
}

func (d *VpnDelegate) OnLinkedParams(ipAddrs, dnsAddrs, routes []string) {
	elLog.Info("LinkedParams", "IP", ipAddrs, "DNS", dnsAddrs, "ROUTES", routes)
	ipAddr := ipAddrs[0][:strings.Index(ipAddrs[0], "/")]
	elLog.Info("get ip address", "address", ipAddr)
	if d.results == nil {
		return
	}
	addr := net.ParseIP(ipAddr)
	if addr == nil {
		d.results <- LinkedResult{Err: fmt.Errorf("invalid IP from EL: %s", ipAddr)}
		return
	}
	d.results <- LinkedResult{Addr: addr}
}

func SetupEL(cfg *ELConfig, results chan LinkedResult, quit <-chan struct{}) {
	if results == nil {
		return
	}
	if err := ValidateELConfig(cfg); err != nil {
		results <- LinkedResult{Err: err}
		return
	}

	// We intentionally panic on missing required values earlier so failures are
	// loud during startup rather than surfacing deep in the networking stack.
	elLog.Info("SetupEL arg", "cfg.ServerAddr", cfg.ServerAddr)
	elLog.Info("SetupEL arg", "cfg.ServerPort", cfg.ServerPort)

	vc := cfg.HolderVC
	vcPrivKey := cfg.HolderPrivKey
	issuerPubkey := cfg.IssuerPubKey

	vpnHost := cfg.ServerAddr
	vpnPort := strconv.Itoa(cfg.ServerPort)

	antiOverlap := cfg.AntiOverlap

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

	prodCfg := el_stack.NewElStackProductConfig(productName, productVersion, productPlatform, cfg.ServerCACert, 1280)

	// default:
	// - tcpBuffSize = 16,384 bytes
	// - udpBuffSize = 8,192 bytes
	// - udpMetaSize = 32 entries
	// buffCfg := el_stack.NewElStackSocketBufferConfig(1024, nil, nil, nil)
	maxBurstSize := uint64(2048)
	tcpBuffSize := uint64(65536)
	udpBuffSize := uint64(65536)
	udpMetaSize := uint64(2048)
	buffCfg := el_stack.NewElStackSocketBufferConfig(maxBurstSize, &tcpBuffSize, &udpBuffSize, &udpMetaSize)

	el_stack.Initialize(prodCfg, buffCfg)

	vcCfg := el_stack.NewElStackVcConfig(vc, vcPrivKey, issuerPubkey)

	delegate := &VpnDelegate{results: results}

	if err := el_stack.Start(delegate, vpnCfg, vcCfg, cfg.CapturePath); err != nil {
		el_stack.Stop()
		elLog.Error("SetupEL ERROR", "err", err)
		results <- LinkedResult{Err: err}
		return
	}

	if quit != nil {
		go func() {
			<-quit
			el_stack.Stop()
			if results != nil {
				close(results)
			}
		}()
	}
}

// WaitInitialEL waits for the first address or error on the results channel.
func WaitInitialEL(results <-chan LinkedResult) (net.IP, error) {
	for {
		v, ok := <-results
		if !ok {
			return nil, fmt.Errorf("EL setup terminated before initial link")
		}
		if v.Err != nil {
			return nil, v.Err
		}
		if v.Addr != nil {
			return v.Addr, nil
		}
	}
}

// StopElStack stops the EL stack.
func StopElStack() {
	start := time.Now()
	elLog.Trace("StopElStack START")
	el_stack.Stop()
	elLog.Trace("StopElStack DONE", "elapsed", time.Since(start))
}

// StopElStackSafe stops the EL stack and closes the updates channel if provided.
func StopElStackSafe(resCh chan LinkedResult) {
	StopElStack()
	if resCh != nil {
		close(resCh)
	}
}
