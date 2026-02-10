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
		el_stack.ElStackVpnConnectionTypeTls,
	)

	productName := "go-ethereum-el"
	productVersion := "0.1.0"
	productPlatform := "Linux"

	prodCfg := el_stack.NewElStackProductConfig(productName, productVersion, productPlatform, cfg.ServerCACert, 1280)

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
			elLog.Info("waiting srv.quit at SetupEL")
			<-quit
			elLog.Trace("StopElStack by quit signal")
			start := time.Now()
			el_stack.Stop()
			elLog.Trace("StopElStack by quit signal DONE", "elapsed", time.Since(start))
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
	start := time.Now()
	elLog.Trace("StopElStack START")
	el_stack.Stop()
	elLog.Trace("StopElStack DONE", "elapsed", time.Since(start))
}

// StopElStackSafe stops the EL stack and closes the updates channel if provided.
func StopElStackSafe(updates chan VpnDelegate) {
	StopElStack()
	if updates != nil {
		close(updates)
	}
}
