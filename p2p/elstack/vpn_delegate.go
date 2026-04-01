package elstack

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
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
	results *linkedResultStream
}

// linkedResultStream serializes send/close operations for LinkedResult channel.
// It prevents panics caused by concurrent close and send.
type linkedResultStream struct {
	ch     chan LinkedResult
	mu     sync.Mutex
	closed bool
}

const criticalResultRetryInterval = 10 * time.Millisecond

func newLinkedResultStream(ch chan LinkedResult) *linkedResultStream {
	if ch == nil {
		return nil
	}
	return &linkedResultStream{ch: ch}
}

func (s *linkedResultStream) trySendLocked(v LinkedResult) bool {
	select {
	case s.ch <- v:
		return true
	default:
		return false
	}
}

// SendBestEffort sends a result without blocking. It may drop when the buffer is full.
func (s *linkedResultStream) SendBestEffort(v LinkedResult) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ch == nil {
		return false
	}
	if s.trySendLocked(v) {
		return true
	}
	elLog.Warn("LinkedResult channel is full; dropping event")
	return false
}

// SendCritical retries until the event is sent or the stream is closed.
func (s *linkedResultStream) SendCritical(v LinkedResult) bool {
	if s == nil {
		return false
	}
	loggedRetry := false
	for {
		s.mu.Lock()
		if s.closed || s.ch == nil {
			s.mu.Unlock()
			return false
		}
		if s.trySendLocked(v) {
			s.mu.Unlock()
			return true
		}
		s.mu.Unlock()

		if !loggedRetry {
			elLog.Warn("LinkedResult channel is full; retrying critical event")
			loggedRetry = true
		}
		time.Sleep(criticalResultRetryInterval)
	}
}

func (s *linkedResultStream) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	if s.ch != nil {
		close(s.ch)
	}
}

func (d *VpnDelegate) OnStatusChange(status el_stack.VpnStatus) {
	elLog.Debug("VPN Status", "status", status)
}

func (d *VpnDelegate) OnConnectionError(msg string) {
	elLog.Error("VPN Connection error", "msg", msg)
	_ = d.results.SendBestEffort(LinkedResult{Err: errors.New(msg)})
}

func (d *VpnDelegate) OnLinkedParams(ipAddrs, dnsAddrs, routes []string) {
	elLog.Info("LinkedParams", "IP", ipAddrs, "DNS", dnsAddrs, "ROUTES", routes)
	if len(ipAddrs) == 0 {
		elLog.Warn("LinkedParams has no IP address yet; skipping")
		return
	}
	ipAddr := strings.TrimSpace(ipAddrs[0])
	if slash := strings.Index(ipAddr, "/"); slash >= 0 {
		ipAddr = strings.TrimSpace(ipAddr[:slash])
	}
	elLog.Info("get ip address", "address", ipAddr)
	addr := net.ParseIP(ipAddr)
	if addr == nil {
		_ = d.results.SendBestEffort(LinkedResult{Err: fmt.Errorf("invalid IP from EL: %s", ipAddr)})
		return
	}
	_ = d.results.SendCritical(LinkedResult{Addr: addr})
}

func SetupEL(cfg *ELConfig, results chan LinkedResult, quit <-chan struct{}) {
	resultStream := newLinkedResultStream(results)
	if resultStream == nil {
		return
	}
	if err := ValidateELConfig(cfg); err != nil {
		_ = resultStream.SendCritical(LinkedResult{Err: err})
		resultStream.Close()
		return
	}

	// We intentionally panic on missing required values earlier so failures are
	// loud during startup rather than surfacing deep in the networking stack.
	elLog.Debug("SetupEL arg", "cfg.ServerAddr", cfg.ServerAddr)
	elLog.Debug("SetupEL arg", "cfg.ServerPort", cfg.ServerPort)

	vpnTimeoutSec := uint64(30)
	vpnKeepAliveSec := uint64(10)
	vpnCfg := el_stack.NewElStackVpnConfig(
		cfg.ServerAddr,
		strconv.Itoa(cfg.ServerPort),
		cfg.AntiOverlap,
		vpnTimeoutSec,
		vpnKeepAliveSec,
		el_stack.ElStackVpnConnectionTypeQuic,
	)

	productName := "go-ethereum-el"
	productVersion := "0.1.0"
	productPlatform := "Linux"
	prodCfg := el_stack.NewElStackProductConfig(
		productName,
		productVersion,
		productPlatform,
		cfg.ServerCACert,
		1280,
	)

	// args of el_stack.NewElStackSocketBufferConfig
	maxBurstSize := uint64(1024)
	// default:
	// tcpBuffSize := uint64(16384)
	// udpBuffSize := uint64(8192)
	// udpMetaSize := uint64(32)

	// AndroidOS:
	tcpBuffSize := uint64(131072)
	udpBuffSize := uint64(212992)
	udpMetaSize := uint64(32)

	// iOS:
	// tcpBuffSize := uint64(65536)
	// udpBuffSize := uint64(65536)
	// udpMetaSize := uint64(32)

	// buffCfg := el_stack.NewElStackSocketBufferConfig(1024, nil, nil, nil)
	buffCfg := el_stack.NewElStackSocketBufferConfig(
		maxBurstSize,
		&tcpBuffSize,
		&udpBuffSize,
		&udpMetaSize,
	)

	el_stack.Initialize(prodCfg, buffCfg)

	vcCfg := el_stack.NewElStackVcConfig(cfg.HolderVC, cfg.HolderPrivKey, cfg.IssuerPubKey)

	delegate := &VpnDelegate{results: resultStream}

	if err := el_stack.Start(delegate, vpnCfg, vcCfg, &cfg.CapturePath); err != nil {
		el_stack.Stop()
		elLog.Error("SetupEL ERROR", "err", err)
		_ = resultStream.SendCritical(LinkedResult{Err: err})
		resultStream.Close()
		return
	}

	if quit != nil {
		go func() {
			<-quit
			el_stack.Stop()
			resultStream.Close()
		}()
	}
}

// WaitInitialEL keeps waiting until an initial address is received.
// Error events are logged and ignored so transient failures can recover.
func WaitInitialEL(results <-chan LinkedResult) (net.IP, error) {
	var lastErr error
	for {
		v, ok := <-results
		if !ok {
			if lastErr != nil {
				return nil, fmt.Errorf("EL setup terminated before initial link: %w", lastErr)
			}
			return nil, fmt.Errorf("EL setup terminated before initial link")
		}
		if v.Err != nil {
			lastErr = v.Err
			elLog.Warn("EL initial link failed, waiting for retry", "err", v.Err)
			continue
		}
		if v.Addr != nil {
			elLog.Info("EL initial link established", "ip", v.Addr)
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

// StopElStackSafe stops the EL stack.
// Channel close is intentionally owned by SetupEL to avoid close/send races.
func StopElStackSafe(_ chan LinkedResult) {
	StopElStack()
}
