package elstack

import (
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/internal/version"
	"github.com/ethereum/go-ethereum/p2p/elstack/el_stack"
	"github.com/ethereum/go-ethereum/params"
)

// LinkedResult represents the outcome of initial link to the EL server.
// It contains either the assigned IP address or an error if the link failed.
type LinkedResult struct {
	Addr net.IP
	Err  error
}

// vpnDelegate receives callbacks from EL stack and forwards
// them to a linkedResultStream for processing.
type vpnDelegate struct {
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ch == nil {
		return false
	}
	if s.trySendLocked(v) {
		return true
	}
	elLog.Warn("LinkedResult channel is full. Canceling best effort result delivery.")
	return false
}

// SendCritical retries until the result is sent or the stream is closed.
func (s *linkedResultStream) SendCritical(v LinkedResult) bool {
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
			elLog.Warn("LinkedResult channel is full. Retrying critical result delivery.")
			loggedRetry = true
		}
		time.Sleep(criticalResultRetryInterval)
	}
}

func (s *linkedResultStream) Close() {
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

func (d *vpnDelegate) OnStatusChange(status el_stack.VpnStatus) {
	elLog.Debug("VPN OnStatusChange", "status", status)
}

func (d *vpnDelegate) OnConnectionError(msg string) {
	elLog.Error("VPN OnConnectionError", "msg", msg)
	_ = d.results.SendBestEffort(LinkedResult{Err: errors.New(msg)})
}

func (d *vpnDelegate) OnLinkedParams(ipAddrs, dnsAddrs, routes []string) {
	elLog.Info("VPN OnLinkedParams", "IP", ipAddrs, "DNS", dnsAddrs, "ROUTES", routes)
	if len(ipAddrs) == 0 {
		elLog.Warn("No IP address from EL yet...")
		return
	}
	ipAddr := strings.TrimSpace(ipAddrs[0])
	if slash := strings.Index(ipAddr, "/"); slash >= 0 {
		ipAddr = strings.TrimSpace(ipAddr[:slash])
	}
	elLog.Info("Got IP address from EL", "ip", ipAddr)
	addr := net.ParseIP(ipAddr)
	if addr == nil {
		_ = d.results.SendBestEffort(LinkedResult{Err: fmt.Errorf("Invalid IP address from EL: %s", ipAddr)})
		return
	}
	_ = d.results.SendCritical(LinkedResult{Addr: addr})
}

// SetupEL creates various configs, initializes and starts the EL stack,
// and optionally listens on the quit channel for p2p server shutdown
// in order to stop the EL stack and release alocated resources.
func SetupEL(cfg *ELConfig, results chan LinkedResult, quit <-chan struct{}) {
	resultStream := newLinkedResultStream(results)
	if resultStream == nil {
		return
	}

	// We intentionally panic on missing required values earlier so failures are
	// loud during startup rather than surfacing deep in the networking stack.
	elLog.Info("Setting up EL", "serverAddr", cfg.ServerAddr, "serverPort", cfg.ServerPort)

	// Create VPN config

	vpnRecvTimeoutSec := uint64(180)
	vpnKeepAliveIntervalSec := uint64(60)
	var vpnConnectionTimeoutSec *uint64
	if cfg.ConnectionTimeout != 0 {
		connectionTimeoutUint := uint64(cfg.ConnectionTimeout)
		vpnConnectionTimeoutSec = &connectionTimeoutUint
	}

	vpnConfig := el_stack.NewElStackVpnConfig(cfg.ServerAddr, strconv.Itoa(cfg.ServerPort), cfg.AntiOverlap,
		vpnRecvTimeoutSec, vpnConnectionTimeoutSec, vpnKeepAliveIntervalSec, el_stack.ElStackVpnConnectionTypeQuic,
	)

	// Create product config

	git, _ := version.VCS()
	productVersion := params.VersionWithCommit(git.Commit, git.Date)
	productPlatform := runtime.GOOS + "-" + runtime.GOARCH + "/" + runtime.Version()
	mtu := uint64(1280)

	prodConfig := el_stack.NewElStackProductConfig(cfg.ProductName, productVersion, productPlatform, cfg.ServerCACert, mtu)

	// Create socket buffer config

	maxBurstSize := uint64(1024)

	// TODO by Jakub Pajek (EL): check runtime.GOOS (linux, darwin, windows, android, ios) and set buffer sizes accordingly.

	// EL stack defaults:
	// tcpBuffSize := uint64(16384)
	// udpBuffSize := uint64(8192)
	// udpMetaSize := uint64(32)
	// buffCfg := el_stack.NewElStackSocketBufferConfig(maxBurstSize, nil, nil, nil)

	// Android defaults:
	tcpBuffSize := uint64(131072)
	udpBuffSize := uint64(212992)
	udpMetaSize := uint64(32)

	// iOS defaults:
	// tcpBuffSize := uint64(65536)
	// udpBuffSize := uint64(65536)
	// udpMetaSize := uint64(32)
	// udpMetaSize := uint64(2048)

	buffConfig := el_stack.NewElStackSocketBufferConfig(maxBurstSize, &tcpBuffSize, &udpBuffSize, &udpMetaSize)

	// Initialize EL stack

	el_stack.Initialize(prodConfig, buffConfig)

	// Create VC config

	vcConfig := el_stack.NewElStackVcConfig(cfg.HolderVC, cfg.HolderPrivKey, cfg.IssuerPubKey)

	// Start EL stack

	vpnDelegate := &vpnDelegate{results: resultStream}

	var capturePath *string
	if cfg.CapturePath != "" {
		capturePath = &cfg.CapturePath
	}

	if err := el_stack.Start(vpnDelegate, vpnConfig, vcConfig, capturePath); err != nil {
		elLog.Error("EL setup failed!", "err", err)
		el_stack.Stop()
		_ = resultStream.SendCritical(LinkedResult{Err: err})
		resultStream.Close()
		return
	}

	// Stop EL stack on p2p server stop

	if quit != nil {
		go func() {
			<-quit
			el_stack.Stop()
			resultStream.Close()
		}()
	}
}

// WaitInitialEL keeps waiting until initial link with the EL server is established.
// Error events are logged and ignored so that transient failures can recover.
func WaitInitialEL(results <-chan LinkedResult) (net.IP, error) {
	for {
		result, ok := <-results
		if !ok {
			return nil, fmt.Errorf("EL setup terminated before initial link established")
		}
		if result.Err != nil {
			elLog.Warn("EL initial link failed! Waiting for retry...", "err", result.Err)
			continue
		}
		if result.Addr != nil {
			elLog.Info("EL initial link established", "ip", result.Addr)
			return result.Addr, nil
		}
	}
}

// MonitorEL keeps monitoring the EL link status and logs any disconnections or re-establishments.
func MonitorEL(results <-chan LinkedResult, srvQuit <-chan struct{}) {
	for {
		select {
		case result, ok := <-results:
			if !ok {
				elLog.Error("LinkedResult channel closed! Stopping EL monitoring...")
				return
			}
			if result.Err != nil {
				elLog.Error("EL link disconnected! Waiting for retry...", "err", result.Err)
				continue
			}
			if result.Addr != nil {
				// TODO by Jakub Pajek (EL): what if the IP changes?
				// We should update staticIP and rebind listeners,
				// but is it possible without stopping the Server object?
				// (Server object can not be re-used after stopping)
				elLog.Info("EL link re-established", "ip", result.Addr)
				continue
			}
		case <-srvQuit:
			// srvQuit will be nil when MonitorEL is called from bootnode.
			// Any send or receive operation on a nil channel blocks forever.
			// When used inside a select statement, the select simply ignores
			// that case and it will never be chosen.
			return
		}
	}
}
