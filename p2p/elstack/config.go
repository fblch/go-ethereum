package elstack

import (
	"fmt"
	"strings"
)

// ELConfig holds Emotion Link configuration propagated from CLI flags.
// Note: field names drop the leading EL prefix here per specification.
type ELConfig struct {
	// Use is the flag for enabling p2p networking over Emotion Link.
	Use bool

	// ProductName is the name of the product using the EL stack.
	ProductName string

	// HolderVC is the EL client's VC required for connecting to the EL server.
	HolderVC string

	// HolderPrivKey is the EL client's private key.
	HolderPrivKey string

	// AntiOverlap is the EL client's anti-overlap value.
	AntiOverlap string

	// IssuerPubKey is the VC issuer's public key.
	IssuerPubKey string

	// ServerAddr is the EL server's address (hostname).
	ServerAddr string

	// ServerPort is the EL server's port number.
	ServerPort int

	// ServerCACert is the EL server's CA certificate.
	ServerCACert string

	// RecvTimeout is the EL server receive timeout in seconds.
	RecvTimeout int

	// ConnTimeout is the EL server connection timeout in seconds (0 = infinite).
	// Note that the effective connection timeout is the smaller of ConnTimeout and RecvTimeout.
	ConnTimeout int

	// KeepAliveInterval is the EL keepalive interval in seconds.
	KeepAliveInterval int

	// CapturePath is the file to store EL packet capture (set to enable packet capture).
	CapturePath string
}

// ValidateELConfig validates EL config before starting EL stack.
func ValidateELConfig(cfg *ELConfig) error {
	if cfg == nil {
		return fmt.Errorf("El config is nil")
	}
	if !cfg.Use {
		return fmt.Errorf("EL is disabled")
	}
	if strings.TrimSpace(cfg.ProductName) == "" {
		return fmt.Errorf("ProductName is not set")
	}
	if strings.TrimSpace(cfg.HolderVC) == "" {
		return fmt.Errorf("HolderVC is not set")
	}
	if strings.TrimSpace(cfg.HolderPrivKey) == "" {
		return fmt.Errorf("HolderPrivKey is not set")
	}
	if strings.TrimSpace(cfg.AntiOverlap) == "" {
		return fmt.Errorf("AntiOverlap is not set")
	}
	if strings.TrimSpace(cfg.IssuerPubKey) == "" {
		return fmt.Errorf("IssuerPubKey is not set")
	}
	if strings.TrimSpace(cfg.ServerAddr) == "" {
		return fmt.Errorf("ServerAddr is not set")
	}
	if cfg.ServerPort <= 0 {
		return fmt.Errorf("ServerPort is not set or invalid")
	}
	// Note: zero causes connection failure, so we don't allow it.
	if cfg.RecvTimeout <= 0 {
		return fmt.Errorf("RecvTimeout is too short")
	}
	// Note: zero means infinite timeout, so we allow it.
	if cfg.ConnTimeout < 0 {
		return fmt.Errorf("ConnTimeout is negative")
	}
	// Note: zero causes constant transmissions, so we don't allow it.
	if cfg.KeepAliveInterval <= 0 {
		return fmt.Errorf("KeepAliveInterval is too short")
	}
	if cfg.RecvTimeout <= cfg.KeepAliveInterval {
		return fmt.Errorf("RecvTimeout has to be longer than KeepAliveInterval")
	}
	return nil
}

// ValidateMobileELConfig validates EL config for mobile before starting EL stack.
func ValidateMobileELConfig(cfg *ELConfig) error {
	if err := ValidateELConfig(cfg); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.ServerCACert) == "" {
		return fmt.Errorf("ServerCACert is not set")
	}
	return nil
}
