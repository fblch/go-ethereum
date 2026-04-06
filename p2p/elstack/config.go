package elstack

import (
	"errors"
	"fmt"
	"strings"
)

// ELConfig holds Emotion Link configuration propagated from CLI flags.
// Note: field names drop the leading EL prefix here per specification.
type ELConfig struct {
	Use           bool
	HolderVC      string
	HolderPrivKey string
	AntiOverlap   string
	IssuerPubKey  string
	ServerAddr    string
	ServerPort    int
	ServerCACert  string
	CapturePath   string
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

func ValidateMobileELConfig(cfg *ELConfig) error {
	if err := ValidateELConfig(cfg); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.ServerCACert) == "" {
		return fmt.Errorf("ServerCACert is required value to boot on mobile")
	}
	return nil
}
