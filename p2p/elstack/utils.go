package elstack

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

// readFileOrEmpty reads a file and returns its contents or an empty slice on error.
func readFileOrEmpty(path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		return []byte{}
	}
	return b
}

// ReadCertFile loads a certificate file as string. Empty content is allowed.
func ReadCertFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read certificate file %s: %w", path, err)
	}
	// トリムは行うが、空でもエラーにしない
	return strings.TrimSpace(string(content)), nil
}

// ReadSecretFile reads a file and returns its trimmed contents.
func ReadSecretFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("secret file path is empty")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read secret file: %w", err)
	}
	value := strings.TrimSpace(string(content))
	if value == "" {
		return "", fmt.Errorf("secret file %s is empty", path)
	}
	return value, nil
}

// ReadOrCreateAntiOverlap loads an anti-overlap token from the given path.
// If the file is missing or invalid, it generates a new token, saves it, and returns it.
func ReadOrCreateAntiOverlap(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("anti-overlap file path is empty")
	}
	content, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read anti-overlap file: %w", err)
	}
	token := strings.TrimSpace(string(content))
	if !isAlphaNumeric32(token) {
		token, err = randomAlphaNumeric32()
		if err != nil {
			return "", fmt.Errorf("generate anti-overlap token: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return "", fmt.Errorf("create anti-overlap directory: %w", err)
		}
		if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
			return "", fmt.Errorf("write anti-overlap token: %w", err)
		}
	}
	return token, nil
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
			return "", err
		}
		buf[i] = letters[n.Int64()]
	}
	return string(buf), nil
}
