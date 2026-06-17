package elstack

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ReadTrimmedFile reads a file and returns its trimmed contents.
// If the trimmed path or content is empty and allowEmpty is false, it returns an error.
func ReadTrimmedFile(path string, allowEmpty bool) (string, error) {
	if strings.TrimSpace(path) == "" {
		if !allowEmpty {
			return "", fmt.Errorf("file path is empty")
		}
		return "", nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", path, err)
	}
	value := strings.TrimSpace(string(content))
	if value == "" && !allowEmpty {
		return "", fmt.Errorf("file %s is empty", path)
	}
	return value, nil
}

// ReadOrCreateAntiOverlap reads anti-overlap token from a given file.
// If the file is missing or invalid, it generates a new token, saves it, and returns it.
func ReadOrCreateAntiOverlap(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", fmt.Errorf("file path is empty")
	}
	content, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("failed to read file %s: %w", path, err)
	}
	token := strings.TrimSpace(string(content))
	if !isAlphaNumeric32(token) {
		token, err = randomAlphaNumeric32()
		if err != nil {
			return "", fmt.Errorf("failed to generate anti-overlap token: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return "", fmt.Errorf("failed to create anti-overlap token directory: %w", err)
		}
		if err := os.WriteFile(path, []byte(token), 0o600); err != nil {
			return "", fmt.Errorf("failed to write anti-overlap token to file: %w", err)
		}
	}
	return token, nil
}

func isAlphaNumeric32(s string) bool {
	return regexp.MustCompile("^[a-zA-Z0-9]{32}$").MatchString(s)
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
