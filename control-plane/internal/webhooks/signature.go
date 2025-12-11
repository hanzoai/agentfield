package webhooks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

// ComputeSignature returns the canonical signature string for the given inputs.
// Signature format: sha256=<hex>
func ComputeSignature(secret, timestamp string, body []byte) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("secret is required for signature")
	}
	if strings.TrimSpace(timestamp) == "" {
		return "", fmt.Errorf("timestamp is required for signature")
	}
	payload := timestamp + "." + string(body)
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(payload))
	return "sha256=" + hex.EncodeToString(mac.Sum(nil)), nil
}

// ValidateSignature checks the incoming signature against the expected value.
func ValidateSignature(secret, signature, timestamp string, body []byte) bool {
	if secret == "" || strings.TrimSpace(signature) == "" || strings.TrimSpace(timestamp) == "" {
		return false
	}

	expected, err := ComputeSignature(secret, timestamp, body)
	if err != nil {
		return false
	}

	return hmac.Equal([]byte(expected), []byte(signature))
}
