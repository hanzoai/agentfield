package client

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// DID Authentication header names
const (
	HeaderCallerDID    = "X-Caller-DID"
	HeaderDIDSignature = "X-DID-Signature"
	HeaderDIDTimestamp = "X-DID-Timestamp"
)

// DIDAuthenticator handles DID authentication for agent requests.
type DIDAuthenticator struct {
	did        string
	privateKey ed25519.PrivateKey
}

// NewDIDAuthenticator creates a new DID authenticator.
func NewDIDAuthenticator(did string, privateKeyJWK string) (*DIDAuthenticator, error) {
	if did == "" || privateKeyJWK == "" {
		return nil, nil // Return nil authenticator if credentials not provided
	}

	privateKey, err := parsePrivateKeyJWK(privateKeyJWK)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return &DIDAuthenticator{
		did:        did,
		privateKey: privateKey,
	}, nil
}

// IsConfigured returns true if DID authentication is configured.
func (a *DIDAuthenticator) IsConfigured() bool {
	return a != nil && a.did != "" && a.privateKey != nil
}

// DID returns the configured DID identifier.
func (a *DIDAuthenticator) DID() string {
	if a == nil {
		return ""
	}
	return a.did
}

// SignRequest creates DID authentication headers for a request body.
func (a *DIDAuthenticator) SignRequest(body []byte) map[string]string {
	if !a.IsConfigured() {
		return nil
	}

	// Get current timestamp
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Hash the body
	bodyHash := sha256.Sum256(body)

	// Create payload: "{timestamp}:{body_hash}"
	payload := fmt.Sprintf("%s:%x", timestamp, bodyHash)

	// Sign the payload
	signature := ed25519.Sign(a.privateKey, []byte(payload))

	// Encode signature as base64
	signatureB64 := base64.StdEncoding.EncodeToString(signature)

	return map[string]string{
		HeaderCallerDID:    a.did,
		HeaderDIDSignature: signatureB64,
		HeaderDIDTimestamp: timestamp,
	}
}

// jwk represents a JSON Web Key for Ed25519.
type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	D   string `json:"d"`
	X   string `json:"x"`
}

// parsePrivateKeyJWK parses an Ed25519 private key from JWK format.
func parsePrivateKeyJWK(jwkJSON string) (ed25519.PrivateKey, error) {
	var key jwk
	if err := json.Unmarshal([]byte(jwkJSON), &key); err != nil {
		return nil, fmt.Errorf("invalid JWK format: %w", err)
	}

	// Verify key type
	if key.Kty != "OKP" || key.Crv != "Ed25519" {
		return nil, fmt.Errorf("invalid key type: expected Ed25519 OKP key")
	}

	if key.D == "" {
		return nil, fmt.Errorf("missing 'd' (private key) in JWK")
	}

	// Decode base64url-encoded private key
	privateKeyBytes, err := base64.RawURLEncoding.DecodeString(key.D)
	if err != nil {
		return nil, fmt.Errorf("invalid private key encoding: %w", err)
	}

	// Ed25519 seed is 32 bytes
	if len(privateKeyBytes) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid private key length: expected %d bytes, got %d", ed25519.SeedSize, len(privateKeyBytes))
	}

	return ed25519.NewKeyFromSeed(privateKeyBytes), nil
}
