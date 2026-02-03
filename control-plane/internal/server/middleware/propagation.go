package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

// Headers for key propagation through workflow
const (
	HeaderAPIKeyID        = "X-AgentField-Key-ID"
	HeaderAPIKeyName      = "X-AgentField-Key-Name"
	HeaderAPIKeyScopes    = "X-AgentField-Key-Scopes" // JSON-encoded []string
	HeaderAPIKeySignature = "X-AgentField-Key-Sig"    // HMAC-SHA256 signature
	HeaderAPIKeyTimestamp = "X-AgentField-Key-TS"     // Timestamp for replay prevention
)

// DefaultPropagationMaxAge is the default max age for signed headers (prevents replay attacks)
const DefaultPropagationMaxAge = 5 * time.Minute

// PropagateKeyContext adds signed key context headers to outbound requests.
// This is called by the control plane when forwarding requests to agents.
func PropagateKeyContext(c *gin.Context, req *http.Request, secret []byte) {
	keyID := GetKeyID(c)
	keyName := GetKeyName(c)
	scopes := GetKeyScopes(c)

	if keyID == "" {
		return
	}

	// Set basic headers
	req.Header.Set(HeaderAPIKeyID, keyID)
	req.Header.Set(HeaderAPIKeyName, keyName)
	scopesJSON, _ := json.Marshal(scopes)
	req.Header.Set(HeaderAPIKeyScopes, string(scopesJSON))

	// Sign the key context
	timestamp := time.Now().UTC().Format(time.RFC3339)
	signature := signKeyContext(keyID, keyName, scopes, timestamp, secret)
	req.Header.Set(HeaderAPIKeyTimestamp, timestamp)
	req.Header.Set(HeaderAPIKeySignature, signature)
}

// PropagateKeyContextFromValues adds signed key context headers using explicit values.
// This is useful when key context is not available in gin.Context.
func PropagateKeyContextFromValues(req *http.Request, keyID, keyName string, scopes []string, secret []byte) {
	if keyID == "" {
		return
	}

	// Set basic headers
	req.Header.Set(HeaderAPIKeyID, keyID)
	req.Header.Set(HeaderAPIKeyName, keyName)
	scopesJSON, _ := json.Marshal(scopes)
	req.Header.Set(HeaderAPIKeyScopes, string(scopesJSON))

	// Sign the key context
	timestamp := time.Now().UTC().Format(time.RFC3339)
	signature := signKeyContext(keyID, keyName, scopes, timestamp, secret)
	req.Header.Set(HeaderAPIKeyTimestamp, timestamp)
	req.Header.Set(HeaderAPIKeySignature, signature)
}

// signKeyContext creates an HMAC-SHA256 signature of the key context.
func signKeyContext(keyID, keyName string, scopes []string, timestamp string, secret []byte) string {
	payload := fmt.Sprintf("%s|%s|%s|%s", keyID, keyName, strings.Join(scopes, ","), timestamp)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyAndExtractPropagatedKey extracts and verifies key context from headers.
// Returns an error if signature is invalid or timestamp is too old.
// Returns empty keyID if no propagation headers are present (not an error).
func VerifyAndExtractPropagatedKey(c *gin.Context, secret []byte, maxAge time.Duration) (keyID, keyName string, scopes []string, err error) {
	keyID = c.GetHeader(HeaderAPIKeyID)
	if keyID == "" {
		return "", "", nil, nil // No propagated context - not an error
	}

	keyName = c.GetHeader(HeaderAPIKeyName)
	timestamp := c.GetHeader(HeaderAPIKeyTimestamp)
	signature := c.GetHeader(HeaderAPIKeySignature)

	// All propagation headers must be present if any are
	if timestamp == "" || signature == "" {
		return "", "", nil, fmt.Errorf("incomplete propagation headers")
	}

	// Validate timestamp (prevent replay attacks)
	ts, parseErr := time.Parse(time.RFC3339, timestamp)
	if parseErr != nil {
		return "", "", nil, fmt.Errorf("invalid propagation timestamp")
	}
	if time.Since(ts) > maxAge {
		return "", "", nil, fmt.Errorf("propagation headers expired")
	}
	// Also check for future timestamps (clock skew tolerance of 1 minute)
	if ts.After(time.Now().Add(time.Minute)) {
		return "", "", nil, fmt.Errorf("propagation timestamp in future")
	}

	// Extract scopes
	if scopesJSON := c.GetHeader(HeaderAPIKeyScopes); scopesJSON != "" {
		if err := json.Unmarshal([]byte(scopesJSON), &scopes); err != nil {
			return "", "", nil, fmt.Errorf("invalid scopes format")
		}
	}

	// Verify signature
	expectedSig := signKeyContext(keyID, keyName, scopes, timestamp, secret)
	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return "", "", nil, fmt.Errorf("invalid propagation signature")
	}

	return keyID, keyName, scopes, nil
}

// VerifyAndExtractPropagatedKeyFromRequest extracts and verifies key context from http.Request headers.
// This is useful for non-gin contexts.
func VerifyAndExtractPropagatedKeyFromRequest(req *http.Request, secret []byte, maxAge time.Duration) (keyID, keyName string, scopes []string, err error) {
	keyID = req.Header.Get(HeaderAPIKeyID)
	if keyID == "" {
		return "", "", nil, nil // No propagated context - not an error
	}

	keyName = req.Header.Get(HeaderAPIKeyName)
	timestamp := req.Header.Get(HeaderAPIKeyTimestamp)
	signature := req.Header.Get(HeaderAPIKeySignature)

	// All propagation headers must be present if any are
	if timestamp == "" || signature == "" {
		return "", "", nil, fmt.Errorf("incomplete propagation headers")
	}

	// Validate timestamp (prevent replay attacks)
	ts, parseErr := time.Parse(time.RFC3339, timestamp)
	if parseErr != nil {
		return "", "", nil, fmt.Errorf("invalid propagation timestamp")
	}
	if time.Since(ts) > maxAge {
		return "", "", nil, fmt.Errorf("propagation headers expired")
	}
	// Also check for future timestamps (clock skew tolerance of 1 minute)
	if ts.After(time.Now().Add(time.Minute)) {
		return "", "", nil, fmt.Errorf("propagation timestamp in future")
	}

	// Extract scopes
	if scopesJSON := req.Header.Get(HeaderAPIKeyScopes); scopesJSON != "" {
		if err := json.Unmarshal([]byte(scopesJSON), &scopes); err != nil {
			return "", "", nil, fmt.Errorf("invalid scopes format")
		}
	}

	// Verify signature
	expectedSig := signKeyContext(keyID, keyName, scopes, timestamp, secret)
	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return "", "", nil, fmt.Errorf("invalid propagation signature")
	}

	return keyID, keyName, scopes, nil
}

// KeyPropagationHeaders returns all propagation header names.
// Useful for SDKs to know which headers to capture and forward.
func KeyPropagationHeaders() []string {
	return []string{
		HeaderAPIKeyID,
		HeaderAPIKeyName,
		HeaderAPIKeyScopes,
		HeaderAPIKeySignature,
		HeaderAPIKeyTimestamp,
	}
}

// CopyPropagationHeaders copies propagation headers from one request to another.
// This is used by agents to forward key context on subsequent calls.
func CopyPropagationHeaders(src, dst *http.Request) {
	for _, header := range KeyPropagationHeaders() {
		if val := src.Header.Get(header); val != "" {
			dst.Header.Set(header, val)
		}
	}
}
