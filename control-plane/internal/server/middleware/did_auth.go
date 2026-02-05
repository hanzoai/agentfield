package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

// DIDWebServiceInterface defines the methods required for DID verification.
// This interface allows the middleware to work with any DID service implementation.
type DIDWebServiceInterface interface {
	VerifyDIDOwnership(ctx context.Context, did string, message []byte, signature []byte) (bool, error)
}

// DIDAuthConfig holds configuration for DID authentication middleware.
type DIDAuthConfig struct {
	// Enabled determines if DID authentication is active
	Enabled bool
	// TimestampWindowSeconds is the allowed time drift for signature timestamps (default: 300)
	TimestampWindowSeconds int64
	// SkipPaths are paths that bypass DID authentication
	SkipPaths []string
}

// ContextKey is the type for context keys used by this middleware.
type ContextKey string

const (
	// VerifiedCallerDIDKey is the context key for the verified caller DID.
	VerifiedCallerDIDKey ContextKey = "verified_caller_did"
	// DIDAuthSkippedKey is set when DID auth was skipped (no DID claimed).
	DIDAuthSkippedKey ContextKey = "did_auth_skipped"
)

// DIDAuthMiddleware creates a gin middleware that verifies DID-based authentication.
//
// The middleware extracts X-Caller-DID, X-DID-Signature, and X-DID-Timestamp headers
// from incoming requests. If a caller DID is present, it verifies the signature
// against the caller's DID document public key.
//
// Authentication flow:
//  1. If no X-Caller-DID header is present, the request proceeds without DID auth
//  2. If X-Caller-DID is present, X-DID-Signature and X-DID-Timestamp are required
//  3. The timestamp must be within the configured time window (default: 5 minutes)
//  4. The signature is verified against: timestamp + ":" + SHA256(body)
//  5. On successful verification, the verified DID is stored in the gin context
//
// This middleware should be applied AFTER API key authentication and BEFORE
// routes that need to know the caller's identity.
func DIDAuthMiddleware(didService DIDWebServiceInterface, config DIDAuthConfig) gin.HandlerFunc {
	// Set defaults
	if config.TimestampWindowSeconds <= 0 {
		config.TimestampWindowSeconds = 300 // 5 minutes
	}

	skipPathSet := make(map[string]struct{}, len(config.SkipPaths))
	for _, p := range config.SkipPaths {
		skipPathSet[p] = struct{}{}
	}

	return func(c *gin.Context) {
		// Skip if DID auth is disabled
		if !config.Enabled {
			c.Set(string(DIDAuthSkippedKey), true)
			c.Next()
			return
		}

		// Skip explicit paths
		if _, ok := skipPathSet[c.Request.URL.Path]; ok {
			c.Set(string(DIDAuthSkippedKey), true)
			c.Next()
			return
		}

		// Extract headers
		callerDID := c.GetHeader("X-Caller-DID")
		signature := c.GetHeader("X-DID-Signature")
		timestamp := c.GetHeader("X-DID-Timestamp")

		// If no DID claimed, proceed without DID auth
		// This allows unauthenticated requests when DID is optional
		if callerDID == "" {
			c.Set(string(DIDAuthSkippedKey), true)
			c.Next()
			return
		}

		// DID claimed - signature and timestamp are now required
		if signature == "" || timestamp == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "did_auth_required",
				"message": "DID claimed but signature or timestamp missing",
				"details": "When X-Caller-DID is provided, X-DID-Signature and X-DID-Timestamp headers are required",
			})
			return
		}

		// Parse and verify timestamp (prevent replay attacks)
		ts, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "invalid_timestamp",
				"message": "X-DID-Timestamp must be a valid Unix timestamp",
			})
			return
		}

		timeDiff := abs(time.Now().Unix() - ts)
		if timeDiff > config.TimestampWindowSeconds {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "timestamp_expired",
				"message": "Timestamp too old or too far in future",
				"details": fmt.Sprintf("Timestamp must be within %d seconds of server time", config.TimestampWindowSeconds),
			})
			return
		}

		// Read and restore request body for signature verification
		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error":   "body_read_error",
				"message": "Failed to read request body",
			})
			return
		}
		// Restore body for downstream handlers
		c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))

		// Build verification payload: timestamp:SHA256(body)
		bodyHash := sha256.Sum256(bodyBytes)
		payload := fmt.Sprintf("%s:%x", timestamp, bodyHash)

		// Decode base64 signature
		sigBytes, err := base64.StdEncoding.DecodeString(signature)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "invalid_signature_encoding",
				"message": "X-DID-Signature must be valid base64",
			})
			return
		}

		// Verify signature against DID document
		valid, err := didService.VerifyDIDOwnership(
			c.Request.Context(),
			callerDID,
			[]byte(payload),
			sigBytes,
		)

		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "verification_error",
				"message": "Failed to verify DID signature",
				"details": err.Error(),
			})
			return
		}

		if !valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "invalid_signature",
				"message": "DID signature verification failed",
				"details": "The signature does not match the claimed DID's public key",
			})
			return
		}

		// DID verified successfully - store in context
		c.Set(string(VerifiedCallerDIDKey), callerDID)
		c.Next()
	}
}

// GetVerifiedCallerDID extracts the verified caller DID from the gin context.
// Returns empty string if no verified DID is present.
func GetVerifiedCallerDID(c *gin.Context) string {
	if did, exists := c.Get(string(VerifiedCallerDIDKey)); exists {
		if didStr, ok := did.(string); ok {
			return didStr
		}
	}
	return ""
}

// IsDIDAuthSkipped returns true if DID authentication was skipped for this request.
func IsDIDAuthSkipped(c *gin.Context) bool {
	if skipped, exists := c.Get(string(DIDAuthSkippedKey)); exists {
		if skippedBool, ok := skipped.(bool); ok {
			return skippedBool
		}
	}
	return false
}

// abs returns the absolute value of an int64.
func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
