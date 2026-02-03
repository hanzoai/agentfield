# Policy Engine Implementation Guide

**Version:** 1.0
**Status:** Draft
**Date:** January 2025

This document provides detailed implementation guidance for the tag-based access control system described in [POLICY_ENGINE_PRD.md](./POLICY_ENGINE_PRD.md).

---

## Table of Contents

1. [Overview](#overview)
2. [File Structure](#file-structure)
3. [Phase 1: Core Infrastructure](#phase-1-core-infrastructure)
4. [Phase 2: Auth Middleware](#phase-2-auth-middleware)
5. [Phase 3: Enforcement](#phase-3-enforcement)
6. [Phase 4: Admin API](#phase-4-admin-api)
7. [Testing Strategy](#testing-strategy)
8. [Migration Guide](#migration-guide)

---

## Overview

### Architecture Summary

```
Request Flow:
┌──────────────────────────────────────────────────────────────────────┐
│  HTTP Request                                                         │
│  Header: X-API-Key: sk_finance_xxx                                   │
└──────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Auth Middleware (middleware/auth.go)                                 │
│                                                                       │
│  1. Extract key from header/bearer/query                             │
│  2. Look up key in storage → get APIKey struct                       │
│  3. Verify key hash                                                  │
│  4. Check expiration                                                 │
│  5. Attach scopes to gin.Context                                     │
│                                                                       │
│  c.Set("api_key_scopes", key.Scopes)                                 │
│  c.Set("api_key_id", key.ID)                                         │
│  c.Set("api_key_name", key.Name)                                     │
└──────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────┐
│  Handler (handlers/execute.go, handlers/discovery.go)                │
│                                                                       │
│  1. Get scopes from context                                          │
│  2. Get target agent tags                                            │
│  3. Call accessControl.CanAccess(scopes, tags)                       │
│  4. If denied → return 403                                           │
│  5. If allowed → proceed                                             │
└──────────────────────────────────────────────────────────────────────┘
```

---

## File Structure

```
control-plane/
├── internal/
│   ├── config/
│   │   └── config.go                    # MODIFY: Add APIKeyConfig
│   ├── server/
│   │   ├── middleware/
│   │   │   ├── auth.go                  # MODIFY: Multi-key support
│   │   │   └── scopes.go                # NEW: Scope helpers
│   │   └── routes.go                    # MODIFY: Add admin routes
│   ├── handlers/
│   │   ├── execute.go                   # MODIFY: Add permission check
│   │   ├── discovery.go                 # MODIFY: Add permission filter
│   │   ├── memory.go                    # MODIFY: Add permission check
│   │   └── admin/
│   │       └── keys.go                  # NEW: Key management endpoints
│   ├── services/
│   │   └── access_control.go            # NEW: Access control logic
│   └── storage/
│       ├── api_keys.go                  # NEW: API key storage
│       └── api_keys_test.go             # NEW: Storage tests
├── pkg/
│   └── types/
│       └── api_key.go                   # NEW: APIKey type
└── migrations/
    ├── 018_create_api_keys.sql          # NEW: API keys table
    └── 019_create_access_audit_log.sql  # NEW: Audit log table
```

---

## Phase 1: Core Infrastructure

### 1.1 API Key Types

**File:** `control-plane/pkg/types/api_key.go`

```go
package types

import (
	"strings"
	"time"
)

// APIKey represents an authentication key with optional scope restrictions.
type APIKey struct {
	ID          string     `json:"id" db:"id"`
	Name        string     `json:"name" db:"name"`
	KeyHash     string     `json:"-" db:"key_hash"` // bcrypt hash, never exposed in JSON

	// Scopes define what tags this key can access.
	// Empty slice or ["*"] = super key (full access)
	// ["finance", "shared"] = individual tags
	// ["finance*"] = wildcard prefix matching
	// ["@payment-workflow"] = scope group reference (expanded at runtime)
	Scopes      []string   `json:"scopes" db:"scopes"`

	// ExpandedScopes is populated at runtime after resolving @group references
	ExpandedScopes []string `json:"-" db:"-"`

	// Metadata
	Description string     `json:"description,omitempty" db:"description"`
	Enabled     bool       `json:"enabled" db:"enabled"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty" db:"last_used_at"`
}

// ScopeGroup defines a named group of tags for workflow-level access.
type ScopeGroup struct {
	Name        string   `json:"name" yaml:"name"`
	Tags        []string `json:"tags" yaml:"tags"`
	Description string   `json:"description,omitempty" yaml:"description,omitempty"`
}

// IsSuperKey returns true if this key has unrestricted access.
func (k *APIKey) IsSuperKey() bool {
	if len(k.Scopes) == 0 {
		return true
	}
	if len(k.Scopes) == 1 && k.Scopes[0] == "*" {
		return true
	}
	return false
}

// IsExpired returns true if the key has expired.
func (k *APIKey) IsExpired() bool {
	if k.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*k.ExpiresAt)
}

// ExpandScopes resolves @group references and populates ExpandedScopes.
func (k *APIKey) ExpandScopes(groups map[string]ScopeGroup) {
	expanded := make([]string, 0)
	for _, scope := range k.Scopes {
		if strings.HasPrefix(scope, "@") {
			groupName := strings.TrimPrefix(scope, "@")
			if group, ok := groups[groupName]; ok {
				expanded = append(expanded, group.Tags...)
			}
		} else {
			expanded = append(expanded, scope)
		}
	}
	k.ExpandedScopes = expanded
}

// GetEffectiveScopes returns expanded scopes if available, otherwise raw scopes.
func (k *APIKey) GetEffectiveScopes() []string {
	if len(k.ExpandedScopes) > 0 {
		return k.ExpandedScopes
	}
	return k.Scopes
}

// CanAccess checks if this key can access an agent with the given tags.
func (k *APIKey) CanAccess(agentTags []string) bool {
	if k.IsSuperKey() {
		return true
	}

	effectiveScopes := k.GetEffectiveScopes()
	for _, scope := range effectiveScopes {
		for _, tag := range agentTags {
			if MatchesTagPattern(scope, tag) {
				return true
			}
		}
	}
	return false
}

// MatchesTagPattern checks if a scope pattern matches a tag.
// Supports:
//   - Exact match: "finance" matches "finance"
//   - Prefix wildcard: "finance*" matches "finance", "finance-internal"
//   - Suffix wildcard: "*-internal" matches "finance-internal", "hr-internal"
//   - Full wildcard: "*" matches anything
func MatchesTagPattern(pattern, tag string) bool {
	if pattern == "*" {
		return true
	}

	// Prefix wildcard: "finance*"
	if strings.HasSuffix(pattern, "*") && !strings.HasPrefix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(tag, prefix)
	}

	// Suffix wildcard: "*-internal"
	if strings.HasPrefix(pattern, "*") && !strings.HasSuffix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(tag, suffix)
	}

	// Exact match
	return pattern == tag
}

// APIKeyCreateRequest represents a request to create a new API key.
type APIKeyCreateRequest struct {
	Name        string     `json:"name" binding:"required"`
	Scopes      []string   `json:"scopes"`
	Description string     `json:"description,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// APIKeyResponse represents an API key in responses (no sensitive data).
type APIKeyResponse struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Scopes      []string   `json:"scopes"`
	Description string     `json:"description,omitempty"`
	Enabled     bool       `json:"enabled"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

// ToResponse converts an APIKey to a safe response format.
func (k *APIKey) ToResponse() APIKeyResponse {
	return APIKeyResponse{
		ID:          k.ID,
		Name:        k.Name,
		Scopes:      k.Scopes,
		Description: k.Description,
		Enabled:     k.Enabled,
		CreatedAt:   k.CreatedAt,
		ExpiresAt:   k.ExpiresAt,
		LastUsedAt:  k.LastUsedAt,
	}
}

// AccessDecision represents the result of an access check.
type AccessDecision struct {
	Allowed    bool     `json:"allowed"`
	KeyScopes  []string `json:"key_scopes"`
	AgentTags  []string `json:"agent_tags"`
	MatchedOn  string   `json:"matched_on,omitempty"`  // Which scope/tag pair matched
	DenyReason string   `json:"deny_reason,omitempty"` // Why access was denied
}

// AccessAuditEntry represents a logged access decision.
type AccessAuditEntry struct {
	ID             int64     `json:"id" db:"id"`
	Timestamp      time.Time `json:"timestamp" db:"timestamp"`
	APIKeyID       string    `json:"api_key_id" db:"api_key_id"`
	APIKeyName     string    `json:"api_key_name" db:"api_key_name"`
	TargetAgent    string    `json:"target_agent" db:"target_agent"`
	TargetReasoner string    `json:"target_reasoner,omitempty" db:"target_reasoner"`
	AgentTags      []string  `json:"agent_tags" db:"agent_tags"`
	KeyScopes      []string  `json:"key_scopes" db:"key_scopes"`
	Allowed        bool      `json:"allowed" db:"allowed"`
	DenyReason     string    `json:"deny_reason,omitempty" db:"deny_reason"`
}
```

### 1.2 Config Changes

**File:** `control-plane/internal/config/config.go`

Add to existing `AuthConfig`:

```go
// AuthConfig holds API authentication configuration.
type AuthConfig struct {
	// Legacy: Single shared API key (backwards compatible)
	// If set and Keys is empty, this becomes a super key named "default"
	APIKey string `yaml:"api_key" mapstructure:"api_key"`

	// SkipPaths allows bypassing auth for specific endpoints
	SkipPaths []string `yaml:"skip_paths" mapstructure:"skip_paths"`

	// ScopeGroups defines named groups of tags for workflow-level access
	ScopeGroups map[string]ScopeGroupConfig `yaml:"scope_groups" mapstructure:"scope_groups"`

	// Keys defines multiple API keys with scoped access
	Keys []APIKeyConfig `yaml:"keys" mapstructure:"keys"`

	// AuditEnabled enables logging of all access decisions
	AuditEnabled bool `yaml:"audit_enabled" mapstructure:"audit_enabled"`
}

// ScopeGroupConfig defines a scope group in configuration.
type ScopeGroupConfig struct {
	Tags        []string `yaml:"tags" mapstructure:"tags"`
	Description string   `yaml:"description,omitempty" mapstructure:"description"`
}

// APIKeyConfig defines an API key in configuration.
type APIKeyConfig struct {
	Name        string     `yaml:"name" mapstructure:"name"`
	Scopes      []string   `yaml:"scopes" mapstructure:"scopes"` // Can include "@group-name"
	Description string     `yaml:"description,omitempty" mapstructure:"description"`
	ExpiresAt   *time.Time `yaml:"expires_at,omitempty" mapstructure:"expires_at"`
}
```

Add to `applyEnvOverrides`:

```go
// API Key environment variable resolution
// Format: AGENTFIELD_API_KEY_<NAME> where NAME is uppercase with - replaced by _
func resolveAPIKeyValues(keys []APIKeyConfig) map[string]string {
	values := make(map[string]string)
	for _, key := range keys {
		envKey := "AGENTFIELD_API_KEY_" + strings.ToUpper(strings.ReplaceAll(key.Name, "-", "_"))
		if val := os.Getenv(envKey); val != "" {
			values[key.Name] = val
		}
	}
	return values
}
```

### 1.3 Database Migration

**File:** `control-plane/migrations/018_create_api_keys.sql`

```sql
-- +goose Up
-- API keys table for scoped access control

CREATE TABLE IF NOT EXISTS api_keys (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    key_hash        TEXT NOT NULL,
    scopes          JSONB NOT NULL DEFAULT '[]',
    description     TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMP WITH TIME ZONE,
    last_used_at    TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_api_keys_name ON api_keys(name);
CREATE INDEX idx_api_keys_enabled ON api_keys(enabled);

-- +goose Down
DROP TABLE IF EXISTS api_keys;
```

**File:** `control-plane/migrations/019_create_access_audit_log.sql`

```sql
-- +goose Up
-- Access audit log for compliance and debugging

CREATE TABLE IF NOT EXISTS access_audit_log (
    id              BIGSERIAL PRIMARY KEY,
    timestamp       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    api_key_id      TEXT NOT NULL,
    api_key_name    TEXT NOT NULL,
    target_agent    TEXT NOT NULL,
    target_reasoner TEXT,
    agent_tags      JSONB NOT NULL DEFAULT '[]',
    key_scopes      JSONB NOT NULL DEFAULT '[]',
    allowed         BOOLEAN NOT NULL,
    deny_reason     TEXT
);

CREATE INDEX idx_access_audit_timestamp ON access_audit_log(timestamp DESC);
CREATE INDEX idx_access_audit_key_id ON access_audit_log(api_key_id);
CREATE INDEX idx_access_audit_allowed ON access_audit_log(allowed);
CREATE INDEX idx_access_audit_target ON access_audit_log(target_agent);

-- +goose Down
DROP TABLE IF EXISTS access_audit_log;
```

### 1.3.1 SQLite Schema (Local Mode)

For local mode, add schema creation in `control-plane/internal/storage/local.go`:

```go
// ensureAPIKeysSchema creates the API keys table for SQLite (local mode)
func (ls *LocalStorage) ensureAPIKeysSchema() error {
	createTable := `
	CREATE TABLE IF NOT EXISTS api_keys (
		id              TEXT PRIMARY KEY,
		name            TEXT NOT NULL UNIQUE,
		key_hash        TEXT NOT NULL,
		scopes          TEXT NOT NULL DEFAULT '[]',
		description     TEXT,
		enabled         INTEGER NOT NULL DEFAULT 1,
		created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
		expires_at      TEXT,
		last_used_at    TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_api_keys_name ON api_keys(name);
	CREATE INDEX IF NOT EXISTS idx_api_keys_enabled ON api_keys(enabled);
	`
	_, err := ls.db.Exec(createTable)
	return err
}

// ensureAccessAuditLogSchema creates the audit log table for SQLite
func (ls *LocalStorage) ensureAccessAuditLogSchema() error {
	createTable := `
	CREATE TABLE IF NOT EXISTS access_audit_log (
		id              INTEGER PRIMARY KEY AUTOINCREMENT,
		timestamp       TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
		api_key_id      TEXT NOT NULL,
		api_key_name    TEXT NOT NULL,
		target_agent    TEXT NOT NULL,
		target_reasoner TEXT,
		agent_tags      TEXT NOT NULL DEFAULT '[]',
		key_scopes      TEXT NOT NULL DEFAULT '[]',
		allowed         INTEGER NOT NULL,
		deny_reason     TEXT
	);
	CREATE INDEX IF NOT EXISTS idx_access_audit_timestamp ON access_audit_log(timestamp);
	CREATE INDEX IF NOT EXISTS idx_access_audit_key_id ON access_audit_log(api_key_id);
	CREATE INDEX IF NOT EXISTS idx_access_audit_allowed ON access_audit_log(allowed);
	`
	_, err := ls.db.Exec(createTable)
	return err
}
```

**Note:** SQLite uses `TEXT` for JSON (stored as string), `INTEGER` for boolean, and `CURRENT_TIMESTAMP` instead of `NOW()`.

### 1.4 API Key Storage

**File:** `control-plane/internal/storage/api_keys.go`

```go
package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
	"golang.org/x/crypto/bcrypt"
)

// APIKeyStorage defines the interface for API key persistence.
type APIKeyStorage interface {
	// CreateKey creates a new API key and returns the plain key value (only returned once)
	CreateKey(ctx context.Context, req types.APIKeyCreateRequest) (*types.APIKey, string, error)

	// GetKeyByID retrieves a key by its ID
	GetKeyByID(ctx context.Context, id string) (*types.APIKey, error)

	// GetKeyByName retrieves a key by its name
	GetKeyByName(ctx context.Context, name string) (*types.APIKey, error)

	// VerifyKey verifies a plain key and returns the APIKey if valid
	VerifyKey(ctx context.Context, plainKey string) (*types.APIKey, error)

	// ListKeys returns all API keys (without sensitive data)
	ListKeys(ctx context.Context) ([]*types.APIKey, error)

	// UpdateKeyLastUsed updates the last_used_at timestamp
	UpdateKeyLastUsed(ctx context.Context, id string) error

	// DeleteKey removes an API key
	DeleteKey(ctx context.Context, id string) error

	// DisableKey disables an API key
	DisableKey(ctx context.Context, id string) error

	// EnableKey enables an API key
	EnableKey(ctx context.Context, id string) error
}

// GenerateAPIKey generates a new random API key with prefix.
func GenerateAPIKey(prefix string) (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(bytes), nil
}

// HashAPIKey creates a bcrypt hash of an API key.
func HashAPIKey(plainKey string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plainKey), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// VerifyAPIKeyHash verifies a plain key against a bcrypt hash.
func VerifyAPIKeyHash(plainKey, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plainKey)) == nil
}

// GenerateKeyID generates a unique key ID.
func GenerateKeyID() string {
	bytes := make([]byte, 8)
	rand.Read(bytes)
	return "key_" + hex.EncodeToString(bytes)
}
```

---

## Phase 2: Auth Middleware

### 2.1 Multi-Key Auth Middleware

**File:** `control-plane/internal/server/middleware/auth.go`

Replace the existing implementation:

```go
package middleware

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/Agent-Field/agentfield/control-plane/internal/storage"
	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
)

// AuthConfig holds configuration for the auth middleware.
type AuthConfig struct {
	// LegacyAPIKey is the single shared key (backwards compatible)
	LegacyAPIKey string

	// SkipPaths are paths that bypass authentication
	SkipPaths []string

	// KeyStorage provides API key lookup
	KeyStorage storage.APIKeyStorage

	// KeyCache caches verified keys to avoid repeated DB lookups
	keyCache     map[string]*types.APIKey
	keyCacheMu   sync.RWMutex
	keyCacheTTL  time.Duration
}

// Context keys for storing auth info
const (
	ContextKeyScopes  = "api_key_scopes"
	ContextKeyID      = "api_key_id"
	ContextKeyName    = "api_key_name"
	ContextIsSuperKey = "api_key_is_super"
)

// APIKeyAuth creates the authentication middleware.
func APIKeyAuth(config AuthConfig) gin.HandlerFunc {
	skipPathSet := make(map[string]struct{}, len(config.SkipPaths))
	for _, p := range config.SkipPaths {
		skipPathSet[p] = struct{}{}
	}

	// Initialize cache
	if config.keyCache == nil {
		config.keyCache = make(map[string]*types.APIKey)
	}
	if config.keyCacheTTL == 0 {
		config.keyCacheTTL = 5 * time.Minute
	}

	return func(c *gin.Context) {
		// No auth configured - allow everything (development mode)
		if config.LegacyAPIKey == "" && config.KeyStorage == nil {
			// Set super key context for handlers
			c.Set(ContextKeyScopes, []string{"*"})
			c.Set(ContextIsSuperKey, true)
			c.Next()
			return
		}

		// Skip explicit paths
		if _, ok := skipPathSet[c.Request.URL.Path]; ok {
			c.Set(ContextKeyScopes, []string{"*"})
			c.Set(ContextIsSuperKey, true)
			c.Next()
			return
		}

		// Always allow health, metrics, and UI
		path := c.Request.URL.Path
		if strings.HasPrefix(path, "/api/v1/health") ||
			path == "/health" ||
			path == "/metrics" ||
			strings.HasPrefix(path, "/ui") ||
			path == "/" {
			c.Set(ContextKeyScopes, []string{"*"})
			c.Set(ContextIsSuperKey, true)
			c.Next()
			return
		}

		// Extract API key from request
		apiKey := extractAPIKey(c)
		if apiKey == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "missing API key",
			})
			return
		}

		// Try legacy single key first (backwards compatibility)
		if config.LegacyAPIKey != "" && apiKey == config.LegacyAPIKey {
			c.Set(ContextKeyScopes, []string{"*"})
			c.Set(ContextKeyID, "legacy")
			c.Set(ContextKeyName, "default")
			c.Set(ContextIsSuperKey, true)
			c.Next()
			return
		}

		// Look up key in storage
		if config.KeyStorage != nil {
			key, err := config.KeyStorage.VerifyKey(c.Request.Context(), apiKey)
			if err == nil && key != nil {
				// Check if key is enabled
				if !key.Enabled {
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
						"error":   "unauthorized",
						"message": "API key is disabled",
					})
					return
				}

				// Check expiration
				if key.IsExpired() {
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
						"error":   "unauthorized",
						"message": "API key has expired",
					})
					return
				}

				// Update last used (async, don't block request)
				go config.KeyStorage.UpdateKeyLastUsed(c.Request.Context(), key.ID)

				// Set context values
				c.Set(ContextKeyScopes, key.Scopes)
				c.Set(ContextKeyID, key.ID)
				c.Set(ContextKeyName, key.Name)
				c.Set(ContextIsSuperKey, key.IsSuperKey())
				c.Next()
				return
			}
		}

		// Invalid key
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error":   "unauthorized",
			"message": "invalid API key",
		})
	}
}

// extractAPIKey extracts the API key from the request.
func extractAPIKey(c *gin.Context) string {
	// Preferred: X-API-Key header
	if key := c.GetHeader("X-API-Key"); key != "" {
		return key
	}

	// Fallback: Authorization: Bearer <token>
	if auth := c.GetHeader("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	// SSE/WebSocket: api_key query parameter
	if key := c.Query("api_key"); key != "" {
		return key
	}

	return ""
}

// GetKeyScopes retrieves the API key scopes from the gin context.
func GetKeyScopes(c *gin.Context) []string {
	if scopes, exists := c.Get(ContextKeyScopes); exists {
		if s, ok := scopes.([]string); ok {
			return s
		}
	}
	return nil
}

// GetKeyID retrieves the API key ID from the gin context.
func GetKeyID(c *gin.Context) string {
	if id, exists := c.Get(ContextKeyID); exists {
		if s, ok := id.(string); ok {
			return s
		}
	}
	return ""
}

// GetKeyName retrieves the API key name from the gin context.
func GetKeyName(c *gin.Context) string {
	if name, exists := c.Get(ContextKeyName); exists {
		if s, ok := name.(string); ok {
			return s
		}
	}
	return ""
}

// IsSuperKey returns true if the current request is using a super key.
func IsSuperKey(c *gin.Context) bool {
	if isSuper, exists := c.Get(ContextIsSuperKey); exists {
		if b, ok := isSuper.(bool); ok {
			return b
		}
	}
	return false
}
```

### 2.2 Key Propagation with Signature Verification

When the control plane forwards requests to agents, and when agents make calls back to the control plane, the API key context must be propagated **with cryptographic verification** to prevent forgery.

**File:** `control-plane/internal/server/middleware/propagation.go`

```go
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

// Default max age for signed headers (prevents replay attacks)
const DefaultPropagationMaxAge = 5 * time.Minute

// PropagateKeyContext adds signed key context headers to outbound requests.
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

// signKeyContext creates an HMAC-SHA256 signature of the key context.
func signKeyContext(keyID, keyName string, scopes []string, timestamp string, secret []byte) string {
	payload := fmt.Sprintf("%s|%s|%s|%s", keyID, keyName, strings.Join(scopes, ","), timestamp)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyAndExtractPropagatedKey extracts and verifies key context from headers.
// Returns an error if signature is invalid or timestamp is too old.
func VerifyAndExtractPropagatedKey(c *gin.Context, secret []byte, maxAge time.Duration) (keyID, keyName string, scopes []string, err error) {
	keyID = c.GetHeader(HeaderAPIKeyID)
	if keyID == "" {
		return "", "", nil, nil // No propagated context
	}

	keyName = c.GetHeader(HeaderAPIKeyName)
	timestamp := c.GetHeader(HeaderAPIKeyTimestamp)
	signature := c.GetHeader(HeaderAPIKeySignature)

	// Validate timestamp (prevent replay attacks)
	ts, parseErr := time.Parse(time.RFC3339, timestamp)
	if parseErr != nil {
		return "", "", nil, fmt.Errorf("invalid propagation timestamp")
	}
	if time.Since(ts) > maxAge {
		return "", "", nil, fmt.Errorf("propagation headers expired")
	}

	// Extract scopes
	if scopesJSON := c.GetHeader(HeaderAPIKeyScopes); scopesJSON != "" {
		json.Unmarshal([]byte(scopesJSON), &scopes)
	}

	// Verify signature
	expectedSig := signKeyContext(keyID, keyName, scopes, timestamp, secret)
	if !hmac.Equal([]byte(signature), []byte(expectedSig)) {
		return "", "", nil, fmt.Errorf("invalid propagation signature")
	}

	return keyID, keyName, scopes, nil
}
```

**Updated Auth Middleware** - Verify signature before trusting propagated headers:

```go
// In APIKeyAuth middleware, before looking up the key:

// Check for propagated key context (internal agent-to-agent calls)
// IMPORTANT: Always verify signature to prevent forgery
keyID, keyName, scopes, err := VerifyAndExtractPropagatedKey(c, config.PropagationSecret, DefaultPropagationMaxAge)
if err != nil {
	// Invalid/expired signature - reject the request
	c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
		"error":   "unauthorized",
		"message": "invalid key propagation: " + err.Error(),
	})
	return
}
if keyID != "" {
	// Valid signed propagation - trust the context
	c.Set(ContextKeyScopes, scopes)
	c.Set(ContextKeyID, keyID)
	c.Set(ContextKeyName, keyName)
	c.Set(ContextIsSuperKey, isSuperKeyScopes(scopes))
	c.Next()
	return
}
```

**Config addition for propagation secret:**

```go
// In AuthConfig struct
type AuthConfig struct {
	// ... existing fields ...

	// PropagationSecret is used to sign key context headers.
	// If empty, a random secret is generated at startup.
	PropagationSecret string `yaml:"propagation_secret" mapstructure:"propagation_secret"`
}

// In applyEnvOverrides
if secret := os.Getenv("AGENTFIELD_KEY_PROPAGATION_SECRET"); secret != "" {
	cfg.API.Auth.PropagationSecret = secret
}
```

---

## Phase 3: Enforcement

### 3.1 Access Control Service

**File:** `control-plane/internal/services/access_control.go`

```go
package services

import (
	"context"
	"strings"

	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
)

// AccessControlService handles access control decisions.
type AccessControlService struct {
	auditEnabled bool
	auditStorage AccessAuditStorage
}

// AccessAuditStorage defines the interface for audit logging.
type AccessAuditStorage interface {
	LogAccessDecision(ctx context.Context, entry types.AccessAuditEntry) error
}

// NewAccessControlService creates a new access control service.
func NewAccessControlService(auditEnabled bool, auditStorage AccessAuditStorage) *AccessControlService {
	return &AccessControlService{
		auditEnabled: auditEnabled,
		auditStorage: auditStorage,
	}
}

// CheckAccess verifies if the given scopes can access an agent with the given tags.
func (s *AccessControlService) CheckAccess(
	ctx context.Context,
	keyID, keyName string,
	keyScopes []string,
	targetAgent string,
	targetReasoner string,
	agentTags []string,
) types.AccessDecision {
	decision := types.AccessDecision{
		KeyScopes: keyScopes,
		AgentTags: agentTags,
	}

	// Super key check
	if isSuperKeyScopes(keyScopes) {
		decision.Allowed = true
		decision.MatchedOn = "*"
		return decision
	}

	// Check for any matching scope/tag pair
	for _, scope := range keyScopes {
		for _, tag := range agentTags {
			if types.MatchesTagPattern(scope, tag) {
				decision.Allowed = true
				decision.MatchedOn = scope + " -> " + tag
				s.logDecision(ctx, keyID, keyName, targetAgent, targetReasoner, decision)
				return decision
			}
		}
	}

	// No match found
	decision.Allowed = false
	decision.DenyReason = "no matching tags"
	s.logDecision(ctx, keyID, keyName, targetAgent, targetReasoner, decision)
	return decision
}

// GetAgentTags extracts all unique tags from an agent's reasoners and skills.
func GetAgentTags(agent *types.AgentNode) []string {
	tagSet := make(map[string]struct{})

	for _, r := range agent.Reasoners {
		for _, t := range r.Tags {
			tagSet[t] = struct{}{}
		}
	}
	for _, s := range agent.Skills {
		for _, t := range s.Tags {
			tagSet[t] = struct{}{}
		}
	}

	tags := make([]string, 0, len(tagSet))
	for t := range tagSet {
		tags = append(tags, t)
	}
	return tags
}

// FilterAgentsByAccess filters a list of agents to only those accessible by the given scopes.
func (s *AccessControlService) FilterAgentsByAccess(
	agents []*types.AgentNode,
	keyScopes []string,
) []*types.AgentNode {
	// Super key sees everything
	if isSuperKeyScopes(keyScopes) {
		return agents
	}

	permitted := make([]*types.AgentNode, 0)
	for _, agent := range agents {
		agentTags := GetAgentTags(agent)
		if canAccessWithScopes(keyScopes, agentTags) {
			permitted = append(permitted, agent)
		}
	}
	return permitted
}

// isSuperKeyScopes returns true if the scopes represent a super key.
func isSuperKeyScopes(scopes []string) bool {
	if len(scopes) == 0 {
		return true
	}
	if len(scopes) == 1 && scopes[0] == "*" {
		return true
	}
	return false
}

// canAccessWithScopes checks if scopes can access agent tags.
func canAccessWithScopes(scopes, agentTags []string) bool {
	if isSuperKeyScopes(scopes) {
		return true
	}

	for _, scope := range scopes {
		for _, tag := range agentTags {
			if types.MatchesTagPattern(scope, tag) {
				return true
			}
		}
	}
	return false
}

// logDecision logs an access decision if audit is enabled.
func (s *AccessControlService) logDecision(
	ctx context.Context,
	keyID, keyName, targetAgent, targetReasoner string,
	decision types.AccessDecision,
) {
	if !s.auditEnabled || s.auditStorage == nil {
		return
	}

	entry := types.AccessAuditEntry{
		APIKeyID:       keyID,
		APIKeyName:     keyName,
		TargetAgent:    targetAgent,
		TargetReasoner: targetReasoner,
		AgentTags:      decision.AgentTags,
		KeyScopes:      decision.KeyScopes,
		Allowed:        decision.Allowed,
		DenyReason:     decision.DenyReason,
	}

	// Log async to not block request
	go s.auditStorage.LogAccessDecision(ctx, entry)
}
```

### 3.2 Execute Handler Changes

**File:** `control-plane/internal/handlers/execute.go`

Add to the execute handler (around line 100, after parsing the request):

```go
// Add this import
import (
	"github.com/Agent-Field/agentfield/control-plane/internal/server/middleware"
	"github.com/Agent-Field/agentfield/control-plane/internal/services"
)

// In the Execute function, after resolving the target agent:

func (h *ExecuteHandler) Execute(c *gin.Context) {
	// ... existing code to parse request and resolve target ...

	// Get the target agent
	agent, err := h.storage.GetAgent(ctx, targetAgentID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	// --- ACCESS CONTROL CHECK ---
	// Permission check happens on EVERY call (including internal)
	// The key context is propagated through the workflow
	scopes := middleware.GetKeyScopes(c)
	keyID := middleware.GetKeyID(c)
	keyName := middleware.GetKeyName(c)
	agentTags := services.GetAgentTags(agent)

	decision := h.accessControl.CheckAccess(
		ctx, keyID, keyName, scopes,
		targetAgentID, reasonerID, agentTags,
	)

	if !decision.Allowed {
		c.JSON(http.StatusForbidden, gin.H{
			"error":   "access_denied",
			"message": "API key does not have access to this agent",
			"agent":   targetAgentID,
			"key":     keyName,
			"hint":    "Agent requires one of these tags: " + strings.Join(agentTags, ", "),
		})
		return
	}
	// --- END ACCESS CONTROL CHECK ---

	// --- PROPAGATE KEY CONTEXT TO AGENT ---
	// When forwarding the request to the agent, include key context
	// so the agent can propagate it on subsequent calls
	req := h.buildAgentRequest(ctx, agent, reasonerID, input)
	middleware.PropagateKeyContext(c, req)
	// --- END PROPAGATION ---

	// ... rest of existing execution logic ...
}
```

### 3.3 Discovery Handler Changes

**File:** `control-plane/internal/handlers/discovery.go`

Modify the `DiscoverCapabilities` function:

```go
func (h *DiscoveryHandler) DiscoverCapabilities(c *gin.Context) {
	// ... existing filter parsing ...

	// Get all agents
	agents, err := h.storage.ListAgents(ctx, types.AgentFilters{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// --- LAYER 1: PERMISSION FILTER ---
	scopes := middleware.GetKeyScopes(c)
	agents = h.accessControl.FilterAgentsByAccess(agents, scopes)
	// --- END PERMISSION FILTER ---

	// --- LAYER 2: TAG FILTER (existing) ---
	if len(filters.Tags) > 0 {
		agents = filterAgentsByTags(agents, filters.Tags)
	}
	// --- END TAG FILTER ---

	// ... rest of existing discovery logic ...
}
```

---

## Phase 4: Admin API

### 4.1 Admin Key Handlers

**File:** `control-plane/internal/handlers/admin/keys.go`

```go
package admin

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/Agent-Field/agentfield/control-plane/internal/server/middleware"
	"github.com/Agent-Field/agentfield/control-plane/internal/storage"
	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
)

// KeyHandlers handles API key management endpoints.
type KeyHandlers struct {
	storage storage.APIKeyStorage
}

// NewKeyHandlers creates a new KeyHandlers.
func NewKeyHandlers(storage storage.APIKeyStorage) *KeyHandlers {
	return &KeyHandlers{storage: storage}
}

// RequireSuperKey middleware ensures only super keys can access admin endpoints.
func RequireSuperKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !middleware.IsSuperKey(c) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":   "forbidden",
				"message": "admin endpoints require a super key",
			})
			return
		}
		c.Next()
	}
}

// ListKeys returns all API keys (without sensitive data).
// GET /api/v1/admin/keys
func (h *KeyHandlers) ListKeys(c *gin.Context) {
	keys, err := h.storage.ListKeys(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	responses := make([]types.APIKeyResponse, len(keys))
	for i, k := range keys {
		responses[i] = k.ToResponse()
	}

	c.JSON(http.StatusOK, gin.H{"keys": responses})
}

// CreateKey creates a new API key.
// POST /api/v1/admin/keys
func (h *KeyHandlers) CreateKey(c *gin.Context) {
	var req types.APIKeyCreateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	key, plainKey, err := h.storage.CreateKey(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Return the plain key value only on creation
	c.JSON(http.StatusCreated, gin.H{
		"key":       key.ToResponse(),
		"key_value": plainKey,
		"warning":   "Store this key value securely. It cannot be retrieved again.",
	})
}

// GetKey returns a specific API key.
// GET /api/v1/admin/keys/:id
func (h *KeyHandlers) GetKey(c *gin.Context) {
	id := c.Param("id")

	key, err := h.storage.GetKeyByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "key not found"})
		return
	}

	c.JSON(http.StatusOK, key.ToResponse())
}

// DeleteKey deletes an API key.
// DELETE /api/v1/admin/keys/:id
func (h *KeyHandlers) DeleteKey(c *gin.Context) {
	id := c.Param("id")

	if err := h.storage.DeleteKey(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "key deleted"})
}

// DisableKey disables an API key.
// POST /api/v1/admin/keys/:id/disable
func (h *KeyHandlers) DisableKey(c *gin.Context) {
	id := c.Param("id")

	if err := h.storage.DisableKey(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "key disabled"})
}

// EnableKey enables an API key.
// POST /api/v1/admin/keys/:id/enable
func (h *KeyHandlers) EnableKey(c *gin.Context) {
	id := c.Param("id")

	if err := h.storage.EnableKey(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "key enabled"})
}

// CheckAccess tests if a key can access a specific agent.
// POST /api/v1/admin/keys/check-access
func (h *KeyHandlers) CheckAccess(c *gin.Context) {
	var req struct {
		KeyName     string `json:"key_name" binding:"required"`
		TargetAgent string `json:"target_agent" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get the key
	key, err := h.storage.GetKeyByName(c.Request.Context(), req.KeyName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "key not found"})
		return
	}

	// Get the agent (would need agent storage injected)
	// For now, return the key's scopes for manual verification
	c.JSON(http.StatusOK, gin.H{
		"key_name":   key.Name,
		"key_scopes": key.Scopes,
		"is_super":   key.IsSuperKey(),
	})
}
```

### 4.2 Route Registration

**File:** `control-plane/internal/server/routes.go`

Add admin routes:

```go
// Admin routes (require super key)
admin := v1.Group("/admin")
admin.Use(adminHandlers.RequireSuperKey())
{
	// API Key management
	admin.GET("/keys", keyHandlers.ListKeys)
	admin.POST("/keys", keyHandlers.CreateKey)
	admin.GET("/keys/:id", keyHandlers.GetKey)
	admin.DELETE("/keys/:id", keyHandlers.DeleteKey)
	admin.POST("/keys/:id/disable", keyHandlers.DisableKey)
	admin.POST("/keys/:id/enable", keyHandlers.EnableKey)
	admin.POST("/keys/check-access", keyHandlers.CheckAccess)
}
```

---

## Testing Strategy

### Unit Tests

**File:** `control-plane/pkg/types/api_key_test.go`

```go
package types

import "testing"

func TestMatchesTagPattern(t *testing.T) {
	tests := []struct {
		pattern  string
		tag      string
		expected bool
	}{
		// Exact match
		{"finance", "finance", true},
		{"finance", "hr", false},

		// Prefix wildcard
		{"finance*", "finance", true},
		{"finance*", "finance-internal", true},
		{"finance*", "finance-pci", true},
		{"finance*", "hr", false},

		// Suffix wildcard
		{"*-internal", "finance-internal", true},
		{"*-internal", "hr-internal", true},
		{"*-internal", "finance", false},

		// Full wildcard
		{"*", "anything", true},
		{"*", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"_"+tt.tag, func(t *testing.T) {
			result := MatchesTagPattern(tt.pattern, tt.tag)
			if result != tt.expected {
				t.Errorf("MatchesTagPattern(%q, %q) = %v, want %v",
					tt.pattern, tt.tag, result, tt.expected)
			}
		})
	}
}

func TestAPIKey_CanAccess(t *testing.T) {
	tests := []struct {
		name      string
		scopes    []string
		agentTags []string
		expected  bool
	}{
		{
			name:      "super key with empty scopes",
			scopes:    []string{},
			agentTags: []string{"anything"},
			expected:  true,
		},
		{
			name:      "super key with wildcard",
			scopes:    []string{"*"},
			agentTags: []string{"anything"},
			expected:  true,
		},
		{
			name:      "exact match",
			scopes:    []string{"finance"},
			agentTags: []string{"finance", "internal"},
			expected:  true,
		},
		{
			name:      "no match",
			scopes:    []string{"finance"},
			agentTags: []string{"hr", "internal"},
			expected:  false,
		},
		{
			name:      "pattern match",
			scopes:    []string{"finance*"},
			agentTags: []string{"finance-internal"},
			expected:  true,
		},
		{
			name:      "multiple scopes one match",
			scopes:    []string{"hr", "finance"},
			agentTags: []string{"finance"},
			expected:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &APIKey{Scopes: tt.scopes}
			result := key.CanAccess(tt.agentTags)
			if result != tt.expected {
				t.Errorf("CanAccess() = %v, want %v", result, tt.expected)
			}
		})
	}
}
```

### Integration Tests

**File:** `control-plane/internal/handlers/execute_access_test.go`

```go
package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestExecuteHandler_AccessControl(t *testing.T) {
	// Setup test server with mock storage
	// ...

	tests := []struct {
		name           string
		keyScopes      []string
		agentTags      []string
		expectedStatus int
	}{
		{
			name:           "super key allowed",
			keyScopes:      []string{"*"},
			agentTags:      []string{"admin"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "matching scope allowed",
			keyScopes:      []string{"finance"},
			agentTags:      []string{"finance", "internal"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "no matching scope denied",
			keyScopes:      []string{"hr"},
			agentTags:      []string{"finance", "admin"},
			expectedStatus: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create request with scopes in context
			// Execute handler
			// Assert response status
		})
	}
}
```

---

## SDK Changes for Key Propagation

All SDKs need to capture incoming key context headers and forward them on outbound calls. The headers include signature data that the control plane will verify.

### Headers to Propagate

| Header | Description |
|--------|-------------|
| `X-AgentField-Key-ID` | Key identifier |
| `X-AgentField-Key-Name` | Human-readable key name |
| `X-AgentField-Key-Scopes` | JSON-encoded scopes array |
| `X-AgentField-Key-Sig` | HMAC signature (verified by control plane) |
| `X-AgentField-Key-TS` | Timestamp |

**Important:** SDKs forward all these headers exactly as received. Only the control plane can sign/verify them.

### Python SDK

**File:** `sdk/python/agentfield/agent.py`

```python
import contextvars
import json

# Key context storage (request-scoped)
_key_context: contextvars.ContextVar = contextvars.ContextVar('key_context', default=None)

# Headers to capture and propagate
KEY_PROPAGATION_HEADERS = [
    'X-AgentField-Key-ID',
    'X-AgentField-Key-Name',
    'X-AgentField-Key-Scopes',
    'X-AgentField-Key-Sig',
    'X-AgentField-Key-TS',
]

class Agent:
    async def _handle_reasoner_request(self, request: Request, reasoner_id: str):
        # Capture all key propagation headers
        key_context = {
            header: request.headers.get(header)
            for header in KEY_PROPAGATION_HEADERS
            if request.headers.get(header)
        }
        _key_context.set(key_context)

        # Execute reasoner...
        try:
            result = await self._execute_reasoner(reasoner_id, request)
            return result
        finally:
            _key_context.set(None)

    async def call(self, target: str, input: dict = None, **kwargs):
        """Call another agent's reasoner through the control plane."""
        headers = {}

        # Forward captured key context headers (includes signature)
        key_context = _key_context.get()
        if key_context:
            headers.update(key_context)

        response = await self._http_client.post(
            f"{self.agentfield_url}/api/v1/execute/{target}",
            json={"input": input},
            headers=headers,
        )
        return response.json()
```

### Go SDK

**File:** `sdk/go/agent/agent.go`

```go
package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

// Key propagation headers
var keyPropagationHeaders = []string{
	"X-AgentField-Key-ID",
	"X-AgentField-Key-Name",
	"X-AgentField-Key-Scopes",
	"X-AgentField-Key-Sig",
	"X-AgentField-Key-TS",
}

// KeyContext holds captured propagation headers
type KeyContext struct {
	Headers map[string]string
}

// Agent key context (request-scoped via context.Context)
type keyContextKey struct{}

// WithKeyContext adds key context to a context
func WithKeyContext(ctx context.Context, kc *KeyContext) context.Context {
	return context.WithValue(ctx, keyContextKey{}, kc)
}

// GetKeyContext retrieves key context from a context
func GetKeyContext(ctx context.Context) *KeyContext {
	if kc, ok := ctx.Value(keyContextKey{}).(*KeyContext); ok {
		return kc
	}
	return nil
}

// ExtractKeyContext extracts key context from incoming request headers
func ExtractKeyContext(r *http.Request) *KeyContext {
	kc := &KeyContext{Headers: make(map[string]string)}
	for _, header := range keyPropagationHeaders {
		if val := r.Header.Get(header); val != "" {
			kc.Headers[header] = val
		}
	}
	if len(kc.Headers) == 0 {
		return nil
	}
	return kc
}

// Call makes a request to another agent, propagating key context
func (a *Agent) Call(ctx context.Context, target string, input any) (any, error) {
	req, err := http.NewRequestWithContext(ctx, "POST",
		fmt.Sprintf("%s/api/v1/execute/%s", a.AgentFieldURL, target),
		/* body */)
	if err != nil {
		return nil, err
	}

	// Forward key context headers (includes signature)
	if kc := GetKeyContext(ctx); kc != nil {
		for header, value := range kc.Headers {
			req.Header.Set(header, value)
		}
	}

	// Execute request...
	return a.executeRequest(req)
}
```

### TypeScript SDK

**File:** `sdk/typescript/src/agent/Agent.ts`

```typescript
// Key propagation headers
const KEY_PROPAGATION_HEADERS = [
  'X-AgentField-Key-ID',
  'X-AgentField-Key-Name',
  'X-AgentField-Key-Scopes',
  'X-AgentField-Key-Sig',
  'X-AgentField-Key-TS',
] as const;

type KeyContext = Partial<Record<typeof KEY_PROPAGATION_HEADERS[number], string>>;

// AsyncLocalStorage for request-scoped key context
import { AsyncLocalStorage } from 'node:async_hooks';
const keyContextStorage = new AsyncLocalStorage<KeyContext>();

export class Agent {
  // Extract key context from incoming request
  private extractKeyContext(headers: Record<string, string | undefined>): KeyContext {
    const ctx: KeyContext = {};
    for (const header of KEY_PROPAGATION_HEADERS) {
      const value = headers[header] || headers[header.toLowerCase()];
      if (value) {
        ctx[header] = value;
      }
    }
    return ctx;
  }

  // Handle incoming reasoner request
  async handleReasonerRequest(req: any, reasonerId: string): Promise<any> {
    const keyContext = this.extractKeyContext(req.headers);

    return keyContextStorage.run(keyContext, async () => {
      return this.executeReasoner(reasonerId, req);
    });
  }

  // Call another agent (propagates key context)
  async call<T = any>(target: string, input: any): Promise<T> {
    const headers: Record<string, string> = {};

    // Forward captured key context headers
    const keyContext = keyContextStorage.getStore();
    if (keyContext) {
      for (const [header, value] of Object.entries(keyContext)) {
        if (value) {
          headers[header] = value;
        }
      }
    }

    const res = await this.agentFieldClient.execute(target, input, { headers });
    return res as T;
  }
}
```

**File:** `sdk/typescript/src/client/AgentFieldClient.ts`

```typescript
// Update execute method to accept additional headers
async execute<T = any>(
  target: string,
  input: any,
  options?: {
    headers?: Record<string, string>;
    // ... existing metadata options
  }
): Promise<T> {
  const headers: Record<string, string> = {
    ...this.defaultHeaders,
    ...(options?.headers || {}),
  };

  const res = await this.http.post(
    `/api/v1/execute/${target}`,
    { input },
    { headers }
  );
  return (res.data?.result as T) ?? res.data;
}
```

---

## Migration Guide

### Upgrading from Single API Key

1. **Add key configuration to `agentfield.yaml`:**

```yaml
api:
  auth:
    # Keep existing key as super key
    keys:
      - name: admin
        scopes: ["*"]
        description: "Migrated from legacy single key"
```

2. **Set environment variable:**

```bash
# Use the same key value
export AGENTFIELD_API_KEY_ADMIN="your-existing-key-value"
```

3. **Test access** - All existing workflows should continue working.

4. **Add scoped keys** as needed for different teams/integrations.

### Adding Scoped Keys

1. **Identify access patterns** - Which teams access which agents?

2. **Define scopes** based on agent tags:

```yaml
keys:
  - name: finance-team
    scopes: ["finance", "shared"]

  - name: external-integration
    scopes: ["public"]
```

3. **Update agent tags** to match scopes:

```python
app = Agent(
    node_id="payment-processor",
    tags=["finance", "pci-compliant"]
)
```

4. **Distribute scoped keys** to appropriate teams.

5. **Monitor audit log** for access patterns and adjust.

---

## Checklist

### Phase 1: Core Infrastructure
- [ ] Create `pkg/types/api_key.go` (APIKey, ScopeGroup, pattern matching)
- [ ] Add `Tags []string` field to `AgentNode` struct in `pkg/types/types.go`
- [ ] Update `internal/config/config.go` (AuthConfig with keys, scope_groups, propagation_secret)
- [ ] Create `internal/storage/api_keys.go` (interface + PostgreSQL impl)
- [ ] Create migration `018_create_api_keys.sql` (PostgreSQL)
- [ ] Create migration `019_create_access_audit_log.sql` (PostgreSQL)
- [ ] Add SQLite schema in `internal/storage/local.go` (ensureAPIKeysSchema)
- [ ] Write unit tests for types and pattern matching

### Phase 2: Auth Middleware
- [ ] Update `internal/server/middleware/auth.go` (multi-key lookup)
- [ ] Create `internal/server/middleware/propagation.go` (signature sign/verify)
- [ ] Add scope context helpers (GetKeyID, GetKeyScopes, etc.)
- [ ] Add config validation for scope group references
- [ ] Test backwards compatibility with single `api_key`
- [ ] Test multi-key lookup and expiration

### Phase 3: Enforcement
- [ ] Create `internal/services/access_control.go`
- [ ] Create `internal/services/tag_resolver.go` (GetAgentTags aggregation)
- [ ] Update `internal/handlers/execute.go` (permission check + propagation)
- [ ] Update `internal/handlers/discovery.go` (two-layer filtering)
- [ ] Update `internal/handlers/memory.go` (scope-based protection)
- [ ] Write integration tests for access control

### Phase 4: SDK Updates
- [ ] Python SDK: Key context capture and propagation (`sdk/python/agentfield/agent.py`)
- [ ] Go SDK: Key context capture and propagation (`sdk/go/agent/agent.go`)
- [ ] TypeScript SDK: Key context capture and propagation (`sdk/typescript/src/agent/Agent.ts`)
- [ ] TypeScript SDK: Update client headers (`sdk/typescript/src/client/AgentFieldClient.ts`)
- [ ] Write SDK integration tests

### Phase 5: Admin API (Optional)
- [ ] Create `internal/handlers/admin/keys.go`
- [ ] Update `internal/server/routes.go`
- [ ] Write API tests
- [ ] Update API documentation

### Phase 6: Documentation
- [ ] Update README with access control section
- [ ] Add configuration examples to documentation
- [ ] Document migration process from single key
- [ ] Add troubleshooting guide for common permission errors

### Files to Create/Modify

| File | Action | Description |
|------|--------|-------------|
| `pkg/types/api_key.go` | Create | APIKey, ScopeGroup types |
| `pkg/types/types.go` | Modify | Add Tags to AgentNode |
| `internal/config/config.go` | Modify | Extended AuthConfig |
| `internal/storage/api_keys.go` | Create | API key storage interface |
| `internal/storage/local.go` | Modify | SQLite schema for api_keys |
| `internal/server/middleware/auth.go` | Modify | Multi-key auth |
| `internal/server/middleware/propagation.go` | Create | Signed key propagation |
| `internal/services/access_control.go` | Create | Access control logic |
| `internal/services/tag_resolver.go` | Create | Tag aggregation |
| `internal/handlers/execute.go` | Modify | Permission check |
| `internal/handlers/discovery.go` | Modify | Two-layer filtering |
| `internal/handlers/memory.go` | Modify | Scope protection |
| `migrations/018_create_api_keys.sql` | Create | PostgreSQL migration |
| `migrations/019_create_access_audit_log.sql` | Create | PostgreSQL migration |
| `sdk/python/agentfield/agent.py` | Modify | Key propagation |
| `sdk/go/agent/agent.go` | Modify | Key propagation |
| `sdk/typescript/src/agent/Agent.ts` | Modify | Key propagation |
| `sdk/typescript/src/client/AgentFieldClient.ts` | Modify | Header forwarding |

---

*End of Implementation Guide*
