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

// Context keys for storing auth info
const (
	ContextKeyScopes  = "api_key_scopes"
	ContextKeyID      = "api_key_id"
	ContextKeyName    = "api_key_name"
	ContextIsSuperKey = "api_key_is_super"
)

// AuthConfig holds configuration for the auth middleware.
type AuthConfig struct {
	// MasterAPIKey is the super admin key with full access to all agents
	MasterAPIKey string

	// SkipPaths are paths that bypass authentication
	SkipPaths []string

	// KeyStorage provides API key lookup (nil = legacy mode only)
	KeyStorage storage.APIKeyStorage

	// PropagationSecret is used to sign/verify key context headers
	PropagationSecret []byte

	// ScopeGroups for expanding @group references
	ScopeGroups map[string]types.ScopeGroup

	// keyCache caches verified keys to avoid repeated DB lookups
	keyCache    map[string]*cachedKey
	keyCacheMu  sync.RWMutex
	keyCacheTTL time.Duration
}

// cachedKey holds a cached API key with expiration
type cachedKey struct {
	key       *types.APIKey
	expiresAt time.Time
}

// APIKeyAuth creates the authentication middleware.
func APIKeyAuth(config AuthConfig) gin.HandlerFunc {
	skipPathSet := make(map[string]struct{}, len(config.SkipPaths))
	for _, p := range config.SkipPaths {
		skipPathSet[p] = struct{}{}
	}

	// Initialize cache
	if config.keyCache == nil {
		config.keyCache = make(map[string]*cachedKey)
	}
	if config.keyCacheTTL == 0 {
		config.keyCacheTTL = 5 * time.Minute
	}

	return func(c *gin.Context) {
		// No auth configured - allow everything (development mode)
		if config.MasterAPIKey == "" && config.KeyStorage == nil {
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

		// Check for propagated key context (internal agent-to-agent calls)
		if len(config.PropagationSecret) > 0 {
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

		// Try master API key first (super admin access)
		if config.MasterAPIKey != "" && apiKey == config.MasterAPIKey {
			c.Set(ContextKeyScopes, []string{"*"})
			c.Set(ContextKeyID, "master")
			c.Set(ContextKeyName, "master")
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

				// Expand scope groups if configured
				if len(config.ScopeGroups) > 0 {
					key.ExpandScopes(config.ScopeGroups)
				}

				// Update last used (async, don't block request)
				go func(keyID string) {
					_ = config.KeyStorage.UpdateKeyLastUsed(c.Request.Context(), keyID)
				}(key.ID)

				// Set context values
				c.Set(ContextKeyScopes, key.GetEffectiveScopes())
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
