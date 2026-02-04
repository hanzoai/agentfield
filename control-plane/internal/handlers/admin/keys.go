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

	c.JSON(http.StatusOK, gin.H{
		"key_name":     key.Name,
		"key_scopes":   key.Scopes,
		"is_super":     key.IsSuperKey(),
		"target_agent": req.TargetAgent,
	})
}
