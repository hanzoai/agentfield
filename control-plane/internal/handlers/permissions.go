package handlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/Agent-Field/agentfield/control-plane/internal/logger"
	"github.com/Agent-Field/agentfield/control-plane/internal/services"
	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
	"github.com/gin-gonic/gin"
)

// PermissionHandlers handles permission-related HTTP requests.
type PermissionHandlers struct {
	permissionService *services.PermissionService
	storage           AgentResolverStorage
	didResolver       DIDResolver
}

// AgentResolverStorage defines the storage interface needed for resolving agents.
type AgentResolverStorage interface {
	GetAgent(ctx context.Context, agentID string) (*types.AgentNode, error)
}

// DIDResolver defines DID generation required by permission checks.
type DIDResolver interface {
	GenerateDIDWeb(agentID string) string
}

// NewPermissionHandlers creates a new permission handlers instance.
func NewPermissionHandlers(permissionService *services.PermissionService, storage AgentResolverStorage, didResolver DIDResolver) *PermissionHandlers {
	return &PermissionHandlers{
		permissionService: permissionService,
		storage:           storage,
		didResolver:       didResolver,
	}
}

// RequestPermission handles permission request creation.
// POST /api/v1/permissions/request
func (h *PermissionHandlers) RequestPermission(c *gin.Context) {
	var req types.PermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_request",
			"message": "Invalid request body",
			"details": err.Error(),
		})
		return
	}

	// Validate required fields
	if req.CallerDID == "" || req.TargetDID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "missing_fields",
			"message": "caller_did and target_did are required",
		})
		return
	}

	if req.CallerAgentID == "" || req.TargetAgentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "missing_fields",
			"message": "caller_agent_id and target_agent_id are required",
		})
		return
	}

	// If DID auth is enabled, verify that the caller_did matches the authenticated DID
	if verifiedDID, exists := c.Get("verified_caller_did"); exists {
		if verifiedDIDStr, ok := verifiedDID.(string); ok && verifiedDIDStr != "" {
			if req.CallerDID != verifiedDIDStr {
				c.JSON(http.StatusForbidden, gin.H{
					"error":   "did_mismatch",
					"message": "caller_did does not match authenticated DID",
				})
				return
			}
		}
	}

	approval, err := h.permissionService.RequestPermission(c.Request.Context(), &req)
	if err != nil {
		logger.Logger.Error().Err(err).Msg("Failed to create permission request")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "request_failed",
			"message": "Failed to create permission request",
		})
		return
	}

	c.JSON(http.StatusCreated, approval)
}

// CheckPermission checks if a permission exists between caller and target.
// GET /api/v1/permissions/check?caller_did=...&target_did=...&target_agent_id=...
func (h *PermissionHandlers) CheckPermission(c *gin.Context) {
	callerDID := c.Query("caller_did")
	requestedTargetDID := c.Query("target_did")
	targetAgentID := c.Query("target_agent_id")

	if callerDID == "" || targetAgentID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "missing_parameters",
			"message": "caller_did and target_agent_id query parameters are required",
		})
		return
	}

	if h.storage == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "storage_unavailable",
			"message": "Target context resolver is unavailable",
		})
		return
	}

	agent, err := h.storage.GetAgent(c.Request.Context(), targetAgentID)
	if err != nil || agent == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_target_context",
			"message": "target_agent_id could not be resolved",
		})
		return
	}
	targetTags := services.CanonicalAgentTags(agent)
	if h.didResolver == nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "did_resolver_unavailable",
			"message": "Canonical target DID resolver is unavailable",
		})
		return
	}
	targetDID := h.didResolver.GenerateDIDWeb(targetAgentID)

	// Optional compatibility input: if caller provides target_did, it must match canonical target context.
	if requestedTargetDID != "" && requestedTargetDID != targetDID {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "target_context_mismatch",
			"message": "target_did does not match target_agent_id canonical DID",
		})
		return
	}

	check, err := h.permissionService.CheckPermission(
		c.Request.Context(),
		callerDID,
		targetDID,
		targetAgentID,
		targetTags,
	)
	if err != nil {
		logger.Logger.Error().Err(err).Msg("Failed to check permission")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "check_failed",
			"message": "Failed to check permission",
		})
		return
	}

	c.JSON(http.StatusOK, check)
}

// GetPermissionVC returns the VC for an approved permission.
// GET /api/v1/permissions/:id/vc
func (h *PermissionHandlers) GetPermissionVC(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_id",
			"message": "Permission ID must be a valid integer",
		})
		return
	}

	// Get the approval by ID (we need to add this method or use existing one)
	// For now, we'll use the storage directly through the service
	approval, err := h.permissionService.GetPermissionByID(c.Request.Context(), id)
	if err != nil {
		logger.Logger.Error().Err(err).Int64("permission_id", id).Msg("Permission not found")
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "not_found",
			"message": "Permission not found",
		})
		return
	}

	if approval.Status != types.PermissionStatusApproved {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "not_approved",
			"message": "Permission is not in approved state",
			"status":  approval.Status,
		})
		return
	}

	// Generate the VC
	vc, err := h.permissionService.GeneratePermissionVC(c.Request.Context(), approval)
	if err != nil {
		logger.Logger.Error().Err(err).Int64("permission_id", id).Msg("Failed to generate permission VC")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "vc_generation_failed",
			"message": "Failed to generate permission VC",
		})
		return
	}

	c.JSON(http.StatusOK, vc)
}

// RegisterRoutes registers permission-related routes.
func (h *PermissionHandlers) RegisterRoutes(router *gin.RouterGroup) {
	permGroup := router.Group("/permissions")
	{
		permGroup.POST("/request", h.RequestPermission)
		permGroup.GET("/check", h.CheckPermission)
		permGroup.GET("/:id/vc", h.GetPermissionVC)
	}
}
