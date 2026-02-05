package handlers

import (
	"context"
	"net/http"
	"strconv"

	"github.com/Agent-Field/agentfield/control-plane/internal/services"
	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
	"github.com/gin-gonic/gin"
)

// PermissionHandlers handles permission-related HTTP requests.
type PermissionHandlers struct {
	permissionService *services.PermissionService
	storage           AgentResolverStorage
}

// AgentResolverStorage defines the storage interface needed for resolving agents.
type AgentResolverStorage interface {
	GetAgent(ctx context.Context, agentID string) (*types.AgentNode, error)
}

// NewPermissionHandlers creates a new permission handlers instance.
func NewPermissionHandlers(permissionService *services.PermissionService, storage AgentResolverStorage) *PermissionHandlers {
	return &PermissionHandlers{
		permissionService: permissionService,
		storage:           storage,
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

	approval, err := h.permissionService.RequestPermission(c.Request.Context(), &req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "request_failed",
			"message": "Failed to create permission request",
			"details": err.Error(),
		})
		return
	}

	c.JSON(http.StatusCreated, approval)
}

// CheckPermission checks if a permission exists between caller and target.
// GET /api/v1/permissions/check?caller_did=...&target_did=...&target_agent_id=...
func (h *PermissionHandlers) CheckPermission(c *gin.Context) {
	callerDID := c.Query("caller_did")
	targetDID := c.Query("target_did")
	targetAgentID := c.Query("target_agent_id")

	if callerDID == "" || targetDID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "missing_parameters",
			"message": "caller_did and target_did query parameters are required",
		})
		return
	}

	// Get target agent tags if we have the agent ID
	var targetTags []string
	if targetAgentID != "" && h.storage != nil {
		agent, err := h.storage.GetAgent(c.Request.Context(), targetAgentID)
		if err == nil && agent != nil {
			targetTags = getAgentTagsFromNode(agent)
		}
	}

	check, err := h.permissionService.CheckPermission(
		c.Request.Context(),
		callerDID,
		targetDID,
		targetAgentID,
		targetTags,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "check_failed",
			"message": "Failed to check permission",
			"details": err.Error(),
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
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "not_found",
			"message": "Permission not found",
			"details": err.Error(),
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
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "vc_generation_failed",
			"message": "Failed to generate permission VC",
			"details": err.Error(),
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

// getAgentTagsFromNode extracts tags from an agent node.
func getAgentTagsFromNode(agent *types.AgentNode) []string {
	if agent == nil {
		return nil
	}

	var tags []string

	// Add explicit tags from deployment metadata
	if agent.Metadata.Deployment != nil && agent.Metadata.Deployment.Tags != nil {
		for key, value := range agent.Metadata.Deployment.Tags {
			tags = append(tags, key+":"+value)
		}
	}

	// Add deployment type as a tag
	if agent.DeploymentType != "" {
		tags = append(tags, "deployment:"+agent.DeploymentType)
	}

	return tags
}
