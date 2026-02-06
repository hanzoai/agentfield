package admin

import (
	"net/http"
	"strconv"

	"github.com/Agent-Field/agentfield/control-plane/internal/logger"
	"github.com/Agent-Field/agentfield/control-plane/internal/services"
	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
	"github.com/gin-gonic/gin"
)

// PermissionAdminHandlers handles admin permission management HTTP requests.
type PermissionAdminHandlers struct {
	permissionService *services.PermissionService
}

// NewPermissionAdminHandlers creates a new admin permission handlers instance.
func NewPermissionAdminHandlers(permissionService *services.PermissionService) *PermissionAdminHandlers {
	return &PermissionAdminHandlers{
		permissionService: permissionService,
	}
}

// ListPendingPermissions returns all pending permission requests.
// GET /api/v1/admin/permissions/pending
func (h *PermissionAdminHandlers) ListPendingPermissions(c *gin.Context) {
	permissions, err := h.permissionService.ListPendingPermissions(c.Request.Context())
	if err != nil {
		logger.Logger.Error().Err(err).Msg("Failed to list pending permissions")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "list_failed",
			"message": "Failed to list pending permissions",
		})
		return
	}

	c.JSON(http.StatusOK, types.PermissionListResponse{
		Permissions: permissions,
		Total:       len(permissions),
	})
}

// ListAllPermissions returns all permissions regardless of status.
// GET /api/v1/admin/permissions
func (h *PermissionAdminHandlers) ListAllPermissions(c *gin.Context) {
	permissions, err := h.permissionService.ListAllPermissions(c.Request.Context())
	if err != nil {
		logger.Logger.Error().Err(err).Msg("Failed to list permissions")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "list_failed",
			"message": "Failed to list permissions",
		})
		return
	}

	c.JSON(http.StatusOK, types.PermissionListResponse{
		Permissions: permissions,
		Total:       len(permissions),
	})
}

// GetPermission returns a single permission by ID.
// GET /api/v1/admin/permissions/:id
func (h *PermissionAdminHandlers) GetPermission(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_id",
			"message": "Permission ID must be a valid integer",
		})
		return
	}

	permission, err := h.permissionService.GetPermissionByID(c.Request.Context(), id)
	if err != nil {
		logger.Logger.Error().Err(err).Int64("permission_id", id).Msg("Permission not found")
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "not_found",
			"message": "Permission not found",
		})
		return
	}

	c.JSON(http.StatusOK, permission)
}

// ApprovePermission approves a pending permission request.
// POST /api/v1/admin/permissions/:id/approve
func (h *PermissionAdminHandlers) ApprovePermission(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_id",
			"message": "Permission ID must be a valid integer",
		})
		return
	}

	var req types.PermissionApproveRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Allow empty body - use defaults
		req = types.PermissionApproveRequest{}
	}

	// Get approver identity from context or header
	// In a real implementation, this would come from authentication
	approvedBy := c.GetHeader("X-Admin-User")
	if approvedBy == "" {
		approvedBy = "admin"
	}

	approval, err := h.permissionService.ApprovePermission(
		c.Request.Context(),
		id,
		approvedBy,
		req.DurationHours,
	)
	if err != nil {
		logger.Logger.Error().Err(err).Int64("permission_id", id).Msg("Failed to approve permission")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "approve_failed",
			"message": "Failed to approve permission",
		})
		return
	}

	c.JSON(http.StatusOK, approval)
}

// RejectPermission rejects a pending permission request.
// POST /api/v1/admin/permissions/:id/reject
func (h *PermissionAdminHandlers) RejectPermission(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_id",
			"message": "Permission ID must be a valid integer",
		})
		return
	}

	var req types.PermissionRejectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Allow empty body
		req = types.PermissionRejectRequest{}
	}

	// Get rejector identity from context or header
	rejectedBy := c.GetHeader("X-Admin-User")
	if rejectedBy == "" {
		rejectedBy = "admin"
	}

	approval, err := h.permissionService.RejectPermission(
		c.Request.Context(),
		id,
		rejectedBy,
		req.Reason,
	)
	if err != nil {
		logger.Logger.Error().Err(err).Int64("permission_id", id).Msg("Failed to reject permission")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "reject_failed",
			"message": "Failed to reject permission",
		})
		return
	}

	c.JSON(http.StatusOK, approval)
}

// RevokePermission revokes an approved permission.
// POST /api/v1/admin/permissions/:id/revoke
func (h *PermissionAdminHandlers) RevokePermission(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_id",
			"message": "Permission ID must be a valid integer",
		})
		return
	}

	var req types.PermissionRevokeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Allow empty body
		req = types.PermissionRevokeRequest{}
	}

	// Get revoker identity from context or header
	revokedBy := c.GetHeader("X-Admin-User")
	if revokedBy == "" {
		revokedBy = "admin"
	}

	approval, err := h.permissionService.RevokePermission(
		c.Request.Context(),
		id,
		revokedBy,
		req.Reason,
	)
	if err != nil {
		logger.Logger.Error().Err(err).Int64("permission_id", id).Msg("Failed to revoke permission")
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "revoke_failed",
			"message": "Failed to revoke permission",
		})
		return
	}

	c.JSON(http.StatusOK, approval)
}

// ListProtectedAgentRules returns all protected agent rules.
// GET /api/v1/admin/protected-agents
func (h *PermissionAdminHandlers) ListProtectedAgentRules(c *gin.Context) {
	rules, err := h.permissionService.ListProtectedAgentRules(c.Request.Context())
	if err != nil {
		logger.Logger.Error().Err(err).Msg("Failed to list protected agent rules")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "list_failed",
			"message": "Failed to list protected agent rules",
		})
		return
	}

	c.JSON(http.StatusOK, types.ProtectedAgentListResponse{
		Rules: rules,
		Total: len(rules),
	})
}

// AddProtectedAgentRule adds a new protected agent rule.
// POST /api/v1/admin/protected-agents
func (h *PermissionAdminHandlers) AddProtectedAgentRule(c *gin.Context) {
	var req types.ProtectedAgentRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_request",
			"message": "Invalid request body",
		})
		return
	}

	// Validate pattern type
	switch req.PatternType {
	case types.PatternTypeTag, types.PatternTypeTagPattern, types.PatternTypeAgentID:
		// Valid
	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_pattern_type",
			"message": "pattern_type must be one of: tag, tag_pattern, agent_id",
		})
		return
	}

	if req.Pattern == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "missing_pattern",
			"message": "pattern is required",
		})
		return
	}

	rule, err := h.permissionService.AddProtectedAgentRule(c.Request.Context(), &req)
	if err != nil {
		logger.Logger.Error().Err(err).Msg("Failed to create protected agent rule")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "create_failed",
			"message": "Failed to create protected agent rule",
		})
		return
	}

	c.JSON(http.StatusCreated, rule)
}

// RemoveProtectedAgentRule removes a protected agent rule.
// DELETE /api/v1/admin/protected-agents/:id
func (h *PermissionAdminHandlers) RemoveProtectedAgentRule(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_id",
			"message": "Rule ID must be a valid integer",
		})
		return
	}

	if err := h.permissionService.RemoveProtectedAgentRule(c.Request.Context(), id); err != nil {
		logger.Logger.Error().Err(err).Int64("rule_id", id).Msg("Failed to delete protected agent rule")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "delete_failed",
			"message": "Failed to delete protected agent rule",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Protected agent rule deleted successfully",
		"id":      id,
	})
}

// RegisterRoutes registers admin permission routes.
func (h *PermissionAdminHandlers) RegisterRoutes(router *gin.RouterGroup) {
	adminGroup := router.Group("/admin")
	{
		// Permission management
		permGroup := adminGroup.Group("/permissions")
		{
			permGroup.GET("", h.ListAllPermissions)
			permGroup.GET("/pending", h.ListPendingPermissions)
			permGroup.GET("/:id", h.GetPermission)
			permGroup.POST("/:id/approve", h.ApprovePermission)
			permGroup.POST("/:id/reject", h.RejectPermission)
			permGroup.POST("/:id/revoke", h.RevokePermission)
		}

		// Protected agent rules management
		protectedGroup := adminGroup.Group("/protected-agents")
		{
			protectedGroup.GET("", h.ListProtectedAgentRules)
			protectedGroup.POST("", h.AddProtectedAgentRule)
			protectedGroup.DELETE("/:id", h.RemoveProtectedAgentRule)
		}
	}
}
