package middleware

import (
	"context"
	"net/http"

	"github.com/Agent-Field/agentfield/control-plane/internal/services"
	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
	"github.com/gin-gonic/gin"
)

// PermissionServiceInterface defines the methods required for permission checking.
type PermissionServiceInterface interface {
	IsEnabled() bool
	IsAgentProtected(agentID string, tags []string) bool
	CheckPermission(ctx context.Context, callerDID, targetDID string, targetAgentID string, targetTags []string) (*types.PermissionCheck, error)
	RequestPermission(ctx context.Context, req *types.PermissionRequest) (*types.PermissionApproval, error)
}

// AgentResolverInterface provides methods for resolving agent information.
type AgentResolverInterface interface {
	GetAgent(ctx context.Context, agentID string) (*types.AgentNode, error)
}

// DIDResolverInterface provides methods for resolving agent DIDs.
type DIDResolverInterface interface {
	GenerateDIDWeb(agentID string) string
	// ResolveAgentIDByDID looks up the agent ID associated with a DID.
	// Returns empty string if the DID cannot be resolved.
	ResolveAgentIDByDID(ctx context.Context, did string) string
}

// PermissionConfig holds configuration for permission checking.
type PermissionConfig struct {
	// Enabled determines if permission checking is active
	Enabled bool
	// AutoRequestOnDeny if true, automatically creates a permission request when access is denied
	AutoRequestOnDeny bool
}

// PermissionCheckResult contains the result of a permission check.
type PermissionCheckResult struct {
	Allowed            bool
	RequiresPermission bool
	ApprovalStatus     types.PermissionStatus
	ApprovalID         *int64
	Error              error
}

const (
	// PermissionCheckResultKey is the context key for storing permission check results.
	PermissionCheckResultKey ContextKey = "permission_check_result"
	// TargetAgentKey is the context key for storing the resolved target agent.
	TargetAgentKey ContextKey = "target_agent"
	// TargetDIDKey is the context key for storing the target agent's DID.
	TargetDIDKey ContextKey = "target_did"
)

// PermissionCheckMiddleware creates a middleware that checks permissions before allowing
// requests to protected agents.
//
// This middleware should be applied AFTER DIDAuthMiddleware so that the verified
// caller DID is available in the context.
//
// The middleware:
//  1. Extracts the verified caller DID from context (set by DIDAuthMiddleware)
//  2. Resolves the target agent from the request path
//  3. Checks if the caller has permission to call the target
//  4. If permission is required but not granted, returns 403 Forbidden
//  5. If auto-request is enabled, creates a permission request on denial
func PermissionCheckMiddleware(
	permissionService PermissionServiceInterface,
	agentResolver AgentResolverInterface,
	didResolver DIDResolverInterface,
	config PermissionConfig,
) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip if permission checking is disabled
		if !config.Enabled || permissionService == nil || !permissionService.IsEnabled() {
			c.Next()
			return
		}

		// Extract target from path parameter
		target := c.Param("target")
		if target == "" {
			// No target specified - let the handler deal with it
			c.Next()
			return
		}

		// Parse target (format: "agent_id.reasoner_name")
		agentID, _, err := parseTargetParam(target)
		if err != nil {
			c.Next()
			return
		}

		// Resolve the target agent
		ctx := c.Request.Context()
		agent, err := agentResolver.GetAgent(ctx, agentID)
		if err != nil {
			// Fail closed if target resolution fails to avoid bypass on transient backend errors.
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":           "target_resolution_failed",
				"message":         "Unable to resolve target agent for permission enforcement",
				"target_agent_id": agentID,
			})
			return
		}
		if agent == nil {
			// Agent not found - let the handler deal with the error
			c.Next()
			return
		}

		// Store the resolved agent in context for downstream use
		c.Set(string(TargetAgentKey), agent)

		// Generate target DID
		targetDID := didResolver.GenerateDIDWeb(agentID)
		c.Set(string(TargetDIDKey), targetDID)

		// Get canonical plain tags for permission matching.
		tags := services.CanonicalAgentTags(agent)
		isProtected := permissionService.IsAgentProtected(agentID, tags)

		// Unprotected targets may proceed without DID auth or permission approval.
		if !isProtected {
			c.Set(string(PermissionCheckResultKey), &PermissionCheckResult{
				Allowed:            true,
				RequiresPermission: false,
			})
			c.Next()
			return
		}

		// Protected targets require a verified DID.
		callerDID := GetVerifiedCallerDID(c)
		if callerDID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error":               "did_auth_required",
				"message":             "Protected target requires verified DID authentication",
				"requires_permission": true,
				"target_agent_id":     agentID,
				"target_did":          targetDID,
			})
			return
		}

		// Check permission
		check, err := permissionService.CheckPermission(ctx, callerDID, targetDID, agentID, tags)
		if err != nil {
			// Protected targets fail closed on permission backend errors.
			c.Set(string(PermissionCheckResultKey), &PermissionCheckResult{
				Allowed:            false,
				RequiresPermission: true,
				Error:              err,
			})
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error":               "permission_check_failed",
				"message":             "Permission verification failed for protected target",
				"requires_permission": true,
				"caller_did":          callerDID,
				"target_did":          targetDID,
				"target_agent_id":     agentID,
			})
			return
		}

		// Store the check result
		result := &PermissionCheckResult{
			Allowed:            !check.RequiresPermission || check.HasValidApproval,
			RequiresPermission: check.RequiresPermission,
			ApprovalStatus:     check.ApprovalStatus,
			ApprovalID:         check.ApprovalID,
		}
		c.Set(string(PermissionCheckResultKey), result)

		// If permission is required but not granted
		if check.RequiresPermission && !check.HasValidApproval {
			response := gin.H{
				"error":               "permission_denied",
				"message":             "Permission required to call this agent",
				"requires_permission": true,
				"caller_did":          callerDID,
				"target_did":          targetDID,
				"target_agent_id":     agentID,
			}

			// Add approval status if there's an existing request
			if check.ApprovalStatus != "" {
				response["approval_status"] = check.ApprovalStatus
			}
			if check.ApprovalID != nil {
				response["approval_id"] = *check.ApprovalID
			}

			// Auto-create permission request if enabled.
			// Also re-request if the previous record was revoked or rejected,
			// so the admin can re-evaluate. RequestPermission() handles the
			// revoked/rejected → pending transition via UPDATE (not INSERT).
			if config.AutoRequestOnDeny && (check.ApprovalStatus == "" ||
				check.ApprovalStatus == types.PermissionStatusRevoked ||
				check.ApprovalStatus == types.PermissionStatusRejected) {
				// Resolve caller agent ID from DID via storage lookup, falling
				// back to simple did:web parsing when unavailable.
				callerAgentID := didResolver.ResolveAgentIDByDID(ctx, callerDID)
				if callerAgentID == "" {
					callerAgentID = extractAgentIDFromDID(callerDID)
				}

				req := &types.PermissionRequest{
					CallerDID:     callerDID,
					TargetDID:     targetDID,
					CallerAgentID: callerAgentID,
					TargetAgentID: agentID,
					Reason:        "Auto-requested: caller attempted to invoke protected agent",
				}

				approval, reqErr := permissionService.RequestPermission(ctx, req)
				if reqErr == nil && approval != nil {
					response["approval_id"] = approval.ID
					response["approval_status"] = string(approval.Status)
					response["message"] = "Permission request created automatically. Awaiting approval."
				}
			}

			c.AbortWithStatusJSON(http.StatusForbidden, response)
			return
		}

		c.Next()
	}
}

// GetPermissionCheckResult extracts the permission check result from the gin context.
func GetPermissionCheckResult(c *gin.Context) *PermissionCheckResult {
	if result, exists := c.Get(string(PermissionCheckResultKey)); exists {
		if r, ok := result.(*PermissionCheckResult); ok {
			return r
		}
	}
	return nil
}

// GetTargetAgent extracts the resolved target agent from the gin context.
func GetTargetAgent(c *gin.Context) *types.AgentNode {
	if agent, exists := c.Get(string(TargetAgentKey)); exists {
		if a, ok := agent.(*types.AgentNode); ok {
			return a
		}
	}
	return nil
}

// GetTargetDID extracts the target DID from the gin context.
func GetTargetDID(c *gin.Context) string {
	if did, exists := c.Get(string(TargetDIDKey)); exists {
		if d, ok := did.(string); ok {
			return d
		}
	}
	return ""
}

// parseTargetParam parses a target parameter in the format "agent_id.reasoner_name".
func parseTargetParam(target string) (agentID, reasonerName string, err error) {
	for i := 0; i < len(target); i++ {
		if target[i] == '.' {
			return target[:i], target[i+1:], nil
		}
	}
	return target, "", nil
}

// extractAgentIDFromDID attempts to extract the agent ID from a did:web identifier.
// Format: did:web:{domain}:agents:{agentID}
func extractAgentIDFromDID(did string) string {
	// Simple extraction - look for ":agents:" and take what follows
	const agentsMarker = ":agents:"
	for i := 0; i <= len(did)-len(agentsMarker); i++ {
		if did[i:i+len(agentsMarker)] == agentsMarker {
			return did[i+len(agentsMarker):]
		}
	}
	return ""
}
