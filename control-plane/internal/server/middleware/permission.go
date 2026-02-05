package middleware

import (
	"context"
	"net/http"

	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
	"github.com/gin-gonic/gin"
)

// PermissionServiceInterface defines the methods required for permission checking.
type PermissionServiceInterface interface {
	IsEnabled() bool
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

		// Get verified caller DID from context (set by DIDAuthMiddleware)
		callerDID := GetVerifiedCallerDID(c)
		if callerDID == "" {
			// No verified DID - allow through for now (might be API key auth only)
			// Protected agents will still be protected by their rules
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
		if err != nil || agent == nil {
			// Agent not found - let the handler deal with the error
			c.Next()
			return
		}

		// Store the resolved agent in context for downstream use
		c.Set(string(TargetAgentKey), agent)

		// Generate target DID
		targetDID := didResolver.GenerateDIDWeb(agentID)
		c.Set(string(TargetDIDKey), targetDID)

		// Get agent tags for permission matching
		tags := getAgentTags(agent)

		// Check permission
		check, err := permissionService.CheckPermission(ctx, callerDID, targetDID, agentID, tags)
		if err != nil {
			// Permission check failed - log and allow through (fail open for now)
			c.Set(string(PermissionCheckResultKey), &PermissionCheckResult{
				Allowed: true, // Fail open
				Error:   err,
			})
			c.Next()
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

			// Auto-create permission request if enabled
			if config.AutoRequestOnDeny && check.ApprovalStatus == "" {
				// Extract caller agent ID from DID (if possible)
				callerAgentID := extractAgentIDFromDID(callerDID)

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

// getAgentTags extracts tags from an agent node.
func getAgentTags(agent *types.AgentNode) []string {
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
