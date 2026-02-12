package connector

import (
	"net/http"

	"github.com/Agent-Field/agentfield/control-plane/internal/config"
	"github.com/Agent-Field/agentfield/control-plane/internal/handlers/admin"
	"github.com/Agent-Field/agentfield/control-plane/internal/server/middleware"
	"github.com/Agent-Field/agentfield/control-plane/internal/services"
	"github.com/Agent-Field/agentfield/control-plane/internal/storage"
	"github.com/Agent-Field/agentfield/control-plane/pkg/types"

	"github.com/gin-gonic/gin"
)

// Handlers provides connector-specific HTTP handlers for the control plane.
type Handlers struct {
	connectorConfig     config.ConnectorConfig
	storage             storage.StorageProvider
	accessPolicyService *services.AccessPolicyService
	tagApprovalService  *services.TagApprovalService
	didService          *services.DIDService
}

// NewHandlers creates connector handlers with injected dependencies.
func NewHandlers(
	cfg config.ConnectorConfig,
	store storage.StorageProvider,
	accessPolicyService *services.AccessPolicyService,
	tagApprovalService *services.TagApprovalService,
	didService *services.DIDService,
) *Handlers {
	return &Handlers{
		connectorConfig:     cfg,
		storage:             store,
		accessPolicyService: accessPolicyService,
		tagApprovalService:  tagApprovalService,
		didService:          didService,
	}
}

// RegisterRoutes registers all connector routes on the given router group.
// Each route group is gated by its corresponding capability — the CP is the
// sole authority for what the connector token is allowed to access.
// The /manifest endpoint is always accessible so the connector can learn
// its granted capabilities on startup.
func (h *Handlers) RegisterRoutes(group *gin.RouterGroup) {
	caps := h.connectorConfig.Capabilities

	// Manifest endpoint — always accessible (connector needs this to learn capabilities)
	group.GET("/manifest", h.GetManifest)

	// Reasoner management routes
	reasonerGroup := group.Group("")
	reasonerGroup.Use(middleware.ConnectorCapabilityCheck("reasoner_management", caps))
	{
		reasonerGroup.GET("/reasoners", h.ListReasoners)
		reasonerGroup.GET("/reasoners/:id", h.GetReasoner)
		reasonerGroup.PUT("/reasoners/:id/version", h.SetReasonerVersion)
		reasonerGroup.POST("/reasoners/:id/restart", h.RestartReasoner)
	}

	// DID management routes
	if h.didService != nil {
		didGroup := group.Group("")
		didGroup.Use(middleware.ConnectorCapabilityCheck("did_management", caps))
		{
			didGroup.POST("/did/rotate-keys", h.RotateDIDKeys)
		}
	}

	// Policy management routes (proxied admin endpoints)
	if h.accessPolicyService != nil {
		policyGroup := group.Group("")
		policyGroup.Use(middleware.ConnectorCapabilityCheck("policy_management", caps))
		policyHandlers := admin.NewAccessPolicyHandlers(h.accessPolicyService)
		policyHandlers.RegisterRoutes(policyGroup)
	}

	// Tag management routes (proxied admin endpoints)
	if h.tagApprovalService != nil {
		tagGroup := group.Group("")
		tagGroup.Use(middleware.ConnectorCapabilityCheck("tag_management", caps))
		tagHandlers := admin.NewTagApprovalHandlers(h.tagApprovalService)
		tagHandlers.RegisterRoutes(tagGroup)
	}
}

// GetManifest returns the server-side capability manifest showing what
// this control plane supports and what the connector is configured to access.
func (h *Handlers) GetManifest(c *gin.Context) {
	capabilities := make(map[string]map[string]interface{})
	for name, cap := range h.connectorConfig.Capabilities {
		capabilities[name] = map[string]interface{}{
			"enabled":   cap.Enabled,
			"read_only": cap.ReadOnly,
		}
	}

	manifest := gin.H{
		"connector_enabled": h.connectorConfig.Enabled,
		"capabilities":      capabilities,
		"features": gin.H{
			"did_enabled":           h.didService != nil,
			"authorization_enabled": h.accessPolicyService != nil,
		},
	}

	c.JSON(http.StatusOK, manifest)
}

// ListReasoners returns all registered agent nodes with their reasoner info.
func (h *Handlers) ListReasoners(c *gin.Context) {
	ctx := c.Request.Context()
	agents, err := h.storage.ListAgents(ctx, types.AgentFilters{})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	type nodeInfo struct {
		NodeID       string                    `json:"node_id"`
		TeamID       string                    `json:"team_id"`
		Version      string                    `json:"version"`
		HealthStatus types.HealthStatus        `json:"health_status"`
		Reasoners    []types.ReasonerDefinition `json:"reasoners"`
		Skills       []types.SkillDefinition    `json:"skills"`
	}

	var result []nodeInfo
	for _, agent := range agents {
		result = append(result, nodeInfo{
			NodeID:       agent.ID,
			TeamID:       agent.TeamID,
			Version:      agent.Version,
			HealthStatus: agent.HealthStatus,
			Reasoners:    agent.Reasoners,
			Skills:       agent.Skills,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"reasoners": result,
		"total":     len(result),
	})
}

// GetReasoner returns detailed info for a specific agent node.
func (h *Handlers) GetReasoner(c *gin.Context) {
	ctx := c.Request.Context()
	id := c.Param("id")

	agent, err := h.storage.GetAgent(ctx, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if agent == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent node not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":              agent.ID,
		"team_id":         agent.TeamID,
		"version":         agent.Version,
		"health_status":   agent.HealthStatus,
		"lifecycle_status": agent.LifecycleStatus,
		"reasoners":       agent.Reasoners,
		"skills":          agent.Skills,
		"base_url":        agent.BaseURL,
	})
}

// SetReasonerVersion is a placeholder for future version management.
func (h *Handlers) SetReasonerVersion(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error":   "not_implemented",
		"message": "reasoner version management is not yet supported",
	})
}

// RestartReasoner is a placeholder for future reasoner restart functionality.
func (h *Handlers) RestartReasoner(c *gin.Context) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error":   "not_implemented",
		"message": "reasoner restart is not yet supported",
	})
}

// RotateDIDKeys triggers DID key rotation for the control plane.
func (h *Handlers) RotateDIDKeys(c *gin.Context) {
	if h.didService == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "did_not_enabled",
			"message": "DID system is not enabled on this control plane",
		})
		return
	}

	c.JSON(http.StatusNotImplemented, gin.H{
		"error":   "not_implemented",
		"message": "DID key rotation via connector is not yet supported",
	})
}
