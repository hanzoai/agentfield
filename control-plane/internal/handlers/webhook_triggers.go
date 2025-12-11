package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Agent-Field/agentfield/control-plane/internal/logger"
	"github.com/Agent-Field/agentfield/control-plane/internal/storage"
	"github.com/Agent-Field/agentfield/control-plane/internal/utils"
	"github.com/Agent-Field/agentfield/control-plane/internal/webhooks"
	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
	"github.com/gin-gonic/gin"
)

// WebhookHandlers serves the API-first inbound webhook functionality.
type WebhookHandlers struct {
	store storage.StorageProvider
}

func NewWebhookHandlers(store storage.StorageProvider) *WebhookHandlers {
	return &WebhookHandlers{store: store}
}

// RegisterRoutes registers webhook trigger CRUD and receiver routes.
func (h *WebhookHandlers) RegisterRoutes(api *gin.RouterGroup) {
	triggers := api.Group("/webhook-triggers")
	{
		triggers.POST("", h.CreateTrigger)
		triggers.GET("", h.ListTriggers)
		triggers.GET("/:id", h.GetTrigger)
		triggers.GET("/:id/example", h.GetTriggerExample)
		triggers.PATCH("/:id", h.UpdateTrigger)
		triggers.DELETE("/:id", h.DeleteTrigger)
		triggers.GET("/:id/deliveries", h.ListDeliveries)
	}

	api.POST("/webhooks/:trigger_id", h.ReceiveWebhook)
}

type createTriggerRequest struct {
	Name           string                 `json:"name" binding:"required"`
	Description    string                 `json:"description"`
	Target         string                 `json:"target" binding:"required"`
	TeamID         string                 `json:"team_id"`
	Mode           string                 `json:"mode"`
	FieldMappings  map[string]string      `json:"field_mappings"`
	Defaults       map[string]interface{} `json:"defaults"`
	TypeCoercions  map[string]string      `json:"type_coercions"`
	AllowedIPs     []string               `json:"allowed_ips"`
	EventIDPointer string                 `json:"event_id_pointer"`
	IdempotencyTTL string                 `json:"idempotency_ttl"`
	AsyncExecution bool                   `json:"async_execution"`
	MaxDuration    string                 `json:"max_duration"`
	Enabled        *bool                  `json:"enabled"`
}

func (h *WebhookHandlers) CreateTrigger(c *gin.Context) {
	var req createTriggerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request", "details": err.Error()})
		return
	}

	triggerID := utils.GenerateWebhookTriggerID()
	secret := utils.GenerateWebhookSecret()

	idemTTL := 24 * time.Hour
	if strings.TrimSpace(req.IdempotencyTTL) != "" {
		if parsed, err := time.ParseDuration(req.IdempotencyTTL); err == nil && parsed > 0 {
			idemTTL = parsed
		} else {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid idempotency_ttl"})
			return
		}
	}

	var maxDuration time.Duration
	if strings.TrimSpace(req.MaxDuration) != "" {
		parsed, err := time.ParseDuration(req.MaxDuration)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid max_duration"})
			return
		}
		maxDuration = parsed
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	now := time.Now().UTC()
	trigger := &types.WebhookTrigger{
		ID:             triggerID,
		Name:           req.Name,
		Description:    req.Description,
		Target:         req.Target,
		TeamID:         strings.TrimSpace(req.TeamID),
		Mode:           types.WebhookMappingMode(req.Mode),
		FieldMappings:  req.FieldMappings,
		Defaults:       req.Defaults,
		TypeCoercions:  req.TypeCoercions,
		SecretHash:     secret, // Stored as-is for now; can be hashed/encrypted later.
		AllowedIPs:     req.AllowedIPs,
		EventIDPointer: req.EventIDPointer,
		IdempotencyTTL: idemTTL,
		AsyncExecution: req.AsyncExecution,
		MaxDuration:    maxDuration,
		Enabled:        enabled,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := h.store.CreateWebhookTrigger(c.Request.Context(), trigger); err != nil {
		logger.Logger.Error().Err(err).Msg("failed to create webhook trigger")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create webhook trigger"})
		return
	}

	webhookURL := h.buildWebhookURL(c, triggerID)
	exampleSig := "<computed_signature>"
	if sig, err := webhooks.ComputeSignature(secret, "1702342800", []byte(`{"your":"payload"}`)); err == nil {
		exampleSig = sig
	}

	c.JSON(http.StatusOK, gin.H{
		"trigger_id":  triggerID,
		"webhook_url": webhookURL,
		"secret":      secret,
		"example": gin.H{
			"curl": `curl -X POST ` + webhookURL + ` \
  -H 'Content-Type: application/json' \
  -H 'X-AF-Signature: ` + exampleSig + `' \
  -H 'X-AF-Timestamp: 1702342800' \
  -d '{"your":"payload"}'`,
			"signature_generation": `echo -n '1702342800.{"your":"payload"}' | openssl dgst -sha256 -hmac '` + secret + `' | sed 's/^.* /sha256=/'`,
		},
		"created_at": now.Format(time.RFC3339),
	})
}

func (h *WebhookHandlers) ListTriggers(c *gin.Context) {
	var filters types.WebhookTriggerFilters
	if team := strings.TrimSpace(c.Query("team_id")); team != "" {
		filters.TeamID = &team
	}
	if target := strings.TrimSpace(c.Query("target")); target != "" {
		filters.Target = &target
	}
	if enabled := strings.TrimSpace(c.Query("enabled")); enabled != "" {
		if enabled == "true" || enabled == "1" {
			v := true
			filters.Enabled = &v
		} else if enabled == "false" || enabled == "0" {
			v := false
			filters.Enabled = &v
		}
	}
	if after := strings.TrimSpace(c.Query("after")); after != "" {
		filters.AfterID = &after
	}
	if limit := strings.TrimSpace(c.Query("limit")); limit != "" {
		if parsed, err := parsePositiveInt(limit); err == nil {
			filters.Limit = parsed
		}
	}

	triggers, err := h.store.ListWebhookTriggers(c.Request.Context(), filters)
	if err != nil {
		logger.Logger.Error().Err(err).Msg("failed to list webhook triggers")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list webhook triggers"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"triggers": triggers})
}

func (h *WebhookHandlers) GetTrigger(c *gin.Context) {
	triggerID := c.Param("id")
	trigger, err := h.store.GetWebhookTrigger(c.Request.Context(), triggerID)
	if err != nil {
		logger.Logger.Error().Err(err).Msg("failed to fetch webhook trigger")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch webhook trigger"})
		return
	}
	if trigger == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "webhook trigger not found"})
		return
	}
	c.JSON(http.StatusOK, trigger)
}

func (h *WebhookHandlers) GetTriggerExample(c *gin.Context) {
	triggerID := c.Param("id")
	trigger, err := h.store.GetWebhookTrigger(c.Request.Context(), triggerID)
	if err != nil {
		logger.Logger.Error().Err(err).Msg("failed to fetch webhook trigger example")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch webhook trigger"})
		return
	}
	if trigger == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "webhook trigger not found"})
		return
	}

	webhookURL := h.buildWebhookURL(c, triggerID)
	body := []byte(`{"your":"payload"}`)
	exampleSig, _ := webhooks.ComputeSignature(trigger.SecretHash, "1702342800", body)

	c.JSON(http.StatusOK, gin.H{
		"trigger_id":         triggerID,
		"webhook_url":        webhookURL,
		"target":             trigger.Target,
		"signature_required": true,
		"request_example": gin.H{
			"method": "POST",
			"url":    webhookURL,
			"headers": gin.H{
				"Content-Type":   "application/json",
				"X-AF-Signature": exampleSig,
				"X-AF-Timestamp": "1702342800",
			},
			"body": gin.H{
				"example": "replace with your payload",
			},
		},
		"signature_generation": gin.H{
			"algorithm":       "HMAC-SHA256",
			"payload_format":  "{timestamp}.{json_body}",
			"header_format":   "sha256=<hex_signature>",
			"example_command": `echo -n '1702342800.{"your":"payload"}' | openssl dgst -sha256 -hmac '` + trigger.SecretHash + `'`,
		},
	})
}

type updateTriggerRequest struct {
	Name           *string                `json:"name"`
	Description    *string                `json:"description"`
	Target         *string                `json:"target"`
	TeamID         *string                `json:"team_id"`
	Mode           *string                `json:"mode"`
	FieldMappings  map[string]string      `json:"field_mappings"`
	Defaults       map[string]interface{} `json:"defaults"`
	TypeCoercions  map[string]string      `json:"type_coercions"`
	AllowedIPs     []string               `json:"allowed_ips"`
	EventIDPointer *string                `json:"event_id_pointer"`
	IdempotencyTTL *string                `json:"idempotency_ttl"`
	AsyncExecution *bool                  `json:"async_execution"`
	MaxDuration    *string                `json:"max_duration"`
	Enabled        *bool                  `json:"enabled"`
}

func (h *WebhookHandlers) UpdateTrigger(c *gin.Context) {
	var req updateTriggerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request", "details": err.Error()})
		return
	}

	triggerID := c.Param("id")
	updated, err := h.store.UpdateWebhookTrigger(c.Request.Context(), triggerID, func(current *types.WebhookTrigger) (*types.WebhookTrigger, error) {
		if req.Name != nil {
			current.Name = *req.Name
		}
		if req.Description != nil {
			current.Description = *req.Description
		}
		if req.Target != nil {
			current.Target = *req.Target
		}
		if req.TeamID != nil {
			current.TeamID = strings.TrimSpace(*req.TeamID)
		}
		if req.Mode != nil {
			current.Mode = types.WebhookMappingMode(*req.Mode)
		}
		if req.FieldMappings != nil {
			current.FieldMappings = req.FieldMappings
		}
		if req.Defaults != nil {
			current.Defaults = req.Defaults
		}
		if req.TypeCoercions != nil {
			current.TypeCoercions = req.TypeCoercions
		}
		if req.AllowedIPs != nil {
			current.AllowedIPs = req.AllowedIPs
		}
		if req.EventIDPointer != nil {
			current.EventIDPointer = *req.EventIDPointer
		}
		if req.IdempotencyTTL != nil {
			if parsed, err := time.ParseDuration(*req.IdempotencyTTL); err == nil && parsed > 0 {
				current.IdempotencyTTL = parsed
			} else {
				return nil, err
			}
		}
		if req.AsyncExecution != nil {
			current.AsyncExecution = *req.AsyncExecution
		}
		if req.MaxDuration != nil {
			if *req.MaxDuration == "" {
				current.MaxDuration = 0
			} else if parsed, err := time.ParseDuration(*req.MaxDuration); err == nil {
				current.MaxDuration = parsed
			} else {
				return nil, err
			}
		}
		if req.Enabled != nil {
			current.Enabled = *req.Enabled
		}
		return current, nil
	})

	if err != nil {
		logger.Logger.Error().Err(err).Msg("failed to update webhook trigger")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update webhook trigger"})
		return
	}
	if updated == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "webhook trigger not found"})
		return
	}
	c.JSON(http.StatusOK, updated)
}

func (h *WebhookHandlers) DeleteTrigger(c *gin.Context) {
	triggerID := c.Param("id")
	if err := h.store.DeleteWebhookTrigger(c.Request.Context(), triggerID); err != nil {
		logger.Logger.Error().Err(err).Msg("failed to delete webhook trigger")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete webhook trigger"})
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *WebhookHandlers) ListDeliveries(c *gin.Context) {
	triggerID := c.Param("id")
	filters := types.WebhookDeliveryFilters{
		TriggerID: triggerID,
	}
	if status := strings.TrimSpace(c.Query("status")); status != "" {
		filters.Status = &status
	}
	if after := strings.TrimSpace(c.Query("after")); after != "" {
		filters.AfterID = &after
	}
	if limit := strings.TrimSpace(c.Query("limit")); limit != "" {
		if parsed, err := parsePositiveInt(limit); err == nil {
			filters.Limit = parsed
		}
	}

	deliveries, err := h.store.ListWebhookDeliveries(c.Request.Context(), filters)
	if err != nil {
		logger.Logger.Error().Err(err).Msg("failed to list webhook deliveries")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list webhook deliveries"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deliveries": deliveries})
}

func (h *WebhookHandlers) ReceiveWebhook(c *gin.Context) {
	triggerID := c.Param("trigger_id")
	trigger, err := h.store.GetWebhookTrigger(c.Request.Context(), triggerID)
	if err != nil {
		logger.Logger.Error().Err(err).Msg("failed to load webhook trigger")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load webhook trigger"})
		return
	}
	if trigger == nil || !trigger.Enabled {
		c.JSON(http.StatusNotFound, gin.H{"error": "webhook trigger not found"})
		return
	}

	body, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
		return
	}

	if len(trigger.AllowedIPs) > 0 {
		sourceIP := c.ClientIP()
		allowed := false
		for _, ip := range trigger.AllowedIPs {
			if strings.TrimSpace(ip) == sourceIP {
				allowed = true
				break
			}
		}
		if !allowed {
			c.JSON(http.StatusForbidden, gin.H{"error": "ip_not_allowed"})
			return
		}
	}

	eventID, _ := webhooks.ExtractEventID(body, trigger.EventIDPointer)
	if eventID != "" {
		if existing, _ := h.store.FindDeliveryByEventID(c.Request.Context(), triggerID, eventID); existing != nil {
			if trigger.IdempotencyTTL <= 0 || time.Since(existing.ReceivedAt) < trigger.IdempotencyTTL {
				c.JSON(http.StatusOK, gin.H{
					"status":       "duplicate",
					"delivery_id":  existing.ID,
					"execution_id": existing.ExecutionID,
					"message":      "Event already processed (event_id: " + eventID + ")",
				})
				return
			}
		}
	}

	signature := c.GetHeader("X-AF-Signature")
	timestamp := c.GetHeader("X-AF-Timestamp")
	if !webhooks.ValidateSignature(trigger.SecretHash, signature, timestamp, body) {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error_code":       "invalid_signature",
			"message":          "Signature verification failed",
			"www_authenticate": `X-AF-Signature signature="sha256=...", timestamp="X-AF-Timestamp"`,
		})
		return
	}

	mapped, err := webhooks.MapPayload(body, trigger)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error_code": "mapping_failed",
			"message":    err.Error(),
		})
		return
	}

	mappedHash, _ := webhooks.HashMappedInput(mapped)
	now := time.Now().UTC()
	delivery := &types.WebhookDelivery{
		ID:              utils.GenerateWebhookDeliveryID(),
		TriggerID:       triggerID,
		EventID:         eventID,
		SourceIP:        c.ClientIP(),
		Signature:       signature,
		Timestamp:       timestamp,
		PayloadHash:     webhooks.HashPayload(body),
		PayloadSize:     len(body),
		Status:          "accepted",
		MappedInputHash: mappedHash,
		ReceivedAt:      now,
		StoredPayload:   body,
	}

	if err := h.store.StoreWebhookDelivery(c.Request.Context(), delivery); err != nil {
		logger.Logger.Error().Err(err).Msg("failed to store webhook delivery")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store webhook delivery"})
		return
	}

	_, _ = h.store.UpdateWebhookTrigger(c.Request.Context(), triggerID, func(current *types.WebhookTrigger) (*types.WebhookTrigger, error) {
		current.TriggerCount++
		current.LastTriggeredAt = &now
		return current, nil
	})

	c.JSON(http.StatusAccepted, gin.H{
		"status":      "accepted",
		"delivery_id": delivery.ID,
		"message":     "Webhook queued for async processing",
	})
}

func (h *WebhookHandlers) buildWebhookURL(c *gin.Context, triggerID string) string {
	scheme := "https"
	if c.Request.TLS == nil {
		if forwarded := c.GetHeader("X-Forwarded-Proto"); forwarded != "" {
			scheme = forwarded
		} else {
			scheme = "http"
		}
	}
	host := c.Request.Host
	if host == "" {
		host = "localhost"
	}
	return scheme + "://" + host + "/api/v1/webhooks/" + triggerID
}

func parsePositiveInt(raw string) (int, error) {
	val, err := strconv.Atoi(raw)
	if err != nil {
		return 0, err
	}
	if val < 0 {
		return 0, fmt.Errorf("value must be positive")
	}
	return val, nil
}
