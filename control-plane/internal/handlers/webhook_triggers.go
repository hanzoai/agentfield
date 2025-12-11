package handlers

import (
	"encoding/json"
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

const exampleSignatureTimestamp = "1702342800"

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
		triggers.POST("/:id/rotate-secret", h.RotateSecret)
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
	secret, err := utils.GenerateWebhookSecret()
	if err != nil {
		logger.Logger.Error().Err(err).Msg("failed to securely generate webhook secret")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to securely generate webhook secret"})
		return
	}

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
	exampleBody, exampleBodyBytes, mappedPreview := buildExampleData(trigger)
	if sig, err := webhooks.ComputeSignature(secret, exampleSignatureTimestamp, exampleBodyBytes); err == nil {
		exampleSig = sig
	}

	c.JSON(http.StatusOK, gin.H{
		"trigger_id":  triggerID,
		"webhook_url": webhookURL,
		"secret":      secret,
		"example": gin.H{
			"curl":                 buildCurlExample(webhookURL, exampleSig, exampleBodyBytes),
			"signature_generation": buildSignatureCommand(secret, exampleBodyBytes),
			"timestamp":            exampleSignatureTimestamp,
			"body":                 exampleBody,
			"mapped_input_preview": mappedPreview,
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
	body, bodyBytes, mappedPreview := buildExampleData(trigger)
	exampleSig, _ := webhooks.ComputeSignature(trigger.SecretHash, exampleSignatureTimestamp, bodyBytes)

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
				"X-AF-Timestamp": exampleSignatureTimestamp,
			},
			"body": body,
		},
		"signature_generation": gin.H{
			"algorithm":       "HMAC-SHA256",
			"payload_format":  "{timestamp}.{json_body}",
			"header_format":   "sha256=<hex_signature>",
			"example_command": buildSignatureCommand(trigger.SecretHash, bodyBytes),
		},
		"mapped_input_preview": mappedPreview,
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

func (h *WebhookHandlers) RotateSecret(c *gin.Context) {
	triggerID := c.Param("id")
	trigger, err := h.store.GetWebhookTrigger(c.Request.Context(), triggerID)
	if err != nil {
		logger.Logger.Error().Err(err).Msg("failed to fetch webhook trigger for rotation")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to rotate webhook secret"})
		return
	}
	if trigger == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "webhook trigger not found"})
		return
	}

	newSecret, err := utils.GenerateWebhookSecret()
	if err != nil {
		logger.Logger.Error().Err(err).Msg("failed to securely generate webhook secret")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to securely generate webhook secret"})
		return
	}
	updated, err := h.store.UpdateWebhookTrigger(c.Request.Context(), triggerID, func(current *types.WebhookTrigger) (*types.WebhookTrigger, error) {
		current.SecretHash = newSecret
		return current, nil
	})
	if err != nil {
		logger.Logger.Error().Err(err).Msg("failed to rotate webhook secret")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to rotate webhook secret"})
		return
	}
	if updated == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "webhook trigger not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"trigger_id": triggerID,
		"new_secret": newSecret,
		"rotated_at": updated.UpdatedAt.Format(time.RFC3339),
		"message":    "Update your webhook provider with the new secret",
	})
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

	now := time.Now().UTC()
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

	var existingDelivery *types.WebhookDelivery
	eventID, _ := webhooks.ExtractEventID(body, trigger.EventIDPointer)
	if eventID != "" {
		var lookupErr error
		existingDelivery, lookupErr = h.store.FindDeliveryByEventID(c.Request.Context(), triggerID, eventID)
		if lookupErr != nil {
			logger.Logger.Error().Err(lookupErr).Msg("failed to check existing webhook delivery for idempotency")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process webhook"})
			return
		}
		if existingDelivery != nil {
			if trigger.IdempotencyTTL <= 0 || now.Sub(existingDelivery.ReceivedAt) < trigger.IdempotencyTTL {
				c.JSON(http.StatusOK, gin.H{
					"status":       "duplicate",
					"delivery_id":  existingDelivery.ID,
					"execution_id": existingDelivery.ExecutionID,
					"message":      "Event already processed (event_id: " + eventID + ")",
				})
				return
			}
			if err := h.store.DeleteWebhookDelivery(c.Request.Context(), existingDelivery.ID); err != nil {
				logger.Logger.Error().Err(err).Msg("failed to evict expired idempotency record")
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process webhook"})
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
		if eventID != "" && isUniqueEventConstraint(err) {
			if existingDelivery == nil {
				existingDelivery, _ = h.store.FindDeliveryByEventID(c.Request.Context(), triggerID, eventID)
			}
			c.JSON(http.StatusOK, gin.H{
				"status":       "duplicate",
				"delivery_id":  safeDeliveryID(existingDelivery),
				"execution_id": safeExecutionID(existingDelivery),
				"message":      "Event already processed (event_id: " + eventID + ")",
			})
			return
		}
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

func isUniqueEventConstraint(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") &&
		strings.Contains(msg, "webhook") &&
		strings.Contains(msg, "event")
}

func safeDeliveryID(delivery *types.WebhookDelivery) string {
	if delivery == nil {
		return ""
	}
	return delivery.ID
}

func safeExecutionID(delivery *types.WebhookDelivery) string {
	if delivery == nil {
		return ""
	}
	return delivery.ExecutionID
}

func buildExampleData(trigger *types.WebhookTrigger) (map[string]interface{}, []byte, map[string]interface{}) {
	payload := buildExamplePayload(trigger)
	body, err := json.Marshal(payload)
	if err != nil {
		body = []byte(`{"example":"payload"}`)
	}

	mapped, err := webhooks.MapPayload(body, trigger)
	if err != nil {
		mapped = map[string]interface{}{}
	}
	return payload, body, mapped
}

func buildExamplePayload(trigger *types.WebhookTrigger) map[string]interface{} {
	payload := make(map[string]interface{})
	if trigger == nil {
		payload["example"] = "replace with your payload"
		return payload
	}

	for field, pointer := range trigger.FieldMappings {
		value := exampleValueForField(field, trigger.TypeCoercions[field])
		_ = setPointerValue(payload, pointer, value)
	}

	if strings.TrimSpace(trigger.EventIDPointer) != "" {
		_ = setPointerValue(payload, trigger.EventIDPointer, "evt_example_123")
	}

	if len(payload) == 0 {
		payload["example"] = "replace with your payload"
	}

	return payload
}

func exampleValueForField(field, coercion string) interface{} {
	lowerField := strings.ToLower(field)
	switch strings.ToLower(coercion) {
	case "int", "integer":
		return 42
	case "float", "float64", "double":
		return 1.23
	case "bool", "boolean":
		return true
	case "string":
		return fmt.Sprintf("example-%s", field)
	}
	switch {
	case strings.Contains(lowerField, "repo"):
		return "org/repo"
	case strings.Contains(lowerField, "url"):
		return "https://example.com/resource"
	case strings.Contains(lowerField, "id"):
		return field + "-example"
	case strings.Contains(lowerField, "name"):
		return "example-name"
	}
	return fmt.Sprintf("example-%s", field)
}

func setPointerValue(target map[string]interface{}, pointer string, value interface{}) error {
	if strings.TrimSpace(pointer) == "" || pointer == "/" {
		target["example"] = value
		return nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return fmt.Errorf("invalid json pointer %q", pointer)
	}

	current := interface{}(target)
	var parentMap map[string]interface{}
	var parentSlice []interface{}
	var parentKey string
	var parentIndex int

	segments := strings.Split(pointer[1:], "/")
	for i, raw := range segments {
		token := decodePointerToken(raw)
		last := i == len(segments)-1

		switch node := current.(type) {
		case map[string]interface{}:
			next, ok := node[token]
			if !ok {
				if last {
					node[token] = value
					return nil
				}
				node[token] = allocateNextContainer(segments, i)
				next = node[token]
			}
			if last {
				node[token] = value
				return nil
			}
			parentMap = node
			parentSlice = nil
			parentKey = token
			current = next
		case []interface{}:
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 {
				return fmt.Errorf("invalid array index %q", token)
			}

			if len(node) <= index {
				resized := make([]interface{}, index+1)
				copy(resized, node)
				node = resized
				if parentMap != nil {
					parentMap[parentKey] = node
				} else if parentSlice != nil {
					parentSlice[parentIndex] = node
				}
			}

			if last {
				node[index] = value
				return nil
			}
			if node[index] == nil {
				node[index] = allocateNextContainer(segments, i)
			}
			parentMap = nil
			parentSlice = node
			parentIndex = index
			current = node[index]
		default:
			return fmt.Errorf("cannot traverse pointer segment %q", token)
		}
	}

	return nil
}

func allocateNextContainer(segments []string, current int) interface{} {
	nextIdx := current + 1
	if nextIdx >= len(segments) {
		return make(map[string]interface{})
	}

	if _, err := strconv.Atoi(decodePointerToken(segments[nextIdx])); err == nil {
		return make([]interface{}, 1)
	}
	return make(map[string]interface{})
}

func decodePointerToken(raw string) string {
	return strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
}

func buildCurlExample(webhookURL, signature string, body []byte) string {
	return `curl -X POST ` + webhookURL + ` \
  -H 'Content-Type: application/json' \
  -H 'X-AF-Signature: ` + signature + `' \
  -H 'X-AF-Timestamp: ` + exampleSignatureTimestamp + `' \
  -d '` + string(body) + `'`
}

func buildSignatureCommand(secret string, body []byte) string {
	return `echo -n '` + exampleSignatureTimestamp + `.` + string(body) + `' | openssl dgst -sha256 -hmac '` + secret + `' | sed 's/^.* /sha256=/'`
}
