package types

import (
	"encoding/json"
	"time"
)

// WebhookTrigger represents the configuration for an inbound webhook.
type WebhookTrigger struct {
	ID              string                 `json:"id" db:"id"`
	Name            string                 `json:"name" db:"name"`
	Description     string                 `json:"description,omitempty" db:"description"`
	Target          string                 `json:"target" db:"target"`
	TeamID          string                 `json:"team_id" db:"team_id"`
	Mode            WebhookMappingMode     `json:"mode" db:"mode"`
	FieldMappings   map[string]string      `json:"field_mappings,omitempty" db:"field_mappings"`
	Defaults        map[string]interface{} `json:"defaults,omitempty" db:"defaults"`
	TypeCoercions   map[string]string      `json:"type_coercions,omitempty" db:"type_coercions"`
	SecretHash      string                 `json:"-" db:"secret_hash"`
	AllowedIPs      []string               `json:"allowed_ips,omitempty" db:"allowed_ips"`
	EventIDPointer  string                 `json:"event_id_pointer" db:"event_id_pointer"`
	IdempotencyTTL  time.Duration          `json:"idempotency_ttl" db:"idempotency_ttl_seconds"`
	AsyncExecution  bool                   `json:"async_execution" db:"async_execution"`
	MaxDuration     time.Duration          `json:"max_duration,omitempty" db:"max_duration_seconds"`
	Enabled         bool                   `json:"enabled" db:"enabled"`
	CreatedAt       time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at" db:"updated_at"`
	LastTriggeredAt *time.Time             `json:"last_triggered_at,omitempty" db:"last_triggered_at"`
	TriggerCount    int64                  `json:"trigger_count" db:"trigger_count"`
}

type WebhookMappingMode string

const (
	MappingModePassthrough WebhookMappingMode = "passthrough"
	MappingModeSelect      WebhookMappingMode = "select"
	MappingModeRemap       WebhookMappingMode = "remap"
)

// WebhookDelivery tracks each inbound webhook invocation.
type WebhookDelivery struct {
	ID              string          `json:"id" db:"id"`
	TriggerID       string          `json:"trigger_id" db:"trigger_id"`
	EventID         string          `json:"event_id,omitempty" db:"event_id"`
	SourceIP        string          `json:"source_ip" db:"source_ip"`
	Signature       string          `json:"signature,omitempty" db:"signature"`
	Timestamp       string          `json:"timestamp,omitempty" db:"timestamp"`
	PayloadHash     string          `json:"payload_hash" db:"payload_hash"`
	PayloadSize     int             `json:"payload_size" db:"payload_size"`
	Status          string          `json:"status" db:"status"`
	ErrorCode       string          `json:"error_code,omitempty" db:"error_code"`
	ErrorMessage    string          `json:"error_message,omitempty" db:"error_message"`
	MappedInputHash string          `json:"mapped_input_hash,omitempty" db:"mapped_input_hash"`
	ExecutionID     string          `json:"execution_id,omitempty" db:"execution_id"`
	ReceivedAt      time.Time       `json:"received_at" db:"received_at"`
	ProcessedAt     *time.Time      `json:"processed_at,omitempty" db:"processed_at"`
	DurationMS      int64           `json:"duration_ms,omitempty" db:"duration_ms"`
	StoredPayload   json.RawMessage `json:"-" db:"stored_payload"`
}
