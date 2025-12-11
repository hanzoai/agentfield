package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
)

const (
	webhookTriggerColumns = `
		id, name, description, target, team_id, mode,
		field_mappings, defaults, type_coercions, secret_hash, allowed_ips,
		event_id_pointer, idempotency_ttl_seconds, async_execution, max_duration_seconds,
		enabled, created_at, updated_at, last_triggered_at, trigger_count
	`

	webhookDeliveryColumns = `
		id, trigger_id, event_id, source_ip, signature, timestamp,
		payload_hash, payload_size, status, error_code, error_message,
		mapped_input_hash, execution_id, received_at, processed_at,
		duration_ms, stored_payload
	`
)

// CreateWebhookTrigger stores a new webhook trigger configuration.
func (ls *LocalStorage) CreateWebhookTrigger(ctx context.Context, trigger *types.WebhookTrigger) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if trigger == nil {
		return fmt.Errorf("webhook trigger is required")
	}
	if strings.TrimSpace(trigger.ID) == "" {
		return fmt.Errorf("webhook trigger id is required")
	}
	if strings.TrimSpace(trigger.Name) == "" {
		return fmt.Errorf("webhook trigger name is required")
	}
	if strings.TrimSpace(trigger.Target) == "" {
		return fmt.Errorf("webhook trigger target is required")
	}
	if strings.TrimSpace(trigger.SecretHash) == "" {
		return fmt.Errorf("webhook trigger secret hash is required")
	}

	normalizeWebhookTriggerDefaults(trigger)

	fieldMappings, err := encodeStringMap(trigger.FieldMappings)
	if err != nil {
		return err
	}
	defaultsJSON, err := encodeInterfaceMap(trigger.Defaults)
	if err != nil {
		return err
	}
	typeCoercions, err := encodeStringMap(trigger.TypeCoercions)
	if err != nil {
		return err
	}
	allowedIPs, err := encodeStringSlice(trigger.AllowedIPs)
	if err != nil {
		return err
	}

	desc := sql.NullString{}
	if strings.TrimSpace(trigger.Description) != "" {
		desc = sql.NullString{String: trigger.Description, Valid: true}
	}
	eventPointer := sql.NullString{}
	if strings.TrimSpace(trigger.EventIDPointer) != "" {
		eventPointer = sql.NullString{String: trigger.EventIDPointer, Valid: true}
	}
	lastTriggered := sql.NullTime{}
	if trigger.LastTriggeredAt != nil && !trigger.LastTriggeredAt.IsZero() {
		lastTriggered = sql.NullTime{Time: trigger.LastTriggeredAt.UTC(), Valid: true}
	}
	maxDuration := sql.NullInt64{}
	if trigger.MaxDuration > 0 {
		maxDuration = sql.NullInt64{Int64: int64(trigger.MaxDuration / time.Second), Valid: true}
	}

	_, err = ls.db.ExecContext(ctx, `
		INSERT INTO webhook_triggers (
			id, name, description, target, team_id, mode,
			field_mappings, defaults, type_coercions, secret_hash, allowed_ips,
			event_id_pointer, idempotency_ttl_seconds, async_execution, max_duration_seconds,
			enabled, created_at, updated_at, last_triggered_at, trigger_count
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, trigger.ID, trigger.Name, desc, trigger.Target, trigger.TeamID, trigger.Mode,
		fieldMappings, defaultsJSON, typeCoercions, trigger.SecretHash, allowedIPs,
		eventPointer, int64(trigger.IdempotencyTTL/time.Second), trigger.AsyncExecution, maxDuration,
		trigger.Enabled, trigger.CreatedAt.UTC(), trigger.UpdatedAt.UTC(), lastTriggered, trigger.TriggerCount)
	if err != nil {
		return fmt.Errorf("create webhook trigger: %w", err)
	}

	return nil
}

// GetWebhookTrigger fetches a webhook trigger by ID.
func (ls *LocalStorage) GetWebhookTrigger(ctx context.Context, triggerID string) (*types.WebhookTrigger, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(triggerID) == "" {
		return nil, fmt.Errorf("trigger id is required")
	}

	row := ls.db.QueryRowContext(ctx, `
		SELECT `+webhookTriggerColumns+`
		FROM webhook_triggers
		WHERE id = ?
	`, triggerID)

	return scanWebhookTrigger(row)
}

// ListWebhookTriggers returns triggers filtered by team/target/enabled.
func (ls *LocalStorage) ListWebhookTriggers(ctx context.Context, filters types.WebhookTriggerFilters) ([]*types.WebhookTrigger, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	conditions := make([]string, 0)
	args := make([]interface{}, 0)

	if filters.TeamID != nil && strings.TrimSpace(*filters.TeamID) != "" {
		conditions = append(conditions, "team_id = ?")
		args = append(args, strings.TrimSpace(*filters.TeamID))
	}
	if filters.Target != nil && strings.TrimSpace(*filters.Target) != "" {
		conditions = append(conditions, "target = ?")
		args = append(args, strings.TrimSpace(*filters.Target))
	}
	if filters.Enabled != nil {
		conditions = append(conditions, "enabled = ?")
		args = append(args, *filters.Enabled)
	}
	if filters.AfterID != nil && strings.TrimSpace(*filters.AfterID) != "" {
		conditions = append(conditions, "id > ?")
		args = append(args, strings.TrimSpace(*filters.AfterID))
	}

	query := `
		SELECT ` + webhookTriggerColumns + `
		FROM webhook_triggers`
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY id ASC LIMIT ?"

	limit := filters.Limit
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	args = append(args, limit)

	rows, err := ls.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list webhook triggers: %w", err)
	}
	defer rows.Close()

	results := make([]*types.WebhookTrigger, 0)
	for rows.Next() {
		trigger, err := scanWebhookTrigger(rows)
		if err != nil {
			return nil, err
		}
		results = append(results, trigger)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate webhook triggers: %w", err)
	}

	return results, nil
}

// UpdateWebhookTrigger loads, mutates via callback, and persists a webhook trigger.
func (ls *LocalStorage) UpdateWebhookTrigger(ctx context.Context, triggerID string, update func(*types.WebhookTrigger) (*types.WebhookTrigger, error)) (*types.WebhookTrigger, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(triggerID) == "" {
		return nil, fmt.Errorf("trigger id is required")
	}
	if update == nil {
		return nil, fmt.Errorf("update func is required")
	}

	current, err := ls.GetWebhookTrigger(ctx, triggerID)
	if err != nil {
		return nil, err
	}
	if current == nil {
		return nil, nil
	}

	updated, err := update(current)
	if err != nil {
		return nil, err
	}
	if updated == nil {
		updated = current
	}
	updated.ID = triggerID
	normalizeWebhookTriggerDefaults(updated)
	updated.UpdatedAt = time.Now().UTC()

	fieldMappings, err := encodeStringMap(updated.FieldMappings)
	if err != nil {
		return nil, err
	}
	defaultsJSON, err := encodeInterfaceMap(updated.Defaults)
	if err != nil {
		return nil, err
	}
	typeCoercions, err := encodeStringMap(updated.TypeCoercions)
	if err != nil {
		return nil, err
	}
	allowedIPs, err := encodeStringSlice(updated.AllowedIPs)
	if err != nil {
		return nil, err
	}

	desc := sql.NullString{}
	if strings.TrimSpace(updated.Description) != "" {
		desc = sql.NullString{String: updated.Description, Valid: true}
	}
	eventPointer := sql.NullString{}
	if strings.TrimSpace(updated.EventIDPointer) != "" {
		eventPointer = sql.NullString{String: updated.EventIDPointer, Valid: true}
	}
	lastTriggered := sql.NullTime{}
	if updated.LastTriggeredAt != nil && !updated.LastTriggeredAt.IsZero() {
		lastTriggered = sql.NullTime{Time: updated.LastTriggeredAt.UTC(), Valid: true}
	}
	maxDuration := sql.NullInt64{}
	if updated.MaxDuration > 0 {
		maxDuration = sql.NullInt64{Int64: int64(updated.MaxDuration / time.Second), Valid: true}
	}

	_, err = ls.db.ExecContext(ctx, `
		UPDATE webhook_triggers
		SET name = ?, description = ?, target = ?, team_id = ?, mode = ?,
			field_mappings = ?, defaults = ?, type_coercions = ?, secret_hash = ?, allowed_ips = ?,
			event_id_pointer = ?, idempotency_ttl_seconds = ?, async_execution = ?, max_duration_seconds = ?,
			enabled = ?, updated_at = ?, last_triggered_at = ?, trigger_count = ?
		WHERE id = ?
	`, updated.Name, desc, updated.Target, updated.TeamID, updated.Mode,
		fieldMappings, defaultsJSON, typeCoercions, updated.SecretHash, allowedIPs,
		eventPointer, int64(updated.IdempotencyTTL/time.Second), updated.AsyncExecution, maxDuration,
		updated.Enabled, updated.UpdatedAt, lastTriggered, updated.TriggerCount, triggerID)
	if err != nil {
		return nil, fmt.Errorf("update webhook trigger: %w", err)
	}

	return updated, nil
}

// DeleteWebhookTrigger removes a trigger and its deliveries.
func (ls *LocalStorage) DeleteWebhookTrigger(ctx context.Context, triggerID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if strings.TrimSpace(triggerID) == "" {
		return fmt.Errorf("trigger id is required")
	}

	tx, err := ls.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin delete webhook trigger: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM webhook_deliveries WHERE trigger_id = ?`, triggerID); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("delete webhook deliveries: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM webhook_triggers WHERE id = ?`, triggerID); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("delete webhook trigger: %w", err)
	}
	return tx.Commit()
}

// StoreWebhookDelivery records a webhook delivery.
func (ls *LocalStorage) StoreWebhookDelivery(ctx context.Context, delivery *types.WebhookDelivery) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if delivery == nil {
		return fmt.Errorf("webhook delivery is required")
	}
	if strings.TrimSpace(delivery.ID) == "" {
		return fmt.Errorf("delivery id is required")
	}
	if strings.TrimSpace(delivery.TriggerID) == "" {
		return fmt.Errorf("trigger id is required for delivery")
	}
	if strings.TrimSpace(delivery.PayloadHash) == "" {
		return fmt.Errorf("payload hash is required for delivery")
	}

	if delivery.ReceivedAt.IsZero() {
		delivery.ReceivedAt = time.Now().UTC()
	}
	if delivery.PayloadSize == 0 && len(delivery.StoredPayload) > 0 {
		delivery.PayloadSize = len(delivery.StoredPayload)
	}

	signature := sql.NullString{}
	if strings.TrimSpace(delivery.Signature) != "" {
		signature = sql.NullString{String: delivery.Signature, Valid: true}
	}
	timestamp := sql.NullString{}
	if strings.TrimSpace(delivery.Timestamp) != "" {
		timestamp = sql.NullString{String: delivery.Timestamp, Valid: true}
	}
	eventID := sql.NullString{}
	if strings.TrimSpace(delivery.EventID) != "" {
		eventID = sql.NullString{String: delivery.EventID, Valid: true}
	}
	errorCode := sql.NullString{}
	if strings.TrimSpace(delivery.ErrorCode) != "" {
		errorCode = sql.NullString{String: delivery.ErrorCode, Valid: true}
	}
	errorMsg := sql.NullString{}
	if strings.TrimSpace(delivery.ErrorMessage) != "" {
		errorMsg = sql.NullString{String: delivery.ErrorMessage, Valid: true}
	}
	mappedInput := sql.NullString{}
	if strings.TrimSpace(delivery.MappedInputHash) != "" {
		mappedInput = sql.NullString{String: delivery.MappedInputHash, Valid: true}
	}
	executionID := sql.NullString{}
	if strings.TrimSpace(delivery.ExecutionID) != "" {
		executionID = sql.NullString{String: delivery.ExecutionID, Valid: true}
	}
	processedAt := sql.NullTime{}
	if delivery.ProcessedAt != nil && !delivery.ProcessedAt.IsZero() {
		processedAt = sql.NullTime{Time: delivery.ProcessedAt.UTC(), Valid: true}
	}
	durationMS := sql.NullInt64{}
	if delivery.DurationMS != 0 {
		durationMS = sql.NullInt64{Int64: delivery.DurationMS, Valid: true}
	}

	payload := delivery.StoredPayload
	if payload == nil {
		payload = json.RawMessage("null")
	}

	_, err := ls.db.ExecContext(ctx, `
		INSERT INTO webhook_deliveries (
			id, trigger_id, event_id, source_ip, signature, timestamp,
			payload_hash, payload_size, status, error_code, error_message,
			mapped_input_hash, execution_id, received_at, processed_at,
			duration_ms, stored_payload
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, delivery.ID, delivery.TriggerID, eventID, delivery.SourceIP, signature, timestamp,
		delivery.PayloadHash, delivery.PayloadSize, delivery.Status, errorCode, errorMsg,
		mappedInput, executionID, delivery.ReceivedAt.UTC(), processedAt, durationMS, string(payload))
	if err != nil {
		return fmt.Errorf("store webhook delivery: %w", err)
	}

	return nil
}

// FindDeliveryByEventID returns the first delivery for a given trigger/event ID pair.
func (ls *LocalStorage) FindDeliveryByEventID(ctx context.Context, triggerID, eventID string) (*types.WebhookDelivery, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(triggerID) == "" || strings.TrimSpace(eventID) == "" {
		return nil, nil
	}

	row := ls.db.QueryRowContext(ctx, `
		SELECT `+webhookDeliveryColumns+`
		FROM webhook_deliveries
		WHERE trigger_id = ? AND event_id = ?
		LIMIT 1
	`, triggerID, eventID)

	return scanWebhookDelivery(row)
}

// ListWebhookDeliveries returns deliveries for a trigger with optional status and cursor.
func (ls *LocalStorage) ListWebhookDeliveries(ctx context.Context, filters types.WebhookDeliveryFilters) ([]*types.WebhookDelivery, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(filters.TriggerID) == "" {
		return nil, fmt.Errorf("trigger_id is required")
	}

	conditions := []string{"trigger_id = ?"}
	args := []interface{}{filters.TriggerID}

	if filters.Status != nil && strings.TrimSpace(*filters.Status) != "" {
		conditions = append(conditions, "status = ?")
		args = append(args, strings.TrimSpace(*filters.Status))
	}

	if filters.AfterID != nil && strings.TrimSpace(*filters.AfterID) != "" {
		afterID := strings.TrimSpace(*filters.AfterID)
		var receivedAt time.Time
		err := ls.db.QueryRowContext(ctx, `
			SELECT received_at FROM webhook_deliveries WHERE id = ?
		`, afterID).Scan(&receivedAt)
		if err != nil && err != sql.ErrNoRows {
			return nil, fmt.Errorf("lookup after cursor: %w", err)
		}
		if err == nil {
			conditions = append(conditions, "(received_at < ? OR (received_at = ? AND id < ?))")
			args = append(args, receivedAt.UTC(), receivedAt.UTC(), afterID)
		}
	}

	query := `
		SELECT ` + webhookDeliveryColumns + `
		FROM webhook_deliveries`
	if len(conditions) > 0 {
		query += " WHERE " + strings.Join(conditions, " AND ")
	}
	query += " ORDER BY received_at DESC, id DESC LIMIT ?"

	limit := filters.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	args = append(args, limit)

	rows, err := ls.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list webhook deliveries: %w", err)
	}
	defer rows.Close()

	deliveries := make([]*types.WebhookDelivery, 0)
	for rows.Next() {
		delivery, err := scanWebhookDelivery(rows)
		if err != nil {
			return nil, err
		}
		deliveries = append(deliveries, delivery)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate webhook deliveries: %w", err)
	}

	return deliveries, nil
}

func scanWebhookTrigger(scanner interface {
	Scan(dest ...interface{}) error
}) (*types.WebhookTrigger, error) {
	var (
		modelID               string
		name                  string
		description           sql.NullString
		target                string
		teamID                string
		mode                  string
		fieldMappings         sql.NullString
		defaults              sql.NullString
		typeCoercions         sql.NullString
		secretHash            string
		allowedIPs            sql.NullString
		eventIDPointer        sql.NullString
		idempotencyTTLSeconds int64
		asyncExecution        bool
		maxDurationSeconds    sql.NullInt64
		enabled               bool
		createdAt             time.Time
		updatedAt             time.Time
		lastTriggeredAt       sql.NullTime
		triggerCount          int64
	)

	if err := scanner.Scan(
		&modelID, &name, &description, &target, &teamID, &mode,
		&fieldMappings, &defaults, &typeCoercions, &secretHash, &allowedIPs,
		&eventIDPointer, &idempotencyTTLSeconds, &asyncExecution, &maxDurationSeconds,
		&enabled, &createdAt, &updatedAt, &lastTriggeredAt, &triggerCount,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan webhook trigger: %w", err)
	}

	trigger := &types.WebhookTrigger{
		ID:             modelID,
		Name:           name,
		Description:    description.String,
		Target:         target,
		TeamID:         teamID,
		Mode:           types.WebhookMappingMode(mode),
		SecretHash:     secretHash,
		EventIDPointer: eventIDPointer.String,
		IdempotencyTTL: time.Duration(idempotencyTTLSeconds) * time.Second,
		AsyncExecution: asyncExecution,
		Enabled:        enabled,
		CreatedAt:      createdAt.UTC(),
		UpdatedAt:      updatedAt.UTC(),
		TriggerCount:   triggerCount,
	}

	if maxDurationSeconds.Valid {
		trigger.MaxDuration = time.Duration(maxDurationSeconds.Int64) * time.Second
	}
	if lastTriggeredAt.Valid {
		t := lastTriggeredAt.Time.UTC()
		trigger.LastTriggeredAt = &t
	}

	trigger.FieldMappings = decodeStringMap(fieldMappings.String)
	trigger.Defaults = decodeInterfaceMap(defaults.String)
	trigger.TypeCoercions = decodeStringMap(typeCoercions.String)
	trigger.AllowedIPs = decodeStringSlice(allowedIPs.String)

	return trigger, nil
}

func scanWebhookDelivery(scanner interface {
	Scan(dest ...interface{}) error
}) (*types.WebhookDelivery, error) {
	var (
		id              string
		triggerID       string
		eventID         sql.NullString
		sourceIP        string
		signature       sql.NullString
		timestamp       sql.NullString
		payloadHash     string
		payloadSize     int
		status          string
		errorCode       sql.NullString
		errorMessage    sql.NullString
		mappedInputHash sql.NullString
		executionID     sql.NullString
		receivedAt      time.Time
		processedAt     sql.NullTime
		durationMS      sql.NullInt64
		storedPayload   sql.NullString
	)

	if err := scanner.Scan(
		&id, &triggerID, &eventID, &sourceIP, &signature, &timestamp,
		&payloadHash, &payloadSize, &status, &errorCode, &errorMessage,
		&mappedInputHash, &executionID, &receivedAt, &processedAt,
		&durationMS, &storedPayload,
	); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("scan webhook delivery: %w", err)
	}

	delivery := &types.WebhookDelivery{
		ID:              id,
		TriggerID:       triggerID,
		EventID:         eventID.String,
		SourceIP:        sourceIP,
		Signature:       signature.String,
		Timestamp:       timestamp.String,
		PayloadHash:     payloadHash,
		PayloadSize:     payloadSize,
		Status:          status,
		ErrorCode:       errorCode.String,
		ErrorMessage:    errorMessage.String,
		MappedInputHash: mappedInputHash.String,
		ExecutionID:     executionID.String,
		ReceivedAt:      receivedAt.UTC(),
		DurationMS:      durationMS.Int64,
	}

	if processedAt.Valid {
		t := processedAt.Time.UTC()
		delivery.ProcessedAt = &t
	}

	if storedPayload.Valid && strings.TrimSpace(storedPayload.String) != "" {
		delivery.StoredPayload = json.RawMessage(storedPayload.String)
	}

	return delivery, nil
}

func normalizeWebhookTriggerDefaults(trigger *types.WebhookTrigger) {
	if strings.TrimSpace(trigger.TeamID) == "" {
		trigger.TeamID = "default"
	}
	if trigger.Mode == "" {
		trigger.Mode = types.MappingModePassthrough
	}
	if trigger.IdempotencyTTL <= 0 {
		trigger.IdempotencyTTL = 24 * time.Hour
	}
	if trigger.CreatedAt.IsZero() {
		trigger.CreatedAt = time.Now().UTC()
	}
	if trigger.UpdatedAt.IsZero() {
		trigger.UpdatedAt = trigger.CreatedAt
	}
}

func encodeStringMap(m map[string]string) (string, error) {
	if len(m) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("encode string map: %w", err)
	}
	return string(b), nil
}

func encodeInterfaceMap(m map[string]interface{}) (string, error) {
	if len(m) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("encode map: %w", err)
	}
	return string(b), nil
}

func encodeStringSlice(values []string) (string, error) {
	if len(values) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(values)
	if err != nil {
		return "", fmt.Errorf("encode string slice: %w", err)
	}
	return string(b), nil
}

func decodeStringMap(raw string) map[string]string {
	if strings.TrimSpace(raw) == "" {
		return map[string]string{}
	}
	result := make(map[string]string)
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return map[string]string{}
	}
	return result
}

func decodeInterfaceMap(raw string) map[string]interface{} {
	if strings.TrimSpace(raw) == "" {
		return map[string]interface{}{}
	}
	result := make(map[string]interface{})
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return map[string]interface{}{}
	}
	return result
}

func decodeStringSlice(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return []string{}
	}
	var result []string
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return []string{}
	}
	return result
}
