package storage

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestWebhookTriggerCRUDStorage(t *testing.T) {
	ctx := context.Background()
	ls := newTestWebhookStorage(t, ctx)

	trigger := &types.WebhookTrigger{
		ID:             "wht_test",
		Name:           "Test Trigger",
		Target:         "agent.reasoner",
		TeamID:         "team-1",
		Mode:           types.MappingModeRemap,
		FieldMappings:  map[string]string{"foo": "/foo"},
		Defaults:       map[string]interface{}{"bar": "baz"},
		TypeCoercions:  map[string]string{"foo": "int"},
		SecretHash:     "secret_hash_value",
		AllowedIPs:     []string{"127.0.0.1"},
		EventIDPointer: "/headers/X-Request-ID",
		IdempotencyTTL: 2 * time.Hour,
		AsyncExecution: true,
		MaxDuration:    5 * time.Second,
		Enabled:        true,
	}

	require.NoError(t, ls.CreateWebhookTrigger(ctx, trigger))

	stored, err := ls.GetWebhookTrigger(ctx, trigger.ID)
	require.NoError(t, err)
	require.NotNil(t, stored)
	require.Equal(t, trigger.Target, stored.Target)
	require.Equal(t, trigger.Mode, stored.Mode)
	require.Equal(t, trigger.FieldMappings["foo"], stored.FieldMappings["foo"])
	require.Equal(t, trigger.Defaults["bar"], stored.Defaults["bar"])
	require.Equal(t, trigger.IdempotencyTTL, stored.IdempotencyTTL)
	require.Equal(t, trigger.AllowedIPs, stored.AllowedIPs)
	require.Equal(t, trigger.MaxDuration, stored.MaxDuration)

	list, err := ls.ListWebhookTriggers(ctx, types.WebhookTriggerFilters{TeamID: &trigger.TeamID})
	require.NoError(t, err)
	require.Len(t, list, 1)

	updated, err := ls.UpdateWebhookTrigger(ctx, trigger.ID, func(tg *types.WebhookTrigger) (*types.WebhookTrigger, error) {
		tg.Enabled = false
		tg.FieldMappings["url"] = "/url"
		return tg, nil
	})
	require.NoError(t, err)
	require.NotNil(t, updated)
	require.False(t, updated.Enabled)
	require.Contains(t, updated.FieldMappings, "url")

	disabled := false
	listDisabled, err := ls.ListWebhookTriggers(ctx, types.WebhookTriggerFilters{Enabled: &disabled})
	require.NoError(t, err)
	require.Len(t, listDisabled, 1)
}

func TestWebhookDeliveryStoreAndList(t *testing.T) {
	ctx := context.Background()
	ls := newTestWebhookStorage(t, ctx)

	trigger := &types.WebhookTrigger{
		ID:             "wht_delivery",
		Name:           "Delivery Trigger",
		Target:         "agent.reasoner",
		SecretHash:     "secret_hash",
		AsyncExecution: true,
	}
	require.NoError(t, ls.CreateWebhookTrigger(ctx, trigger))

	now := time.Now().UTC()
	payload := json.RawMessage(`{"hello":"world"}`)

	accepted := &types.WebhookDelivery{
		ID:            "whd_1",
		TriggerID:     trigger.ID,
		EventID:       "evt-1",
		SourceIP:      "1.1.1.1",
		Signature:     "sig",
		Timestamp:     "12345",
		PayloadHash:   "sha256:abc",
		Status:        "accepted",
		ReceivedAt:    now,
		StoredPayload: payload,
	}
	require.NoError(t, ls.StoreWebhookDelivery(ctx, accepted))

	failed := &types.WebhookDelivery{
		ID:            "whd_2",
		TriggerID:     trigger.ID,
		EventID:       "evt-2",
		SourceIP:      "1.1.1.1",
		PayloadHash:   "sha256:def",
		Status:        "failed",
		ReceivedAt:    now.Add(-time.Minute),
		StoredPayload: payload,
		ErrorCode:     "mapping_failed",
	}
	require.NoError(t, ls.StoreWebhookDelivery(ctx, failed))

	found, err := ls.FindDeliveryByEventID(ctx, trigger.ID, "evt-1")
	require.NoError(t, err)
	require.NotNil(t, found)
	require.Equal(t, "whd_1", found.ID)

	statusAccepted := "accepted"
	acceptedList, err := ls.ListWebhookDeliveries(ctx, types.WebhookDeliveryFilters{
		TriggerID: trigger.ID,
		Status:    &statusAccepted,
		Limit:     10,
	})
	require.NoError(t, err)
	require.Len(t, acceptedList, 1)
	require.Equal(t, "whd_1", acceptedList[0].ID)

	afterID := accepted.ID
	older, err := ls.ListWebhookDeliveries(ctx, types.WebhookDeliveryFilters{
		TriggerID: trigger.ID,
		AfterID:   &afterID,
	})
	require.NoError(t, err)
	require.Len(t, older, 1)
	require.Equal(t, "whd_2", older[0].ID)

	require.Greater(t, accepted.PayloadSize, 0)
}

func newTestWebhookStorage(t *testing.T, ctx context.Context) *LocalStorage {
	t.Helper()
	tempDir := t.TempDir()
	cfg := StorageConfig{
		Mode: "local",
		Local: LocalStorageConfig{
			DatabasePath: filepath.Join(tempDir, "agentfield.db"),
			KVStorePath:  filepath.Join(tempDir, "agentfield.bolt"),
		},
	}

	ls := NewLocalStorage(LocalStorageConfig{})
	if err := ls.Initialize(ctx, cfg); err != nil {
		if strings.Contains(err.Error(), "no such module: fts5") {
			t.Skip("sqlite3 compiled without FTS5; skipping webhook storage test")
		}
		require.NoError(t, err)
	}
	t.Cleanup(func() {
		_ = ls.Close(ctx)
	})
	return ls
}
