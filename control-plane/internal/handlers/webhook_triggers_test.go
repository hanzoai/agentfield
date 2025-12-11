package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Agent-Field/agentfield/control-plane/internal/storage"
	"github.com/Agent-Field/agentfield/control-plane/internal/webhooks"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestWebhookTriggerLifecycleAndReceiver(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := newLocalTestStorage(t)
	router := gin.New()
	api := router.Group("/api/v1")
	NewWebhookHandlers(store).RegisterRoutes(api)

	createPayload := `{
		"name": "github-pr-webhook",
		"target": "github-bot.review_pull_request",
		"mode": "remap",
		"field_mappings": { "id": "/id" },
		"event_id_pointer": "/id",
		"idempotency_ttl": "24h",
		"async_execution": true,
		"enabled": true
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhook-triggers", bytes.NewBufferString(createPayload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var createResp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &createResp))
	triggerID := createResp["trigger_id"].(string)
	secret := createResp["secret"].(string)

	// Fetch example
	req = httptest.NewRequest(http.MethodGet, "/api/v1/webhook-triggers/"+triggerID+"/example", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// Receive webhook with valid signature
	body := []byte(`{"id":"evt-123","hello":"world"}`)
	timestamp := time.Now().UTC().Format("20060102150405")
	sig, err := webhooks.ComputeSignature(secret, timestamp, body)
	require.NoError(t, err)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/"+triggerID, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AF-Timestamp", timestamp)
	req.Header.Set("X-AF-Signature", sig)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code)

	// Duplicate should be detected
	req = httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/"+triggerID, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AF-Timestamp", timestamp)
	req.Header.Set("X-AF-Signature", sig)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// Invalid signature
	req = httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/"+triggerID, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AF-Timestamp", timestamp)
	req.Header.Set("X-AF-Signature", "sha256=deadbeef")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func newLocalTestStorage(t *testing.T) storage.StorageProvider {
	t.Helper()
	tempDir := t.TempDir()
	cfg := storage.StorageConfig{
		Mode: "local",
		Local: storage.LocalStorageConfig{
			DatabasePath: filepath.Join(tempDir, "agentfield.db"),
			KVStorePath:  filepath.Join(tempDir, "agentfield.bolt"),
		},
	}
	ls := storage.NewLocalStorage(storage.LocalStorageConfig{})
	if err := ls.Initialize(context.Background(), cfg); err != nil {
		if strings.Contains(err.Error(), "no such module: fts5") {
			t.Skip("sqlite3 without FTS5 support; skipping webhook trigger handler test")
		}
		require.NoError(t, err)
	}
	t.Cleanup(func() { _ = ls.Close(context.Background()) })
	return ls
}
