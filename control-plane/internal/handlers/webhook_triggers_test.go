package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

func TestWebhookIdempotencyTTLExpiryAllowsReprocess(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := newLocalTestStorage(t)
	router := gin.New()
	api := router.Group("/api/v1")
	NewWebhookHandlers(store).RegisterRoutes(api)

	createPayload := `{
		"name": "ttl-webhook",
		"target": "github-bot.review_pull_request",
		"mode": "remap",
		"field_mappings": { "id": "/id" },
		"event_id_pointer": "/id",
		"idempotency_ttl": "1ms",
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

	body := []byte(`{"id":"evt-ttl","message":"hello"}`)
	firstTimestamp := time.Now().UTC().Format("20060102150405")
	firstSig, err := webhooks.ComputeSignature(secret, firstTimestamp, body)
	require.NoError(t, err)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/"+triggerID, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AF-Timestamp", firstTimestamp)
	req.Header.Set("X-AF-Signature", firstSig)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code)

	var firstResp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &firstResp))
	firstDeliveryID := firstResp["delivery_id"].(string)

	time.Sleep(10 * time.Millisecond)

	secondTimestamp := time.Now().UTC().Format("20060102150405")
	secondSig, err := webhooks.ComputeSignature(secret, secondTimestamp, body)
	require.NoError(t, err)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/webhooks/"+triggerID, bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-AF-Timestamp", secondTimestamp)
	req.Header.Set("X-AF-Signature", secondSig)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusAccepted, rec.Code)

	var secondResp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &secondResp))
	require.Equal(t, "accepted", secondResp["status"])
	secondDeliveryID := secondResp["delivery_id"].(string)
	require.NotEqual(t, firstDeliveryID, secondDeliveryID, "should allocate a fresh delivery after TTL expiry")

	req = httptest.NewRequest(http.MethodGet, "/api/v1/webhook-triggers/"+triggerID+"/deliveries", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var deliveriesResp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &deliveriesResp))
	deliveries, ok := deliveriesResp["deliveries"].([]interface{})
	require.True(t, ok)
	require.Equal(t, 1, len(deliveries), "expired idempotency entry should be evicted before new delivery")
	deliveryObj, ok := deliveries[0].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, secondDeliveryID, deliveryObj["id"])
}

func TestTriggerExampleIncludesMappingPreview(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := newLocalTestStorage(t)
	router := gin.New()
	api := router.Group("/api/v1")
	NewWebhookHandlers(store).RegisterRoutes(api)

	createPayload := `{
		"name": "example-preview",
		"target": "github-bot.review_pull_request",
		"mode": "remap",
		"field_mappings": {
			"url": "/pull_request/diff_url",
			"repo": "/repository/full_name",
			"pr_number": "/pull_request/number"
		},
		"defaults": {
			"auto_merge": false
		},
		"type_coercions": {
			"pr_number": "int"
		},
		"event_id_pointer": "/headers/X-Delivery",
		"async_execution": true
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhook-triggers", bytes.NewBufferString(createPayload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var createResp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &createResp))
	triggerID := createResp["trigger_id"].(string)

	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/v1/webhook-triggers/%s/example", triggerID), nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var exampleResp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &exampleResp))

	preview, ok := exampleResp["mapped_input_preview"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "org/repo", preview["repo"])
	require.EqualValues(t, 42, preview["pr_number"])
	require.Equal(t, false, preview["auto_merge"])

	reqExample, ok := exampleResp["request_example"].(map[string]interface{})
	require.True(t, ok)

	body, ok := reqExample["body"].(map[string]interface{})
	require.True(t, ok)
	repo, ok := body["repository"].(map[string]interface{})
	require.True(t, ok)
	require.Equal(t, "org/repo", repo["full_name"])

	headers, ok := reqExample["headers"].(map[string]interface{})
	require.True(t, ok)
	require.NotEmpty(t, headers["X-AF-Signature"])
	require.Equal(t, exampleSignatureTimestamp, headers["X-AF-Timestamp"])
}

func TestWebhookRotateSecret(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := newLocalTestStorage(t)
	router := gin.New()
	api := router.Group("/api/v1")
	NewWebhookHandlers(store).RegisterRoutes(api)

	createPayload := `{
		"name": "rotate-secret",
		"target": "github-bot.review_pull_request",
		"mode": "passthrough",
		"async_execution": true
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhook-triggers", bytes.NewBufferString(createPayload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var createResp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &createResp))
	triggerID := createResp["trigger_id"].(string)
	initialSecret := createResp["secret"].(string)

	req = httptest.NewRequest(http.MethodPost, "/api/v1/webhook-triggers/"+triggerID+"/rotate-secret", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var rotateResp map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &rotateResp))
	newSecret := rotateResp["new_secret"].(string)
	require.NotEqual(t, initialSecret, newSecret)
	require.NotEmpty(t, rotateResp["rotated_at"])

	stored, err := store.GetWebhookTrigger(context.Background(), triggerID)
	require.NoError(t, err)
	require.Equal(t, newSecret, stored.SecretHash)
	require.True(t, stored.UpdatedAt.After(stored.CreatedAt))
}

func TestShellEscapeSingleQuotes(t *testing.T) {
	in := "a'b c'd"
	out := shellEscapeSingleQuotes(in)
	require.Equal(t, "a'\"'\"'b c'\"'\"'d", out)
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
