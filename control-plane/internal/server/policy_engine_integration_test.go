package server

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Agent-Field/agentfield/control-plane/internal/handlers/admin"
	"github.com/Agent-Field/agentfield/control-plane/internal/server/middleware"
	"github.com/Agent-Field/agentfield/control-plane/internal/services"
	"github.com/Agent-Field/agentfield/control-plane/internal/storage"
	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// testKeyStorage implements storage.APIKeyStorage for integration testing.
// Uses direct SQL to avoid needing access to LocalStorage internals.
type testKeyStorage struct {
	db *sql.DB
}

func (s *testKeyStorage) CreateKey(ctx context.Context, req types.APIKeyCreateRequest) (*types.APIKey, string, error) {
	keyID := storage.GenerateKeyID()
	plainKey, err := storage.GenerateAPIKey("sk")
	if err != nil {
		return nil, "", err
	}

	keyHash, err := storage.HashAPIKey(plainKey)
	if err != nil {
		return nil, "", err
	}

	scopes := req.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	scopesJSON, _ := json.Marshal(scopes)

	now := time.Now()
	key := &types.APIKey{
		ID:          keyID,
		Name:        req.Name,
		KeyHash:     keyHash,
		Scopes:      scopes,
		Description: req.Description,
		Enabled:     true,
		CreatedAt:   now,
		ExpiresAt:   req.ExpiresAt,
	}

	var expiresAtStr interface{} = nil
	if req.ExpiresAt != nil {
		expiresAtStr = req.ExpiresAt.Format(time.RFC3339)
	}

	_, err = s.db.ExecContext(ctx,
		`INSERT INTO api_keys (id, name, key_hash, scopes, description, enabled, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, 1, ?, ?)`,
		key.ID, key.Name, key.KeyHash, string(scopesJSON), key.Description, now.Format(time.RFC3339), expiresAtStr,
	)
	if err != nil {
		return nil, "", err
	}

	return key, plainKey, nil
}

func (s *testKeyStorage) GetKeyByID(ctx context.Context, id string) (*types.APIKey, error) {
	return s.scanKey(s.db.QueryRowContext(ctx,
		`SELECT id, name, key_hash, scopes, description, enabled, created_at, expires_at, last_used_at
		 FROM api_keys WHERE id = ?`, id))
}

func (s *testKeyStorage) GetKeyByName(ctx context.Context, name string) (*types.APIKey, error) {
	return s.scanKey(s.db.QueryRowContext(ctx,
		`SELECT id, name, key_hash, scopes, description, enabled, created_at, expires_at, last_used_at
		 FROM api_keys WHERE name = ?`, name))
}

func (s *testKeyStorage) VerifyKey(ctx context.Context, plainKey string) (*types.APIKey, error) {
	// Query all keys (including disabled) so the middleware can check the enabled status
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, key_hash, scopes, description, enabled, created_at, expires_at, last_used_at
		 FROM api_keys`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		key, err := s.scanKeyFromRows(rows)
		if err != nil {
			continue
		}
		if storage.VerifyAPIKeyHash(plainKey, key.KeyHash) {
			return key, nil // Return key regardless of enabled status
		}
	}
	return nil, sql.ErrNoRows
}

func (s *testKeyStorage) ListKeys(ctx context.Context) ([]*types.APIKey, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, key_hash, scopes, description, enabled, created_at, expires_at, last_used_at
		 FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*types.APIKey
	for rows.Next() {
		key, err := s.scanKeyFromRows(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func (s *testKeyStorage) UpdateKeyLastUsed(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE api_keys SET last_used_at = ? WHERE id = ?`, time.Now().Format(time.RFC3339), id)
	return err
}

func (s *testKeyStorage) DeleteKey(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM api_keys WHERE id = ?`, id)
	return err
}

func (s *testKeyStorage) DisableKey(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE api_keys SET enabled = 0 WHERE id = ?`, id)
	return err
}

func (s *testKeyStorage) EnableKey(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE api_keys SET enabled = 1 WHERE id = ?`, id)
	return err
}

func (s *testKeyStorage) scanKey(row *sql.Row) (*types.APIKey, error) {
	key := &types.APIKey{}
	var scopesRaw string
	var description, expiresAt, lastUsedAt sql.NullString
	var enabledInt int
	var createdAtStr string

	err := row.Scan(&key.ID, &key.Name, &key.KeyHash, &scopesRaw, &description, &enabledInt, &createdAtStr, &expiresAt, &lastUsedAt)
	if err != nil {
		return nil, err
	}

	key.Enabled = enabledInt == 1
	key.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)
	if description.Valid {
		key.Description = description.String
	}
	if expiresAt.Valid && expiresAt.String != "" {
		t, _ := time.Parse(time.RFC3339, expiresAt.String)
		key.ExpiresAt = &t
	}
	if lastUsedAt.Valid && lastUsedAt.String != "" {
		t, _ := time.Parse(time.RFC3339, lastUsedAt.String)
		key.LastUsedAt = &t
	}
	json.Unmarshal([]byte(scopesRaw), &key.Scopes)

	return key, nil
}

func (s *testKeyStorage) scanKeyFromRows(rows *sql.Rows) (*types.APIKey, error) {
	key := &types.APIKey{}
	var scopesRaw string
	var description, expiresAt, lastUsedAt sql.NullString
	var enabledInt int
	var createdAtStr string

	err := rows.Scan(&key.ID, &key.Name, &key.KeyHash, &scopesRaw, &description, &enabledInt, &createdAtStr, &expiresAt, &lastUsedAt)
	if err != nil {
		return nil, err
	}

	key.Enabled = enabledInt == 1
	key.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)
	if description.Valid {
		key.Description = description.String
	}
	if expiresAt.Valid && expiresAt.String != "" {
		t, _ := time.Parse(time.RFC3339, expiresAt.String)
		key.ExpiresAt = &t
	}
	if lastUsedAt.Valid && lastUsedAt.String != "" {
		t, _ := time.Parse(time.RFC3339, lastUsedAt.String)
		key.LastUsedAt = &t
	}
	json.Unmarshal([]byte(scopesRaw), &key.Scopes)

	return key, nil
}

// testAuditStorage implements storage.AccessAuditStorage for integration testing.
type testAuditStorage struct {
	db *sql.DB
}

func (s *testAuditStorage) LogAccessDecision(ctx context.Context, entry types.AccessAuditEntry) error {
	agentTagsJSON, _ := json.Marshal(entry.AgentTags)
	keyScopesJSON, _ := json.Marshal(entry.KeyScopes)

	allowedInt := 0
	if entry.Allowed {
		allowedInt = 1
	}

	_, err := s.db.ExecContext(ctx,
		`INSERT INTO access_audit_log (api_key_id, api_key_name, target_agent, target_reasoner, agent_tags, key_scopes, allowed, deny_reason)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.APIKeyID, entry.APIKeyName, entry.TargetAgent, entry.TargetReasoner,
		string(agentTagsJSON), string(keyScopesJSON), allowedInt, entry.DenyReason,
	)
	return err
}

func (s *testAuditStorage) ListAccessAuditEntries(ctx context.Context, filters storage.AccessAuditFilters) ([]*types.AccessAuditEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, timestamp, api_key_id, api_key_name, target_agent, target_reasoner, agent_tags, key_scopes, allowed, deny_reason FROM access_audit_log`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*types.AccessAuditEntry
	for rows.Next() {
		e := &types.AccessAuditEntry{}
		var tsStr, agentTagsRaw, keyScopesRaw string
		var targetReasoner, denyReason sql.NullString
		var allowedInt int

		rows.Scan(&e.ID, &tsStr, &e.APIKeyID, &e.APIKeyName, &e.TargetAgent, &targetReasoner, &agentTagsRaw, &keyScopesRaw, &allowedInt, &denyReason)
		e.Timestamp, _ = time.Parse(time.RFC3339, tsStr)
		e.Allowed = allowedInt == 1
		if targetReasoner.Valid {
			e.TargetReasoner = targetReasoner.String
		}
		if denyReason.Valid {
			e.DenyReason = denyReason.String
		}
		json.Unmarshal([]byte(agentTagsRaw), &e.AgentTags)
		json.Unmarshal([]byte(keyScopesRaw), &e.KeyScopes)

		entries = append(entries, e)
	}
	return entries, nil
}

// testServer holds the components for integration testing.
type testServer struct {
	router       *gin.Engine
	keyStorage   *testKeyStorage
	auditStorage *testAuditStorage
	accessCtrl   *services.AccessControlService
	db           *sql.DB
	tmpFile      string
	masterKey    string
	scopeGroups  map[string]types.ScopeGroup
	propagSecret []byte
}

// setupIntegrationTest creates a full test server with real SQLite storage.
func setupIntegrationTest(t *testing.T) *testServer {
	t.Helper()

	// Create temp SQLite DB
	tmpFile, err := os.CreateTemp("", "policy_integration_*.db")
	require.NoError(t, err)
	tmpFile.Close()

	db, err := sql.Open("sqlite3", tmpFile.Name())
	require.NoError(t, err)

	// Create schema
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS api_keys (
			id              TEXT PRIMARY KEY,
			name            TEXT NOT NULL UNIQUE,
			key_hash        TEXT NOT NULL,
			scopes          TEXT NOT NULL DEFAULT '[]',
			description     TEXT,
			enabled         INTEGER NOT NULL DEFAULT 1,
			created_at      TEXT NOT NULL,
			expires_at      TEXT,
			last_used_at    TEXT
		);
		CREATE TABLE IF NOT EXISTS access_audit_log (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp       TEXT NOT NULL DEFAULT (datetime('now')),
			api_key_id      TEXT NOT NULL,
			api_key_name    TEXT NOT NULL,
			target_agent    TEXT NOT NULL,
			target_reasoner TEXT,
			agent_tags      TEXT NOT NULL DEFAULT '[]',
			key_scopes      TEXT NOT NULL DEFAULT '[]',
			allowed         INTEGER NOT NULL,
			deny_reason     TEXT
		);
	`)
	require.NoError(t, err)

	keyStorage := &testKeyStorage{db: db}
	auditStorage := &testAuditStorage{db: db}

	scopeGroups := map[string]types.ScopeGroup{
		"financial": {
			Name: "financial",
			Tags: []string{"finance", "billing", "payment"},
		},
	}

	accessCtrl := services.NewAccessControlService(true, auditStorage, scopeGroups)

	ts := &testServer{
		keyStorage:   keyStorage,
		auditStorage: auditStorage,
		accessCtrl:   accessCtrl,
		db:           db,
		tmpFile:      tmpFile.Name(),
		masterKey:    "master-secret-key",
		scopeGroups:  scopeGroups,
		propagSecret: []byte("propagation-secret-32bytes!!!!"),
	}

	ts.setupRouter()
	return ts
}

func (ts *testServer) cleanup() {
	ts.db.Close()
	os.Remove(ts.tmpFile)
}

func (ts *testServer) setupRouter() {
	router := gin.New()

	// Auth middleware
	authConfig := middleware.AuthConfig{
		MasterAPIKey:      ts.masterKey,
		KeyStorage:        ts.keyStorage,
		PropagationSecret: ts.propagSecret,
		ScopeGroups:       ts.scopeGroups,
	}

	// Public routes
	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// Protected routes
	api := router.Group("/api/v1")
	api.Use(middleware.APIKeyAuth(authConfig))
	{
		// Test endpoint that returns auth context
		api.GET("/auth-info", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"key_id":   middleware.GetKeyID(c),
				"key_name": middleware.GetKeyName(c),
				"scopes":   middleware.GetKeyScopes(c),
				"is_super": middleware.IsSuperKey(c),
			})
		})

		// Test endpoint that checks access
		api.POST("/check-agent-access", func(c *gin.Context) {
			var req struct {
				AgentID   string   `json:"agent_id"`
				AgentTags []string `json:"agent_tags"`
			}
			if err := c.ShouldBindJSON(&req); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}

			decision := ts.accessCtrl.CheckAccess(
				c.Request.Context(),
				middleware.GetKeyID(c),
				middleware.GetKeyName(c),
				middleware.GetKeyScopes(c),
				req.AgentID, "",
				req.AgentTags,
			)

			c.JSON(http.StatusOK, decision)
		})

		// Admin routes
		adminGroup := api.Group("/admin")
		adminGroup.Use(admin.RequireSuperKey())
		{
			handlers := admin.NewKeyHandlers(ts.keyStorage)
			adminGroup.GET("/keys", handlers.ListKeys)
			adminGroup.POST("/keys", handlers.CreateKey)
			adminGroup.GET("/keys/:id", handlers.GetKey)
			adminGroup.DELETE("/keys/:id", handlers.DeleteKey)
			adminGroup.POST("/keys/:id/disable", handlers.DisableKey)
			adminGroup.POST("/keys/:id/enable", handlers.EnableKey)
		}
	}

	ts.router = router
}

// makeRequest is a helper for making HTTP requests.
func (ts *testServer) makeRequest(method, path, apiKey string, body interface{}) *httptest.ResponseRecorder {
	var reqBody *bytes.Buffer
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewBuffer(b)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}

	req := httptest.NewRequest(method, path, reqBody)
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}

	w := httptest.NewRecorder()
	ts.router.ServeHTTP(w, req)
	return w
}

// Direct DB helper for tests (bypasses storage layer for setup)
func (ts *testServer) createKeyDirect(name string, scopes []string, enabled bool, expiresAt *time.Time) (string, string) {
	keyID := storage.GenerateKeyID()
	plainKey, _ := storage.GenerateAPIKey("sk")
	hash, _ := storage.HashAPIKey(plainKey)

	scopesJSON, _ := json.Marshal(scopes)

	var expiresAtStr interface{} = nil
	if expiresAt != nil {
		expiresAtStr = expiresAt.Format(time.RFC3339)
	}

	enabledInt := 0
	if enabled {
		enabledInt = 1
	}

	_, err := ts.db.Exec(
		`INSERT INTO api_keys (id, name, key_hash, scopes, enabled, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		keyID, name, hash, string(scopesJSON), enabledInt, time.Now().Format(time.RFC3339), expiresAtStr,
	)
	if err != nil {
		panic(err)
	}

	return keyID, plainKey
}

// =============================================================================
// Integration Tests
// =============================================================================

func TestIntegration_MasterKeyAuth(t *testing.T) {
	ts := setupIntegrationTest(t)
	defer ts.cleanup()

	t.Run("master key grants super access", func(t *testing.T) {
		w := ts.makeRequest("GET", "/api/v1/auth-info", ts.masterKey, nil)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)

		assert.Equal(t, "master", resp["key_id"])
		assert.Equal(t, "master", resp["key_name"])
		assert.True(t, resp["is_super"].(bool))
	})

	t.Run("master key can access admin endpoints", func(t *testing.T) {
		w := ts.makeRequest("GET", "/api/v1/admin/keys", ts.masterKey, nil)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestIntegration_ScopedKeyAuth(t *testing.T) {
	ts := setupIntegrationTest(t)
	defer ts.cleanup()

	// Create a scoped key
	keyID, plainKey := ts.createKeyDirect("finance-key", []string{"finance", "billing"}, true, nil)

	t.Run("scoped key sets correct context", func(t *testing.T) {
		w := ts.makeRequest("GET", "/api/v1/auth-info", plainKey, nil)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)

		assert.Equal(t, keyID, resp["key_id"])
		assert.Equal(t, "finance-key", resp["key_name"])
		assert.False(t, resp["is_super"].(bool))

		scopes := resp["scopes"].([]interface{})
		assert.Len(t, scopes, 2)
	})

	t.Run("scoped key cannot access admin endpoints", func(t *testing.T) {
		w := ts.makeRequest("GET", "/api/v1/admin/keys", plainKey, nil)
		assert.Equal(t, http.StatusForbidden, w.Code)
	})
}

func TestIntegration_DisabledKeyRejected(t *testing.T) {
	ts := setupIntegrationTest(t)
	defer ts.cleanup()

	// Create and disable a key
	_, plainKey := ts.createKeyDirect("disabled-key", []string{"test"}, false, nil)

	w := ts.makeRequest("GET", "/api/v1/auth-info", plainKey, nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "disabled")
}

func TestIntegration_ExpiredKeyRejected(t *testing.T) {
	ts := setupIntegrationTest(t)
	defer ts.cleanup()

	// Create an expired key
	past := time.Now().Add(-time.Hour)
	_, plainKey := ts.createKeyDirect("expired-key", []string{"test"}, true, &past)

	w := ts.makeRequest("GET", "/api/v1/auth-info", plainKey, nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "expired")
}

func TestIntegration_InvalidKeyRejected(t *testing.T) {
	ts := setupIntegrationTest(t)
	defer ts.cleanup()

	w := ts.makeRequest("GET", "/api/v1/auth-info", "invalid-key", nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestIntegration_NoKeyRejected(t *testing.T) {
	ts := setupIntegrationTest(t)
	defer ts.cleanup()

	w := ts.makeRequest("GET", "/api/v1/auth-info", "", nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]string
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Contains(t, resp["message"], "missing")
}

func TestIntegration_PublicEndpointNoAuth(t *testing.T) {
	ts := setupIntegrationTest(t)
	defer ts.cleanup()

	w := ts.makeRequest("GET", "/health", "", nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestIntegration_AccessControlDecision(t *testing.T) {
	ts := setupIntegrationTest(t)
	defer ts.cleanup()

	// Create a scoped key
	_, plainKey := ts.createKeyDirect("access-test-key", []string{"finance"}, true, nil)

	t.Run("allows access to matching tag", func(t *testing.T) {
		body := map[string]interface{}{
			"agent_id":   "finance-agent",
			"agent_tags": []string{"finance", "internal"},
		}

		w := ts.makeRequest("POST", "/api/v1/check-agent-access", plainKey, body)
		assert.Equal(t, http.StatusOK, w.Code)

		var decision types.AccessDecision
		json.Unmarshal(w.Body.Bytes(), &decision)

		assert.True(t, decision.Allowed)
		assert.Contains(t, decision.MatchedOn, "finance")
	})

	t.Run("denies access to non-matching tag", func(t *testing.T) {
		body := map[string]interface{}{
			"agent_id":   "hr-agent",
			"agent_tags": []string{"hr", "personnel"},
		}

		w := ts.makeRequest("POST", "/api/v1/check-agent-access", plainKey, body)
		assert.Equal(t, http.StatusOK, w.Code)

		var decision types.AccessDecision
		json.Unmarshal(w.Body.Bytes(), &decision)

		assert.False(t, decision.Allowed)
		assert.Equal(t, "no matching tags", decision.DenyReason)
	})
}

func TestIntegration_SuperKeyAccessAll(t *testing.T) {
	ts := setupIntegrationTest(t)
	defer ts.cleanup()

	// Create a super key (empty scopes)
	_, plainKey := ts.createKeyDirect("super-test-key", []string{}, true, nil)

	body := map[string]interface{}{
		"agent_id":   "any-agent",
		"agent_tags": []string{"random", "tags"},
	}

	w := ts.makeRequest("POST", "/api/v1/check-agent-access", plainKey, body)
	assert.Equal(t, http.StatusOK, w.Code)

	var decision types.AccessDecision
	json.Unmarshal(w.Body.Bytes(), &decision)

	assert.True(t, decision.Allowed)
	assert.Equal(t, "*", decision.MatchedOn)
}

func TestIntegration_ScopeGroupExpansion(t *testing.T) {
	ts := setupIntegrationTest(t)
	defer ts.cleanup()

	// Create a key with @financial scope group
	_, plainKey := ts.createKeyDirect("group-key", []string{"@financial"}, true, nil)

	t.Run("scope group expands to match", func(t *testing.T) {
		body := map[string]interface{}{
			"agent_id":   "billing-agent",
			"agent_tags": []string{"billing"},
		}

		w := ts.makeRequest("POST", "/api/v1/check-agent-access", plainKey, body)
		assert.Equal(t, http.StatusOK, w.Code)

		var decision types.AccessDecision
		json.Unmarshal(w.Body.Bytes(), &decision)

		assert.True(t, decision.Allowed)
	})

	t.Run("scope group does not match outside tags", func(t *testing.T) {
		body := map[string]interface{}{
			"agent_id":   "hr-agent",
			"agent_tags": []string{"hr"},
		}

		w := ts.makeRequest("POST", "/api/v1/check-agent-access", plainKey, body)
		assert.Equal(t, http.StatusOK, w.Code)

		var decision types.AccessDecision
		json.Unmarshal(w.Body.Bytes(), &decision)

		assert.False(t, decision.Allowed)
	})
}

func TestIntegration_WildcardPatterns(t *testing.T) {
	ts := setupIntegrationTest(t)
	defer ts.cleanup()

	// Create key with prefix wildcard
	_, prefixKey := ts.createKeyDirect("prefix-key", []string{"finance*"}, true, nil)

	// Create key with suffix wildcard
	_, suffixKey := ts.createKeyDirect("suffix-key", []string{"*-internal"}, true, nil)

	t.Run("prefix wildcard matches", func(t *testing.T) {
		body := map[string]interface{}{
			"agent_id":   "test-agent",
			"agent_tags": []string{"finance-department"},
		}

		w := ts.makeRequest("POST", "/api/v1/check-agent-access", prefixKey, body)
		var decision types.AccessDecision
		json.Unmarshal(w.Body.Bytes(), &decision)

		assert.True(t, decision.Allowed)
	})

	t.Run("suffix wildcard matches", func(t *testing.T) {
		body := map[string]interface{}{
			"agent_id":   "test-agent",
			"agent_tags": []string{"hr-internal"},
		}

		w := ts.makeRequest("POST", "/api/v1/check-agent-access", suffixKey, body)
		var decision types.AccessDecision
		json.Unmarshal(w.Body.Bytes(), &decision)

		assert.True(t, decision.Allowed)
	})
}

func TestIntegration_KeyPropagation(t *testing.T) {
	ts := setupIntegrationTest(t)
	defer ts.cleanup()

	// Create a scoped key
	keyID, plainKey := ts.createKeyDirect("propagation-key", []string{"finance"}, true, nil)

	t.Run("propagated headers work", func(t *testing.T) {
		// First, authenticate normally to get context
		w := ts.makeRequest("GET", "/api/v1/auth-info", plainKey, nil)
		require.Equal(t, http.StatusOK, w.Code)

		// Now create a request with propagated headers
		scopes := []string{"finance"}
		scopesJSON, _ := json.Marshal(scopes)
		timestamp := time.Now().UTC().Format(time.RFC3339)

		// Create HMAC signature
		req := httptest.NewRequest("GET", "/api/v1/auth-info", nil)
		middleware.PropagateKeyContextFromValues(req, keyID, "propagation-key", scopes, ts.propagSecret)

		// Make request
		w2 := httptest.NewRecorder()
		ts.router.ServeHTTP(w2, req)

		assert.Equal(t, http.StatusOK, w2.Code)

		var resp map[string]interface{}
		json.Unmarshal(w2.Body.Bytes(), &resp)

		assert.Equal(t, keyID, resp["key_id"])
		assert.Equal(t, "propagation-key", resp["key_name"])

		// Verify scopes from context - need to handle the JSON properly
		_ = scopesJSON
		_ = timestamp
	})
}

func TestIntegration_AdminKeyManagement(t *testing.T) {
	ts := setupIntegrationTest(t)
	defer ts.cleanup()

	t.Run("create key via API", func(t *testing.T) {
		body := types.APIKeyCreateRequest{
			Name:        "api-created-key",
			Scopes:      []string{"test"},
			Description: "Created via API",
		}

		w := ts.makeRequest("POST", "/api/v1/admin/keys", ts.masterKey, body)
		assert.Equal(t, http.StatusCreated, w.Code)

		var resp struct {
			Key      types.APIKeyResponse `json:"key"`
			KeyValue string               `json:"key_value"`
		}
		json.Unmarshal(w.Body.Bytes(), &resp)

		assert.Equal(t, "api-created-key", resp.Key.Name)
		assert.NotEmpty(t, resp.KeyValue)

		// Verify the created key works
		w2 := ts.makeRequest("GET", "/api/v1/auth-info", resp.KeyValue, nil)
		assert.Equal(t, http.StatusOK, w2.Code)
	})

	t.Run("full key lifecycle", func(t *testing.T) {
		// Create
		createBody := types.APIKeyCreateRequest{
			Name:   "lifecycle-key",
			Scopes: []string{"test"},
		}
		w := ts.makeRequest("POST", "/api/v1/admin/keys", ts.masterKey, createBody)
		require.Equal(t, http.StatusCreated, w.Code)

		var createResp struct {
			Key      types.APIKeyResponse `json:"key"`
			KeyValue string               `json:"key_value"`
		}
		json.Unmarshal(w.Body.Bytes(), &createResp)
		keyID := createResp.Key.ID
		keyValue := createResp.KeyValue

		// Verify key works
		w = ts.makeRequest("GET", "/api/v1/auth-info", keyValue, nil)
		assert.Equal(t, http.StatusOK, w.Code)

		// Disable via API
		w = ts.makeRequest("POST", "/api/v1/admin/keys/"+keyID+"/disable", ts.masterKey, nil)
		assert.Equal(t, http.StatusOK, w.Code)

		// Verify key no longer works
		w = ts.makeRequest("GET", "/api/v1/auth-info", keyValue, nil)
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		// Enable via API
		w = ts.makeRequest("POST", "/api/v1/admin/keys/"+keyID+"/enable", ts.masterKey, nil)
		assert.Equal(t, http.StatusOK, w.Code)

		// Verify key works again
		w = ts.makeRequest("GET", "/api/v1/auth-info", keyValue, nil)
		assert.Equal(t, http.StatusOK, w.Code)

		// Delete via API
		w = ts.makeRequest("DELETE", "/api/v1/admin/keys/"+keyID, ts.masterKey, nil)
		assert.Equal(t, http.StatusOK, w.Code)

		// Verify key no longer works
		w = ts.makeRequest("GET", "/api/v1/auth-info", keyValue, nil)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

func TestIntegration_AuditLogging(t *testing.T) {
	ts := setupIntegrationTest(t)
	defer ts.cleanup()

	// Create a scoped key
	_, plainKey := ts.createKeyDirect("audit-key", []string{"finance"}, true, nil)

	// Make access check requests (with small delay to ensure distinct timestamps)
	body := map[string]interface{}{
		"agent_id":   "finance-agent",
		"agent_tags": []string{"finance"},
	}
	ts.makeRequest("POST", "/api/v1/check-agent-access", plainKey, body)

	time.Sleep(10 * time.Millisecond) // Ensure distinct ordering

	body["agent_tags"] = []string{"hr"}
	ts.makeRequest("POST", "/api/v1/check-agent-access", plainKey, body)

	// Wait for async logging
	time.Sleep(100 * time.Millisecond)

	// Query audit log directly (order by id for deterministic insertion order)
	rows, err := ts.db.Query("SELECT allowed, deny_reason FROM access_audit_log ORDER BY id")
	require.NoError(t, err)
	defer rows.Close()

	var entries []struct {
		allowed    int
		denyReason sql.NullString
	}
	for rows.Next() {
		var e struct {
			allowed    int
			denyReason sql.NullString
		}
		rows.Scan(&e.allowed, &e.denyReason)
		entries = append(entries, e)
	}

	// Should have 2 entries
	assert.Len(t, entries, 2)
	assert.Equal(t, 1, entries[0].allowed) // First was allowed
	assert.Equal(t, 0, entries[1].allowed) // Second was denied
}

func TestIntegration_ErrorMessages(t *testing.T) {
	ts := setupIntegrationTest(t)
	defer ts.cleanup()

	tests := []struct {
		name           string
		setup          func() string
		expectedStatus int
		expectedMsg    string
	}{
		{
			name:           "missing API key",
			setup:          func() string { return "" },
			expectedStatus: http.StatusUnauthorized,
			expectedMsg:    "missing API key",
		},
		{
			name:           "invalid API key",
			setup:          func() string { return "invalid-key" },
			expectedStatus: http.StatusUnauthorized,
			expectedMsg:    "invalid API key",
		},
		{
			name: "disabled API key",
			setup: func() string {
				_, key := ts.createKeyDirect("disabled-err-key", []string{"test"}, false, nil)
				return key
			},
			expectedStatus: http.StatusUnauthorized,
			expectedMsg:    "disabled",
		},
		{
			name: "expired API key",
			setup: func() string {
				past := time.Now().Add(-time.Hour)
				_, key := ts.createKeyDirect("expired-err-key", []string{"test"}, true, &past)
				return key
			},
			expectedStatus: http.StatusUnauthorized,
			expectedMsg:    "expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey := tt.setup()
			w := ts.makeRequest("GET", "/api/v1/auth-info", apiKey, nil)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var resp map[string]string
			json.Unmarshal(w.Body.Bytes(), &resp)
			assert.Contains(t, resp["message"], tt.expectedMsg)
		})
	}
}

func TestIntegration_BearerTokenAuth(t *testing.T) {
	ts := setupIntegrationTest(t)
	defer ts.cleanup()

	_, plainKey := ts.createKeyDirect("bearer-key", []string{"test"}, true, nil)

	req := httptest.NewRequest("GET", "/api/v1/auth-info", nil)
	req.Header.Set("Authorization", "Bearer "+plainKey)

	w := httptest.NewRecorder()
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "bearer-key", resp["key_name"])
}

func TestIntegration_QueryParamAuth(t *testing.T) {
	ts := setupIntegrationTest(t)
	defer ts.cleanup()

	_, plainKey := ts.createKeyDirect("query-key", []string{"test"}, true, nil)

	req := httptest.NewRequest("GET", "/api/v1/auth-info?api_key="+plainKey, nil)

	w := httptest.NewRecorder()
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "query-key", resp["key_name"])
}

func TestIntegration_XAPIKeyTakesPrecedence(t *testing.T) {
	ts := setupIntegrationTest(t)
	defer ts.cleanup()

	_, xApiKey := ts.createKeyDirect("x-api-key", []string{"test"}, true, nil)
	_, bearerKey := ts.createKeyDirect("bearer-key2", []string{"test"}, true, nil)

	req := httptest.NewRequest("GET", "/api/v1/auth-info", nil)
	req.Header.Set("X-API-Key", xApiKey)
	req.Header.Set("Authorization", "Bearer "+bearerKey)

	w := httptest.NewRecorder()
	ts.router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	// X-API-Key should take precedence
	assert.Equal(t, "x-api-key", resp["key_name"])
}
