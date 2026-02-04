package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Agent-Field/agentfield/control-plane/internal/server/middleware"
	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// mockKeyStorage implements storage.APIKeyStorage for testing.
type mockKeyStorage struct {
	keys       map[string]*types.APIKey
	plainKeys  map[string]string // id -> plain key
	createErr  error
	verifyErr  error
	listErr    error
	deleteErr  error
	disableErr error
	enableErr  error
}

func newMockKeyStorage() *mockKeyStorage {
	return &mockKeyStorage{
		keys:      make(map[string]*types.APIKey),
		plainKeys: make(map[string]string),
	}
}

func (m *mockKeyStorage) CreateKey(ctx context.Context, req types.APIKeyCreateRequest) (*types.APIKey, string, error) {
	if m.createErr != nil {
		return nil, "", m.createErr
	}
	key := &types.APIKey{
		ID:          "key_" + req.Name,
		Name:        req.Name,
		Scopes:      req.Scopes,
		Description: req.Description,
		Enabled:     true,
		CreatedAt:   time.Now(),
		ExpiresAt:   req.ExpiresAt,
	}
	plainKey := "sk_test_" + req.Name
	m.keys[key.ID] = key
	m.plainKeys[key.ID] = plainKey
	return key, plainKey, nil
}

func (m *mockKeyStorage) GetKeyByID(ctx context.Context, id string) (*types.APIKey, error) {
	key, ok := m.keys[id]
	if !ok {
		return nil, errors.New("key not found")
	}
	return key, nil
}

func (m *mockKeyStorage) GetKeyByName(ctx context.Context, name string) (*types.APIKey, error) {
	for _, key := range m.keys {
		if key.Name == name {
			return key, nil
		}
	}
	return nil, errors.New("key not found")
}

func (m *mockKeyStorage) VerifyKey(ctx context.Context, plainKey string) (*types.APIKey, error) {
	if m.verifyErr != nil {
		return nil, m.verifyErr
	}
	for id, pk := range m.plainKeys {
		if pk == plainKey {
			return m.keys[id], nil
		}
	}
	return nil, errors.New("invalid key")
}

func (m *mockKeyStorage) ListKeys(ctx context.Context) ([]*types.APIKey, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	keys := make([]*types.APIKey, 0, len(m.keys))
	for _, k := range m.keys {
		keys = append(keys, k)
	}
	return keys, nil
}

func (m *mockKeyStorage) UpdateKeyLastUsed(ctx context.Context, id string) error {
	if key, ok := m.keys[id]; ok {
		now := time.Now()
		key.LastUsedAt = &now
	}
	return nil
}

func (m *mockKeyStorage) DeleteKey(ctx context.Context, id string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.keys, id)
	delete(m.plainKeys, id)
	return nil
}

func (m *mockKeyStorage) DisableKey(ctx context.Context, id string) error {
	if m.disableErr != nil {
		return m.disableErr
	}
	if key, ok := m.keys[id]; ok {
		key.Enabled = false
	}
	return nil
}

func (m *mockKeyStorage) EnableKey(ctx context.Context, id string) error {
	if m.enableErr != nil {
		return m.enableErr
	}
	if key, ok := m.keys[id]; ok {
		key.Enabled = true
	}
	return nil
}

func setupTestRouter(storage *mockKeyStorage, isSuperKey bool) *gin.Engine {
	router := gin.New()
	handlers := NewKeyHandlers(storage)

	// Simulate auth middleware setting context
	router.Use(func(c *gin.Context) {
		if isSuperKey {
			c.Set(middleware.ContextIsSuperKey, true)
			c.Set(middleware.ContextKeyScopes, []string{"*"})
		} else {
			c.Set(middleware.ContextIsSuperKey, false)
			c.Set(middleware.ContextKeyScopes, []string{"limited"})
		}
		c.Next()
	})

	admin := router.Group("/api/v1/admin")
	admin.Use(RequireSuperKey())
	{
		admin.GET("/keys", handlers.ListKeys)
		admin.POST("/keys", handlers.CreateKey)
		admin.GET("/keys/:id", handlers.GetKey)
		admin.DELETE("/keys/:id", handlers.DeleteKey)
		admin.POST("/keys/:id/disable", handlers.DisableKey)
		admin.POST("/keys/:id/enable", handlers.EnableKey)
		admin.POST("/keys/check-access", handlers.CheckAccess)
	}

	return router
}

func TestRequireSuperKey_Allows(t *testing.T) {
	storage := newMockKeyStorage()
	router := setupTestRouter(storage, true) // super key

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/keys", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireSuperKey_Denies(t *testing.T) {
	storage := newMockKeyStorage()
	router := setupTestRouter(storage, false) // not super key

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/keys", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "forbidden", resp["error"])
	assert.Contains(t, resp["message"], "super key")
}

func TestListKeys(t *testing.T) {
	storage := newMockKeyStorage()
	// Pre-populate some keys
	storage.keys["key_1"] = &types.APIKey{
		ID:      "key_1",
		Name:    "finance-key",
		Scopes:  []string{"finance"},
		Enabled: true,
	}
	storage.keys["key_2"] = &types.APIKey{
		ID:      "key_2",
		Name:    "hr-key",
		Scopes:  []string{"hr"},
		Enabled: true,
	}

	router := setupTestRouter(storage, true)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/keys", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Keys []types.APIKeyResponse `json:"keys"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp.Keys, 2)
}

func TestListKeys_Error(t *testing.T) {
	storage := newMockKeyStorage()
	storage.listErr = errors.New("database error")

	router := setupTestRouter(storage, true)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/keys", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCreateKey(t *testing.T) {
	storage := newMockKeyStorage()
	router := setupTestRouter(storage, true)

	body := types.APIKeyCreateRequest{
		Name:        "new-key",
		Scopes:      []string{"finance", "billing"},
		Description: "Test key for finance",
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/keys", bytes.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp struct {
		Key      types.APIKeyResponse `json:"key"`
		KeyValue string               `json:"key_value"`
		Warning  string               `json:"warning"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.Equal(t, "new-key", resp.Key.Name)
	assert.Equal(t, []string{"finance", "billing"}, resp.Key.Scopes)
	assert.True(t, resp.Key.Enabled)
	assert.NotEmpty(t, resp.KeyValue)
	assert.Contains(t, resp.KeyValue, "sk_test_")
	assert.Contains(t, resp.Warning, "Store this key")
}

func TestCreateKey_ValidationError(t *testing.T) {
	storage := newMockKeyStorage()
	router := setupTestRouter(storage, true)

	// Missing required name field
	body := map[string]interface{}{
		"scopes": []string{"finance"},
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/keys", bytes.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateKey_StorageError(t *testing.T) {
	storage := newMockKeyStorage()
	storage.createErr = errors.New("duplicate key name")

	router := setupTestRouter(storage, true)

	body := types.APIKeyCreateRequest{
		Name:   "new-key",
		Scopes: []string{"finance"},
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/keys", bytes.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestGetKey(t *testing.T) {
	storage := newMockKeyStorage()
	storage.keys["key_123"] = &types.APIKey{
		ID:          "key_123",
		Name:        "test-key",
		Scopes:      []string{"finance"},
		Description: "Test description",
		Enabled:     true,
	}

	router := setupTestRouter(storage, true)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/keys/key_123", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp types.APIKeyResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "key_123", resp.ID)
	assert.Equal(t, "test-key", resp.Name)
}

func TestGetKey_NotFound(t *testing.T) {
	storage := newMockKeyStorage()
	router := setupTestRouter(storage, true)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/keys/nonexistent", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["error"], "not found")
}

func TestDeleteKey(t *testing.T) {
	storage := newMockKeyStorage()
	storage.keys["key_to_delete"] = &types.APIKey{
		ID:   "key_to_delete",
		Name: "doomed-key",
	}

	router := setupTestRouter(storage, true)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/keys/key_to_delete", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "deleted")

	// Verify deleted from storage
	_, exists := storage.keys["key_to_delete"]
	assert.False(t, exists)
}

func TestDeleteKey_Error(t *testing.T) {
	storage := newMockKeyStorage()
	storage.deleteErr = errors.New("cannot delete key")

	router := setupTestRouter(storage, true)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/keys/any", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestDisableKey(t *testing.T) {
	storage := newMockKeyStorage()
	storage.keys["key_123"] = &types.APIKey{
		ID:      "key_123",
		Name:    "test-key",
		Enabled: true,
	}

	router := setupTestRouter(storage, true)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/keys/key_123/disable", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "disabled")

	// Verify disabled in storage
	assert.False(t, storage.keys["key_123"].Enabled)
}

func TestDisableKey_Error(t *testing.T) {
	storage := newMockKeyStorage()
	storage.disableErr = errors.New("cannot disable key")

	router := setupTestRouter(storage, true)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/keys/any/disable", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestEnableKey(t *testing.T) {
	storage := newMockKeyStorage()
	storage.keys["key_123"] = &types.APIKey{
		ID:      "key_123",
		Name:    "test-key",
		Enabled: false, // Initially disabled
	}

	router := setupTestRouter(storage, true)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/keys/key_123/enable", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp["message"], "enabled")

	// Verify enabled in storage
	assert.True(t, storage.keys["key_123"].Enabled)
}

func TestEnableKey_Error(t *testing.T) {
	storage := newMockKeyStorage()
	storage.enableErr = errors.New("cannot enable key")

	router := setupTestRouter(storage, true)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/keys/any/enable", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCheckAccess(t *testing.T) {
	storage := newMockKeyStorage()
	storage.keys["key_123"] = &types.APIKey{
		ID:     "key_123",
		Name:   "finance-key",
		Scopes: []string{"finance", "billing"},
	}

	router := setupTestRouter(storage, true)

	body := map[string]string{
		"key_name":     "finance-key",
		"target_agent": "payment-agent",
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/keys/check-access", bytes.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "finance-key", resp["key_name"])
	assert.Equal(t, "payment-agent", resp["target_agent"])
}

func TestCheckAccess_KeyNotFound(t *testing.T) {
	storage := newMockKeyStorage()
	router := setupTestRouter(storage, true)

	body := map[string]string{
		"key_name":     "nonexistent",
		"target_agent": "agent",
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/keys/check-access", bytes.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCheckAccess_ValidationError(t *testing.T) {
	storage := newMockKeyStorage()
	router := setupTestRouter(storage, true)

	// Missing required fields
	body := map[string]string{}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/keys/check-access", bytes.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCreateKey_WithExpiration(t *testing.T) {
	storage := newMockKeyStorage()
	router := setupTestRouter(storage, true)

	expiration := time.Now().Add(24 * time.Hour)
	body := types.APIKeyCreateRequest{
		Name:      "expiring-key",
		Scopes:    []string{"limited"},
		ExpiresAt: &expiration,
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/keys", bytes.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp struct {
		Key types.APIKeyResponse `json:"key"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotNil(t, resp.Key.ExpiresAt)
}

func TestCreateKey_SuperKey(t *testing.T) {
	storage := newMockKeyStorage()
	router := setupTestRouter(storage, true)

	// Empty scopes = super key
	body := types.APIKeyCreateRequest{
		Name:   "super-key",
		Scopes: []string{},
	}
	bodyJSON, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/admin/keys", bytes.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp struct {
		Key types.APIKeyResponse `json:"key"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Empty(t, resp.Key.Scopes)
}

func TestListKeys_NoKeyHashExposed(t *testing.T) {
	storage := newMockKeyStorage()
	storage.keys["key_1"] = &types.APIKey{
		ID:      "key_1",
		Name:    "test-key",
		KeyHash: "bcrypt_hash_should_not_appear",
		Scopes:  []string{"finance"},
		Enabled: true,
	}

	router := setupTestRouter(storage, true)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/admin/keys", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Verify raw response doesn't contain key_hash
	bodyStr := w.Body.String()
	assert.NotContains(t, bodyStr, "key_hash")
	assert.NotContains(t, bodyStr, "bcrypt_hash")
}

// Test lifecycle: Create -> Get -> Disable -> Enable -> Delete
func TestKeyLifecycle(t *testing.T) {
	storage := newMockKeyStorage()
	router := setupTestRouter(storage, true)

	// 1. Create
	createBody := types.APIKeyCreateRequest{
		Name:        "lifecycle-key",
		Scopes:      []string{"test"},
		Description: "Lifecycle test",
	}
	createJSON, _ := json.Marshal(createBody)

	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/keys", bytes.NewReader(createJSON))
	createReq.Header.Set("Content-Type", "application/json")
	createW := httptest.NewRecorder()
	router.ServeHTTP(createW, createReq)
	require.Equal(t, http.StatusCreated, createW.Code)

	var createResp struct {
		Key      types.APIKeyResponse `json:"key"`
		KeyValue string               `json:"key_value"`
	}
	json.Unmarshal(createW.Body.Bytes(), &createResp)
	keyID := createResp.Key.ID

	// 2. Get
	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/keys/"+keyID, nil)
	getW := httptest.NewRecorder()
	router.ServeHTTP(getW, getReq)
	require.Equal(t, http.StatusOK, getW.Code)

	var getResp types.APIKeyResponse
	json.Unmarshal(getW.Body.Bytes(), &getResp)
	assert.Equal(t, "lifecycle-key", getResp.Name)
	assert.True(t, getResp.Enabled)

	// 3. Disable
	disableReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/keys/"+keyID+"/disable", nil)
	disableW := httptest.NewRecorder()
	router.ServeHTTP(disableW, disableReq)
	require.Equal(t, http.StatusOK, disableW.Code)

	// Verify disabled
	assert.False(t, storage.keys[keyID].Enabled)

	// 4. Enable
	enableReq := httptest.NewRequest(http.MethodPost, "/api/v1/admin/keys/"+keyID+"/enable", nil)
	enableW := httptest.NewRecorder()
	router.ServeHTTP(enableW, enableReq)
	require.Equal(t, http.StatusOK, enableW.Code)

	// Verify enabled
	assert.True(t, storage.keys[keyID].Enabled)

	// 5. Delete
	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/keys/"+keyID, nil)
	deleteW := httptest.NewRecorder()
	router.ServeHTTP(deleteW, deleteReq)
	require.Equal(t, http.StatusOK, deleteW.Code)

	// Verify deleted
	_, exists := storage.keys[keyID]
	assert.False(t, exists)

	// 6. Get after delete returns 404
	getAfterDeleteReq := httptest.NewRequest(http.MethodGet, "/api/v1/admin/keys/"+keyID, nil)
	getAfterDeleteW := httptest.NewRecorder()
	router.ServeHTTP(getAfterDeleteW, getAfterDeleteReq)
	assert.Equal(t, http.StatusNotFound, getAfterDeleteW.Code)
}
