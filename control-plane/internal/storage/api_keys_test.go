package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Agent-Field/agentfield/control-plane/pkg/types"
)

// testStorage implements APIKeyStorage and AccessAuditStorage for testing
// using direct SQL queries against SQLite.
type testStorage struct {
	db *sql.DB
}

// setupTestDB creates a temporary SQLite database with the API keys schema.
func setupTestDB(t *testing.T) (*testStorage, func()) {
	t.Helper()

	// Create temp file for SQLite
	tmpFile, err := os.CreateTemp("", "api_keys_test_*.db")
	require.NoError(t, err)
	tmpFile.Close()

	db, err := sql.Open("sqlite3", tmpFile.Name())
	require.NoError(t, err)

	// Create tables (matching migrations)
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
		CREATE INDEX IF NOT EXISTS idx_api_keys_name ON api_keys(name);
		CREATE INDEX IF NOT EXISTS idx_api_keys_enabled ON api_keys(enabled);

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
		CREATE INDEX IF NOT EXISTS idx_access_audit_timestamp ON access_audit_log(timestamp DESC);
		CREATE INDEX IF NOT EXISTS idx_access_audit_key_id ON access_audit_log(api_key_id);
		CREATE INDEX IF NOT EXISTS idx_access_audit_allowed ON access_audit_log(allowed);
		CREATE INDEX IF NOT EXISTS idx_access_audit_target ON access_audit_log(target_agent);
	`)
	require.NoError(t, err)

	ts := &testStorage{db: db}

	cleanup := func() {
		db.Close()
		os.Remove(tmpFile.Name())
	}

	return ts, cleanup
}

// Implement APIKeyStorage interface for testStorage
func (ts *testStorage) CreateKey(ctx context.Context, req types.APIKeyCreateRequest) (*types.APIKey, string, error) {
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}

	keyID := GenerateKeyID()
	plainKey, err := GenerateAPIKey("sk")
	if err != nil {
		return nil, "", err
	}

	keyHash, err := HashAPIKey(plainKey)
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

	_, err = ts.db.ExecContext(ctx,
		`INSERT INTO api_keys (id, name, key_hash, scopes, description, enabled, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?, 1, ?, ?)`,
		key.ID, key.Name, key.KeyHash, string(scopesJSON), key.Description, now.Format(time.RFC3339Nano), expiresAtStr,
	)
	if err != nil {
		return nil, "", err
	}

	return key, plainKey, nil
}

func (ts *testStorage) GetKeyByID(ctx context.Context, id string) (*types.APIKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return ts.scanKey(ts.db.QueryRowContext(ctx,
		`SELECT id, name, key_hash, scopes, description, enabled, created_at, expires_at, last_used_at
		 FROM api_keys WHERE id = ?`, id))
}

func (ts *testStorage) GetKeyByName(ctx context.Context, name string) (*types.APIKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return ts.scanKey(ts.db.QueryRowContext(ctx,
		`SELECT id, name, key_hash, scopes, description, enabled, created_at, expires_at, last_used_at
		 FROM api_keys WHERE name = ?`, name))
}

func (ts *testStorage) VerifyKey(ctx context.Context, plainKey string) (*types.APIKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rows, err := ts.db.QueryContext(ctx,
		`SELECT id, name, key_hash, scopes, description, enabled, created_at, expires_at, last_used_at
		 FROM api_keys WHERE enabled = 1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		key, err := ts.scanKeyFromRows(rows)
		if err != nil {
			continue
		}
		if VerifyAPIKeyHash(plainKey, key.KeyHash) {
			return key, nil
		}
	}
	return nil, sql.ErrNoRows
}

func (ts *testStorage) ListKeys(ctx context.Context) ([]*types.APIKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	rows, err := ts.db.QueryContext(ctx,
		`SELECT id, name, key_hash, scopes, description, enabled, created_at, expires_at, last_used_at
		 FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*types.APIKey
	for rows.Next() {
		key, err := ts.scanKeyFromRows(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func (ts *testStorage) UpdateKeyLastUsed(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := ts.db.ExecContext(ctx, `UPDATE api_keys SET last_used_at = ? WHERE id = ?`, time.Now().Format(time.RFC3339), id)
	return err
}

func (ts *testStorage) DeleteKey(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	result, err := ts.db.ExecContext(ctx, `DELETE FROM api_keys WHERE id = ?`, id)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (ts *testStorage) DisableKey(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	result, err := ts.db.ExecContext(ctx, `UPDATE api_keys SET enabled = 0 WHERE id = ?`, id)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (ts *testStorage) EnableKey(ctx context.Context, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	result, err := ts.db.ExecContext(ctx, `UPDATE api_keys SET enabled = 1 WHERE id = ?`, id)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (ts *testStorage) scanKey(row *sql.Row) (*types.APIKey, error) {
	key := &types.APIKey{}
	var scopesRaw string
	var description, expiresAt, lastUsedAt sql.NullString
	var enabledInt int
	var createdAtStr string

	err := row.Scan(&key.ID, &key.Name, &key.KeyHash, &scopesRaw, &description, &enabledInt, &createdAtStr, &expiresAt, &lastUsedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, sql.ErrNoRows
		}
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

func (ts *testStorage) scanKeyFromRows(rows *sql.Rows) (*types.APIKey, error) {
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

// Implement AccessAuditStorage interface for testStorage
func (ts *testStorage) LogAccessDecision(ctx context.Context, entry types.AccessAuditEntry) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	agentTagsJSON, _ := json.Marshal(entry.AgentTags)
	keyScopesJSON, _ := json.Marshal(entry.KeyScopes)

	allowedInt := 0
	if entry.Allowed {
		allowedInt = 1
	}

	_, err := ts.db.ExecContext(ctx,
		`INSERT INTO access_audit_log (api_key_id, api_key_name, target_agent, target_reasoner, agent_tags, key_scopes, allowed, deny_reason, timestamp)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.APIKeyID, entry.APIKeyName, entry.TargetAgent, entry.TargetReasoner,
		string(agentTagsJSON), string(keyScopesJSON), allowedInt, entry.DenyReason, time.Now().Format(time.RFC3339),
	)
	return err
}

func (ts *testStorage) ListAccessAuditEntries(ctx context.Context, filters AccessAuditFilters) ([]*types.AccessAuditEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	query := `SELECT id, timestamp, api_key_id, api_key_name, target_agent, target_reasoner, agent_tags, key_scopes, allowed, deny_reason FROM access_audit_log WHERE 1=1`
	var args []interface{}

	if filters.APIKeyID != nil {
		query += " AND api_key_id = ?"
		args = append(args, *filters.APIKeyID)
	}
	if filters.TargetAgent != nil {
		query += " AND target_agent = ?"
		args = append(args, *filters.TargetAgent)
	}
	if filters.Allowed != nil {
		allowedInt := 0
		if *filters.Allowed {
			allowedInt = 1
		}
		query += " AND allowed = ?"
		args = append(args, allowedInt)
	}
	query += " ORDER BY timestamp DESC"
	if filters.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filters.Limit)
	}
	if filters.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filters.Offset)
	}

	rows, err := ts.db.QueryContext(ctx, query, args...)
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

func TestGenerateAPIKey(t *testing.T) {
	t.Run("generates unique keys", func(t *testing.T) {
		keys := make(map[string]struct{})
		for i := 0; i < 100; i++ {
			key, err := GenerateAPIKey("sk")
			require.NoError(t, err)
			assert.True(t, len(key) > 10)
			assert.Contains(t, key, "sk_")
			_, exists := keys[key]
			assert.False(t, exists, "duplicate key generated")
			keys[key] = struct{}{}
		}
	})

	t.Run("respects prefix", func(t *testing.T) {
		key, err := GenerateAPIKey("test")
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(key, "test_"))
	})
}

func TestHashAPIKey(t *testing.T) {
	t.Run("produces consistent verification", func(t *testing.T) {
		plainKey := "sk_testkey123"
		hash, err := HashAPIKey(plainKey)
		require.NoError(t, err)
		assert.NotEmpty(t, hash)
		assert.NotEqual(t, plainKey, hash) // Should be hashed

		// Verify should work
		assert.True(t, VerifyAPIKeyHash(plainKey, hash))
	})

	t.Run("different keys produce different hashes", func(t *testing.T) {
		hash1, _ := HashAPIKey("key1")
		hash2, _ := HashAPIKey("key2")
		assert.NotEqual(t, hash1, hash2)
	})

	t.Run("wrong key fails verification", func(t *testing.T) {
		hash, _ := HashAPIKey("correctkey")
		assert.False(t, VerifyAPIKeyHash("wrongkey", hash))
	})
}

func TestGenerateKeyID(t *testing.T) {
	t.Run("generates unique IDs", func(t *testing.T) {
		ids := make(map[string]struct{})
		for i := 0; i < 100; i++ {
			id := GenerateKeyID()
			assert.True(t, strings.HasPrefix(id, "key_"))
			_, exists := ids[id]
			assert.False(t, exists, "duplicate ID generated")
			ids[id] = struct{}{}
		}
	})
}

func TestStorageCreateKey(t *testing.T) {
	ts, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	t.Run("creates key successfully", func(t *testing.T) {
		req := types.APIKeyCreateRequest{
			Name:        "test-key",
			Scopes:      []string{"finance", "hr"},
			Description: "Test description",
		}

		key, plainKey, err := ts.CreateKey(ctx, req)
		require.NoError(t, err)

		assert.NotEmpty(t, key.ID)
		assert.True(t, strings.HasPrefix(key.ID, "key_"))
		assert.Equal(t, "test-key", key.Name)
		assert.Equal(t, []string{"finance", "hr"}, key.Scopes)
		assert.Equal(t, "Test description", key.Description)
		assert.True(t, key.Enabled)
		assert.NotEmpty(t, plainKey)
		assert.True(t, strings.HasPrefix(plainKey, "sk_"))
	})

	t.Run("creates key with empty scopes (super key)", func(t *testing.T) {
		req := types.APIKeyCreateRequest{
			Name:   "super-key",
			Scopes: []string{},
		}

		key, _, err := ts.CreateKey(ctx, req)
		require.NoError(t, err)

		assert.Empty(t, key.Scopes)
		assert.True(t, key.IsSuperKey())
	})

	t.Run("creates key with nil scopes", func(t *testing.T) {
		req := types.APIKeyCreateRequest{
			Name:   "nil-scopes-key",
			Scopes: nil,
		}

		key, _, err := ts.CreateKey(ctx, req)
		require.NoError(t, err)

		assert.Empty(t, key.Scopes)
	})

	t.Run("creates key with expiration", func(t *testing.T) {
		expiration := time.Now().Add(24 * time.Hour)
		req := types.APIKeyCreateRequest{
			Name:      "expiring-key",
			Scopes:    []string{"limited"},
			ExpiresAt: &expiration,
		}

		key, _, err := ts.CreateKey(ctx, req)
		require.NoError(t, err)

		assert.NotNil(t, key.ExpiresAt)
	})

	t.Run("rejects duplicate name", func(t *testing.T) {
		req := types.APIKeyCreateRequest{
			Name:   "duplicate-key",
			Scopes: []string{"test"},
		}

		_, _, err := ts.CreateKey(ctx, req)
		require.NoError(t, err)

		// Try to create another with same name
		_, _, err = ts.CreateKey(ctx, req)
		assert.Error(t, err)
	})
}

func TestStorageGetKeyByID(t *testing.T) {
	ts, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Create a key first
	req := types.APIKeyCreateRequest{
		Name:        "get-by-id-key",
		Scopes:      []string{"finance"},
		Description: "Test key",
	}
	created, _, err := ts.CreateKey(ctx, req)
	require.NoError(t, err)

	t.Run("retrieves existing key", func(t *testing.T) {
		key, err := ts.GetKeyByID(ctx, created.ID)
		require.NoError(t, err)

		assert.Equal(t, created.ID, key.ID)
		assert.Equal(t, created.Name, key.Name)
		assert.Equal(t, created.Scopes, key.Scopes)
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		_, err := ts.GetKeyByID(ctx, "nonexistent")
		assert.Error(t, err)
	})
}

func TestStorageGetKeyByName(t *testing.T) {
	ts, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Create a key
	req := types.APIKeyCreateRequest{
		Name:   "named-key",
		Scopes: []string{"hr"},
	}
	created, _, err := ts.CreateKey(ctx, req)
	require.NoError(t, err)

	t.Run("retrieves key by name", func(t *testing.T) {
		key, err := ts.GetKeyByName(ctx, "named-key")
		require.NoError(t, err)

		assert.Equal(t, created.ID, key.ID)
		assert.Equal(t, "named-key", key.Name)
	})

	t.Run("returns error for non-existent name", func(t *testing.T) {
		_, err := ts.GetKeyByName(ctx, "nonexistent")
		assert.Error(t, err)
	})
}

func TestStorageVerifyKey(t *testing.T) {
	ts, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Create a key
	req := types.APIKeyCreateRequest{
		Name:   "verify-key",
		Scopes: []string{"finance"},
	}
	created, plainKey, err := ts.CreateKey(ctx, req)
	require.NoError(t, err)

	t.Run("verifies valid key", func(t *testing.T) {
		key, err := ts.VerifyKey(ctx, plainKey)
		require.NoError(t, err)

		assert.Equal(t, created.ID, key.ID)
		assert.Equal(t, created.Name, key.Name)
	})

	t.Run("rejects invalid key", func(t *testing.T) {
		_, err := ts.VerifyKey(ctx, "sk_invalid_key")
		assert.Error(t, err)
	})

	t.Run("rejects disabled key", func(t *testing.T) {
		// Create and disable a key
		req := types.APIKeyCreateRequest{
			Name:   "disabled-verify-key",
			Scopes: []string{"test"},
		}
		_, disabledPlainKey, err := ts.CreateKey(ctx, req)
		require.NoError(t, err)

		disabledKey, _ := ts.GetKeyByName(ctx, "disabled-verify-key")
		err = ts.DisableKey(ctx, disabledKey.ID)
		require.NoError(t, err)

		// Try to verify disabled key
		_, err = ts.VerifyKey(ctx, disabledPlainKey)
		assert.Error(t, err)
	})
}

func TestStorageListKeys(t *testing.T) {
	ts, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Create multiple keys
	for i := 0; i < 3; i++ {
		req := types.APIKeyCreateRequest{
			Name:   "list-key-" + string(rune('a'+i)),
			Scopes: []string{"test"},
		}
		_, _, err := ts.CreateKey(ctx, req)
		require.NoError(t, err)
		time.Sleep(50 * time.Millisecond) // Ensure different timestamps (SQLite has second-level precision)
	}

	t.Run("lists all keys", func(t *testing.T) {
		keys, err := ts.ListKeys(ctx)
		require.NoError(t, err)

		assert.Len(t, keys, 3)
	})

	t.Run("orders by created_at DESC", func(t *testing.T) {
		keys, err := ts.ListKeys(ctx)
		require.NoError(t, err)

		// Last created should be first
		assert.Equal(t, "list-key-c", keys[0].Name)
	})
}

func TestStorageUpdateKeyLastUsed(t *testing.T) {
	ts, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Create a key
	req := types.APIKeyCreateRequest{
		Name:   "last-used-key",
		Scopes: []string{"test"},
	}
	created, _, err := ts.CreateKey(ctx, req)
	require.NoError(t, err)

	// Initially, last_used_at should be nil
	key, _ := ts.GetKeyByID(ctx, created.ID)
	assert.Nil(t, key.LastUsedAt)

	// Update last used
	err = ts.UpdateKeyLastUsed(ctx, created.ID)
	require.NoError(t, err)

	// Now last_used_at should be set
	key, _ = ts.GetKeyByID(ctx, created.ID)
	assert.NotNil(t, key.LastUsedAt)
}

func TestStorageDeleteKey(t *testing.T) {
	ts, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Create a key
	req := types.APIKeyCreateRequest{
		Name:   "delete-key",
		Scopes: []string{"test"},
	}
	created, _, err := ts.CreateKey(ctx, req)
	require.NoError(t, err)

	t.Run("deletes existing key", func(t *testing.T) {
		err := ts.DeleteKey(ctx, created.ID)
		require.NoError(t, err)

		// Verify deleted
		_, err = ts.GetKeyByID(ctx, created.ID)
		assert.Error(t, err)
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		err := ts.DeleteKey(ctx, "nonexistent")
		assert.Error(t, err)
	})
}

func TestStorageDisableEnableKey(t *testing.T) {
	ts, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Create a key
	req := types.APIKeyCreateRequest{
		Name:   "toggle-key",
		Scopes: []string{"test"},
	}
	created, _, err := ts.CreateKey(ctx, req)
	require.NoError(t, err)

	t.Run("disables key", func(t *testing.T) {
		err := ts.DisableKey(ctx, created.ID)
		require.NoError(t, err)

		key, _ := ts.GetKeyByID(ctx, created.ID)
		assert.False(t, key.Enabled)
	})

	t.Run("enables key", func(t *testing.T) {
		err := ts.EnableKey(ctx, created.ID)
		require.NoError(t, err)

		key, _ := ts.GetKeyByID(ctx, created.ID)
		assert.True(t, key.Enabled)
	})

	t.Run("disable returns error for non-existent key", func(t *testing.T) {
		err := ts.DisableKey(ctx, "nonexistent")
		assert.Error(t, err)
	})

	t.Run("enable returns error for non-existent key", func(t *testing.T) {
		err := ts.EnableKey(ctx, "nonexistent")
		assert.Error(t, err)
	})
}

func TestStorageLogAccessDecision(t *testing.T) {
	ts, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	t.Run("logs allowed decision", func(t *testing.T) {
		entry := types.AccessAuditEntry{
			APIKeyID:    "key-123",
			APIKeyName:  "finance-key",
			TargetAgent: "payment-agent",
			AgentTags:   []string{"finance", "billing"},
			KeyScopes:   []string{"finance"},
			Allowed:     true,
		}

		err := ts.LogAccessDecision(ctx, entry)
		require.NoError(t, err)
	})

	t.Run("logs denied decision with reason", func(t *testing.T) {
		entry := types.AccessAuditEntry{
			APIKeyID:    "key-456",
			APIKeyName:  "hr-key",
			TargetAgent: "finance-agent",
			AgentTags:   []string{"finance"},
			KeyScopes:   []string{"hr"},
			Allowed:     false,
			DenyReason:  "no matching tags",
		}

		err := ts.LogAccessDecision(ctx, entry)
		require.NoError(t, err)
	})

	t.Run("logs decision with reasoner", func(t *testing.T) {
		entry := types.AccessAuditEntry{
			APIKeyID:       "key-789",
			APIKeyName:     "workflow-key",
			TargetAgent:    "multi-agent",
			TargetReasoner: "finance-reasoner",
			AgentTags:      []string{"finance"},
			KeyScopes:      []string{"finance"},
			Allowed:        true,
		}

		err := ts.LogAccessDecision(ctx, entry)
		require.NoError(t, err)
	})
}

func TestStorageListAccessAuditEntries(t *testing.T) {
	ts, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Create some audit entries
	entries := []types.AccessAuditEntry{
		{APIKeyID: "key-1", APIKeyName: "key1", TargetAgent: "agent-a", AgentTags: []string{"finance"}, KeyScopes: []string{"finance"}, Allowed: true},
		{APIKeyID: "key-1", APIKeyName: "key1", TargetAgent: "agent-b", AgentTags: []string{"hr"}, KeyScopes: []string{"finance"}, Allowed: false, DenyReason: "no match"},
		{APIKeyID: "key-2", APIKeyName: "key2", TargetAgent: "agent-a", AgentTags: []string{"finance"}, KeyScopes: []string{"finance"}, Allowed: true},
	}

	for _, e := range entries {
		err := ts.LogAccessDecision(ctx, e)
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond)
	}

	t.Run("lists all entries", func(t *testing.T) {
		result, err := ts.ListAccessAuditEntries(ctx, AccessAuditFilters{})
		require.NoError(t, err)
		assert.Len(t, result, 3)
	})

	t.Run("filters by API key ID", func(t *testing.T) {
		keyID := "key-1"
		result, err := ts.ListAccessAuditEntries(ctx, AccessAuditFilters{APIKeyID: &keyID})
		require.NoError(t, err)
		assert.Len(t, result, 2)
	})

	t.Run("filters by target agent", func(t *testing.T) {
		agent := "agent-a"
		result, err := ts.ListAccessAuditEntries(ctx, AccessAuditFilters{TargetAgent: &agent})
		require.NoError(t, err)
		assert.Len(t, result, 2)
	})

	t.Run("filters by allowed status", func(t *testing.T) {
		allowed := false
		result, err := ts.ListAccessAuditEntries(ctx, AccessAuditFilters{Allowed: &allowed})
		require.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, "no match", result[0].DenyReason)
	})

	t.Run("applies limit", func(t *testing.T) {
		result, err := ts.ListAccessAuditEntries(ctx, AccessAuditFilters{Limit: 2})
		require.NoError(t, err)
		assert.Len(t, result, 2)
	})

	t.Run("applies offset", func(t *testing.T) {
		result, err := ts.ListAccessAuditEntries(ctx, AccessAuditFilters{Limit: 10, Offset: 1})
		require.NoError(t, err)
		assert.Len(t, result, 2)
	})

	t.Run("combines filters", func(t *testing.T) {
		keyID := "key-1"
		allowed := true
		result, err := ts.ListAccessAuditEntries(ctx, AccessAuditFilters{
			APIKeyID: &keyID,
			Allowed:  &allowed,
		})
		require.NoError(t, err)
		assert.Len(t, result, 1)
	})
}

func TestStorageKeyExpiration(t *testing.T) {
	ts, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	t.Run("non-expired key is valid", func(t *testing.T) {
		future := time.Now().Add(time.Hour)
		req := types.APIKeyCreateRequest{
			Name:      "future-key",
			Scopes:    []string{"test"},
			ExpiresAt: &future,
		}
		created, _, err := ts.CreateKey(ctx, req)
		require.NoError(t, err)

		key, _ := ts.GetKeyByID(ctx, created.ID)
		assert.False(t, key.IsExpired())
	})

	t.Run("expired key is invalid", func(t *testing.T) {
		past := time.Now().Add(-time.Hour)
		req := types.APIKeyCreateRequest{
			Name:      "past-key",
			Scopes:    []string{"test"},
			ExpiresAt: &past,
		}
		created, _, err := ts.CreateKey(ctx, req)
		require.NoError(t, err)

		key, _ := ts.GetKeyByID(ctx, created.ID)
		assert.True(t, key.IsExpired())
	})

	t.Run("key without expiration never expires", func(t *testing.T) {
		req := types.APIKeyCreateRequest{
			Name:   "no-expiry-key",
			Scopes: []string{"test"},
		}
		created, _, err := ts.CreateKey(ctx, req)
		require.NoError(t, err)

		key, _ := ts.GetKeyByID(ctx, created.ID)
		assert.Nil(t, key.ExpiresAt)
		assert.False(t, key.IsExpired())
	})
}

func TestStorageScopesSerialization(t *testing.T) {
	ts, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	t.Run("preserves scope patterns", func(t *testing.T) {
		req := types.APIKeyCreateRequest{
			Name:   "pattern-key",
			Scopes: []string{"finance*", "*-internal", "@group-ref", "exact"},
		}
		created, _, err := ts.CreateKey(ctx, req)
		require.NoError(t, err)

		key, _ := ts.GetKeyByID(ctx, created.ID)
		assert.Equal(t, req.Scopes, key.Scopes)
	})

	t.Run("preserves special characters", func(t *testing.T) {
		req := types.APIKeyCreateRequest{
			Name:   "special-key",
			Scopes: []string{"scope:with:colons", "scope-with-dashes", "scope_with_underscores"},
		}
		created, _, err := ts.CreateKey(ctx, req)
		require.NoError(t, err)

		key, _ := ts.GetKeyByID(ctx, created.ID)
		assert.Equal(t, req.Scopes, key.Scopes)
	})
}

func TestStorageConcurrentAccess(t *testing.T) {
	ts, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	// Create a key
	req := types.APIKeyCreateRequest{
		Name:   "concurrent-key",
		Scopes: []string{"test"},
	}
	_, plainKey, err := ts.CreateKey(ctx, req)
	require.NoError(t, err)

	// Simulate concurrent verifications
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			_, err := ts.VerifyKey(ctx, plainKey)
			assert.NoError(t, err)
			done <- true
		}()
	}

	// Wait for all
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestStorageContextCancellation(t *testing.T) {
	ts, cleanup := setupTestDB(t)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	t.Run("CreateKey respects cancellation", func(t *testing.T) {
		req := types.APIKeyCreateRequest{Name: "test", Scopes: []string{}}
		_, _, err := ts.CreateKey(ctx, req)
		assert.Error(t, err)
	})

	t.Run("GetKeyByID respects cancellation", func(t *testing.T) {
		_, err := ts.GetKeyByID(ctx, "any")
		assert.Error(t, err)
	})

	t.Run("ListKeys respects cancellation", func(t *testing.T) {
		_, err := ts.ListKeys(ctx)
		assert.Error(t, err)
	})
}

// Benchmark bcrypt verification (important for security and performance)
func BenchmarkBcryptVerification(b *testing.B) {
	plainKey := "sk_test_key_12345678"
	hash, _ := HashAPIKey(plainKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyAPIKeyHash(plainKey, hash)
	}
}

func BenchmarkKeyGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateAPIKey("sk")
	}
}
