package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWebhookSchemaMigrated(t *testing.T) {
	ctx := context.Background()
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
			t.Skip("sqlite3 compiled without FTS5; skipping webhook schema test")
		}
		require.NoError(t, err)
	}
	t.Cleanup(func() {
		_ = ls.Close(ctx)
	})

	assertTableExists(t, ls.db, "webhook_triggers")
	assertTableExists(t, ls.db, "webhook_deliveries")

	triggerColumns := getColumnNames(t, ls.db, "webhook_triggers")
	expectedTriggerColumns := []string{
		"id", "name", "description", "target", "team_id", "mode",
		"field_mappings", "defaults", "type_coercions", "secret_hash",
		"allowed_ips", "event_id_pointer", "idempotency_ttl_seconds",
		"async_execution", "max_duration_seconds", "enabled",
		"created_at", "updated_at", "last_triggered_at", "trigger_count",
	}
	for _, col := range expectedTriggerColumns {
		require.Contains(t, triggerColumns, col, "missing column in webhook_triggers")
	}

	deliveryColumns := getColumnNames(t, ls.db, "webhook_deliveries")
	expectedDeliveryColumns := []string{
		"id", "trigger_id", "event_id", "source_ip", "signature", "timestamp",
		"payload_hash", "payload_size", "status", "error_code", "error_message",
		"mapped_input_hash", "execution_id", "received_at", "processed_at",
		"duration_ms", "stored_payload",
	}
	for _, col := range expectedDeliveryColumns {
		require.Contains(t, deliveryColumns, col, "missing column in webhook_deliveries")
	}

	requireIndexExists(t, ls.db, "idx_webhook_deliveries_unique_event")

	var migrations int
	require.NoError(t, ls.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, "016").Scan(&migrations))
	require.Equal(t, 1, migrations, "webhook migration should be recorded")
}

func assertTableExists(t *testing.T, db *sqlDatabase, table string) {
	t.Helper()
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 1, count, "expected table %s to exist", table)
}

func getColumnNames(t *testing.T, db *sqlDatabase, table string) map[string]struct{} {
	t.Helper()
	rows, err := db.Query(`PRAGMA table_info('` + table + `')`)
	require.NoError(t, err)
	defer rows.Close()

	cols := make(map[string]struct{})
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		require.NoError(t, rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk))
		cols[name] = struct{}{}
	}
	require.NoError(t, rows.Err())
	return cols
}

func requireIndexExists(t *testing.T, db *sqlDatabase, indexName string) {
	t.Helper()
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, indexName).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 1, count, "expected index %s to exist", indexName)
}
