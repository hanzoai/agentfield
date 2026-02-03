-- +goose Up
-- API keys table for scoped access control

CREATE TABLE IF NOT EXISTS api_keys (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    key_hash        TEXT NOT NULL,
    scopes          JSONB NOT NULL DEFAULT '[]',
    description     TEXT,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMP WITH TIME ZONE,
    last_used_at    TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_api_keys_name ON api_keys(name);
CREATE INDEX idx_api_keys_enabled ON api_keys(enabled);

-- +goose Down
DROP INDEX IF EXISTS idx_api_keys_enabled;
DROP INDEX IF EXISTS idx_api_keys_name;
DROP TABLE IF EXISTS api_keys;
