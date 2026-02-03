-- +goose Up
-- Access audit log for compliance and debugging

CREATE TABLE IF NOT EXISTS access_audit_log (
    id              BIGSERIAL PRIMARY KEY,
    timestamp       TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    api_key_id      TEXT NOT NULL,
    api_key_name    TEXT NOT NULL,
    target_agent    TEXT NOT NULL,
    target_reasoner TEXT,
    agent_tags      JSONB NOT NULL DEFAULT '[]',
    key_scopes      JSONB NOT NULL DEFAULT '[]',
    allowed         BOOLEAN NOT NULL,
    deny_reason     TEXT
);

CREATE INDEX idx_access_audit_timestamp ON access_audit_log(timestamp DESC);
CREATE INDEX idx_access_audit_key_id ON access_audit_log(api_key_id);
CREATE INDEX idx_access_audit_allowed ON access_audit_log(allowed);
CREATE INDEX idx_access_audit_target ON access_audit_log(target_agent);

-- +goose Down
DROP INDEX IF EXISTS idx_access_audit_target;
DROP INDEX IF EXISTS idx_access_audit_allowed;
DROP INDEX IF EXISTS idx_access_audit_key_id;
DROP INDEX IF EXISTS idx_access_audit_timestamp;
DROP TABLE IF EXISTS access_audit_log;
