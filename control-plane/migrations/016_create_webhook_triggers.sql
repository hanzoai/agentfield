-- Migration: Create inbound webhook trigger and delivery tables
-- Description: Adds webhook_triggers and webhook_deliveries for generic inbound webhooks

CREATE TABLE IF NOT EXISTS webhook_triggers (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    target TEXT NOT NULL,
    team_id TEXT NOT NULL DEFAULT 'default',

    mode TEXT NOT NULL DEFAULT 'passthrough',
    field_mappings JSONB,
    defaults JSONB,
    type_coercions JSONB,

    secret_hash TEXT NOT NULL,
    allowed_ips JSONB,

    event_id_pointer TEXT,
    idempotency_ttl_seconds INTEGER DEFAULT 86400,

    async_execution BOOLEAN DEFAULT true,
    max_duration_seconds INTEGER,

    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    last_triggered_at TIMESTAMP,
    trigger_count BIGINT DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_webhook_triggers_team_id ON webhook_triggers(team_id);
CREATE INDEX IF NOT EXISTS idx_webhook_triggers_target ON webhook_triggers(target);
CREATE INDEX IF NOT EXISTS idx_webhook_triggers_enabled ON webhook_triggers(enabled);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id TEXT PRIMARY KEY,
    trigger_id TEXT NOT NULL REFERENCES webhook_triggers(id) ON DELETE CASCADE,
    event_id TEXT,

    source_ip TEXT,
    signature TEXT,
    timestamp TEXT,
    payload_hash TEXT NOT NULL,
    payload_size INTEGER NOT NULL,

    status TEXT NOT NULL,
    error_code TEXT,
    error_message TEXT,
    mapped_input_hash TEXT,
    execution_id TEXT,

    received_at TIMESTAMP NOT NULL DEFAULT NOW(),
    processed_at TIMESTAMP,
    duration_ms BIGINT,

    stored_payload JSONB
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_trigger_id ON webhook_deliveries(trigger_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_event_id ON webhook_deliveries(trigger_id, event_id);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_status ON webhook_deliveries(status);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_received_at ON webhook_deliveries(received_at DESC);

CREATE UNIQUE INDEX IF NOT EXISTS idx_webhook_deliveries_unique_event ON webhook_deliveries(trigger_id, event_id) WHERE event_id IS NOT NULL;
