-- =====================================================================
-- loginsight schema
-- Author: Matthew Faber
-- =====================================================================
-- Design notes:
--  * Four tables: users, uploads, events, anomalies.
--  * `events` holds every parsed log row. We keep the raw line too so the UI
--    can show "what the analyst actually saw" alongside our parsed view.
--  * `anomalies` references `events` and carries the reason + confidence the
--    detector assigned. The optional `ai_explanation` column is filled in
--    later by the Azure AI Foundry pass for the top-N anomalies.
--  * UUIDs over serial ints so IDs are unguessable in URLs (defence in depth
--    even with auth).
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS uploads (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filename     TEXT NOT NULL,
    blob_path    TEXT NOT NULL,                  -- container-relative path
    size_bytes   BIGINT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'pending',-- pending|parsing|analyzing|done|error
    error        TEXT,
    event_count  INTEGER NOT NULL DEFAULT 0,
    anomaly_count INTEGER NOT NULL DEFAULT 0,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_uploads_user ON uploads(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS events (
    id           BIGSERIAL PRIMARY KEY,
    upload_id    UUID NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
    line_number  INTEGER NOT NULL,
    occurred_at  TIMESTAMPTZ,
    user_name    TEXT,
    client_ip    TEXT,
    action       TEXT,            -- Allowed | Blocked
    url          TEXT,
    host         TEXT,
    url_category TEXT,
    status_code  INTEGER,
    bytes_out    BIGINT,
    bytes_in     BIGINT,
    user_agent   TEXT,
    raw_line     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_upload ON events(upload_id);
CREATE INDEX IF NOT EXISTS idx_events_upload_time ON events(upload_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_events_upload_ip ON events(upload_id, client_ip);

CREATE TABLE IF NOT EXISTS anomalies (
    id              BIGSERIAL PRIMARY KEY,
    upload_id       UUID NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
    event_id        BIGINT REFERENCES events(id) ON DELETE CASCADE,
    rule            TEXT NOT NULL,           -- short rule id (e.g. "burst_from_ip")
    reason          TEXT NOT NULL,           -- human-readable explanation
    confidence      REAL NOT NULL,           -- 0..1
    severity        TEXT NOT NULL,           -- low|medium|high
    ai_explanation  TEXT,                    -- optional Foundry-generated narrative
    metadata        JSONB                    -- detector-specific extras (counts, thresholds)
);

CREATE INDEX IF NOT EXISTS idx_anomalies_upload ON anomalies(upload_id);
