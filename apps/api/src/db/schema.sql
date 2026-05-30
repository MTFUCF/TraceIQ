-- =====================================================================
-- TraceIQ schema
-- Author: Matthew Faber
-- =====================================================================
-- Tables:
--   users       seeded admin + (future) registered users
--   uploads     one row per uploaded log file (any source_type)
--   events      one row per parsed log line — generic columns reused
--               across all source types, with per-type extras in details JSONB
--   anomalies   detector output, with MITRE ATT&CK mapping + optional
--               LLM analyst narrative for the top-N
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email         TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS uploads (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id       UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filename      TEXT NOT NULL,
    blob_path     TEXT NOT NULL,
    size_bytes    BIGINT NOT NULL,
    log_type      TEXT NOT NULL DEFAULT 'proxy', -- proxy|email|endpoint|cloud
    status        TEXT NOT NULL DEFAULT 'pending',
    error         TEXT,
    event_count   INTEGER NOT NULL DEFAULT 0,
    anomaly_count INTEGER NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_uploads_user ON uploads(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS events (
    id           BIGSERIAL PRIMARY KEY,
    upload_id    UUID NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
    source_type  TEXT NOT NULL DEFAULT 'proxy',
    line_number  INTEGER NOT NULL,
    occurred_at  TIMESTAMPTZ,
    user_name    TEXT,
    client_ip    TEXT,
    action       TEXT,
    url          TEXT,
    host         TEXT,
    url_category TEXT,
    status_code  INTEGER,
    bytes_out    BIGINT,
    bytes_in     BIGINT,
    user_agent   TEXT,
    details      JSONB,
    raw_line     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_upload ON events(upload_id);
CREATE INDEX IF NOT EXISTS idx_events_upload_time ON events(upload_id, occurred_at);
CREATE INDEX IF NOT EXISTS idx_events_upload_ip ON events(upload_id, client_ip);
CREATE INDEX IF NOT EXISTS idx_events_upload_user ON events(upload_id, user_name);

CREATE TABLE IF NOT EXISTS anomalies (
    id              BIGSERIAL PRIMARY KEY,
    upload_id       UUID NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
    event_id        BIGINT REFERENCES events(id) ON DELETE CASCADE,
    rule            TEXT NOT NULL,
    reason          TEXT NOT NULL,
    confidence      REAL NOT NULL,
    severity        TEXT NOT NULL,
    ai_explanation  TEXT,
    mitre           JSONB,
    metadata        JSONB
);

CREATE INDEX IF NOT EXISTS idx_anomalies_upload ON anomalies(upload_id);

-- Backward-compatible column adds for repos with the older schema.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                 WHERE table_name='uploads' AND column_name='log_type') THEN
    ALTER TABLE uploads ADD COLUMN log_type TEXT NOT NULL DEFAULT 'proxy';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                 WHERE table_name='events' AND column_name='source_type') THEN
    ALTER TABLE events ADD COLUMN source_type TEXT NOT NULL DEFAULT 'proxy';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                 WHERE table_name='events' AND column_name='details') THEN
    ALTER TABLE events ADD COLUMN details JSONB;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                 WHERE table_name='anomalies' AND column_name='mitre') THEN
    ALTER TABLE anomalies ADD COLUMN mitre JSONB;
  END IF;
END $$;
