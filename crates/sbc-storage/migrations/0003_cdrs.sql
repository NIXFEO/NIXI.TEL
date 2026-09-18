-- Call detail records live in the store; the JSONL file becomes an
-- optional mirror. Rolling back to a binary that does not know this
-- migration: DELETE FROM _sqlx_migrations WHERE version IN (2, 3) — a 0.19
-- binary refuses a store carrying any migration it does not know, and both
-- 0002 and 0003 came after it (0.20 ignores unknown applied migrations, so
-- rolling back to it needs no DELETE at all).
CREATE TABLE IF NOT EXISTS cdrs (
    id                TEXT PRIMARY KEY,
    v                 INTEGER NOT NULL DEFAULT 2,
    uuid              TEXT NOT NULL DEFAULT '',
    call_id           TEXT NOT NULL,
    direction         TEXT NOT NULL DEFAULT '',
    caller            TEXT NOT NULL,
    callee            TEXT NOT NULL,
    source_ip         TEXT NOT NULL DEFAULT '',
    trunk_id          TEXT,
    codec             TEXT,
    is_webrtc         INTEGER NOT NULL DEFAULT 0,
    started_at        INTEGER NOT NULL,
    answered_at       INTEGER,
    ended_at          INTEGER NOT NULL,
    duration_secs     INTEGER NOT NULL DEFAULT 0,
    billable_secs     INTEGER NOT NULL DEFAULT 0,
    sip_code          INTEGER,
    disconnect_reason TEXT NOT NULL,
    reason            TEXT,
    hangup_by         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_cdrs_started_at ON cdrs(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_cdrs_caller     ON cdrs(caller, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_cdrs_callee     ON cdrs(callee, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_cdrs_trunk      ON cdrs(trunk_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_cdrs_call_id    ON cdrs(call_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_cdrs_uuid ON cdrs(uuid) WHERE uuid <> '';
