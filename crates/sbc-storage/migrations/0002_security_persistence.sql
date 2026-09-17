-- 0.20: anti-fraud settings that must survive a restart.
-- Destination (anti-IRSF) rules were in-memory only; per-user limits live in
-- users.max_concurrent_calls / max_calls_per_minute (already there) and the
-- global defaults in the settings table (user_limits.default_*).
CREATE TABLE IF NOT EXISTS destination_rules (
    id          TEXT PRIMARY KEY,
    prefix      TEXT NOT NULL,
    action      TEXT NOT NULL CHECK(action IN ('allow','deny')),
    user        TEXT,
    description TEXT NOT NULL DEFAULT '',
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_destination_rules_user ON destination_rules(user);
