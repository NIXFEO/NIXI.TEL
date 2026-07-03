-- Dynamic SBC configuration — source of truth, managed via the REST API.
-- Static config (network listeners, media, logging) stays in the TOML file.

CREATE TABLE IF NOT EXISTS users (
    username     TEXT PRIMARY KEY,
    -- MD5(username:realm:password) — plaintext passwords are never stored
    ha1          TEXT NOT NULL,
    realm        TEXT NOT NULL,
    display_name TEXT,
    enabled      INTEGER NOT NULL DEFAULT 1,
    -- Per-user security limits (NULL = use global defaults)
    max_concurrent_calls  INTEGER,
    max_calls_per_minute  INTEGER,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS dids (
    number       TEXT PRIMARY KEY,
    sip_user     TEXT NOT NULL,
    display_name TEXT,
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS trunks (
    name                   TEXT PRIMARY KEY,
    enabled                INTEGER NOT NULL DEFAULT 1,
    host                   TEXT NOT NULL,
    port                   INTEGER NOT NULL DEFAULT 5060,
    transport              TEXT NOT NULL DEFAULT 'UDP',      -- UDP|TCP|TLS|WS|WSS
    auth_required          INTEGER NOT NULL DEFAULT 0,
    username               TEXT,
    -- Needed in clear for outbound digest auth toward the trunk; DB file is 0600
    password               TEXT,
    realm                  TEXT,
    register_with_trunk    INTEGER NOT NULL DEFAULT 0,
    registration_interval  INTEGER NOT NULL DEFAULT 300,
    prefix_patterns        TEXT NOT NULL DEFAULT '[]',       -- JSON array of strings
    priority               INTEGER NOT NULL DEFAULT 100,
    weight                 INTEGER NOT NULL DEFAULT 100,
    cost_per_minute        INTEGER NOT NULL DEFAULT 0,
    number_format          TEXT NOT NULL DEFAULT 'e164',     -- e164|national|local
    country_code           TEXT,
    national_prefix        TEXT,
    caller_number_format   TEXT,
    caller_number_override TEXT,
    caller_display_name    TEXT,
    allowed_codecs         TEXT NOT NULL DEFAULT '["PCMU","PCMA"]',  -- JSON array
    max_concurrent_calls   INTEGER NOT NULL DEFAULT 100,
    -- Outbound TLS (Phase E5)
    tls_sni                TEXT,
    tls_ca_cert            TEXT,
    tls_verify             INTEGER NOT NULL DEFAULT 1,
    tls_client_cert        TEXT,
    tls_client_key         TEXT,
    created_at             TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at             TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS routes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    prefix      TEXT NOT NULL,
    trunk_name  TEXT NOT NULL REFERENCES trunks(name) ON DELETE CASCADE,
    priority    INTEGER NOT NULL DEFAULT 100,
    enabled     INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    UNIQUE(prefix, trunk_name)
);

CREATE TABLE IF NOT EXISTS acl_rules (
    id         TEXT PRIMARY KEY,                 -- uuid
    cidr       TEXT NOT NULL,                    -- "203.0.113.0/24" or single IP
    action     TEXT NOT NULL CHECK(action IN ('allow','deny')),
    direction  TEXT NOT NULL DEFAULT 'both',     -- inbound|outbound|both
    priority   INTEGER NOT NULL DEFAULT 100,
    enabled    INTEGER NOT NULL DEFAULT 1,
    comment    TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Security: persisted bans (Phase E2)
CREATE TABLE IF NOT EXISTS bans (
    ip         TEXT PRIMARY KEY,
    reason     TEXT NOT NULL,
    banned_at  TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    failures   INTEGER NOT NULL DEFAULT 0,
    manual     INTEGER NOT NULL DEFAULT 0,
    offense_count INTEGER NOT NULL DEFAULT 1
);

-- Misc key/value: acl_default_action, toml_imported_at, schema markers…
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
