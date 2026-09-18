-- Media facts on every CDR: how many RTP packets the SBC actually
-- delivered to each side, and a compact flag list. Billing can then tell
-- an answered call that carried audio from an answered call that was
-- silent, without correlating logs.
--
-- Rolling back: a 0.20 binary ignores both unknown applied migrations and
-- the extra columns, so nothing has to be deleted for it. For a pre-0.20
-- binary, delete rows 2 and 3 only and **keep row 4**: SQLite has no
-- `ADD COLUMN IF NOT EXISTS`, so re-running this migration on the same
-- store fails ("duplicate column name") and the boot fails with it.
--   sqlite3 sbc.db "DELETE FROM _sqlx_migrations WHERE version IN (2, 3)"
ALTER TABLE cdrs ADD COLUMN rtp_tx_caller INTEGER NOT NULL DEFAULT 0;
ALTER TABLE cdrs ADD COLUMN rtp_tx_callee INTEGER NOT NULL DEFAULT 0;
-- Comma-separated, empty when nothing notable: no-relay | one-way-caller |
-- one-way-callee | no-media.
ALTER TABLE cdrs ADD COLUMN media_flags TEXT NOT NULL DEFAULT '';
