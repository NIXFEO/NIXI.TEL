-- Media facts on every CDR: how many RTP packets the SBC actually
-- delivered to each side, and a compact flag list. Billing can then tell
-- an answered call that carried audio from an answered call that was
-- silent, without correlating logs.
--
-- Rolling back to a binary that does not know this migration:
-- DELETE FROM _sqlx_migrations WHERE version IN (2, 3, 4) for a pre-0.20
-- binary; a 0.20/0.21 binary ignores unknown applied migrations and the
-- extra columns, so no DELETE is needed for those.
ALTER TABLE cdrs ADD COLUMN rtp_tx_caller INTEGER NOT NULL DEFAULT 0;
ALTER TABLE cdrs ADD COLUMN rtp_tx_callee INTEGER NOT NULL DEFAULT 0;
-- Comma-separated, empty when nothing notable: no-relay | one-way-caller |
-- one-way-callee | no-media.
ALTER TABLE cdrs ADD COLUMN media_flags TEXT NOT NULL DEFAULT '';
