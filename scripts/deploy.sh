#!/usr/bin/env bash
# Deploy the SBC to a host that builds locally (small VPS, no CI artifacts).
#
#   scripts/deploy.sh [--dry-run|--rollback] user@host
#
# Steps: rsync the sources (never --delete: the remote tree may carry local
# files), back up binary/config/sources, add a temporary swapfile and build
# the release binary under a memory cap (a 2 GB box OOM-kills otherwise),
# refuse to restart while calls are active, stop gracefully (BYEs), swap the
# binary, start, wait for /ready, run the API smoke test, remove the swap.
# The SQLite store (database.sqlite_path of the remote config) is copied
# with the backups: the binary migrates it forward at startup and an older
# binary may refuse the migrated store. (At runtime the SBC keeps its own
# copies in [database] backup_dir and on POST /api/v1/backup; a restore
# must also delete <sqlite_path>-wal/-shm, see INSTALL.md §10.)
# --rollback restores the most recent binary and config backups and
# restarts; it never touches the store, it prints the applied migrations
# and the remediation from INSTALL.md §10 instead.
#
# Overridable: SBC_REMOTE_SRC (/root/sbc) SBC_REMOTE_CARGO (/root/.cargo/bin/cargo)
#              SBC_REMOTE_CONFIG (/opt/sbc/config/production.toml) SBC_MAX_WAIT (600 s)
set -euo pipefail

MODE=deploy
case "${1:-}" in
  --dry-run) MODE=dry; shift ;;
  --rollback) MODE=rollback; shift ;;
esac
HOST="${1:?usage: scripts/deploy.sh [--dry-run|--rollback] user@host}"

SRC="${SBC_REMOTE_SRC:-/root/sbc}"
CARGO="${SBC_REMOTE_CARGO:-/root/.cargo/bin/cargo}"
CONFIG="${SBC_REMOTE_CONFIG:-/opt/sbc/config/production.toml}"
MAX_WAIT="${SBC_MAX_WAIT:-600}"
BIN=/usr/local/bin/sbc
BACKUPS=/opt/sbc/backups
LOCAL_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GIT_SHA="$(git -C "$LOCAL_ROOT" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)"
TS="$(date -u +%Y%m%d-%H%M%S)"

say() { printf '\n== %s\n' "$*"; }

# database.sqlite_path of the remote config (first match), empty if unset.
REMOTE_DB_CMD="sed -n 's/^[[:space:]]*sqlite_path[[:space:]]*=[[:space:]]*\"\([^\"]*\)\".*/\1/p' $CONFIG | head -1"

if [ "$MODE" = rollback ]; then
  say "Rolling back on $HOST to the most recent binary and config backups (store untouched)"
  ssh "$HOST" "set -e
    B=\$(ls -t $BIN.bak.* | head -1); C=\$(ls -t $CONFIG.bak.* | head -1)
    echo \"binary: \$B\"; echo \"config: \$C\"
    systemctl stop sbc && cp -p \"\$B\" $BIN && cp -p \"\$C\" $CONFIG && systemctl start sbc
    sleep 3; systemctl is-active sbc || true; curl -s -m 3 http://127.0.0.1:8080/health; echo
    DB=\$($REMOTE_DB_CMD)
    if [ -n \"\$DB\" ] && [ -f \"\$DB\" ] && command -v sqlite3 >/dev/null; then
      echo \"store: \$DB — applied migrations: \$(sqlite3 \"\$DB\" 'SELECT group_concat(version) FROM _sqlx_migrations' 2>/dev/null)\"
    fi
    echo 'NOTE: the SQLite store was not restored. If the service does not start because the'
    echo 'restored binary does not know a migration, see INSTALL.md §10: delete that row from'
    echo \"_sqlx_migrations (sqlite3 \$DB \\\"DELETE FROM _sqlx_migrations WHERE version = N\\\") or, losing\"
    echo \"every change since, restore $BACKUPS/sbc-db-<timestamp>.db while stopped.\""
  exit 0
fi

say "Sync sources → $HOST:$SRC (commit $GIT_SHA)"
RSYNC_FLAGS=(-az --itemize-changes --exclude target --exclude .git --exclude 'config/sbc.toml' --exclude '*.db' --exclude '.DS_Store')
[ "$MODE" = dry ] && RSYNC_FLAGS+=(-n)
rsync "${RSYNC_FLAGS[@]}" "$LOCAL_ROOT/" "$HOST:$SRC/" | grep -c '^<f' | xargs echo "files to update:"

if [ "$MODE" = dry ]; then
  say "Dry run: would back up, build with SBC_GIT_SHA=$GIT_SHA, edit nothing, restart $BIN via systemctl"
  ssh "$HOST" "echo host: \$(hostname); systemctl is-active sbc; $CARGO --version; free -m | tail -2; ls -la $BIN"
  exit 0
fi

say "Backups (suffix $TS) + temporary swap"
ssh "$HOST" "set -e
  mkdir -p $BACKUPS
  tar czf $BACKUPS/sbc-src-$TS.tgz -C \$(dirname $SRC) \$(basename $SRC) --exclude=\$(basename $SRC)/target
  cp -p $BIN $BIN.bak.$TS; cp -p $CONFIG $CONFIG.bak.$TS
  DB=\$($REMOTE_DB_CMD)
  if [ -n \"\$DB\" ] && [ -f \"\$DB\" ]; then
    if command -v sqlite3 >/dev/null; then
      sqlite3 \"\$DB\" \".backup '$BACKUPS/sbc-db-$TS.db'\"
    else
      cp -p \"\$DB\" $BACKUPS/sbc-db-$TS.db; [ -f \"\$DB-wal\" ] && cp -p \"\$DB-wal\" $BACKUPS/sbc-db-$TS.db-wal || true
    fi
    echo \"store backup: $BACKUPS/sbc-db-$TS.db\"
  else
    echo 'store backup: skipped (no sqlite_path in config or file missing)'
  fi
  if ! swapon --show | grep -q swapfile.build; then
    fallocate -l 2G /swapfile.build && chmod 600 /swapfile.build && mkswap /swapfile.build >/dev/null && swapon /swapfile.build
  fi
  free -m | tail -1"

say "Release build on $HOST (memory-capped; 30+ min on 2 vCPU)"
ssh "$HOST" "set -e; cd $SRC
  SBC_GIT_SHA=$GIT_SHA systemd-run --scope --quiet -p MemoryMax=1400M -p MemorySwapMax=2G nice -n 10 $CARGO build --release 2>&1 | tail -3
  ./target/release/sbc --version"

say "Waiting for 0 active calls (max ${MAX_WAIT}s), then graceful restart"
ssh "$HOST" "set -e
  for i in \$(seq 1 $((MAX_WAIT / 10))); do
    A=\$(curl -s -m 3 http://127.0.0.1:8080/health | sed -n 's/.*\"active_calls\": *\([0-9]*\).*/\1/p')
    echo \"active_calls=\${A:-?}\"; [ \"\$A\" = 0 ] && break; sleep 10
  done
  [ \"\$A\" = 0 ] || { echo 'ABORT: calls still active — not restarting'; exit 3; }
  echo \"restart at \$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
  systemctl stop sbc; cp $SRC/target/release/sbc $BIN; systemctl start sbc
  # /ready (not /health) is the real gate: it stays 503 until the
  # SQLite store is open and hydrated and the SIP listeners are bound, and a
  # store that cannot be opened aborts the boot.
  for i in \$(seq 1 20); do
    R=\$(curl -s -m 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/ready)
    [ \"\$R\" = 200 ] && break; sleep 1
  done
  systemctl is-active sbc
  echo \"ready=\$R\"; curl -s -m 3 http://127.0.0.1:8080/ready; echo
  [ \"\$R\" = 200 ] || { echo 'ABORT: /ready never turned 200 — check journalctl -u sbc (store? listeners?)'; exit 4; }
  curl -s -m 3 http://127.0.0.1:8080/health; echo
  . /etc/sbc/sbc.env; SBC_API_TOKEN=\$SBC_API_TOKEN bash $SRC/scripts/api_smoke.sh | grep -c '^OK' | xargs echo 'smoke OK:'
  swapoff /swapfile.build && rm -f /swapfile.build
  journalctl -u sbc --since '-1min' --no-pager | grep -i -E 'version|error|panic' | tail -5"

say "Done. Rollback: scripts/deploy.sh --rollback $HOST"
