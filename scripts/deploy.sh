#!/usr/bin/env bash
# Deploy the SBC to a host that builds locally (small VPS, no CI artifacts).
#
#   scripts/deploy.sh [--dry-run|--rollback] user@host
#
# Steps: rsync the sources (never --delete: the remote tree may carry local
# files), back up binary/config/sources, add a temporary swapfile and build
# the release binary under a memory cap (a 2 GB box OOM-kills otherwise),
# refuse to restart while calls are active, stop gracefully (BYEs), swap the
# binary, start, check /health, run the API smoke test, remove the swap.
# --rollback restores the most recent backups and restarts.
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

if [ "$MODE" = rollback ]; then
  say "Rolling back on $HOST to the most recent backups"
  ssh "$HOST" "set -e
    B=\$(ls -t $BIN.bak.* | head -1); C=\$(ls -t $CONFIG.bak.* | head -1)
    echo \"binary: \$B\"; echo \"config: \$C\"
    systemctl stop sbc && cp -p \"\$B\" $BIN && cp -p \"\$C\" $CONFIG && systemctl start sbc
    sleep 3; systemctl is-active sbc; curl -s -m 3 http://127.0.0.1:8080/health; echo"
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
  systemctl stop sbc; cp $SRC/target/release/sbc $BIN; systemctl start sbc; sleep 4
  systemctl is-active sbc; curl -s -m 3 http://127.0.0.1:8080/health; echo
  . /etc/sbc/sbc.env; SBC_API_TOKEN=\$SBC_API_TOKEN bash $SRC/scripts/api_smoke.sh | grep -c '^OK' | xargs echo 'smoke OK:'
  swapoff /swapfile.build && rm -f /swapfile.build
  journalctl -u sbc --since '-1min' --no-pager | grep -i -E 'version|error|panic' | tail -5"

say "Done. Rollback: scripts/deploy.sh --rollback $HOST"
