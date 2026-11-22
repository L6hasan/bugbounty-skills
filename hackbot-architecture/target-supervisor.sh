#!/usr/bin/env bash
# target-supervisor.sh — keeps ONE target's hunting loop running CONTINUOUSLY.
# hunt-loop.sh runs a single pass then exits; this wraps it so the cycle repeats:
#   research -> recon(+hunt) -> chain -> validate -> skill upgrade -> repeat
# Isolated per target: own state dir, own pass lock.
#
# usage: target-supervisor.sh <slug>
set -uo pipefail
export PATH="/root/.hermes/hermes-agent/.hermes/bin:/root/go/bin:/usr/local/bin:/root/.local/bin:/usr/bin:/bin:${PATH:-}"
HA=/root/hackbot-architecture
SLUG="${1:?usage: target-supervisor.sh <slug>}"
ST="/root/state/recon/$SLUG"
CONF="/root/state/targets/active/$SLUG.conf"
[ -f "$CONF" ] || { echo "no conf $CONF"; exit 2; }
TARGET=""; SCOPE=""; HOSTS=""; EXCLUSIONS=""; SLUGCFG=""
# shellcheck disable=SC1090
. "$CONF"
SUPLOG="$ST/supervisor.log"
mkdir -p "$ST"
log(){ printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$SUPLOG"; }

GAP=$(( ${LOOP_GAP_MIN:-20} * 60 ))
log "══ $SLUG supervisor start (target=$TARGET gap=${LOOP_GAP_MIN:-20}m) ══"
while true; do
  args=(--target "$TARGET" --slug "$SLUG")
  [ -n "$SCOPE" ] && [ -f "$SCOPE" ] && args+=(--scope "$SCOPE")
  [ -n "$HOSTS" ] && [ -f "$HOSTS" ] && args+=(--hosts "$HOSTS")
  [ -n "$EXCLUSIONS" ] && [ -f "$EXCLUSIONS" ] && args+=(--exclusions "$EXCLUSIONS")
  log "CYCLE begin"
  bash "$HA/hunt-loop.sh" "${args[@]}" --phases coverage,surface,recon,hunt,chain,validate >>"$SUPLOG" 2>&1
  rc=$?
  [ $rc -eq 75 ] && log "CYCLE skipped — another $SLUG pass holds the lock"
  if [ $rc -eq 3 ]; then
    # EDGE BLOCK: the estate is dropping our packets. block-watch.sh (spawned by the pass)
    # owns recovery detection, so back off hard instead of retrying into the ban.
    log "CYCLE BLOCKED at the edge (rc=3) — backing off 60m; block-watch.sh canary owns recovery"
    bash "$HA/cycle-report.sh" "$SLUG" --no-send >>"$SUPLOG" 2>&1 || true
    sleep 3600
    continue
  fi
  # skill upgrade (research) runs on its own cron; do not duplicate it here.
  log "CYCLE end rc=$rc — sleeping ${LOOP_GAP_MIN:-20}m"
  sleep "$GAP"
done
