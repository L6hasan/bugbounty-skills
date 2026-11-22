#!/usr/bin/env bash
# target-intake.sh — automatic multi-target spin-up (Q6).
#
# Operator drops a target file into the queue and the harness launches a FULLY
# ISOLATED recon->validate loop for it, on its own state tree and pass lock, one
# target at a time. Nothing is hardcoded to any particular target.
#
# FEED IT A NEW TARGET BY WRITING ONE FILE:
#   /root/state/targets/queue/<name>.conf
# containing shell assignments:
#   TARGET="example.com"
#   SCOPE="/root/scope/example.txt"      # optional; omit for wildcard-of-target
#   PROGRAM="hackerone:example"          # optional, label only
#   MAX_CONCURRENT="1"                   # optional
#
# usage: target-intake.sh [--dry-run] [--max N]
set -uo pipefail
export PATH="/root/.hermes/hermes-agent/.hermes/bin:/root/go/bin:/usr/local/bin:/root/.local/bin:/usr/bin:/bin:${PATH:-}"
HA=/root/hackbot-architecture
Q=/root/state/targets/queue
DONE=/root/state/targets/done
FAILED=/root/state/targets/failed
RUNNING=/root/state/targets/running
INTLOG=/root/state/targets/intake.log
mkdir -p "$Q" "$DONE" "$FAILED" "$RUNNING"
DRY=0; MAX=1
while [ $# -gt 0 ]; do
  case "$1" in --dry-run) DRY=1; shift;; --max) MAX="$2"; shift 2;; *) shift;; esac
done
log(){ printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$INTLOG"; }

# reconcile: a slug with no live process is no longer running
for f in "$RUNNING"/*.pid; do
  [ -e "$f" ] || continue
  pid=$(cat "$f" 2>/dev/null || echo 0)
  kill -0 "$pid" 2>/dev/null || rm -f "$f"
done
RUNCOUNT=$(ls -1 "$RUNNING"/*.pid 2>/dev/null | wc -l)
log "intake scan: queue=$(ls -1 "$Q"/*.conf 2>/dev/null | wc -l) running=$RUNCOUNT"

for conf in "$Q"/*.conf; do
  [ -e "$conf" ] || continue
  [ "$RUNCOUNT" -ge "$MAX" ] && { log "at concurrency limit ($MAX) — deferring $(basename "$conf")"; break; }
  TARGET=""; SCOPE=""; PROGRAM=""; MAX_CONCURRENT="1"; HOSTS=""; EXCLUSIONS=""; SLUG=""
  # shellcheck disable=SC1090
  . "$conf"
  name="$(basename "$conf" .conf)"
  [ -n "$TARGET" ] || { log "SKIP $name — no TARGET= in conf"; mv -f "$conf" "$FAILED/"; continue; }
  [ -n "$SLUG" ] || SLUG="$(printf '%s' "$TARGET" | tr 'A-Z' 'a-z' | sed 's/[^a-z0-9]/-/g')"
  slug="$SLUG"
  st="/root/state/recon/$slug"
  if [ -f "$RUNNING/$slug.pid" ]; then log "SKIP $slug — already running"; continue; fi

  args=(--target "$TARGET" --slug "$slug")
  [ -n "$SCOPE" ] && [ -f "$SCOPE" ] && args+=(--scope "$SCOPE")
  [ -n "$HOSTS" ] && [ -f "$HOSTS" ] && args+=(--hosts "$HOSTS")
  [ -n "$EXCLUSIONS" ] && [ -f "$EXCLUSIONS" ] && args+=(--exclusions "$EXCLUSIONS")
  if [ "$DRY" = 1 ]; then
    log "DRY-RUN would launch: hunt-loop.sh ${args[*]} --phases coverage,surface,recon,hunt,chain,validate"
    continue
  fi
  log "LAUNCH $slug  (target=$TARGET program=${PROGRAM:-n/a})"
  mkdir -p "$st"   # the nohup redirect below needs the state dir to exist first
  nohup bash "$HA/hunt-loop.sh" "${args[@]}" \
        --phases coverage,surface,recon,hunt,chain,validate \
        > "$st/intake-run.log" 2>&1 &
  pid=$!
  echo "$pid" > "$RUNNING/$slug.pid"
  echo "$name $TARGET $pid $(date -Is)" >> "$RUNNING/$slug.meta"
  RUNCOUNT=$((RUNCOUNT+1))
  mv -f "$conf" "$DONE/"
  log "  pid=$pid state=$st"
done
exit 0
