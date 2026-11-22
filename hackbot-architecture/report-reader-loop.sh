#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  report-reader-loop.sh — endless read → upgrade skill → (every 100) Discord
#
#  Runs report-reader.sh passes forever: each pass harvests a class-filtered
#  queue, reads the next batch of reports one by one, appends new techniques to
#  the skill files, advances the cumulative counter, and posts a Discord digest
#  every READER_MILESTONE (default 100) reports.
#
#  Controlled via /etc/systemd/system/report-reader.service.
# ══════════════════════════════════════════════════════════════════════════════
set -uo pipefail
ROOT="/root/hackbot-architecture"
LOG="$ROOT/state/report-reader-loop.log"
LOCK="$ROOT/state/report-reader.lock"
GAP="${READER_GAP:-180}"          # seconds between passes
HARVEST_EVERY="${READER_HARVEST_EVERY:-8}"   # force a harvest refresh every N passes
mkdir -p "$ROOT/state"

say(){ printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" | tee -a "$LOG"; }

# single instance only — an on-demand pass must not overlap the loop
exec 9>"$LOCK"
if ! flock -n 9; then say "another report-reader is running — exiting"; exit 0; fi

say "══════ report-reader loop start (gap=${GAP}s, milestone=${READER_MILESTONE:-100}) ══════"
i=0
while true; do
  i=$((i+1))
  say "pass #$i start — $(cat "$ROOT/state/report-reader.count" 2>/dev/null || echo 0) reports read so far"
  bash "$ROOT/report-reader.sh" >> "$LOG" 2>&1
  rc=$?
  say "pass #$i done (rc=$rc) — $(cat "$ROOT/state/report-reader.count" 2>/dev/null || echo 0) total, $(wc -l < "$ROOT/state/report-queue.txt" 2>/dev/null || echo 0) queued"
  sleep "$GAP"
done
