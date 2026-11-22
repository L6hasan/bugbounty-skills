#!/usr/bin/env bash
# cycle-report.sh — 2-hourly Discord status + CYCLE-HEALTH summary (Q1 + Q6).
# Answers, every run: is each loop stage actually firing, which agent ran it, did
# anything stall, and what changed. Generic: pass a slug, defaults to microkeeper.
#
# usage: cycle-report.sh [slug] [--no-send]
set -uo pipefail

SLUG="${1:-microkeeper}"; SEND=0
# NOTIFICATION POLICY (operator 2026-11-19): cycle-health is status, not a finding.
# Default is LOCAL-ONLY; --send or HACKBOT_NOTIFY_DIGEST=1 restores the Discord digest.
[ "${HACKBOT_NOTIFY_DIGEST:-0}" = "1" ] && SEND=1
for _a in "$@"; do case "$_a" in --send) SEND=1;; --no-send) SEND=0;; esac; done

# gct <grep-args...> — like `grep -c` but ALWAYS yields exactly one integer.
# `$(grep -c X f || echo 0)` is a trap: grep -c prints "0" AND exits 1 on no match,
# so the fallback appends a second 0 -> "0\n0" -> "[ 0\n0 -gt 0 ]: integer expression expected".
gct(){ local n; n=$(grep -c "$@" 2>/dev/null); printf '%s' "${n:-0}"; }

# SEND was decided by the notification policy block above (default 0 = local-only).
export PATH="/root/go/bin:/usr/local/bin:/usr/bin:/bin:${PATH:-}"
SLUG="${1:-$SLUG}"
ST="/root/state/recon/$SLUG"; LOGD="$ST/loop/logs"; SUP="$LOGD/supervisor.log"
[ -d "$ST" ] || { echo "no state dir $ST"; exit 1; }
NOW=$(date +%s)

# ---------- service ----------
SVC="microkeeper-loop.service"
if systemctl cat "$SVC" >/dev/null 2>&1; then
  ACTIVE=$(systemctl is-active "$SVC" 2>/dev/null)
  SINCE=$(systemctl show "$SVC" -p ActiveEnterTimestamp --value 2>/dev/null)
else ACTIVE="n/a"; SINCE=""; fi

# ---------- last pass + per-stage health ----------
LAST_START=$(grep -n 'LOOP PASS START' "$SUP" 2>/dev/null | tail -1)
START_LINE="${LAST_START%%:*}"
START_TS=$(printf '%s' "$LAST_START" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:]+' | head -1)
if [ -n "$START_TS" ]; then
  START_EPOCH=$(date -d "$START_TS" +%s 2>/dev/null || echo 0)
  PASS_AGE=$(( NOW - START_EPOCH ))
else PASS_AGE=-1; fi

STAGE_TABLE=""
for ph in coverage recon hunt chain validate; do
  line=$(tail -n +"${START_LINE:-1}" "$SUP" 2>/dev/null | grep -m1 -E "PHASE $ph" || true)
  agent=$(tail -n +"${START_LINE:-1}" "$SUP" 2>/dev/null | grep -m1 -E "\[agent\] ${ph}" | sed -E 's/.*\[agent\] *//' || true)
  if [ -n "$line" ]; then
    STAGE_TABLE="${STAGE_TABLE}  ${ph}: FIRED  ${agent}"
  else
    STAGE_TABLE="${STAGE_TABLE}  ${ph}: (not yet this pass)"
  fi
  STAGE_TABLE="${STAGE_TABLE}
"
done

# ---------- counters ----------
c(){ [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo 0; }
LEADS=$(c "$ST/loop/leads.jsonl"); CHAINS=$(c "$ST/loop/chains.jsonl"); HELD=$(c "$ST/loop/held.jsonl")
COV=$(c "$ST/loop/coverage.tsv")
UNT=$(awk -F'\t' 'NR>1 && $5=="UNTESTED"' "$ST/loop/coverage.tsv" 2>/dev/null | wc -l | tr -d ' ')
VAL=$(ls -1 "$ST"/loop/validations/*.json 2>/dev/null | wc -l | tr -d ' ')
NEWVAL=$(find "$ST/loop/validations" -name '*.json' -newermt '-2 hours' 2>/dev/null | wc -l | tr -d ' ')
SWEEP=$(c "$ST/surface/sweep.log")

# research cron health
RLOG=/root/hackbot-architecture/state/research-upgrade.log
RLAST=$(grep -E 'research: ledger' "$RLOG" 2>/dev/null | tail -1 | sed -E 's/^\[([^]]+)\].*/\1/')
RDUP=$(gct -E 'duplicate|already recorded|Dropped after dedupe' "$RLOG")

# ---------- stall detection ----------
WARN=""
[ "$PASS_AGE" -gt 9000 ] && WARN="${WARN}⚠ last pass started $((PASS_AGE/60))m ago (>150m) — possible stall
"
grep -q 'NO AGENT AVAILABLE' "$SUP" 2>/dev/null && WARN="${WARN}⚠ an agent ladder exhausted this pass
"
[ "$ACTIVE" != "active" ] && [ "$ACTIVE" != "n/a" ] && WARN="${WARN}⚠ service state = $ACTIVE
"

REPORT="**🔁 Cycle health — ${SLUG}**  $(date '+%F %T')
service: ${ACTIVE}  since ${SINCE:0:19}
last pass: ${START_TS:-none} ($(( PASS_AGE/60 ))m ago)   reports in last 2h: ${NEWVAL}

**stage firing (current pass)**
${STAGE_TABLE}
**counters**  leads=${LEADS} chains=${CHAINS} held=${HELD}  validations=${VAL}
coverage rows=${COV}  untested=${UNT}  surface-sweep-log=${SWEEP}
**research**  last merge: ${RLAST:-never}  dedupe-suppressed lines (log): ${RDUP}
${WARN}"

printf '%s\n' "$REPORT" | tee -a "$ST/loop/cycle-reports.log"
if [ "$SEND" = "1" ]; then
  bash /root/hackbot-architecture/notch.sh "$REPORT" >/dev/null 2>&1 && echo "[cycle-report] posted to Discord" || echo "[cycle-report] Discord post FAILED"
fi
