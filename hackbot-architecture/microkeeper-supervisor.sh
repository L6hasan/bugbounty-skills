#!/usr/bin/env bash
# microkeeper-supervisor.sh — the endless driver for the Microkeeper assessment loop.
#
#   CYCLE: coverage matrix -> research/recon -> hunt -> bypass/chain -> validate -> sleep -> repeat
#
# One cycle = one call to `microkeeper-loop.sh all`, which takes its own flock, so a second
# driver (the Hermes cron job, or a hand-run pass) can never interleave with it.
#
# Engine routing is MEASURED per pass, never assumed (probes live in microkeeper-loop.sh):
#   coverage    -> python3 mk-coverage.py (deterministic, no LLM)
#   research    -> hermes
#   hunt        -> opencode on its own default model; hermes+commandcode-provider fallback
#   chain       -> commandcode CLI when authenticated; hermes+commandcode-provider fallback
#   validate    -> same as chain
set -u
export PATH="/root/.hermes/hermes-agent/.hermes/bin:/root/go/bin:/usr/local/bin:/usr/bin:/bin:${PATH:-}"

# gct <grep-args...> — like `grep -c` but ALWAYS yields exactly one integer.
# `$(grep -c X f || echo 0)` is a trap: grep -c prints "0" AND exits 1 on no match,
# so the fallback appends a second 0 -> "0\n0" -> "[ 0\n0 -gt 0 ]: integer expression expected".
gct(){ local n; n=$(grep -c "$@" 2>/dev/null); printf '%s' "${n:-0}"; }

HA=/root/hackbot-architecture
ROOT=/root/state/recon/microkeeper
STATE="$ROOT/loop"
SLEEP="${LOOP_SLEEP:-1200}"
LOCK_RETRY="${LOCK_RETRY:-180}"
LOG="$STATE/logs/supervisor.log"
mkdir -p "$STATE/logs"
logline(){ echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }

logline "=== microkeeper supervisor start pid=$$ target=microkeeper.com.au cycle-sleep=${SLEEP}s ==="
n=0
while true; do
  n=$((n+1))
  logline "CYCLE $n begin"
  bash "$HA/microkeeper-loop.sh" all >>"$LOG" 2>&1
  rc=$?
  if [ "$rc" = "75" ]; then
    logline "CYCLE $n skipped — another pass holds .pass.lock; retrying in ${LOCK_RETRY}s"
    sleep "$LOCK_RETRY"
    n=$((n-1))
    continue
  fi
  leads=$(gct . "$STATE/leads.jsonl")
  chains=$(gct . "$STATE/chains.jsonl")
  untested=$(awk -F'\t' '$5=="UNTESTED"' "$STATE/coverage.tsv" 2>/dev/null | grep -c .)
  logline "CYCLE $n end rc=$rc leads=$leads chains=$chains untested-cells=${untested:-0}"
  logline "sleeping ${SLEEP}s"
  sleep "$SLEEP"
done
