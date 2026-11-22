#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  monitor.sh <stage> <target> [scope_file] — MONITOR + PUSH layer
#  Watches each agent's output. If a stage stalled or produced nothing, it
#  re-drives that stage with a corrective prompt — the "keep pushing" behavior.
#
#  stage: recon | hunt | validate
# ══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

STAGE="${1:-}"
TARGET="${2:-klook}"
SCOPE_FILE="${3:-}"
ROOT="/root/hackbot-architecture"
STATE="$ROOT/state"
FIND="$ROOT/findings"
LOG="$STATE/monitor-${TARGET}.log"
log(){ printf '[%s] monitor:%s %s\n' "$(date '+%H:%M:%S')" "$STAGE" "$*" >> "$LOG"; }

OC_MODEL="${OC_MODEL:-commandcode/deepseek/deepseek-v4-flash}"
CC_MODEL="${CC_MODEL:-commandcode/deepseek/deepseek-v4-pro}"

# helper: count non-empty lines in a file (0 if missing/empty)
lines(){ [ -f "$1" ] && wc -l < "$1" 2>/dev/null | tr -d ' ' || echo 0; }

notify_discord(){
  local token channel msg
  token="$(grep -E '^DISCORD_BOT_TOKEN=' /root/.hermes/.env 2>/dev/null | sed 's/^[^=]*=//' | tr -d '\n')"
  channel="${DISCORD_HOME_CHANNEL:-1567763899808354387}"
  [ -z "$token" ] && return 0
  msg="$1"; [ "${#msg}" -gt 1900 ] && msg="${msg:0:1900}…"
  curl -sS -m 10 -o /dev/null -X POST -H "Authorization: Bot $token" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg c "$msg" '{content:$c}')" "https://discord.com/api/v10/channels/$channel/messages" 2>/dev/null
}

case "$STAGE" in
  recon)
    # recon output = files under state/recon/. Push if empty.
    n="$(find "$STATE/recon" -type f -newermt '-5 minutes' 2>/dev/null | wc -l | tr -d ' ')"
    log "recon files written in last 5m: $n"
    if [ "$n" -eq 0 ]; then
      log "PUSH: recon produced nothing — re-driving with corrective prompt"
      notify_discord "🟠 Monitor: recon stalled for **$TARGET** — re-driving"
      timeout 900 opencode run --model "$OC_MODEL" "Recon for $TARGET produced no output. Re-run discovery now: subfinder, httpx, katana, gau, waybackurls, ffuf, JS-bundle source→sink mapping. Scope: ${SCOPE_FILE:-/root/scope/*.txt}. Respect mandatory UA + out-of-scope rules. Write to /root/hackbot-architecture/state/recon/. Reply one-line summary." >> "$LOG" 2>&1 || log "recon re-drive failed"
    fi
    ;;
  hunt)
    # hunt output = candidates.jsonl. Push if empty or not growing.
    c="$(lines "$FIND/candidates.jsonl")"
    log "candidates: $c"
    if [ "$c" -eq 0 ]; then
      log "PUSH: hunter found nothing — re-driving with deeper prompt"
      notify_discord "🟠 Monitor: hunter found no candidates for **$TARGET** — pushing deeper"
      wf="$(cat "$ROOT/MASTER_WORKFLOW.md" 2>/dev/null)"
      timeout 900 hermes chat -q "You produced no candidates for $TARGET. Go DEEPER. Re-read /root/hackbot-architecture/state/recon/ and ${SCOPE_FILE:-/root/scope/*.txt}. Analyze from more perspectives: JS bundles, API routes, GraphQL, auth flows, IDOR params, SSRF sinks. NON-DESTRUCTIVE. Append evidence-backed candidates to /root/hackbot-architecture/findings/candidates.jsonl. Never fabricate — if genuinely nothing, say so explicitly and explain why.

$wf" >> "$LOG" 2>&1 || log "hunt re-drive failed"
    fi
    ;;
  validate)
    # validate output = confirmed + rejected. Sanity-check the reject rate.
    conf="$(lines "$FIND/confirmed.jsonl")"
    rej="$(lines "$FIND/rejected.jsonl")"
    total=$((conf + rej))
    log "confirmed=$conf rejected=$rej"
    if [ "$total" -gt 0 ]; then
      rate=$(( rej * 100 / total ))
      log "reject rate: $rate%"
      if [ "$rate" -gt 80 ]; then
        log "FLAG: reject rate >80% — hunter over-firing, surface to user"
        notify_discord "⚠️ Monitor: validator rejected $rate% of candidates for **$TARGET** — hunter may be over-firing (too many false positives). Review candidates.jsonl."
      fi
    fi
    # check reports have all required fields
    if [ "$conf" -gt 0 ]; then
      missing="$(find "$ROOT/reports/raw" -type f -newermt '-5 minutes' 2>/dev/null | while read -r f; do
        for k in title description steps impact severity; do
          grep -qi "\"$k\"" "$f" 2>/dev/null || echo "$f missing $k"
        done
      done)"
      if [ -n "$missing" ]; then
        log "FLAG: incomplete reports: $missing"
        notify_discord "⚠️ Monitor: some reports missing required fields for **$TARGET**"
      fi
    fi
    ;;
  *)
    log "unknown stage '$STAGE'"
    exit 1
    ;;
esac
log "monitor pass complete"
exit 0
