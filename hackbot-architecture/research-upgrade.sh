#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  research-upgrade.sh — REAL self-improvement pass (replaces the inert
#  self-improve.sh whose "web_search ..." step was a shell call to a command
#  that does not exist, so it harvested nothing and rewrote a static keyword
#  list into the methodology DB every hour).
#
#  What it does, in one bounded LLM pass:
#    1. reads SEVERITY_DOCTRINE.md §5 (the source list) + the active scope classes
#    2. reads the tail of the existing ledgers so it does NOT duplicate a technique
#    3. uses its OWN web tools (web_search / web_extract) to read NEW writeups /
#       disclosed reports from: HackerOne Hacktivity, Bugcrowd, Intigriti,
#       PentesterLand, Medium, InfoSec Writeups, HackerOne docs
#    4. extracts CLASS / entry point / BYPASS / CHAIN / TRANSFERABLE TEST —
#       preferring techniques that escalate a P4 primitive into a P1/P2 chain
#    5. APPENDS them to /root/bugbountyhuntingskills.md and
#       /root/hackbot-architecture/knowledge/methodologies-<date>.md
#    6. prints "nothing new — N sources checked" when there is genuinely nothing
#
#  Usage: research-upgrade.sh [--if-due]
#         --if-due = skip unless the last run is older than RESEARCH_MIN_GAP (6h)
# ══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

# cron (0 */6) runs with a minimal PATH that lacks the hermes bin — make it explicit
export PATH="/root/.hermes/hermes-agent/.hermes/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# gct <grep-args...> — like `grep -c` but ALWAYS yields exactly one integer.
# `$(grep -c X f || echo 0)` is a trap: grep -c prints "0" AND exits 1 on no match,
# so the fallback appends a second 0 -> "0\n0" -> "[ 0\n0 -gt 0 ]: integer expression expected".
gct(){ local n; n=$(grep -c "$@" 2>/dev/null); printf '%s' "${n:-0}"; }


ROOT="/root/hackbot-architecture"
STATE="$ROOT/state"
KB="$ROOT/knowledge"
LEDGER="/root/bugbountyhuntingskills.md"
DOCTRINE="$ROOT/SEVERITY_DOCTRINE.md"
LOG="$STATE/research-upgrade.log"
STAMP="$STATE/research-upgrade.last"
SKILL_MD="/root/Bugbountyskills.md"
MIN_GAP="${RESEARCH_MIN_GAP:-21600}"   # 6h
mkdir -p "$STATE" "$KB"

log(){ printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG"; }
nlines(){ [ -f "$1" ] && gct . "$1"; }

if [ "${1:-}" = "--if-due" ] && [ -f "$STAMP" ]; then
  last="$(cat "$STAMP" 2>/dev/null || echo 0)"
  now="$(date +%s)"
  if [ $((now - last)) -lt "$MIN_GAP" ]; then
    log "skip: last research run $(( (now-last)/60 ))m ago (< $((MIN_GAP/60))m)"
    exit 0
  fi
fi

TODAY="$(date +%F)"
OUT_MD="$KB/methodologies-$TODAY.md"
PROMPT="$STATE/research-upgrade-prompt.txt"
BEFORE_LEDGER="$(nlines "$LEDGER")"
BEFORE_OUT="$(nlines "$OUT_MD")"

{
  echo "You are the RESEARCH agent of an autonomous bug-bounty system. Your job this pass is"
  echo "KNOWLEDGE INTAKE: read new security writeups / disclosed reports and distill reusable"
  echo "ATTACK METHODOLOGY into the skill files. You are NOT hunting a target right now."
  echo
  echo "HARD RULES"
  echo "- Use your own web tools (web_search / web_extract) to actually READ sources. Do not"
  echo "  invent reports, IDs, or techniques. If a fetch is blocked, use a cache/mirror or a"
  echo "  different source; if you cannot read anything, say so plainly."
  echo "- APPEND ONLY. Never rewrite or delete existing ledger content."
  echo "- NO DUPLICATES: the tail of the existing ledger is included below. If the technique is"
  echo "  already there, do not re-append it. Quality over volume: 3-8 genuinely new, specific"
  echo "  techniques beat 30 generic ones."
  echo "- If nothing new is found, append nothing and reply exactly: nothing new — <N> sources checked"
  echo "- Bias to techniques that ESCALATE a low/informational primitive into a P1/P2 chain, and"
  echo "  to the classes this program cares about: RCE, command/code injection, SQLi, XSS with"
  echo "  impact, BAC/IDOR/BOLA, auth bypass, OAuth/OIDC bypass, JWT/session forgery, LFI/internal"
  echo "  file read, SSRF, XXE, deserialization, sandbox escape, server/client misconfiguration,"
  echo "  business-logic with monetary impact, sensitive info disclosure with PoC, admin panel access."
  echo
  echo "SOURCES TO READ (all of them; go newest-first)"
  echo "  1. HackerOne Hacktivity — disclosed reports (hackerone.com/hacktivity)"
  echo "  2. Bugcrowd published/disclosed reports (bugcrowd.com/research)"
  echo "  3. Intigriti writeups (blog.intigriti.com / intigriti.com/researchers)"
  echo "  4. PentesterLand writeup index (pentester.land/list-of-write-ups)"
  echo "  5. Medium — bug bounty tag (medium.com/tag/bug-bounty)"
  echo "  6. InfoSec Writeups (infosecwriteups.com)"
  echo "  7. HackerOne program docs, incl. Core Ineligible Findings (docs.hackerone.com)"
  echo
  echo "OUTPUT FORMAT — for each new technique append to BOTH files below, one entry per technique,"
  echo "in exactly this shape (keep the existing ledger's shape):"
  echo
  echo "SOURCE: <url or program+report id>  <date you read it>"
  echo "CLASS: <vuln class>"
  echo "CORE METHOD:"
  echo "  1. <ordered, concrete steps — the actual request shapes / params / headers>"
  echo "  2. ..."
  echo "DETECTION SIGNAL: <what you observe that says this class is present here>"
  echo "CHAIN: <primitive -> escalation -> high/critical impact, every link recorded>"
  echo "TRANSFERABLE TEST: <the one reproducible test to run on the next target>"
  echo
  echo "WRITE TARGETS"
  echo "  A) /root/bugbountyhuntingskills.md      (append at end; harvest ledger)"
  echo "  B) $OUT_MD     (append at end; same entries, dated file)"
  echo "  C) If a technique is a genuinely NEW general method, also add it under Section 17 of"
  echo "     $SKILL_MD (append only, same shape). Do not touch other sections."
  echo
  echo "Read this doctrine first (it defines what we care about):"
  echo "===== SEVERITY_DOCTRINE.md ====="
  cat "$DOCTRINE" 2>/dev/null
  echo "===== end doctrine ====="
  echo
  echo "EXISTING LEDGER TAIL (do NOT duplicate these):"
  echo "===== tail $LEDGER ====="
  tail -80 "$LEDGER" 2>/dev/null
  echo "===== end tail ====="
  echo
  echo "ACTIVE SCOPE CLASS LIST (context for what is worth learning):"
  cat /root/scope/*.txt 2>/dev/null | grep -iE 'rce|xss|sql|bac|idor|auth|oauth|lfi|ssrf|xxe|deserial|inject|misconfig|logic|disclosure|admin|bypass' | head -60
  echo
  echo "Reply with one line: appended=<n> sources_checked=<n> out=$OUT_MD"
} > "$PROMPT"

log "══════ research pass start (ledger=$BEFORE_LEDGER lines) ══════"
# Agent routing (operator spec 2026-11-17): research = commandcode, ladder falls back to hermes.
# Each rung is chosen by a MEASURED probe so a lapsed credential degrades instead of skipping.
export PATH="/root/.hermes/hermes-agent/.hermes/bin:/root/.local/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
if timeout 45 commandcode -p 'ping' --max-turns 1 >/dev/null 2>&1; then
  log "research: [agent] commandcode (authenticated)"
  timeout 1500 commandcode -p "$(cat "$PROMPT")" --tools-all --permission-mode yolo --max-turns 80 >> "$LOG" 2>&1 \
    || log "research: commandcode timed out or errored — falling back"
else
  log "research: [agent] commandcode auth FAILED -> hermes (config default model)"
  timeout 1500 hermes -z "$(cat "$PROMPT")" --yolo >> "$LOG" 2>&1 \
    || log "research: hermes timed out or errored (non-fatal)"
fi

AFTER_LEDGER="$(nlines "$LEDGER")"
AFTER_OUT="$(nlines "$OUT_MD")"
DELTA=$(( (AFTER_LEDGER - BEFORE_LEDGER) + (AFTER_OUT - BEFORE_OUT) ))
date +%s > "$STAMP"
log "research: ledger $BEFORE_LEDGER -> $AFTER_LEDGER, $OUT_MD $BEFORE_OUT -> $AFTER_OUT (delta=$DELTA)"

if [ "$DELTA" -le 0 ]; then
  log "research: NOTHING NEW recorded this pass — check the log above for a fetch/format failure, do not fake an entry"
fi

# Surface the outcome to Discord only when something real landed.
if [ "$DELTA" -gt 0 ]; then
  bash "$ROOT/notch.sh" "📚 **Skill upgraded** — research pass added $DELTA new line(s) of methodology from disclosed reports/writeups. Ledger: /root/bugbountyhuntingskills.md, dated: $OUT_MD" >/dev/null 2>&1 || true
  # Re-split the monoliths into the modular skill so workers see the new atoms without
  # reading a 23k-line file. Idempotent: regenerates vulnerabilities/intake/*.md,
  # references/intake/*.md and the byte-identical archive copies from the monoliths.
  python3 "$ROOT/migrate_monoliths.py" >>"$ROOT/principal/supervisor.log" 2>&1 \
    || log "research: migrate_monoliths.py failed — atoms stay in the monolith only"
fi
exit 0
