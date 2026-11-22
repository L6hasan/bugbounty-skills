#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  supervisor.sh — ENDLESS bug-bounty loop:
#      RESEARCH -> RECON -> HUNT -> VALIDATE -> DRAFT (each confirmed finding to
#      Discord as a draft report) -> digest -> sleep -> repeat.
#
#  Runs 24/7 under systemd (hackbot.service, Restart=always). Never exits.
#
#  PRINCIPLES
#    * Validation is AUTOMATIC (no human gate) — the user wants the loop to run.
#    * Confirmed findings are delivered as DRAFT REPORTS to Discord
#      (title / description / steps to reproduce / PoC / impact) by
#      post-drafts.sh. NO report files are written.
#    * Drafting is deduped (state/drafts-posted.ids) so each finding is sent once.
#    * Every stage is idempotent and time-bounded; a stage crash cannot kill the
#      loop. All state is on disk, so a restart resumes where it left off.
#    * Hunt rotates vulnerability classes across cycles and is told what is
#      already confirmed/rejected so it does not re-report.
# ══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

# gct <grep-args...> — like `grep -c` but ALWAYS yields exactly one integer.
# `$(grep -c X f || echo 0)` is a trap: grep -c prints "0" AND exits 1 on no match,
# so the fallback appends a second 0 -> "0\n0" -> "[ 0\n0 -gt 0 ]: integer expression expected".
gct(){ local n; n=$(grep -c "$@" 2>/dev/null); printf '%s' "${n:-0}"; }


ROOT="/root/hackbot-architecture"
STATE="$ROOT/state"
FIND="$ROOT/findings"
SCOPE_DIR="/root/scope"
LOG="$STATE/supervisor.log"
TARGET="${TARGET:-klook}"
LOOP_SLEEP="${LOOP_SLEEP:-1800}"      # seconds between full cycles (30 min)
STAGE_GAP="${STAGE_GAP:-45}"          # pause between stages
DOCTRINE_FILE="$ROOT/SEVERITY_DOCTRINE.md"   # severity doctrine — loaded into every stage

mkdir -p "$STATE" "$FIND" "$ROOT/knowledge"

log(){ printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG"; }
nlines(){ [ -f "$1" ] && gct . "$1"; }

notify_discord(){  # $1 = message text
  local token channel msg code
  token="$(grep -E '^DISCORD_BOT_TOKEN=' /root/.hermes/.env 2>/dev/null | sed 's/^[^=]*=//' | tr -d '\r\n')"
  channel="${DISCORD_HOME_CHANNEL:-1567763899808354387}"
  [ -z "$token" ] && return 0
  msg="$1"
  if [ "${#msg}" -gt 1900 ]; then msg="${msg:0:1900}…"; fi
  code="$(curl -sS -m 15 -o /dev/null -w '%{http_code}' \
    -X POST -H "Authorization: Bot $token" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg c "$msg" '{content:$c}')" \
    "https://discord.com/api/v10/channels/$channel/messages" 2>/dev/null)"
  log "discord notify http=$code"
}

# ── STAGE 1: RESEARCH — distil methodology signals + REAL skill upgrade pass ──
stage_research(){
  log "STAGE research begin"
  grep -ohiE '(SQLi|IDOR|SSRF|XSS|RCE|LFI|XXE|CSRF|auth|bypass|privilege|escalat|prototype|postMessage|open redirect|graphql|secret|innerHTML)' \
    "$FIND"/*.jsonl "$STATE"/*.md 2>/dev/null | tr 'A-Z' 'a-z' | sort | uniq -c | sort -rn \
    > "$ROOT/knowledge/methodology-counts.txt" 2>/dev/null
  log "research: $(nlines "$ROOT/knowledge/methodology-counts.txt") methodology signals into knowledge/"

  # REAL knowledge intake: read new disclosed reports/writeups and APPEND distilled
  # methodology to the skill files. Throttled (RESEARCH_MIN_GAP, default 6h) so it
  # does not burn an LLM pass every 30-min cycle. Non-fatal if it fails.
  if [ -x "$ROOT/research-upgrade.sh" ]; then
    log "research: running skill-upgrade pass (--if-due)"
    timeout 1600 bash "$ROOT/research-upgrade.sh" --if-due >> "$LOG" 2>&1 \
      || log "research: upgrade pass timed out/errored (non-fatal)"
  fi
}

# ── STAGE 2: RECON — in-scope hosts + archived-JS corpus refresh ─────────────
stage_recon(){
  log "STAGE recon begin"
  local out="$STATE/recon"
  mkdir -p "$out"
  for f in "$SCOPE_DIR"/*.txt; do
    [ -f "$f" ] || continue
    grep -oE 'https?://[a-zA-Z0-9.-]+' "$f" 2>/dev/null | sed -E 's#https?://##' >> "$out/hosts.raw"
  done
  sort -u "$out/hosts.raw" > "$out/hosts.txt" 2>/dev/null && rm -f "$out/hosts.raw"
  log "recon: $(nlines "$out/hosts.txt") in-scope hosts"

  # Refresh the archived-JS corpus for the target. Reachability is per-target (klook
  # is edge-WAF 403 from this egress, aspire answers 200), so the archived shipped
  # bundles are the always-available surface and the live hosts are a bonus.
  if [ -x "$out/$TARGET/js_fetch.sh" ]; then
    log "recon: refreshing archived JS corpus for $TARGET (bounded)"
    ( cd "$out" && timeout 900 bash "$TARGET/js_fetch.sh" ) >> "$STATE/recon-refresh.log" 2>&1 \
      || log "recon: js_fetch timed out/errored (non-fatal)"
    log "recon: archived JS files now $(find "$out/$TARGET" -name '*.js' 2>/dev/null | wc -l | tr -d ' ')"
  fi
  if command -v jsluice >/dev/null 2>&1; then
    timeout 300 bash -c "jsluice urls $out/$TARGET/**/*.js 2>/dev/null | head -3000" \
      > "$out/jsluice_urls_latest.jsonl" 2>/dev/null || true
    log "recon: jsluice endpoints $(nlines "$out/jsluice_urls_latest.jsonl")"
  fi
}

# ── STAGE 3: HUNT — LLM reasoning over the corpus, evidence-only ─────────────
stage_hunt(){
  log "STAGE hunt begin"
  local wf doc
  wf="$(cat "$ROOT/MASTER_WORKFLOW.md" 2>/dev/null)"
  doc="$(cat "$DOCTRINE_FILE" 2>/dev/null)"
  timeout 1800 hermes chat -q "You are the HUNTING agent of a bug bounty hackbot. FOLLOW THE METHODOLOGY in this master workflow (authoritative; stages 0-3, 7-9 apply to you):

$wf

════════ SEVERITY DOCTRINE — BINDING, OVERRIDES EVERYTHING BELOW ════════
$doc
════════ end doctrine ════════

STANDING ORDER FROM THE OPERATOR (Kr Hasan), read it twice:
I do NOT want low-grade P4/P5 findings — I do not want the HackerOne core-ineligible-findings list
(https://docs.hackerone.com/en/articles/8494488-core-ineligible-findings). I want RCE, XSS, SQLi,
BAC, AUTHENTICATION BYPASS, LFI, SANDBOX BYPASS, OAUTH BYPASS, DESERIALIZATION, XXE, CODE INJECTION,
COMMAND EXECUTION, SSRF, IDOR, SERVER MISCONFIGURATION, CLIENT-SIDE MISCONFIGURATION, BUSINESS LOGIC
ERROR, INFORMATION DISCLOSURE, INTERNAL FILE READ, ADMIN PANEL ACCESS. Hunt HIGH/CRITICAL ONLY.
- Use informational/P4/low primitives ONLY to chain further; never report them standalone.
- Do NOT report early. Hold the primitive and keep digging (bypass -> escalate -> chain) until the
  chain reaches real high/critical impact — or drop it in silence.
- Do not report non-sensitive or out-of-scope cases. Read the scope file's do-NOT-test list first.
- Do not keep doing recon for unnecessary calls/requests. Go straight at the SENSITIVE endpoints
  (auth/token, admin, account, payment, upload/download/export, internal & undocumented API, GraphQL,
  RPC, mobile BFF) and spend the budget BYPASSING and CHAINING them. Dig, bypass, chain.
- Think high-critical: always ask \"what is the worst outcome reachable here?\" and work back to it.

ACTIVE SCOPE: read /root/scope/*.txt for in-scope hosts and /root/hackbot-architecture/state/recon/$TARGET/ for the attack surface (shipped JS bundles, endpoints, params). Hunt ONE vulnerability class per pass, and ROTATE classes between cycles over the doctrine §1 list.

Read these FIRST and do not re-report or duplicate anything in them: $FIND/confirmed.jsonl, $FIND/rejected.jsonl, $FIND/archive.jsonl.

NON-DESTRUCTIVE only: no attack payloads, no DoS, no brute force, no data mutation. Reachability is PER-TARGET and must be MEASURED, never assumed: probe each in-scope host once (GET / with the mandatory header named in the scope file) and let the measured result drive the method. If a host answers 200/3xx, verify LIVE within the rules of conduct — read-only requests, max 10 req/sec, never sustained load, no mutation, only your own test account, and the mandatory header on EVERY request (requests without it can void the bounty). If a host is edge-WAF blocked (403/406), ground the judgement in deterministic evidence from shipped artifacts (state/recon/$TARGET/) and say plainly when live confirmation is required.

Append ONLY evidence-backed candidates as JSON lines {host,endpoint,param,vuln_class,evidence,confidence} to $FIND/candidates.jsonl. If a claimed flaw cannot be proven from evidence, emit nothing for it. Never fabricate. Reply with one line: candidates appended=<n> classes hunted=<...>." \
    >> "$LOG" 2>&1 || log "hunt: timed out or errored (non-fatal)"
  log "hunt: candidates file now $(nlines "$FIND/candidates.jsonl")"
}

# ── STAGE 4: VALIDATE — AUTOMATIC, new candidates only ──────────────────────
stage_validate(){
  log "STAGE validate begin"
  [ -s "$FIND/candidates.jsonl" ] || { log "validate: no candidates"; return 0; }
  local new
  new="$(python3 - "$FIND" <<'PY'
import json, os, sys, hashlib
F = sys.argv[1]
def key(d):
    return hashlib.sha1(("%s|%s|%s" % (d.get("host",""), d.get("endpoint",""), d.get("vuln_class",""))).encode()).hexdigest()
seen = set()
for f in ("confirmed.jsonl", "rejected.jsonl", "archive.jsonl", "tovalidate.jsonl"):
    p = os.path.join(F, f)
    if os.path.exists(p):
        for l in open(p, errors="replace"):
            l = l.strip()
            if l:
                try: seen.add(key(json.loads(l)))
                except Exception: pass
n = 0
with open(os.path.join(F, "tovalidate.jsonl"), "w") as out:
    for l in open(os.path.join(F, "candidates.jsonl"), errors="replace"):
        l = l.strip()
        if not l: continue
        try: d = json.loads(l)
        except Exception: continue
        k = key(d)
        if k in seen: continue
        seen.add(k); out.write(l + "\n"); n += 1
print(n)
PY
)"
  log "validate: $new new candidate(s) queued in tovalidate.jsonl"
  [ "${new:-0}" -eq 0 ] && { log "validate: nothing new — skip"; return 0; }

  timeout 900 hermes chat -q "You are the VALIDATION (judge) + REPORT agent of a bug bounty hackbot. Target: $TARGET.

Read $FIND/tovalidate.jsonl (the candidates), plus $FIND/confirmed.jsonl and $FIND/rejected.jsonl so you never duplicate a decided finding.

════════ SEVERITY DOCTRINE — BINDING ════════
$(cat "$DOCTRINE_FILE" 2>/dev/null)
════════ end doctrine ════════

DOCTRINE GATE — apply it BEFORE any other reasoning: if the candidate is a doctrine §2 ineligible
finding (version/banner disclosure, stack trace, descriptive error, CORS without impact,
non-sensitive CSRF/clickjacking, open redirect without added impact, cookie flags, TLS/CSP/SPF
opinions, rate limiting, content spoofing, tabnabbing, self-XSS, broken-link hijacking, CSV
injection) it is REJECTED at once with reason 'chain-primitive-only (doctrine §2)' — never
confirmed, never drafted, no matter how well measured. Also REJECT anything out of scope or in the
program's do-NOT-test list. The operator does not want P4/P5 reports; a primitive only becomes
reportable inside a chain that independently demonstrates HIGH/CRITICAL impact.

For each candidate: try to DISPROVE it (CIA triad + negative testing). State the concrete confidentiality/integrity/availability impact, and whether an attacker can actually reach the sink. Reachability is per-target and must be MEASURED, not assumed: probe each in-scope host once (GET / with the mandatory header named in the scope file) and let the measured result drive the method — a 200/3xx host allows a live read-only check within the rules of conduct (max 10 req/sec, no mutation, own test account only, mandatory header on every request), while a 403/406 edge-WAF block means grounding everything in deterministic evidence from shipped artifacts under state/recon/$TARGET/ and saying plainly when live confirmation is required. Never fabricate; if it cannot be proven from evidence, REJECT.
- Real impact -> append to $FIND/confirmed.jsonl with ALL of: id, title, host, weakness, severity, cvss, description, steps_to_reproduce, impact, poc.
- Disproven / unproven -> append to $FIND/rejected.jsonl with a 'reason' field naming the exact missing evidence.
- Then append the processed candidates to $FIND/archive.jsonl and empty $FIND/tovalidate.jsonl.

Do NOT write any report files — the pipeline delivers confirmed findings to the user as draft reports on Discord. Never fabricate. Reply with one line: confirmed=<n> rejected=<n>." \
    >> "$LOG" 2>&1 || log "validate: timed out or errored (non-fatal)"
  log "validate done: confirmed=$(nlines "$FIND/confirmed.jsonl") rejected=$(nlines "$FIND/rejected.jsonl")"
}

# ── STAGE 5: DRAFT — push new confirmed findings to Discord as draft reports ─
stage_draft(){
  log "STAGE draft begin"
  bash "$ROOT/post-drafts.sh" "$TARGET" >> "$LOG" 2>&1 || log "draft: failed (non-fatal)"
  log "draft: total drafted $(nlines "$STATE/drafts-posted.ids")"
  # Standing convention: every confirmed finding must also be downloadable from
  # Discord as a PDF attachment, not just described in a message.
  bash "$ROOT/report-pdf.sh" --all-new >> "$LOG" 2>&1 || log "draft: report-pdf failed (non-fatal)"
  log "draft: report PDFs sent total $(nlines "$STATE/reports-sent.ids")"
}

# ── STAGE 3b: PLAN-PROBES — run the reviewed test plan's read-only probes ─────
# Executes /root/recon/klook/run_plan_probes.py (top-20 endpoints from
# /root/recon/klook/test_plan.md): GET only, required UA, no WAF bypass, no
# mutation. Records every result; escalates to candidates.jsonl ONLY on a
# non-blocked response or a redirect/XSS signal (otherwise it is just 403s).
stage_planprobes(){
  local script="/root/recon/klook/run_plan_probes.py" out
  [ "$TARGET" = "klook" ] || { log "plan-probes: no reviewed plan for $TARGET — skip"; return 0; }
  [ -f "$script" ] || { log "plan-probes: script missing — skip"; return 0; }
  log "STAGE plan-probes begin"
  out="/root/recon/klook/plan_probes_$(date +%F).txt"
  timeout 600 python3 "$script" >> "$LOG" 2>&1 || log "plan-probes: errored (non-fatal)"
  local total blocked signals
  total=$(gct -E '^#[0-9]' "$out")
  blocked=$(gct 'BLOCKED' "$out")
  signals=$(gct 'SIGNAL' "$out")
  log "plan-probes done: ran=$total blocked=$blocked signals=$signals"
  if [ "${signals:-0}" -gt 0 ]; then
    grep 'SIGNAL' "$out" | while IFS= read -r l; do
      printf '{"host":"plan-probe","endpoint":"%s","vuln_class":"plan-probe-signal","evidence":"%s","confidence":"low"}\n' \
        "$(printf '%s' "$l" | sed 's/"/\\"/g')" "from $out" >> "$FIND/candidates.jsonl"
    done
    notify_discord "🔴 **Plan-probes SIGNAL** on $TARGET — a planned endpoint answered outside the WAF block (see $out). Queued to validation."
  fi
}

# ── STATUS DIGEST ────────────────────────────────────────────────────────────
status_digest(){
  local hosts cand conf rej arch
  hosts="$(nlines "$STATE/recon/hosts.txt")"
  cand="$(nlines "$FIND/candidates.jsonl")"
  conf="$(nlines "$FIND/confirmed.jsonl")"
  rej="$(nlines "$FIND/rejected.jsonl")"
  arch="$(nlines "$FIND/archive.jsonl")"
  notify_discord "🤖 **Hackbot loop** @ $(date '+%H:%M') — target: $TARGET
• in-scope hosts: $hosts
• candidates: $cand · confirmed: $conf · rejected: $rej · archived: $arch
• draft reports sent to you: $(nlines "$STATE/drafts-posted.ids")
Loop: research → recon → hunt → validate → draft. Next cycle in $((LOOP_SLEEP/60))m."
  log "digest posted: hosts=$hosts cand=$cand conf=$conf rej=$rej arch=$arch"
}

tick(){
  stage_research; sleep "$STAGE_GAP"
  stage_recon;    sleep "$STAGE_GAP"
  stage_hunt;     sleep "$STAGE_GAP"
  stage_planprobes; sleep "$STAGE_GAP"
  stage_validate; sleep 5
  stage_draft
  status_digest
  log "cycle complete"
}

# ── main loop ────────────────────────────────────────────────────────────────
log "══════ supervisor started (pid $$, target=$TARGET, loop_sleep=${LOOP_SLEEP}s) ══════"
notify_discord "♻️ **Hackbot loop started** — target **$TARGET**. Running research → recon → hunt → validate → draft on repeat. Confirmed bugs arrive here as draft reports (title/description/steps/PoC/impact)."
while true; do
  tick
  sleep "$LOOP_SLEEP"
done
