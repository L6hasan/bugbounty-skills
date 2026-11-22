#!/usr/bin/env bash
# microkeeper-loop.sh — continuous full-asset assessment loop for the Microkeeper program.
#
#   research  -> Hermes   (discovery/delta: subdomains, live hosts, URL/JS delta, leads)
#   hunt      -> opencode (attack the priority surfaces from the delta)
#   chain     -> commandcode (bypass + chaining of the hunt candidates)
#   validate  -> commandcode (reproduce + negative controls, non-destructive, verdict JSON)
#   then loops back to research on the next scheduled run.
#
#   usage:  microkeeper-loop.sh {research|hunt|chain|validate|all|--status}
#
# SCOPE (from /root/scope/microkeeper-in-scope.txt):
#   in  = *.microkeeper.com.au EXCEPT the two named OOS hosts
#   out = info.microkeeper.com.au (Webflow), shop.microkeeper.com.au (Shopify)
#   third-party operated (help Freshdesk / status UptimeRobot / tickets CF-523) = flagged, not tested
#   program rules: no DoS/DDoS, no social engineering, no destructive payloads, pace >=3s on the main
#   host, bursts <50 (an earlier engagement died to Cloudflare error 1015).
# DISCORD: posted ONLY on a validated High/Critical confirmation (PDF) or a regression of a delivered
#   finding. Quiet otherwise — per operator convention the channel carries confirmations only.
set -u
# systemd/cron PATH is minimal: Go tools live in /root/go/bin, hermes in
# /root/.hermes/hermes-agent/.hermes/bin, opencode in /usr/local/bin.
export PATH="/root/.hermes/hermes-agent/.hermes/bin:/root/go/bin:/usr/local/bin:/usr/bin:/bin:${PATH:-}"

# gct <grep-args...> — like `grep -c` but ALWAYS yields exactly one integer.
# `$(grep -c X f || echo 0)` is a trap: grep -c prints "0" AND exits 1 on no match,
# so the fallback appends a second 0 -> "0\n0" -> "[ 0\n0 -gt 0 ]: integer expression expected".
gct(){ local n; n=$(grep -c "$@" 2>/dev/null); printf '%s' "${n:-0}"; }

ROOT=/root/state/recon/microkeeper
HA=/root/hackbot-architecture
STATE="$ROOT/loop"
LOGD="$STATE/logs"; DEL="$STATE/delta"
mkdir -p "$STATE" "$LOGD" "$DEL" "$STATE/validations"
LOG="$LOGD/pass-$(date +%Y%m%d-%H%M)-${1:-all}.log"
LEADS="$STATE/leads.jsonl"; CHAINS="$STATE/chains.jsonl"; HELD="$STATE/held.jsonl"
touch "$LEADS" "$CHAINS" "$HELD"   # every stage appends; a missing file must not abort a pass
ALLOWED="microkeeper.com.au www.microkeeper.com.au dev.microkeeper.com.au vpsadmin.microkeeper.com.au server.microkeeper.com.au secondary.microkeeper.com.au failover.microkeeper.com.au mail.microkeeper.com.au beta.microkeeper.com.au"
OOS="info.microkeeper.com.au shop.microkeeper.com.au"
UA_C="curl/8.5.0"; UA_B="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
SKILL_CORE="/root/hackbot-architecture/knowledge/SKILL-CORE.md"
SKILL_INDEX="/root/hackbot-architecture/knowledge/SKILL-INDEX.md"
SUBCLASS="$STATE/subclass-checklist.md"
PASS="${1:-all}"

# one pass at a time (a full pass can run ~80 min across the three agent stages)
exec 9>"$STATE/.pass.lock"
flock -n 9 || { echo "another microkeeper pass is running — exit 75"; exit 75; }

log(){ echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }
notch(){ bash "$HA/notch.sh" "$1" >/dev/null 2>&1 || echo "notch failed"; }

# ── METHODOLOGY ROUTING BLOCK ────────────────────────────────────────────────
# The ledgers are 4.3 MB + 8.0 MB (47,429 lines) and CANNOT be read whole by any
# model. Every stage gets this routing card instead, and reads a section by offset.
routing_block(){
  cat <<EOF
METHODOLOGY ROUTING (binding). Do NOT read /root/Bugbountyskills.md or
/root/bugbountyhuntingskills.md top-to-bottom — 47,429 lines, it will not fit.
Route: grep -n -i '<class>' $SKILL_INDEX   then   read_file(<ledger>, offset=<line-5>, limit=200)

$(cat "$SKILL_CORE" 2>/dev/null)

SUBCLASS CHECKLIST — a coarse class is NOT covered until each subclass has a verdict:
$(cat "$SUBCLASS" 2>/dev/null)
EOF
}

# ── AGENT ROUTING — probe-based ladder per stage, every ladder ENDS at hermes ──
# Operator spec: research=commandcode, recon=opencode, hunt=hermes,
# bypass/chain=opencode, validate=claudecode, report=deterministic report-pdf.sh.
# Each rung is chosen by a MEASURED probe, so a stage is never skipped because one
# CLI's credential lapsed (e.g. claudecode OAuth expiry, commandcode cmd login).
probe_opencode(){ timeout 150 opencode run "Reply with exactly: OC_OK" >/dev/null 2>&1; }
probe_commandcode(){ timeout 45 commandcode -p 'ping' --max-turns 1 >/dev/null 2>&1; }
probe_claude(){ timeout 90 claude -p "Reply with exactly: CC_OK" >/dev/null 2>&1; }
probe_hermes(){ timeout 120 hermes -z "Reply with exactly: HB_OK" --yolo >/dev/null 2>&1; }

run_hermes(){ timeout 2400 hermes -z "$(cat "$1")" --yolo >> "$LOG" 2>&1; }   # H28 FIX: the old pinned form "-m commandcode/deepseek/deepseek-v4-flash --provider commandcode" now 404s ("Beam 1.0 free period ended") and killed EVERY recon+hunt stage (they log "[agent] ... = hermes" then die ~2 min later). config.yaml already sets model.default=deepseek/deepseek-v4-flash + provider=commandcode; measured 2026-11-19: PINNED=FAIL, UNPINNED=HB_OK. Do not re-pin.
run_opencode(){ timeout 2400 opencode run "$(cat "$1")" -f "$LEADS" -f "$ROOT/MICROKEEPER-ENGAGEMENT-STATUS-2026-11-14.md" -f "$SKILL_CORE" >> "$LOG" 2>&1; }
run_commandcode(){ timeout 2400 commandcode -p "$(cat "$1")" --tools-all --permission-mode yolo --max-turns "${2:-60}" >> "$LOG" 2>&1; }
run_claude(){ timeout 2400 claude -p "$(cat "$1")" --dangerously-skip-permissions >> "$LOG" 2>&1; }

run_stage(){ # run_stage <recon|hunt|chain|validate> <prompt-file> [max-turns]
  local stage="$1" pf="$2" turns="${3:-60}"
  case "$stage" in
    recon)
      # OPERATOR SPEC 2026-11-17 (Q8): recon + hunt = hermes; bypass+chain+report/validate = opencode.
      if probe_hermes; then log "   [agent] recon      = hermes";            run_hermes "$pf" "$turns"
      elif probe_opencode; then log "   [agent] recon      = opencode (hermes probe failed)"; run_opencode "$pf"
      else log "   [agent] recon      = NO AGENT AVAILABLE (all probes failed)"; return 1; fi ;;
    hunt)
      if probe_hermes; then log "   [agent] hunt       = hermes";            run_hermes "$pf" "$turns"
      elif probe_opencode; then log "   [agent] hunt       = opencode (hermes probe failed)"; run_opencode "$pf"
      else log "   [agent] hunt       = NO AGENT AVAILABLE"; return 1; fi ;;
    chain)
      if probe_opencode; then log "   [agent] chain/byp  = opencode";        run_opencode "$pf"
      elif probe_commandcode; then log "   [agent] chain/byp  = commandcode"; run_commandcode "$pf" "$turns"
      elif probe_hermes; then log "   [agent] chain/byp  = hermes (fallback)"; run_hermes "$pf" "$turns"
      else log "   [agent] chain      = NO AGENT AVAILABLE"; return 1; fi ;;
    validate)
      if probe_opencode; then log "   [agent] validate   = opencode";        run_opencode "$pf"
      elif probe_commandcode; then log "   [agent] validate   = commandcode"; run_commandcode "$pf" "$turns"
      elif probe_hermes; then log "   [agent] validate   = hermes (fallback)"; run_hermes "$pf" "$turns"
      else log "   [agent] validate   = NO AGENT AVAILABLE"; return 1; fi ;;
  esac
}

common_rules(){ cat <<'RULES'
TARGET: microkeeper.com.au and *.microkeeper.com.au (wildcard entitled) — a PHP 8.3 payroll/rostering
SaaS on Cloudflare. IN SCOPE: every *.microkeeper.com.au host EXCEPT info.microkeeper.com.au and
shop.microkeeper.com.au (explicitly out of scope). Third-party-operated hosts (help.* on Freshdesk,
status.* on UptimeRobot, tickets.* CF-523) are NOT operated by Microkeeper: flag, do not test.
AUTHORISED SCOPE AND INTENT: operator-owned bug bounty engagement; report channel bug-bounty@microkeeper.com.au.
HARD RULES: non-destructive only. No DoS/DDoS, no brute force beyond a handful of probes, no social
engineering, no destructive payloads, never mutate real data (no deletes/updates/writes of real records;
a registration with your own throwaway email is the only permitted write, and only once).
PACING: normal browser User-Agent, >=3 s between requests to the main host, bursts under 50 — an earlier
session on this target was killed by Cloudflare error 1015.
QUALIFYING CLASSES (program grid: Critical $1-5k, High $500-1k, Medium $200-500, Low $50-200):
auth/authz bypass, session/privilege escalation, data exposure (payroll/organisational/PII), broken API
auth, XSS (reflected/DOM/stored), SQLi, RCE, LFI/arbitrary file read, insecure deserialization, command
injection, SSRF, CSRF with impact, information disclosure with PoC.
NOT reportable standalone (chain material only): version/banner/stack-trace disclosure, CORS without
impact, cookie flags, CSP opinions, SPF/DKIM/DMARC, rate limiting, SSL config, open redirect alone,
username enumeration alone (the scope file states enumeration is only reportable WITH further impact).
EVIDENCE: every claim needs the exact request, the response, and a NEGATIVE CONTROL (a same-shaped
request that must fail). Unproven = lead, never a finding.
ALREADY REPORTED — DO NOT RE-RUN (the write shapes MUTATE production): MK-2026-001 is CONFIRMED, delivered
and awaiting the program's fix. It is the hardcoded API password shipped in the public Microkeeper
Timesheets MSI, accepted by /fp_api.php. Any POST to /fp_api.php carrying pw=fb_mk_6142 with a non-empty
nfc_code_tag (version=3) or with key_code=add_user (version=1) CREATES a record in the production store —
7 such records already had to be declared to the program. Never send those two shapes again, in any stage,
including validate: treat MK-2026-001 as validated and re-check it read-only only (a bare GET /fp_api.php
answering "API password incorrect", or a re-hash of the two installers).
SERVICE GUARD: never run systemctl stop/restart/disable/kill (or killall/pkill) on
microkeeper-loop.service or ANY unit — the continuous loop is managed by the operator from outside; stopping
it halts the engagement. Never stop, disable or reconfigure the loop that invoked you. If a service change
truly seems needed, write it as a note in LOOP_STATE.md instead of doing it.
RULES
}

# ---------------------------------------------------------------- 1. RESEARCH / RECON  (Hermes)
phase_research(){
  log "=== PHASE recon (hermes) ==="
  log "-- subdomain discovery"
  { subfinder -d microkeeper.com.au -all -silent 2>/dev/null
    curl -sS -m 30 "https://crt.sh/?q=%25.microkeeper.com.au&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | tr '\r' '\n'
    cat "$ROOT/all_hosts.txt" 2>/dev/null
    cat "$ROOT/known_hosts.txt" 2>/dev/null; } | grep -v '^#' | sed 's/\*\.//' | tr 'A-Z' 'a-z' | grep -E '^[a-z0-9._-]+$' | sort -u > "$DEL/hosts.now"
  comm -13 <(sort -u "$ROOT/all_hosts.txt" 2>/dev/null) "$DEL/hosts.now" > "$DEL/hosts.new" || true
  log "   hosts now=$(wc -l < "$DEL/hosts.now") new=$(wc -l < "$DEL/hosts.new")"
  log "-- liveness (dnsx resolve -> projectdiscovery httpx; the venv 'httpx' on PATH is NOT ProjectDiscovery)"
  dnsx -l "$DEL/hosts.now" -silent 2>/dev/null | sort -u > "$DEL/resolving.txt" || true
  comm -13 <(sort -u "$ROOT/resolving.prev" 2>/dev/null) "$DEL/resolving.txt" > "$DEL/resolving.new" || true
  cp -f "$DEL/resolving.txt" "$ROOT/resolving.prev" 2>/dev/null || true
  log "   resolving=$(wc -l < "$DEL/resolving.txt") newly-resolving=$(wc -l < "$DEL/resolving.new")"
  /root/go/bin/httpx -l "$DEL/resolving.txt" -silent -status-code -title -tech-detect -no-color -timeout 12 2>/dev/null > "$DEL/httpx.now" || true
  comm -13 <(sort -u "$ROOT/httpx_live.txt" 2>/dev/null) <(sort -u "$DEL/httpx.now") > "$DEL/httpx.new" || true
  log "   live=$(wc -l < "$DEL/httpx.now") new-or-changed=$(wc -l < "$DEL/httpx.new")"
  if [ -s "$DEL/resolving.new" ]; then
    log "   NEW RESOLVING HOSTS:"; sed 's/^/     /' "$DEL/resolving.new" | tee -a "$LOG"
  fi
  log "-- url/JS delta (gau/wayback) on the app host"
  { gau --threads 5 microkeeper.com.au 2>/dev/null; waybackurls microkeeper.com.au 2>/dev/null; } | sort -u > "$DEL/urls.now"
  comm -13 <(sort -u "$ROOT/p45/gau_urls.txt" 2>/dev/null) "$DEL/urls.now" > "$DEL/urls.new" || true
  log "   urls now=$(wc -l < "$DEL/urls.now") new=$(wc -l < "$DEL/urls.new")"
  log "-- JS bundle hash delta (new code = new surface)"
  mkdir -p "$DEL/js"; : > "$DEL/js_hashes.new"
  # Only hash REAL bundles: https, from the in-scope host, HTTP 200, content-type javascript.
  # (v1 of this stage hashed http:// 301 bodies and 404 pages, so every pass looked "unchanged".)
  grep -oE 'https?://[^"'"'"' ]+\.js(\?[^"'"'"' ]*)?' "$ROOT/p45/gau_urls.txt" 2>/dev/null \
    | grep -iE '^https?://(www\.)?microkeeper\.com\.au/' | sed 's#^http://#https://#' | sort -u | head -40 \
  | while IFS= read -r u; do
      f="$DEL/js/$(printf '%s' "$u" | md5sum | cut -c1-10).js"
      code=$(curl -sS --compressed -m 20 -A "$UA_B" -D "$DEL/js/hdr.tmp" -o "$f" -w '%{http_code}' "$u" 2>/dev/null)
      ctg=$(grep -i '^content-type:' "$DEL/js/hdr.tmp" 2>/dev/null | head -1 | tr -d '\r')
      if [ "$code" = "200" ] && printf '%s' "$ctg" | grep -qiE 'javascript|ecmascript'; then
        printf '%s  %s\n' "$(md5sum "$f" | cut -d' ' -f1)" "$u" >> "$DEL/js_hashes.new"
      else
        rm -f "$f"
      fi
      sleep 3
    done
  if [ -s "$DEL/js_hashes.prev" ]; then
    comm -13 <(awk '{print $1}' "$DEL/js_hashes.prev" | sort -u) <(awk '{print $1}' "$DEL/js_hashes.new" | sort -u) > "$DEL/js_hashes.changed" 2>/dev/null || true
    n=$(wc -l < "$DEL/js_hashes.changed" 2>/dev/null || echo 0)
    log "   js bundles hashed=$(wc -l < "$DEL/js_hashes.new") changed-since-last-pass=$n"
    [ "$n" -gt 0 ] && log "   ⚠ JS CODE CHANGED — review delta/js_hashes.new before the hunt stage"
  else
    log "   js baseline recorded: $(wc -l < "$DEL/js_hashes.new") bundles"
  fi
  cp -f "$DEL/js_hashes.new" "$DEL/js_hashes.prev" 2>/dev/null || true
  log "-- agent pass (Hermes) reads the delta and appends leads"
  local prompt
  prompt="$(common_rules)
You are the RESEARCH/RECON stage of a continuous assessment loop. Working dir: $ROOT.
Read: $ROOT/RECON_SUMMARY.md, $ROOT/MICROKEEPER-ENGAGEMENT-STATUS-2026-11-14.md, and TODAY'S DELTA files in $DEL
(hosts.now/hosts.new, httpx.now/httpx.new, urls.new, js_hashes.new, plus raw JS in $DEL/js).
Task: (1) list every NEW or CHANGED asset/endpoint/JS bundle vs the prior engagement; (2) for each, name the
specific attack surface and the ONE most promising class; (3) append one JSON line per lead to $LEADS with
fields {ts,asset,endpoint,class,hypothesis,next_test,status:\"open\"}. Cap at 15 leads, most promising first.
Do NOT run intrusive tests in this stage. Finish with a 5-line summary of the delta."
  prompt="$prompt

$(routing_block)"
  printf '%s\n' "$prompt" > "$STATE/prompt-recon.txt"
  run_stage recon "$STATE/prompt-recon.txt" 40 || log "   (recon stage returned non-zero; delta files still written)"
  log "   leads total=$(wc -l < "$LEADS" 2>/dev/null || echo 0)"
}

# ---------------------------------------------------------------- 2. HUNT  (opencode)
phase_hunt(){
  log "=== PHASE hunt (hermes) ==="
  local prompt
  prompt="$(common_rules)
You are the HUNT stage of a continuous assessment loop (stage 2 of 4: research -> HUNT -> chain -> validate).
Read first: $ROOT/RECON_SUMMARY.md, $ROOT/MICROKEEPER-ENGAGEMENT-STATUS-2026-11-14.md (sections 3 NEGATIVES and 6 LEADS
— do not re-test what is already closed there), and the OPEN leads in $LEADS plus $STATE/delta/urls.new.
COVERAGE QUEUE (binding): $STATE/coverage.tsv is the work-item matrix (host x endpoint x vuln_class); $STATE/next-cells.txt
holds the next untested in-scope cells, most promising first. Work from the top of that file. For EVERY cell you test,
update its row in coverage.tsv IN PLACE (same host|endpoint|class): status -> TESTED_NO_ISSUE | CANDIDATE | BLOCKED,
and set evidence_path to the file holding the request/response, plus a reason when BLOCKED. A cell whose status you did
not change was not tested. Append any newly discovered host/endpoint as NEW UNTESTED rows; never delete rows.
Pick the 3 most promising open leads/cells and actually attack them with curl/python over this VPS, read-only:
authn/authz bypass, session & privilege issues, payroll/PII data exposure, broken API auth, XSS/DOM XSS,
SQLi, LFI/file read, deserialization, command injection, SSRF. Read the shipped JS you find.
For every result append a JSON line to $CHAINS: {ts,lead,request,response,control,observation,status}.
A candidate is only 'candidate' if you have a request+response pair AND the negative control that must fail.
Non-destructive, paced >=3 s on the main host. Report at the end: what you tried, what responded, what is
new, and what you could not test and why."
  prompt="$prompt

$(routing_block)"
  printf '%s\n' "$prompt" > "$STATE/prompt-hunt.txt"
  run_stage hunt "$STATE/prompt-hunt.txt" 80 || log "   (hunt stage returned non-zero — check the log)"
}

# ---------------------------------------------------------------- 3. BYPASS / CHAINING  (commandcode)
phase_chain(){
  log "=== PHASE chain (opencode bypass) ==="
  local prompt
  prompt="$(common_rules)
You are the BYPASS/CHAINING stage (stage 3 of 4). Read $CHAINS (hunt candidates), $LEADS (open leads),
$ROOT/RECON_SUMMARY.md and the closed-negatives list in $ROOT/MICROKEEPER-ENGAGEMENT-STATUS-2026-11-14.md.
Job: take each candidate and try to (a) BYPASS its control — encoding, case, path shapes, parameter
pollution, alternate methods/headers, auth-context confusion — and (b) CHAIN it to real impact: a bypass
of a filter to reach a sink, an ID/reference to reach another tenant's data, a file read to a credential
to escalated access, an XSS to session theft. Keep going until the chain reaches a qualifying class or
you can state exactly why it cannot.
Log every attempt as a JSON line in $CHAINS with {ts,candidate,attempt,request,response,control,result}.
Do not mutate data. Do not report anything unproven. End with the ranked list of chains and, for each, the
single missing step."
  prompt="$prompt

$(routing_block)"
  printf '%s\n' "$prompt" > "$STATE/prompt-chain.txt"
  run_stage chain "$STATE/prompt-chain.txt" 60 || log "   (chain stage returned non-zero — check the log)"
}

# ---------------------------------------------------------------- 4. VALIDATION  (commandcode)
phase_validate(){
  log "=== PHASE validate (opencode) ==="
  local prompt
  prompt="$(common_rules)
You are the VALIDATION stage (stage 4 of 4). Read $CHAINS and validate ONLY candidates that claim real impact.
For each: (1) reproduce it end-to-end from a clean shell with the exact command; (2) run the negative control
that must fail and show it failing; (3) confirm there is no other explanation (static echo, cached page, your
own session); (4) grade it against the program grid; (5) write $STATE/validations/<id>.json with
{id,asset,endpoint,class,severity,program:high|medium|low|none,cvss,evidence,control,repro,impact,confidence,read_only:true}.
If it cannot be reproduced with a passing control, mark it 'unproven' and say so plainly — do NOT inflate.
Never mutate data. Finish with one line per candidate: id, verdict, severity."
  prompt="$prompt

$(routing_block)"
  printf '%s\n' "$prompt" > "$STATE/prompt-validate.txt"
  run_stage validate "$STATE/prompt-validate.txt" 60 || log "   (validate stage returned non-zero — check the log)"

  # report only High/Critical (doctrine); everything else is held for the operator
  for f in "$STATE"/validations/*.json; do
    [ -e "$f" ] || continue
    sev=$(python3 -c "import json,sys;d=json.load(open(sys.argv[1]));print(str(d.get('severity','')).lower())" "$f" 2>/dev/null || echo "")
    id=$(python3 -c "import json,sys;d=json.load(open(sys.argv[1]));print(d.get('id','?'))" "$f" 2>/dev/null || echo "?")
    case "$sev" in
      *high*|*critical*)
        # NOTIFICATION POLICY (operator directive 2026-11-19): "validated" is a LEAD, not a finding.
        # Nothing is rendered and nothing reaches Discord unless the record is Exploited&Ready
        # (executed end-to-end + PoC artefact on disk). See notify-policy.sh.
        if bash "$HA/notify-policy.sh" finding "$f" "🔥 **$id** ($sev) — EXPLOITED & READY TO SUBMIT (Microkeeper). Report PDF attached." >> "$LOG" 2>&1; then
          log "   $id ($sev) EXPLOITED & READY -> PDF delivered"
        else
          log "   $id ($sev) = validated LEAD (not executed end-to-end) -> held locally, no PDF, no Discord"
          bash "$HA/notify-policy.sh" suppress "$f" lead "$id ($sev) validated, not executed end-to-end" >> "$LOG" 2>&1 || true
          echo "{\"ts\":\"$(date -Is)\",\"file\":\"$f\",\"severity\":\"$sev\",\"reason\":\"not-exploited\"}" >> "$HELD"
        fi ;;
      *) [ -n "$sev" ] && { log "   $id = $sev (held, not posted)"; echo "{\"ts\":\"$(date -Is)\",\"file\":\"$f\",\"severity\":\"$sev\"}" >> "$HELD"; } ;;
    esac
  done
}

# ------------------------------------------------------- 0. COVERAGE MATRIX (deterministic, no LLM)
phase_coverage(){
  log "=== PHASE coverage (work-item matrix) ==="
  python3 "$HA/mk-coverage.py" --next 15 >> "$LOG" 2>&1
  local rc=$?
  log "   coverage rows=$(gct . "$STATE/coverage.tsv")  next-cells=$(gct . "$STATE/next-cells.txt")  gate-rc=$rc"
  case "$rc" in
    2) log "   coverage gate: untested in-scope cells remain — hunting continues (this is the normal state)" ;;
    3) log "   coverage gate: a completion claim was made while untested cells remain — REFUSED, loop keeps hunting" ;;
  esac
  return 0
}

phase_state(){
  touch "$LEADS" "$CHAINS" "$HELD"
  echo "microkeeper loop state ($STATE)"
  echo "  leaders: $(wc -l < "$LEADS" 2>/dev/null || echo 0)  chains: $(wc -l < "$CHAINS" 2>/dev/null || echo 0)  held: $(wc -l < "$HELD" 2>/dev/null || echo 0)"
  ls -1t "$LOGD" 2>/dev/null | head -5
  for f in "$STATE"/validations/*.json; do [ -e "$f" ] && python3 -c "
import json,sys
d=json.load(open('$f'))
print('  ',d.get('id'),'|',d.get('severity'),'|',str(d.get('impact'))[:100])" 2>/dev/null; done
}

case "$PASS" in
  coverage) phase_coverage ;;
  research) phase_research ;;
  hunt)     phase_hunt ;;
  chain)    phase_chain ;;
  validate) phase_validate ;;
  --status) phase_state ;;
  all|*)    log "=== MICROKEEPER LOOP PASS START ==="; phase_coverage; phase_research; phase_hunt; phase_chain; phase_validate ;;
esac
if [ "$PASS" != "--status" ]; then
  touch "$LEADS" "$CHAINS" "$HELD"
  { echo "# Microkeeper loop state — $(date '+%F %T') (pass: $PASS)"; echo
    echo "leads: $(wc -l < "$LEADS" 2>/dev/null || echo 0) | chains: $(wc -l < "$CHAINS" 2>/dev/null || echo 0) | held: $(wc -l < "$HELD" 2>/dev/null || echo 0)"; echo
    echo "## open leads (last 20)"; tail -20 "$LEADS" 2>/dev/null; echo
    echo "## validations"; for f in "$STATE"/validations/*.json; do [ -e "$f" ] && python3 -c "
import json;d=json.load(open('$f'));print('-',d.get('id'),d.get('severity'),d.get('confidence'))" 2>/dev/null; done
  } > "$STATE/LOOP_STATE.md"
  log "=== MICROKEEPER LOOP PASS END ($PASS) ==="
fi
