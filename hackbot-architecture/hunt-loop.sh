#!/usr/bin/env bash
# hunt-loop.sh — GENERIC per-target hunting loop (Q6: decouple from microkeeper).
#
# Runs a full recon->validate cycle on ANY target, one at a time, with cleanly
# isolated per-target state, scope and artefacts:
#   /root/state/recon/<slug>/{surface,loop,delta,evidence}
#
# ROLE MAP (operator spec, Q8):
#   research  = commandcode        (external writeup intake -> skill upgrade)
#   recon     = hermes             (delta + enumeration)
#   hunt      = hermes             (attack the priority surfaces)
#   bypass+chain = opencode        (control bypass + escalation chaining)
#   validate  = opencode           (reproduce + negative controls -> verdict JSON)
#   report    = deterministic report-pdf.sh -> Discord PDF (never an LLM)
# Every ladder is probe-based and ENDS at hermes, so a lapsed CLI credential
# degrades a stage instead of skipping it.
#
# usage: hunt-loop.sh --target <host> [--slug S] [--scope FILE]
#                     [--phases coverage,surface,recon,hunt,chain,validate]
#                     [--dry-run]
set -uo pipefail
export PATH="/root/.hermes/hermes-agent/.hermes/bin:/root/go/bin:/usr/local/bin:/root/.local/bin:/usr/bin:/bin:${PATH:-}"

# gct <grep-args...> — like `grep -c` but ALWAYS yields exactly one integer.
# `$(grep -c X f || echo 0)` is a trap: grep -c prints "0" AND exits 1 on no match,
# so the fallback appends a second 0 -> "0\n0" -> "[ 0\n0 -gt 0 ]: integer expression expected".
gct(){ local n; n=$(grep -c "$@" 2>/dev/null); printf '%s' "${n:-0}"; }


TARGET=""; SLUG=""; SCOPE=""; PHASES="coverage,surface,recon,hunt,chain,validate"; DRY=0
HOSTS_FILE=""; EXCL_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --target) TARGET="$2"; shift 2;;
    --slug) SLUG="$2"; shift 2;;
    --scope) SCOPE="$2"; shift 2;;
    --hosts) HOSTS_FILE="$2"; shift 2;;
    --exclusions) EXCL_FILE="$2"; shift 2;;
    --phases) PHASES="$2"; shift 2;;
    --dry-run) DRY=1; shift;;
    *) echo "unknown arg: $1"; exit 2;;
  esac
done
[ -n "$TARGET" ] || { echo "usage: hunt-loop.sh --target <host> [...]"; exit 2; }
[ -n "$SLUG" ] || SLUG="$(printf '%s' "$TARGET" | tr 'A-Z' 'a-z' | sed 's/[^a-z0-9]/-/g')"
HA=/root/hackbot-architecture
STATE=/root/state/recon/$SLUG; SURF=$STATE/surface; DEL=$STATE/delta; LOGD=$STATE/logs
LOOPD=$STATE/loop
mkdir -p "$STATE" "$SURF" "$DEL" "$LOGD" "$LOOPD" "$LOOPD/validations"
LOG="$LOGD/pass-$(date +%Y%m%d-%H%M)-$SLUG.log"
LEADS="$LOOPD/leads.jsonl"; CHAINS="$LOOPD/chains.jsonl"; HELD="$LOOPD/held.jsonl"
COV="$LOOPD/coverage.tsv"
touch "$LEADS" "$CHAINS" "$HELD"
[ -n "$SCOPE" ] && [ -f "$SCOPE" ] && cp -f "$SCOPE" "$STATE/scope.txt"
SCOPE_TXT="$STATE/scope.txt"
HOSTS_TXT="$STATE/allowlist.txt"
[ -n "$HOSTS_FILE" ] && [ -f "$HOSTS_FILE" ] && cp -f "$HOSTS_FILE" "$HOSTS_TXT"
EXCL_TXT="$STATE/exclusions.txt"
[ -n "$EXCL_FILE" ] && [ -f "$EXCL_FILE" ] && cp -f "$EXCL_FILE" "$EXCL_TXT"
SKILL_CORE="$HA/knowledge/SKILL-CORE.md"
SKILL_INDEX="$HA/knowledge/SKILL-INDEX.md"
SUBCLASS="$LOOPD/subclass-checklist.md"
[ -f "$SUBCLASS" ] || cp -f /root/state/recon/microkeeper/loop/subclass-checklist.md "$SUBCLASS" 2>/dev/null || true
UA_B="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"

exec 9>"$LOOPD/.pass.lock"
flock -n 9 || { echo "a $SLUG pass is already running — exit 75"; exit 75; }

log(){ echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }
notch(){ bash "$HA/notch.sh" "$1" >/dev/null 2>&1 || echo "notch failed"; }

routing_block(){
  cat <<EOF
METHODOLOGY ROUTING (binding). Do NOT read the ledgers top-to-bottom (47,429 lines).
Route: grep -n -i '<class>' $SKILL_INDEX   then   read_file(<ledger>, offset=<line-5>, limit=200)
Modular per-class files: $HA/knowledge/modular/<class>.md (+ <class>.index.md)

$(cat "$SKILL_CORE" 2>/dev/null)

SUBCLASS CHECKLIST — a coarse class is NOT covered until each subclass has a verdict:
$(cat "$SUBCLASS" 2>/dev/null)
EOF
}

common_rules(){
  cat <<RULES
TARGET: $TARGET
SCOPE FILE: $SCOPE_TXT $([ -f "$SCOPE_TXT" ] && echo '(READ IT FIRST — it is authoritative)' || echo '(none supplied: treat ONLY this host as in scope, everything else OUT)')
$([ -f "$HOSTS_TXT" ] && echo "STRICT ALLOWLIST (read $HOSTS_TXT) — these hosts and ONLY these hosts may be
resolved, requested, port-scanned or fuzzed. NO wildcard subdomain enumeration or permutation guessing.
A host not on the list is OUT OF SCOPE; contacting it is a scope violation. Never do it.")
$([ -f "$EXCL_TXT" ] && { echo "EXCLUSIONS / NOISE (read $EXCL_TXT) — never report these, and never spend a cycle on
them beyond what is needed to prove a chain into a qualifying class:"; grep -E '^(EXCLUDE|PRIORITY|BLOCK)' "$EXCL_TXT" | sed 's/^/  /'; })
HARD RULES: non-destructive only. No DoS/DDoS, no brute force beyond a handful of probes, no social
engineering, never mutate real data. Any write requires operator sign-off. Unproven = lead, never a finding.
PACING: browser User-Agent, >=3 s between requests to the main host, bursts under 50 (Cloudflare 1015 risk).
EVIDENCE: every claim needs the exact request, the response, and a NEGATIVE CONTROL that must fail.
CREDENTIALS: if a stage needs an authenticated session / verified account to proceed (SMS-gated signup,
  MFA, login wall), STOP that line of work and write a JSON line to $STATE/credential-request.jsonl with
  {ts,need,why,endpoint,how_to_supply}. Do NOT guess or create accounts beyond the single permitted one.
SERVICE GUARD: never stop/restart/disable any systemd unit or kill processes; the operator manages the loop.
$([ -f "$STATE/OBJECTIVE.md" ] && { echo "OPERATOR OBJECTIVE (BINDING — read $STATE/OBJECTIVE.md in full before choosing work; it overrides the generic priority order):"; sed 's/^/  /' "$STATE/OBJECTIVE.md"; })
RULES
}

probe_opencode(){ timeout 150 opencode run "Reply with exactly: OC_OK" >/dev/null 2>&1; }
probe_commandcode(){ timeout 45 commandcode -p 'ping' --max-turns 1 >/dev/null 2>&1; }
probe_hermes(){ timeout 120 hermes -z "Reply with exactly: HB_OK" --yolo >/dev/null 2>&1; }
run_hermes(){ timeout 2400 hermes -z "$(cat "$1")" --yolo >> "$LOG" 2>&1; }   # H28 FIX: do NOT pin "-m commandcode/deepseek/deepseek-v4-flash --provider commandcode" (404s: "Beam 1.0 free period ended"); config.yaml default already = deepseek/deepseek-v4-flash @ commandcode
run_opencode(){ timeout 2400 opencode run "$(cat "$1")" -f "$LEADS" -f "$SKILL_CORE" >> "$LOG" 2>&1; }
run_commandcode(){ timeout 2400 commandcode -p "$(cat "$1")" --tools-all --permission-mode yolo --max-turns "${2:-80}" >> "$LOG" 2>&1; }

run_stage(){ # run_stage <recon|hunt|chain|validate> <prompt-file> [turns]
  local stage="$1" pf="$2" turns="${3:-60}"
  case "$stage" in
    recon|hunt)
      if probe_hermes; then log "   [agent] $stage = hermes"; run_hermes "$pf" "$turns"
      elif probe_opencode; then log "   [agent] $stage = opencode (hermes probe failed)"; run_opencode "$pf"
      else log "   [agent] $stage = NO AGENT AVAILABLE"; return 1; fi ;;
    chain|validate)
      if probe_opencode; then log "   [agent] $stage = opencode"; run_opencode "$pf"
      elif probe_commandcode; then log "   [agent] $stage = commandcode (opencode probe failed)"; run_commandcode "$pf" "$turns"
      elif probe_hermes; then log "   [agent] $stage = hermes (fallback)"; run_hermes "$pf" "$turns"
      else log "   [agent] $stage = NO AGENT AVAILABLE"; return 1; fi ;;
  esac
}

phase_coverage(){ log "=== PHASE coverage ($SLUG) ==="; python3 "$HA/mk-coverage-generic.py" --slug "$SLUG" --next 15 ${HOSTS_FILE:+--hosts "$HOSTS_FILE"} >>"$LOG" 2>&1; log "   rc=$?"; }
phase_surface(){
  log "=== PHASE surface-sweep ($TARGET) ==="
  if [ "$DRY" = 1 ]; then log "   (dry-run: skipping network sweep)"; return 0; fi
  bash "$HA/surface-sweep.sh" "$TARGET" --slug "$SLUG" ${HOSTS_FILE:+--hosts "$HOSTS_FILE"} >>"$LOG" 2>&1
  local rc=$?
  if [ "$rc" = 3 ]; then
    # EDGE BLOCK (2026-11-18): the estate silently DROPs our packets, which looks like an outage.
    # Running the agent stages now would burn the whole pass against a black hole AND add to the
    # volume that caused the ban, so the pass ends here and block-watch.sh owns recovery detection.
    : > "$LOOPD/.blocked"
    log "   BLOCKED: estate unreachable (sweep rc=3) — skipping jsdeep + every agent stage this pass"
    if ! pgrep -f "block-watch.sh --slug $SLUG" >/dev/null 2>&1; then
      nohup bash "$HA/block-watch.sh" --slug "$SLUG" ${HOSTS_FILE:+--hosts "$HOSTS_FILE"} \
        --interval 900 --max-interval 3600 --notify >>"$LOG" 2>&1 &
      log "   block-watch.sh started (canary every 15m, backs off to 60m) — Discord on recovery"
    fi
    return 3
  fi
  [ "$rc" != 0 ] && log "   (sweep rc=$rc)"
  rm -f "$LOOPD/.blocked"
  log "=== PHASE jsdeep ($TARGET) ==="
  python3 "$HA/jsdeep.py" --target "$TARGET" --slug "$SLUG" >>"$LOG" 2>&1 || log "   (jsdeep non-zero)"
}

phase_recon(){
  log "=== PHASE recon (hermes) ==="
  local p; p="$(common_rules)
You are the RECON stage of a generic per-target loop. Working dir: $STATE.
Read: $SURF/* (ips, subdomains, httpx, headers, rootfiles, methods, dirs, urls, params, ports, js_urls)
and $LOOPD/jsdeep-leads.json (AST + source-map harvest).
Task: (1) list every NEW/changed host, endpoint, parameter, header anomaly, open port, fingerprint;
(2) for each, name the specific attack surface and the ONE most promising class;
(3) append one JSON line per lead to $LEADS {ts,asset,endpoint,class,hypothesis,next_test,status:\"open\"}.
Cap 20 leads, most promising first. No intrusive tests here.

$(routing_block)"
  printf '%s\n' "$p" > "$LOOPD/prompt-recon.txt"
  [ "$DRY" = 1 ] && { log "   (dry-run: prompt written)"; return 0; }
  run_stage recon "$LOOPD/prompt-recon.txt" 60 || log "   (recon non-zero)"
}

phase_hunt(){
  log "=== PHASE hunt (hermes) ==="
  local p; p="$(common_rules)
You are the HUNT stage. Read $LOOPD/next-cells.txt (untested cells, most promising first) and the open
leads in $LEADS. Work from the TOP of next-cells. For EVERY cell you test, update its row in $COV
IN PLACE (status -> TESTED_NO_ISSUE|CANDIDATE|BLOCKED + evidence_path + reason). A row you did not
change was not tested. Attack the top 3 cells for real, read-only, and work the SUBCLASS checklist —
a coarse class is not covered until every subclass has a verdict.
Append results to $CHAINS {ts,lead,request,response,control,observation,subclass,status}.

$(routing_block)"
  printf '%s\n' "$p" > "$LOOPD/prompt-hunt.txt"
  [ "$DRY" = 1 ] && { log "   (dry-run: prompt written)"; return 0; }
  run_stage hunt "$LOOPD/prompt-hunt.txt" 80 || log "   (hunt non-zero)"
}

phase_chain(){
  log "=== PHASE chain/bypass (opencode) ==="
  local p; p="$(common_rules)
You are the BYPASS/CHAINING stage. Read $CHAINS (candidates) and $LEADS.
For each candidate: (a) BYPASS the control — encoding, case, path shapes, parameter pollution,
alternate methods/headers, auth-context confusion; (b) CHAIN to real impact until it reaches a
qualifying class or you can state exactly why it cannot. Append to $CHAINS.
Do not mutate data. End with the ranked chains and each one's single missing step.

$(routing_block)"
  printf '%s\n' "$p" > "$LOOPD/prompt-chain.txt"
  [ "$DRY" = 1 ] && { log "   (dry-run: prompt written)"; return 0; }
  run_stage chain "$LOOPD/prompt-chain.txt" 60 || log "   (chain non-zero)"
}

phase_validate(){
  log "=== PHASE validate (opencode) ==="
  local p; p="$(common_rules)
You are the VALIDATION stage. Validate ONLY candidates claiming real impact. For each: reproduce
end-to-end from a clean shell; run the negative control and show it FAILING; rule out static echo,
caching and your own session; grade against the program grid; write
$LOOPD/validations/<id>.json {id,asset,endpoint,class,severity,program,cvss,evidence,control,repro,impact,confidence,read_only:true}.
If it cannot be reproduced with a passing control, mark it unproven — do NOT inflate.

$(routing_block)"
  printf '%s\n' "$p" > "$LOOPD/prompt-validate.txt"
  [ "$DRY" = 1 ] && { log "   (dry-run: prompt written)"; return 0; }
  run_stage validate "$LOOPD/prompt-validate.txt" 60 || log "   (validate non-zero)"

  for f in "$LOOPD"/validations/*.json; do
    [ -e "$f" ] || continue
    sev=$(python3 -c "import json,sys;print(str(json.load(open(sys.argv[1])).get('severity','')).lower())" "$f" 2>/dev/null || echo "")
    id=$(python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('id','?'))" "$f" 2>/dev/null || echo "?")
    case "$sev" in
      *high*|*critical*) log "   $id ($sev) validated -> Exploited&Ready gate decides (no chat from this stage)"
        # NOTIFICATION POLICY (2026-11-19): report-pdf.sh self-gates — a validated record is a LEAD and
        # is refused unless it is executed end-to-end with a PoC artefact on disk.
        bash "$HA/notify-policy.sh" finding "$f" "🔥 **$id** ($sev) — EXPLOITED & READY TO SUBMIT ($SLUG). Report PDF attached." >>"$LOG" 2>&1 \
          || bash "$HA/notify-policy.sh" suppress "$f" lead "$id ($sev) validated, not executed end-to-end" >>"$LOG" 2>&1 || true ;;
      *) [ -n "$sev" ] && { log "   $id = $sev (held)"; echo "{\"ts\":\"$(date -Is)\",\"file\":\"$f\",\"severity\":\"$sev\"}" >> "$HELD"; } ;;
    esac
  done
  # QUIET MODE: cycle health goes to the LOCAL log only (no Discord).
  bash "$HA/cycle-report.sh" "$SLUG" --no-send >>"$LOG" 2>&1 || true
  # Discord fires ONLY on a validated qualifying bug or an auth-session request.
  bash "$HA/alert-only.sh" "$SLUG" >>"$LOG" 2>&1 || true
}

IFS=',' read -ra WANT <<< "$PHASES"
log "=== $SLUG LOOP PASS START (target=$TARGET, phases=$PHASES) ==="
for ph in "${WANT[@]}"; do
  case "$ph" in
    recon|hunt|chain|validate)
      # Never run an agent stage while the estate is dropping our packets: the findings would be
      # fabricated by silence, and the traffic only deepens the ban.
      if [ -f "$LOOPD/.blocked" ]; then log "   skipping phase '$ph' — edge block in effect (recovery: block-watch.sh)"; continue; fi;;
  esac
  case "$ph" in
    coverage) phase_coverage;;
    surface)  phase_surface;;
    recon)    phase_recon;;
    hunt)     phase_hunt;;
    chain)    phase_chain;;
    validate) phase_validate;;
    *) log "   unknown phase '$ph'";;
  esac
done
log "=== $SLUG LOOP PASS END ==="
# Surface the edge-block to the supervisor so it backs off instead of re-running the pass
# every 20m into a black hole.
[ -f "$LOOPD/.blocked" ] && exit 3
exit 0
