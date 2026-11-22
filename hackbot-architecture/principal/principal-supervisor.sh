#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# principal-supervisor.sh — PERSISTENT multi-agent bug-bounty supervisor.
#
# The principal owns: the active target, the task queue, agent health, coverage,
# validation, reporting and the never-ending cycle. Worker agents are dispatched
# as bounded, time-limited hermes sessions over the SHARED FILESYSTEM.
#
#   recon -> map -> hunt wave (parallel disciplines) -> bypass/chain -> validate
#        -> report -> knowledge -> next cycle -> repeat forever
#
# usage:
#   principal-supervisor.sh                # daemon loop (systemd default)
#   principal-supervisor.sh --once         # one cycle, then exit
#   principal-supervisor.sh --selftest     # offline mechanics test (no network)
#   principal-supervisor.sh --status       # print state, exit
#
# Operator controls (env, all optional):
#   PRINCIPAL_TARGET_CONF   path to active_target.conf (default principal/active_target.conf)
#   PRINCIPAL_LOOP_GAP      seconds between cycles (default 1800)
#   PRINCIPAL_AGENT_TIMEOUT per-agent timeout seconds (default 1800)
#   PRINCIPAL_MAX_PARALLEL  max concurrent agents (default 3)
#   PRINCIPAL_MAX_CELLS     max cells per discipline slice (default 25)
#   PRINCIPAL_WAVE          comma list of disciplines (default serverside,clientside,injection,business)
#   PRINCIPAL_NO_NETWORK    1 = skip surface-sweep/jsdeep (artifact-driven only)
# ══════════════════════════════════════════════════════════════════════════════
set -uo pipefail
export PATH="/root/.hermes/hermes-agent/.hermes/bin:/root/go/bin:/usr/local/bin:/root/.local/bin:/usr/bin:/bin:${PATH:-}"

HA=/root/hackbot-architecture
PR="$HA/principal"
PROMPTS="$PR/prompts"
PS="$PR/state"
PF="$PR/findings"
PEV="$PR/evidence"
PREP="$PR/reports"
PHIST="$PR/history"
mkdir -p "$PS" "$PF" "$PEV" "$PREP" "$PHIST" "$PS/prompts"
LOG="$PR/supervisor.log"
LOCK="$PR/.principal.lock"
TARGET_CONF="${PRINCIPAL_TARGET_CONF:-$PR/active_target.conf}"

LOOP_GAP="${PRINCIPAL_LOOP_GAP:-1800}"
AGENT_TIMEOUT="${PRINCIPAL_AGENT_TIMEOUT:-1800}"
MAX_PARALLEL="${PRINCIPAL_MAX_PARALLEL:-3}"
MAX_CELLS="${PRINCIPAL_MAX_CELLS:-25}"
WAVE="${PRINCIPAL_WAVE:-serverside,clientside,injection,business}"
NO_NETWORK="${PRINCIPAL_NO_NETWORK:-0}"
MODE="${1:---daemon}"
DRY=0

touch "$LOG"
log(){ printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG"; }
dlog(){ [ "$DRY" = 1 ] && log "  (dry) $*" || true; }

# gct — like grep -c but ALWAYS yields exactly one integer. `grep -c X f || echo 0`
# prints "0" AND exits 1 on no match, so the fallback appends a SECOND 0 and any
# `[ "$n" -gt 0 ]` aborts with "integer expression expected".
gct(){ local n; n=$(grep -c "$@" 2>/dev/null); printf '%s' "${n:-0}"; }

# ── single-instance lock (read-only --status is exempt) ─────────────────────
if [ "$MODE" != "--status" ]; then
  exec 9>"$LOCK"
  if ! flock -n 9; then
    log "another principal supervisor holds $LOCK — exit 75"
    exit 75
  fi
fi

# ── runtime state (set by load_target) ───────────────────────────────────────
TARGET=""; SLUG=""; SCOPE=""; HOSTS=""; EXCLUSIONS=""; PROGRAM=""; CONF_HASH=""
STATE="/root/state/recon"          # per-target generic-harness tree
PST=""                            # principal per-target state dir
CYCLE=0
ENGINE="none"; ENGINE_PROVIDER=""; ENGINE_MODEL=""

# ── helpers ──────────────────────────────────────────────────────────────────
now(){ date '+%F %T'; }
iso(){ date '+%Y-%m-%dT%HM%SZ' 2>/dev/null || date '+%Y-%m-%dT%H:%M:%SZ'; }

write_json(){ # <path> <json>
  local p="$1" j="$2"
  mkdir -p "$(dirname "$p")"
  printf '%s' "$j" > "$p.tmp" && mv -f "$p.tmp" "$p"
}

load_target(){
  [ -f "$TARGET_CONF" ] || return 1
  TARGET=""; SLUG=""; SCOPE=""; HOSTS=""; EXCLUSIONS=""; PROGRAM=""
  # trusted local operator conf
  # shellcheck disable=SC1090
  . "$TARGET_CONF"
  [ -n "${TARGET:-}" ] || { log "conf $TARGET_CONF has no TARGET — ignoring"; return 1; }
  [ -n "${SLUG:-}" ] || SLUG="$(printf '%s' "$TARGET" | tr 'A-Z' 'a-z' | sed 's/[^a-z0-9]/-/g')"
  CONF_HASH="$(sha256sum "$TARGET_CONF" | cut -d' ' -f1)"
  STATE="/root/state/recon/$SLUG"
  PST="$PS/targets/$SLUG"
  mkdir -p "$PST" "$STATE/surface" "$STATE/loop" "$STATE/delta" "$STATE/logs" \
           "$STATE/evidence" "$STATE/artifacts" "$STATE/agents"
  return 0
}

active_hash(){
  [ -f "$PS/active_target.json" ] || { echo ""; return; }
  jq -r '.conf_hash // ""' "$PS/active_target.json" 2>/dev/null || echo ""
}

# ── engine resolution: probe, cache, never assume ────────────────────────────
resolve_engine(){
  local cache="$PS/engine.json" age
  if [ -f "$cache" ]; then
    age=$(( $(date +%s) - $(stat -c %Y "$cache" 2>/dev/null || echo 0) ))
    if [ "$age" -lt 900 ]; then
      ENGINE="$(jq -r '.engine' "$cache" 2>/dev/null)"
      ENGINE_PROVIDER="$(jq -r '.provider // ""' "$cache" 2>/dev/null)"
      ENGINE_MODEL="$(jq -r '.model // ""' "$cache" 2>/dev/null)"
      [ "$ENGINE" = "hermes" ] && { log "engine: hermes via ${ENGINE_PROVIDER:-default} ${ENGINE_MODEL:-default} (cached)"; return 0; }
    fi
  fi
  log "probing inference engines..."
  ENGINE="none"; ENGINE_PROVIDER=""; ENGINE_MODEL=""
  if timeout 90 hermes chat -q 'Reply with exactly: ENG_OK' >/tmp/eng1.$$ 2>&1 && grep -aq ENG_OK /tmp/eng1.$$; then
    ENGINE=hermes; ENGINE_PROVIDER=""; ENGINE_MODEL=""; log "engine: hermes default (config) OK"
  elif timeout 90 hermes chat -q 'Reply with exactly: ENG_OK' --provider nous --model meituan/longcat-2.5:free >/tmp/eng2.$$ 2>&1 && grep -aq ENG_OK /tmp/eng2.$$; then
    ENGINE=hermes; ENGINE_PROVIDER="nous"; ENGINE_MODEL="meituan/longcat-2.5:free"; log "engine: hermes nous/longcat OK (fallback)"
  else
    log "engine: NONE AVAILABLE — agent stages will be skipped this cycle"
  fi
  rm -f /tmp/eng1.$$ /tmp/eng2.$$
  write_json "$cache" "$(jq -n --arg e "$ENGINE" --arg p "$ENGINE_PROVIDER" --arg m "$ENGINE_MODEL" \
      '{engine:$e,provider:$p,model:$m,checked:now}')"
}

run_agent_prompt(){ # <prompt-file> <out-file> [timeout]
  local pf="$1" out="$2" to="${3:-$AGENT_TIMEOUT}"
  [ "$ENGINE" = "hermes" ] || return 1
  local -a args=(chat --query-file "$pf" --quiet)
  [ -n "$ENGINE_PROVIDER" ] && args+=(--provider "$ENGINE_PROVIDER")
  [ -n "$ENGINE_MODEL" ] && args+=(--model "$ENGINE_MODEL")
  # stdout/stderr goes to a SEPARATE transcript, NEVER into the data file. The chat transcript carries
  # write_file DIFF MIRRORS (box-drawing '│' previews of every file the agent writes), and appending
  # that to the same path as the agent's JSONL output corrupts the contract: measured 2026-11-22, one
  # wave file became "entirely such junk" and two others needed cleanup, silently destroying agent
  # results (which then read as 'no candidates' rather than 'results lost').
  timeout "$to" hermes "${args[@]}" >>"${out}.transcript" 2>&1
}

# ── common rules block (target-parameterised) ────────────────────────────────
common_rules(){
  cat <<RULES
TARGET: $TARGET
SLUG: $SLUG
SCOPE FILE: ${SCOPE:-<none supplied — treat ONLY this host as in scope>}
$([ -n "$HOSTS" ] && [ -f "$HOSTS" ] && echo "STRICT ALLOWLIST ($HOSTS) — these hosts and ONLY these hosts may be resolved, requested, port-scanned or fuzzed. NO wildcard enumeration or permutation guessing. Anything else is OUT OF SCOPE and contacting it is a violation.")
$([ -n "$EXCLUSIONS" ] && [ -f "$EXCLUSIONS" ] && { echo "EXCLUSIONS / NOISE ($EXCLUSIONS):"; grep -E '^(EXCLUDE|PRIORITY|BLOCK)' "$EXCLUSIONS" 2>/dev/null | sed 's/^/  /'; })
STATE DIR: $STATE
PRINCIPAL STATE: $PST
$([ -f "$PST/program_rules.md" ] && { echo "PROGRAM RULES (BINDING — read $PST/program_rules.md in full before choosing work):"; sed 's/^/  /' "$PST/program_rules.md"; })

HARD RULES: non-destructive only. No DoS/DDoS, no brute force beyond a handful of probes,
no social engineering, never mutate real data. Any write requires operator sign-off.
Unproven = lead, never a finding.
PACING: browser User-Agent, >=3 s between requests to the main host, bursts under 50.
EVIDENCE: every claim needs the exact request, the response, and a NEGATIVE CONTROL that must fail.
CREDENTIALS: if a stage needs an authenticated session / verified account, STOP that line of
work and append a JSON line to $STATE/credential-request.jsonl with
{ts,need,why,endpoint,how_to_supply}. Do NOT guess or create accounts.
SERVICE GUARD: never stop/restart/disable any systemd unit and never kill any process.
The operator manages the loops. Write a note to the supervisor log instead.
FABRICATION: never invent endpoints, findings, responses, screenshots or commands.

METHODOLOGY ROUTING (binding). Do NOT read the 47k-line ledgers top-to-bottom.
Route: grep -n -i '<class>' $HA/knowledge/SKILL-INDEX.md then read_file(<ledger>, offset=<line-5>, limit=200)
Modular per-class files: $HA/knowledge/modular/<class>.md (+ <class>.index.md)
SEVERITY DOCTRINE — INLINED VERBATIM AND BINDING. This is NOT a pointer; the rule follows. Do not
skip it and do not claim you read a file: the text below IS the standard you are judged against.
$(cat "$HA/SEVERITY_DOCTRINE.md" 2>/dev/null | sed 's/^/  /')

P4/P5 SELF-CHECK (run BEFORE emitting any candidate; the most common self-inflicted failure):
  - Name the class from doctrine §1. If it is not in §1 it is NOT a candidate — it is a chain PRIMITIVE.
    Hold it in a lead, keep digging (bypass -> escalate -> chain), and emit NOTHING until the chain
    reaches real impact (account takeover / sensitive data / RCE / admin function / monetary loss).
  - Emitting a header/cookie-flag/TLS/version/banner/stack-trace/CORS-without-impact/open-redirect/
    self-XSS/clickjacking/rate-limit/CSV-injection item as a candidate is a PROCESS ERROR. Do not do it.
  - If your last three candidates were P4/P5, STOP and change ASSET or CLASS — do not lower the floor.
  - It is correct and expected to end a pass with: `no reportable finding — N primitives held as leads`.
RULES
  cat "$HA/knowledge/SKILL-CORE.md" 2>/dev/null | sed 's/^/  /'
}

build_prompt(){ # <discipline> <slice-file> <out-prompt> <out-data-file>
  # SPLIT, do not merge: in a single `local a="$1" b="$a"`, bash expands EVERY right-hand side
  # before performing ANY assignment, so `$disc` on the same line is still unset. Under `set -u`
  # that aborts the whole supervisor ("disc: unbound variable") on the FIRST recon dispatch —
  # i.e. every cycle crashed, systemd restarted it, and the loop re-ran recon forever and never
  # reached hunt. The offline selftest missed it because it dispatches a sentinel prompt and
  # never calls build_prompt().
  local disc="$1" slice="$2" out="$3" data="$4"
  local pf_name="$disc"
  case "$disc" in
    serverside) pf_name="server-side";;
    clientside) pf_name="client-side";;
    business)   pf_name="business-logic";;
    chain)      pf_name="bypass-chain";;
  esac
  {
    common_rules
    printf '\n\n'
    cat "$PROMPTS/$pf_name.md" 2>/dev/null || echo "(no discipline prompt for $disc)"
    if [ -n "$slice" ] && [ -s "$slice" ]; then
      printf '\n\n## TASK SLICE — your assigned cells (work top-down, do not overlap other agents)\n'
      cat "$slice"
    else
      printf '\n\n## TASK SLICE — none assigned. Do a coverage review of the highest-value unreviewed cells and report gaps.\n'
    fi
    printf '\n\n## OUTPUT CONTRACT (machine-readable)\nAppend one JSON object per line to:\n  %s\nUse status CANDIDATE only for real, evidenced candidates. Also write any durable map/plan artefacts under %s.\n' "$data" "$PST"
  } > "$out"
}

# ── agent status ledger ──────────────────────────────────────────────────────
agents_reset(){
  write_json "$PS/agent_status.json" "$(jq -n --arg t "$(now)" --arg slug "$SLUG" \
    '{updated:$t,slug:$slug,cycle:$cycle_no,agents:[]}' --argjson cycle_no "${CYCLE:-0}")"
}
agents_add(){ # name pid task status
  local n="$1" p="$2" t="$3" s="$4" f="$PS/agent_status.json"
  jq --arg n "$n" --argjson p "$p" --arg t "$t" --arg s "$s" --arg ts "$(now)" \
     '.agents += [{name:$n,pid:$p,task:$t,status:$s,started:$ts,ended:null,retries:0,error:""}] | .updated=$ts' \
     "$f" > "$f.tmp" && mv -f "$f.tmp" "$f"
}
agents_mark(){ # pid status [error]
  local p="$1" s="$2" e="${3:-}" f="$PS/agent_status.json"
  jq --argjson p "$p" --arg s "$s" --arg e "$e" --arg ts "$(now)" \
     '(.agents[] | select(.pid==$p)) |= (.status=$s | .ended=$ts | if $e=="" then . else .error=$e end) | .updated=$ts' \
     "$f" > "$f.tmp" && mv -f "$f.tmp" "$f"
}

# ── target init / archive / switch ───────────────────────────────────────────
init_target(){
  log "══ TARGET INIT: $TARGET (slug=$SLUG program=${PROGRAM:-n/a}) ══"
  mkdir -p "$STATE/surface" "$STATE/loop" "$STATE/delta" "$STATE/logs" "$STATE/evidence" "$STATE/agents" "$PST"
  [ -n "$SCOPE" ] && [ -f "$SCOPE" ] && cp -f "$SCOPE" "$STATE/scope.txt"
  [ -n "$HOSTS" ] && [ -f "$HOSTS" ] && cp -f "$HOSTS" "$STATE/allowlist.txt"
  [ -n "$EXCLUSIONS" ] && [ -f "$EXCLUSIONS" ] && cp -f "$EXCLUSIONS" "$STATE/exclusions.txt"
  touch "$STATE/loop/leads.jsonl" "$STATE/loop/chains.jsonl" "$STATE/loop/held.jsonl" \
        "$STATE/credential-request.jsonl" "$PF/candidates.jsonl" "$PF/confirmed.jsonl" \
        "$PF/rejected.jsonl" "$PF/hypotheses.jsonl"
  # scope.md
  { echo "# Scope — $TARGET ($SLUG)"; echo; echo "program: ${PROGRAM:-n/a}"; echo "activated: $(now)";
    echo; echo '```'; [ -f "$STATE/scope.txt" ] && cat "$STATE/scope.txt" || echo "(no scope file supplied)";
    echo '```'; echo; echo "## Allowlist (STRICT mode)"; echo '```';
    [ -f "$STATE/allowlist.txt" ] && cat "$STATE/allowlist.txt" || echo "(none — wildcard of target)";
    echo '```'; echo; echo "## Exclusions / noise"; echo '```';
    [ -f "$STATE/exclusions.txt" ] && cat "$STATE/exclusions.txt" || echo "(none)"; echo '```';
  } > "$PST/scope.md"
  # program_rules.md — operator fills; supervisor never invents rules
  if [ ! -f "$PST/program_rules.md" ]; then
    cat > "$PST/program_rules.md" <<'EOF'
# Program rules — OPERATOR FILL THIS IN (the supervisor does not invent rules)

Paste the program's own policy here: scope, prohibited testing, rate limits, mandatory
headers, bounty tiers / severity vocabulary, and any do-NOT-test list.

Until this file contains real rules, the supervisor enforces only: the scope/allowlist,
non-destructive testing, and the standing SEVERITY_DOCTRINE (HIGH/CRITICAL only).
EOF
  fi
  write_json "$PS/active_target.json" "$(jq -n --arg t "$TARGET" --arg s "$SLUG" \
    --arg sc "$SCOPE" --arg h "$HOSTS" --arg e "$EXCLUSIONS" --arg p "$PROGRAM" \
    --arg ch "$CONF_HASH" --arg ts "$(now)" \
    '{target:$t,slug:$s,scope:$sc,hosts:$h,exclusions:$e,program:$p,conf_hash:$ch,activated:$ts}')"
  write_json "$PST/task_queue.json" '{"target":"'"$SLUG"'","updated":"'"$(now)"'","tasks":[]}'
  write_json "$PST/cycle_state.json" '{"target":"'"$SLUG"'","cycle":0,"phase":"init","updated":"'"$(now)"'","history":[]}'
  agents_reset
  log "target state: $PST"
}

archive_target(){ # <reason>
  local why="${1:-cycle end}" d="$PHIST/$SLUG-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$d"
  for f in "$PS/active_target.json" "$PST/task_queue.json" "$PST/cycle_state.json" "$PS/agent_status.json"; do
    [ -f "$f" ] && cp -f "$f" "$d/" 2>/dev/null
  done
  [ -f "$PST/RECON_SUMMARY.md" ] && cp -f "$PST/RECON_SUMMARY.md" "$d/" 2>/dev/null
  log "archived $SLUG state -> $d ($why)"
}

switch_if_needed(){
  local h; h="$(active_hash)"
  if [ -z "$h" ]; then init_target; return 0; fi
  if [ "$h" != "$CONF_HASH" ]; then
    log "══ TARGET SWITCH: $SLUG -> $TARGET ══"
    archive_target "target switch"
    init_target
    return 0
  fi
  # same target: refresh conf-derived facts
  return 0
}

# ── phases ───────────────────────────────────────────────────────────────────
phase_recon(){
  log "PHASE recon begin"
  if [ "$NO_NETWORK" != 1 ]; then
    bash "$HA/surface-sweep.sh" "$TARGET" --slug "$SLUG" ${HOSTS:+--hosts "$HOSTS"} >>"$LOG" 2>&1
    local rc=$?
    if [ "$rc" = 3 ]; then
      log "PHASE recon: edge block (sweep rc=3) — artifact-driven this cycle"
      : > "$STATE/loop/.blocked"
      return 3
    fi
    python3 "$HA/jsdeep.py" --target "$TARGET" --slug "$SLUG" >>"$LOG" 2>&1 || log "   (jsdeep non-zero)"
    rm -f "$STATE/loop/.blocked"
  else
    log "   NO_NETWORK=1 — skipping surface-sweep/jsdeep"
  fi
  python3 "$HA/mk-coverage-generic.py" --slug "$SLUG" --next 15 ${HOSTS:+--hosts "$HOSTS"} >>"$LOG" 2>&1 || true
  python3 "$PR/phelp.py" assets "$STATE" "$PST/assets.json" >>"$LOG" 2>&1 || true
  if [ "$ENGINE" = "hermes" ]; then
    local pf="$PS/prompts/cycle-$CYCLE-recon.txt" df="$PST/recon-$CYCLE.jsonl"
    build_prompt recon "" "$pf" "$df"; : > "$df"
    log "   dispatch recon (timeout ${AGENT_TIMEOUT}s)"
    if run_agent_prompt "$pf" "$df"; then
      local n; n=$(gct '^{' "$df")
      log "   recon leads: $n"
      [ "$n" -gt 0 ] && cat "$df" >> "$STATE/loop/leads.jsonl"
    else
      log "   recon agent failed (engine or timeout) — recorded, next cycle retries"
    fi
  else
    log "   engine unavailable — recon agent skipped"
  fi
  log "PHASE recon done"
}

phase_map(){
  log "PHASE map begin"
  if [ "$ENGINE" != "hermes" ]; then log "   engine unavailable — mapper skipped"; return 0; fi
  local pf="$PS/prompts/cycle-$CYCLE-mapper.txt" df="$PST/map-$CYCLE.jsonl"
  build_prompt mapper "" "$pf" "$df"; : > "$df"
  # mapper writes the map files itself; give it the exact paths
  local extra="$PST/mapper-targets.txt"
  cat > "$extra" <<EOF
Write/update these files (absolute paths):
  $PST/endpoints.json
  $PST/application_map.md
  $PST/features.json
  $PST/roles.json
  $PST/coverage.json
EOF
  cat "$extra" >> "$pf"
  if run_agent_prompt "$pf" "$df"; then
    log "   mapper done"
  else
    log "   mapper failed — deterministic coverage.json still refreshed below"
  fi
  python3 "$PR/phelp.py" cov "$STATE/loop/coverage.tsv" "$PST/coverage.json" >>"$LOG" 2>&1 || true
  log "PHASE map done"
}

phase_hunt_wave(){
  log "PHASE hunt wave begin (disciplines: $WAVE)"
  python3 "$HA/mk-coverage-generic.py" --slug "$SLUG" --next 15 ${HOSTS:+--hosts "$HOSTS"} >>"$LOG" 2>&1 || true
  local sdir="$PST/slices"; mkdir -p "$sdir"; rm -f "$sdir"/*.txt
  python3 "$PR/slicer.py" "$STATE/loop/coverage.tsv" "$sdir" "$MAX_CELLS" >>"$LOG" 2>&1 || true
  IFS=',' read -ra DISC <<< "$WAVE"
  local -a names=() pids=() slices=()
  for d in "${DISC[@]}"; do
    d="$(printf '%s' "$d" | tr -d ' ')"
    [ -n "$d" ] || continue
    names+=("$d"); slices+=("$sdir/$d.txt")
  done
  [ "${#names[@]}" -eq 0 ] && { log "   no disciplines"; return 0; }
  agents_reset
  local launched=0 i
  for i in "${!names[@]}"; do
    [ "$launched" -ge "$MAX_PARALLEL" ] && break
    local d="${names[$i]}" sl="${slices[$i]}"
    local pf="$PS/prompts/cycle-$CYCLE-$d.txt" df="$PST/wave-$CYCLE-$d.jsonl"
    : > "$df"
    build_prompt "$d" "$sl" "$pf" "$df"
    log "   dispatch $d (timeout ${AGENT_TIMEOUT}s, slice $(gct . "$sl") cells)"
    run_agent_prompt "$pf" "$df" &
    local pid=$!
    pids+=("$pid"); launched=$((launched+1))
    agents_add "$d" "$pid" "hunt:$d" running
    log "   $d pid=$pid"
  done
  # wait with per-agent timeout, kill by PID only
  local deadline=$(( $(date +%s) + AGENT_TIMEOUT + 120 )) j pid rc
  for j in "${!pids[@]}"; do
    pid="${pids[$j]}"
    while kill -0 "$pid" 2>/dev/null; do
      if [ "$(date +%s)" -gt "$deadline" ]; then
        log "   ${names[$j]} pid=$pid TIMEOUT — killing"
        kill "$pid" 2>/dev/null || true
        agents_mark "$pid" timeout "exceeded ${AGENT_TIMEOUT}s"
        break
      fi
      sleep 5
    done
    wait "$pid" 2>/dev/null; rc=$?
    kill -0 "$pid" 2>/dev/null || agents_mark "$pid" "$([ "$rc" = 0 ] && echo done || echo failed)" "rc=$rc"
  done
  # collect
  local merged; merged=$(python3 "$PR/phelp.py" merge "$PF" "$PST/wave-$CYCLE-*.jsonl" "$SLUG" "$CYCLE" 2>>"$LOG")
  log "   wave merge: $merged"
  # retry once for empty critical disciplines
  for j in "${!names[@]}"; do
    local d="${names[$j]}"
    local df="$PST/wave-$CYCLE-$d.jsonl"
    if [ ! -s "$df" ] || ! grep -q '^{' "$df" 2>/dev/null; then
      log "   $d produced no JSON — one retry with a narrower prompt"
      build_prompt "$d" "" "$PS/prompts/cycle-$CYCLE-$d-retry.txt" "$df"
      if run_agent_prompt "$PS/prompts/cycle-$CYCLE-$d-retry.txt" "$df" 600; then
        log "   $d retry done"
      else
        log "   $d retry failed"
      fi
    fi
  done
  merged=$(python3 "$PR/phelp.py" merge "$PF" "$PST/wave-$CYCLE-*.jsonl" "$SLUG" "$CYCLE" 2>>"$LOG")
  log "   wave merge after retry: $merged"
  log "PHASE hunt wave done"
}

phase_chain(){
  log "PHASE bypass/chain begin"
  [ "$ENGINE" = "hermes" ] || { log "   engine unavailable — skipped"; return 0; }
  local n; n=$(gct '^{' "$PF/candidates.jsonl")
  [ "$n" -gt 0 ] || { log "   no candidates to chain"; return 0; }
  local pf="$PS/prompts/cycle-$CYCLE-chain.txt" df="$PST/chain-$CYCLE.jsonl"
  : > "$df"
  build_prompt bypass-chain "" "$pf" "$df"
  {
    echo
    echo "## CANDIDATES (read $PF/candidates.jsonl — the newest $n lines are this wave)"
    tail -n 40 "$PF/candidates.jsonl" 2>/dev/null | sed 's/^/  /'
  } >> "$pf"
  if run_agent_prompt "$pf" "$df"; then log "   chain agent done"; else log "   chain agent failed"; fi
  log "PHASE bypass/chain done"
}

phase_validate(){
  log "PHASE validate begin"
  [ "$ENGINE" = "hermes" ] || { log "   engine unavailable — skipped"; return 0; }
  local n; n=$(gct '^{' "$PF/candidates.jsonl")
  [ "$n" -gt 0 ] || { log "   no candidates"; return 0; }
  local pf="$PS/prompts/cycle-$CYCLE-validate.txt" df="$PST/verdicts-$CYCLE.jsonl"
  : > "$df"
  build_prompt validate "" "$pf" "$df"
  {
    echo
    echo "## CANDIDATES TO JUDGE (from $PF/candidates.jsonl)"
    echo "Already decided (do NOT re-litigate): $PF/confirmed.jsonl , $PF/rejected.jsonl"
    tail -n 60 "$PF/candidates.jsonl" 2>/dev/null | sed 's/^/  /'
  } >> "$pf"
  if run_agent_prompt "$pf" "$df"; then
    local applied; applied=$(python3 "$PR/phelp.py" verdict "$PF" "$df" 2>>"$LOG")
    log "   verdicts: $applied"
  else
    log "   validator failed — candidates stay NEW for the next cycle"
  fi
  log "PHASE validate done"
}

phase_report(){
  log "PHASE report begin"
  local n; n=$(gct '^{' "$PF/confirmed.jsonl")
  log "   confirmed findings: $n"
  # The gate owns Discord. Render+upload per record; report-pdf.sh self-gates on
  # notify-policy (executed end-to-end + PoC artefact) and dedupes by finding id.
  if [ "$n" -gt 0 ]; then
    local tmp="$PS/record.json" i=0 line
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      printf '%s' "$line" > "$tmp"
      bash "$HA/report-pdf.sh" --file "$tmp" >>"$LOG" 2>&1 || log "   (report-pdf non-zero for record $i)"
      i=$((i+1))
    done < "$PF/confirmed.jsonl"
  fi
  bash "$HA/alert-only.sh" "$SLUG" >>"$LOG" 2>&1 || true
  log "PHASE report done"
}

phase_knowledge(){
  log "PHASE knowledge begin"
  bash "$HA/research-upgrade.sh" --if-due >>"$LOG" 2>&1 || log "   (research-upgrade non-zero)"
  log "PHASE knowledge done"
}

cycle_record(){ # <result>
  local res="${1:-ok}" h="${PHIST}/cycles.jsonl"
  jq -n --arg slug "$SLUG" --arg cy "$CYCLE" --arg res "$res" --arg ts "$(now)" \
    '{ts:$ts,slug:$slug,cycle:($cy|tonumber),result:$res}' >> "$h"
  local cj="$PST/cycle_state.json"
  jq --arg ph "$2" --arg ts "$(now)" --arg res "$res" \
     '.phase=$ph | .updated=$ts | .last_result=$res' "$cj" > "$cj.tmp" 2>/dev/null && mv -f "$cj.tmp" "$cj" || true
}

run_cycle(){
  CYCLE=$((CYCLE+1))
  write_json "$PST/cycle_state.json" "$(jq -n --arg t "$SLUG" --argjson c "$CYCLE" --arg ts "$(now)" \
    '{target:$t,cycle:$c,phase:"begin",updated:$ts,last_result:""}' 2>/dev/null)"
  log "══ CYCLE $CYCLE begin (target=$TARGET) ══"
  resolve_engine
  switch_if_needed
  phase_recon; local r=$?; cycle_record "recon done" "recon"
  if [ "$r" = 3 ]; then
    log "edge-blocked at recon — skipping map/hunt/chain/validate/report this cycle"
    return 3
  fi
  phase_map;     cycle_record "map done" "map"
  phase_hunt_wave; cycle_record "hunt done" "hunt"
  phase_chain;   cycle_record "chain done" "chain"
  phase_validate; cycle_record "validate done" "validate"
  phase_report;  cycle_record "report done" "report"
  phase_knowledge; cycle_record "knowledge done" "knowledge"
  log "══ CYCLE $CYCLE complete — sleeping ${LOOP_GAP}s ══"
  return 0
}

# ── selftest (offline mechanics; no network, no scope) ───────────────────────
selftest(){
  log "SELFTEST begin"
  PST="$PS/selftest"; STATE="/root/state/recon/_selftest"; mkdir -p "$PST" "$STATE/loop"
  local pass=0 fail=0
  chk(){ if [ "$1" = 0 ]; then log "  PASS $2"; pass=$((pass+1)); else log "  FAIL $2"; fail=$((fail+1)); fi; }

  # 1. state dirs
  mkdir -p "$PS" "$PF" "$PEV" "$PREP"
  [ -d "$PS" ] && [ -d "$PF" ]; chk $? "state dirs"

  # 2. engine resolution path (cached)
  resolve_engine
  [ "$ENGINE" = "hermes" ]; chk $? "engine resolution (got: $ENGINE ${ENGINE_PROVIDER:-default})"

  # 3. agent dispatch mechanics with a minimal sentinel prompt
  local pf="$PS/prompts/selftest.txt" df="$PS/selftest-out.txt"
  { common_rules; printf '\nReply with exactly: SELFTEST_OK and nothing else.\n'; } > "$pf"
  : > "$df"
  run_agent_prompt "$pf" "$df" 240; chk $? "agent dispatch rc"
  grep -aq SELFTEST_OK "$df"; chk $? "agent produced sentinel"

  # 4. phelp merge + verdict on synthetic records
  local wf="$PS/selftest-wave.jsonl"
  printf '{"host":"selftest.local","endpoint":"/a","class":"xss","status":"CANDIDATE","title":"t"}\n{"host":"selftest.local","endpoint":"/b","class":"sqli","status":"CANDIDATE","title":"t2"}\n' > "$wf"
  python3 "$PR/phelp.py" merge "$PF" "$wf" "selftest" 0 >/dev/null 2>&1; chk $? "phelp merge"
  local c1; c1=$(gct 'selftest.local' "$PF/candidates.jsonl"); [ "${c1:-0}" -ge 2 ]; chk $? "candidates appended ($c1)"
  printf '{"id":"PR-selftest-0-0","verdict":"VERIFIED","reason":"selftest","severity":"high"}\n{"id":"PR-selftest-0-1","verdict":"FALSE_POSITIVE","reason":"selftest"}\n' > "$PS/selftest-verdicts.jsonl"
  python3 "$PR/phelp.py" verdict "$PF" "$PS/selftest-verdicts.jsonl" >/dev/null 2>&1; chk $? "phelp verdict"
  local c2; c2=$(gct 'PR-selftest-0-0' "$PF/confirmed.jsonl"); [ "${c2:-0}" -ge 1 ]; chk $? "confirmed written"

  # 5. slicer
  printf 'host\tendpoint\tmethod\tvuln_class\tstatus\tevidence_path\treason\tauth_state\trole\tupdated\nx\t/a\tGET\tsqli\tUNTESTED\t\t\tanon\tnone\t2026-01-01\nx\t/b\tGET\txss\tTESTED_NO_ISSUE\t\te\tanon\tnone\t2026-01-01\n' > "$PS/selftest-cov.tsv"
  python3 "$PR/slicer.py" "$PS/selftest-cov.tsv" "$PS/selftest-slices" 10 >/dev/null 2>&1; chk $? "slicer rc"
  [ -s "$PS/selftest-slices/injection.txt" ]; chk $? "slicer produced injection slice"
  [ ! -s "$PS/selftest-slices/clientside.txt" ]; chk $? "slicer excluded TESTED row"

  # 6. lock behaviour
  ( exec 9>"$LOCK"; flock -n 9 ) ; [ $? -ne 0 ]; chk $? "lock is held by this process"

  # 7. json state writes
  write_json "$PS/selftest.json" '{"ok":true}'; jq -e .ok "$PS/selftest.json" >/dev/null 2>&1; chk $? "json write/read"

  # cleanup synthetic ledgers
  rm -f "$PF/candidates.jsonl" "$PF/confirmed.jsonl" "$PF/rejected.jsonl" "$PS/selftest-wave.jsonl" \
        "$PS/selftest-verdicts.jsonl" "$PS/selftest-cov.tsv" "$PS/selftest.json" "$PS/selftest-out.txt"
  rm -rf "$PS/selftest-slices"
  log "SELFTEST end: pass=$pass fail=$fail"
  [ "$fail" = 0 ]; return $?
}

status_report(){
  echo "== principal status =="
  echo "conf: ${TARGET_CONF}"
  if [ -f "$PS/active_target.json" ]; then jq . "$PS/active_target.json"; else echo "(no active target)"; fi
  [ -f "$PS/agent_status.json" ] && { echo "-- agents"; jq '.agents | map({name,pid,status,task,started,ended})' "$PS/agent_status.json"; }
  [ -f "$PS/engine.json" ] && { echo "-- engine"; jq . "$PS/engine.json"; }
  for f in "$PF/candidates.jsonl" "$PF/confirmed.jsonl" "$PF/rejected.jsonl"; do
    [ -f "$f" ] && printf '%-40s %s\n' "$(basename "$f")" "$(gct . "$f")"
  done
  echo "-- log tail"; tail -15 "$LOG"
}

# ── entry ────────────────────────────────────────────────────────────────────
case "$MODE" in
  --selftest) selftest; exit $?;;
  --status)   status_report; exit 0;;
  --check-target)  # parse conf + run init/switch only; NO network, NO phases
              load_target || { echo "no usable target conf at $TARGET_CONF"; exit 2; }
              switch_if_needed
              echo "target=$TARGET slug=$SLUG hash=$CONF_HASH"
              echo "state=$PST"
              jq . "$PS/active_target.json" 2>/dev/null
              exit 0;;
  --once)     load_target || { log "no target conf at $TARGET_CONF — waiting"; exit 2; }
              CYCLE=0; resolve_engine; switch_if_needed; run_cycle; exit $?;;
  --daemon)   :;;
  *) echo "unknown mode: $MODE"; exit 2;;
esac

log "══ PRINCIPAL SUPERVISOR start (pid=$$ gap=${LOOP_GAP}s parallel=${MAX_PARALLEL}) ══"
while true; do
  if ! load_target; then
    log "no active target ($TARGET_CONF missing) — idle, waiting for the operator's target. sleep 60."
    sleep 60
    continue
  fi
  switch_if_needed
  run_cycle
  rc=$?
  [ "$rc" = 3 ] && { log "edge-blocked cycle — backing off 60m"; sleep 3600; continue; }
  log "cycle rc=$rc — sleeping ${LOOP_GAP}s"
  sleep "$LOOP_GAP"
done
