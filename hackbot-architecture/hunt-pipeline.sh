#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  hunt-pipeline.sh <target> — 3-FRAMEWORK FAN-OUT
#  Triggers the user's exact workflow across OpenCode + Hermes + CommandCode.
#
#    STAGE 1  RECON + fingerprinting + source/JS analysis  →  OpenCode
#    STAGE 2  bug hunting + injection + logic + chain/bypass →  Hermes
#    STAGE 3  validate + escalate + report writing          →  Hermes
#              (CommandCode cannot: print mode + dont-ask denies all writes)
#    STAGE 4  deliver report summary to Discord (bot home channel)
#
#  Each stage writes to /root/hackbot-architecture/state/ and findings/.
#  A MONITOR pass (monitor.sh) runs after each stage and re-drives it if the
#  stage stalled or produced nothing — the "push the agent" behavior.
# ══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

# gct <grep-args...> — like `grep -c` but ALWAYS yields exactly one integer.
# `$(grep -c X f || echo 0)` is a trap: grep -c prints "0" AND exits 1 on no match,
# so the fallback appends a second 0 -> "0\n0" -> "[ 0\n0 -gt 0 ]: integer expression expected".
gct(){ local n; n=$(grep -c "$@" 2>/dev/null); printf '%s' "${n:-0}"; }


ROOT="/root/hackbot-architecture"
STATE="$ROOT/state"
FIND="$ROOT/findings"
REPORTS="$ROOT/reports/raw"
mkdir -p "$STATE/recon" "$FIND" "$REPORTS"

TARGET="${1:-klook}"
MODE="${2:-hunt}"
LOG="$STATE/pipeline-${TARGET}.log"
DOCTRINE_FILE="$ROOT/SEVERITY_DOCTRINE.md"   # severity doctrine — binding on every stage
log(){ printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*" >> "$LOG"; }

# ── the operator's standing order, injected into every hunt/validate prompt ──
DOCTRINE="$(cat "$DOCTRINE_FILE" 2>/dev/null)"
STANDING_ORDER="STANDING ORDER FROM THE OPERATOR (Kr Hasan), read it twice:
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
- Think high-critical: always ask \"what is the worst outcome reachable here?\" and work back to it."

# ── model routing (cheap for recon, strong for hunt/validate) ────────────────
OC_MODEL="${OC_MODEL:-commandcode/deepseek/deepseek-v4-flash}"   # OpenCode recon
CC_MODEL="${CC_MODEL:-commandcode/deepseek/deepseek-v4-pro}"     # CommandCode validate
# Hermes hunt uses the gateway's main model (deepseek-v4-pro)

# ── Discord notify via BOT (two-way channel) ─────────────────────────────────
notify_discord(){
  local token channel msg
  token="$(grep -E '^DISCORD_BOT_TOKEN=' /root/.hermes/.env 2>/dev/null | sed 's/^[^=]*=//' | tr -d '\n')"
  channel="${DISCORD_HOME_CHANNEL:-1567763899808354387}"
  [ -z "$token" ] && return 0
  msg="$1"
  if [ "${#msg}" -gt 1900 ]; then msg="${msg:0:1900}…"; fi
  curl -sS -m 10 -o /dev/null -w '%{http_code}' \
    -X POST -H "Authorization: Bot $token" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg c "$msg" '{content:$c}')" \
    "https://discord.com/api/v10/channels/$channel/messages" 2>/dev/null
}

# ── scope resolution ─────────────────────────────────────────────────────────
resolve_scope(){
  case "$TARGET" in
    klook)  echo "/root/scope/klook-in-scope.txt" ;;
    aspire) echo "/root/scope/aspire-in-scope.txt" ;;
    subspace) echo "/root/scope/subspace-in-scope.txt" ;;
    groww) echo "/root/scope/groww-in-scope.txt" ;;
    swisslos) echo "/root/scope/swisslos-in-scope.txt" ;;
    magentrix|bugbounty) echo "/root/scope/magentrix-in-scope.txt" ;;
    norma) echo "/root/scope/norma-in-scope.txt" ;;
    phantombuster|pb) echo "/root/scope/phantombuster-in-scope.txt" ;;
    diepresse|presse) echo "/root/scope/diepresse-in-scope.txt" ;;
    mediacorp) echo "/root/scope/mediacorp-in-scope.txt" ;;
    malt) echo "/root/scope/malt-in-scope.txt" ;;
    riot|tryriot) echo "/root/scope/riot-in-scope.txt" ;;
    vwfs) echo "/root/scope/vwfs-in-scope.txt" ;;
    *)      for f in /root/scope/*.txt; do
              if grep -qi "$TARGET" "$f" 2>/dev/null; then echo "$f"; return 0; fi
            done
            echo "" ;;
  esac
}

SCOPE_FILE="$(resolve_scope)"

# ═══ STAGE 1 — RECON via OpenCode ═════════════════════════════════════════════
stage1_recon(){
  log "STAGE1 recon (OpenCode) begin"
  timeout 900 opencode run --model "$OC_MODEL" "You are the RECON specialist of a bug bounty hackbot. Target: $TARGET. Scope file: ${SCOPE_FILE:-none}. Perform information gathering, technology fingerprinting, source-code and JS-bundle analysis (map sources→sinks). Use subfinder, httpx, katana, gau, waybackurls, ffuf (read-only, NO attack payloads). Respect the mandatory User-Agent and out-of-scope rules in the scope file. Write structured results (hosts, endpoints, params, tech, JS findings) to /root/hackbot-architecture/state/recon/. Reply with a one-line summary: hosts found, endpoints, params." \
    >> "$LOG" 2>&1 || log "STAGE1: timed out/errored (non-fatal)"
  log "STAGE1 done: $(find "$STATE/recon" -type f -newermt '-2 minutes' 2>/dev/null | wc -l) files written"
}

# ═══ STAGE 2 — HUNT via Hermes ════════════════════════════════════════════════
stage2_hunt(){
  log "STAGE2 hunt (Hermes) begin"
  local wf
  wf="$(cat "$ROOT/MASTER_WORKFLOW.md" 2>/dev/null)"
  timeout 900 hermes chat -q "You are the HUNTING agent of a bug bounty hackbot. Target: $TARGET. FOLLOW this master methodology (stages 2-3 are authoritative):

$wf

════════ SEVERITY DOCTRINE — BINDING, OVERRIDES EVERYTHING BELOW ════════
$DOCTRINE
════════ end doctrine ════════

$STANDING_ORDER

Read /root/hackbot-architecture/state/recon/ (from OpenCode) and ${SCOPE_FILE:-/root/scope/*.txt}. Use the gathered info to find bugs: go at the SENSITIVE surface (auth/token, admin, account, payment, upload/download/export, internal & undocumented API, GraphQL, RPC, mobile BFF) and test injection (SQLi/XSS/RCE/XXE/SSRF/LFI/SSTI), break business-logic flow, chain primitives, attempt auth/OAuth bypass. NON-DESTRUCTIVE only. Append each candidate as JSON line {host,endpoint,param,vuln_class,evidence,confidence} to /root/hackbot-architecture/findings/candidates.jsonl. Do NOT emit doctrine-§2 ineligible items (version/banner disclosure, stack traces, CORS-without-impact, cookie flags, rate limiting, self-XSS, open redirect without impact) as standalone candidates. Never fabricate; no evidence = write nothing. Reply with a one-line count of candidates." \
    >> "$LOG" 2>&1 || log "STAGE2: timed out/errored (non-fatal)"
  log "STAGE2 done: $(wc -l < "$FIND/candidates.jsonl" 2>/dev/null || echo 0) candidates"
}

# ═══ RESUME — skip recon (artifacts already mapped), hunt the existing corpus ═
# Used when a prior run already completed stage 1 and the hunt stage died
# (provider outage / timeout). Reuses state/recon/ and never re-reports
# already-confirmed or already-rejected candidates.
stage2_hunt_resume(){
  log "STAGE2-resume hunt (Hermes) begin"
  local prompt_file="$STATE/hunt_resume_prompt.txt" attempt model before after
  {
    cat <<'PROMPT_EOF'
You are the HUNTING agent of a bug bounty hackbot, RESUMING a hunt that stopped
mid-way. Work ONLY on the target named below. This is an AUTHORIZED engagement.

RULES (hard):
- SEVERITY DOCTRINE is BINDING and is included below — read it in full before hunting.
  Hunt HIGH/CRITICAL only. Do NOT emit doctrine-§2 ineligible items (version/banner
  disclosure, stack traces, CORS-without-impact, cookie flags, rate limiting, self-XSS,
  open redirect without impact, content spoofing) as standalone candidates — they are
  chain primitives only. Do not report early: keep digging (bypass -> escalate -> chain)
  until the chain reaches real high/critical impact, or drop it in silence.
  Spend no requests on pointless enumeration: go straight at the sensitive endpoints
  (auth/token, admin, account, payment, upload/download/export, internal API, BFF) and
  spend the budget bypassing and chaining them.
- Append each candidate as ONE JSON line to
  /root/hackbot-architecture/findings/candidates.jsonl with keys
  {host,endpoint,param,vuln_class,evidence,confidence}.
- Evidence-backed only. No evidence = write NOTHING. Never fabricate.
- NON-DESTRUCTIVE: no payloads that mutate/delete data, no DoS, no brute force.
- Only in-scope hosts listed in the scope file. Skip + ignore anything else.
- Keep the mandatory User-Agent suffix from the scope file on every request.
- Do NOT re-report anything in the ALREADY CONFIRMED / ALREADY REJECTED lists
  included below. Only genuinely new candidates.
- Prior runs over-fired on "hypothetical" IDOR/open-redirect candidates with no
  demonstrated impact. Live traffic is edge-WAF-blocked (403), so prefer
  DETERMINISTIC static proof (shipped-JS/source reasoning + reproducible test,
  as was done for the confirmed unanchored-regex finding) over speculation.

WHERE THE PREVIOUS RUN LEFT OFF:
- Stage 1 (recon) is COMPLETE. Read /root/hackbot-architecture/state/recon/
  (RECON_SUMMARY.md, JS_FINDINGS.md, endpoints.txt, params.txt, js_urls.txt,
  klook/api_*_endpoints.txt, klook/js_findings/*.jsonl, klook/scope_hosts.txt).
- Stage 2 (hunt) died on a provider/rate-limit outage. Coverage is
  DISCOVERED/MAPPED/NOT_TESTED for most of the corpus.

WORK THIS PASS (one vulnerability class at a time, highest value first):
1. klook.klktech.com B2B agent API surfaces recovered from archived JS
   (/v1|v2/agentwebserv/*: account/balance/bookings/sub_accounts/api_list,
   register, findpassword, batchorder, bill/upload, fileagentserv agent/license,
   agent/voucher/logo/upload). Look for authz gaps, IDOR/BOLA object refs,
   parameter tampering, SSRF/file-upload sinks, secret leakage — but ONLY report
   what you can prove from artifacts.
2. merchant.klook.com Merchant API (/v1|v2/merchantserv/*: password reset,
   notice/getAuthCode, sub_account, schedules, booking PDF upload).
3. appapi.klook.com / mappapi.klook.com API routes in the endpoint corpus.
4. Continue the archived-JS / JS-chunk analysis in
   /root/.hermes/cache/scratch/klook_pm/ (postMessage handlers, origin
   validation, dangerous sinks; ~500 CDX chunk rows cached in cdx_js.json,
   downloads in bulk/). A cross-origin card-data exfil was already confirmed on
   pay.klook.com — look for the same class on other in-scope SPAs.

REPLY with one line: number of NEW candidates appended.

=== ALREADY CONFIRMED (do not duplicate) ===
PROMPT_EOF
    cat "$FIND/confirmed.jsonl" 2>/dev/null
    echo
    echo "=== ALREADY REJECTED (do not re-report) ==="
    cat "$FIND/rejected.jsonl" 2>/dev/null
    echo
    echo "$(cat "$ROOT/MASTER_WORKFLOW.md" 2>/dev/null)"
    echo
    echo "════════ SEVERITY DOCTRINE — BINDING ════════"
    cat "$DOCTRINE_FILE" 2>/dev/null
    echo "════════ end doctrine ════════"
  } > "$prompt_file"

  for attempt in 1 2 3; do
    case "$attempt" in
      1) model="" ;;                      # gateway default model
      2) model="claude-sonnet-5-5" ;;
      3) model="gpt-5.6-sol" ;;
    esac
    before="$(lines "$FIND/candidates.jsonl")"
    if [ -n "$model" ]; then
      log "STAGE2-resume attempt $attempt with model=$model"
      timeout 1500 hermes chat --model "$model" --query-file "$prompt_file" --quiet >> "$LOG" 2>&1 \
        || log "STAGE2-resume attempt $attempt ($model) errored/failed over"
    else
      log "STAGE2-resume attempt $attempt with gateway default model"
      timeout 1500 hermes chat --query-file "$prompt_file" --quiet >> "$LOG" 2>&1 \
        || log "STAGE2-resume attempt $attempt (default) errored/failed over"
    fi
    after="$(lines "$FIND/candidates.jsonl")"
    log "STAGE2-resume attempt $attempt: candidates $before -> $after"
    if [ "$after" -gt "$before" ]; then
      log "STAGE2-resume: produced candidates on attempt $attempt"
      return 0
    fi
  done
  log "STAGE2-resume: exhausted attempts with no new candidates"
}

# ── line-count helper ────────────────────────────────────────────────────────
lines(){ [ -f "$1" ] && wc -l < "$1" 2>/dev/null | tr -d ' ' || echo 0; }

# ═══ GATE — surface NEW candidates and ASK; do NOT auto-validate ──────────────
# New = in candidates.jsonl but not yet in pending/confirmed/rejected.
gate_candidates(){
  log "GATE: computing new candidates"
  local new alert cnt
  # Dedupe on a NORMALISED key (host|endpoint|vuln_class), not on exact lines.
  # The judge rewrites vuln_class/endpoint wording when it records a verdict in
  # rejected.jsonl/confirmed.jsonl, so a byte-for-byte line diff makes every
  # already-decided candidate look brand new on each run (spurious "N potential
  # findings awaiting approval" alerts). Key it exactly like supervisor.sh's
  # stage_validate does, and also treat archive.jsonl/tovalidate.jsonl as seen.
  new="$(python3 - "$FIND" <<'PY'
import json, os, sys, hashlib
F = sys.argv[1]
def key(d):
    return hashlib.sha1(("%s|%s|%s" % (d.get("host",""), d.get("endpoint",""), d.get("vuln_class",""))).encode()).hexdigest()
seen = set()
for f in ("pending.jsonl", "confirmed.jsonl", "rejected.jsonl", "archive.jsonl", "tovalidate.jsonl"):
    p = os.path.join(F, f)
    if os.path.exists(p):
        for l in open(p, errors="replace"):
            l = l.strip()
            if l:
                try: seen.add(key(json.loads(l)))
                except Exception: pass
out = []
p = os.path.join(F, "candidates.jsonl")
if os.path.exists(p):
    for l in open(p, errors="replace"):
        l = l.strip()
        if not l: continue
        try: d = json.loads(l)
        except Exception: continue
        k = key(d)
        if k in seen: continue
        seen.add(k); out.append(l)
sys.stdout.write("\n".join(out))
PY
)"
  if [ -z "$new" ]; then
    log "GATE: no new candidates"
    return 1
  fi
  printf '%s\n' "$new" >> "$FIND/pending.jsonl" 2>/dev/null
  cnt="$(printf '%s\n' "$new" | grep -c .)"
  log "GATE: $cnt new candidate(s) → surfaced to user, awaiting approval"
  alert="🟠 **$cnt potential finding(s) on $TARGET — awaiting your call**

$(printf '%s\n' "$new" | head -5 | jq -r '.vuln_class + \" @ \" + (.host//\"\") + \" \" + (.endpoint//\"\")' 2>/dev/null | head -5)

Reply:
  \`deep dive $TARGET\`  → validate + escalate + write report
  \`skip $TARGET\`       → drop these candidates"
  notify_discord "$alert"
  return 0
}

# ═══ STAGE 3 — VALIDATE + REPORT via CommandCode (only after approval) ════════
stage3_validate_report(){
  log "STAGE3 validate+report (Hermes) begin"
  if [ ! -s "$FIND/pending.jsonl" ]; then
    log "STAGE3: no pending candidates to validate"
    return 0
  fi
  local before after wf
  before="$(gct . "$FIND/pending.jsonl")"
  wf="$(cat "$ROOT/MASTER_WORKFLOW.md" 2>/dev/null)"
  # ENGINE NOTE: this stage runs on Hermes, not CommandCode. CommandCode in print
  # mode with permissions.defaultMode=dont-ask can READ inside its launch dir but
  # cannot WRITE (write_file/edit_file and shell_command are refused with
  # "not pre-approved and dont-ask mode never prompts"). A validator that cannot
  # write its verdict is a guaranteed no-op, so it is the wrong engine for
  # validate+report. Hermes has full workspace access and is used by the
  # supervisor's own validate/report stages.
  timeout 900 hermes chat -q "You are the VALIDATION (judge) + REPORT agent of a bug bounty hackbot. Target: $TARGET.

$wf

════════ SEVERITY DOCTRINE — BINDING ════════
$DOCTRINE
════════ end doctrine ════════

$STANDING_ORDER

DOCTRINE GATE — apply BEFORE any other reasoning: a doctrine §2 ineligible candidate
(version/banner disclosure, stack trace, descriptive error, CORS without impact, non-sensitive
CSRF/clickjacking, open redirect without added impact, cookie flags, TLS/CSP/SPF opinions, rate
limiting, content spoofing, self-XSS) is REJECTED at once with reason 'chain-primitive-only
(doctrine §2)' — never confirmed and never drafted, however well measured. Also REJECT anything
out of scope / in the program's do-NOT-test list. A primitive is only reportable inside a chain
that independently demonstrates HIGH/CRITICAL impact.

Read $FIND/pending.jsonl (the candidate list) plus $FIND/confirmed.jsonl and $FIND/rejected.jsonl (already-decided findings — do NOT re-report or duplicate them). Non-destructive checks ONLY: no payloads, no DoS, no brute force, no data mutation. Reachability is per-target and must be MEASURED, not assumed: probe each in-scope host once (GET / with the mandatory header named in the scope file) and let the measured result drive the method — a 200/3xx host allows a live read-only check within the rules of conduct (max 10 req/sec, no mutation, own test account only, mandatory header on every request), while a 403/406 edge-WAF block means grounding every judgement in deterministic evidence from the shipped JS bundles under $STATE/recon/$TARGET/.

For each pending candidate, try to DISPROVE it (CIA triad + negative testing): state the concrete impact, and whether an attacker can actually reach the sink. Never fabricate and never assume a server-side flaw — if it cannot be proven from evidence, it is REJECTED.
- Real impact → append to $FIND/confirmed.jsonl with ALL of: id, title, host, weakness, severity, cvss, description, steps_to_reproduce, impact, poc. Do NOT write report files — confirmed findings are delivered to the user as DRAFT reports on Discord by the pipeline.
- Disproven / unproven → append to $FIND/rejected.jsonl with a 'reason' field naming exactly what evidence is missing.
- Then append the processed candidates to $FIND/archive.jsonl and empty $FIND/pending.jsonl.
Reply with exactly one line: confirmed=<n> rejected=<n> reports=<files>." \
    >> "$LOG" 2>&1 || log "STAGE3: timed out/errored (non-fatal)"
  after="$(gct . "$FIND/pending.jsonl")"
  if [ "$after" -ge "$before" ]; then
    # pending did not shrink → the stage did not actually process the candidates.
    # Do NOT report a green "deep-dive complete" over a no-op.
    log "STAGE3 WARNING: NO-OP — pending still $after (was $before); stage did not process candidates"
    notify_discord "⚠️ **Deep-dive on $TARGET produced NO change** — $after candidate(s) still pending, none validated (see state/pipeline-$TARGET.log)."
    return 1
  fi
  log "STAGE3 done: $(gct . "$FIND/confirmed.jsonl") confirmed, $(gct . "$FIND/rejected.jsonl") rejected"
}

# ═══ STAGE 4 — deliver result to Discord ══════════════════════════════════════
stage4_deliver(){
  # Confirmed findings are delivered to Discord as DRAFT reports by post-drafts.sh
  # (one message per finding, deduped), AND as a downloadable PDF attachment by
  # report-pdf.sh --all-new (standing convention: every report must be downloadable
  # from Discord, not just a path on the box), deduped via state/reports-sent.ids.
  bash "$ROOT/post-drafts.sh" "$TARGET" >> "$LOG" 2>&1 || log "STAGE4: draft post failed (non-fatal)"
  bash "$ROOT/report-pdf.sh" --all-new >> "$LOG" 2>&1 || log "STAGE4: report-pdf failed (non-fatal)"
  notify_discord "🗂️ **Deep-dive done — $TARGET** — confirmed: $(gct . "$FIND/confirmed.jsonl"), rejected: $(gct . "$FIND/rejected.jsonl"). Any new bug was sent above as a draft report + downloadable PDF."
  log "STAGE4: drafts posted + summary sent"
}

# ═══ main ════════════════════════════════════════════════════════════════════
if [ "$MODE" = "resume" ]; then
  log "══════ resume start target=$TARGET (recon reused, hunt only) ══════"
  notify_discord "🟢 Resuming hunt on **$TARGET** — recon already mapped, hunting the existing corpus (no re-recon)."
  stage2_hunt_resume
  /root/hackbot-architecture/monitor.sh hunt "$TARGET" "$SCOPE_FILE" || true
  if gate_candidates; then
    log "══════ resume complete: candidates awaiting approval ══════"
  else
    log "══════ resume complete: no new candidates ══════"
    notify_discord "✅ Resume hunt on **$TARGET** finished — no NEW candidates this pass (existing confirmed findings unchanged)."
  fi
  exit 0
fi

if [ "$MODE" = "deepdive" ]; then
  log "══════ deep-dive start target=$TARGET ══════"
  # stage4 only runs when stage3 really processed the candidates (non-no-op),
  # otherwise the failure warning from stage3 is the last word.
  stage3_validate_report && stage4_deliver
  log "══════ deep-dive complete target=$TARGET ══════"
  exit 0
fi

# default: hunt mode with gate
log "══════ hunt-pipeline start target=$TARGET ══════"
notify_discord "🟢 Hunting **$TARGET** — recon + hunt. I'll ping you if I find anything."
stage1_recon
/root/hackbot-architecture/monitor.sh recon "$TARGET" "$SCOPE_FILE" || true
stage2_hunt
/root/hackbot-architecture/monitor.sh hunt "$TARGET" "$SCOPE_FILE" || true
if gate_candidates; then
  log "══════ hunt complete: candidates awaiting approval ══════"
else
  log "══════ hunt complete: no new candidates ══════"
  notify_discord "✅ Hunt on **$TARGET** finished — no new potential findings this pass."
fi
