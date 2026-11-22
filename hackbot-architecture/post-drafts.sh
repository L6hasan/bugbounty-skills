#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  post-drafts.sh — post DRAFT reports for newly confirmed findings to Discord.
#
#  Behaviour (per user directive):
#    • No report FILES are written. The draft IS the delivery.
#    • One Discord message per new confirmed finding containing
#      TITLE / DESCRIPTION / STEPS TO REPRODUCE / POC / IMPACT (+ severity).
#    • Deduped by a stable key (id|vuln_class|host) so a finding is drafted once.
#
#  Usage: bash post-drafts.sh [target]
# ══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

ROOT="/root/hackbot-architecture"
FIND="$ROOT/findings"
STATE="$ROOT/state"
TARGET="${1:-klook}"
POSTED="$STATE/drafts-posted.ids"
LOG="$STATE/drafts.log"
mkdir -p "$STATE"
touch "$POSTED"
log(){ printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG"; }

TOKEN="$(grep -E '^DISCORD_BOT_TOKEN=' /root/.hermes/.env 2>/dev/null | sed 's/^[^=]*=//' | tr -d '\r\n')"
CHANNEL="${DISCORD_HOME_CHANNEL:-1567763899808354387}"
[ -z "$TOKEN" ] && { log "no DISCORD_BOT_TOKEN — cannot post"; exit 0; }
[ -s "$FIND/confirmed.jsonl" ] || { log "no confirmed findings"; exit 0; }

# ── THE GATE (operator directive 2026-11-19) ────────────────────────────────
# A draft goes to Discord ONLY for an Exploited&Ready finding: executed end-to-end,
# PoC artefact on disk, final report ready. Everything else is a lead -> held locally.
ELIGIBLE="$STATE/.confirmed-eligible.jsonl"
: > "$ELIGIBLE"
held=0
while IFS= read -r _line; do
  [ -z "$_line" ] && continue
  _fid=$(printf '%s' "$_line" | python3 -c 'import json,sys;
try: print(json.load(sys.stdin).get("id",""))
except Exception: print("")' 2>/dev/null)
  [ -z "$_fid" ] && continue
  if bash "$ROOT/notify-policy.sh" check "$_fid" >/dev/null 2>&1; then
    printf '%s\n' "$_line" >> "$ELIGIBLE"
  else
    held=$((held+1))
    log "draft held locally (not Exploited&Ready): $_fid"
    bash "$ROOT/notify-policy.sh" suppress "$_fid" lead "post-drafts gate: not Exploited&Ready" >/dev/null 2>&1 || true
  fi
done < "$FIND/confirmed.jsonl"
elig_n=$(grep -c . "$ELIGIBLE" 2>/dev/null); elig_n=${elig_n:-0}
log "gate: $elig_n eligible, $held held locally"
[ -s "$ELIGIBLE" ] || { log "nothing eligible — no draft posted"; exit 0; }

# ── select new findings + render messages ────────────────────────────────────
python3 - "$ELIGIBLE" "$POSTED" "$TARGET" > "$STATE/.drafts.out" <<'PY'
import json, sys, os, hashlib

conf, posted_path, target = sys.argv[1], sys.argv[2], sys.argv[3]
seen = set(open(posted_path).read().split()) if os.path.exists(posted_path) else set()

def get(d, *keys, default=""):
    for k in keys:
        v = d.get(k)
        if isinstance(v, (str, int, float)) and str(v).strip():
            return str(v).strip()
    return default

def as_block(v, limit=800):
    if isinstance(v, (list, tuple)):
        v = "\n".join("  %d) %s" % (i + 1, str(x)) for i, x in enumerate(v))
    elif isinstance(v, dict):
        v = json.dumps(v, indent=1)
    v = str(v).strip()
    return v[:limit] + ("…" if len(v) > limit else "")

for line in open(conf, errors="replace"):
    line = line.strip()
    if not line:
        continue
    try:
        d = json.loads(line)
    except Exception:
        continue
    fid = get(d, "id", "finding_id") or ("DRAFT-" + hashlib.sha1(
        ("%s|%s" % (get(d, "host", "asset"), get(d, "vuln_class", "title"))).encode()).hexdigest()[:6].upper())
    title = get(d, "title", "vuln_class", "weakness") or "Untitled finding"
    host = get(d, "host", "asset")
    key = hashlib.sha1(("%s|%s|%s" % (fid, title, host)).encode()).hexdigest()[:16]
    if key in seen:
        continue

    desc = get(d, "description", "summary", "details", "evidence")
    steps = (d.get("steps_to_reproduce") or d.get("steps") or d.get("repro")
             or d.get("reproduction") or d.get("evidence") or [])
    poc = get(d, "poc", "proof_of_concept", "exploit", "payload", "evidence")
    impact = get(d, "impact", "consequence")
    sev = get(d, "severity", "cvss", "confidence")
    cwe = get(d, "weakness", "vuln_class", "cwe")

    msg = [
        "📝 DRAFT REPORT — %s  (target: %s)" % (fid, target),
        "Status: DRAFT / not verified by you, not submitted anywhere.",
        "",
        "TITLE: %s" % title,
        "HOST: %s" % (host or "n/a"),
        "CLASS/SEVERITY: %s%s" % (cwe or "n/a", (" · " + sev) if sev else ""),
        "",
        "DESCRIPTION:",
        as_block(desc, 700),
        "",
        "STEPS TO REPRODUCE:",
        as_block(steps, 700),
        "",
        "POC:",
        as_block(poc, 700),
        "",
        "IMPACT:",
        as_block(impact, 600),
    ]
    body = "\n".join(msg)

    # split into <=1900-char chunks on line boundaries
    chunks, cur = [], ""
    for ln in body.splitlines():
        if len(cur) + len(ln) + 1 > 1900:
            chunks.append(cur)
            cur = ln
        else:
            cur = (cur + "\n" + ln) if cur else ln
    if cur:
        chunks.append(cur)

    for i, c in enumerate(chunks):
        print(json.dumps({"key": key if i == 0 else "", "text": c}))
PY

COUNT=0
while IFS= read -r row; do
  [ -z "$row" ] && continue
  key="$(printf '%s' "$row" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("key",""))')"
  text="$(printf '%s' "$row" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("text",""))')"
  code="$(curl -sS -m 15 -o /dev/null -w '%{http_code}' \
    -X POST -H "Authorization: Bot $TOKEN" -H 'Content-Type: application/json' \
    -d "$(jq -n --arg c "$text" '{content:$c}')" \
    "https://discord.com/api/v10/channels/$CHANNEL/messages" 2>/dev/null)"
  if [ "$code" = "200" ]; then
    log "draft posted (http 200)"
    [ -n "$key" ] && echo "$key" >> "$POSTED"
    [ -n "$key" ] && COUNT=$((COUNT + 1))
  else
    log "draft post FAILED (http $code)"
  fi
  sleep 1
done < "$STATE/.drafts.out"

rm -f "$STATE/.drafts.out"
log "post-drafts complete: $COUNT new draft(s)"
echo "drafts posted: $COUNT"
