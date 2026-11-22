#!/usr/bin/env bash
# report-pdf.sh — turn confirmed findings into report PDFs AND make each one downloadable on Discord.
#
#   report-pdf.sh <FINDING_ID> [--no-send]   one finding from findings/confirmed.jsonl
#   report-pdf.sh --all-new                  every confirmed finding not yet sent (the loop calls this)
#   report-pdf.sh --file <finding.json>      an arbitrary finding record
#
# Behaviour (standing convention: a report is delivered as a downloadable PDF attached to Discord):
#   1. render a PDF (report_pdf.py -> headless Chrome)
#   2. upload it to the Discord home channel as a real file attachment (send_report_pdf.sh)
#   3. record the finding id in state/reports-sent.ids so it is sent exactly once
# Missing/failed steps fail loudly; a PDF is never announced without the upload returning an attachment URL.
set -u

# gct <grep-args...> — like `grep -c` but ALWAYS yields exactly one integer.
# `$(grep -c X f || echo 0)` is a trap: grep -c prints "0" AND exits 1 on no match,
# so the fallback appends a second 0 -> "0\n0" -> "[ 0\n0 -gt 0 ]: integer expression expected".
gct(){ local n; n=$(grep -c "$@" 2>/dev/null); printf '%s' "${n:-0}"; }

ROOT=/root/hackbot-architecture
FIND="$ROOT/findings"
STATE="$ROOT/state"
OUTDIR="${REPORT_PDF_DIR:-$ROOT/reports}"
SENT="$STATE/reports-sent.ids"
mkdir -p "$OUTDIR" "$STATE"
touch "$SENT"

log(){ echo "[report-pdf $(date '+%F %T')] $*"; }

# cycle-health block injected into every rendered PDF (Q6)
CYCLE_HEALTH_FILE=""
_slug=""
for _a in "$@"; do case "$_a" in */state/recon/*) _slug="$(printf '%s' "$_a" | sed -E 's#.*/state/recon/([^/]+)/.*#\1#')";; esac; done
[ -z "$_slug" ] && _slug="${SLUG:-microkeeper}"
if [ -x "$ROOT/cycle-report.sh" ]; then
  CYCLE_HEALTH_FILE="$(mktemp)"
  "$ROOT/cycle-report.sh" "$_slug" --no-send > "$CYCLE_HEALTH_FILE" 2>/dev/null || true
  export CYCLE_HEALTH_FILE
fi

already_sent(){ grep -qxF "$1" "$SENT" 2>/dev/null; }

# ── THE GATE (operator directive 2026-11-19) ────────────────────────────────
# A report PDF is rendered AND uploaded ONLY for a 100%-confirmed, end-to-end
# EXECUTED finding with a working PoC artefact on disk (see notify-policy.sh).
# Everything else is a lead: audited locally, never rendered, never uploaded.
FORCE=0; DRYRUN=0
for _a in "$@"; do case "$_a" in --force) FORCE=1;; --dry-run) DRYRUN=1;; esac; done
gate(){ # $1 = finding id OR json file path
  if [ "$FORCE" = "1" ]; then log "GATE: --force override for $1 (operator override)"; return 0; fi
  local why
  if why="$(bash "$ROOT/notify-policy.sh" check "$1" 2>/dev/null)"; then log "GATE pass $1 — $why"; return 0; fi
  log "GATE HOLD $1 — not Exploited&Ready (${why:-ineligible}); no PDF rendered, nothing uploaded"
  bash "$ROOT/notify-policy.sh" suppress "$1" lead "report-pdf gate: ${why:-ineligible}" >/dev/null 2>&1 || true
  return 1
}

do_one(){ # $1 = finding id or json file path, $2 = 1 if it is a file
  local id file
  if [ "${2:-0}" = "1" ]; then
    file="$1"; id="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("id","FINDING"))' "$file" 2>/dev/null || echo FINDING)"
  else
    id="$1"
    file="$(mktemp)"
    python3 - "$FIND/confirmed.jsonl" "$id" > "$file" <<'PY'
import json,sys
path,fid=sys.argv[1],sys.argv[2]
for line in open(path):
    line=line.strip()
    if not line: continue
    try: o=json.loads(line)
    except Exception: continue
    if o.get("id")==fid:
        print(json.dumps(o)); break
else:
    sys.exit(3)
PY
    [ $? -ne 0 ] && { log "finding $id not found in confirmed.jsonl — skip"; rm -f "$file"; return 1; }
  fi

  if [ "$DRYRUN" = "1" ]; then
    if gate "$1"; then echo "would SEND   $id"; else echo "would HOLD   $id"; fi
    [ "${2:-0}" != "1" ] && rm -f "$file"; return 0
  fi
  gate "$1" || { [ "${2:-0}" != "1" ] && rm -f "$file"; return 2; }
  if already_sent "$id"; then log "$id already sent — skip (dedupe)"; [ "${2:-0}" != "1" ] && rm -f "$file"; return 0; fi

  local pdf="$OUTDIR/${id}-$(date +%F).pdf"
  local title
  title="$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("title","")[:220])' "$file" 2>/dev/null || true)"
  log "rendering $id -> $pdf"
  renderer="$ROOT/report_pdf.py"
  if [ -f "$ROOT/report_pdf_esc.py" ] && python3 -c 'import json,sys;d=json.load(open(sys.argv[1]));sys.exit(0 if d.get("poc_screenshots") else 1)' "$file" 2>/dev/null; then
    renderer="$ROOT/report_pdf_esc.py"   # embeds the poc_screenshots section when the record has figures
  fi
  python3 "$renderer" "$file" "$pdf" || { log "RENDER FAILED for $id"; [ "${2:-0}" != "1" ] && rm -f "$file"; return 1; }
  [ "${2:-0}" != "1" ] && rm -f "$file"

  log "uploading $pdf to Discord"
  local up
  export HACKBOT_ALLOW_SEND=1   # we already passed the Exploited&Ready gate above
  up="$(bash "$ROOT/send_report_pdf.sh" "$pdf" "📄 $id — $title
Download the full report below.")" || true
  echo "$up"
  if echo "$up" | grep -q '^url: .*cdn.discordapp.com'; then
    echo "$id" >> "$SENT"
    log "$id delivered: $(echo "$up" | grep '^url:' | head -1)"
    return 0
  fi
  log "UPLOAD FAILED for $id (not recorded as sent) -> $up"
  return 1
}

case "${1:-}" in
  ""|-h|--help) sed -n '2,12p' "$0"; exit 2 ;;
  --all-new)
    n=0; fail=0
    while IFS= read -r fid; do
      [ -z "$fid" ] && continue
      already_sent "$fid" && continue
      if do_one "$fid" 0; then n=$((n+1)); else fail=$((fail+1)); fi
    done < <(python3 -c 'import json,sys
for l in open(sys.argv[1]):
    l=l.strip()
    if l:
        try: print(json.loads(l).get("id",""))
        except Exception: pass' "$FIND/confirmed.jsonl")
    log "all-new done: sent=$n failed=$fail (sent list: $(gct . "$SENT"))"
    [ "$fail" -gt 0 ] && exit 1
    exit 0 ;;
  --file) [ -n "${2:-}" ] || { echo "usage: $0 --file <finding.json>"; exit 2; }; do_one "$2" 1 ;;
  --no-send) : ;;  # only meaningful after an id; handled below
  *)
    if [ "${2:-}" = "--no-send" ]; then
      # render only (no upload, no dedupe record)
      f="$(mktemp)"; id="$1"
      python3 - "$FIND/confirmed.jsonl" "$id" > "$f" <<'PY'
import json,sys
path,fid=sys.argv[1],sys.argv[2]
for line in open(path):
    line=line.strip()
    if line:
        try:
            o=json.loads(line)
        except Exception:
            continue
        if o.get("id")==fid:
            print(json.dumps(o)); break
else:
    sys.exit(3)
PY
      [ $? -ne 0 ] && { log "finding $id not found"; rm -f "$f"; exit 1; }
      gate "$1" || { log "GATE HOLD $id (render refused: not Exploited&Ready)"; rm -f "$f"; exit 2; }
      pdf="$OUTDIR/${id}-$(date +%F).pdf"
      python3 "$ROOT/report_pdf.py" "$f" "$pdf"; rc=$?; rm -f "$f"; exit $rc
    fi
    do_one "$1" 0 ;;
esac
