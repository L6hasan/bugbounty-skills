#!/usr/bin/env bash
# alert-only.sh — QUIET MODE gate for Discord.
#
# The operator wants NO routine chat: Discord fires ONLY when
#   (a) a VALIDATED qualifying vulnerability exists with a working PoC, or
#   (b) an authenticated session token is required (credential-request.jsonl).
# Everything else (cycle health, stage firing, counters) stays in the local logs.
#
# Dedupes so a standing credential request does not re-ping every pass.
#
# usage: alert-only.sh <slug>
set -uo pipefail
HA=/root/hackbot-architecture
SLUG="${1:?usage: alert-only.sh <slug>}"
ST="/root/state/recon/$SLUG"
SENT="$ST/.alerts-sent"
touch "$SENT"
slug_key(){ printf '%s' "$1" | md5sum | cut -c1-12; }
fired=0

# ---- (b) credential request ----
CR="$ST/credential-request.jsonl"
if [ -s "$CR" ]; then
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    k="cred:$(slug_key "$line")"
    grep -qxF "$k" "$SENT" && continue
    need=$(printf '%s' "$line" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("need","session"))' 2>/dev/null || echo "session")
    why=$(printf '%s' "$line"  | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("why",""))' 2>/dev/null || echo "")
    ep=$(printf '%s' "$line"   | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d.get("endpoint",""))' 2>/dev/null || echo "")
    # NOTIFICATION POLICY (operator 2026-11-19): a credential/session request is a BLOCKER, not a finding.
    # It is recorded locally in state/blockers.jsonl and, by default, NOT posted to Discord.
    # Re-enable with HACKBOT_NOTIFY_BLOCKERS=1 (then rate-limited to one per target per 6h).
    bash "$HA/notify-policy.sh" blocker "$SLUG" "🔑 **[$SLUG] Authenticated session needed** — ${need}
endpoint: ${ep}
why: ${why}
(Blockers are held locally by default now; set HACKBOT_NOTIFY_BLOCKERS=1 to have them announced.)" >/dev/null 2>&1
    rc=$?
    [ "$rc" -eq 0 ] && { echo "$k" >> "$SENT"; fired=$((fired+1)); }
  done < "$CR"
fi

# ---- (a) validated qualifying findings ----
for f in "$ST"/loop/validations/*.json; do
  [ -e "$f" ] || continue
  sev=$(python3 -c 'import json,sys;print(str(json.load(open(sys.argv[1])).get("severity","")).lower())' "$f" 2>/dev/null || echo "")
  case "$sev" in
    *high*|*critical*)
      k="val:$(slug_key "$(cat "$f")")"
      grep -qxF "$k" "$SENT" && continue
      id=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("id","?"))' "$f" 2>/dev/null || echo "?")
      # NOTIFICATION POLICY (2026-11-19): a "validated" record is a LEAD. Only an Exploited&Ready
      # finding (executed end-to-end + PoC artefact on disk) is rendered/uploaded/posted.
      if bash "$HA/notify-policy.sh" finding "$f" "🔥 **$id** — EXPLOITED & READY TO SUBMIT (${SLUG}). Report PDF attached." >/dev/null 2>&1; then
        printf '[%s] EXPLOITED&READY alert fired for %s (%s)\n' "$(date '+%F %T')" "$id" "$sev" >> "$ST/alerts.log"
        fired=$((fired+1))
      else
        printf '[%s] held locally (validated lead, not executed end-to-end): %s (%s)\n' "$(date '+%F %T')" "$id" "$sev" >> "$ST/alerts.log"
      fi
      echo "$k" >> "$SENT"
      ;;
  esac
done

[ "$fired" = "0" ] && printf '[%s] quiet: no qualifying alert\n' "$(date '+%F %T')" >> "$ST/alerts.log"
exit 0
