#!/usr/bin/env bash
# jsminer-offline.sh — mine this estate's JS/HTML from the Wayback Machine (NO traffic to the target).
#
# WHY: while an edge block is in force the target is off-limits, but the hunt does not have to
# stop. Archived bundles/HTML reveal endpoints, parameters, auth flows, hidden fields and
# secrets, and they cost the target nothing. Everything found here becomes a named cell in the
# coverage matrix, so the moment access returns the loop tests known surface instead of
# re-discovering it.
#
# usage: jsminer-offline.sh <slug> [max_files]
set -uo pipefail
export PATH="/usr/local/bin:/usr/bin:/bin:${PATH:-}"
SLUG="${1:?usage: jsminer-offline.sh <slug> [max_files]}"
MAXF="${2:-40}"
ST="/root/state/recon/$SLUG"; OUT="$ST/evidence/jsdeep/offline"
mkdir -p "$OUT/raw"
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36'
LOG="$OUT/miner.log"
: > "$LOG"
log(){ printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG"; }

# candidates: every .js in the corpus + the high-value HTML pages that carry inline flow logic
{ grep -E '\.js(\?|$)' "$ST/surface/urls.txt" 2>/dev/null
  cat "$ST/corpus/operator-endpoints.txt" 2>/dev/null | grep -E '\.js(\?|$)|login\.html|jackpot-statistiken|bingo-chat|textbook\.json'
} | grep -E '^https?://' | sort -u | head -"$MAXF" > "$OUT/targets.txt"
log "candidates: $(wc -l < "$OUT/targets.txt")"

n=0
while IFS= read -r u; do
  [ -z "$u" ] && continue
  safe=$(printf '%s' "$u" | sed 's#^https\?://##; s#[^A-Za-z0-9._-]#_#g' | cut -c1-120)
  f="$OUT/raw/$safe"
  [ -s "$f" ] && continue
  code=$(curl -sSL -m 60 -A "$UA" -o "$f" -w '%{http_code}' "https://web.archive.org/web/2025id_/$u" 2>/dev/null)
  case "$code" in 200) n=$((n+1));; *) rm -f "$f";; esac
  sleep 2
  log "  $code  $u"
done < "$OUT/targets.txt"
log "fetched $n archived file(s) -> $OUT/raw"

# ---- extract signal -----------------------------------------------------------
cat "$OUT"/raw/* > "$OUT/all.txt" 2>/dev/null || true
bytes=$(wc -c < "$OUT/all.txt" 2>/dev/null || echo 0)
log "corpus bytes: $bytes"
: > "$OUT/endpoints.txt"; : > "$OUT/params.txt"; : > "$OUT/secrets.txt"

# endpoints (paths that look like application routes/handlers)
grep -oE '"/[A-Za-z0-9_./?=&{}$:-]{2,120}"' "$OUT/all.txt" 2>/dev/null \
  | tr -d '"' | sed 's/[?&].*$//' | grep -vE '\.(png|jpe?g|gif|svg|woff2?|css|ico|webp)$' \
  | sort -u >> "$OUT/endpoints.txt"
grep -oE "https?://[A-Za-z0-9._-]+/[A-Za-z0-9_./-]{2,80}" "$OUT/all.txt" 2>/dev/null \
  | sort -u >> "$OUT/endpoints.txt"
sort -u -o "$OUT/endpoints.txt" "$OUT/endpoints.txt"

# parameters
grep -oE '[?&"'"'"'][A-Za-z_][A-Za-z0-9_.-]{1,40}=' "$OUT/all.txt" 2>/dev/null \
  | tr -d '?&"'"'"'=' | sort -u > "$OUT/params.txt"

# secrets / keys / tokens
grep -ohiE '(api[_-]?key|apikey|secret|client[_-]?secret|access[_-]?token|bearer|authorization|password|passwd|pwd|private[_-]?key|AKIA[0-9A-Z]{16}|recaptcha[^"'"'"']{0,40})["'"'"']?\s*[:=]\s*["'"'"'][^"'"'"']{6,80}' \
  "$OUT/all.txt" 2>/dev/null | cut -c1-160 | sort -u > "$OUT/secrets.txt"

log "endpoints=$(wc -l < "$OUT/endpoints.txt") params=$(wc -l < "$OUT/params.txt") secret-candidates=$(wc -l < "$OUT/secrets.txt")"
echo
echo "=== endpoints (application routes found in archived JS/HTML) ==="
grep -E '/(rest|api|\.do|\.jsp|\.action|\.json|login|check|register|game|draw|purchase|user|account|wallet|admin)' \
  "$OUT/endpoints.txt" 2>/dev/null | head -60
echo
echo "=== parameters ==="
head -80 "$OUT/params.txt"
echo
echo "=== secret candidates (redacted preview) ==="
sed -E 's/([":=][[:space:]]*"?)[A-Za-z0-9_+\/=-]{8,}/\1<REDACTED>/g' "$OUT/secrets.txt" 2>/dev/null | head -25
