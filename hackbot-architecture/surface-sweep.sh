#!/usr/bin/env bash
# surface-sweep.sh — DETERMINISTIC total-surface enumeration (Q2).
# Every dimension the operator listed is covered by a named stage, and every new
# artefact is appended to the target's coverage matrix as UNTESTED rows so no agent
# can silently skip it:
#   ports | ip/dns | root files | hidden information | headers | HTTP methods
#   directories/paths | parameters | urls | js files | fingerprint/tech
#
# usage: surface-sweep.sh <target> [--readonly-heavy]
set -uo pipefail
export PATH="/root/go/bin:/usr/local/bin:/usr/bin:/bin:${PATH:-}"

# gct <grep-args...> — like `grep -c` but ALWAYS yields exactly one integer.
# `$(grep -c X f || echo 0)` is a trap: grep -c prints "0" AND exits 1 on no match,
# so the fallback appends a second 0 -> "0\n0" -> "[ 0\n0 -gt 0 ]: integer expression expected".
gct(){ local n; n=$(grep -c "$@" 2>/dev/null); printf '%s' "${n:-0}"; }

T=""; SLUG=""; HEAVY=0; HOSTS_FILE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --slug) SLUG="$2"; shift 2;;
    --hosts) HOSTS_FILE="$2"; shift 2;;
    --readonly-heavy) HEAVY=1; shift;;
    *) [ -z "$T" ] && T="$1"; shift;;
  esac
done
[ -n "$T" ] || { echo "usage: surface-sweep.sh <target> [--slug S]"; exit 2; }
# Slug resolution: a caller that already owns state (hunt-loop.sh) passes --slug so the sweep
# writes into the EXISTING engagement dir. Deriving blindly turns microkeeper.com.au into
# microkeeper-com-au and silently strands every artefact in a parallel tree.
[ -n "$SLUG" ] || SLUG="$(printf '%s' "$T" | tr 'A-Z' 'a-z' | sed 's/[^a-z0-9]/-/g')"
ST="/root/state/recon/$SLUG"; SURF="$ST/surface"; COV="$ST/loop/coverage.tsv"
# HA = this script's own directory. Referenced by the opt-in brute stage for the curated
# wordlist; it was never defined, so enabling TARGET_BRUTE=1 aborted that stage with
# "HA: unbound variable" under `set -u` and silently skipped directory discovery entirely.
HA="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mkdir -p "$SURF" "$ST/loop"
[ -f "$COV" ] || printf 'host\tendpoint\tmethod\tvuln_class\tstatus\tevidence_path\treason\tauth_state\trole\tupdated\n' > "$COV"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
# Program-mandated request header (e.g. "x-client-identifier: webapp@4.4.0"). Some estates gate EVERY
# path behind a header and answer 426/403 without it — which reads as "estate blocked/unreachable" and
# hides the whole surface from the deterministic sweep while the LLM agents (told the header in the scope
# file) see a completely different picture. Set TARGET_HEADER so both layers send the same header.
HDR_ARGS=(); [ -n "${TARGET_HEADER:-}" ] && HDR_ARGS=(-H "$TARGET_HEADER")
log(){ printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$SURF/sweep.log"; }

# ---- reachability guard -----------------------------------------------------
# A silent-DROP edge block (see 2026-11-18) is indistinguishable from an outage by exit codes
# alone; without this check every stage fires into a black hole and can lengthen the ban.
# GATE ON $T ONLY: a 403 from an unrelated in-scope host (goooal answers 403 to a plain GET)
# must never satisfy the check for a target whose own edge is dropping our packets.
guard(){ bash /root/hackbot-architecture/net-guard.sh "$T" >/dev/null 2>&1 \
  || { log "   NET-GUARD: $T unreachable (edge block or outage) — ABORTING sweep, no traffic sent"; exit 3; }; }

# ---- buffered coverage seeding ---------------------------------------------
# The old add_row grepped the ENTIRE coverage matrix for every candidate: on the 408MB matrix
# this estate produced that is O(n^2) — 43,803 dir hits cost ~30h of wall clock and the sweep
# never reached its hunt phases. Candidates now stage into a temp file and merge in ONE awk pass.
SEED="$ST/loop/.seed.$$"; : > "$SEED"
add_row(){ printf '%s\t%s\tGET\t%s\tUNTESTED\t\t%s\tanon\tnone\t%s\n' "$T" "$1" "$2" "surface-sweep: $3" "$(date '+%FT%H:%M')" >> "$SEED"; }
seed_merge(){ # existing rows + staged rows, deduped on host|endpoint|class, atomic replace
  [ -s "$SEED" ] || { rm -f "$SEED"; return 0; }
  awk -F'\t' 'FNR==1 && FILENAME==ARGV[1] {print; next} {k=$1"|"$2"|"$4; if(!seen[k]++) print}' \
      "$COV" "$SEED" > "$COV.tmp.$$" 2>/dev/null && mv -f "$COV.tmp.$$" "$COV"
  rm -f "$SEED"
}

log "══ surface sweep start: $T ══"
guard   # never start enumerating a blocked estate

# ---- 1. DNS / IP / mapping -------------------------------------------------
log "-- dns/ip/mapping"
if [ -n "$HOSTS_FILE" ]; then
  # STRICT ALLOWLIST MODE. No subfinder, no wildcard resolution, no name guessing:
  # a generic sweep would otherwise probe hosts the engagement forbids. Only the hosts
  # named in the file are ever contacted, and enumerating more is a scope violation.
  grep -E '^[A-Za-z0-9._-]+$' "$HOSTS_FILE" | grep -v '^#' | sort -u > "$SURF/subdomains.txt"
  log "   STRICT MODE: $(wc -l < "$SURF/subdomains.txt") allowlisted host(s); subdomain enumeration DISABLED"
else
  subfinder -d "$T" -silent -all 2>/dev/null | sort -u > "$SURF/subdomains.txt"
fi
{ while IFS= read -r h; do dig +short A "$h" 2>/dev/null; done < "$SURF/subdomains.txt"; } 2>/dev/null | sort -u > "$SURF/ips.txt"
dnsx -l "$SURF/subdomains.txt" -silent -a -resp 2>/dev/null > "$SURF/dnsx.txt" || true
cp -f "$SURF/subdomains.txt" "$ST/all_hosts.txt" 2>/dev/null || true
log "   ips=$(wc -l < "$SURF/ips.txt") hosts=$(wc -l < "$SURF/subdomains.txt")"

# ---- 2. live hosts + fingerprint + headers ---------------------------------
guard   # re-check: the edge can start dropping mid-pass (it did on 2026-11-18)
log "-- liveness, fingerprint, headers"
httpx -l "$SURF/subdomains.txt" -silent -status-code -title -tech-detect -web-server -cdn -favicon -no-color -timeout 12 \
  2>/dev/null > "$SURF/httpx.txt" || true
grep -oE 'https?://[^ ]+' "$SURF/httpx.txt" 2>/dev/null | sort -u > "$SURF/live_urls.txt" || true
{ while IFS= read -r h; do printf 'https://%s\n' "$h"; done < "$SURF/subdomains.txt"; cat "$SURF/live_urls.txt" 2>/dev/null; } | sort -u > "$SURF/live_all.txt"
: > "$SURF/headers.txt"; : > "$SURF/rootfiles.txt"
while IFS= read -r u; do
  [ -z "$u" ] && continue
  code=$(curl -sS --compressed -m 15 -A "$UA" "${HDR_ARGS[@]}" -D - -o /dev/null "$u" -w 'HTTPCODE:%{http_code}\n' 2>/dev/null | tr -d '\r')
  printf '===== %s\n%s\n' "$u" "$code" >> "$SURF/headers.txt"
  sleep 1
done < "$SURF/live_all.txt"
log "   live=$(wc -l < "$SURF/live_all.txt") header-blocks=$(grep -c '^=====' "$SURF/headers.txt")"

# ---- 3. root files / hidden information ------------------------------------
log "-- root files + hidden information"
for p in robots.txt sitemap.xml sitemap_index.xml security.txt humans.txt manifest.json \
         .well-known/security.txt .well-known/change-password .well-known/assetlinks.json \
         .git/HEAD .git/config .svn/entries .env .env.bak .htaccess .htpasswd web.config \
         crossdomain.xml clientaccesspolicy.xml phpinfo.php info.php server-status server-info \
         backup.zip backup.tar.gz site.zip www.zip db.sql dump.sql .DS_Store Thumbs.db \
         composer.json package.json package-lock.json yarn.lock composer.lock \
         README.md CHANGELOG.md LICENSE Dockerfile docker-compose.yml .dockerignore \
         .travis.yml .gitlab-ci.yml Jenkinsfile .github/workflows/main.yml \
         app.js bundle.js main.js main.js.map app.js.map webpack.config.js \
         api.php aws.json config.json settings.json credentials.json .npmrc .aws/credentials; do
  for base in "https://$T" ; do
    # -L: the estate 301s nearly everything, so WITHOUT following redirects every root
    # file looks like a 301/244-byte page and real hits are invisible.
    out=$(curl -sSL --compressed -m 15 -A "$UA" "${HDR_ARGS[@]}" -o /dev/null -w '%{http_code} %{size_download}' "$base/$p" 2>/dev/null)
    case "$out" in 200*|401*|403*) printf '%-58s %s\n' "/$p" "$out" >> "$SURF/rootfiles.txt" ;; esac
    sleep 1
  done
done
log "   interesting root files: $(gct -E '^(/[^ ]+)\s+(200|401|403)' "$SURF/rootfiles.txt")"

# ---- 4. HTTP methods --------------------------------------------------------
log "-- HTTP methods"
: > "$SURF/methods.txt"
while IFS= read -r u; do
  [ -z "$u" ] && continue
  for m in OPTIONS TRACE PUT DELETE PATCH; do
    r=$(curl -sS -m 12 -A "$UA" "${HDR_ARGS[@]}" -X "$m" -o /dev/null -w '%{http_code}' -D - "$u" 2>/dev/null | tr -d '\r' | grep -iE '^(HTTP/|allow:)' | tr '\n' ' ')
    printf '%-8s %-55s %s\n' "$m" "$u" "$r" >> "$SURF/methods.txt"
    sleep 1
  done
done < <(head -6 "$SURF/live_all.txt")
log "   method probes: $(wc -l < "$SURF/methods.txt")"

# ---- 5. directories / paths -------------------------------------------------
log "-- directories/paths (feroxbuster)"
# OPT-IN ONLY (2026-11-18). An unrequested dir brute that produced 42,963 hits (the estate
# answers 200 to nearly everything) is what got this engagement IP silently dropped at the
# edge. Brute/fuzz stages now need an explicit TARGET_BRUTE=1 from the operator, and even
# then they run 2 threads at 5 req/s against the SMALL list with a soft-404 filter.
if [ "${TARGET_BRUTE:-0}" != "1" ]; then
  log "   DISABLED (brute/fuzz is opt-in: export TARGET_BRUTE=1 to enable)"
else
  guard
  # CURATED SENSITIVE-PATH LIST (2026-11-22). MEASURED PROBLEM: the generic raft-small-words list is
  # 43,007 entries; at the mandated --rate-limit 5 that is ~2.4 HOURS for ONE host, and it pins the
  # entire cycle in recon while producing nothing on an app that returns a uniform 404. Doctrine §3.4
  # says go at the SENSITIVE surface, so prefer the curated list, and CAP any fallback list so a big
  # wordlist can never again pin the cycle for hours.
  WORDLIST="$HA/wordlists/sensitive-paths.txt"
  if [ ! -f "$WORDLIST" ]; then
    WORDLIST="/usr/share/wordlists/dirb/common.txt"
    [ -f "$WORDLIST" ] || WORDLIST="/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
    if [ -f "$WORDLIST" ]; then
      head -n 400 "$WORDLIST" > "$SURF/.wl.capped" 2>/dev/null || true
      [ -s "$SURF/.wl.capped" ] && WORDLIST="$SURF/.wl.capped"
      log "   (no curated list — capped fallback wordlist to $(gct . "$WORDLIST") entries)"
    fi
  else
    log "   curated sensitive-path list: $(gct . "$WORDLIST") entries (~$(( $(gct . "$WORDLIST") / 5 ))s at 5 req/s)"
  fi
  if [ -f "$WORDLIST" ]; then
    # measure the catch-all: a random nonexistent path tells us the soft-404 signature so
    # 40k identical noise hits can be filtered down to the handful of real ones.
    read -r CATCH_CODE CATCH_SIZE < <(curl -sS -m 12 -A "$UA" "${HDR_ARGS[@]}" -o /dev/null \
        -w '%{http_code} %{size_download}' "https://$T/zzq-$$-nonexistent")
    log "   catch-all signature: code=$CATCH_CODE size=$CATCH_SIZE"
    feroxbuster -u "https://$T" -w "$WORDLIST" -t 2 --rate-limit 5 -d 1 --no-state -C 404 \
      --json -o "$SURF/dirs.json" >/dev/null 2>&1 || true
    if [ -s "$SURF/dirs.json" ]; then
      jq -r --argjson cs "${CATCH_SIZE:-0}" \
        'select((.content_length // -1) != $cs) | select(.status >= 200 and .status < 400) | .url' \
        "$SURF/dirs.json" 2>/dev/null | sort -u | head -300 > "$SURF/dirs.txt" || : > "$SURF/dirs.txt"
    fi
    log "   dirs found=$(wc -l < "$SURF/dirs.txt" 2>/dev/null || echo 0) (soft-404 filtered, capped at 300)"
  else
    log "   (no wordlist found — skipping dir brute)"
  fi
fi

# ---- 6. urls + parameters ---------------------------------------------------
log "-- urls + parameters (operator corpus + gau/wayback)"
# The operator's own wayback corpus (state/recon/<slug>/corpus/cdx_urls.txt) is authoritative
# for this estate: gau/waybackurls pull third-party indexes and returned 0 here. Both sources
# are merged so the coverage matrix is seeded from the real historical parameter surface.
OPC_GLOB="$ST"/corpus
: > "$SURF/urls.txt"
for cf in "$OPC_GLOB"/*.txt; do
  [ -s "$cf" ] && grep -E '^https?://' "$cf" >> "$SURF/urls.txt"
done
{ gau --threads 5 "$T" 2>/dev/null; waybackurls "$T" 2>/dev/null; } >> "$SURF/urls.txt" 2>/dev/null || true
grep -E '^https?://' "$SURF/urls.txt" | sort -u > "$SURF/urls.clean" && mv -f "$SURF/urls.clean" "$SURF/urls.txt"
grep -oE '[?&][A-Za-z_][A-Za-z0-9_.-]{1,40}=' "$SURF/urls.txt" 2>/dev/null | tr -d '?&=' | sort -u > "$SURF/params.txt"
log "   urls=$(wc -l < "$SURF/urls.txt") params=$(wc -l < "$SURF/params.txt")"

# ---- 7. ports ---------------------------------------------------------------
log "-- ports"
# OPT-IN ONLY: a top-1000 sweep of five hosts is 5k connection attempts at a banned estate.
if [ "${TARGET_PORTSCAN:-0}" != "1" ]; then
  log "   DISABLED (port scan is opt-in: export TARGET_PORTSCAN=1 to enable)"
else
  guard
  cp -f "$SURF/subdomains.txt" "$SURF/ports_targets.txt"
  naabu -l "$SURF/ports_targets.txt" -p 80,443,8443,8080 -silent -rate 50 2>/dev/null > "$SURF/ports.txt" || true
  log "   open ports: $(wc -l < "$SURF/ports.txt" 2>/dev/null || echo 0)"
fi

# ---- 8. js files -> hand to jsdeep -----------------------------------------
log "-- js inventory"
grep -E '\.js(\?|$)' "$SURF/urls.txt" 2>/dev/null | sort -u > "$SURF/js_urls.txt" || true
log "   js urls=$(wc -l < "$SURF/js_urls.txt")"

# ---- 9. seed the coverage matrix -------------------------------------------
log "-- seeding coverage.tsv with every surface artefact as UNTESTED"
n0=$(wc -l < "$COV")
while IFS= read -r p; do
  pat="${p%% *}"; code="${p##* }"
  case "$code" in 200*|401*|403*) add_row "$pat" "info_disclosure_poc" "root-file hit $code" ;; esac
done < "$SURF/rootfiles.txt"
[ -f "$SURF/dirs.txt" ] && while IFS= read -r d; do
  dp=$(printf '%s' "$d" | grep -oE '/[A-Za-z0-9_./-]+' | head -1); [ -n "$dp" ] && add_row "$dp" "authz_idor" "dir brute hit"
done < "$SURF/dirs.txt"
while IFS= read -r u; do
  up=$(printf '%s' "$u" | sed -E 's#^https?://[^/]+##; s#\?.*$##'); [ -n "$up" ] && add_row "$up" "xss" "gau/wayback corpus"
done < "$SURF/urls.txt" 2>/dev/null
seed_merge   # one awk pass instead of a full-matrix grep per candidate
n1=$(wc -l < "$COV")
log "══ sweep end: coverage rows $n0 -> $n1 (+$((n1-n0))) ══"
printf '{"target":"%s","ts":"%s","new_rows":%d,"files":"%s"}\n' "$T" "$(date -Is)" "$((n1-n0))" "$SURF" >> "$SURF/sweep-history.jsonl"
