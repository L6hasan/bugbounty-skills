#!/usr/bin/env bash
# artifact-audit.sh — whitebox deep-audit of client artefacts (Q5).
# Decompiles and mines every client-side artefact to reconstruct backend schemas,
# auth logic and hidden APIs, then feeds discovered endpoints into the target's
# coverage matrix. If the audit proves a surface needs an authenticated session,
# it writes a credential request and can notify the operator.
#
# handles: APK (jadx -> dex + smali + java), MSI/EXE/DLL (msiextract + strings),
#          JS bundles + source maps (jsdeep.py), plus a generic strings fallback.
#
# usage: artifact-audit.sh --slug <slug> [--artefact PATH]... [--notify]
set -uo pipefail
export PATH="/root/go/bin:/usr/local/bin:/opt/jadx/bin:/usr/bin:/bin:${PATH:-}"

# gct <grep-args...> — like `grep -c` but ALWAYS yields exactly one integer.
# `$(grep -c X f || echo 0)` is a trap: grep -c prints "0" AND exits 1 on no match,
# so the fallback appends a second 0 -> "0\n0" -> "[ 0\n0 -gt 0 ]: integer expression expected".
gct(){ local n; n=$(grep -c "$@" 2>/dev/null); printf '%s' "${n:-0}"; }

SLUG=""; NOTIFY=0; ARTEFACTS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --slug) SLUG="$2"; shift 2;;
    --artefact) ARTEFACTS+=("$2"); shift 2;;
    --notify) NOTIFY=1; shift;;
    *) echo "unknown arg $1"; exit 2;;
  esac
done
[ -n "$SLUG" ] || { echo "usage: artifact-audit.sh --slug <slug> [--artefact PATH]"; exit 2; }
ST="/root/state/recon/$SLUG"; SURF="$ST/surface"; OUT="$ST/artefacts"; COV="$ST/loop/coverage.tsv"
mkdir -p "$SURF" "$OUT" "$ST/loop"
[ -f "$COV" ] || printf 'host\tendpoint\tmethod\tvuln_class\tstatus\tevidence_path\treason\tauth_state\trole\tupdated\n' > "$COV"
log(){ printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$OUT/audit.log"; }

add_ep(){ # add_ep <endpoint> <reason>
  local ep="$1"
  [ ${#ep} -lt 4 ] && return 0
  grep -qP "\t\Q$ep\E\t" "$COV" 2>/dev/null && return 0
  local cls
  for cls in rce command_injection sqli ssti deserialization lfi_file_read path_traversal \
             ssrf xxe auth_bypass authz_idor api_broken_auth session_privesc jwt_session_forgery; do
    printf '%s\t%s\tGET\t%s\tUNTESTED\t\tartefact-audit: %s\tanon\tnone\t%s\n' \
      "$SLUG" "$ep" "$cls" "$2" "$(date '+%FT%H:%M')" >> "$COV"
  done
}

# collect artefacts if none given
if [ ${#ARTEFACTS[@]} -eq 0 ]; then
  while IFS= read -r f; do ARTEFACTS+=("$f"); done < <(find "$ST" -type f \
    \( -name '*.apk' -o -name '*.msi' -o -name '*.exe' -o -name '*.dll' -o -name '*.dmg' \) 2>/dev/null | sort -u)
fi
log "══ artefact audit: $SLUG, ${#ARTEFACTS[@]} artefact(s) ══"

EPF="$OUT/endpoints.txt"; SECF="$OUT/secrets.txt"; APIF="$OUT/api-shapes.txt"
: > "$EPF"; : > "$SECF"; : > "$APIF"

# Noise filter: certificate/CRL/OCSP/schema URLs are .NET + Android boilerplate, not target
# surface. Without this the interest list is drowned (33 of 71 urls in the first run were PKI).
denoise(){ grep -vEi 'ocsp|crl\.|/pki/|verisign|godaddy|symantec|thawte|digicert|globalsign|entrust|sectigo|schemas\.android|apk/res-|w3\.org|iec\.ch|android\.com|microsoft\.com/(PKI|pkiops|whdc)|cloudfunctions\.net|/inspector/|launch-js-devtools|open-debugger|/status$|capture\.json|/repository/'; }

strings_all(){ # strings_all <file-or-dir> -> ascii + UTF-16LE extraction
  local t="$1"
  find "$t" -type f 2>/dev/null | while IFS= read -r f; do
    strings    -n 6 "$f" 2>/dev/null
    strings -el -n 6 "$f" 2>/dev/null
    strings -eb -n 6 "$f" 2>/dev/null
  done
}

for a in "${ARTEFACTS[@]}"; do
  [ -f "$a" ] || continue
  base="$(basename "$a")"; ext="${a##*.}"; work="$OUT/$base.d"; mkdir -p "$work"
  log "-- $base ($(stat -c%s "$a") B)"
  case "${ext,,}" in
    apk)
      # The endpoint strings live in the Hermes bytecode bundle under assets/, which jadx
      # (a dex->java decompiler) never sees. Always ALSO unzip + strings the raw archive.
      unzip -oq "$a" -d "$work/zip" 2>/dev/null || true
      strings_all "$work/zip" > "$work/strings.txt"
      log "   raw archive strings: $(wc -l < "$work/strings.txt") lines (ascii+utf16)"
      if command -v jadx >/dev/null 2>&1; then
        log "   jadx decompile"
        jadx -d "$work/jadx" --no-res -q "$a" >/dev/null 2>&1 || log "   (jadx partial)"
        grep -rhoE 'https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+' "$work/jadx" 2>/dev/null | sort -u >> "$EPF"
        grep -rhoE '"\/[A-Za-z0-9_./-]+\.(php|jsp|aspx?|json|do)"' "$work/jadx" 2>/dev/null | tr -d '"' | sort -u >> "$EPF"
        grep -rhiE '(api[_-]?key|secret|password|passwd|token|bearer|authorization)\s*[:=]\s*"[^"]{6,}"' "$work/jadx" 2>/dev/null | sort -u | head -100 >> "$SECF"
        grep -rhoE '(POST|GET|PUT|DELETE)\s+"[^"]+"' "$work/jadx" 2>/dev/null | sort -u >> "$APIF"
      fi
      if [ -f "$work/strings.txt" ]; then
        grep -oE '/[A-Za-z0-9_./-]+\.php' "$work/strings.txt" 2>/dev/null | denoise | sort -u >> "$EPF"
        grep -oE 'https://[A-Za-z0-9._-]*microkeeper[A-Za-z0-9._~:/?#@!$&()*+,;=%-]*' "$work/strings.txt" 2>/dev/null | denoise | sort -u >> "$EPF"
        grep -oE '[A-Za-z0-9_]{0,8}(password|passwd|api_?key|secret|token)[A-Za-z0-9_]{0,8}[=:][A-Za-z0-9_!@#$%^&*.-]{6,}' "$work/strings.txt" 2>/dev/null | sort -u | head -60 >> "$SECF"
      else
        log "   (jadx missing: zip + strings fallback)"
        unzip -oq "$a" -d "$work/zip" 2>/dev/null || true
        find "$work/zip" -name '*.dex' -exec strings -n 6 {} \; 2>/dev/null >> "$work/strings.txt"
        grep -oE 'https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+' "$work/strings.txt" 2>/dev/null | sort -u >> "$EPF"
        grep -oE '/[A-Za-z0-9_./-]+\.(php|jsp|aspx?|json)' "$work/strings.txt" 2>/dev/null | sort -u >> "$EPF"
      fi
      ;;
    msi)
      msiextract -C "$work/msi" "$a" >/dev/null 2>&1 || log "   (msiextract partial)"
      strings_all "$work/msi" > "$work/strings.txt"
      log "   strings extracted: $(wc -l < "$work/strings.txt") lines (ascii+utf16)"
      grep -oE 'https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+' "$work/strings.txt" 2>/dev/null | denoise | sort -u >> "$EPF"
      grep -oE '/[A-Za-z0-9_./-]+\.php(\?[A-Za-z0-9_=&%.-]*)?' "$work/strings.txt" 2>/dev/null | denoise | sort -u >> "$EPF"
      grep -iE '(api[_-]?key|secret|password|passwd|token)\s*[:=]' "$work/strings.txt" 2>/dev/null | sort -u | head -100 >> "$SECF"
      ;;
    exe|dll)
      strings -n 6 "$a" 2>/dev/null > "$work/strings.txt"
      grep -oE 'https?://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]+' "$work/strings.txt" | sort -u >> "$EPF"
      ;;
    js|map)
      python3 /root/hackbot-architecture/jsdeep.py --target "$SLUG" --slug "$SLUG" >/dev/null 2>&1 || true
      ;;
  esac
done

sort -u -o "$EPF" "$EPF" 2>/dev/null; sort -u -o "$SECF" "$SECF" 2>/dev/null
log "-- extracted: $(wc -l < "$EPF") url/path strings, $(wc -l < "$SECF") secret-shaped strings"

# feed endpoints that look like a real route on this target
target_host="$SLUG"
while IFS= read -r u; do
  ep="$(printf '%s' "$u" | sed -E "s#^https?://([^/]+)##; s#\?.*##")"
  [ -z "$ep" ] && continue
  case "$ep" in /*.php|/*/*.php|/api*|/rest*|/v[0-9]*) add_ep "$ep" "from client artefact";; esac
done < "$EPF"

# ---- authenticated-surface detection -> credential request ----
CR="$ST/credential-request.jsonl"; : > "$CR"
# Deterministic signal: an auth/API gate exists in the extracted surface (login-ish route OR an
# api_broken_auth / auth_bypass cell in the coverage matrix). That is exactly the state in which
# graybox + injection classes are UNTESTABLE without a session, so ask the operator.
GATED=$(gct -iE 'login|signin|auth|password|token|nfc|fp_api' "$EPF")
COVGATED=$(awk -F'\t' 'NR>1 && ($4=="api_broken_auth"||$4=="auth_bypass") && $5=="UNTESTED"' "$COV" 2>/dev/null | wc -l | tr -d ' ')
if [ "$GATED" -gt 0 ] || [ "$COVGATED" -gt 0 ]; then
  printf '{"ts":"%s","need":"authenticated session","why":"artefact audit shows the app surface sits behind a login gate; graybox + injection classes cannot be tested without a session","endpoint":"/login.php","how_to_supply":"supply a verified account (email+password) or a session cookie/token, or confirm SMS-gated signup should be completed by the operator"}\n' "$(date -Is)" >> "$CR"
  log "!! credential request written -> $CR"
  if [ "$NOTIFY" = 1 ]; then
    bash /root/hackbot-architecture/notch.sh "🔑 **$SLUG needs an authenticated session.** Graybox/injection testing is blocked behind the login gate. Supply a verified account or session token and I will continue. Details: $CR" >/dev/null 2>&1 || true
  fi
fi
log "══ audit end: endpoints=$EPF secrets=$SECF ══"
