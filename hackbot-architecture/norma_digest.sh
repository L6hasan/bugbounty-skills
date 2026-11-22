#!/bin/bash

# gct <grep-args...> — like `grep -c` but ALWAYS yields exactly one integer.
# `$(grep -c X f || echo 0)` is a trap: grep -c prints "0" AND exits 1 on no match,
# so the fallback appends a second 0 -> "0\n0" -> "[ 0\n0 -gt 0 ]: integer expression expected".
gct(){ local n; n=$(grep -c "$@" 2>/dev/null); printf '%s' "${n:-0}"; }

# NORMA hunt — 30-minute Discord digest of confirmed P1/P2/P3 findings.
# Reads state file, posts only if there is something new since the last digest.
STATE=/root/hackbot-architecture/state/norma
FINDINGS=$STATE/findings.jsonl
LAST=$STATE/.digest_last_count
LOG=$STATE/digest.log
INTERVAL=1800

mkdir -p "$STATE"
touch "$FINDINGS"

while true; do
  sleep "$INTERVAL"
  n=$(gct . "$FINDINGS")
  last=$(cat "$LAST" 2>/dev/null || echo 0)
  if [ "$n" -le "$last" ]; then
    echo "$(date -u +%FT%TZ) digest: no new findings ($n total) — skipping" >> "$LOG"
    continue
  fi
  echo "$n" > "$LAST"

  # build the digest from the findings file
  msg=$(python3 - "$FINDINGS" <<'PY'
import json, sys
rows = []
try:
    for line in open(sys.argv[1]):
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        rows.append(d)
except FileNotFoundError:
    pass
if not rows:
    print("")
    sys.exit(0)
sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
rows.sort(key=lambda r: (sev_order.get((r.get("severity") or "").lower(), 9), r.get("id") or "")))
lines = ["🟢 NORMA hunt — 30 min digest", f"Confirmed findings: {len(rows)}", ""]
for r in rows:
    sev = (r.get("severity") or "?").upper()
    emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(sev, "⚪")
    lines.append(f"{emoji} [{sev}] {r.get('id','?')} — {r.get('title','?')}")
    lines.append(f"    host: {r.get('host','?')}  endpoint: {r.get('endpoint','?')}")
    lines.append(f"    cvss: {r.get('cvss','?')}")
    lines.append("")
print("\n".join(lines)[:1850])
PY
)
  if [ -z "$msg" ]; then
    echo "$(date -u +%FT%TZ) digest: empty message — skipping" >> "$LOG"
    continue
  fi
  out=$(bash /root/hackbot-architecture/notch.sh "$msg" 2>&1)
  echo "$(date -u +%FT%TZ) digest posted ($n findings): $out" >> "$LOG"
done
