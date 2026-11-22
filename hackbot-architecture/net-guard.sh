#!/usr/bin/env bash
# net-guard.sh — PRE-FLIGHT reachability check, called before any stage that will send traffic.
#
# WHY: 2026-11-18 the swisslos surface sweep ran a 43k-hit dir brute at 20 req/s and the edge
# answered by silently DROPPING every packet from our IP (TCP connect timeouts to www AND gs,
# while the rest of the internet answered instantly). Every later stage kept firing into the
# black hole: wasted hours, and no evidence the ban was even noticed. A stage must therefore
# ask "is this estate reachable RIGHT NOW?" before it starts, and abort instead of adding to
# the volume that caused the block.
#
# usage: net-guard.sh <host> [<host2> ...]
# exit:  0 = at least one host reachable (any HTTP status)   3 = every host unreachable
# A single request per host, 8s timeout, no retries, no parallelism.
set -uo pipefail
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
[ $# -gt 0 ] || { echo "usage: net-guard.sh <host> [host...]"; exit 2; }
ok=0; report=""
for h in "$@"; do
  [ -z "$h" ] && continue
  out=$(curl -sS -m 8 -A "$UA" -o /dev/null -w '%{http_code}' "https://$h/" 2>/dev/null)
  case "$out" in
    ""|000) report+="$h=DOWN ";;
    *)      report+="$h=$out "; ok=1;;
  esac
  sleep 1   # never burst, even on a guard check
done
if [ "$ok" = 1 ]; then
  echo "REACHABLE: $report"
  exit 0
fi
echo "UNREACHABLE (edge block or outage): $report"
exit 3
