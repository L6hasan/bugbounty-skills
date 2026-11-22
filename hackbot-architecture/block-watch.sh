#!/usr/bin/env bash
# block-watch.sh — CANARY for an edge/IP block on a target estate.
#
# WHY: a silent-DROP ban (TCP timeouts, not 403s) looks exactly like a dead target. Without a
# canary you either (a) keep hammering the ban into a longer one, or (b) stop hunting forever
# because you cannot tell "blocked" from "down". This watcher sends ONE request per host per
# cycle, backs off exponentially while blocked, and announces recovery on Discord.
#
# usage: block-watch.sh --slug <slug> [--hosts FILE] [--host H]... [--interval 1200]
#                       [--max-interval 7200] [--notify] [--exit-on-recover]
#   default interval 1200s (20m), doubling per consecutive blocked cycle, capped at
#   --max-interval. Never scans, never retries inside a cycle.
set -uo pipefail
export PATH="/root/go/bin:/usr/local/bin:/usr/bin:/bin:${PATH:-}"
HA=/root/hackbot-architecture
SLUG=""; HOSTS_FILE=""; INTERVAL=1200; MAXINT=7200; NOTIFY=0; EXIT_OK=0; PRIMARY=""
HOSTS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --slug) SLUG="$2"; shift 2;;
    --hosts) HOSTS_FILE="$2"; shift 2;;
    --host) HOSTS+=("$2"); shift 2;;
    --primary) PRIMARY="$2"; shift 2;;
    --interval) INTERVAL="$2"; shift 2;;
    --max-interval) MAXINT="$2"; shift 2;;
    --notify) NOTIFY=1; shift;;
    --exit-on-recover) EXIT_OK=1; shift;;
    *) echo "unknown arg: $1"; exit 2;;
  esac
done
[ -n "$SLUG" ] || { echo "usage: block-watch.sh --slug <slug> [--hosts FILE] [--interval N]"; exit 2; }
ST="/root/state/recon/$SLUG"; mkdir -p "$ST"
LOG="$ST/block-watch.log"
STATE="$ST/block-state.json"
if [ -n "$HOSTS_FILE" ] && [ -f "$HOSTS_FILE" ]; then
  while IFS= read -r h; do
    h="$(printf '%s' "$h" | tr -d ' \r')"
    case "$h" in ''|\#*) continue;; esac
    HOSTS+=("$h")
  done < "$HOSTS_FILE"
fi
[ "${#HOSTS[@]}" -gt 0 ] || { echo "no hosts"; exit 2; }
# The judgement is made by the PRIMARY host only. On the first run of this watcher every host
# was listed and goooal.swisslos.ineor.si answered 403 -- a single reachable third-party host
# flipped the whole estate to "RECOVERED" while www was still silently dropping our packets.
# A canary that can be satisfied by a host you are not hunting is worse than none.
[ -n "$PRIMARY" ] || PRIMARY="${HOSTS[0]}"
notify(){ [ "$NOTIFY" = 1 ] || return 0; bash "$HA/notch.sh" "$1" >/dev/null 2>&1 || true; }
log(){ printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG"; }

log "══ block-watch start slug=$SLUG primary=$PRIMARY hosts=${HOSTS[*]} interval=${INTERVAL}s ══"
cur=$INTERVAL; blocked_announced=0
while true; do
  statuses=""; up=0
  for h in "${HOSTS[@]}"; do
    code=$(curl -sS -m 8 -o /dev/null -w '%{http_code}' "https://$h/" 2>/dev/null)
    case "$code" in ""|000) statuses+="$h=DOWN ";; *) statuses+="$h=$code "; [ "$h" = "$PRIMARY" ] && up=1;; esac
    sleep 1
  done
  if [ "$up" -gt 0 ]; then
    log "RECOVERED: $statuses (up=$up/${#HOSTS[@]})"
    printf '{"slug":"%s","state":"reachable","ts":"%s","statuses":"%s"}\n' "$SLUG" "$(date -Is)" "$statuses" > "$STATE"
    if [ "$blocked_announced" = 1 ]; then
      notify "✅ $SLUG reachable again after an edge block — resuming hunting at low rate. $statuses"
    fi
    [ "$EXIT_OK" = 1 ] && exit 0
    # stay resident but slow: confirms it keeps working and re-arms if the block returns
    cur=$INTERVAL; blocked_announced=0
  else
    if [ "$blocked_announced" = 0 ]; then
      log "BLOCKED (silent DROP): $statuses — backing off, next check in ${cur}s"
      printf '{"slug":"%s","state":"blocked","ts":"%s","statuses":"%s","next_check_s":%d}\n' "$SLUG" "$(date -Is)" "$statuses" "$cur" > "$STATE"
      notify "⛔ $SLUG edge is dropping our IP (silent TCP timeout) — pausing traffic, canary checks every ${cur}s. Fix: wait out the ban, or change egress IP."
      blocked_announced=1
    else
      log "still blocked: $statuses — next check in ${cur}s"
      printf '{"slug":"%s","state":"blocked","ts":"%s","statuses":"%s","next_check_s":%d}\n' "$SLUG" "$(date -Is)" "$statuses" "$cur" > "$STATE"
    fi
    cur=$(( cur * 2 )); [ "$cur" -gt "$MAXINT" ] && cur=$MAXINT
  fi
  sleep "$cur"
done
