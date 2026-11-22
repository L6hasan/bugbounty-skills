#!/usr/bin/env bash
# set-target.sh — point the principal supervisor at a target (and switch cleanly).
#
# usage:
#   set-target.sh <target> [slug] [--scope FILE] [--hosts FILE] [--exclusions FILE]
#                 [--program LABEL] [--gap MIN] [--parallel N] [--note TEXT]
#
# Writes /root/hackbot-architecture/principal/active_target.conf.
# The running supervisor detects the conf hash change at the next phase boundary,
# archives the old target under principal/history/ and re-initialises every agent
# on the new target. No agent context is carried over.
set -uo pipefail
PR=/root/hackbot-architecture/principal
CONF="$PR/active_target.conf"
LOG="$PR/supervisor.log"

TARGET="${1:-}"; [ -n "$TARGET" ] || { echo "usage: set-target.sh <target> [slug] [--scope F] [--hosts F] [--exclusions F] [--program L] [--gap M] [--parallel N] [--note T]"; exit 2; }
shift || true
SLUG=""; SCOPE=""; HOSTS=""; EXCLUSIONS=""; PROGRAM=""; GAP="30"; PARALLEL="3"; NOTE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --scope) SCOPE="$2"; shift 2;;
    --hosts) HOSTS="$2"; shift 2;;
    --exclusions) EXCLUSIONS="$2"; shift 2;;
    --program) PROGRAM="$2"; shift 2;;
    --gap) GAP="$2"; shift 2;;
    --parallel) PARALLEL="$2"; shift 2;;
    --note) NOTE="$2"; shift 2;;
    *) [ -z "$SLUG" ] && SLUG="$1"; shift;;
  esac
done
[ -n "$SLUG" ] || SLUG="$(printf '%s' "$TARGET" | tr 'A-Z' 'a-z' | sed 's/[^a-z0-9]/-/g')"
[ -n "$SCOPE" ] && [ -f "$SCOPE" ] || { [ -n "$SCOPE" ] && echo "warning: scope file not found: $SCOPE"; SCOPE=""; }
[ -n "$HOSTS" ] && [ -f "$HOSTS" ] || { [ -n "$HOSTS" ] && echo "warning: hosts file not found: $HOSTS"; HOSTS=""; }

mkdir -p "$PR"
{ echo "# principal active target — written by set-target.sh $(date '+%F %T')"
  echo "TARGET=\"$TARGET\""
  echo "SLUG=\"$SLUG\""
  echo "SCOPE=\"$SCOPE\""
  echo "HOSTS=\"$HOSTS\""
  echo "EXCLUSIONS=\"$EXCLUSIONS\""
  echo "PROGRAM=\"$PROGRAM\""
  echo "LOOP_GAP_MIN=\"$GAP\""
  echo "MAX_PARALLEL=\"$PARALLEL\""
  echo "NOTE=\"$NOTE\""
} > "$CONF"
printf '[%s] set-target: %s (slug=%s program=%s)\n' "$(date '+%F %T')" "$TARGET" "$SLUG" "${PROGRAM:-n/a}" | tee -a "$LOG"
echo "wrote $CONF"
echo "slug=$SLUG  gap=${GAP}m  parallel=$PARALLEL"
echo "the running supervisor switches at the next phase boundary; to force now:"
echo "  systemctl restart principal-supervisor.service"
