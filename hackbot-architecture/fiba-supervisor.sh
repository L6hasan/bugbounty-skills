#!/usr/bin/env bash
# fiba-supervisor.sh — keeps the FIBA hunting loop running CONTINUOUSLY.
# Same contract as target-supervisor.sh but WITHOUT the heavy surface-sweep phase:
# the FIBA surface was already enumerated to closure by passes 1-6, and a repeating
# ffuf/nuclei sweep would only add volume at the Azure edge (block risk) for no new surface.
# Phases kept: coverage (cheap matrix refresh) + recon + hunt + chain + validate.
# Discord: QUIET — hunt-loop.sh's alert-only.sh fires ONLY on a validated high/critical
# finding or an explicit credential request. Routine health stays in the local log.
#
# usage: fiba-supervisor.sh
set -uo pipefail
export PATH="/root/.hermes/hermes-agent/.hermes/bin:/root/go/bin:/usr/local/bin:/root/.local/bin:/usr/bin:/bin:${PATH:-}"
HA=/root/hackbot-architecture
SLUG=fiba
TARGET=www.fiba.basketball
SCOPE=/root/scope/fiba-in-scope.txt
HOSTS=/root/scope/fiba-hosts.txt
EXCLUSIONS=/root/scope/fiba-excluded-noise.txt
ST=/root/state/recon/$SLUG
SUPLOG=$ST/supervisor.log
GAP=$(( ${FIBA_LOOP_GAP_MIN:-40} * 60 ))
mkdir -p "$ST"
log(){ printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$SUPLOG"; }
log "══ $SLUG supervisor start (phases=coverage,recon,hunt,chain,validate gap=${FIBA_LOOP_GAP_MIN:-40}m) ══"
while true; do
  log "CYCLE begin"
  bash "$HA/hunt-loop.sh" --target "$TARGET" --slug "$SLUG" \
       --scope "$SCOPE" --hosts "$HOSTS" --exclusions "$EXCLUSIONS" \
       --phases coverage,recon,hunt,chain,validate >>"$SUPLOG" 2>&1
  rc=$?
  [ $rc -eq 75 ] && log "CYCLE skipped — another $SLUG pass holds the lock"
  if [ $rc -eq 3 ]; then
    log "CYCLE BLOCKED at the edge (rc=3) — backing off 60m"
    sleep 3600; continue
  fi
  log "CYCLE end rc=$rc — sleeping ${FIBA_LOOP_GAP_MIN:-40}m"
  sleep "$GAP"
done
