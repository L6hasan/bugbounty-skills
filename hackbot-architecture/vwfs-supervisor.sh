#!/usr/bin/env bash
# vwfs-supervisor.sh — keeps the VWFS (NBW) hunting loop running CONTINUOUSLY.
# Same contract as fiba-supervisor.sh: phases coverage,recon,hunt,chain,validate
# (surface-sweep is dropped after pass 1 — a repeating ffuf/nuclei sweep only adds
# volume at the CloudFront edge for no new surface on this estate).
# Discord stays QUIET: hunt-loop.sh's alert-only.sh fires only on a validated
# high/critical finding. Routine health stays in the local log.
#
# usage: vwfs-supervisor.sh
set -uo pipefail
export PATH="/root/.hermes/hermes-agent/.hermes/bin:/root/go/bin:/usr/local/bin:/root/.local/bin:/usr/bin:/bin:${PATH:-}"
HA=/root/hackbot-architecture
SLUG=vwfs
TARGET=www.vwfs.de
SCOPE=/root/scope/vwfs-in-scope.txt
HOSTS=/root/scope/vwfs-hosts.txt
EXCLUSIONS=/root/scope/vwfs-excluded-noise.txt
ST=/root/state/recon/$SLUG
SUPLOG=$ST/supervisor.log
GAP=$(( ${VWFS_LOOP_GAP_MIN:-40} * 60 ))
mkdir -p "$ST"
log(){ printf '[%s] %s\n' "$(date '+%F %T')" "$*" | tee -a "$SUPLOG"; }
log "══ $SLUG supervisor start (phases=coverage,recon,hunt,chain,validate gap=${VWFS_LOOP_GAP_MIN:-40}m) ══"
while true; do
  log "CYCLE begin"
  bash "$HA/hunt-loop.sh" --target "$TARGET" --slug "$SLUG" \
       --scope "$SCOPE" --hosts "$HOSTS" --exclusions "$EXCLUSIONS" \
       --phases coverage,recon,hunt,chain,validate >>"$SUPLOG" 2>&1
  rc=$?
  if [ $rc -eq 75 ]; then
    log "CYCLE skipped — another $SLUG pass holds the lock; retry in 3m"
    sleep 180; continue
  fi
  if [ $rc -eq 3 ]; then
    log "CYCLE BLOCKED at the edge (rc=3) — backing off 60m"
    sleep 3600; continue
  fi
  log "CYCLE end rc=$rc — sleeping ${VWFS_LOOP_GAP_MIN:-40}m"
  sleep "$GAP"
done
