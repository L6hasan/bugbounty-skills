#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  notify-policy.sh — THE single gate for every Discord notification.
#
#  Operator directive (2026-11-19): Discord carries ONE category only —
#      "Exploited & Ready to Submit": a 100% confirmed, end-to-end EXECUTED
#      vulnerability, with a working PoC, at least one screenshot of the exploit
#      execution, and a final report PDF ready to submit.
#  Everything else is a lead and stays LOCAL (audited in state/notify-audit.jsonl).
#
#  Eligibility (all required, enforced in Python below):
#    id, title, host|asset, endpoint, vuln_class|class|weakness, severity,
#    description|summary, impact, steps_to_reproduce|steps|repro
#    AND exploit_executed == true  (or verdict/status in EXPLOITED* / READY_TO_SUBMIT)
#    AND at least one PoC artifact that EXISTS on disk and is non-empty
#        (poc_screenshots | poc_files | artifacts | screenshots | poc.path)
#    AND severity band is Medium+ (CRITICAL/HIGH/MEDIUM)
#
#  Usage
#    notify-policy.sh check <id|finding.json>      exit 0 = eligible, 1 = suppressed (reason on stdout)
#    notify-policy.sh finding <id|finding.json> [msg]
#                                                  if eligible: render+send the report PDF and post [msg]
#    notify-policy.sh blocker <slug> <text>        credential/session request. LOCAL-ONLY unless
#                                                  HACKBOT_NOTIFY_BLOCKERS=1 (then rate-limited 6h/slug).
#    notify-policy.sh digest <slug> <text>         status digest. LOCAL-ONLY unless HACKBOT_NOTIFY_DIGEST=1.
#    notify-policy.sh suppress <slug> <kind> <text>  record a lead locally (never posts).
#    notify-policy.sh report [n]                   print the last n audit rows (default 25).
#    notify-policy.sh audit-path
#
#  Env overrides: HACKBOT_NOTIFY_BLOCKERS=1, HACKBOT_NOTIFY_DIGEST=1,
#                 HACKBOT_NOTIFY_FORCE=1 (operator override; loudly logged).
# ══════════════════════════════════════════════════════════════════════════════
set -uo pipefail
HA=/root/hackbot-architecture
STATE="$HA/state"
AUDIT="$STATE/notify-audit.jsonl"
LOCAL="$STATE/notify-local.jsonl"      # the human-readable "leads held" ledger
BLOCKERS="$STATE/blockers.jsonl"
mkdir -p "$STATE"
touch "$AUDIT" "$LOCAL" "$BLOCKERS"

log(){ printf '[notify-policy %s] %s\n' "$(date '+%F %T')" "$*" >&2; }

audit(){ # $1=id $2=eligible(yes|no) $3=kind $4=reason
  python3 - "$AUDIT" "$1" "$2" "$3" "$4" <<'PY'
import json,sys,datetime
path,fid,ok,kind,reason=sys.argv[1:6]
row={"ts":datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
     "id":fid,"eligible":ok=="yes","kind":kind,"reason":reason[:400]}
open(path,"a").write(json.dumps(row)+"\n")
PY
}

hold(){ # $1=slug $2=kind $3=text  — record a held item locally
  python3 - "$LOCAL" "$1" "$2" "$3" <<'PY'
import json,sys,datetime
path,slug,kind,text=sys.argv[1:5]
row={"ts":datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
     "slug":slug,"kind":kind,"text":text[:1200]}
open(path,"a").write(json.dumps(row)+"\n")
PY
}

# ── eligibility ──────────────────────────────────────────────────────────────
eligibility(){ # $1 = id or path to a finding json; prints reasons, exit 0/1
  python3 - "$HA/findings/confirmed.jsonl" "$1" <<'PY'
import json,os,sys
conf,farg=sys.argv[1],sys.argv[2]
rec=None
if os.path.isfile(farg):
    try: rec=json.load(open(farg))
    except Exception as e: print("unreadable finding json: %s"%e); sys.exit(1)
else:
    for line in open(conf,errors="replace"):
        line=line.strip()
        if not line: continue
        try: d=json.loads(line)
        except Exception: continue
        if str(d.get("id",""))==farg: rec=d; break
    if rec is None: print("finding %s not in confirmed.jsonl"%farg); sys.exit(1)

def g(*keys):
    for k in keys:
        v=rec.get(k)
        if isinstance(v,(str,int,float)) and str(v).strip(): return str(v).strip()
        if isinstance(v,list) and v: return v
    return ""

bad=[]
for field,keys in (("id",("id",)),("title",("title","name")),
                   ("asset",("host","asset","target","hostname")),
                   ("endpoint",("endpoint","url","path")),
                   ("vuln_class",("vuln_class","class","weakness","cwe")),
                   ("severity",("severity",)),
                   ("description",("description","summary","details")),
                   ("impact",("impact","consequence")),
                   ("steps_to_reproduce",("steps_to_reproduce","steps","repro","reproduction"))):
    if not g(*keys): bad.append("missing %s"%field)

# 1. executed end-to-end
executed = rec.get("exploit_executed") is True or rec.get("end_to_end") is True
verdict = str(g("verdict","status")).upper().replace(" ","_")
if verdict and any(t in verdict for t in ("EXPLOITED","READY_TO_SUBMIT","SUBMIT_READY")): executed=True
if not executed:
    bad.append("not executed end-to-end (needs exploit_executed:true or verdict EXPLOITED/READY_TO_SUBMIT; "
               "verdict=%r)"%verdict)

# 2. PoC artifact that actually exists (accepts plain paths AND {"file": ...} dicts)
pocs=[]
for k in ("poc_screenshots","poc_files","artifacts","screenshots","poc_artifacts","images"):
    v=rec.get(k)
    if isinstance(v,list):
        for x in v:
            if isinstance(x,str) and x.strip(): pocs.append(x.strip())
            elif isinstance(x,dict):
                for kk in ("file","path","src","image","img"):
                    if isinstance(x.get(kk),str) and x.get(kk).strip():
                        pocs.append(x[kk].strip()); break
    elif isinstance(v,str) and v.strip(): pocs.append(v.strip())
p=rec.get("poc")
if isinstance(p,dict):
    for v in p.values():
        if isinstance(v,str) and v.strip(): pocs.append(v.strip())
elif isinstance(p,str) and p.strip() and "\n" not in p.strip() and len(p.strip())<300:
    pocs.append(p.strip())   # a bare path only; prose in `poc` is not treated as an artefact
found=[x for x in pocs if os.path.isfile(x) and os.path.getsize(x)>0]
if not found:
    refs=[x.replace("\n"," ")[:60] for x in pocs[:3]]
    bad.append("no PoC artefact exists on disk (%d referenced: %s)"%(len(pocs),refs))

# 3. severity band — Discord floor is now HIGH/CRITICAL only (operator directive 2026-11-20:
#    "only notify me ... with a severity of High or Critical"). Mediums are held locally.
#    Override for a specific delivery: HACKBOT_NOTIFY_MIN_SEVERITY=medium
sev=str(g("severity")).upper()
MINSEV="${HACKBOT_NOTIFY_MIN_SEVERITY:-high}".upper()
bands = ("critical","high") if MINSEV != "MEDIUM" else ("critical","high","medium")
if sev and not any(b in sev.lower() for b in bands) \
   and not (MINSEV == "MEDIUM" and any(x in sev for x in ("5.", "4."))):
    bad.append("severity below the Discord floor (%s): %r" % (MINSEV, sev))

if bad:
    print(" | ".join(bad)); sys.exit(1)
print("eligible: executed end-to-end, PoC artefacts present (%d), severity %s"%(len(found),g("severity")))
sys.exit(0)
PY
}

cmd_check(){ local r; r="$(eligibility "$1")"; local rc=$?
  r="${r:0:300}"
  if [ $rc -eq 0 ]; then audit "$1" yes finding "eligible"; echo "$r"; else audit "$1" no finding "${r:-ineligible}"; echo "SUPPRESSED: ${r:-ineligible}"; fi
  return $rc; }

cmd_finding(){ # $1 id|file, $2 optional msg
  local id="$1" msg="${2:-}"
  if [ "${HACKBOT_NOTIFY_FORCE:-0}" != "1" ]; then
    if ! cmd_check "$id" >/dev/null; then
      log "suppressed (not Exploited&Ready): $id"
      hold "finding" "finding" "$id: $(eligibility "$id")"
      return 1
    fi
  else
    log "FORCE=1 overriding eligibility for $id (operator override)"
    audit "$id" yes finding "FORCED by HACKBOT_NOTIFY_FORCE=1"
  fi
  local f="$id"
  [ -f "$id" ] || { f="$(mktemp)"; python3 - "$HA/findings/confirmed.jsonl" "$id" > "$f" <<'PY'
import json,sys
path,fid=sys.argv[1],sys.argv[2]
for line in open(path,errors="replace"):
    line=line.strip()
    if not line: continue
    try: d=json.loads(line)
    except Exception: continue
    if str(d.get("id",""))==fid: print(json.dumps(d)); break
PY
  }
  bash "$HA/report-pdf.sh" --file "$f" || { log "report-pdf failed for $id"; return 1; }
  [ -n "$msg" ] && bash "$HA/notch.sh" "$msg" >/dev/null 2>&1 || true
  audit "$id" yes finding "delivered"
  return 0; }

cmd_blocker(){ # $1 slug, $2 text
  local slug="$1" text="$2"
  hold "$slug" blocker "$text"
  if [ "${HACKBOT_NOTIFY_BLOCKERS:-0}" != "1" ]; then
    log "blocker held locally (HACKBOT_NOTIFY_BLOCKERS=0): $slug"
    return 3
  fi
  local stamp="$STATE/.blocker-$slug.stamp"
  if [ -f "$stamp" ]; then
    local age=$(( $(date +%s) - $(stat -c%Y "$stamp") ))
    [ "$age" -lt 21600 ] && { log "blocker rate-limited for $slug (${age}s < 6h)"; return 0; }
  fi
  bash "$HA/notch.sh" "$text" >/dev/null 2>&1 && { touch "$stamp"; audit "$slug" yes blocker "blocker delivered"; }
  return 0; }

cmd_digest(){ # $1 slug, $2 text
  hold "$1" digest "$2"
  if [ "${HACKBOT_NOTIFY_DIGEST:-0}" != "1" ]; then log "digest held locally: $1"; return 0; fi
  bash "$HA/notch.sh" "$2" >/dev/null 2>&1 || true; return 0; }

cmd_suppress(){ hold "$1" "$2" "$3"; audit "$1" no "$2" "$3"; log "lead held locally: $1/$2"; }

cmd_report(){ python3 - "$AUDIT" "$LOCAL" "${1:-25}" <<'PY'
import json,sys
audit,local,n=sys.argv[1],sys.argv[2],int(sys.argv[3])
rows=[json.loads(l) for l in open(audit) if l.strip()]
print("last %d notifications decisions (of %d):"%(min(n,len(rows)),len(rows)))
for r in rows[-n:]:
    print("  %s  %-6s %-8s %s"%(r["ts"],"SEND" if r["eligible"] else "held",r["kind"],r["id"]))
    if not r["eligible"]: print("      reason: %s"%r["reason"][:180])
leads=[json.loads(l) for l in open(local) if l.strip()] if __import__("os").path.exists(local) else []
print("\nheld-locally ledger: %d entries -> %s"%(len(leads),local))
PY
}

case "${1:-}" in
  check)    cmd_check "${2:?usage: check <id|file>}" ;;
  finding)  cmd_finding "${2:?usage: finding <id|file> [msg]}" "${3:-}" ;;
  blocker)  cmd_blocker "${2:?usage: blocker <slug> <text>}" "${3:-}" ;;
  digest)   cmd_digest  "${2:?usage: digest <slug> <text>}"  "${3:-}" ;;
  suppress) cmd_suppress "${2:?usage: suppress <slug> <kind> <text>}" "${3:-lead}" "${4:-}" ;;
  report)   cmd_report "${2:-25}" ;;
  audit-path) echo "$AUDIT" ;;
  *) sed -n '2,30p' "$0"; exit 2 ;;
esac
