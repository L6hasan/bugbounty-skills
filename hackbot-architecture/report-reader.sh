#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  report-reader.sh — ONE uninterrupted knowledge-intake pass.
#
#  Loop contract (owner: Kr Hasan):
#    read reports/writeups ONE BY ONE, only the VALID ones, from
#      HackerOne Hacktivity (disclosed) · Bugcrowd published · Intigriti
#      PortSwigger research + lab solutions · PentesterLand · Medium · InfoSec Writeups
#    restricted to the hunting classes in CLASSES below,
#    distill each into a reusable technique and APPEND it to the skill files,
#    and every 100 reports post a digest to Discord.
#
#  Stages
#    1. HARVEST  (deterministic, no LLM) — pull a candidate queue of report URLs,
#                dedupe against everything already read.
#    2. READ     (one bounded LLM pass)  — read the next BATCH urls one by one,
#                validate, classify, append technique entries, print a machine line.
#    3. COUNT    (deterministic)         — advance the cumulative counter.
#    4. MILESTONE                        — every 100 reports → notch.sh Discord digest.
#
#  Usage: report-reader.sh [--harvest-only] [--batch N] [--status]
# ══════════════════════════════════════════════════════════════════════════════
set -uo pipefail

# gct <grep-args...> — like `grep -c` but ALWAYS yields exactly one integer.
# `$(grep -c X f || echo 0)` is a trap: grep -c prints "0" AND exits 1 on no match,
# so the fallback appends a second 0 -> "0\n0" -> "[ 0\n0 -gt 0 ]: integer expression expected".
gct(){ local n; n=$(grep -c "$@" 2>/dev/null); printf '%s' "${n:-0}"; }


ROOT="${READER_ROOT:-/root/hackbot-architecture}"
STATE="$ROOT/state"
KB="$ROOT/knowledge"
LEDGER="${READER_LEDGER:-/root/bugbountyhuntingskills.md}"
SKILL_MD="${READER_SKILL:-/root/Bugbountyskills.md}"
DOCTRINE="$ROOT/SEVERITY_DOCTRINE.md"
QUEUE="$STATE/report-queue.txt"
SEEN="$STATE/report-reader.seen"
COUNT="$STATE/report-reader.count"
LOG="$STATE/report-reader.log"
EVENTS="$STATE/report-reader.events.jsonl"
H1CSV="$STATE/h1-reports.csv"
MILESTONE_FILE="$STATE/report-reader.milestone"
BATCH="${READER_BATCH:-6}"
MILESTONE_EVERY="${READER_MILESTONE:-100}"
mkdir -p "$STATE" "$KB"
touch "$SEEN" "$QUEUE"

log(){ printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >> "$LOG"; }
nlines(){ [ -f "$1" ] && gct . "$1"; }

if [ "${1:-}" = "--status" ]; then
  echo "cumulative reports read : $(cat "$COUNT" 2>/dev/null || echo 0)"
  echo "next Discord milestone  : $(( (($(cat "$COUNT" 2>/dev/null || echo 0) / MILESTONE_EVERY) + 1) * MILESTONE_EVERY ))"
  echo "queue (unread candidates): $(wc -l < "$QUEUE")"
  echo "seen (already handled)   : $(wc -l < "$SEEN")"
  echo "ledger lines             : $(nlines "$LEDGER")"
  echo "skill file lines         : $(nlines "$SKILL_MD")"
  exit 0
fi

# ─────────────────────────────────────────────────────────────────────────────
# 1. HARVEST — deterministic candidate queue, class-filtered
# ─────────────────────────────────────────────────────────────────────────────
harvest(){
  log "harvest: start (queue=$(wc -l < "$QUEUE"))"

  # (a) HackerOne disclosed reports, classified by bug type (15k rows).
  #     Refreshed at most daily; 2MB, single raw fetch.
  if [ ! -f "$H1CSV" ] || [ -n "$(find "$H1CSV" -mtime +1 2>/dev/null)" ]; then
    curl -sL -m 90 "https://raw.githubusercontent.com/reddelexc/hackerone-reports/master/data.csv" \
      -o "$H1CSV.tmp" && [ -s "$H1CSV.tmp" ] && mv "$H1CSV.tmp" "$H1CSV"
    log "harvest: refreshed HackerOne dataset ($(wc -l < "$H1CSV" 2>/dev/null) rows)"
  fi

  python3 - "$H1CSV" "$QUEUE" "$SEEN" <<'PY'
import csv, sys, os, collections
csv_f, queue_f, seen_f = sys.argv[1], sys.argv[2], sys.argv[3]

# Kr Hasan's hunting classes -> the disclosed-report taxonomy (VRT-style vuln_type).
CLASSES = {
 "RCE":                 ["code injection", "command injection", "os command injection",
                         "remote code execution", "server-side include"],
 "CODE-INJECTION":      ["code injection", "template injection", "ssti"],
 "COMMAND-EXECUTION":   ["command injection", "os command injection"],
 "SQLI":                ["sql injection"],
 "XSS":                 ["xss"],
 "BAC":                 ["improper access control", "improper authorization",
                         "violation of secure design principles"],
 "AUTH-BYPASS":         ["improper authentication", "authentication bypass",
                         "insufficient session expiration",
                         "improper restriction of authentication attempts"],
 "PRIV-ESC":            ["privilege escalation"],
 "IDOR":                ["idor", "insecure direct object reference"],
 "LFI":                 ["path traversal"],
 "INTERNAL-FILE-READ":  ["path traversal", "file disclosure", "information disclosure"],
 "SANDBOX-BYPASS":      ["sandbox"],
 "OAUTH-BYPASS":        ["improper authentication", "oauth"],
 "DESERIALIZATION":     ["deserialization of untrusted data"],
 "XXE":                 ["xml external entit"],
 "SSRF":                ["server-side request forgery", "ssrf"],
 "SERVER-MISCONFIG":    ["misconfiguration", "violation of secure design principles"],
 "CLIENT-MISCONFIG":    ["misconfiguration", "content security policy"],
 "BUSINESS-LOGIC":      ["business logic"],
 "INFO-DISCLOSURE":     ["information disclosure", "privacy violation",
                         "cleartext storage of sensitive information",
                         "insufficiently protected credentials"],
 "ADMIN-ACCESS":        ["improper access control", "improper authorization"],
 "SMUGGLING":           ["http request smuggling"],
 "MEMORY-CORRUPTION":   ["use after free", "buffer overflow", "memory corruption",
                         "out-of-bounds", "null pointer"],
}
NEEDLES = {n for v in CLASSES.values() for n in v}

if not os.path.exists(csv_f) or os.path.getsize(csv_f) == 0:
    print(0); sys.exit(0)

rows = list(csv.DictReader(open(csv_f, encoding='utf-8', errors='replace')))
seen = {l.strip() for l in open(seen_f, encoding='utf-8', errors='replace') if l.strip()}
have = set()
if os.path.exists(queue_f):
    have = {l.split('\t')[0].strip() for l in open(queue_f, encoding='utf-8', errors='replace') if l.strip()}

def cls_of(vt):
    vt = (vt or "").lower()
    for name, needles in CLASSES.items():
        if any(n in vt for n in needles):
            return name
    return None

cand = []
for r in rows:
    link = (r.get('link') or '').strip()
    if not link or 'hackerone.com/reports/' not in link:
        continue
    if not link.startswith('http'):
        link = 'https://' + link
    link = link.split('#')[0].rstrip('/')
    if link in seen or link in have:
        continue
    c = cls_of(r.get('vuln_type'))
    if not c:
        continue
    try:    bounty = float(r.get('bounty') or 0)
    except Exception: bounty = 0.0
    try:    up = int(float(r.get('upvotes') or 0))
    except Exception: up = 0
    cand.append((bounty, up, link, c, (r.get('title') or '').strip()[:110], (r.get('program') or '').strip()))

# highest-signal first: paid reports, then community upvotes
cand.sort(key=lambda x: (-x[0], -x[1]))
out = []
for bounty, up, link, c, title, prog in cand:
    out.append(f"{link}\t{c}\t{prog}\t{title}")
    if len(out) >= 400:   # keep the queue bounded
        break

with open(queue_f, 'a', encoding='utf-8') as fh:
    for line in out:
        fh.write(line + "\n")
print(len(out))
PY
  log "harvest: hackerone candidates appended (queue=$(wc -l < "$QUEUE"))"

  # (b) PortSwigger — research feed (in (c)) + every Web Security Academy lab solution.
  #     The lab list is class-mapped in the URL path (access-control, sql-injection, ssrf,
  #     xxe, insecure-deserialization, os-command-injection, file-path-traversal, oauth, jwt…).
  python3 - "$QUEUE" "$SEEN" <<'PY'
import sys,urllib.request,re
queue_f,seen_f=sys.argv[1],sys.argv[2]
UA={'User-Agent':'Mozilla/5.0'}
TOPIC_CLASS=[("sql-injection","SQLI"),("cross-site-scripting","XSS"),("ssrf","SSRF"),
 ("server-side-request-forgery","SSRF"),("xxe","XXE"),("insecure-deserialization","DESERIALIZATION"),
 ("os-command-injection","COMMAND-EXECUTION"),("command-injection","COMMAND-EXECUTION"),
 ("file-path-traversal","LFI"),("access-control","BAC"),("authentication","AUTH-BYPASS"),
 ("oauth","OAUTH-BYPASS"),("jwt","AUTH-BYPASS"),("business-logic","BUSINESS-LOGIC"),
 ("information-disclosure","INFO-DISCLOSURE"),("api-testing","BAC"),("graphql","BAC"),
 ("race-conditions","BUSINESS-LOGIC"),("web-cache-deception","SERVER-MISCONFIG"),
 ("cors","SERVER-MISCONFIG"),("web-sockets","BAC"),("prototype-pollution","RCE"),
 ("server-side-template-injection","RCE"),("ssti","RCE"),("dom-based","XSS"),("clickjacking","SKIP"),
 ("csrf","SKIP"),("essential-skills","SKIP"),("mystery-lab","SKIP")]
seen={l.strip() for l in open(seen_f,encoding='utf-8',errors='replace') if l.strip()}
have={l.split('\t')[0].strip() for l in open(queue_f,encoding='utf-8',errors='replace') if l.strip()}
n=0
try:
    raw=urllib.request.urlopen(urllib.request.Request("https://portswigger.net/sitemap.xml",headers=UA),timeout=45).read().decode('utf-8','replace')
    locs=re.findall(r'<loc>([^<]+)</loc>',raw)
except Exception:
    locs=[]
for u in locs:
    if '/web-security/' not in u or '/lab-' not in u:
        continue
    cls=None
    for key,c in TOPIC_CLASS:
        if f'/{key}/' in u:
            cls=c; break
    if not cls or cls=="SKIP":
        continue
    if u in seen or u in have:
        continue
    open(queue_f,'a',encoding='utf-8').write(f"{u}\t{cls}\tportswigger-lab\t{cls} lab solution\n"); n+=1
print(n)
PY

  # (b2) curated cross-platform writeup index (HackerOne / Bugcrowd / PentesterLand links,
  #      grouped by bug class in the README)
  python3 - "$QUEUE" "$SEEN" <<'PY'
import sys,urllib.request,re
queue_f,seen_f=sys.argv[1],sys.argv[2]
UA={'User-Agent':'Mozilla/5.0'}
seen={l.strip() for l in open(seen_f,encoding='utf-8',errors='replace') if l.strip()}
have={l.split('\t')[0].strip() for l in open(queue_f,encoding='utf-8',errors='replace') if l.strip()}
CLASSES=[("xss","XSS"),("cross site scripting","XSS"),("sql","SQLI"),("sqli","SQLI"),
 ("rce","RCE"),("remote code","RCE"),("command injection","COMMAND-EXECUTION"),("ssrf","SSRF"),
 ("xxe","XXE"),("idor","IDOR"),("access control","BAC"),("auth","AUTH-BYPASS"),
 ("oauth","OAUTH-BYPASS"),("csrf","SKIP"),("open redirect","OPEN-REDIRECT"),
 ("deserial","DESERIALIZATION"),("traversal","LFI"),("lfi","LFI"),("information disclosure","INFO-DISCLOSURE"),
 ("business logic","BUSINESS-LOGIC"),("template","RCE"),("graphql","BAC")]
n=0
try:
    raw=urllib.request.urlopen(urllib.request.Request(
        "https://raw.githubusercontent.com/ngalongc/bug-bounty-reference/master/README.md",
        headers=UA),timeout=45).read().decode('utf-8','replace')
except Exception:
    raw=""
cur="REFERENCE"
for line in raw.splitlines():
    h=line.strip()
    if h.startswith('#'):
        cur=h.lstrip('# ').strip()
        continue
    for m in re.findall(r'\((https?://[^)\s]+)\)', line):
        u=m
        if not re.search(r'(writeup|write-up|report|blog|medium|hackerone|bugcrowd|pentester|infosec)', u, re.I):
            continue
        cls=cur.upper()[:24]
        for key,c in CLASSES:
            if key in cur.lower():
                cls=c; break
        if cls in ("SKIP","CSRF"):
            continue
        if u in seen or u in have:
            continue
        open(queue_f,'a',encoding='utf-8').write(f"{u}\t{cls}\treference-index\t{cur[:100]}\n"); n+=1
        if n>=60: break
    if n>=60: break
print(n)
PY

  # (c) RSS: InfoSec Writeups, Medium bug-bounty tag, Intigriti, PortSwigger research+labs
  python3 - "$QUEUE" "$SEEN" <<'PY'
import sys,urllib.request,re,xml.etree.ElementTree as ET
queue_f,seen_f=sys.argv[1],sys.argv[2]
FEEDS=[("INFOSEC","https://infosecwriteups.com/feed"),
       ("MEDIUM","https://medium.com/feed/tag/bug-bounty"),
       ("INTIGRITI","https://blog.intigriti.com/feed"),
       ("PORTSWIGGER","https://portswigger.net/research/rss")]
seen={l.strip() for l in open(seen_f,encoding='utf-8',errors='replace') if l.strip()}
have={l.split('\t')[0].strip() for l in open(queue_f,encoding='utf-8',errors='replace') if l.strip()}
UA={'User-Agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120 Safari/537.36'}
n=0
for src,url in FEEDS:
    try:
        raw=urllib.request.urlopen(urllib.request.Request(url,headers=UA),timeout=30).read()
        root=ET.fromstring(raw)
    except Exception as e:
        continue
    for it in root.iter('item'):
        link=(it.findtext('link') or '').strip()
        title=(it.findtext('title') or '').strip()[:110]
        if not link.startswith('http'): continue
        link=link.split('#')[0]
        if link in seen or link in have: continue
        open(queue_f,'a',encoding='utf-8').write(f"{link}\t{src}\tfeed\t{title}\n"); n+=1
print(n)
PY

  # (d) PentesterLand — the real writeup index (2 MB HTML table, sectioned by year with a
  #     "Vulnerability" column), from the site's own source repo. Cached daily.
  python3 - "$QUEUE" "$SEEN" "$STATE/pentesterland.md" <<'PY'
import sys,urllib.request,re,os,time
queue_f,seen_f,cache=sys.argv[1],sys.argv[2],sys.argv[3]
URL="https://raw.githubusercontent.com/pentesterland/pentesterland.github.io/master/_pages/list-of-bug-bounty-writeups.md"
if (not os.path.exists(cache)) or (time.time()-os.path.getmtime(cache))>86400:
    try:
        raw=urllib.request.urlopen(urllib.request.Request(URL,headers={'User-Agent':'Mozilla/5.0'}),timeout=120).read().decode('utf-8','replace')
        if len(raw)>10000: open(cache,'w',encoding='utf-8').write(raw)
    except Exception: pass
t=open(cache,encoding='utf-8',errors='replace').read() if os.path.exists(cache) else ""
seen={l.strip() for l in open(seen_f,encoding='utf-8',errors='replace') if l.strip()}
have={l.split('\t')[0].strip() for l in open(queue_f,encoding='utf-8',errors='replace') if l.strip()}
# the table's 4th column is the vulnerability class
CLASSES=[("cross-site scripting","XSS"),("xss","XSS"),("sql injection","SQLI"),("sqli","SQLI"),
 ("remote code","RCE"),("rce","RCE"),("command injection","COMMAND-EXECUTION"),("ssrf","SSRF"),
 ("xxe","XXE"),("idor","IDOR"),("broken access","BAC"),("access control","BAC"),
 ("authorization","BAC"),("authentication","AUTH-BYPASS"),("oauth","OAUTH-BYPASS"),
 ("jwt","AUTH-BYPASS"),("deserial","DESERIALIZATION"),("path traversal","LFI"),("traversal","LFI"),
 ("lfi","LFI"),("file read","INTERNAL-FILE-READ"),("information disclosure","INFO-DISCLOSURE"),
 ("info disclosure","INFO-DISCLOSURE"),("business logic","BUSINESS-LOGIC"),("race condition","BUSINESS-LOGIC"),
 ("open redirect","OPEN-REDIRECT"),("csrf","SKIP"),("clickjacking","SKIP"),("graphql","BAC"),
 ("ssti","RCE"),("template injection","RCE"),("request smuggling","SMUGGLING"),("cache poisoning","SERVER-MISCONFIG"),
 ("cache deception","SERVER-MISCONFIG"),("subdomain takeover","SKIP"),("account takeover","AUTH-BYPASS"),
 ("privilege escalation","PRIV-ESC"),("storage","INFO-DISCLOSURE"),("exposure","INFO-DISCLOSURE")]
rows=re.findall(r'<tr[^>]*>(.*?)</tr>', t, re.S)
per_class={}; n=0; CAP=15
for row in rows:
    tds=re.findall(r'<td[^>]*>(.*?)</td>', row, re.S)
    if len(tds)<4: continue
    m=re.search(r'href="(https?://[^"]+)"', tds[0])
    if not m: continue
    u=m.group(1).split('#')[0]
    if 'pentester.land' in u: continue
    vuln=re.sub(r'<[^>]+>',' ', tds[3]).lower()
    cls=None
    for key,c in CLASSES:
        if key in vuln: cls=c; break
    if not cls or cls=="SKIP": continue
    if per_class.get(cls,0)>=CAP: continue
    if u in seen or u in have: continue
    per_class[cls]=per_class.get(cls,0)+1
    title=re.sub(r'<[^>]+>',' ',tds[0])
    title=re.sub(r'\s+',' ',title).strip()[:100]
    open(queue_f,'a',encoding='utf-8').write(f"{u}\t{cls}\tpentesterland\t{title}\n"); n+=1
print(n)
PY

  awk '!seen[$0]++' "$QUEUE" > "$QUEUE.tmp" && mv "$QUEUE.tmp" "$QUEUE"   # dedupe, keep priority order
  log "harvest: done (queue=$(wc -l < "$QUEUE") candidates)"
}

# ─────────────────────────────────────────────────────────────────────────────
# 2. READ — one bounded LLM pass over the next BATCH reports, one at a time
# ─────────────────────────────────────────────────────────────────────────────
read_pass(){
  local prompt="$STATE/report-reader-prompt.txt"
  local before_ledger before_kb before_skill
  before_ledger=$(nlines "$LEDGER"); before_skill=$(nlines "$SKILL_MD")
  local TODAY OUT_MD; TODAY="$(date +%F)"; OUT_MD="$KB/methodologies-$TODAY.md"
  before_kb=$(nlines "$OUT_MD")

  local batch; batch=$(head -n "$BATCH" "$QUEUE")
  if [ -z "$batch" ]; then log "read: queue empty — nothing to read"; echo 0; return 0; fi
  local nurls; nurls=$(printf '%s\n' "$batch" | grep -c .)

  {
    echo "You are the REPORT-READER agent of an autonomous bug-bounty system. This pass is"
    echo "KNOWLEDGE INTAKE ONLY — you are NOT hunting, and you must NOT touch any target."
    echo
    echo "TASK: read the $nurls sources below ONE BY ONE, in order. For each:"
    echo "  1. FETCH IT with your own web tools (web_extract first; if it returns junk/empty or"
    echo "     the page is JS-only, use the browser tools). Do not skip a reachable source."
    echo "  2. VALIDATE: it must be a real, readable report/writeup that actually teaches a"
    echo "     technique. If it 404s, is a paywall stub, is off-topic, or teaches nothing"
    echo "     concrete, mark it INVALID and move on — do NOT invent content for it."
    echo "     If a HackerOne report page will not render, try in order: web_extract again,"
    echo "     the browser tool on the same URL, https://r.jina.ai/<url>, the Wayback copy, then"
    echo "     the credited public writeup. Note in the entry which route worked."
    echo "  3. EXTRACT the reusable method — the CLASS, the ENTRY POINT, the BYPASS, the CHAIN and"
    echo "     the exact TRANSFERABLE TEST. Not the CVE number, not the outcome: the method."
    echo
    echo "HARD RULES"
    echo "- Never fabricate a report, an ID, a quote or a technique. If a source is unreadable,"
    echo "  say so. Honesty about a failed fetch is required; invention is forbidden."
    echo "- APPEND ONLY to the write targets. Never rewrite or delete existing content."
    echo "- NO DUPLICATES. The tail of the ledger is below; if the technique is already recorded,"
    echo "  do not re-append it. 1-3 genuinely new, specific techniques beats 10 generic ones."
    echo "- Only these hunting classes are worth recording (skip anything else):"
    echo "  RCE, command execution, code injection, SQLi/NoSQLi, XSS with real impact, BAC,"
    echo "  authentication bypass, authorization/IDOR/BOLA, privilege escalation, LFI/RFI/path"
    echo "  traversal, internal file read, sandbox/container escape, OAuth/OIDC/SSO bypass,"
    echo "  JWT/session forgery, insecure deserialization, XXE, SSRF, server/client-side"
    echo "  misconfiguration with impact, business-logic with monetary/account impact, sensitive"
    echo "  info disclosure with PoC, admin/internal panel access, ATO chains."
    echo "- Prefer techniques that ESCALATE a P4/P5 primitive into a P1/P2 chain."
    echo "- FRESHNESS: prefer sources published in the last 6-12 months. Do not import a technique"
    echo "  from memory or because it 'sounds right' — open the source and read it this pass."
    echo "- NO UNSOURCED ENTRIES: every entry must carry the SOURCE url and the date you read it."
    echo "  A technique you did not open does not get written down."
    echo "- Reproduce or tag: if you did not verify the technique against a lab or first-hand PoC,"
    echo "  mark the entry STATUS: UNVERIFIED (not reproduced). Verified => STATUS: VERIFIED."
    echo "- CHAIN-ONLY MATERIAL: an info-disclosure / reflected-param / open-redirect / verbose-error"
    echo "  / weak-header finding is NOT an entry on its own — record it only as the first link of a"
    echo "  documented chain, and say what concrete impact the chain reaches."
    echo
    echo "SOURCES TO READ NOW (one by one, in this order)"
    printf '%s\n' "$batch" | nl -w2 -s'. '
    echo
    echo "OUTPUT FORMAT — for every VALID source that taught a new technique, append ONE entry"
    echo "in exactly this shape (match the ledger):"
    echo
    echo "SOURCE: <url>  <date read>"
    echo "STATUS: VERIFIED | UNVERIFIED (not reproduced)"
    echo "CLASS: <vuln class>"
    echo "CORE METHOD:"
    echo "  1. <ordered concrete steps — real request shapes / params / headers>"
    echo "  2. ..."
    echo "DETECTION SIGNAL: <what you observe that says this class is present>"
    echo "CHAIN: <primitive -> escalation -> high/critical impact, every link recorded>"
    echo "TRANSFERABLE TEST: <the one reproducible test to run on the next target>"
    echo
    echo "WRITE TARGETS (append at end only)"
    echo "  A) $LEDGER             (harvest ledger)"
    echo "  B) $OUT_MD   (dated knowledge file)"
    echo "  C) Section 17 of $SKILL_MD — only for a genuinely NEW general method, same shape."
    echo
    echo "Then finish with EXACTLY ONE machine-readable line, no text after it:"
    echo "READER_RESULT READ=<valid sources read> SKIPPED=<invalid/unreachable> APPENDED=<entries appended> CLASSES=<comma list>"
    echo
    echo "===== SEVERITY_DOCTRINE.md ====="
    cat "$DOCTRINE" 2>/dev/null
    echo "===== end doctrine ====="
    echo
    echo "===== LEDGER TAIL (do NOT duplicate) ====="
    tail -60 "$LEDGER" 2>/dev/null
    echo "===== end tail ====="
  } > "$prompt"

  log "read: pass start — batch=$nurls queue=$(wc -l < "$QUEUE")"
  local passout="$STATE/report-reader-pass.out"
  : > "$passout"
  # --quiet is REQUIRED: hermes prints the whole prompt as a console label and rich
  # parses it as markup, so any '[' in the prompt (e.g. a ledger-tail token like
  # [/{id}]) raises MarkupError before the agent runs and the pass silently no-ops.
  timeout 2400 hermes chat --query-file "$prompt" --quiet >> "$passout" 2>&1 \
    || log "read: pass timed out or errored (non-fatal)"
  cat "$passout" >> "$LOG"

  local line read_n skip_n append_n classes
  line="$(grep -oE 'READER_RESULT READ=[0-9]+ SKIPPED=[0-9]+ APPENDED=[0-9]+[^"]*' "$passout" | tail -1)"
  read_n=$(printf '%s' "$line"   | grep -oE 'READ=[0-9]+'     | grep -oE '[0-9]+' || echo 0)
  skip_n=$(printf '%s' "$line"   | grep -oE 'SKIPPED=[0-9]+'  | grep -oE '[0-9]+' || echo 0)
  append_n=$(printf '%s' "$line" | grep -oE 'APPENDED=[0-9]+' | grep -oE '[0-9]+' || echo 0)
  classes=$(printf '%s' "$line"  | grep -oE 'CLASSES=[^ ]*'   | cut -d= -f2 || echo "")

  # anything the agent read (valid or not) leaves the queue — remove by EXACT url match,
  # not by position, so a concurrent append can never drop the wrong rows
  printf '%s\n' "$batch" >> "$SEEN"
  printf '%s\n' "$batch" > "$STATE/report-reader.batch.tmp"
  grep -vxF -f "$STATE/report-reader.batch.tmp" "$QUEUE" > "$QUEUE.tmp" 2>/dev/null
  mv "$QUEUE.tmp" "$QUEUE"

  local dl=$(( $(nlines "$LEDGER") - before_ledger ))
  local dk=$(( $(nlines "$OUT_MD") - before_kb ))
  local ds=$(( $(nlines "$SKILL_MD") - before_skill ))
  log "read: READ=$read_n SKIPPED=$skip_n APPENDED=$append_n classes=$classes | ledger+$dl kb+$dk skill+$ds"

  python3 - "$EVENTS" "$read_n" "$skip_n" "$append_n" "$classes" "$dl" "$dk" "$ds" <<'PY'
import json,sys,time
ev,rd,sk,ap,cl,dl,dk,ds=sys.argv[1:9]
open(ev,'a',encoding='utf-8').write(json.dumps({
 "ts":int(time.time()),"date":time.strftime("%Y-%m-%d %H:%M:%S"),
 "read":int(rd),"skipped":int(sk),"appended":int(ap),"classes":cl,
 "ledger_delta":int(dl),"kb_delta":int(dk),"skill_delta":int(ds)})+"\n")
PY
  echo "$read_n"
}

# ─────────────────────────────────────────────────────────────────────────────
# 3-4. COUNT + MILESTONE
# ─────────────────────────────────────────────────────────────────────────────
advance_and_notify(){
  local read_n="$1"
  local total; total=$(cat "$COUNT" 2>/dev/null || echo 0)
  total=$(( total + read_n ))
  echo "$total" > "$COUNT"

  local last; last=$(cat "$MILESTONE_FILE" 2>/dev/null || echo 0)
  local reached=$(( total / MILESTONE_EVERY * MILESTONE_EVERY ))
  [ "$reached" -gt "$last" ] && [ "$reached" -gt 0 ] && {
    echo "$reached" > "$MILESTONE_FILE"
    post_digest "$total" "$reached"
  }
  log "count: total=$total (milestone last=$last reached=$reached)"
}

post_digest(){
  local total="$1" reached="$2"
  local stats
  stats=$(python3 - "$EVENTS" "$MILESTONE_EVERY" "$total" "$LEDGER" "$SKILL_MD" <<'PY'
import json,sys,os,collections
ev,milestone,total,ledger,skill=sys.argv[1:6]
milestone=int(milestone); total=int(total)
recs=[json.loads(l) for l in open(ev,encoding='utf-8',errors='replace') if l.strip()]
# the window that produced this milestone
window=[];acc=0
for r in reversed(recs):
    window.append(r); acc+=r.get("read",0)
    if acc>=milestone: break
window=list(reversed(window))
tr=sum(r.get("read",0) for r in window); ta=sum(r.get("appended",0) for r in window)
ts=sum(r.get("skipped",0) for r in window)
c=collections.Counter()
for r in window:
    for x in (r.get("classes") or "").split(","):
        x=x.strip()
        if x: c[x]+=1
top=", ".join(f"{k}×{v}" for k,v in c.most_common(8)) or "n/a"
dl=sum(r.get("ledger_delta",0) for r in window)
def cnt(p):
    try: return sum(1 for l in open(p,encoding='utf-8',errors='replace') if l.strip())
    except Exception: return 0
print(f"reports_read={tr} appended={ta} invalid_skipped={ts} classes={top} "
      f"ledger_lines=+{dl} total_reports_read={total} ledger_now={cnt(ledger)} skill_now={cnt(skill)}")
PY
)
  local rn ap inv cl ln tt lg sk
  rn=$(printf '%s' "$stats" | grep -oE '(^| )reports_read=[0-9]+' | grep -oE '[0-9]+$')
  ap=$(printf '%s' "$stats" | grep -oE 'appended=[0-9]+'          | cut -d= -f2)
  inv=$(printf '%s' "$stats" | grep -oE 'invalid_skipped=[0-9]+'  | cut -d= -f2)
  cl=$(printf '%s' "$stats" | sed -n 's/.*classes=\(.*\) ledger_lines=.*/\1/p')
  ln=$(printf '%s' "$stats" | grep -oE 'ledger_lines=\+[0-9]+'    | cut -d+ -f2)
  tt=$(printf '%s' "$stats" | grep -oE 'total_reports_read=[0-9]+'| cut -d= -f2)
  lg=$(printf '%s' "$stats" | grep -oE 'ledger_now=[0-9]+'        | cut -d= -f2)
  sk=$(printf '%s' "$stats" | grep -oE 'skill_now=[0-9]+'         | cut -d= -f2)

  local msg
  msg="📚 **Skill upgrade milestone — ${reached} reports read**
Cumulative reports read: **${tt}** · this window: **${rn}** valid (${inv} invalid/unreachable skipped)
New technique entries appended: **${ap}** (+${ln} ledger lines)
Classes harvested: ${cl}
Skill files: \`/root/bugbountyhuntingskills.md\` (${lg} lines) · \`/root/Bugbountyskills.md\` (${sk} lines)
Next milestone at $(( reached + MILESTONE_EVERY )). Reader loop continues automatically."
  bash "$ROOT/notch.sh" "$msg" >/dev/null 2>&1 || log "notch: Discord post failed"
  log "milestone: posted Discord digest for $reached"
}

# ─────────────────────────────────────────────────────────────────────────────
# main
# ─────────────────────────────────────────────────────────────────────────────
case "${1:-}" in
  --status) exit 0 ;;
  --batch) shift; BATCH="${1:-6}" ;;
esac

# serialize EVERY pass (harvest, read, or harvest-only) — one writer at a time, always
exec 8>"$STATE/report-reader.pass.lock"
if ! flock -n 8; then log "another pass is already running — exiting"; exit 0; fi

if [ "${1:-}" = "--harvest-only" ]; then harvest; exit 0; fi

harvest
READ=$(read_pass)
advance_and_notify "${READ:-0}"
exit 0
