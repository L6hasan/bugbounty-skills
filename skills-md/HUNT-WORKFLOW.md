# HUNT-WORKFLOW — the case-by-case operating procedure

*Root entry point for any hunting agent. Read this, then run the ONE branch that matches your
current mode. Never read the 47k-line ledgers top-to-bottom.*

**Companions (bind these, do not duplicate them):**
- `/root/hackbot-architecture/SEVERITY_DOCTRINE.md` — what is reportable.
- `/root/HUNT-MODES.md` — the three modes (blackbox / graybox / whitebox), step by step.
- `/root/HUNT-CLASSES.md` — the full vulnerability taxonomy → test → skill route.
- `/root/hackbot-architecture/knowledge/SKILL-CORE.md` — always-inject routing card.
- `/root/hackbot-architecture/knowledge/SKILL-INDEX.md` — line-offset router into the ledgers.
- `/root/state/recon/<slug>/` — per-target state (this is the source of truth, not chat memory).

---

## 0. The contract (10 seconds)

1. **Scope gate first.** No packet leaves until the host is in the program's in-scope list.
   Write `/root/state/recon/<slug>/scope.txt` before anything else. Unsure → stop, ask once.
2. **Severity floor.** Report HIGH/CRITICAL only. Everything else is chain material.
3. **Evidence or silence.** Nothing is a finding until reproduced twice with your own accounts.
   Never fabricate an endpoint, response, or result.
4. **Non-destructive.** No DoS, no brute force, no mass mail, no writes to other users' data.
   Execution proof is read-only (`id`, `hostname`, `sleep 5`, unique OOB token).
5. **One hypothesis per pass.** Exhaust it (bypass → escalate → chain) before switching.
6. **Write to disk every pass.** State that lives only in context is lost and will be re-tested.

---

## 1. Pick your mode (case by case)

The single biggest failure is applying blackbox technique to a whitebox target, or vice versa.
Classify FIRST — it changes the entry point, the budget split, and the tooling.

```
IF you have only a URL ............................. BLACKBOX   -> HUNT-MODES.md §B
IF you have credentials (any role) ................. GRAYBOX    -> HUNT-MODES.md §G
IF you have source / binary / repo / .git / APK .... WHITEBOX   -> HUNT-MODES.md §W
IF you have creds AND source ....................... GRAYBOX, then WHITEBOX to confirm by code
```

Mode is per-asset, not per-program. A program with three hosts can be GRAYBOX on one and
BLACKBOX on another. Record the mode per host in `state.md`.

| Mode | What you may assume | Time split | First action |
|---|---|---|---|
| BLACKBOX | nothing; only what the wire shows | 60% recon-surfacing, 40% hunting | fingerprint → surface map → sensitive-surface triage |
| GRAYBOX | you are a real user; two roles available | 20% recon, 80% hunting | log in as BOTH roles, diff every response |
| WHITEBOX | code is the map; runtime confirms it | 60% code read, 30% hunt, 10% runtime proof | grep sinks → trace to route → test at runtime |

**The GRAYBOX rule that wins most bounties:** one account proves nothing. Every object test
needs an *own-object baseline* and a *cross-principal probe*. Without the baseline you cannot
tell "404 because forbidden" from "404 because wrong id".

---

## 2. The loop (deterministic, one pass = one artifact)

```
 RESEARCH ──► RECON ──► SURFACE ──► TRIAGE ──► HUNT ──► DIG ──► BLOCKED? ──► BYPASS ──┐
    ▲                                                                        │          │
    │                                                    no ◄────────────────┘          │
    │                                                    │                             │
    └────────── LEARN ◄── REPORT ◄── VERIFY ◄── CHAIN ◄── ESCALATE ◄───────────────────┘
```

| State | Goal | Exit criterion | Artifact written |
|---|---|---|---|
| RESEARCH | 3 usable attack-pattern cards mapped to this target | 3 cards with source URL + date | `research/cards.md` |
| RECON | enumerate every host, path, JS bundle, param, header | surface map complete for in-scope hosts | `surface/*`, `surface.md` |
| SURFACE | rank the sensitive surface (auth, admin, upload, export, internal API) | ranked list ≤ 20 entries | `surface.md` §ranked |
| TRIAGE | pick ONE endpoint + ONE class | hypothesis written as a testable sentence | `state.md` |
| HUNT | run the minimal test for that class | confirmed lead or clean negative | `leads.jsonl` |
| DIG | go deep: siblings, roles, tenants, verbs, versions | exhausted or 20 min | `leads.jsonl` |
| BYPASS | defeat the control that stopped you | 5 attempts or 20 min | `bypass.md` |
| ESCALATE | raise impact via role/tenant/sibling/verb | a higher-impact lead | `leads.jsonl` |
| CHAIN | combine leads into one end-to-end story | demonstrable impact | `chains.jsonl` |
| VERIFY | reproduce twice, with negative controls | request+response pair, both roles | `findings/<id>.md` |
| REPORT | 10-minute repro, severity justified | PDF + delivery | `reports/` |
| LEARN | write the non-obvious detail back | skill file updated | `LESSONS.md` |

**Never skip VERIFY. Never report from HUNT. BLOCKED is normal — it is a routing signal, not a
dead end.**

---

## 3. RECON — read the target properly (the part most hunters skip)

Do these in order. Each line is a concrete action, not a concept.

### 3.1 Source & bundle reads (highest yield per minute)
```
# HTML → every asset the app actually loads
curl -sS "$U" | grep -oE 'src="[^"]+"|href="[^"]+"'
# JS → route table, API prefixes, param names, feature flags
curl -sS "$U/main.<hash>.js" -o main.js
grep -oE '"/[A-Za-z0-9_.:/-]{3,60}"' main.js | sort -u      # literal paths
grep -oE 'https?://[A-Za-z0-9_.:/-]+' main.js | sort -u    # cross-host APIs
grep -oiE '(rest|api|graphql|rpc|internal)[-_a-z0-9/]*' main.js | sort -u
# source maps — often the entire original source tree
curl -sSI "$U/main.<hash>.js.map"; curl -sS "$U/main.<hash>.js.map" -o main.js.map
```
Also: `zone-config.js`, `polyfills.js`, `remoteEntry.js` (micro-frontend), `assets/config.json`,
`env.js`, `runtime.js`. Micro-frontend `remoteEntry.js` leak is the cheapest way to get the whole
module + chunk map: it contains `e.u()` (chunk hash table) and `e.p` (base path).

### 3.2 Hidden files, dirs, paths
```
for p in .git/HEAD .svn/entries .env .env.bak config.json config.js \
         robots.txt sitemap.xml swagger.json openapi.json api-docs \
         actuator/ actuator/env actuator/heapdump WEB-INF/web.xml \
         .DS_Store backup.zip dump.sql phpinfo.php server-status; do
  printf '%-24s ' "$p"; curl -sS -o /dev/null -w '%{http_code} %{size_download}\n' "$U/$p"
done
ffuf -u "$U/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt \
     -mc 200,204,301,302,401,403 -fs 0 -t 20
```
A `401` is a **finding surface**, not a miss: it means the route exists. Log 401/403 paths as
authenticated-test candidates.

### 3.3 Endpoint & parameter map
```
katana -u "$U" -jc -d 3 -o urls.txt          # crawled + JS-extracted URLs
gau "$HOST" | tee -a urls.txt                 # historical
waybackurls "$HOST" | tee -a urls.txt
sort -u urls.txt | grep -E '\?|=' > with_params.txt
arjun -u "$U/path" -m GET,POST                # hidden params
```
Then dedupe by *path shape* (`/runs/collate?id=55` → `POST /runs/collate {id}`), not by string.

### 3.4 Fingerprinting → version → CVE
```
httpx -u "$U" -td -title -status-code -web-server -tech-detect
whatweb -a 3 "$U"
```
Record: server, framework + version, WAF/CDN, auth stack (SSO product), session cookie names.
**Version is not a finding — it is a lookup key.** Map to an advisory, then prove exploitability.

### 3.5 Hosts / IPs / ports
```
subfinder -d "$DOMAIN" -silent | dnsx -silent -a -resp
naabu -host "$U" -top-ports 1000 -silent     # in-scope only, rate-limited
httpx -l hosts.txt -sc -title -td -json -o live.jsonl
```
Open port with no exploitable path = not reportable (program rule). Only escalate a port when
you reach a service that yields data or execution.

### 3.6 Header & trust-boundary map
Record and later test every header the app trusts: `X-Forwarded-For`, `X-Forwarded-Host`,
`X-Original-URL`, `X-Rewrite-URL`, `X-User`, `X-Tenant`, `X-Role`, `Authorization`, custom
`X-Xsrf-Header`-style CSRF tokens, `Origin`, `Referer`. Also cookie flags + which cookie is the
real session (`LWSSO_COOKIE_KEY` vs `Login` vs `PcWeb-Login` in SSO stacks — determine which one
the API actually honors by removing them one at a time).

**Output of RECON:** `surface.md` with a ranked table — endpoint, method, auth required, role,
params, why it is sensitive. Ranked by data/action value, not alphabetically.

---

## 4. HUNT — one class per pass, minimal test first

Pick the class from **`HUNT-CLASSES.md`**. For each class the file gives: the observable signal,
the minimal test, the bypass ladder, and the escalation path.

Universal minimal-test discipline:
1. **Baseline** — request with your own object/role. Record status + body size + a body hash.
2. **Probe** — change exactly ONE variable (id, role, tenant, verb, header, encoding).
3. **Diff** — compare against baseline. Same size ≠ same content; hash the body.
4. **Negative control** — no credentials, wrong credentials, and a nonexistent id. This is what
   separates "forbidden" from "not found" from "crashed".
5. **Repeat** — twice, fresh session, to kill flakiness/caching.

**Authorization oracle** (learned the hard way, applies to any product API):
the *kind* of error tells you whether the check exists.
`{"Message":"An internal server error occurred."}` = the handler never reached business logic
(routing/auth/serialization died) — usually **the request shape is wrong**, not a finding.
`<CommonApiException><ErrorCode>5000</ErrorCode>` = the handler ran and rejected the *object*
— that is an **authorization/validation decision**, which is exactly where IDOR lives.
A `204` with an empty body on a mutating route is a **success signal** — always establish what
"success with no body" means before calling it.

---

## 5. DIG → BLOCKED → BYPASS → ESCALATE → CHAIN

**DIG** (20 min cap): sibling ids, other roles' objects, other verbs on same route, v1 vs v2,
trailing slash, case, duplicate params, nested path segments, alternate content types.

**BYPASS ladder** — always in this order, stop at first success:
1. Encoding/normalization: double-encode, unicode, case, trailing dot/slash, `%00`.
2. Parser differential: JSON vs form vs multipart vs XML for the same field.
3. Parameter pollution: duplicate the key (`?id=A&id=B`), array-wrap, object-wrap.
4. Header trust: the header the app trusts instead of the cookie/claim.
5. Version/path drift: `/v1/` vs `/v2/`, `/internal/`, mobile BFF, legacy route.
6. Cache/edge: `X-Original-URL`, path confusion, case-insensitive router.

**ESCALATE** — the four levers, try each explicitly:
- **Role**: lower account does what higher account's UI exposes.
- **Tenant**: swap tenant/org id to a foreign one (in SSO stacks tenant is often a GUID in the URL).
- **Sibling**: same object reachable by a different route lacking the check.
- **Verb/state**: read-only bug becomes write; draft becomes publish; step 1 becomes step 3.

**CHAIN** — the only thing that turns a P4 into money:
`info leak → token/secret → auth bypass → admin → RCE` ·
`IDOR → PII/ATO` · `SSRF → metadata → creds → RCE` · `upload/traversal → RCE` ·
`reflection → stored/admin-context XSS` · `open redirect → OAuth code → ATO` ·
`logic → negative balance / free goods`.

An unproven chain is **silence**, not a draft.

---

## 6. VERIFY — the anti-false-positive gate

A finding needs ALL of:
1. Reproducible request+response pair, written as copy-paste curl, twice.
2. Both roles' evidence: A cannot, B can (or A sees only A's data).
3. A negative control that fails the same way it should.
4. A demonstration that stops at proof — no exfiltration of real user data.
5. A stated impact in the program's own severity vocabulary.

If any is missing → `findings/rejected.md` with the reason, and move on.

---

## 7. REPORT — 10-minute repro

Template: Title · Severity + CVSS · Affected asset · Preconditions · Summary · Steps to reproduce
(numbered curl, exact headers) · Evidence (redacted) · Impact (what data/action is gained) ·
Remediation · References.

**Before the draft, run the drift audit:** list the severities of your last five candidates.
Three or more at P4/P5/informational ⇒ you are drifting ⇒ change asset or class. Never lower
the floor to justify a report.

**Delivery:** confirmed findings → PDF → operator channel (`notify_telegram.py` /
`send_report_pdf.sh`). Candidates and status pings are never sent.

---

## 8. LEARN — write it back or it did not happen

Every pass appends to `/root/Myskill/LESSONS.md`:
```
## YYYY-MM-DD — <own-report / triage-response / disclosed / conversation>
- Lesson: <the non-obvious detail — what actually made it work or fail>
- Class: <bug class> -> skill: <skill-dir>
- Change: <new variant / false-positive rule / detect step> @ <file>
- Repeat signal: <is this a pattern?>
```
Then write the change into the matching technique skill **in the same pass**. A lesson logged but
not written back is not learned.

---

## 9. Reporting-ratio discipline (program-specific)

Some programs pay a descending rate for duplicate/similar issues (100/100/75/50/25/0). Practical
consequence, and it is not optional:
- **Do not burn your first slots on the obvious.** The first report of a class is worth 4× the
  fifth. Spend the budget finding the *variant* nobody filed, not the textbook reflected XSS.
- Prefer **chains over singletons**, and **stateful over stateless** (a stored/admin-context bug
  outranks ten reflected ones).
- Check the program's non-qualifying list *before* testing a class, not after spending an hour on
  it. A disqualifying class is not a finding even if exploitable.
