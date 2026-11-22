# SKILL TREE — routing layer for ANY agent
*Entry point for every hunting agent. Read §0 doctrine, then run this tree. Route to the ONE
branch that matches what you observed — never read the skill files top-to-bottom.*

Binding companions:
- `/root/hackbot-architecture/SEVERITY_DOCTRINE.md` — what is reportable (P1/P2/P3 only) and
  the drift audit (§7).
- `/root/bugbountyhuntingskills.md` — the class-indexed technique ledger (§1–§17, append target §17).
- `/root/Bugbountyskills.md` — the consolidated playbook (all technique skills in one file).
- `/root/hackbot-architecture/knowledge/methodologies-<date>.md` — dated intake of new methods.

---

## 1. THE TREE

```
START
│
├─ 0. SCOPE GATE  ─────────────────────────────────────────── cannot be skipped
│    IF  asset is not in the program's in-scope list ............ STOP. Send no request.
│    IF  class is on the HackerOne core-ineligible list ......... CHAIN PRIMITIVE only.
│    IF  you cannot prove impact twice, with your own accounts .. it is a LEAD, not a report.
│    ELSE  continue.
│
├─ 1. ROUTE BY OBSERVATION  ─────────────── pick exactly ONE, then go to its playbook
│    IF  an API path / query / body carries an object id ....... BAC · IDOR · BOLA
│    IF  there is a login, SSO, OAuth, JWT, or session cookie .. AUTH BYPASS · OAUTH · JWT
│    IF  any feature fetches a URL you influence ............... SSRF (incl. cloud metadata)
│    IF  your input is stored or rendered on any page .......... XSS (stored / reflected / DOM)
│    IF  input reaches a database query ........................ SQLi · NoSQLi
│    IF  input reaches a shell, template engine, or deserializer  RCE · SSTI · deserialization
│    IF  a file, path, archive, or export is accepted/served ... LFI · path traversal · file read
│    IF  XML, serialized blobs, or signed cookies are parsed ... XXE · insecure deserialization
│    IF  money, credits, coupons, quota, or a workflow step .... BUSINESS LOGIC
│    IF  source, .git, .env, buckets, or backups are exposed ... SECRET → INFO DISCLOSURE
│    IF  an admin / internal / undocumented route answers ...... ADMIN PANEL · INTERNAL ACCESS
│    ELSE ........................................................ go to RECON, get one of the above
│
├─ 2. BLOCKED?  ─────────────────────────── classify the block FIRST, then act
│    IF  WAF / filter / validation / encoding stopped you ...... BYPASS LADDER (5 tries / 20 min)
│    IF  auth required, role denied, or tenant denied .......... ESCALATE (sibling / higher account)
│    IF  allow-list, rate limit, sandbox, or feature flag ...... change SURFACE, then re-enter at 1
│    IF  bypass failed after 5 attempts or 20 min .............. STOP grinding → CHAIN or change asset
│
├─ 3. PRIMITIVE IN HAND? (P4/P5 — NEVER a report, never queued)  ─── chain it or hold it
│    IF  it reads internal or foreign data .................... chain: read → IDOR → disclosure
│    IF  it redirects anywhere ................................ chain: redirect → OAuth/token theft → ATO
│    IF  it leaks a secret, key, or token ..................... chain: secret → auth bypass → admin → RCE
│    IF  it leaks a version, banner, or stack trace ............ chain: version → known CVE or debug route
│    IF  it reflects input .................................... chain: reflect → stored / admin-context XSS
│    IF  it discloses an error or object model ................ chain: error → backend query → SQLi
│    IF  it lets you upload or write a file ................... chain: write → traversal/serve → RCE
│    ELSE ...................................................... HOLD. Do not draft. Do not queue.
│
└─ 4. FINAL IMPACT GATE  ─────────────── severity is judged at the LAST link of the chain
     IF  chain reaches high/critical (data · action · money · account · host) → VERIFY → REPORT
     IF  chain never reaches high/critical ..................................... drop it in silence
     ALWAYS  before any draft → DRIFT AUDIT (doctrine §7): grade your last 5 candidates;
             3 or more at P4/P5 ⇒ you are drifting ⇒ change asset or class, never lower the floor.
```

---

## 2. CLASS → TEST → PLAYBOOK ROUTING TABLE

| Observed signal | Class to test | Minimal test | Playbook |
|---|---|---|---|
| numeric / GUID id in path, query, or JSON | IDOR / BOLA | own object → swap to A's-other-account object; diff 200 body / status | ledger §3, §11 |
| `?id=`, `?user=`, tenant header, role header | BAC / priv-esc | flip role/tenant header, replay; nested-path matrix | ledger §11 |
| login, signup, password reset, invite | auth bypass | header bypass (`X-User`, `X-Forwarded-*`), path variants, token replay | ledger §11, §12 |
| OAuth `redirect_uri`, `state`, `postMessage` | OAuth bypass | unescaped-dot regex / missing anchor → attacker domain; token in URL | ledger §12 |
| JWT / session cookie | JWT forgery | `alg:none`, default/empty HMAC key, weak secret, `kid` traversal | ledger §11 |
| URL / webhook / image / PDF / import param | SSRF | `127.0.0.1`, `[::ffff:127.0.0.1]`, `2130706433`, NAT64, metadata `169.254.169.254` | ledger §2 |
| reflected / stored user content, admin queue | XSS | write-time vs read-time sanitizer gap; context check at the sink | ledger §1, §12 |
| search, filter, sort, `ORDER BY`-shaped param | SQLi / NoSQLi | error shaping, boolean diff, time delay, second-order via stored value | ledger §7 |
| file upload, import, archive, filename in path | LFI → RCE | traversal in name, symlink, parser/decompression bomb, served-as-code | ledger §8, §13 |
| XML body, SOAP, SVG, Office file upload | XXE | external entity, parameter entity, OOB via collaborator | ledger §13 |
| serialized cookie / viewstate / Java blob | deserialization | signed-vs-unsigned check, gadget probe, OOB DNS | ledger §13 |
| template-rendered input (`{{7*7}}`) | SSTI → RCE | polyglot probe, engine fingerprint, sandbox escape | ledger §13 |
| price, credit, coupon, refund, quota, workflow | business logic | negative value, race, step-skip, currency/rounding, limit reuse | business-logic playbook |
| `.git/HEAD`, `.env`, bucket listing, backup file | source/secret disclosure | validate real objects vs soft-404; redact; chain to auth bypass | ledger §9, §10 |
| admin / internal route answering 200 | admin access | verify data or function, not status; then find the auth-bypass link | ledger §11 |
| version banner / stack trace / error page | chain primitive only | map to a known CVE or a debug route; never report alone | doctrine §2 |
| IDE / page-builder API accepting markup or template content; a `/aspx/`, `/page/`, `/template/` render route | template compile — the create filter is not the render path | literal-token control → same logic with tokens assembled at runtime → overwrite a SIBLING page's template and render it | V-29, ledger §17.788–§17.789 |
| archive import (SCORM/TinCan, plugin ZIP, project restore); errors naming entry names or paths | Zip-Slip → write into a compiled/served path | `../../` AND `..\..\` entry names; verify by reading the artefact back, never from the success flag | V-30, ledger §17.790 |
| config/template text built with `replace("{{…}}", value)`; a spawned tool with hooks/includes/aliases | replacement-token config injection | `$'`/`` $` ``/`$&`/`$1` in the value → read the STORED config for template bytes → trigger the tool | V-31, ledger §17.791 |
| file manager with folder/path parameters; sibling verbs where one validates `../` | containment is per parameter and per verb | traversal in every NON-filename param, laddered; prove by fetching the file from its new location | V-32, ledger §17.792 |
| opaque `fil=`/`where=`/`sort=`/`order` parameter; a query builder exposing `SQL.Eval`/`raw`/`$where` | blind injection with a size/status oracle | control byte size → `1=1` vs `1=2` → LEN/`SUBSTRING` ASCII binary search; privilege probes as boundaries | V-33, ledger §17.793–§17.794 |
| a `url=`/`imgUrl=`/`feedUrl=` param plus a generated-asset serving route | SSRF with store-then-serve exfiltration | internal ladder; fetch the STORED artefact with no cookies; parser error text = port oracle | V-34, ledger §17.795 |
| job/queue payload carrying a type tag; a worker using `respond_to?`/duck typing | deserialization gadget → argv injection | inject `^o`/`!ruby/object:`/`__type`; test the gadget's CLI for `-exec`/`--output=` (not shell metachars) | V-35, ledger §17.796 |

---

## 3. HARD STOPS (any agent, any time)

1. No request to an asset that is not confirmed in scope.
2. Never read, change, or exfiltrate real user data — stop at proof (own accounts).
3. Non-destructive only: no DoS, no mass scanning, no persistence, no real payments.
4. Nothing is reported until it is reproduced twice, end-to-end, with your own accounts.
5. P4/P5/informational never ships as a report — it is escalated into a chain or dropped in silence.
