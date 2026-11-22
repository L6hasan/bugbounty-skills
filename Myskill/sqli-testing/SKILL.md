---
name: sqli-testing
description: Deep playbook for SQL injection and NoSQL injection bug bounty testing: 15 variants covering error-based schema extraction, union data retrieval, boolean/time blind inference, OOB DNS exfiltration, stacked queries, second-order pipelines, JSON/XML/GraphQL parametric injection, ORDER BY/GROUP BY structural manipulation, DB-specific command execution, WAF comment/whitespace bypass, polyglot delay evasion, NoSQLi operator substitution, truncation injection, and second-order blind char-by-char extraction. Use this skill whenever the user is doing authorized security testing and mentions SQLi, NoSQLi, injection payloads, sqlmap, blind injection, time-based or boolean-based oracles, union-based, error-based, DNSlog/OOB exfiltration, stacked queries, second-order SQLi, INFILE/xp_cmdshell/COPY PROGRAM, ORDER BY probing, WAF bypass for injection, or truncation-based injection; asks how to test a parameter for injection, wants payloads or request templates for a DBMS, needs to confirm or triage an injection finding, or is writing a report for an injection bug. Also use it when analyzing a request/response pair or code snippet for SQL/NoSQL query construction weaknesses.
---

# sqli-testing: SQLi & NoSQLi Deep Playbook

## 1. Scope & authorization guardrail

Only test targets you are authorized to test: a published bug bounty program with the
asset in scope, a client-engagement target, or your own lab/CTF. Refuse out-of-scope
hosts, third-party assets you have no permission for, and any request to run payloads
against someone else's production system. When in doubt, ask for the program URL or
scope statement before touching a target.

Two rules that are not negotiable:

- **Never run destructive queries** — no `DROP`, `DELETE`, `UPDATE`, `INSERT`,
  `TRUNCATE`, `ALTER`, or schema-mutating statements — against third-party targets.
  Never run DoS-style payloads (heavy cartesian joins, `REPEAT('a',100000000)`,
  recursive CTE bombs, thousands of stacked statements, `pg_sleep` in a loop). These
  break things, burn the target's resources, and turn a valid finding into a ban.
- **Prove impact with read-only extraction on your own account** or with a boolean /
  timing oracle. A single boolean oracle that flips on `AND 1=1` vs `AND 1=2`, or a
  measured time delta on `AND SLEEP(3)`, is enough to prove the vulnerability; schema
  dumps and file reads are demonstrated against data you are entitled to read (your
  own user's row, test records you created), not the platform's crown jewels.

This skill exists to make authorized testing methodical and to produce reports that
hold up under triage review. Speed comes from picking the right variant early, not
from blasting payloads.

## 2. Engagement workflow

1. **Recon & endpoint inventory.** Map every input-bearing surface before sending
   anything: query strings, POST bodies (form, JSON, XML, GraphQL `variables`),
   path segments, headers (`User-Agent`, `Referer`, `Cookie`, `X-Forwarded-For`),
   file-name parameters, sort/filter fields in AJAX calls, and anything a webhook or
   export feature passes to a reporting database. Use proxy logs (Burp/ZAP), the
   browser network tab, and `ffuf` discovery. *Why:* injection hunting fails most
   often because the injectable parameter was never found — the sink is usually in a
   second-order or admin-facing feature nobody looked at.

2. **Parameter & sink mapping.** For each candidate input, classify what it likely
   becomes: a string literal (`'..'` context — union/error/boolean candidates), an
   identifier (table/column names — structural variants), an integer in a `WHERE` or
   `LIMIT` (boolean/time/truncation candidates), a sort key (variant 9), a document
   filter (NoSQLi, variant 13), or something written to the DB and re-queried later
   (second-order, variants 7 and 15). *Why:* the sink type determines which variant
   can even work; feeding union payloads at an integer `LIMIT` slot wastes your
   time, feeding comments at a JSON body does too.

3. **Variant selection.** Use the routing table in §3 to pick 1-2 variants from the
   observed signal (error message, WAF block page, blind behavior, slow responses).
   Read the matching section in `references/variants-1.md` or `references/variants-2.md`
   before improvising — each has preconditions and false-positive traps.

4. **Safe probe.** Send a benign differential probe, not an exploit: a single quote
   `'` vs `' '` (space-padded), `AND 1=1` vs `AND 1=2`, a `+`-appended comment, or
   `' OR '1'='1'-- ` with `-- ` (note trailing space). Compare responses byte-for-byte
   and by timing. *Why:* you need a signal before you escalate; a probe that only
   "looks weird" is a lead, not a finding.

5. **Confirmation test.** Prove the signal with a second, *independent* mechanism.
   Error message observed → confirm with boolean flip. Blind boolean flips → confirm
   with a measured time delta or OOB callback. A single channel can lie (cache, WAF
   template, rate limiter, locale-specific error page). *Why:* independent
   corroboration is what separates confirmed findings from noise in triage.

6. **Impact proof (read-only).** Extract only what proves impact: your own account's
   row, the fact that `version()` returns a string, one schema table name via a
   boolean oracle, or file read of a file you may access (`/etc/passwd` only if the
   program explicitly allows it — otherwise read a file you own). For DB-specific
   command execution, demonstrate the *capability* (e.g. `xp_cmdshell` returns
   `whoami` of a low-priv service account) without touching other users' data.

7. **False-positive filter.** Rule out: cached responses, WAF/CDN error templates,
   generic 500s from malformed input unrelated to SQL, timing caused by network
   jitter or the target's own load, boolean differences caused by random tokens or
   nonces, and framework behavior that echoes input verbatim. Re-run each probe
   3-5 times; a real oracle is deterministic.

8. **Report.** Write it up with the template in §5 — one request/response pair that
   reproduces, redacted evidence, and a remediation that names the actual root cause
   (parameterized query at line X, missing cast, template-built ORDER BY).

## 3. Variant selection table

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

## 4. Verification standard

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

## 5. Report template

```markdown
# <DBMS> SQL injection in <parameter> leaks <data class> via <variant>

**Severity:** <High/Critical — CVSS vector if the program wants it>
**Endpoint:** `https://<target.example>/<path>` (POST/GET, auth: <cookie/token>)
**Summary:** The `<parameter>` parameter is concatenated into a `<query shape>`
query without parameterization. A `<variant>` payload produces <observable>,
confirming <oracle type>. Proven with read-only extraction of <what you got>.

## Steps to reproduce
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

## Impact
<Who can do this, unauthenticated/authed, what data is readable, what actions are
possible — phrased as a concrete attacker capability, e.g. "any unauthenticated
visitor can extract email and password-hash columns from the users table one
character at a time using a boolean oracle, at ~1 row per N requests.">

## Evidence
<Redacted request/response pairs; hashes or truncated payloads if the program
restricts payload sharing. Show the boolean flip and the confirmation signal.>

## Remediation
<Specific to the variant: parameterized query/prepared statement for the string
concat, allow-list for ORDER BY identifiers, cast to int for LIMIT, remove
CONCAT-built dynamic SQL, disable xp_cmdshell, document-level validation for
NoSQL operators, plus WAF as defense-in-depth not as the fix.>

## References
- CWE-89 (SQL Injection), CWE-943 (NoSQL Injection), CWE-564 (SQL Injection: Hibernate)
- OWASP A03:2021 Injection; OWASP Testing Guide WSTG-INP-* ; PortSwigger <variant> labs
```

## 6. Reference pointers

Read `references/variants-1.md` for variants 1-8 and `references/variants-2.md` for
variants 9-15; each file opens with a table of contents linking every section. Read
`references/payloads.md` when you need request templates, the DBMS payload ladder,
tool commands (sqlmap flag templates, curl/ffuf one-liners), WAF-evasion encoding
tables, header-based vectors, or the "chain it with" cross-skill notes.

The suite cross-references by directory name: injection that yields file/shell
capability chains into `rce-testing`; schema extraction paired with leaked
`.env` credentials chains into `info-disclosure-testing`; authenticated parameter
manipulation chains into `bac-idor-testing`; injection discovered through reflected
input chains into `xss-testing` for context-appropriate escaping review.
