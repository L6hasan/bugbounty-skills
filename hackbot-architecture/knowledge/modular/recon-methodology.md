# recon-methodology — part 1/1 (61 segment(s))
# content-aware dedupe applied; every unique entry preserved.

## [Bugbountyskills.md] >> bug-hunter — Engagement orchestrator (scope → recon → hunt → validate → report)

*Source: `/root/Myskill/bug-hunter/SKILL.md`*

## [Bugbountyskills.md] Enumeration throttle: rate-limit politely, never hammer

Enumeration is where testers cause outages and get banned — and where scope violations
happen. Rules:

- **Stay far below the limit:** default ≤1 request/second for sweeps, `sleep 1` between
  attempts, and pause on any `429`, `Retry-After`, CAPTCHA, or WAF challenge. Honor
  `Retry-After` exactly; if repeated `5xx` appear, stop and reassess.
- **Small candidate sets:** you are demonstrating a flaw, not dumping a database. 10-50
  IDs (or fewer) is plenty for a statistical claim; **1-2 cross-principal hits are
  sufficient proof** — stop the sweep there.
- **Proof, not corpus:** never collect other users' records "while you're at it". Take
  the minimum redacted sample, then stop. Bulk harvesting turns a legitimate finding into
  your own incident.
- **Check program rules first:** many programs cap scanning rate, forbid DoS-adjacent
  behavior, or restrict testing windows. Those rules override any technique here.
- **Never** run unbounded loops (`while true`, full `1..2^31` integer sweeps, no-delay
  crawlers). Sequential-integer ID spaces make it *tempting*; the feasibility of a
  million requests is not a license to send them.
- Tool rate flags (templates below): ffuf `-rate 1`, sqlmap `--delay=1 --safe-thresh=5`,
  Burp Throttle/`Extensions → Network → rate limiting`. When in doubt, hand-test.

---

## [Bugbountyskills.md] Tool invocations (templates)

```bash

## [Bugbountyskills.md] Header/context flip fuzzing (V-11) — small curated list, not a wordlist dump

for h in 'X-Role: admin' 'X-User-Type: staff' 'X-Tenant: <TENANT_ID_B>'; do
  curl -sS -o /dev/null -w "%{http_code} $h\n" -b jar_a.txt -H "$h" \
    '<TARGET_URL>/api/<FUNCTION>'; sleep 1
done

## [Bugbountyskills.md] Mass-assignment field enumeration (V-04): small candidate list, one field at a time

ffuf -u '<TARGET_URL>/api/profile' -X PUT -b 'session=<SESSION_A>' \
  -H 'Content-Type: application/json' -d '{"FUZZ":1}' -w <ROLE_FIELD_LIST> -rate 1 -mc all

## [Bugbountyskills.md] >> business-logic-testing — payloads.md (request templates, tool commands, evasion)

*Source: `/root/Myskill/business-logic-testing/references/payloads.md`*

## [Bugbountyskills.md] Workflow mapping procedure (map first, then skip/swap)

Run this before any V-02, V-12, or V-14 test. Skipping it is how logic findings die in
triage.

**Phase 1 — record the legitimate flow (clean session, no tampering):**
1. With a fresh account and a fresh object, walk the flow end-to-end in a proxy,
   preserving order: every request, response status, and redirect, in sequence.
2. For each step record: request shape (method/path/params/headers), the object `<ID>`
   it carries, the state **before** and **after** (`status`/`stage` field from a
   cache-busted GET), and any artifact minted (step token, nonce, one-time code).
3. Mark which endpoints are pure reads vs. state mutators, and note async steps (state
   that changes *after* a delay — poll to settle).
4. Note where each rejection is enforced when you *deliberately* try one out-of-order
   call in this phase (edge 403 vs. app 422 vs. silent success) — it tells you which
   layer owns the check for the report's remediation.

**Phase 2 — derive the test classes from the map (never invent them):**

| Test | How to derive from your map | Variant |
|---|---|---|
| **Skip** | Call step N with the map showing precondition N-1 never ran | V-02 |
| **Swap/reorder** | Run N before N-1; or terminal step first | V-02 |
| **Repeat/replay** | Re-run a step the map marks terminal (double-finish) | V-02, V-11 |
| **Context swap** | Change the `<ID>` between two steps while keeping step artifacts | V-12 |
| **Parallel** | Fire two steps the map treats as mutually exclusive | V-03, V-09, V-11 |
| **Rollback** | Push a terminal-state object back to an earlier mapped state | V-02 |
| **Client-gate** | Find what the *client* waits on in Phase 1, fail it, follow-up anyway | V-14 |

**Why an unmapped workflow produces false positives:** without the recorded baseline you
have no expected transition to diff against, so every alternative explanation survives:
(a) a step you "skipped" is genuinely optional — the map would have shown it on every
legit path; (b) `200 {"error":...}` soft-rejections look like a successful skip — Phase 1
recorded what *healthy* responses look like; (c) client-only transitions — your browser
advanced while the server silently reverted (re-read state; poll for async steps before
claiming); (d) you attacked a finalizer endpoint while the real gate lives two requests
later in a path your spider never visited; (e) you tamper with an id that resolves to the
same record (namespace collision — the map pins which `<ID>` each step truly binds).
Claims of workflow bypass must survive a fresh state re-read after queues drain — the map
is what makes that re-read meaningful.

---

## [Bugbountyskills.md] V-04: Administrative interface discovery via URL obfuscation and Unicode path bruteforcing

**Mechanism:** Admin functionality is "hidden" behind obscure or obfuscated paths and
protected by path filters that disagree with the router about what a path *is*. Encoding,
case, Unicode normalization (homoglyphs, NFC/NFD), and edge-rewrite headers make the
filter see `/index` while the router serves `/admin` — security through obscurity plus a
normalization mismatch.

**Preconditions:**
- Some admin/backoffice surface exists (or you suspect it does).
- A candidate wordlist (small, curated) and the encoder table in `payloads.md`.
- Polite rate limits: discovery is a numbers game — stay at ≤1-2 req/s.

**Detect:**
1. Harvest candidates before fuzzing: JS bundles and sourcemaps, response headers,
   comments in HTML, docs (`/swagger`, `/graphql`), common words (`admin`, `backoffice`,
   `manage`, `internal`, `console`, `staff`, `wp-admin`, `actuator`, `debug`).
2. Establish the 404 fingerprint first: request three known-bad paths, note status +
   body length + title. SPA catch-alls return `200` for *everything* — fingerprint the
   body, never the status.
3. Probe each candidate with the variation ladder from `payloads.md`: case, trailing
   slash, `//`, `;`, `/./`, `%20`, double-encoding, then Unicode — Cyrillic `аdmin`,
   fullwidth `ａｄｍｉｎ`, mixed-script, NFC vs NFD of the same string.
4. Edge-vs-app differential: try `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Path`
   headers carrying `/admin` while the request path stays benign — a 200/302-to-login
   where the plain path 404s means a rewriting layer disagrees with the router.
5. Read the differentials: `302 → /login` = route exists; `403` vs `404` = filter vs.
   router disagreement; `200 + app shell` = candidate alive (confirm via step 2).
6. Separate *discovery* from *execution*: hitting an admin login page is a lead; the
   finding is an admin action executing for your low-priv session or no session at all
   (that is V-06-style BAC — chain with `bac-idor-testing`).

**Proof of concept:** (ffuf template; `-rate` keeps you polite)
```bash
ffuf -u '<TARGET_URL>/FUZZ' -w <ADMIN_WORDLIST> -b jar_a.txt \
  -rate 2 -mc 200,302,403,401 -fs <404_BODY_LENGTH>

## [Bugbountyskills.md] Tool invocation templates

```bash

<!-- exact-duplicate entries folded in: 4 -->

## [Bugbountyskills.md] V-11/V-14 header-rule mapping loop (one variable per request)

for o in "null" "https://evil.tld" "https://<TARGET_HOST>.evil.tld" "https://evil.tld/?x=<TARGET_HOST>"; do
  printf '%-45s ' "$o"
  curl -sS -o /dev/null -w '%{http_code}\n' -b '<COOKIE>' -X POST \
    'https://<TARGET_HOST>/<PATH>' -H "Origin: $o" --data '<PARAM>=<VALUE>'
done

## [Bugbountyskills.md] >> info-disclosure-testing — payloads.md (request templates, tool commands, evasion)

*Source: `/root/Myskill/info-disclosure-testing/references/payloads.md`*

## [Bugbountyskills.md] info-disclosure-testing — Payloads, Templates & Tool Invocations (references/payloads.md)

Cross-cutting material for `SKILL.md` and both variant files. Everything here is a
**template**: `<PLACEHOLDER>` slots only, never hardcoded live targets. Keep every
probe read-only — list and read, never modify, upload, or delete (see `SKILL.md` §1).
In this category a 200 status is a *lead*; the body decides the finding.

## [Bugbountyskills.md] 1. Recon path catalog (wordlists with placeholders)

Placeholders: `<BASE>` = origin (`https://<target.example>`), `<NAME>` = a known app or
file name (from HTML/JS/sitemap), `<VER>` = a known version, `<DATE>` = a date window
(`2024`, `20240101`), `<PORT>` = an observed port. Feed these to `ffuf` (§5) — but
inspect **bodies**, not just status codes.

> **Before any subdomain sweep, run a wildcard-DNS control.** Query two gibberish names
> (`zzznonexistentqtest123.<target>`, `nonsuchabc.<target>`). If they resolve, the zone
> publishes `*.target` and *every* name in your brute-force output is a false positive —
> discard the sweep instead of interpreting it. Enumerate with CT SANs instead:
> `https://api.certspotter.com/v1/issuances?domain=<target>&include_subdomains=true&expand=dns_names`
> (no key needed; returns the names that actually have certificates, including internal
> ones like `dev.<target>` with their own wildcard cert). Also check `CNAME`s directly —
> with a wildcard in place, a CNAME is the only DNS record that reveals the true backend
> (a Google/Akamai/Fastly target), whereas a bare `A` answer is just the wildcard.
>
> **And before you accept a WAF/challenge wall as final, map its exemptions.** Verifier
> paths (`/.well-known/**`) and a handful of whole hosts (APIs, collectors, event sinks,
> retired vhosts) routinely bypass bot challenges — those are your real surface. See
> `variants-1.md` V-02 field notes for the calibration method and the challenge-vs-hard-block
> distinction.

| Category | Candidate paths (wordlist) |
|---|---|
| **Git** | `<BASE>/git/HEAD`, `<BASE>/.git/HEAD`, `<BASE>/.git/config`, `<BASE>/.git/index`, `<BASE>/.git/logs/HEAD`, `<BASE>/.gitignore`, `<BASE>/.git/objects/<2>/<38>` |
| **Other VCS** | `<BASE>/.svn/entries`, `<BASE>/.svn/wc.db`, `<BASE>/.hg/hgrc`, `<BASE>/.bzr/`, `<BASE>/CVS/Root`, `<BASE>/WEB-INF/.git/HEAD` |
| **IDE/OS droppings** | `<BASE>/.DS_Store`, `<BASE>/.idea/workspace.xml`, `<BASE>/.vscode/settings.json`, `<BASE>/Thumbs.db`, `<BASE>/.project`, `<BASE>/.svn/*`, `<BASE>/.well-known/security.txt` |
| **Env/config** | `<BASE>/.env`, `<BASE>/.env.local`, `<BASE>/.env.prod`, `<BASE>/.env.production`, `<BASE>/.env.backup`, `<BASE>/.env.bak`, `<BASE>/.env.example`, `<BASE>/config.json`, `<BASE>/config.yml`, `<BASE>/config.yaml`, `<BASE>/config.js`, `<BASE>/settings.py`, `<BASE>/appsettings.json`, `<BASE>/application.yml`, `<BASE>/application.properties`, `<BASE>/web.config`, `<BASE>/parameters.yml`, `<BASE>/docker-compose.yml`, `<BASE>/Dockerfile`, `<BASE>/.dockerenv`, `<BASE>/wp-config.php.bak` |
| **Backup extensions** (append to known names: `<NAME>.php`, `<NAME>.js`, `<NAME>.env`, `index`, `web`, `dump`, `db`) | `<BASE>/<NAME>.bak`, `<BASE>/<NAME>.old`, `<BASE>/<NAME>.orig`, `<BASE>/<NAME>.save`, `<BASE>/<NAME>.swp`, `<BASE>/<NAME>.swo`, `<BASE>/<NAME>~`, `<BASE>/.<NAME>.swp`, `<BASE>/<NAME>.copy`, `<BASE>/<NAME>.tmp`, `<BASE>/<NAME>.1`, `<BASE>/<NAME>.zip`, `<BASE>/<NAME>.tar.gz`, `<BASE>/<NAME>.tar`, `<BASE>/<NAME>.rar`, `<BASE>/<NAME>.sql`, `<BASE>/<NAME>.sql.gz`, `<BASE>/<NAME>.db`, `<BASE>/backup.zip`, `<BASE>/backup.tar.gz`, `<BASE>/www.zip`, `<BASE>/site.tar.gz`, `<BASE>/<DATE>.zip`, `<BASE>/dump.sql.gz` |
| **Sourcemaps** | `<BASE>/<asset>.js.map`, `<BASE>/<asset>.map`, `<BASE>/app.js.map`, `<BASE>/main.js.map`, `<BASE>/bundle.js.map`, `<BASE>/assets/<chunk>.js.map`, `<BASE>/static/js/<chunk>.map`, `<BASE>/<asset-without-hash>.js.map` (strip `.<8hex>` segment), `<BASE>/sourcemap`, `<BASE>/*.js.map` (discovery) |
| **Swagger / OpenAPI / API docs** | `<BASE>/swagger.json`, `<BASE>/swagger-ui.html`, `<BASE>/swagger/index.html`, `<BASE>/swagger/v1/swagger.json`, `<BASE>/openapi.json`, `<BASE>/openapi.yaml`, `<BASE>/api-docs`, `<BASE>/api/docs`, `<BASE>/v2/api-docs`, `<BASE>/v3/api-docs`, `<BASE>/redoc`, `<BASE>/rapidoc`, `<BASE>/api-explorer`, `<BASE>/postman-collection.json`, `<BASE>/postman.json`, `<BASE>/.well-known/openapi`, `<BASE>/actuator`, `<BASE>/actuator/swagger-ui`, `<BASE>/graphql/altair` |
| **GraphQL** | `<BASE>/graphql`, `<BASE>/api/graphql`, `<BASE>/gql`, `<BASE>/graphiql`, `<BASE>/playground`, `<BASE>/v1/graphql`, `<BASE>/query` (probe with `{"query":"{__typename}"}`) |
| **Logs & debug** | `<BASE>/logs/`, `<BASE>/log/`, `<BASE>/log.txt`, `<BASE>/error.log`, `<BASE>/access.log`, `<BASE>/debug.log`, `<BASE>/app.log`, `<BASE>/logs/error.log.1`, `<BASE>/logs/app-<DATE>.gz`, `<BASE>/wp-content/debug.log`, `<BASE>/actuator/logfile`, `<BASE>/actuator/env`, `<BASE>/actuator/health`, `<BASE>/server-status`, `<BASE>/server-info`, `<BASE>/_profiler/`, `<BASE>/telescope/requests`, `<BASE>/phpinfo.php`, `<BASE>/info.php`, `<BASE>/debug/default/view` |
| **Directory indexing probes** (trailing-slash variants) | `<BASE>/uploads/`, `<BASE>/files/`, `<BASE>/media/`, `<BASE>/static/`, `<BASE>/assets/`, `<BASE>/backup/`, `<BASE>/tmp/`, `<BASE>/export/`, `<BASE>/data/`, `<BASE>/images/`, `<BASE>/private/`, `<BASE>/admin/`, `<BASE>/inc/`, `<BASE>/includes/` |
| **Secret-pattern grep** (run over fetched JS/bundles/files, not as URLs) | `AKIA[0-9A-Z]{16}` · `ASIA[0-9A-Z]{16}` · `ghp_[A-Za-z0-9]{36}` · `github_pat_[A-Za-z0-9_]{22,}` · `xox[baprs]-[A-Za-z0-9-]+` · `sk_live_[0-9A-Za-z]{16,}` · `pk_live_[0-9A-Za-z]{16,}` · `AIza[0-9A-Za-z_-]{35}` · `ya29\.[0-9A-Za-z_-]+` · `-----BEGIN (RSA \|EC \|OPENSSH \|PGP )?PRIVATE KEY-----` · `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.` · `(postgres\|mysql\|mongodb\|redis)://[^:]+:[^@]+@` · `(api[_-]?key\|secret\|password\|token\|passwd)\s*[:=]\s*['"][^'"]{8,}['"]` |

Batch ffuf shape (bodies matter — keep `-fs` only after measuring your soft-404 length,
see §2):

```bash
ffuf -u "<BASE>/FUZZ" -w <path-wordlist.txt> -mc all -fc <soft-404-status> \
  -fs <soft-404-length> -t <20-40> -o <out.json> -of json
```

---

## [Bugbountyskills.md] 5. Tool invocation templates & path-probe evasion notes

**ffuf** (path sweep — see §1 for the batch shape): keep `-t` low (20-40) to stay
polite; measure soft-404 baseline first (`ffuf` against a nonsense path) then `-fs`
filter it. `-mc all -fc <status>` so you see everything minus the known-bad.

**git-dumper / GitTools** (V-01, authorized + read-only):
```bash
git-dumper "<BASE>/.git" <output-dir>
git -C <output-dir> log --oneline | head        # history restored — count commits
git -C <output-dir> grep -I -nE '<secret-pattern>' $(git -C <output-dir> rev-list --all) \
  | head                                        # scan history locally; redact hits
```

**GraphQL introspection batch (V-07):**
```bash
curl -sS "<BASE>/graphql" -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind } } }"}'
curl -sS "<BASE>/graphql" -H 'Content-Type: application/json' \
  -d '{"query":"{ __type(name:\"<Type>\") { fields { name type { name kind } } } }"}'
```

**exiftool (V-15):**
```bash
exiftool -a -G1 <downloaded-file>       # full metadata dump; GPS/Author/Company first
```

**Wordlists:** build your own from §1 (placeholders → ffuf `-w`), or fold in a
well-known discovery list and append the §1 custom entries — the leak-specific paths
(`/.env`, `/git/HEAD`, `/*.js.map`) are usually *not* in generic content lists.

**Path-probe evasion notes (WAF blocks on obvious names):**
| Block symptom | Try |
|---|---|
| `/.env` → 403/WAF page | `/.env.` · `/.env%00` · `/.ENV` · `//.env` · `/.;/env` · `/%2e/env` · `/..;/.env` (mix — one at a time, note which class the WAF is keying on) |
| Double-encoding | `/%252e%252e/` style re-encoding of dot/slash when single encoding is normalized |
| Extension filters | trailing junk: `/.env%20` · `/.env%0a` · `/.env/.` · `/.git.bak` (fetch VCS files via backup-name alias) |
| Slash normalization | `\` vs `/` (IIS), `/static../` , semicolon tricks `/x/..;/.env` |
| Hot-name denylist | nest under real dirs: `/<real-subdir>/.env`, `/<real-subdir>/.git/HEAD` (leaks live where the deploy copied them) |

Keep evasion *bounded*: if a WAF blocks `/.env` three ways, that's a hard deny — do not
build a 50-request bypass campaign; note the WAF and move to the next variant. Timebox
evasion to minutes, not hours.

---

## [Bugbountyskills.md] READ-ONLY enumeration — no PUT/POST/DELETE ever

curl -sS "https://<BUCKET>.s3.amazonaws.com/?list-type=2&max-keys=5"   # AWS listing
curl -sS "https://storage.googleapis.com/<BUCKET>/?maxResults=5"       # GCP listing
curl -sSI "https://<BUCKET>.s3.amazonaws.com/<known-object-key>"       # HEAD → 200?
```
Observed: 200 `ListBucketResult` with N keys, or 200 on `<known-key>` — report the
*content class* (`user-exports/*.pdf`, `*.sql.gz`), not the contents.

**Confirm:** Two signals: list **or** object GET returning real (XML/JSON) content —
not HTML — **and** the bucket tied to an in-scope origin (the JS/HTML reference; a
similar-named bucket may belong to someone else — ownership check required).

**False positives:** **403/`AccessDenied` = not a bug** (private — move on); lists of
public website assets/CDN media (public-by-design, often N/A); the target not owning
the bucket (URL lifted from a tutorial); soft-404 HTML from a CDN fronting the bucket
(validate XML); all-public document stores; `lost+found/`-only listings; and any
"confirmation" that involved uploading — that's a scope violation, not proof.

**Impact:** "Anonymous parties enumerate and download <N> objects of class <data:
user uploads / DB dumps / backups / logs>, exposing PII for <population>." Content
decides: PII/credentials/backups → high-critical; public statics → not a bug; write
access only ever described from *inherited* evidence (an existing oddly-named object),
never demonstrated → critical. Recommend Block Public Access + rotation.

**Remediation:** S3 Block Public Access (account + bucket), replace ACLs with
presigned URLs/OAC, remove GCP `allUsers` IAM bindings, and review access logs for
prior abuse.

**CWE / OWASP:** CWE-732 (Incorrect Permission Assignment), CWE-200 — OWASP A01:2021;
CIS AWS S3.1/S3.2.

---

## [Bugbountyskills.md] >> path-traversal-testing — payloads.md (request templates, tool commands, evasion)

*Source: `/root/Myskill/path-traversal-testing/references/payloads.md`*

## [Bugbountyskills.md] --- ffuf: value fuzzing with a traversal wordlist (in-scope target only) ---

ffuf -u 'https://<TARGET>/download?file=FUZZ' \
     -w '<PLACEHOLDER_WORDLIST:traversal-encodings.txt>' \
     -mr '<PLACEHOLDER_CANARY_STRING>' \
     -mc 200,206 -fs '<PLACEHOLDER_BASELINE_LENGTH>' -t 20 -of csv

## [Bugbountyskills.md] Seed wordlists inline (expand per engagement; keep pacing modest):

## [Bugbountyskills.md] V-04: Core system profile access bypass (/etc/passwd or Windows/win.ini isolation mapping)

**Mechanism:** The app isolates files *logically* (per-user folders, jailed
names, "you may only read your own exports") but paths resolve into the shared
OS namespace — `/etc/passwd`, `C:\Windows\win.ini`, neighbor tenant
directories. Nothing at the filesystem layer enforces the logical boundary, so
a traversal step or an absolute path proves isolation exists only in UI text.
"Isolation mapping" is the same flaw in multi-tenant apps: account→directory is
a *path component* (`/data/tenants/<id>/`, `/home/<user>/`), and the client can
re-map which tenant's directory gets opened.

**Preconditions:**
- Traversal/absolute-path reach established (V-01/V-03/V-06)
- Service account can read the target (it usually can for `/etc/passwd`-class)
- No effective jail: no chroot, no `open_basedir`, no read-only container FS
  — or a bypassable one (mis-scoped `open_basedir` is common)
- For tenant mapping: predictable account→path scheme and a read operation
  keyed by that path

**Detect:**
1. Canary first (guardrail): prove namespace escape with `/etc/hostname`
   (Linux) or a public asset — never open with system files.
2. Minimal system signature (second stage, minimal-evidence rule): request
   `/etc/hostname`… then `/etc/passwd` and retain **only** the first line
   (`root:x:0:0:root:/root:/bin/bash`). That signature — not a dump — proves
   OS-namespace read. On Windows, request `C:\Windows\win.ini` and retain only
   the `[fonts]` header. **Do not request `/etc/shadow`, private keys,
   `credentials`, or `.aws/`** — if the traversal pattern implies they resolve,
   state reachability in the report and stop.
3. Nonexistence oracle: same probe against `/etc/notafile-<TOKEN>` — a
   *different* error (ENOENT vs content) proves the signature came from the
   filesystem, not from a fixture.
4. Tenant-mapping probe (entitled proof): fetch **your own** account file
   through the path scheme, then swap in a single adjacent placeholder ID. If
   another account's data returns, you also have broken access control — chain
   `bac-idor-testing`; guardrail: stop at one adjacent placeholder, evidence =
   structural difference with content redacted, never collect other users' data.
5. OS cross-check: `win.ini` failing while `/etc/hostname` succeeds pins the
   target OS and rules out bundled fixture files (repo copies of `/etc/passwd`
   do exist).

**Proof of concept:**
```
GET /export?path=<PLACEHOLDER_CANARY_PATH> HTTP/1.1   # stage 1: canary
GET /export?path=/etc/passwd                           # stage 2: keep line 1 only
GET /export?path=C:\Windows\win.ini                    # Windows: keep [fonts] header only
GET /export?path=/data/tenants/<PLACEHOLDER_OWN_ID>/…  # entitled baseline
GET /export?path=/data/tenants/<ADJACENT_ID>/…         # one probe, redacted evidence
```

**Confirm:** The OS signature line *plus* the nonexistence oracle differential
(ENOENT for `/etc/notafile` vs content for `/etc/passwd`), reproducible twice.
Reflection cannot produce an OS-specific signature with a working oracle.

**False positives:** Honeypot/WAF pages echoing your requested path. Fixture
files bundled with the app (check leaked source — chain `info-disclosure-
testing`; a repo copy of `/etc/passwd` won't pair with a live ENENT oracle for
invented names). Docker images where `/etc/passwd` appears in the app's own
data directory — `/etc/hostname` and `/proc/version` distinguish these.
Plain reflection of the path string in an error page (decode and compare).

**Impact:** Logical isolation doesn't exist at the FS layer: read any file the
service account can read, and (tenant form) read across account boundaries.
Phrase as "file namespace escape as `<user>`; isolation boundary enforced only
at application level; evidence: redacted OS signature". Severity: High/Critical
pre-auth; note the tenant-mapping variant separately as BAC.

**Remediation:** Enforce isolation at the filesystem layer (container
read-only mounts, chroot/`open_basedir` scoped tightly) *and* keep the
canonical-prefix check; for tenants, resolve paths server-side from an internal
record ID — never from a client-supplied path segment.

**CWE / OWASP:** CWE-22 (Path Traversal) + CWE-200 (Info Exposure) / CWE-639
(Authorization Bypass by User-Controlled Key); OWASP A01:2021 Broken Access
Control.

## [Bugbountyskills.md] Param discovery for command/code sinks

ffuf -u 'https://<TARGET>/api/ping?param=FUZZ' -w params.txt -mr 'example' -t 30

## [Bugbountyskills.md] >> sandbox-escape-testing — payloads.md (request templates, tool commands, evasion)

*Source: `/root/Myskill/sandbox-escape-testing/references/payloads.md`*

## [Bugbountyskills.md] 1. Environment fingerprinting ladder

**First determine what sandbox you are actually in** — language, version,
then confinement mechanism. Wrong model → wrong variant → wasted work.

**Layer 0 — runtime + version (benign probes, all read-only):**

| Ecosystem | Benign probe | Expected tell |
|---|---|---|
| Node.js | `process.version`, `process.versions.v8` | `v18.x`, V8 `10.x` |
| vm2 (in lab clone) | `require('vm2/package.json').version` | exact vm2 version for advisories |
| Python | `sys.version` / `platform.python_version()` | `3.x.y` + build tag |
| PHP | `phpversion()`, `PHP_VERSION` | `8.x.y` / `7.x.y` |
| Java | `System.getProperty("java.version")`, `Runtime.version()` | JDK `1.8` / `11` / `17+` |
| Ruby | `RUBY_VERSION`, `RUBY_ENGINE` | `2.7` = $SAFE era; `3.x` = removed |
| Lua | `_VERSION`, `jit and jit.version` | `Lua 5.4`, `LuaJIT 2.1` |
| Go/WASM host | `wasmtime --version` / `wasmer --version` | engine + version |
| Chromium/Electron | `navigator.userAgent`, `process.versions.v8`, `process.versions.electron` | build ↔ bundled V8 mapping |
| Android | `apkanalyzer manifest print <APK>` | min/target SDK, providers |
| Windows | `systeminfo`, `ver` | OS build for RPC/tooling advisories |
| Hypervisor (guest side) | `dmidecode -s system-manufacturer`, `VBoxControl --version` | hypervisor + additions |

**Layer 1 — confinement mechanism (what restricts you):**

| Confinement | Benign probe | Tell |
|---|---|---|
| Node `vm`/vm2 | `typeof process` inside context | `undefined` = confined; visible = misconfig, not escape |
| Python jail | `len(().__class__.__base__.__subclasses__())` | count > 0 = object graph intact |
| PHP restrictions | `ini_get('disable_functions')`, `ini_get('open_basedir')` | the actual denylist |
| Java SecurityManager | `System.getSecurityManager() != null`; denied `File.exists` → `SecurityException` | SM engaged vs absent |
| Ruby `$SAFE` | `$SAFE` value; gated op → `SecurityError` | engaged on <3.0; `NameError` on 3.x |
| Lua sandbox | `type(load)`, `type(string.dump)`, `type(debug)`, `type(ffi)` | `ffi` present = decorative sandbox |
| Container | `id`, `/.dockerenv`, `/proc/self/status` → `CapEff`, `uname -r` | capability + kernel context |
| Kubernetes | `kubectl auth can-i ...`, serviceaccount namespace | RBAC reach |
| eBPF surface | `cat /proc/sys/kernel/unprivileged_bpf_disabled` | `0` = open to unprivileged |
| Windows token | `whoami /priv` | `SeImpersonatePrivilege` etc. |
| WASM | module magic `\0asm`; host API errors | engine vs wrapper layer |
| FaaS reuse | marker write→read across two invocations | warm instance confirmed |
| Hypervisor | virtio/VMware/VBox devices via `lspci`, `/sys/bus/virtio` | exposed guest↔host channels |

All probes return version/config/identity strings — never another user's
data. Record every value: each one feeds §4's advisory match.

## [Bugbountyskills.md] benign fingerprints (one-liners)

node -e 'console.log(process.version)'
python3 -c 'import sys; print(sys.version)'
php -r 'echo phpversion()," | ",ini_get("disable_functions");'

## [Bugbountyskills.md] benign recon (target):

$ uname -r && cat /proc/sys/kernel/unprivileged_bpf_disabled   # → <PLACEHOLDER_KERNEL> / <0|1|2>
$ id                                                            # capability check

## [Bugbountyskills.md] lab only: <PUBLIC_POC_OR_TOOL_FOR_BUILD> → benign proof: `whoami` shows

## [Bugbountyskills.md] guest-side benign fingerprint

dmidecode -s system-manufacturer            # → <PLACEHOLDER_HYPERVISOR>
VBoxControl --version 2>/dev/null || vmware-toolbox-cmd -v 2>/dev/null
ls /sys/bus/virtio/devices | head           # exposed emulated devices

## [Bugbountyskills.md] 3. Tool invocation templates

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

## [Bugbountyskills.md] B-3. Scanner failure modes (proven by server-side coverage data) → what you must do by hand

Each item below was diagnosed by Xdebug traces — *which lines the server actually ran* —
not speculation. They are the standard reasons a "clean" scan is wrong:

1. **Stop-after-first-param.** Default fuzzers stop testing a form after the first
   confirmed injectable param. `login.php` had BOTH `username` and `password` vulnerable;
   plain sqlmap found only one — the fix is `--answers=keep testing=Y`. **Rule: never
   stop at the first hit — enumerate every param in the same request and test each to
   completion.** (Also your false-negative rule when reviewing tool output.)
2. **JS-generated param names.** The vulnerable `js` param existed in the DOM only after
   a button click; scanners that never fired the event never learned the name and never
   sent it (coverage: the DB lines never executed). **Rule: click/hover/expand every
   interactive element, diff the DOM before/after, and fuzz params that appear late.**
3. **Auth-gated content needs registration AND a re-crawl.** sqlmap/Arachni never
   completed signup → never reached `search.php`. ZAP out-crawled Blackmap on one page
   *because* it looped back to `register.php` after login — the authenticated state
   renders different pages/forms. **Rule: register where the program allows, log in,
   re-crawl the same entry points, compare pre/post-auth link and DOM sets.**
4. **iframe-embedded content.** Three of four WSPortal vulns (three previously unknown)
   sat behind HTML/HTTP iframes; three of four mainstream crawlers don't traverse them →
   they never discovered `content.php?page=1` at all. **Rule: enumerate
   `<iframe>`/`<frame>`/`<object>`/`<embed>`/`srcdoc` sources as first-class endpoints.**
5. **Hidden params ride real POST bodies.** `editadmin.php`'s vulnerable `username` was
   not a visible form field but was in the actual POST. **Rule: capture *actual* requests
   from proxy/devtools; never reconstruct bodies from the DOM.**
6. **Inter-state dependencies.** Creating an object on page A generated the link that
   carries the injectable param on page B (`addpage.php` → `content.php?page=1`).
   **Rule: after any create/update action, re-enumerate other pages for newly appeared
   links and params** — the same instinct as second-order discovery (B-1.8).
7. **Crawler loops starve coverage.** Arachni spent >90% of requests on one calendar
   page — enough to have hidden the login vulnerability entirely. **Rule: dedup + a
   per-page request budget; if one path dominates your own logs, cut it off.**
8. **Coverage ≠ detection.** ZAP reached the vulnerable code and still didn't flag it —
   a fuzzer weakness, not a crawling one. **Rule: after a good crawl, manually
   spot-probe the 5-10 highest-value params (login, search, id, sort, export) before
   trusting any tool's "clean".**

## [Bugbountyskills.md] HTTP callback logger with header/UA logging (fingerprint the fetcher)

python3 -m http.server 8000               # basic; a custom logger is better

## [Bugbountyskills.md] Param discovery for URL-fetch sinks

ffuf -u 'https://<TARGET>/api/fetch?param=FUZZ' -w params.txt -mr 'example' -t 30

## [Bugbountyskills.md] Callback listener during labs (logs source IP + UA = fetcher fingerprint)

nc -lvnp 9999

## [Bugbountyskills.md] Timing-differential port mapping (in-scope only, slow pacing, 2 samples + control)

curl -s -o /dev/null -w '%{time_total}\n' --max-time 5 http://<INTERNAL_HOST>:<PORT>/
```

## [Bugbountyskills.md] 5. Tool command templates

All commands are templates — substitute placeholders, confirm scope first.

```bash

## [Bugbountyskills.md] >> infra-fingerprinting — Website fundamentals: fingerprint the stack, route the bug class (client-side + server-side)

*Source: added to `Bugbountyskills.md` 2026-10-30 (operator request). Companion dataset
`comprehensive_infrastructure_recon_map.pdf` (30 infrastructure components / 600+
sub-technologies) is NOT present on this host — see §8 INGEST POINT. Until that table is
pasted and source-verified, treat it as `unknown`, never as loaded knowledge.*

## [Bugbountyskills.md] Infra Fingerprinting — Website Fundamentals Playbook

A fingerprint is not trivia: every component you identify tells you *which trust decisions
the browser is making on the server's behalf* (client side) and *which sinks, stores, and
version-shaped defects are actually in play* (server side). This skill is the routing layer
between "what is this site made of" and the ten technique skills that exploit it. It does
not exploit anything itself — it converts stack observation into a prioritized test plan
and it is where logic-bypass hypotheses come from.

## [Bugbountyskills.md] 8. INGEST POINT — infrastructure recon map (pending data)

The companion dataset `comprehensive_infrastructure_recon_map.pdf` — 30 infrastructure
components / 600+ sub-technologies, intended as the instant-recognition knowledge graph
for fingerprints (runtimes, protocols, version footprints → RCE vectors) — **was not
present on this host when this skill was written** (searched: `/home/krhasan` absent;
filesystem-wide `find` for `*infrastructure_recon*`, `*recon_map*`, `*comprehensive_infra*`
→ no match). Do not invent its contents.

When the operator provides it, paste the table here in this shape:

```markdown
<!-- INFRA-RECON-MAP INGEST POINT — fill from comprehensive_infrastructure_recon_map.pdf -->
| # | Component (30) | Sub-technologies (600+) | Version footprint / tell | Bug-class mapping (§6) | Verified? |
|---|---|---|---|---|---|
| 1 | e.g. reverse proxy: nginx | alias, dav, ssi, status, stub_status | `Server:`, 400 on raw `../` | path-traversal, info-disclosure | verify-before-claim |
```

Ingestion rules: (1) copy, don't paraphrase version numbers; (2) every row gets `Verified?`
= `verified (evidence)` or `guess` — same discipline as §7; (3) rows that duplicate §3/§4
stay only if they add version→CVE precision; (4) after ingest, this section shrinks to the
table and the provenance line.

## [Bugbountyskills.md] 9. Report template (fingerprint-derived findings)

```markdown

### [Bugbountyskills.md] Recon

1. Go wide before you go deep
2. Map the entire attack surface
3. Asset discovery and fingerprinting
4. Technology fingerprinting

### [Bugbountyskills.md] W-B. Recon tradecraft

- **Passive-first for scale AND stealth [W-16]:** active scanners (masscan/naabu) are
  noisy, disclose your IP, and get you blocked by firewalls/IDS; cert/OSINT sources cover
  most hosts at zero contact. Use active scans on shortlists after passive exhaustion.
- **Certificate pivoting finds assets DNS doesn't [W-11][W-16]:** Censys — pivot from a
  target cert to all hosts presenting it (**explicit origin-IP-behind-CDN goal**);
  crt.sh — search the **Organization** field (surfaces unrelated-looking domains) and the
  **SAN** field (a sibling domain's cert revealed assets absent from the main cert).
  Shodan: `hostname:"x.com"`, `http.title:"Swagger UI"`, `"JHipster" port:8080`,
  `filter: ssl.cert.subject.c: target` [W-14][W-16].
- **Historical relations beat current DNS [W-1]:** VirusTotal domain relations surfaced
  `admin.` and `admin-staging.` subdomains; Wayback + GitHub for leaked keys.
- **Wildcard-DNS triage [W-1]:** non-existent hostnames returning `ANSWER: 1` with real
  IPs = wildcard DNS — standard tooling inflates FP subdomains here. Don't just dismiss:
  connect it to the app's features (their instructor-per-tenant-subdomain feature turned
  the wildcard into a cross-tenant vector).
- **Google dorks for leaked docs/logs [W-11]:**
  `inurl:target not for distribution | confidential | "employee only" | proprietary | internal filetype:pdf` and the same with `filetype:log` (+ `WS_FTP | log`).
- **Fingerprint verification rule [W-11]:** Wappalyzer/BuiltWith/WhatRuns/URLscan
  extensions produce **false positives** — pull JS/CSS from page source and confirm
  versions manually before reporting anything version-shaped (matches infra-fingerprinting
  §7 two-signal rule). Match versions to Vulners/snyk; report "Vulnerable Dependency" vs
  "Outdated version" as different impact tiers.
- **Origin exposure check [W-1]:** if the edge isn't CF-fronted (or you found the origin),
  direct port scanning of the origin IP is fair game in scope — found SSH + admin panel
  on a non-standard port that way.
- **Passive tools to keep in the loop [W-16]:** Shodan + Censys + Fofa + ZoomEye + Onyphe
  have different port-range coverage — run them in parallel with Amass/crt.sh/dnsdumpster.

### [Bugbountyskills.md] W-C. Content discovery & inventory

- **Spider and dir brute-force run simultaneously [W-7]:** Burp spider + Dirb in parallel
  "to make sure no directories were missed" — they find disjoint sets.
- **Custom 100-150 wordlist where any HTTP 200 = automatic disclosure [W-16]:**
  `/config.json`, `/.git`, `/web.config`, `/server-status`, `/backup.zip`, `/.DS_Store`,
  `/v2/_catalog`. Small and curated beats huge and generic for leak-hunting.
- **Mine everything for identities [W-13]:** docs, Git/Pastebin leaks, JS files, and
  "contact us" pages yield usernames/dev emails → fuel for enumeration and password
  attacks.
- **Hidden params live in real traffic, not the DOM [W-1][W-5]:** capture actual
  requests; Supabase-style BaaS auto-generates a REST endpoint **per table** — enumerate
  `/rest/v1/<table>` with the public anon key harvested from the client [W-5].

## [Bugbountyskills.md] Scanner: Subzy (or target tool)

<!-- exact-duplicate entries folded in: 1 -->

## [Bugbountyskills.md] Recon tools

go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/gau@latest
go install github.com/tomnomnom/waybackurls@latest

## [Bugbountyskills.md] Other tools (available in environment)

## [Bugbountyskills.md] Discovery: returns closest snapshot URL + timestamp as JSON

curl -sL "https://archive.org/wayback/available?url={URL}"

### [Bugbountyskills.md] 3. Information Disclosure & Asset Mapping

Extracting debug endpoints, verbose error traces, or sensitive metadata using structured requests.

**Probing Common Sensitive Endpoints**
Extract environment variables, heap dumps, or API documentation left exposed in production:

```bash

## [Bugbountyskills.md] Tooling Quick Reference

| Tool           | Purpose                     | Key Command                                        |
| -------------- | --------------------------- | -------------------------------------------------- |
| Burp Suite     | Proxy + scanner             | Intruder, Repeater, Collaborator                   |
| Nuclei         | Template vuln scanning      | nuclei -u URL -severity critical,high            |
| ffuf           | Fuzzing                     | ffuf -u URL/FUZZ -w wordlist -mc all -fc 404 -ac |
| sqlmap         | SQLi exploitation           | sqlmap -u URL --batch --risk 3 --level 5         |
| subfinder      | Subdomain enum              | subfinder -d target.com -all -silent             |
| httpx          | HTTP probing                | httpx -l hosts.txt -status-code -title           |
| Nmap           | Port scanning               | nmap -sV -sC -p- target.com                      |
| dalfox         | XSS scanning                | dalfox url URL                                   |
| Interactsh     | OOB interaction             | Alternative to Burp Collaborator                   |
| jwt_tool       | JWT attacks                 | jwt_tool TOKEN -M at                             |
| truffleHog     | Secret scanning             | truffleHog --regex --entropy=True                |

> All tools are also orchestrated by `/home/siam/Agentic-Bug-Hunter/tools/` (recon_engine.sh, hunt.py, vuln_scanner.sh, validate.py, scope_checker.py, lead_board.py, token_scanner.py, etc.) — when in doubt, call the script by absolute path instead of hand-rolling the step.

## [Bugbountyskills.md] 🎯 Vulnerability → Tool to Use (Full Map)

Every vuln class in the skill → the exact tool on the VPS that hunts it. Run tools in this order: recon → surface → hunt → validate.

| Vulnerability | Primary Tool(s) | Key Command / Flag |
| --- | --- | --- |
| **Recon / attack surface** | `subfinder`, `amass`, `assetfinder`, `httpx`, `katana`, `gau`, `waybackurls`, `whatweb` | `subfinder -d target.com -all` → `httpx -l hosts.txt -sc -title` → `katana -u https://target.com -jc` → `whatweb https://target.com` |
| **Subdomain takeover** | `subzy`, `dnstake`, `dnsx`, `dnsrecon`, `puredns`, `nuclei` (takeover templates) | `subzy run --target target.com` → `dnstake -d target.com` → `dnstake -d 2> /dev/null \| nuclei -t http/takeovers/` |
| **DNS zone takeover** | `dnsrecon`, `dnsx`, `digit`, `rndc`/`dig` manual, `nuclei` (dns templates) | `dnsrecon -d target.com -t axfr` (zone transfer) → check unclaimed NS/AXFR |
| **Port scanning (L3/L4)** | `nmap`, `masscan`, `naabu` | `nmap -sV -sC -p- target` · `masscan -p- --rate 1000` · `naabu -host target.com -p -` |
| **Web content discovery / dir fuzz** | `ffuf`, `feroxbuster`, `gobuster` | `ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt -mc all -fc 404` · `feroxbuster -u https://target.com -w ~/wordlist -d 3` · `gobuster dir -u https://target.com -w $wl` |
| **Admin panel / hidden endpoints** | `gobuster`, `katana`, `ffuf`, `arjun` (params) | `gobuster dir -u https://target.com -w admin_wordlist -x php,html` → `arjun -u https://target.com/api/ -m GET,POST` |
| **XSS (reflected/DOM/stored)** | `dalfox`, `xsstrike`, `httpx`+`katana` (harvest URLs), `nuclei` (exposures) | `dalfox url https://target.com/?q=FUZZ` · `xsstrike -u "URL?p=x" --lvl 3` → mirror + verify manually |
| **SQLi (time/union/boolean)** | `sqlmap`, `ghauri` | `sqlmap -u "https://target.com/page?id=1" --batch --risk 3 --level 5 --dbs` (ghauri as backup) |
| **NoSQLi (Mongo/Redis)** | `sqlmap` (nosql modules), manual payloads, `woothee`/insomnia | inject `$ne`, `$gt` in JSON bodies; verify truthy/error deltas |
| **SSRF (incl. blind)** | `interactsh-client`, `nuclei`, `katana` (url params) | `interactsh-client -v` → inject OOB URL into `url=/image=webhook=` params → check callback |
| **XXE** | `nuclei` (xxe templates), `Burp Repeater`, `interactsh-client` (blind OOB) | inject external DTD → `interactsh-client` for blind exfil |
| **SSTI/CSTI** | `ffuf`+manual payloads, `nuclei` (ssti templates) | test `{{7*7}}`, `${7*7}`, `<%=7*7%>`; verify arithmetic output |
| **RCE / Command Injection** | `nuclei` (rce/cmdi templates), `ffuf` fuzz params, manual | blind: `;sleep 5` / OOB `--dnslog`; in-band: `;id` then `nc -lvp`/`netcat` reverse shell |
| **CRLF Injection / Response Splitting** | `httpx`, `curl` + `nuclei` (crlf templates) | `curl -i -H "Host: target.com%0d%0aSet-Cookie: x=1"` → check header echo |
| **Open Redirect** | `httpx`, `nuclei` (redirect templates), `katana` (param harvest) | grep `redirect=/url=/next=/return=` params → inject `//evil.com` → follow Location |
| **CSRF** | `Burp Repeater`, manual, `nuclei` | test missing token/referer on state-changing POSTs |
| **IDOR / BOLA** | `burp`, `curl`, `httpx` (mass fetch) | enumerate `id=` objects across users → manual vertical/horizontal diff |
| **PrivEsc / RBAC / Improper Auth** | manual + `jwt_tool`, `nuclei` (auth templates) | replay admin endpoints as low-priv user; tamper JWT |
| **JWT attacks** | `jwt_tool` | `jwt_tool <token> -M at` (alg confusion) · `-T` tamper · `-S hs256 -p <secret_guess>` |
| **OAuth / SSO / SAML / Password reset / Login** | `Burp Repeater`, `nuclei`, `curl`, `jwt_tool` | flow-level manual; verify redirect_uri, state, 2FA/OTP logic |
| **LFI / RFI / Path traversal** | `ffuf`, `nuclei` (lfi templates), `curl` | `ffuf -u https://target.com/file=FUZZ -w traversal_payloads -mc all` → check `../../../etc/passwd` |
| **Arbitrary file upload** | `ffuf`/`burp`, `curl` | extension bypass `.php.jpg`, content-type spoof, `magic bytes`; `searchsploit` for CMS/websshell gadgets |
| **Insecure Deserialization** | `searchsploit`, `nuclei`, manual gadget chains | `searchsploit "java deserialization"` → ysoserial/phpggc payloads |
| **HTTP Request Smuggling** | `Burp Repeater` (smuggling), `nuclei` (smuggling templates) | CL.TE / TE.CL probe: send crafted dual requests |
| **Prototype Pollution** | manual + `nuclei` (pp templates) | inject `{"__proto__":{"polluted":"x"}}` in JSON POST → check echoes |
| **GraphQL introspection/query** | `curl`, `katana`, `nuclei` (graphql templates) | POST `{"query":"{__schema{types{name}}}"}` → alias batching IDOR |
| **Hardcoded secrets** | `trufflehog`, `gau`+`katana` (JS/sourcemaps) | `trufflehog filesystem --path . -j` · `gau target.com \| grep -E '\.js' \| trufflehog` |
| **WAF fingerprint** | `wafw00f` | `wafw00f https://target.com` → choose bypass strategy |
| **TLS/SSL misconfig** | `testssl`, `nmap --script ssl*` | `testssl.sh https://target.com` · `nmap --script ssl-enum-ciphers -p 443` |
| **Exploit research** | `searchsploit`, `nuclei` (cve templates) | `searchsploit <product> <version>` → `nuclei -u https://target.com -t cves/` |
| **General passive vuln scan** | `nuclei` (full template pack) | `nuclei -u https://target.com -severity critical,high -stats` |
| **OOB callback / data exfil** | `interactsh-client`, `nc` | `interactsh-client` for blind SSRF/XSS/SQLi/XXE → `nc -lvnp 4444` for reverse shells |

> Tool order of battle: **recon** (subfinder/amass/assetfinder/httpx/katana/gau) → **surface** (naabu/nmap + ffuf/gobuster/feroxbuster + arjun) → **hunt** (nuclei + class-specific tools above) → **validate** (manual/Burp + interactsh OOB) → **report**.

## [Bugbountyskills.md] Discovery chain

1. `common.txt` ffuf at web root → `.gitignore` (200), `/themes` (301→403), `server-status` (403).
2. `.gitignore` body (200, 3954b) lists: `/log/ /config/ /metadata/ /cert/ /envvars/
   /www/assets/…` (+ `!/*/.gitkeep` whitelists).
3. Root probes: `/envvars` → 301 → `/envvars/` → 403; `/log /config /metadata /cert
   /cache /locales /www` → all 404 (and their `.gitkeep` → 404).
4. `/envvars/zzq_nonexistent_987` → 404 ⇒ directory real, children resolvable ⇒ filename fuzz.
5. 988-name env list (env × {.env,.php,.txt,.json,.yml,.yaml,.ini,.conf,.bak,.inc,.local,.dist,''})
   → **`global.php` 200/0**. 875-name generic+BGP list → same single hit.
6. Dotfile pass (`.env.php`, `.database.php`, `.secrets.php`, `.config.bak`, …) → only
   **`.config.php` 200/0** (found by root `common.txt` × `.php`).
7. Backup/source probes for both files → 404 everywhere (`*.phps` = generic 403 rule,
   control: random `.phps` also 403).

## [Bugbountyskills.md] Account existence enumeration via unauthenticated `checkEmail` oracle

**Severity:** Low–Medium (CVSS 5.3 base: `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) — adjust to the
program's own grid; the asset is valued "High" so a Low-CVSS finding sits at the €50 tier.
**Status:** Confirmed (2026-10-24). Positive branch (`exists:true`) inferred from client code,
not yet observed live — see *Open* below.
**Class:** Broken access control / business logic → `business-logic-testing` (primary),
`bac-idor-testing` (cross-account data exposure).
**CWE / OWASP:** CWE-204 (Observable Response Discrepancy), CWE-203 (Observable Discrepancy) —
OWASP A07:2021 Identification and Authentication Failures. WSTG-ATHN-08.

## [Bugbountyskills.md] Recons done (don't redo)

- Source-level: `application.js` (1.14 MB) + `application.js.map` (168 KB, **publicly served**)
  decompose the bundle — Chartkick 5.0.1, Chart.js 4.5.1, chartjs-adapter-date-fns 3.0.0,
  date-fns 2.30.0, popper 2.11.8, Bootstrap 5.3.8, rails-ujs + first-party `slide_toggler`,
  `bootstrap_popover/tooltip` init, `rails_ujs_config` (disables rails-ujs remote `dataType:'script'`
  — deliberate hardening), `application.source.js` (11 lines).
- **Original `.source.js` files are directly fetchable** (Sprockets live compile, unhashed logical
  paths): `application.source.js` (235 B = the `//= require` manifest listing ALL dependencies),
  `slide_toggler.source.js` (2344 B), `rails_ujs_config.source.js` (692 B),
  `rails-ujs.source.js` (24 KB). Also served unhashed: `application.css` (248 KB),
  `activestorage.js` (30.5 KB), `actiontext.js` (34 KB) ⇒ **Active Storage + Action Text are in
  the stack** (attachment/direct-upload endpoints = next-session surface; `channels/consumer.js`
  404 ⇒ no ActionCable).
- **First-party JS is only ~2 files**, both read exclusively server-rendered `data-*` attributes
  (`data-slide-toggler-target`, `data-toggle-target-class`) into `querySelectorAll` — no URL
  input reaches any sink anywhere in shipped JS. Selector is only attacker-influenced if HTML
  already is (i.e. needs a prior XSS) ⇒ DOM XSS dead at source level, independent of CSP.
- jQuery **not** bundled: `/blog` and `/help` load `code.jquery.com/jquery-3.7.1.min.js` +
  `cdn.datatables.net/3.0.3/js/dataTables.min.js` from CDN (nonced); app asset
  `datatables.js` (174 B) just inits `$('.datatable')`.
- No secrets/keys/emails/internal URLs/server paths anywhere in the bundle; source maps expose
  *file names only* (`sourcesContent` absent).
- Assets: `application-<digest>.js` **404s** (importmap target!) while unhashed
  `/assets/application.js` 200s ⇒ **first-party bundle never executes in-browser** → DOM-XSS
  sweeps here would false-clean; assert script execution before trusting zeros.

## [Bugbountyskills.md] Stack (verified — pending first recon pass)

- WAF: unknown — expect Akamai/Imperva on www.verizon.com; record per host.
- Server / framework / language: unknown (many .aspx endpoints ⇒ ASP.NET/IIS on legacy hosts;
  `control/main` on webexcallingus looks like a Java/Spring or webMethods path).
- Auth model: unknown. Expect SSO (mss-sso.verizonbusiness.com, login.us.vzconnect.com,
  login.platform.telogis.com) fronting most portals.
- Notable middleware: `cms-*` hosts look like a shared CMS platform; `*.thingspace.verizon.com`
  is the IoT API platform (separate, well-tested by others).

## [Bugbountyskills.md] 7. LAB FILES — TOOLS & SCOPE

## [Bugbountyskills.md] >> tools-manifest.md

*Source: `/root/bugbounty-lab/tools-manifest.md`*

## [Bugbountyskills.md] Tools Manifest

_Environment inspected: 2026-10-11_

### [Bugbountyskills.md] 17.82 Account-identifier (user_id) enumeration through a MOBILE onboarding/duplication-check flow that ignores an account-level privacy toggle (`AccountDuplicationCheck` returns `check_logged_in_account.user_id` for any phone/email) -> mass de-anonymisation of users who opted out of discoverability (X/Twitter #1439026)

SOURCE: https://hackerone.com/reports/1439026 — X / xAI, "Discoverability by phone number/email restriction bypass" (Improper Access Control - Generic; High 8.2; $5,040; reporter zhirinovskiy; disclosed 2022-02-11)  read 2026-11-07 (full body 4,769 B from the local disclosed-reports dataset; live page also rendered by `web_extract`)
CLASS: broken privacy/BAC -> unauthenticated identifier disclosure + user enumeration · CWE-284
CORE METHOD:
  1. `POST https://api.twitter.com/1.1/onboarding/task.json?flow_name=login` with `Authorization: Bearer <app>`, a GUEST token (`X-Guest-Token`), the client-spoofer pair `X-Twitter-Client: TwitterAndroid` + `System-User-Agent: <android UA>`, `Content-Type: application/json`; body `{"flow_token":null,"input_flow_data":{"country_code":null,"flow_context":{"start_location":{"location":"deeplink"}},"requested_variant":null,"target_user_id":0}}` -> `flow_token` + subtask `LoginEnterUserIdentifier`.
  2. Re-POST the same URL/headers with `{"flow_token":"<t>","subtask_inputs":[{"enter_text":{"suggestion_id":null,"text":"<victim email OR phone>","link":"next_link"},"subtask_id":"LoginEnterUserIdentifier"}]}`.
  3. The next subtask is `AccountDuplicationCheck`, whose `check_logged_in_account.user_id` DISCLOSES the account identifier — for ANY phone/email, even when the user disabled discoverability (whose toggle is therefore enforced only in the client path the user set it in).
  4. Numeric `user_id` -> username/profile via any ID->profile endpoint; script the whole flow (no authentication) -> phone/email -> identity database covering opted-out and suspended accounts.
DETECTION SIGNAL: an app with web AND native clients — grep the mobile traffic for the auth/onboarding TASK graph (`onboarding/task.json`, `flow_name=login|password_reset`, `X-<Product>-Client: …Android`, `System-User-Agent`, guest+bearer tokens) and for subtask names that leak state (`AccountDuplicationCheck`, `check_logged_in_account`); a privacy setting honoured on one surface but bypassed by a duplication/exists-check on another.
CHAIN: unauthenticated request to the mobile login flow -> `AccountDuplicationCheck` leaks `user_id` for a phone/email despite discoverability=OFF -> ID->username mapping -> bulk enumeration of opted-out users (High 8.2, privacy loss at scale).
TRANSFERABLE TEST: replay any target's native-app login/onboarding flow from a script with the client header/UA spoofed (and the app's guest+bearer token), submit the phone/email of an account whose "discoverable by phone/email" toggle is OFF, and check whether any step returns that account's internal ID — a returned ID proves the restriction is client-side only.

### [Bugbountyskills.md] 17.129 The injectable field is INSIDE a base64/hex-encoded blob in one opaque parameter — so no scanner and no reviewer sees a parameter to test (Uber `sctrack`, HackerOne #150156)

CLASS/METHOD: a marketing-mail unsubscribe link carries the recipient record as `…/track/unsubscribe.do?p=eyJ1c2…` = `base64(JSON)`; decoding gives `{"user_id": 5755, "receiver": "…"}` and the integer `user_id` is concatenated into SQL. Confirm by time (`"user_id": "5755 and sleep(12)#"` → a 12 s delay), then extract blind with `"5755 and mid(user(),%d,1)='%c'#"` over `digits+_-@.` using response LENGTH as the oracle (`len(r.content)>0`) → `user()` and the schema name. The whole blob must be rebuilt per request; a base64 string cannot be patched in place. The encoding IS the evasion: an opaque token in a URL reads as a tracking id, not as a query parameter.
DETECTION SIGNAL: an opaque `p=`/`d=`/`data=`/`q=`/`t=`/`token=` value that base64/hex/JWT decodes; tracking, unsubscribe, mail-open, webhook or click-redirect endpoints carrying RECIPIENT data; decoded keys mapping 1:1 onto DB columns (`user_id`, `id`, `email`, `account`); an integer field in the decoded JSON (the classic concatenation site); latency differing between `user_id=N` and `user_id=N and sleep(5)`.
CHAIN: unauthenticated tracking parameter (a P4-looking link) → decode → concatenate → time-based confirm → blind extraction of `user()`/schema → mail-tracking DB (recipient lists, tracking tokens, click records) → and, per grants, the wider database. A full SQLi; the base64 wrapper is exactly why it survives triage.
TRANSFERABLE TEST: decode every opaque parameter harvested from mail/tracking/webhook/redirect links; for each decoded field re-encode with `<orig> and sleep(5)#` (MySQL) / `'; waitfor delay '0:0:5'--` (MSSQL) / `'||pg_sleep(5)--` (Postgres) / `' and 1=dbms_pipe.receive_message(('a'),5)--` (Oracle) and time it; then blind-extract with `mid()`/`substring()`/`ascii()`, using response LENGTH where the body is empty.
WHY IT IS A NEW GENERAL METHOD: the SQLi material here is about WAF bypasses, ORM-alias injection and dialect-specific blind extraction — not about the injection point being hidden from the tester by an encoding layer. The reusable rule: an encoded blob is a parameter you have not tested yet.

### [Bugbountyskills.md] 17.290 A MALFORMED FILE NAME OVERFLOWS THE DIRECTORY-LISTING FORMATTER — the enumeration path (`maps *` → `sprintf`) is the sink, NOT the file parser (Valve, Half-Life 1 `hl.exe`, HackerOne #402566, high, $1,500, reporter `kbeckmann`; reporter body `no-content`, read from the report's TEAM SUMMARY this pass; UNVERIFIED — not reproduced)

SOURCE: https://hackerone.com/reports/402566 — Valve, "[Half-Life 1] Malformed map name leads to memory corruption and code execution" (Classic Buffer Overflow, high, $1,500, 163 votes, reporter `kbeckmann`, created 2018-08-29 / disclosed 2020-09-22)  read 2026-11-08 (team summary only; reporter body `no-content`).
CLASS: native stack buffer overflow → code execution via the DIRECTORY-ENUMERATION path.
CORE METHOD: (1) verbatim: "A stack overflow takes place when map names with malformed names are listed which can be used to execute arbitrary code."; (2) "Extract the attached zip-file in the /valve/maps directory."; (3) TRIGGER BY ENUMERATING — "Start `Half-Life`. Open the console and type `maps *`. This lists the installed maps." → "`gnome-calculator` should now execute."; (4) sink, verbatim callstack: `sprintf () from /usr/lib32/libc.so.6` ← `COM_ListMaps (pszSubString=0x0) at ../engine/common.c:2857` ← `Host_Maps_f () at ../engine/host_cmd.c:1511`, with `Cmd_ExecuteString (text=0x41414141 …)` = attacker-controlled return address; (5) impact, verbatim: "custom code can get executed that is not written by Valve, e.g. malware."
DETECTION SIGNAL: a `list` / `index` / `maps` / `plugins` / `themes` / `files` command or endpoint that formats each entry's user-controlled NAME via `sprintf`/`strcpy`/`strcat` into a fixed-size buffer; the enumeration path is less hardened than the parser and is reachable WITHOUT the file being valid; 32-bit / no-ASLR binaries where `0x41414141` control is enough to pivot.
CHAIN: user-controlled entry NAME in a directory → the LISTING formatter copies it into a fixed STACK buffer with no bounds check → the long name overwrites the saved return address (EIP control, `0x41414141`) → arbitrary code execution (high, $1,500).
TRANSFERABLE TEST: on any enumeration surface (file manager, upload list, plugin/theme/archive index, bucket listing, log viewer), place or upload an entry whose NAME is a length-filling payload (far past the field's expected cap) and trigger the LISTING — not the open/parse; a crash/overflow means the enumerator is unbounded. Rule: **test the file-LISTING/formatting path, not just the file parser — a malformed file NAME overflows the enumerator, which is reachable without a valid file.**
WHY IT IS A NEW GENERAL METHOD: the file already records Valve engine overflows that fire on message parsing (#584603 entity index), file LOAD (L4D2 NAV), a voice DECODER (#3212) and voice PACKETS (#3708); the ledger's other `sprintf` hits are a CTF fragment and a `gmp_sprintf` note. None records a malformed FILE NAME overflowing the DIRECTORY-LISTING formatter — the ENUMERATION-path sink. Slot 17.290.

## [Bugbountyskills.md] >> BATCH 2026-11-14 — operator's paid-report corpus: new variants, routing rows, recon atoms

## [Bugbountyskills.md] V-26: UI-gate-only preconditions + the sibling-action status differential

**Also known as:** hidden-function authorization; level-check bypass; API accepts what the UI forbids.
**Mechanism:** the precondition (verified account / manager role / object lock state / approval level) lives
in the UI or on the happy path only. Paid: an unverified user creates a PAT via the API; a Viewer escalates
to Editor with `_method=PATCH&contract_collaboration[role]=editor` on a SENT contract; a read-only team lead
archives (off-boards) an employee while every sibling action answers 401 (note/salary/role/termination) or
404 (deletion). Violated assumption: "the button is the authorization."
**Preconditions:** any role/level matrix, any "verify/enable first" wall, any locked-state object.
**Detect:** (a) capture and replay the underlying request from the unqualified account; (b) enumerate SIBLING
actions on the same object from the read-only account and tabulate statuses — the single deviating row is
the finding; (c) send state-changing verbs as `_method=PATCH` inside a POST body.
**Chain it with:** `business-logic-testing` (the effect: archived user, changed role), `bac-idor-testing`.

### [bugbountyhuntingskills.md] 1.3 Client-side sink discovery via hash parsing → prototype pollution → gadget

**Source:** HackerOne #998398 — Elastic / Swiftype, *"Prototype Pollution leads to XSS"*, High.

**Core method**
- Read the shipped JS (`st.js`) rather than fuzzing. Found `deparam` parsing `location.hash`
  — a client-side source fully attacker-controlled with no server interaction.
- Confirmed pollution with a hash payload that writes to the prototype:
  `https://blog.swiftype.com/#__proto__[asd]=alert(document.domain)`
- Then hunted a **gadget** — code that reads the polluted property and reaches a dangerous sink.
  Found it in the same bundle:
  `pInstall._convertStringHooksToFunctions` iterates `_userServerConfiguration.install.hooks` and
  calls `eval(hookFunction)` on each value.
- Chain: pollution sets the hook value → gadget `eval`s it → script execution. Payload only fires on
  refresh, which the report notes explicitly.

**Lesson.** Prototype pollution is not a finding by itself; it becomes XSS only through a gadget.
The method is two passes: (1) find the pollutable source, (2) grep every bundle for property reads
that flow into `eval`, `innerHTML`, `Function`, `setTimeout(string)`, or `src`.

**Transferable test.** `location.hash` / `location.search` / `postMessage` → deparam-style parsers →
recursive merge → gadget. Grep for `eval(`, `innerHTML =`, `document.write(` in the same chunk.

---

### [bugbountyhuntingskills.md] 3.2 Identifier discovery from a public surface

**Source:** HackerOne #404797 — Zomato, `photo_ids`, $600.

**Core method**
- Spot the object reference in a state-changing request:
  `/php/client_manage_handler?<params>&case=remove-active-photo` with a `photo_ids` parameter.
- The hard part is not the swap, it's **knowing a valid victim ID**. Method: harvest IDs from a
  public page — the restaurant's front page exposes its photo IDs — then feed them into the
  authenticated delete request.
- Confirmed by observing the photo disappear from the victim's listing.

**Lesson.** IDOR hunting is two problems: the missing check, and the ID oracle. Public profiles,
sitemaps, share links, email notifications, and image CDN paths are all ID oracles. Solve the oracle
first and the check-test becomes trivial.

**Transferable test.** For any write/delete operation on an object, find a public read path that
leaks the same object's ID. Then replay the write with a foreign ID.

---

