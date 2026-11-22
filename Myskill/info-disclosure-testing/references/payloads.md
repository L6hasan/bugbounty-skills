# info-disclosure-testing — Payloads, Templates & Tool Invocations (references/payloads.md)

Cross-cutting material for `SKILL.md` and both variant files. Everything here is a
**template**: `<PLACEHOLDER>` slots only, never hardcoded live targets. Keep every
probe read-only — list and read, never modify, upload, or delete (see `SKILL.md` §1).
In this category a 200 status is a *lead*; the body decides the finding.

## Table of contents

1. [Recon path catalog (wordlists with placeholders)](#1-recon-path-catalog-wordlists-with-placeholders)
2. [.git exposure validation: real HEAD/objects vs soft-404 and honeypots](#2-git-exposure-validation-real-headobjects-vs-soft-404-and-honeypots)
3. [curl capture templates: headers, banners, sourcemaps](#3-curl-capture-templates-headers-banners-sourcemaps)
4. [S3/GCP bucket enumeration & verify (read-only procedure)](#4-s3gcp-bucket-enumeration--verify-read-only-procedure)
5. [Tool invocation templates & path-probe evasion notes](#5-tool-invocation-templates--path-probe-evasion-notes)
6. [Redaction checklist for discovered secrets](#6-redaction-checklist-for-discovered-secrets)
7. [Chain it with (suite cross-references)](#7-chain-it-with-suite-cross-references)

---

## 1. Recon path catalog (wordlists with placeholders)

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

## 2. .git exposure validation: real HEAD/objects vs soft-404 and honeypots

**The soft-404 gotcha — read this before celebrating any 200.** SPAs, CDNs, and
"friendly" servers return **HTTP 200 with an HTML page** for paths that do not exist
(the app's router catches `/*`, or a WAF renders a styled block page, or nginx
`error_page 404 =200 /index.html` is set). Naive scanners report `/.git/HEAD → 200`
on every such site. A real `.git/HEAD` is a *17–41 byte text file*, not HTML. Status
code proves nothing here — **content structure proves everything.**

Validation ladder (stop at the first failure — it's a lead, not a finding):

1. **Fetch HEAD raw, no interpretation.**
   ```bash
   curl -sS -i "<BASE>/.git/HEAD"
   ```
   - **Real:** body is exactly `ref: refs/heads/<branch>\n` or a bare 40-hex SHA;
     `Content-Type: text/plain` (or no type).
   - **Soft-404:** `<!DOCTYPE html>…`, `<title>…</title>`, SPA shell, WAF interstitial,
     or an error page that happens to be 200. Bail: not git.
2. **Fetch `/.git/config`.** Real config has `[core]`, `[remote "origin"]` with a real
   URL, and a `[branch …]` section. Honeypots and stub pages rarely forge this.
   Record the `remote.origin.url` — it often leaks an internal Git host (V-04) or a
   repo name (V-06-adjacent).
3. **Fetch a real object.** Parse `/.git/index` or use `git ls-remote`-style reads:
   pick one SHA from `/.git/logs/HEAD` (contains `<old> <new> <committer>` lines) and
   GET `/.git/objects/<first-2-chars>/<remaining-38>` — expect `gzip` magic bytes
   (`1f 8b`), which `file` reports as gzip. A 404/HTML here means HEAD was a **honeypot**
   (planted HEAD with no objects — a tripwire; don't waste time, and don't trip it
   repeatedly).
4. **Cross-check with a second signal** (per `SKILL.md` §4): `/.git/logs/HEAD`
   timestamps + a recovered file whose content matches the live site (or predates it).
   Two independent artifacts agreeing = confirmed exposure.
5. **Only now escalate** to recovery (`git-dumper`, §5) — read-only checkout, then
   `git log` for history. Proof of capability = one recovered file + history count,
   not a full dump pasted into the report.

Same ladder generalizes: `.svn/wc.db` must be SQLite (`file` → `SQLite 3x database`),
`.DS_Store` must be binary DS_Store (magic `Bud1`), `.env` must contain `KEY=value`
lines with non-empty values (an `.env.example` with blanks is a template, not a
finding), `*.js.map` must parse as JSON with `version`/`mappings` keys.

---

## 3. curl capture templates: headers, banners, sourcemaps

All templates read-only; `<PLACEHOLDER>` slots filled per engagement. `-i` includes
status+headers; `-sS` silences progress but shows errors; `--compressed` avoids
misreading gzip bodies; `-H 'Cache-Control: no-cache'` re-validates against CDN caches
before you claim a *live* leak (cached removals are stale — check `Age:`/`X-Cache:`).

**Header/banner capture (V-02/V-04):**
```bash
curl -sS -i --compressed "<BASE>/<path>" -H 'Cache-Control: no-cache' \
  | tee <headers-<path>.txt>          # save: status, Server, X-Powered-By, Via, internal hosts
curl -sS -o /dev/null -D - "<BASE>/"   # homepage header snapshot only
```
Compare across 3-5 paths (home, API, error-trigger, static): backends behind CDNs
leak *different* headers per route.

**Banner/version trigger (error-path banners, V-02/V-03):**
```bash
curl -sS -i -X OPTIONS "<BASE>/<api-path>"
curl -sS -i -H 'Content-Type: application/json' -d '{invalid json>' "<BASE>/<api-path>"
```

**Sourcemap capture (V-09):**
```bash
# 1) does the bundle advertise one?
curl -sS "<BASE>/<asset>.js" | tail -c 300 | grep -o 'sourceMappingURL=.*'
# 2) fetch and validate structure
curl -sS -i "<BASE>/<asset>.js.map" | head -c 200      # expect JSON: {"version":3,...}
curl -sS "<BASE>/<asset>.js.map" | jq -r '.sources[]'  # original file tree
curl -sS "<BASE>/<asset>.js.map" | jq -r '.sourcesContent[]' \
  | grep -nE '<secret-pattern>'                        # grep locally, redact on report
```

**Stack trace / config capture (V-03/V-11):**
```bash
curl -sS -i -H 'Content-Type: application/json' -d '{"<known-param>":null}' "<BASE>/<path>" > trace.txt
curl -sS -i "<BASE>/.env" | head -n 40                 # status + first lines; mask values immediately
```

**Heartbleed single probe (V-08) — one run, not a loop:**
```bash
nmap -p <PORT> --script ssl-heartbleed <TARGET.HOST>   # confirms; do not repeat against prod
```

---

## 4. S3/GCP bucket enumeration & verify (read-only procedure)

**Rule: verify read/list only. No PUT, POST, DELETE, ACL-change, or object rename —
ever.** Write-access is *inferred*, never tested (you'd be modifying a third party's
infrastructure; if you have inherited evidence of public write, describe it without
demonstrating it).

**Step 1 — Harvest bucket names (passive first).**
```bash
# from in-scope HTML/JS/pages you already fetched — no external scanning needed
grep -ohE '(https?://)?[a-z0-9.-]+\.s3[.-][a-z0-9.-]*amazonaws\.com[^"'\'' )]*' <fetched-files>
grep -ohE 'https?://[a-z0-9.-]+\.s3-website[.-][a-z0-9.-]*\.amazonaws\.com'      <fetched-files>
grep -ohE 'https?://storage\.googleapis\.com/[a-z0-9._-]+'                        <fetched-files>
grep -ohE 'https?://[a-z0-9.-]+\.blob\.core\.windows\.net/[a-z0-9._-]*'           <fetched-files>
grep -ohE '(gs|s3)://[a-z0-9._/-]+'                                               <fetched-files>
```
Confirm each name's tie to the target (it appears in *their* page/JS — a bucket
mentioned in a tutorial may belong to someone else; check program scope).

**Step 2 — AWS: anonymous list attempt (GET only).**
```bash
curl -sS -i "https://<BUCKET>.s3.amazonaws.com/?list-type=2&max-keys=5"
# regional: https://<BUCKET>.s3.<REGION>.amazonaws.com/?list-type=2&max-keys=5
```
- `200` + `<ListBucketResult>` → **public listing confirmed**. Record `IsTruncated`,
  `KeyCount`, and a few *key names* (class evidence).
- `403 AccessDenied` + `<Code>AccessDenied</Code>` → listing private. **Not a bug by
  itself** — proceed to step 3 with a known key, otherwise stop and record as negative.
- `404 NoSuchBucket` → name wrong or deleted; don't chase.

**Step 3 — AWS: object read attempt (one known key, GET/HEAD only).**
```bash
curl -sSI "https://<BUCKET>.s3.amazonaws.com/<known-object-key>"
# 200 + Content-Type + ETag → world-readable object even with listing denied
# 403 AccessDenied → read blocked; 404 → key wrong
```
Pull *at most* what's needed to classify the content (first lines/header of one
object). If listing was denied but a key you got from their own HTML reads fine,
that's still a finding — key-guessing just got a bootstrap.

**Step 4 — GCP: same three probes.**
```bash
curl -sS -i "https://storage.googleapis.com/<BUCKET>/?maxResults=5"      # JSON list
curl -sS -i "https://storage.googleapis.com/<BUCKET>/<known-object>"     # object read
# website-style: https://<BUCKET>.storage.googleapis.com/
```
`{"error":{"code":403,"message":"Access denied…"}}` → private; `404` with
`NoSuchBucket`-style message → wrong name.

**Step 5 — Verify (two signals) & triage.**
1. Signal A: list or object GET returned *real* structure (`ListBucketResult`/JSON keys
   or an object body), not HTML/soft-404.
2. Signal B: bucket ownership tied to an in-scope origin (came from the target's own
   page/JS, or a `Message-ID`-style cross-reference), not an unrelated same-named bucket.
3. **Triage:** 403/`AccessDenied` = not reportable. Lists only public website assets =
   public-by-design (usually N/A). Objects with PII/credentials/backups/logs =
   **reportable, high+**. Write evidence inherited without testing = critical.

**Step 6 — Document redacted.** Report: bucket URL, permission type (list/read),
object *count* and *classes* (e.g. "3,102 keys under `user-exports/*.pdf`"), 1-2 masked
key names as samples. No object contents, no bulk download.

---

## 5. Tool invocation templates & path-probe evasion notes

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

## 6. Redaction checklist for discovered secrets

Run this before writing a single byte of a report, ticket, or chat message. The rule:
**report the type + location, never the live value.** A report containing the
credential it discloses is itself a disclosure incident.

- [ ] **No raw secrets anywhere:** keys, passwords, connection strings, session tokens,
      private keys, cookies, EXIF GPS/person names, and other users' PII are masked —
      not in the report body, evidence blocks, screenshots, or attachments.
- [ ] **Mask by pattern + shape, keep recognition value:** first 4 chars + ellipsis +
      length/charset note where the prefix identifies the service —
      `AKIA••••••••7Q (16 chars, AWS)` · `ghp_•••••••• (40 chars, GitHub PAT)` ·
      `postgres://app@<db-host>:5432/•••• (password omitted, 22 chars)` ·
      `JWT HS256 secret: •••• (32 chars, high-entropy)` · `eyJ•••.eyJ•••.••• (RS256)`.
- [ ] **Location is always included:** file/endpoint URL, JS asset + byte offset or
      line, `.env` key *name* (`DB_PASSWORD=`), git path+commit, bucket + object key
      pattern, log file + date range. Location without value = actionable for the
      fixer, useless to an attacker.
- [ ] **Hash instead of value when needed:** `sha256:ab12…` of the secret lets the
      vendor match it to their store without learning it (say in the report that this
      is a hash, not the secret).
- [ ] **Capability > content:** describe what the secret *would* do ("signs session
      tokens", "grants list+read on <bucket>"), proven read-only; never attach the
      proof-of-content (dumped rows, memory bytes, full EXIF values).
- [ ] **PII & third-party data:** other users' documents/emails/metadata stay *out* of
      evidence — describe class + count ("1,204 records with email+name fields").
- [ ] **Screenshots scrubbed:** no browser-tabs with internal URLs visible, no auth
      headers in captured requests, no tool output panels showing unmasked values.
- [ ] **Attachments scanned:** grep the final report file itself for the secret patterns
      from §1 before submitting — one `grep -E '<your-found-pattern>' report.md` sweep.
- [ ] **Rotation call-to-action:** remediation says *rotate* the exposed credential —
      exposure time unknown, so assume compromised.
- [ ] **Program channel rules:** if the program restricts evidence sharing (redaction
      required, no secret storage on their ticket system), follow that over any
      convenience — offer the hash + a private channel per their policy.

---

## 7. Chain it with (suite cross-references)

Disclosure findings are usually the *map*, not the endpoint. Point each confirmed leak
at the right sibling skill:

- **`sqli-testing` — schema + credential combos.** A leaked `.env`/config (V-11) with
  `DB_HOST`/`DB_PASSWORD` plus an error-leaked query shape (V-03) is exactly the
  pairing that skill's §1/§2 expect: the stack trace names the DBMS and table, the
  config supplies the connection context. Exposed `.git` history containing old
  query code, and GraphQL schema field lists (V-07) feeding `WHERE`-column guesses,
  all route there.
- **`bac-idor-testing` — leaked IDs and GraphQL nodes.** Introspection dumps (V-07)
  and API specs (V-12) hand over the object types and parameter names
  (`/orders/{orderId}`); directory listings and docs leak real record IDs. That skill
  does the access-control probing — this skill only delivers the map. Also the right
  target for leaked JWT secrets from V-06 (token forging is *its* authorization-jwt
  territory, do not forge against real sessions without explicit scope).
- **`ssrf-testing` — metadata endpoints and internal hosts.** Internal IPs and
  hostnames from V-04, `X-Originating-IP` from V-14, `.env` URLs to internal admin
  panels from V-11, and `169.254.169.254`-shaped addresses are the *target list* for
  SSRF work — including cloud metadata (`/latest/meta-data/iam/…`) reachable once an
  SSRF exists. Config files may also reveal command-injection-adjacent paths (cron,
  webhook URLs) for that skill's RCE side.
- **`path-traversal-testing` — leaked file paths and backups.** Stack traces (V-03)
  and `.env`/config (V-11) name absolute paths (`/var/www/app/config.ini`); directory
  listings (V-05) and backup files (V-01) tell you *which* files exist and are worth
  forcing a file parameter to read. It turns "we know the path" into "we can read
  arbitrary paths", and covers wrappers/log-poisoning follow-ons.

Adjacent suite notes (secondary): leaked admin endpoints from V-12 also feed
`business-logic-testing` (abuse of exposed workflows); frontend comments recovered via
V-09 may reveal XSS/CSRF sinks worth a look under `xss-testing`/`csrf-testing`; and if
V-06 dumps a *sandbox/runtime* key or Wasm/JS engine config, `sandbox-escape-testing`
is the follow-on. Route by what the leak *enables*, not by the leak's own CWE.
