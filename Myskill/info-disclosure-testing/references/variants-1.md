# info-disclosure-testing — Variants 1-8 (references/variants-1.md)

Deep playbook for the first half of the leak matrix. Read §4 of `SKILL.md` for the
verification standard before claiming any of these as findings — in this category the
gap between "found something" and "reportable finding" is a sensitivity judgment, not
a technical one. Path wordlists, curl templates, and the `.git` validation procedure
live in `payloads.md`. Redact every secret you cite; never modify what you enumerate.

## Table of contents

- [V-01: Exposed version control repositories and backup management leakage](#v-01-exposed-version-control-repositories-and-backup-management-leakage)
- [V-02: Server banner response modification and micro-service infrastructure footprinting](#v-02-server-banner-response-modification-and-micro-service-infrastructure-footprinting)
- [V-03: Detailed debugging exception extraction via stack trace disclosures](#v-03-detailed-debugging-exception-extraction-via-stack-trace-disclosures)
- [V-04: Internal network schema mapping via server-leaked IP address points](#v-04-internal-network-schema-mapping-via-server-leaked-ip-address-points)
- [V-05: Arbitrary resource harvesting via unprotected directory indexing filters](#v-05-arbitrary-resource-harvesting-via-unprotected-directory-indexing-filters)
- [V-06: Hardcoded sensitive cryptographic keys, client secrets and token extraction](#v-06-hardcoded-sensitive-cryptographic-keys-client-secrets-and-token-extraction)
- [V-07: GraphQL introspection query data schema leakage exploitation](#v-07-graphql-introspection-query-data-schema-leakage-exploitation)
- [V-08: Heartbleed-style memory dump extraction via protocol heartbeat vulnerabilities](#v-08-heartbleed-style-memory-dump-extraction-via-protocol-heartbeat-vulnerabilities)

---

## V-01: Exposed version control repositories and backup management leakage

**Mechanism:** Deploy pipelines copy whole working directories, so `.git/`, `.svn/`,
swap files (`.swp`), and forgotten backups (`app.tar.gz`, `db.sql.bak`, `index.php~`)
sit in the webroot beside live code. Violated assumption: "the dot prefix hides it" —
the server serves any file it can see. Git is worst: `.git/HEAD` plus object recovery
reconstructs *every historical commit*, including secrets "deleted" years ago.

**Preconditions:**
- VCS dir or backup file was deployed with the app and never stripped; the web server has no deny rule for `.git`/backup extensions.
- For full recovery: objects loose or packed and reachable — true when rsync/Docker COPY moved the dir wholesale.

**Detect:**
1. Probe the catalog in `payloads.md` §1: `/git/HEAD`, `/.git/HEAD`, `/.svn/entries`,
   `/.hg/hgrc`, `/.DS_Store`, plus backup extensions on known names: `/index.php.bak`,
   `/.index.php.swp`, `/config.yml~`, `/<app>.tar.gz`, `/dump.sql`.
2. **Validate before believing** — full ladder in `payloads.md` §2: a real `.git/HEAD`
   is `ref: refs/heads/<branch>` (or a 40-hex SHA); a soft-404 returns HTML with 200;
   a honeypot gives a HEAD that never leads to `/git/config` or objects.
3. `/.svn/wc.db` (SVN ≥1.7) should be SQLite — `file` output tells you instantly;
   older SVN: `/.svn/entries` is plain text with revision + URLs.
4. For backups: compare byte size and `Last-Modified` against the live file — a stale
   backup of a since-changed page proves it's a real artifact.

**Proof of concept:**
```bash
curl -sS "https://<TARGET.HOST>/git/HEAD"     # expect: ref: refs/heads/main
curl -sS "https://<TARGET.HOST>/git/config"   # expect: [core], [remote "origin"]
git-dumper "https://<TARGET.HOST>/git/" /tmp/<project>-dump   # authorized, read-only
git -C /tmp/<project>-dump log --oneline | head               # history restored
```

**Confirm:** Two independent signals: HEAD names a branch **and** `/git/config` or a
real object corroborates it (HEAD alone can be a planted page). Cross-check recovered
content against the live site — committed `index.js` should match or predate the deploy.

**False positives:** Soft-404 pages returning 200 (compare body hash against a known-404
path); WAF blocks rendered as 200 HTML; honeypot git dirs (HEAD but no config/objects —
a tripwire; don't keep pulling); `.DS_Store` listing only public assets; backups of
sample/demo data; staging hosts out of scope. A `.bak` of a public JS file is noise.
**403-vs-404 existence control (run it before calling any deny real):** a blanket deny
indistinguishable from existence returns 403 on *nonexistent children too* — e.g.
`/.git/HEAD` 403 meant nothing until `/.git/zzqnonexist` was *also* 403 (⇒ deny rule,
existence unprovable, not clonable) while `/envvars/zzqnonexist` 404 after `/envvars/`
403 ⇒ **real, enumerable directory with resolvable files** (then fuzz filenames). Same
trick separates real from generic at file level: `server-status` 403 + `server-statuz`
404 ⇒ real handler; `/.htaccess` 403 **and** `/.htaccesss` 403 ⇒ generic `.ht*` rule.
**A served `.gitignore` is a ready-made wordlist** (2026-10-24: `/log/ /config/ /cert/
/envvars/` lines led straight to live `envvars/global.php` + `/.config.php`) — read it,
probe its exact paths, and don't stop when the obvious dirs 404: the ignore list maps the
*repo*, the web root may expose only a subset.

**Impact:** Full source disclosure including *historical* secrets and internal structure
— usually enough for a second bug (chain: `sqli-testing` with a leaked connection
string). Reportable even with no secret inside: recovery is trivial and unauthenticated.
State branch, commit count, and whether credentials were found (redacted).

**Remediation:** Exclude VCS/backup artifacts from deploy artifacts (`.dockerignore`, CI
copy rules) and deny `/.git`, `/.svn`, `*.bak`, `*~`, `*.swp` at the web server — plus
rotate anything the history contains; deletion from HEAD doesn't remove it from history.

**CWE / OWASP:** CWE-538 (Sensitive Info in Externally Accessible File), CWE-200 —
OWASP A01:2021; WSTG-INFO-08.

---

## V-02: Server banner response modification and micro-service infrastructure footprinting

**Mechanism:** Servers announce themselves: `Server: nginx/1.24.0`, `X-Powered-By:
PHP/8.1.22`, `X-AspNet-Version`, `X-Application-Context`, `x-envoy-*`, `Via` chains.
Violated assumption: "banner info is harmless" — it hands over the exact CVE search
space plus the topology (which service answers where). The modification angle: some
apps reflect client-controlled values into a banner-ish header or page foot.

**Preconditions:**
- Target returns framework/proxy headers on normal responses (most do).
- For modification: the app itself writes a client-controlled value into a response header (not just proxy pass-through).

**Detect:**
1. Capture headers from several endpoints (home, API, static, forced error) with the
   `payloads.md` §3 template — CDNs normalize some routes only; one snapshot lies.
2. Catalog `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Runtime`,
   `X-Application-Context` (Spring), `x-envoy-*`, `x-vercel-*`, `Via`, `Alt-Svc`,
   `Report-To`, `X-Request-Id`/correlation IDs (service naming).
3. Trigger deliberate errors (bad method, malformed JSON) — 500s often reveal *backend*
   banners the happy path hides (e.g. `Apache-Coyote/1.1`).
4. Micro-service map: differing runtime headers / request-ID formats per subdomain =
   separate services; finish with DNS + CT entries for the same hosts.

**Proof of concept:**
```http
GET /<any-path> HTTP/1.1
Host: <TARGET.HOST>
```
Recorded (redacted): `Server: <server>/<version>`, `X-Powered-By: <framework>/<version>`,
`X-Application-Context: <service-name>`. Modification probe — send
`X-Custom-Banner-Test: <nonce>` and check whether the *app* echoes it into a header
(proxy forwarding your header is normal behavior, not injection).

**Confirm:** Version corroborated by a second signal — a framework fingerprint (favicon
hash, default file), behavior matching that version, or a CVE advisory for the exact
version. Infra names count only if the same internal name recurs across two endpoints.

**False positives:** CDN-injected headers (`Server: cloudflare` describes the CDN, not
your origin); default `X-Powered-By: Express` (real but informational); version-looking
build/request IDs; headers you "modified" via proxy pass-through — hop-by-hop forwarding
isn't injection. Reflection into the *body* is a different issue (`xss-testing`).

**Impact:** Version-accurate targeting: "banner narrows CVE search space to <N>
advisories and confirms <component> <version> behind <host>". Alone informational;
pair with a known-vulnerable version (V-03 traces corroborate) to justify medium. The
infra map becomes high only when it exposes internal hosts enabling V-04/`ssrf-testing`.

**Remediation:** `server_tokens off;` (nginx), `expose_php=Off`, strip `X-AspNet-Version`
and Spring `server.error.include-*` at the proxy, and standardize error responses so
backends don't announce themselves.

**Field notes (2026-10-21, CloudFront-gated SPA):**
- **Always read the error BODY, not just the status.** A CloudFront Lambda@Edge auth
  gate's 401 body (56 bytes) leaked the exact runtime: `node version is 22.23.2`.
  Status+size-only sweeps (the default curl loop) miss this class entirely — pipe 4xx/5xx
  bodies through `xxd`/`head -c` at least once per distinct error type.
- **Fingerprint the gate's allowlist empirically before trusting any existence oracle.**
  Hypothesis "extensionless → gated" was wrong: `/probe-xyz.txt` returned 401 while
  `/robots.txt` passed ⇒ allowlist is exact-path (`/robots.txt`, `/sitemap.xml`,
  `/.well-known/*`, the hashed asset dir), not extension-based. Calibrate with one
  known-EXISTING and one known-MISSING sensitive path first.
- **Catch-all auth kills the oracle — verify by md5-ing bodies.** One API middleware
  returned byte-identical 401 JSON for `/.env`, `/actuator/env`, `/definitely-not-a-route`
  ⇒ no path-existence info leaks; encoding bypasses (`//x`, `/%2e`, `/a/../x`) all still
  hit the gate; null byte → CloudFront's generic 400 page (standard noise, no origin leak).

**Field notes (2026-10-21, Cloudflare managed-challenge zone, public bug bounty):**
- **On a managed-challenge zone, `/.well-known/**` is the origin window — go there
  first.** Verifier traffic (Android assetlinks, Apple AASA, OAuth metadata, security.txt)
  must never be challenged, so those paths are served by the *real app*. That gives you
  genuine origin responses for header posture, cookie flags and CORS behaviour even when
  every HTML/JS path is blocked — a real `200` with `Server`, `via: 1.1 google`,
  `Set-Cookie` and app-specific headers beats ten thousand challenge pages. Match is
  usually on the `/.well-known/` **substring**, so `/anything/.well-known/x` often passes
  too (and then reveals the app's routing-error handler).
- **Distinguish the two failure modes — they are different rules.** A challenge says
  `cf-mitigated: challenge`; a WAF *deny* rule returns `403` titled `Request blocked` with
  **no** `cf-mitigated` header at all. Reading only the status code hides this: a `PATCH`
  to any path, any path containing `status`, and backup extensions (`.bak`) hit the deny
  rule while `GET`/`POST` to the same path hit the challenge. The deny rule is often the
  stronger hint — it exists *because* something sensitive lives there.
- **WAF decodes and normalizes before matching — don't burn requests on encoding.**
  `../`, `%2e%2e%2f`, `%252e%252e%252f`, `..;`, `//`, `%2f` and `status%20` all behaved
  identically (blocked or normalized). Percent-encoded single characters (`stat%75s`) were
  still caught. One known-good boundary test per rule is enough; then move on.
- **Never credit the CDN's headers to the app.** Cloudflare's own challenge/block template
  ships `x-frame-options: SAMEORIGIN`, `referrer-policy: same-origin`,
  `x-content-type-options: nosniff`, COOP/COEP/CORP and a locked-down `permissions-policy`
  — while *origin* responses travelling through the same CDN carry none of them. Compare
  "CDN-generated response" vs "origin-generated response" side by side; the asymmetry is
  what makes a missing-security-headers finding survive triage.
- **Wildcard DNS silently turns every subdomain brute force into noise.** `*.quizlet.com`
  resolved to the same two Cloudflare IPs for gibberish control names. Always fire 2–3
  nonsense names first; if they resolve, discard the whole sweep and switch to CT SANs
  (`api.certspotter.com/v1/issuances?domain=…&include_subdomains=true&expand=dns_names`),
  which listed the 18 names that actually have certificates.

**CWE / OWASP:** CWE-200, CWE-16 (Configuration) — OWASP A05:2021; WSTG-INFO-01.

---

## V-03: Detailed debugging exception extraction via stack trace disclosures

**Mechanism:** An unhandled exception reaches the client as a full trace: file paths,
class/method chains, framework versions, SQL fragments, sometimes env values. Violated
assumption: "the user sees a generic message" — debug mode is on, or the API returns
raw 500 bodies (GraphQL/JSON APIs are notorious). The trace is a recon multiplier: it
names modules, absolute paths (feeds `path-traversal-testing`), and DB tables.

**Preconditions:**
- An exception path exists (invalid types, bad IDs, missing headers are usually enough).
- Debug/verbose error handling is on, or the framework's default JSON error includes `trace`/`stack`.

**Detect:**
1. Trigger errors with benign malformed input: invalid JSON, `?id=abc` on a numeric
   endpoint, wrong `Content-Type`, unsupported method. Capture full *bodies* — traces
   live in the 400/500 body, not the headers.
2. Fingerprint the dump: Django DEBUG (`Traceback (most recent call last)`), Werkzeug
   (`File "/app/…", line`), Spring whitelabel, ASP.NET (`Server Error in '/'`),
   PHP (`Fatal error: Uncaught … in /var/www/…`), Express stack arrays, Rails, Whoops/Ignition.
3. Extract deliberately: messages embed values — SQL errors leak queries (→ `sqli-testing`),
   `FileNotFoundError` leaks intended paths, parse errors echo expected schema.
4. Check non-error debug routes: `/_profiler`, `/actuator/trace`, `/debug`, `/__debug__/`.

**Proof of concept:**
```http
POST /<api-path> HTTP/1.1
Host: <TARGET.HOST>
Content-Type: application/json

{"<known-param>": <malformed-type-for-it>}
```
Observed (redacted): HTTP 500 with `at <service>.handlers.<fn>(/opt/<app>/src/…:NN)`,
framework version `"<framework> <version>"`, internal path `/opt/<app>/…`.

**Confirm:** A *different* malformed input produces a trace from the same code path
(same file:line) — proving it's the app's real error, not a canned page; or the claimed
version matches an independent fingerprint (V-02).

**False positives:** Generic 500 HTML with no trace (WAF/LB errors); error pages that
merely *quote the URL* (reflection, not a trace); client-side framework overlays in JS
(V-09 territory); traces made only of your own input echoed back — require server-side
artifacts (paths, versions, class names). Debug ports out of scope.

**Impact:** Version-accurate targeting plus internals: file paths, module names, table
names, sometimes DSN credentials. Report as "unauthenticated error triggering returns
full stack traces exposing <structure> and <version>". Medium standalone; higher if the
trace includes a secret.

**Remediation:** Turn debug detail off in production (`DEBUG=False`,
`server.error.include-stacktrace=never`, `customErrors="On"`); return a correlation ID
to the client and log the full trace server-side only.

**CWE / OWASP:** CWE-209 (Information Exposure Through an Error Message), CWE-497 —
OWASP A05:2021; WSTG-ERR-01.

---

## V-04: Internal network schema mapping via server-leaked IP address points

**Mechanism:** Responses leak addressing: HTML comments (`<!-- lb-01 10.0.4.12 -->`),
redirects to `http://10.x.internal/`, connection strings in configs/errors,
`X-Backend-Server` headers, health endpoints listing pod IPs. Violated assumption:
"users can't route to RFC1918" — they can't, but they don't need to: the leak *is* the
map for SSRF targeting and trust-boundary discovery.

**Preconditions:**
- Some surface (header, body, error, comment, config) carries an IP or internal hostname.
- Value compounds with a request-forging primitive (→ `ssrf-testing`) — the leak maps, the chain exploits.

**Detect:**
1. Grep everything you already have for `10.x`, `172.16-31.x`, `192.168.x`, `127.x`,
   `169.254.x` (cloud metadata), IPv6 ULA `fc00::/7`, and internal hostnames
   (`*.local`, `*.internal`, `*.corp`, `*.svc.cluster.local`, `db-primary`, `redis-02`).
2. Sources: response headers (`X-Backend-Server`, `Via`, `X-Real-IP` set by origin),
   HTML/JS comments, `Location:` on auth redirects, WebSocket URLs, error pages (V-03),
   `.env`/config (V-11), `/actuator/env`, `/server-status`.
3. Correlate: an address in two independent responses = a node; hostname+IP pairs give
   the DNS scheme to brute later.
4. Optional passive corroboration for in-scope hosts (check program rules on
   third-party scanning first): passive DNS, CT logs.

**Proof of concept:**
```http
GET /<path-with-comment-or-error> HTTP/1.1
Host: <TARGET.HOST>
```
Observed (redacted): body comment `<!-- upstream: <service> 10.0.<a>.<b> -->` plus a
second response `Location: http://<service>.<domain>.local:<port>/callback`. Document
as a table: source → address → inferred role.

**Confirm:** Two independent signals per node: same address/hostname from a different
endpoint or disclosure class (header vs body vs config), or an in-scope reverse lookup
resolving to the same internal name. One mention on one page is a lead.

**False positives:** Public CDN/LB IPs (not internal — don't claim them); `X-Forwarded-For`
echoing *your own* IP (normal proxy behavior); RFC1918 examples copied from tutorials
(`192.168.1.1` in a snippet — verify against real roles); localhost in generic banners;
sample fixtures. And don't conflate leak with exploit: visible internal IP ≠ SSRF exists
— report which one you have.

**Impact:** "Unauthenticated responses disclose internal topology (N hosts, roles,
ports), removing discovery for a follow-on SSRF/RCE." Medium standalone when
corroborated; normally booked as step one of a chain — with an SSRF present, this leak
upgrades that finding because internal targeting becomes deterministic.

**Remediation:** Strip internal headers/comments from edge responses, redact addresses
in client-facing errors, and put health/debug endpoints behind authz.

**Field notes (2026-10-21, Envoy/k8s sidecar on a public subdomain):**
- **`x-envoy-decorator-operation` hands over the internal Kubernetes service FQDN.**
  `eventlogger-publisher-frontend.eventlogger.svc.cluster.local:80/*` tells you the mesh
  (Envoy), the namespace, the service name, the target port *and* the component's
  purpose in one header — a whole V-04 map from a single unauthenticated `GET`. Add it to
  the Detect sweep alongside `X-Backend-Server`/`Via`/`X-Real-IP`; it is emitted on
  **every** response from that host, not just errors.
- **Corroborate before you claim it as the app's.** Same session, same CDN: the header was
  present on every `el.*` response and absent on `quizlet.com`, `study.*` and `jg7y.*`
  responses → it is that one service's, not a zone-wide CDN injection. Scope your claim to
  the host that emits it, and note the pairing that makes it matter: this host was also an
  unauthenticated POST-only event sink, so a future SSRF lands one hop from the service the
  header names.
- **The mesh header arrives with the origin-infrastructure header.** `via: 1.1 google`
  alongside Envoy headers means GCP L7 LB → mesh → pod; the *chain* is the useful map
  (internet → CF → Google LB → Envoy → k8s Service), not either header alone.
- **Cheap adjacent route check:** a service like this usually has a `/status`, `/metrics`
  or `/healthz`. Probe them — and if the WAF hard-blocks exactly that path, that block is
  itself evidence the endpoint exists and is worth re-testing from an allowed network
  rather than "ruling it out".

**CWE / OWASP:** CWE-200, CWE-668 (Exposure of Resource to Wrong Sphere) — OWASP
A05:2021; WSTG-INFO-02/05.

---

## V-05: Arbitrary resource harvesting via unprotected directory indexing filters

**Mechanism:** Servers list directories when no index file exists (`autoindex on`,
IIS `Indexes`, object-store list permission). Violated assumption: "nobody guesses the
URL" — the listing hands over *and* enumerates: `Index of /uploads/` shows
`contract_final.pdf`, `id_scan_2024.jpg`, and stale files never linked but never
deleted. The listing is a filter bypass: you see what the UI would hide.

**Preconditions:**
- Directory lacks an index file (or the lister needs no auth); listing enabled.
- Files inside are fetchable — listing + 403-on-file is a dead end, so check both.

**Detect:**
1. Request dirs with/without trailing slash: `/uploads/`, `/files/`, `/static/`,
   `/backup/`, `/tmp/`, `/export/`, `/data/`, `/private/`. Recognize `Index of /`,
   `parent directory` links, nginx/IIS listing styles, object-store JSON listers.
2. Read the listing for payload value: `.env` inside (→ V-11), `*.sql`/`*.bak` (→ V-01),
   user uploads with PII — the reportable core — and `.git` dirs.
3. Walk one level deep (`/uploads/2024/…`) — depth is where sensitive files hide.
4. Note names the UI deleted but the listing still shows — a leak *and* a hint for
   `path-traversal-testing` about what exists on disk.

**Proof of concept:**
```http
GET /<dir>/ HTTP/1.1
Host: <TARGET.HOST>
```
Observed: 200, `Index of /<dir>/` with N entries including `<sensitive>.pdf` (name only
in evidence). Fetch one file: 200 → harvestable content; 403 → listing-only, downgrade.

**Confirm:** The listing yields a file that (a) fetches and (b) is linked from nowhere
in the app UI — link-check it against sitemap/HTML. That pair separates "index of public
statics" from "arbitrary resource access".

**False positives:** Listings of purely public assets (`/static/css/` of a library
CDN — informational at best); listings containing only `index.html`; fake/soft-404
listings (compare a nonexistent subdir); synthetic sample data; out-of-scope staging;
every file 403ing (listing of names only, low); object-store lists of buckets holding
only a README (apply V-10's bar: public-by-design with no PII = N/A).

**Impact:** Unauthenticated bulk harvesting: "any user's upload in `/<dir>/` is
enumerable and downloadable — filenames alone reveal PII." Severity follows content:
PII/documents → high; source/config → high (V-01/V-11); public statics → informational.
State auth level and count.

**Remediation:** Disable indexing (`autoindex off;` / `Options -Indexes`), serve uploads
via authenticated handlers or signed URLs, and delete rather than hide once unlinked.

**CWE / OWASP:** CWE-548 (Directory Listing), CWE-200 — OWASP A01/A05:2021;
WSTG-INFO-03.

---

## V-06: Hardcoded sensitive cryptographic keys, client secrets and token extraction

**Mechanism:** Secrets get baked into things clients fetch: JS bundles, mobile APKs,
page source, JSON configs. Violated assumption: "obfuscated = secret" — `atob()`,
rot13, and webpack minification stop nobody. Prizes: JWT HMAC secrets, private TLS
keys (`-----BEGIN`), cloud keys (`AKIA…`), Stripe/Slack/Google tokens, DB URLs.

**Preconditions:**
- The secret is delivered to, or discoverable by, the client.
- It is *server-relevant* (signing, service auth, privileged API) — not a documented public identifier (OAuth `client_id`, URL-restricted publishable keys).

**Detect:**
1. Pull every JS asset (from HTML, sourcemaps — V-09) and grep the `payloads.md` §1
   secret patterns: private-key blocks, `AKIA[0-9A-Z]{16}`, `ghp_`, `xox[baprs]-`,
   `sk_live_`, `AIza…`, `ya29.`, JWT triples `eyJ….eyJ….`, `postgres://user:pass@`.
2. Decode first: `atob(...)`, hex literals, webpack string-array obfuscators — decode,
   then re-grep. Sourcemaps make this trivial (`sourcesContent` is original source).
3. Also check inline `<script>` blocks, `manifest.json`, `.well-known/*`, then APKs
   (authorized scope only, per the program's mobile policy).
4. Pattern-match locally; never paste raw hits anywhere before the redaction checklist
   (`payloads.md` §6).

**Proof of concept:**
```bash
curl -sS "https://<TARGET.HOST>/<asset>.js" | \
  grep -oE 'AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|sk_live_[0-9A-Za-z]+|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}'
```
Observed: one match of class `<key-type>` at byte offset N in `<asset>.js`. Verify
read-only: *decode* a JWT to show `alg: HS256` + secret presence — forging tokens for
real sessions crosses into `bac-idor-testing` and needs explicit authorization.

**Confirm:** Two signals: format matches a live service **and** functional evidence —
a read-only API call using a *test account you own*, or a JWT decode showing it signs
the app's real session format. Pattern alone = lead; say "pattern not verified" if you
can't functionally test.

**False positives:** Public-by-design values: OAuth `client_id`, reCAPTCHA *site* keys
(`6Le…Ac`), Stripe `pk_live_`, URL-restricted Google Maps browser keys, Firebase API
keys with scoped rules; example keys in README/tutorial code; expired tokens;
`process.env.X` placeholders never populated; regex over-match on hex hashes/base64.

**Impact:** Capability phrased: "a hardcoded <service> credential with <scope> is
readable by anyone who loads the public bundle; rotation required regardless of
exploitation." High/critical for signing keys (session-forging capability) and live
service creds; don't inflate for client-ID-only configs. Evidence = location + redacted
pattern, never the value.

**Remediation:** Broker secrets behind a server-side authenticated endpoint, rotate the
exposed credential immediately (shipped = public forever), and secret-scan CI artifacts
so this fails the build.

**Field notes (2026-10-21, hashed-bundle SPA):**
- **Grep the app's config block with app-specific keys, not just generic regexes.** The
  generic AKIA/ghp_/AIza/JWT/private-key sweep came back empty; the hit came from
  `[A-Z0-9_]*(API_KEY|_DSN|_TOKEN|_SECRET):"` over every chunk, which surfaced a `PB2_*`
  config object containing a Customer.io site-id + API key + testing-key triple in every
  visitor's download. Do BOTH passes; the config-block pass is where real creds hide.
- **Credential-validation oracle:** the same endpoint answered
  `Missing session cookie or API key (use header 'X-Phantombuster-Key' or query 'key')`
  for no credential vs `API key not found` for garbage — the missing/invalid message split
  = per-key existence oracle (validates leaked/brute-forced keys), AND the message itself
  discloses that auth keys are accepted in the **query string** (Referer/log/history
  leakage). Probe missing/empty/quote/traversal/array/6000-char inputs and compare
  *messages*, not codes.
- A config block also enumerates third-party staging tenants (support-desk, invoicing,
  auth-vendor URLs, a second API domain, a dev Disqus shortname) — treat as surface-
  expansion intel; do NOT actively probe those hosts without explicit scope.

**Field notes (2026-10-24, Next.js pages-router behind Akamai):**
- **The bundle is an endpoint inventory, not just a secret source.** A Next.js production
  build hands you the *whole* route table for free: `/_next/static/<buildId>/_buildManifest.js`
  lists every page route (including `/admin`, `/auth/callback` that the site never links to),
  and grepping the chunks for the API-wrapper call shape recovers every server route with its
  verbs and query params. Because client code calls APIs through one helper
  (`axios.create` → `url:"/api/proxy".concat(path)`), **search for that single prefix and for
  `.post("/…")` / `.get("/…")` / `(0,mod.i)("…","METHOD")` rather than hunting URLs** — one
  pattern yields the entire backend surface. Derive `buildId` from `<script id="__NEXT_DATA__">`
  in the page source. Then split the results: routes *outside* the common wrapper (here a bare
  `/api/business/massAssignment` when everything else went through `/api/proxy`) are prime
  authz-bypass suspects precisely because they skip the shared auth layer.
- **Static assets can be gated harder than the HTML.** Akamai Bot Manager served the page but
  403'd every `/_next/*` chunk — including chunks the HTML itself references — while curl's
  `_abck` was `-1`. The cookie's `~N~` flag is the tell: `-1` = bot, `0` = validated. curl
  cannot mint a `~0~` (the JS sensor runs in the browser), but **an operator-supplied browser
  cookie seeds a jar that Akamai then re-issues as `~0~`, unlocking manifests, chunks and
  sourcemaps.** Ask the operator to paste their `_abck` before concluding sourcemaps are
  unreachable. Conversely, do not conclude "no buildManifest" from a 403 — that's the bot
  gate, not the file's absence.
- **Route manifests expose intent, not just paths:** client-side-guarded pages returned `200`
  with only the site shell (`pageProps` = header/footer), so a 200 on `/admin` proved nothing;
  the security-relevant surface was the `/admin/*` API, whose auth is a `?token=<jwt>` **query
  parameter** — visible straight from the bundle and reportable on its own (Referer/log/history
  leakage) without ever needing to crack the auth.

**CWE / OWASP:** CWE-798, CWE-321/CWE-312, CWE-200 — OWASP A07:2021.

---

## V-07: GraphQL introspection query data schema leakage exploitation

**Mechanism:** Introspection (`__schema`, `__type`) is enabled by default in most
GraphQL stacks and returns the entire API surface: types, fields, arguments, and — the
good part — mutation names hinting at privileged operations (`adminResetPassword`,
`internalTransfer`). Violated assumption: "introspection is a dev convenience" — in
production it's a complete API map for unauthenticated clients.

**Preconditions:**
- A GraphQL endpoint exists (`/graphql`, `/api/graphql`, `/gql`).
- Introspection not disabled (`disableIntrospection`, depth limits, WAF stripping `__schema`).

**Detect:**
1. Locate: `POST /graphql` with `{"query":"{__typename}"}` →
   `{"data":{"__typename":"Query"}}` confirms GraphQL; HTML back → try other paths/GET `?query=`.
2. Minimal introspection (template in `payloads.md` §5): `{ __schema { types { name } } }`
   → resolves = ON; `Field "__schema" is not defined` = OFF (a negative, not a finding).
3. Dump deeper: `queryType`/`mutationType` (write ops), `subscriptionType` (a separate
   WS surface), ENUM types (status/role vocab), `deprecationReason` (removed-but-present
   features).
4. If blocked, try the bypass ladder: `__type(name:"Query")`, fragment-based variants,
   the `graphql-ws` transport, GET/`?query=` form — some WAFs match POST bodies only.
   A depth-limit error on a `__schema` query still proves introspection exists (evasion: `payloads.md` §5).

**Proof of concept:**
```http
POST /<graphql-path> HTTP/1.1
Host: <TARGET.HOST>
Content-Type: application/json

{"query":"{ __schema { queryType { name } mutationType { name } types { name kind } } }"}
```
Observed: 200 with `{"data":{"__schema":{…,"types":[{"name":"User",…},{"name":"Admin",…}]}}}`.
Follow up: `{ __type(name:"User") { fields { name type { name kind } } } }`.

**Confirm:** Beyond the type list: issue one benign, read-only operation naming a
disclosed field (`{ <disclosedField> { id } }`, your own data only) — schema matching
live behavior. A schema nothing resolves against is often stale/ornamental.

**False positives:** Disabled-introspection errors (negative result); deliberately
published schemas (docs sites, demo playgrounds — check scope/ownership); gateway
returning `__typename` only; proxied third-party APIs (different owner); sample apps
(Hasura/Dgraph demo schema). And the sensitivity line: a public content API's schema
(blog posts) isn't a finding — schema matters when it exposes sensitive types, roles,
PII fields, or privileged mutations.

**Impact:** "Unauthenticated attackers obtain the complete API schema including <M>
mutations — notably `<privileged-mutation>` — converting blind fuzzing into targeted
testing of <role-bearing> operations." Medium alone; escalate with privileged mutation
names or authz-sensitive fields, and always note the schema is the *map* feeding
`bac-idor-testing`.

**Remediation:** Disable introspection in production (`NoSchemaIntrospectionCustomRule`,
`introspection: false`), gate any schema access behind auth, and rate-limit `__schema`
at the WAF while publishing docs separately if desired.

**CWE / OWASP:** CWE-200, CWE-16 — OWASP A05:2021; WSTG-INFO-08; OWASP GraphQL Cheat Sheet.

---

## V-08: Heartbleed-style memory dump extraction via protocol heartbeat vulnerabilities

**Mechanism:** A heartbeat length bug (CVE-2014-0160, OpenSSL ≤1.0.1f) lets the client
claim `payload_length` larger than the payload; the server echoes *adjacent heap
memory* — tickets, private keys, cookies, passwords in flight. Violated assumption:
"TLS records are length-checked." The general lesson: any protocol with an unchecked
length field (DTLS, legacy RPC) is the same shape of bug — over-read, not overflow.

**Preconditions:**
- TLS terminated on a vulnerable implementation (classic: OpenSSL 1.0.1–1.0.1f; V-02 banner may hint); heartbeat extension enabled.
- Endpoint in scope and you understand you're touching *other users'* memory — heightened legal care; keep probes minimal (a flood can crash old servers — DoS guardrail).

**Detect:**
1. Fingerprint first: `openssl s_client -connect <TARGET.HOST>:<PORT> -tlsextdebug` —
   is heartbeat advertised?
2. One library probe: `nmap -p <PORT> --script ssl-heartbleed <TARGET.HOST>` or
   `testssl.sh --vulnerable`. One run is the signal — do not loop it against production.
3. Only with explicit authorization: a *single* malformed heartbeat returning bytes
   beyond your payload (report existence + byte count, not content).
4. Same shape elsewhere (DTLS, legacy length-prefixed services) only if the program's
   scope covers them.

**Proof of concept:**
```bash
nmap -p <PORT> --script ssl-heartbleed <TARGET.HOST>
# expected vulnerable output (redacted):
# | ssl-heartbleed: VULNERABLE:
# |   The TLS/DTLS Heartbeat extension returns raw memory
# |   State: VULNERABLE
```

**Confirm:** Two independent signals: nmap **and** testssl.sh agreeing, or the raw probe
returning out-of-payload bytes; plus version corroboration from V-02 (`OpenSSL 1.0.1f`
in banner/ServerHello). A single tool without a corroborating signal stays a lead —
heartbleed scanners false-positive on middleboxes.

**False positives:** Middleboxes/IDS answering on the server's behalf; stale signatures
on patched-but-similar builds (require actual extra bytes returned); "vulnerable" when
the server never negotiates heartbeats on the public endpoint; adjacent TLS issues
(ROBOT, renegotiation) misattributed to heartbleed; misparsed extension support.
Heartbleed is a decade old — most sightings are false; two signals or nothing.

**Impact:** Memory disclosure at handshake: private-key recovery (full TLS
impersonation), session cookies, in-flight credentials of *other users* — the most
severe class here when real. Report capability + byte count; never include captured
memory (others' data) in evidence. Remediation includes key rotation because residency
is unknown.

**Remediation:** Upgrade the TLS terminator to a patched release, restart to purge
resident state, rotate the TLS private key and any possibly-cached session material.

**CWE / OWASP:** CWE-126 (Buffer Over-read), CWE-119 — OWASP A06:2021; CVE-2014-0160.
