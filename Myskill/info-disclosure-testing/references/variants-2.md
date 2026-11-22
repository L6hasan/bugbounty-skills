# info-disclosure-testing — Variants 9-15 (references/variants-2.md)

Deep playbook for the second half of the leak matrix — frontend artifacts, cloud
storage, config/API/log files, and metadata. Read §4 of `SKILL.md` for the
verification standard first: in every one of these variants the finding lives or dies
on *sensitivity triage* (public bucket ≠ bug; public bucket with PII = report). Path
wordlists, curl templates, bucket verification, and the redaction checklist live in
`payloads.md`.

## Table of contents

- [V-09: Client-side source map leakage for de-obfuscating frontend application logic](#v-09-client-side-source-map-leakage-for-de-obfuscating-frontend-application-logic)
- [V-10: Cloud storage bucket data leaks via open/public AWS S3 / GCP bucket permissions](#v-10-cloud-storage-bucket-data-leaks-via-openpublic-aws-s3--gcp-bucket-permissions)
- [V-11: Leaked infrastructure secrets via exposed environmental files (.env, config.json)](#v-11-leaked-infrastructure-secrets-via-exposed-environmental-files-env-configjson)
- [V-12: API documentation leaks via public Swagger / Postman collection endpoints](#v-12-api-documentation-leaks-via-public-swagger--postman-collection-endpoints)
- [V-13: Verbose log file leaks via unsecured log rotation directories (/log/, /logs/)](#v-13-verbose-log-file-leaks-via-unsecured-log-rotation-directories-log-logs)
- [V-14: Internal domain/hostname leakage via intranet SMTP/email header metadata](#v-14-internal-domainhostname-leakage-via-intranet-smtpemail-header-metadata)
- [V-15: Metadata information extraction from publicly uploaded documents (EXIF data leakage)](#v-15-metadata-information-extraction-from-publicly-uploaded-documents-exif-data-leakage)

---

## V-09: Client-side source map leakage for de-obfuscating frontend application logic

**Mechanism:** Bundlers ship `//# sourceMappingURL=<file>.js.map` (or a `SourceMap`
header) beside minified JS; the map contains `sources` and — critically —
`sourcesContent`: the **original unminified source** of the whole app. Violated
assumption: "users only see compiled code" — minification is compression, not secrecy.
Maps also leak comments, internal paths, dead admin routes, and anything that only
"looked hidden" because it was minified.

**Preconditions:**
- Built by webpack/Rollup/Vite/Terser without stripping maps from the production artifact (`hidden-source-maps` not used — those still have guessable filenames).
- The `.map` URL fetches with 200 (maps must be fetchable to work — that's the point).

**Detect:**
1. Fetch main JS assets; grep tails for `sourceMappingURL=`, and check the `SourceMap:`
   response header (some servers advertise it — `payloads.md` §3).
2. Fetch the map and *validate structure*: JSON with `version`, `sources`, `mappings`,
   ideally `sourcesContent` — a 200 HTML page here is a soft-404 (`payloads.md` §2).
3. No comment? Guess: `<asset>.js.map`, strip the hash segment (`app.4f2c1b.js` →
   `app.js.map`), try `assets/`/`static/js/` prefixes (Vite/webpack conventions).
4. Read `sources[]` for the original tree (`webpack://app/src/admin/…`), then grep
   `sourcesContent` for V-06 secret patterns and internal hostnames (V-04).

**Proof of concept:**
```bash
curl -sS "https://<TARGET.HOST>/<asset>.js" | tail -c 200   # → //# sourceMappingURL=app.js.map
curl -sS "https://<TARGET.HOST>/app.js.map" | jq '{version, sources: (.sources|length), has_content: (.sourcesContent != null)}'
# → {"version":3, "sources":87, "has_content":true}
```
Evidence: valid map JSON + one original path from `sources[]` (redact any secret found).

**Confirm:** Two signals: (a) `sourcesContent` behaviorally matches the deployed bundle
(map a minified function back — logic lines up), and (b) at least one `sources[]` entry
that appears nowhere in the minified output (internal path/comment). Map present but
`sourcesContent` null → downgrade: structure disclosure only — say which you got.

**False positives:** `.map` URLs 200-ing to SPA-fallback HTML (validate JSON, never
trust status); maps of *vendor* bundles (jQuery — zero value); `sourcesContent` holding
only generated boilerplate (`runtime.js`); maps of a public open-source repo (if the
content is on GitHub, it's not disclosure — but bundled config *differing* from public
repo still is); out-of-scope staging; name-only maps (low).

**Impact:** "Any unauthenticated visitor recovers the full original frontend source,
including <N> internal routes and <redacted finding: API key pattern> that minification
obscured." Medium alone; high when recovered source holds secrets (→ V-06) or reveals
authz logic/hidden endpoints feeding `bac-idor-testing`. Pull maps early — then re-grep
their content for every other variant's patterns.

**Remediation:** Strip `sourceMappingURL` and don't deploy `.map` for private apps
(`hidden-source-maps` only for server-side debugging), or gate maps behind auth —
note stripping doesn't un-ship secrets already in the bundle (rotate, V-06).

**CWE / OWASP:** CWE-532/CWE-200 — OWASP A05:2021; WSTG-INFO-03.

---

## V-10: Cloud storage bucket data leaks via open/public AWS S3 / GCP bucket permissions

**Mechanism:** Buckets get public ACLs/policies (`"Principal":"*"`, `allUsers`) from a
checkbox, a migration, an old CI role. Three permissions matter: **List** (enumerate),
**Read** (download), **Write** (catastrophic — but you never test it by writing).
Violated assumption: "the URL is unguessable" — bucket names leak from HTML, JS, CT
logs, and headers, and an unguessable URL is not a permission.

**Preconditions:**
- A bucket URL/name is in scope (derived from target pages/JS — many programs scope storage explicitly; check).
- Anonymous permission exists at some level (diagnose which: list, read, write).
- For a *finding*: objects contain sensitive data — the triage line from `SKILL.md` §1/§4.

**Detect:**
1. Harvest names (passive): grep in-scope HTML/JS for `s3.amazonaws.com/<bucket>`,
   `<bucket>.s3.<region>.amazonaws.com`, `storage.googleapis.com/<bucket>`,
   `blob.core.windows.net`, `r2.cloudflarestorage.com`, `digitaloceanspaces.com`,
   `backblazeb2.com`, and app URLs rewritten to storage domains (`payloads.md` §4).
2. Anonymous **list** (read-only GET): `?list-type=2&max-keys=5` (AWS) / JSON `?maxResults=5`
   (GCP) → `ListBucketResult`/JSON keys = listing; `AccessDenied`/403 = listing blocked.
3. Anonymous **read** of one *known* object key (from step 1's page/JS): HEAD → 200 =
   world-readable object even with listing denied (common when key-guessing failed).
4. Never test write/delete/ACL change — read and list only, per `payloads.md` §4's rule.

**Proof of concept:**
```bash
# READ-ONLY enumeration — no PUT/POST/DELETE ever
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

## V-11: Leaked infrastructure secrets via exposed environmental files (.env, config.json)

**Mechanism:** `.env`, `config.json`, `application.yml`, `settings.py`,
`wp-config.php.bak`, `docker-compose.yml` land in webroots or get served by misrouted
static handlers. Unlike a JS bundle these hold *server-side* truth: DB strings, SMTP
creds, JWT secrets, cloud keys, internal URLs. Violated assumption: "dotfile =
invisible" (V-01's sibling — payload is config, not code).

**Preconditions:**
- File sits in a web-reachable path (webroot, static mount, or an SPA fallback that serves *any* missing path — check that soft-404 variant).
- It contains real values — CI sometimes ships `.env.example` by mistake; empty template = lead, not finding.

**Detect:**
1. Sweep (`payloads.md` §1): `/.env`, `/.env.prod`, `/.env.backup`, `/config.json`,
   `/config.yml`, `/appsettings.json`, `/application.yml`, `/parameters.yml`,
   `/settings.py`, `/wp-config.php.bak`, `/docker-compose.yml`, `/.dockerenv`.
2. Validate *content*, not status: real `.env` = `KEY=value` lines; real JSON parses
   with values (not `<YOUR_KEY_HERE>`); 200 HTML = soft-404 (`payloads.md` §2).
3. Classify keys: DB (`DB_PASSWORD`, `DATABASE_URL`), auth (`JWT_SECRET`,
   `SESSION_SECRET`), cloud (`AWS_SECRET_ACCESS_KEY`), third-party (`STRIPE_SECRET_KEY`,
   `SENDGRID_API_KEY`), internal hosts (→ V-04 chain).
4. Capability check read-only and only against resources you own/test — decode a JWT
   secret's shape, never forge sessions against real users.

**Proof of concept:**
```http
GET /.env HTTP/1.1
Host: <TARGET.HOST>
```
Observed: 200, `KEY=value` lines — evidence is key *names* + masked value shapes:
`DB_PASSWORD=•••• (16 chars, high-entropy)`, `JWT_SECRET=•••• (32 chars)`,
`AWS_SECRET_ACCESS_KEY=•••• (40 chars)`. List keys, mask values, paste nothing.

**Confirm:** Two signals: structure matches the real config format **and** a value is
plausibly live — entropy/shape matches the service's credential format, or it pairs
with an endpoint seen elsewhere (a `DB_HOST` naming the host V-04 found), or
functional read-only corroboration on a test resource you own. Format alone = lead.

**False positives:** `.env.example`/`.env.dist` templates (no live values); illustrative
configs in docs (`"password": "password"`); frontend configs public *by design*
(`NEXT_PUBLIC_*` — only server-side entries count); open-source demo configs; expired
values pointing at decommissioned hosts (still note — stale, lower severity); soft-404
HTML masquerading as 200 (the classic — validate every time).

**Impact:** "Unauthenticated download of production configuration exposes <N> live
credentials including a DB password and JWT signing secret, granting <capability>."
High/critical when live and privileged; medium for low-sensitivity config; template-only
→ hardening note. Rotation is mandatory — the file may have been public a long time.

**Remediation:** Load config from a secrets manager/env injection outside the webroot,
deny dotfiles at the server (`location ~ /\.` → deny), purge `.bak` templates, and
rotate every credential the file contained.

**CWE / OWASP:** CWE-526, CWE-312, CWE-200 — OWASP A05:2021; WSTG-INFO-05.

---

## V-12: API documentation leaks via public Swagger / Postman collection endpoints

**Mechanism:** Frameworks mount docs at `/swagger`, `/swagger-ui`, `/api-docs`,
`/openapi.json`, `/v2/api-docs` (Spring), `/redoc`, `/graphql/altair`; Postman
collections (with example requests carrying tokens/URLs) get pushed to Git or served
raw. Violated assumption: "docs are for our team" — public docs hand over the full
endpoint inventory, auth scheme, and often *hidden/deprecated admin routes* the UI
never links.

**Preconditions:**
- A docs artifact is reachable unauthenticated (or at low-priv — note auth level).
- The spec reflects the *live* API (stale specs are common — confirm against real endpoints).

**Detect:**
1. Probe (`payloads.md` §1): `/swagger.json`, `/openapi.json`, `/swagger-ui.html`,
   `/api-docs`, `/v2/api-docs`, `/v3/api-docs`, `/redoc`, `/rapidoc`,
   `/postman-collection.json`, `/.well-known/openapi`.
2. Validate it's a spec, not a soft-404: JSON/YAML with `openapi:`/`swagger:` keys and
   non-empty `paths` — status 200 proves nothing.
3. Mine it: `paths` (API map), `securityDefinitions` (auth type), undocumented
   `/admin/*`/`/debug/*` paths (note, don't attack yet), parameter names for
   `bac-idor-testing`, `servers[].url` (internal/staging hosts → V-04), and *example*
   values that are real tokens (grep `examples`/`default` for secret patterns → V-06).
4. Postman: fetch and grep `{{variables}}` **and** response examples; check
   `info.name`/authorship to distinguish official published docs from a leak.

**Proof of concept:**
```http
GET /openapi.json HTTP/1.1
Host: <TARGET.HOST>
```
Observed: 200, `{"openapi":"3.0.1","paths":{"/users/{id}":{…},"/admin/reset":{…}}}` —
evidence = path-list excerpt + operation count (redact any secret in examples).

**Confirm:** Two signals: (a) a spec `paths` entry answers live (issue one benign GET —
non-404 proves the spec is current), and (b) at least one *interesting* item from step 3
(admin path, leaked example credential, internal `servers`) — that's what separates a
finding from by-design public reference docs.

**False positives:** Vendor deliberately-published API docs (check their site first —
"your public API has documentation" isn't a bug); demo/sandbox subdomains; gateway
specs whose paths are all `/{proxy+}` (content-free); stale specs where nothing
resolves; third-party specs (Stripe's openapi on someone's mirror); Swagger UI *without*
a reachable spec (no leak beyond knowing the tool exists); official developer-posted
Postman collections.

**Impact:** "Unauthenticated access to the live API specification discloses <N>
endpoints including <privileged/deprecated ones> plus auth scheme details — attackers
enumerate the entire API without traffic analysis." Medium for structure alone (the map
value); high when examples contain real credentials/PII, internal `servers` are listed,
or undocumented admin mutations are exposed.

**Remediation:** Serve specs behind auth or on an internal docs host, strip real
`examples` values at build time, and keep admin/debug paths out of production entirely,
not just out of the spec.

**CWE / OWASP:** CWE-200, CWE-615 — OWASP A01/A05:2021; WSTG-INFO-08.

---

## V-13: Verbose log file leaks via unsecured log rotation directories (/log/, /logs/)

**Mechanism:** Rotated logs (`error.log`, `access.log.1`, `app-<date>.gz`,
`wp-content/debug.log`) land in the webroot or get served by a static handler that
never considered `.log` fetchable — often alongside directory listings (V-05). Logs are
a *time machine* of secrets: stack traces with paths (V-03), URLs carrying
`?token=`/`?api_key=`, session IDs, internal IPs (V-04), user emails (PII), and
occasionally a full `Authorization` header in a debug line.

**Preconditions:**
- A log path is web-reachable (listing, guessable filename, or static route serving `*.log`).
- The log contains something sensitive (verbose level + real traffic — debug logs are juiciest).

**Detect:**
1. Sweep (`payloads.md` §1): `/logs/`, `/log/`, `/error.log`, `/access.log`,
   `/debug.log`, `/app.log`, `/logs/error.log.1`, `/wp-content/debug.log`,
   `/actuator/logfile`, `/server-status`, `/telescope/requests`, `/_profiler/`.
2. Validate content: timestamped, line-oriented entries (`2024-01-01 12:00 ERROR …`,
   `IP - - [date] "GET /path"`) or gzip magic for `.gz`; 200 HTML/SPA fallback = soft-404.
3. Grep fetched content *locally*: `Bearer `, `Authorization:`, `token=`, `password`,
   `Set-Cookie:`, `Exception`, internal IPs, emails. Record counts and line shapes —
   never the values.
4. Check `Last-Modified`/entry dates: live-appending log = ongoing exposure; archived
   one-off = bounded window — both belong in the report's timeline.

**Proof of concept:**
```http
GET /logs/error.log HTTP/1.1
Host: <TARGET.HOST>
```
Observed: 200, `text/plain`, entries dated <range> with <redacted count> secret-shaped
patterns (14 `Bearer <32+ chars>`, 3 traces with `/opt/<app>/` paths). Evidence =
headers + 1-2 masked sample lines.

**Confirm:** Two signals: (a) entries reference *this* target's real traffic (paths/
hosts unique to it, correlated timestamps), and (b) one sensitive pattern structurally
confirmed (a `Bearer` that decodes as a JWT header — decode, don't replay; an exception
naming a V-04 internal path). Optional live-append check: fetch twice a minute apart —
file grows = actively written.

**False positives:** Default server pages (`Welcome to nginx!` is not a log); synthetic
sample logs in demos (`[LOG] user logged in`); a debug.log containing only *your own*
harmless request lines (echoing you back isn't leaking others); another tenant's logs
on shared hosting (verify whose traffic before attributing — could be *more* severe);
compressed logs you can't legitimately interpret; error pages merely *mentioning* a log
path (that's V-03, not an exposed file); out-of-scope staging.

**Impact:** "Unauthenticated read of application logs exposes <N> session tokens /
credentials / emails across <date range> — harvested tokens enable impersonation until
expiry (→ `bac-idor-testing`); traces disclose internal architecture." Tokens/PII →
high (ask for revocation); stack traces/paths only → medium; public access logs with no
secrets → low. State the time window — "months of exposure" matters.

**Remediation:** Move logs outside the webroot, deny `*.log`/log dirs at the server
(`location ~* \.log$ { deny; }`), disable verbose logging in production, and
revoke/rotate tokens found in historical content.

**CWE / OWASP:** CWE-532 (Sensitive Info in Log File), CWE-200 — OWASP A05:2021;
WSTG-INFO-03.

---

## V-14: Internal domain/hostname leakage via intranet SMTP/email header metadata

**Mechanism:** Outbound mail leaks directory infrastructure: `Received:` chains name
every hop (`mail01.corp.example.internal`), `X-Originating-IP` exposes the sending app
server, `Message-ID` embeds internal FQDNs, `X-Mailer`/`Return-Path` reveal MTA and
app version. Violated assumption: "headers are invisible to users" — they're visible to
anyone who can *receive* mail (signup, password reset, contact form). The violated
boundary is intranet → internet: internal naming walks out with every message.

**Preconditions:**
- You can trigger an email to an inbox you own via normal features (not abuse).
- The mail path adds revealing headers (most MTAs and many senders do).

**Detect:**
1. Trigger 1-2 messages (password reset, signup, contact form); get *raw headers*
   (Gmail "Show original", or `python3 -m email` on the file).
2. Parse the chain bottom-up: each `Received:` `by`/`from`/`with ESMTP` token
   (`mail01.<internal>`, `smtp-gw02.private`), `X-Originating-IP:`, `X-Mailer:`,
   `X-MS-Exchange-*` (O365 internal routing names), `Message-ID: <…@smtp.internal>`,
   `List-Unsubscribe:` URLs, `DKIM-Signature d=`.
3. Classify each name: genuine internal FQDN (leak) vs vendor SaaS (`smtp.sendgrid.net`
   — vendor infra, note but don't overclaim) vs public MX (normal, not a leak).
4. Correlate with V-04: `X-Originating-IP` internal or matching a mapped host =
   two-signal topology node.

**Proof of concept:**
```http
POST /<password-reset-endpoint> HTTP/1.1
Host: <TARGET.HOST>
Content-Type: application/x-www-form-urlencoded

email=<your-owned-test-address>
```
Raw header excerpt (redacted): `Received: from <mail01>.<internal-domain>
([10.0.<a>.<b>]) by <target-mx> …` / `Message-ID: <…@<app-internal-host>.<corp-domain>>`.
Evidence = structure with names/IPs masked (`mail01.•••`, `[10.0.•••]`).

**Confirm:** Two signals: the internal hostname in two independent header positions
(`Message-ID` **and** `Received`) or across two mail types — **and** it plausibly
belongs to the target's own infra (matches their naming, resolves nowhere public;
SendGrid's own hostnames aren't "internal leaks").

**False positives:** Standard public relays (`gmail.com`, `amazonses.com` — normal);
`X-Originating-IP` showing the mail SaaS's *public* IP; Message-ID domains of the
provider (vendor infra); *your* mail client's headers at the top of the chain (read
bottom-up — the topmost `Received` is your MTA!); the target's own publicly-documented
MX (published in DNS = not leaked); test senders out of scope.

**Impact:** "Emails to any user disclose internal mail infrastructure and app-server
addresses, extending the internal topology map (V-04) and identifying the origin behind
the CDN; with an SSRF this removes target discovery." Low/medium alone; escalates when
the leak includes a *credentialed* artifact (check link query params for signed tokens)
or enables `ssrf-testing` targeting. Follow the program's policy on masking full
internal FQDNs.

**Remediation:** Configure the MTA/relay to rewrite internal `Received:` details and
drop `X-Originating-IP`, route outbound app mail through an anonymizing relay, and
make `Message-ID` use the public domain only.

**CWE / OWASP:** CWE-200, CWE-668 — OWASP A05:2021; WSTG-INFO-02/04.

---

## V-15: Metadata information extraction from publicly uploaded documents (EXIF data leakage)

**Mechanism:** Files keep history after upload: JPEG/TIFF EXIF (`GPS*`, `Make`/`Model`,
`DateTimeOriginal`), Office metadata (author, `Company`, `LastModifiedBy`, template
paths `C:\Users\<name>\…`), PDF `/Info` + XMP (`Author`, `Creator`, `Producer`),
`docProps/core.xml`. Violated assumption: "uploading strips metadata" — most apps don't
re-encode, so the *file the world downloads* still carries the uploader's private
context: home addresses from GPS, real names, internal hostnames from template paths.

**Preconditions:**
- Files are uploaded and served (to others, publicly, or back to you at a predictable URL) without metadata-stripping re-processing.
- The metadata is *sensitive* — GPS of a person/private site, identity of an internal doc. Camera-model-only EXIF on stock photos is not a finding.

**Detect:**
1. Obtain a file you're entitled to (your own upload, or a public shared asset);
   download it — analysis is local and read-only.
2. Extract: `exiftool <file>` (images *and* Office/PDF — one tool, all of it);
   unzip Office → `docProps/core.xml`/`app.xml`; `pdfinfo`/`strings` for PDFs.
3. Inventory: `GPS*` (geolocation), `Author`/`dc:creator`/`LastModifiedBy`
   (identities), `Company`/`Template`/`Revision` (internal paths & workflow),
   `Make`/`Model` (device), `CreateDate` vs `ModifyDate` gaps (timeline),
   `Producer`/`CreatorTool` (software versions → V-02 fingerprinting).
4. Cross-check context: does EXIF author match the filename/uploader? If *other users'*
   files are reachable at enumerable URLs, that's V-05/`bac-idor-testing` — flag it,
   don't harvest their files.

**Proof of concept:**
```bash
exiftool <downloaded-file-you-are-authorized-to-access>
# observed fields (values redacted):
#   GPS Latitude  : <coordinates present — reported as rounded/omitted>
#   Author        : <redacted — real name>
#   Company       : <internal-company-name>
#   Last Modified By : <redacted — employee name>
```
Evidence = field list with values masked per `payloads.md` §6.

**Confirm:** Two signals: (a) metadata attached to a file *the target serves* (verify
the download URL returns it from the target, not some CDN cache of unrelated content),
and (b) content is real, not sample — GPS resolves plausibly in context, or `dc:creator`
matches a name in the app's own content. Re-read with a second tool (exiftool + exiv2)
to rule out parser artifacts on corrupt files.

**False positives:** Stock/promotional photos with the original photographer's
GPS/author (public by design); camera-model-only EXIF (informational — don't call it a
privacy bug); your *own* upload echoing back (only a finding if others can fetch it);
boilerplate (`Creator: Adobe Photoshop`, `Producer: iText`); blank templates
(`Author: Administrator`); CC/government documents whose metadata is published on
purpose; GPS on a company office already public on a map (say why it matters or don't
report); out-of-scope sample galleries.

**Impact:** "Uploaded documents are served with metadata intact, exposing <uploader
identities / GPS coordinates / internal employee names / software versions> to <anyone
with the link / any other user>." GPS tied to a private individual/site → medium-high
(privacy); employee names + internal template paths → medium (recon feeding V-04/OSINT);
device/software fingerprints only → low/informational. Frame as privacy + recon — the
fix is cheap (server-side strip), which programs like.

**Remediation:** Strip metadata server-side on upload (exiftool `-all=`, image
re-encode, docx core-properties scrub, PDF sanitization), keep originals in a
restricted store, and re-serve only sanitized copies.

**CWE / OWASP:** CWE-200, CWE-359 (Exposure of Private Personal Information),
CWE-215 — OWASP A01/A05:2021; GDPR-adjacent personal-data angle.
