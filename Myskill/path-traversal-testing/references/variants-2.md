# Path Traversal / LFI & RFI Variants — Part 2 (V-09 … V-15)

Deep playbook sections for variants 9-15. Read `payloads.md` alongside these
for the shared encoding matrix, wrapper templates, canary catalogue, and tool
commands. Execution proofs in these variants are lab-only (guardrail).

## Table of contents

- [V-09: LFI to RCE via PHP wrappers execution flow (php://filter, php://input, data://)](#v-09-lfi-to-rce-via-php-wrappers-execution-flow-phpfilter-phpinput-data)
- [V-10: Path traversal via nested archive unpacking flaws (Zip Slip)](#v-10-path-traversal-via-nested-archive-unpacking-flaws-zip-slip)
- [V-11: Local file access via symbolic link (symlink) file upload invalidation](#v-11-local-file-access-via-symbolic-link-symlink-file-upload-invalidation)
- [V-12: WAF bypass path traversal via Unicode/UTF-8 alternate slash character mappings](#v-12-waf-bypass-path-traversal-via-unicodeutf-8-alternate-slash-character-mappings)
- [V-13: LFI resource hijacking via PHP session file poisoning (/var/lib/php/sessions/)](#v-13-lfi-resource-hijacking-via-php-session-file-poisoning-varlibphpsessions)
- [V-14: Path traversal via Nginx alias misconfiguration string splitting](#v-14-path-traversal-via-nginx-alias-misconfiguration-string-splitting)
- [V-15: Arbitrary root configuration file read via static asset mapping misconfigurations](#v-15-arbitrary-root-configuration-file-read-via-static-asset-mapping-misconfigurations)

## V-09: LFI to RCE via PHP wrappers execution flow (php://filter, php://input, data://)

**Mechanism:** PHP stream wrappers redefine what "a path" means. `php://filter/
read=convert.base64-encode/resource=X` returns X *transformed* (source
disclosure without executing anything — the safe proof); `php://input` reads
the raw request body; `data://text/plain,…` supplies inline bytes; `zip://`,
`phar://`, `expect://` open other streams entirely. When user input becomes the
wrapper string, the violated assumption "a path is a filesystem location" —
and, for the executing wrappers, "file content is inert until a real file
exists".

**Preconditions:**
- PHP sink taking user path input: `include`, `readfile`, `file_get_contents`,
  `fopen`, `imagecreatefrom*` (some honor wrappers)
- Wrapper not disabled: `php://filter` works with plain reads (no
  `allow_url_include` needed — it's the reliable production probe);
  `php://input` / `data://` **inclusion** additionally needs
  `allow_url_include=On` (older/loosely-configured stacks — verify, never assume)
- No `://` rejection and no wrapper allowlist; `open_basedir` absent or loose

**Detect:**
1. Wrapper probe ladder, read-only first (payloads.md §2): submit
   `php://filter/convert.base64-encode/resource=<PLACEHOLDER_CANARY_PATH>` and
   base64-decode the response — expected: exact canary bytes. This single probe
   proves wrapper handling *and* delivers the impact proof safely.
2. Wrapper-support probe: `data://text/plain,WRAPPER-PROBE-<TOKEN>` — the token
   coming back means `data://` parses (note: your own text returns, so this
   proves wrapper support, *not* file read — don't confuse the two when writing up).
3. Read error taxonomy: "No such file" (path reaches the FS), "operation not
   supported" / "URL-file-access disabled" (wrapper exists but is restricted),
   value echoed unchanged (no wrapper processing at all). Each error names a
   different block — record it before escalating.
4. Relative-anchor variants: `php://filter/…/resource=<KNOWN_LOCAL_FILE>`
   inside the include dir, `/proc/self/cwd/<APP_FILE>` (cwd-relative anchor),
   `file://` prefix — useful when absolute paths are prefixed by the app.
5. Chain vectors for depth: `zip://<UPLOADED_FILE>#<ENTRY>` and `phar://…`
   (V-10/V-11 uploads) — read-only, and `phar://` metadata deserialization is a
   bonus class worth noting.
6. **Lab-only execution stage:** `php://input` with a POST body containing
   `<?php echo 'WRAPPER-OK'; ?>`, `data://text/plain;base64,PD9waHAg…`,
   `expect://id` — one benign marker in a lab clone. Production proof stops at
   the base64 read (guardrail).

**Proof of concept:**
```
GET /download?file=php://filter/convert.base64-encode/resource=<PLACEHOLDER_CANARY_PATH>
→ base64 response → decode → canary bytes          # read-only impact proof

# lab only (execution):
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

## V-10: Path traversal via nested archive unpacking flaws (Zip Slip)

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
# craft (template):
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

## V-11: Local file access via symbolic link (symlink) file upload invalidation

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
# craft (template):
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

## V-12: WAF bypass path traversal via Unicode/UTF-8 alternate slash character mappings

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

## V-13: LFI resource hijacking via PHP session file poisoning (/var/lib/php/sessions/)

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

## V-14: Path traversal via Nginx alias misconfiguration string splitting

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

## V-15: Arbitrary root configuration file read via static asset mapping misconfigurations

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
