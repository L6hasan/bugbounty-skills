# RCE Variants — Part 1 (V-01 … V-05)

Deep playbook sections for the first five variants. Work the **Detect**
steps in order, climb the ladders in `payloads.md` only as far as impact
proof requires, and check **False positives** before writing anything up.

## Table of contents

- [V-01: OS command string injection via unsanitized input concatenation](#v-01-os-command-string-injection-via-unsanitized-input-concatenation)
- [V-02: Language-specific code argument injection via dynamic code evaluators](#v-02-language-specific-code-argument-injection-via-dynamic-code-evaluators)
- [V-03: Arbitrary object instantiation via insecure deserialization protocols](#v-03-arbitrary-object-instantiation-via-insecure-deserialization-protocols)
- [V-04: File upload and malicious web shell execution architectures](#v-04-file-upload-and-malicious-web-shell-execution-architectures)
- [V-05: SSTI RCE via template engine fingerprinting](#v-05-ssti-rce-via-template-engine-fingerprinting)

## V-01: OS command string injection via unsanitized input concatenation

**Mechanism:** The application builds a shell command by concatenating user
input into a string passed to `system()` / `exec($cmd)` / `os.system(cmd)` /
`child_process.exec(...)`. Shell metacharacters in the input become syntax
instead of data — the trust assumption "input is a value" is violated the
moment the string hits the shell.

**Preconditions:**
- The param flows into a *shell string*, not a fixed argv array (`execve`-style
  calls without `/bin/sh -c` are not injectable this way — check which sink you have)
- Metacharacters (`; & | $ \` \n`) survive validation, or the filter is bypassable
- A shell exists in the runtime image (distroless/scratch containers don't)
- Common homes: ping/health-check, export/convert, "diagnostics", dig/lookup features

**Detect:**
1. Inventory candidate params: `host`, `ip`, `domain`, `file`, `format`,
   `dest`, plus regression-y features named `ping`, `check`, `trace`.
2. Send the benign baseline (`host=example.com`), record timing + response shape.
3. Safe probe first: `example.com;<PLACEHOLDER_OOB_DOMAIN>.<TOKEN>` (ladder §1
   in `payloads.md`) — expect a DNS/HTTP hit on your collaborator. DNS-only
   (`nslookup`) before HTTP keeps the first step minimal.
4. No callback? Try time-based with *scaling*: `; sleep 3` then `; sleep 7`
   then `; sleep 3`. Linear scaling with your values is control, not noise.
5. Only after 3+4: one benign output probe (`; id #`) for a reflected uid —
   that is your impact proof ceiling in production.
6. Filtered? Escalate encodings: `${IFS}`, `%0a`, `%0d%0a`, `ca""t`,
   `{cat,/etc/hostname}`, base64 pipe (payloads.md §1/§3). Windows targets:
   `&`, `|`, `%COMSPEC%`, case flipping; note `\r\n` for header contexts.

**Proof of concept:**
```
GET /api/ping?host=<PLACEHOLDER_HOST> HTTP/1.1

baseline: host=example.com
OOB:      host=example.com;<PLACEHOLDER_OOB_DOMAIN>.<TOKEN>
time:     host=example.com; sleep <N> #
```

**Confirm:** Two orthogonal signals — the collaborator DNS query name embeds
your payload context (shell parsed the `;`) *and* the sleep scaling or the
reflected `id` reproduces on re-send. A lone collaborator hit or a lone slow
response is not confirmation.

**False positives:** The app resolves your hostname with its own DNS lookup —
your collaborator gets a hit even with *no* injection (the query name tells
you: a plain lookup of your domain ≠ shell-parsed `;` payload). Ping tools
that return non-zero exit text that happens to contain your input is
reflection, not execution. WAF/browser synthetic checks hitting your OOB.
App-level `timeout` mimicking a sleep — hence scaling.

**Impact:** Remote code execution as the service account — read/modify app
data and secrets, pivot into the internal network (pair with `ssrf-testing` V-01/V-03), and
on shared hosts, affect other tenants. Phrase as "RCE as `<user>` on
`<host-class>` with access to `<app secrets class>`", not "I own the server".

**Remediation:** Invoke the binary with a fixed argv array (no shell) and
validate values against a strict allowlist regex (e.g. hostname grammar)
before the call — never interpolate input into a shell string.

**CWE / OWASP:** CWE-78 (OS Command Injection); OWASP Top 10 A03:2021
Injection; WSTG — Testing for OS Command Injection.

## V-02: Language-specific code argument injection via dynamic code evaluators

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

## V-03: Arbitrary object instantiation via insecure deserialization protocols

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

## V-04: File upload and malicious web shell execution architectures

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

## V-05: SSTI RCE via template engine fingerprinting

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

