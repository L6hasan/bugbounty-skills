# CSRF Variants 1-8 — core request-shape and token-lifecycle failures

Merged set: classic CSRF taxonomy folded with the v2.1 deep-mutation set; each entry
notes the alternate name it was folded from. Route here from the selection table in
`SKILL.md`.

## Table of contents

- [V-01: POST-based CSRF with hidden form parameter tampering](#v-01-post-based-csrf-with-hidden-form-parameter-tampering)
- [V-02: GET-based CSRF via cross-origin embedded resource traversal](#v-02-get-based-csrf-via-cross-origin-embedded-resource-traversal)
- [V-03: SameSite cookie restrictions and the Lax top-level navigation window](#v-03-samesite-cookie-restrictions-and-the-lax-top-level-navigation-window)
- [V-04: SameSite Strict subdomain takeover cross-context execution](#v-04-samesite-strict-subdomain-takeover-cross-context-execution)
- [V-05: Method-dependent token validation and POST to GET mutation](#v-05-method-dependent-token-validation-and-post-to-get-mutation)
- [V-06: Token omission, deletion and stripping](#v-06-token-omission-deletion-and-stripping)
- [V-07: Blank or null CSRF token acceptance](#v-07-blank-or-null-csrf-token-acceptance)
- [V-08: CSRF token not tied to the user session](#v-08-csrf-token-not-tied-to-the-user-session)

---

## V-01: POST-based CSRF with hidden form parameter tampering
**Also known as:** classic "POST-based CSRF" / v2.1 "Hidden form parameter tampering via POST-based CSRF engine".
**Mechanism:** the browser treats the session cookie as the intent signal for a POST while every hidden input is attacker-chosen — the server honors business fields (user id, email, amount, role) the UI never lets the user edit. Violated assumption: "a well-formed POST from a logged-in browser was intended by that user."

**Preconditions:**
- Session carried in cookies, not an `Authorization` bearer header (bearer APIs are outside CSRF scope).
- Endpoint parses urlencoded/multipart with no effective token, Origin, or custom-header requirement (if one exists, run V-05..V-14 first).
- Victim authenticated; the action is not gated by step-up/password re-entry.

**Detect:**
1. From proxy history, list POSTs whose bodies carry hidden business fields (`user_id`, `email`, `role`, `amount`) the UI never exposes as editable.
2. Replay from your own session with the Cookie header removed — expect 401/403, proving auth is cookie-based.
3. Replay with cookie present but token / Origin / custom header stripped one variable at a time; record status **and** response body **and** side effect — all three, because each control fails differently.
4. Probe which headers are mandatory: drop `X-CSRF-Token`, then `X-Requested-With`; a protected request should die. If nothing changes, note whether protection is absent or header-only.

**Proof of concept:**
```html
<form id="f" method="POST" action="https://<TARGET_HOST>/<STATE_CHANGING_PATH>">
  <input type="hidden" name="<BUSINESS_PARAM>" value="<ATTACKER_VALUE>">
</form>
<script>document.getElementById('f').submit();</script>
```
Full auto-submit page and curl matrix: `references/payloads.md`.

**Confirm:** two signals — the PoC fired from a real browser on an attacker origin with the victim cookie visibly attached (DevTools network), and the persisted state change re-fetched **as the victim**. A curl-only success is a lead, never a confirmation.

**False positives:** curl succeeds but the cookie is `SameSite=Lax` and a genuine cross-site POST would never carry it (hand-assembled cookies prove nothing — that is V-03 territory); a 200 whose JSON body says "invalid token" — status lies, always read the body; POST returns 200 but the flow then demands re-authentication (read follow-up requests); CDN-cached 200s (check `Age`/`X-Cache`, add a cache-buster); token still riding in a header, query param, or double-submit cookie you forgot to strip.

**Impact:** attacker forces any state change the victim can perform (email change, API key creation, orders, invites, follows) — phrase as forced account-state change on this endpoint class, escalating severity where a sensitive endpoint shares the same pattern.

**Remediation:** validate a per-session, per-request token (or exact-origin check) in global middleware before business fields are parsed, so hidden input values are never the sole intent signal.

**CWE / OWASP:** CWE-352; OWASP Top 10 2021 A01 Broken Access Control (legacy A8:2017 CSRF).

---

## V-02: GET-based CSRF via cross-origin embedded resource traversal
**Also known as:** classic "GET-based CSRF" / v2.1 "Cross-origin embedded resource traversal via GET-based CSRF".
**Mechanism:** the endpoint mutates state on a method browsers treat as safe, so no token is checked and the request fires from merely embedding a URL (`<img>`, `<script>`, `<link>`, prefetch, top-level navigation). Violated assumption: GET only reads.

**Preconditions:**
- A GET/HEAD/DELETE (or a GET route like `/delete?id=`) changes state; token/Origin checks are absent on the safe method (common: middleware mounted on POST only).
- For **subresource** vectors the cookie must be `SameSite=None` — Lax cookies are NOT sent on cross-site subresource loads, only on top-level safe navigation (that split is V-03).

**Detect:**
1. Hunt mutations in GET history: `?action=`, `?delete=`, `?approve=`, token-less `logout`, `?unsubscribe=`; confirm with and without cookie — the state delta proves cookie auth + mutation.
2. Try the same path as HEAD and DELETE; one handler behind several methods feeds V-05.
3. Read the cookie's `SameSite` before choosing the vector: `None` → subresource embed works; `Lax` → only top-level navigation (`location.href`, meta refresh, `<form method="GET">` submit).
4. Check for a nonce/token in the query string your replay dropped — a 403 there means the GET itself is protected.

**Proof of concept:**
```html
<img src="https://<TARGET_HOST>/<STATE_CHANGING_GET_PATH>?<PARAM>=<VALUE>">
<script src="https://<TARGET_HOST>/<STATE_CHANGING_GET_PATH>?<PARAM>=<VALUE>"></script>
<script>location.href="https://<HOST>/<GET_PATH>?<PARAM>=<VALUE>";</script><!-- Lax-compatible -->
```
Templates: `references/payloads.md`.

**Confirm:** browser from an attacker origin — network panel shows the cookie actually attached to the embedded request or navigation (cookie attachment first, it rules out the SameSite trap), then the server-side state change on re-fetch.

**False positives:** "GET returns 200" when the action was already applied (idempotent repeat) or the response came from cache — vary a param, read the body, check `Age`; a URL that only *renders* a confirmation page while the real mutation is the follow-up POST (lead, not finding); dropping a nonce param made your replay fail and misled you into thinking the GET alone was the gate.

**Impact:** page view alone triggers the action (delete, approve, unfollow) — weaponizable via a single click in chat or email, which is why report impact should mention "no interaction beyond visiting a URL".

**Remediation:** restrict mutations to POST+ with token/Origin validation (HTTP safe methods), and mount those checks method-agnostically so GET handlers can never be a bypass.

**CWE / OWASP:** CWE-352, CWE-749 (Exposed Dangerous Method); OWASP A01 (legacy A8:2017).

---

## V-03: SameSite cookie restrictions and the Lax top-level navigation window
**Also known as:** classic "SameSite cookie restrictions" + "SameSite cookie restriction bypass" (folded) / v2.1 "SameSite cookie restriction evasion via top-level LaxAllowingUnsafe navigation window".
**Mechanism:** SameSite decides whether the cookie rides a cross-site request at all. Unset = `Lax` in every modern browser: cookies go only on **top-level navigations with safe methods**, plus Chrome's "Lax allow unsafe" quirk — a top-level POST navigation within ~2 minutes of cookie set also carries it. `None; Secure` allows everything; `Strict` blocks all cross-site (→ V-04). Violated assumption: "no token = trivially CSRF-able."

**Preconditions:**
- Cookie `SameSite=Lax`/unset (top-level vectors) or `None; Secure` (any vector).
- For the unsafe-POST window: login that set the cookie happened < ~2 minutes before the victim opens the attacker page (Chrome; window starts at cookie write).
- Endpoint unguarded by token/Origin (otherwise see V-05..V-14).

**Detect:**
1. Inventory `Set-Cookie`: `SameSite` value/absence, `Secure`, `Domain`, lifetime; absent `SameSite` = Lax default in current Chrome/Safari/Firefox.
2. Classify viable vectors per value: Lax → top-level GET nav always, top-level POST nav only inside the ~2-minute window; None → subresource + fetch/XHR; Strict → nothing cross-site (go to V-04).
3. Probe in a real browser from an attacker origin and watch DevTools: *is the cookie in the outgoing request?* That observation is the test — the response code is not.
4. Script "login → open attacker page → auto-POST" for the window, then repeat after 5 minutes to watch the window close (documents the constraint honestly).

**Proof of concept:**
```html
<form id="f" method="POST" action="https://<TARGET_HOST>/<PATH>">
  <input type="hidden" name="<PARAM>" value="<VALUE>"></form>
<script>document.getElementById('f').submit();</script><!-- victim logs in, then opens page within ~2 min -->
```
Lax-safe variant: `<script>location="https://<HOST>/<GET_PATH>?<PARAM>=<VALUE>"</script>`

**Confirm:** (a) DevTools evidence the cookie was attached cross-site under the claimed vector, (b) persisted state change re-fetched as the victim; re-run after the window closes to show which condition you are actually claiming.

**False positives:** curl/Repeater success with a hand-attached cookie (SameSite is browser-enforced only — curl proves nothing about exploitability); tests inside an `<iframe>` (frame navigation is not top-level, so Lax cookies are not sent — the most common self-inflicted dead end); claiming one browser's window for all browsers (Safari/Firefox don't implement the unsafe POST window identically — scope the claim to what you tested); a `Domain=`-scoped cookie appearing on sibling hosts (same-site → that is V-04); an `http://` attacker page vs `https://` target (schemeful same-site makes them cross-site).

**Impact:** frames exploitability of every other variant here — "no token + Lax" reduces to navigation-shaped payloads (V-02/V-05) plus time-windowed POSTs; report the concrete vector you proved, never "SameSite is bypassable" in general.

**Remediation:** keep token/Origin validation as the primary control — SameSite is defense-in-depth only; set `Strict` where UX allows or `None; Secure` deliberately, and shorten cookie lifetime to shrink the unsafe window.

**CWE / OWASP:** CWE-352, CWE-1275 (Sensitive Cookie with Improper SameSite Attribute); OWASP A01 (legacy A8:2017).

---

## V-04: SameSite Strict subdomain takeover cross-context execution
**Also known as:** v2.1 "SameSite=Strict subdomain takeover cross-context CSRF execution".
**Mechanism:** SameSite is a *registrable-domain* boundary, not a host boundary — `Strict`/`Lax` cookies flow to every schemeful same-site sibling (`*.example.com`). An attacker hosting content anywhere in that zone (dangling DNS, unclaimed S3/Azure/GitHub Pages/Heroku CNAME, HTML upload feature) gets same-site status, so even `Strict` cookies ride their requests. Violated assumption: "Strict = no cross-context request possible."

**Preconditions:**
- A takeover-able or attacker-influenced sibling subdomain (usually an in-scope finding of its own — check program rules).
- Cookie `Domain=.example.com` (or attacker hosts where the cookie is scoped); victim logged in.
- Same scheme: `http://evil.example.com` vs `https://app.example.com` is **cross-site** under schemeful same-site rules.

**Detect:**
1. Subdomain enum → dangling CNAMEs to unclaimed cloud targets (S3, Azure, github.io, herokuapp, pantheon) and user-content hosts (`<user>.example.com`).
2. From a page on the candidate subdomain, fire a credentialed request to the app and inspect whether the `Strict`/`Lax` cookie was attached (DevTools) — impossible from a truly cross-site origin, which isolates the mechanism.
3. Confirm cookie scope: any `Domain=` in `Set-Cookie`, or `document.cookie` readable on the sibling host; verify scheme match before writing the claim.

**Proof of concept:**
```html
<form id="f" method="POST" action="https://app.<TARGET_DOMAIN>/<STATE_CHANGING_PATH>">
  <input type="hidden" name="<PARAM>" value="<VALUE>"></form>
<script>document.getElementById('f').submit();</script><!-- hosted on the attacker sibling -->
```

**Confirm:** (a) network capture of the Strict cookie attached from the sibling-hosted page, (b) persisted state change re-fetched as victim; plus an explicit scope note (takeover host in-scope, or chain with the takeover report).

**False positives:** subdomain on a *different* registrable domain (`example.co.uk`, unrelated apex) — not same-site; scheme mismatch (http vs https); you attached the cookie manually rather than the browser doing it; a "takeover" that is only a cloud 404 page — you cannot host HTML there, so no CSRF (takeover ≠ content control); CDN/asset subdomains where the session cookie is never present (cookie path/domain decides).

**Impact:** defeats the strongest SameSite posture (`Strict`) on every unguarded endpoint; if the takeover also allows JS hosting, chain to V-18 for XSS-assisted CSRF. Report the over-broad `Domain=` cookie scope alongside the takeover.

**Remediation:** make session cookies host-only (omit `Domain`), monitor dangling DNS, register predictable sibling domains, and keep token validation so a hostile sibling still cannot forge requests.

**CWE / OWASP:** CWE-352, CWE-346 (Origin Validation Error); OWASP A01 (legacy A8:2017).

---

## V-05: Method-dependent token validation and POST to GET mutation
**Also known as:** classic "Token validation depends on request method" / v2.1 "Request method mutation and tunnelling from POST to GET via client-side overrides".
**Mechanism:** the check lives in a method-specific branch (`if (method=="POST") validate()`) while the handler still processes state on other methods — or the framework honors `_method` / `X-HTTP-Method-Override` *after* validation. Switching method skips the check, keeps the effect. Violated assumption: "the endpoint only accepts the method the UI uses."

**Preconditions:**
- Router maps one path to several methods (or parses an override header/param).
- Validation wired to a single method instead of global middleware; state reachable via GET/PUT/PATCH/DELETE or via override tunnelling.

**Detect:**
1. Capture the token-checked POST; replay byte-identical with `-X GET` (params moved to query), then PUT/PATCH/DELETE; log status **and body** per method.
2. Try override vectors: body/query `_method=POST|PUT`, headers `X-HTTP-Method-Override`, `X-Method-Override` — Rails, Laravel, Spring and Express method-override are all common.
3. Read the 405 + `Allow:` response first: it enumerates accepted methods faster than guessing.
4. Test HEAD too — some stacks run the handler and discard the body, giving a status-only oracle.

**Proof of concept:**
```bash
curl -sS -b '<COOKIE>' 'https://<TARGET_HOST>/<PATH>?<BUSINESS_PARAM>=<VALUE>' \
  -H 'Origin: https://<ATTACKER_ORIGIN>'                 # token enforced on POST, silent on GET?
curl -sS -b '<COOKIE>' -X POST 'https://<TARGET_HOST>/<PATH>' \
  --data '_method=GET&<BUSINESS_PARAM>=<VALUE>'          # override tunnelling
```

**Confirm:** cross-origin browser PoC on the winning method (`<img>`/navigation for GET, auto-form otherwise) with cookie attachment observed in DevTools **plus** the persisted state change — two signals because a "200 on GET" can be a read route that merely resembles the mutation.

**False positives:** GET replay served from cache or an idempotent handler re-reporting prior state (vary params, read body, check `Age`); your replay dropped the token so the app returned the SPA shell with 200 — compare `Content-Type`/body shape, not status; override headers honored only from localhost/trusted IPs; DELETE returning 200 with `{"deleted": false}` — status lies, read the body.

**Impact:** total token bypass on the affected path — same reportable impact as V-01, but the root cause is validation scope, so show the method differential side by side in the report.

**Remediation:** mount token/Origin validation as method-agnostic middleware that runs before routing and fails closed for every non-safe method, parsing override headers before — never after — the security check.

**CWE / OWASP:** CWE-352, CWE-749; OWASP A01 (legacy A8:2017).

---

## V-06: Token omission, deletion and stripping
**Also known as:** classic "Token not validated when omitted" / v2.1 "Total CSRF protection evasion via parameter omission, deletion and stripping".
**Mechanism:** the validator is presence-gated — `if (tokenPresent) check(token)` — so deleting the parameter skips validation entirely; some stacks validate only the first occurrence or a known field name, so renaming/polluting strips it away. Violated assumption: "the token is always checked."

**Preconditions:**
- Validation is per-handler or behind an optional/`nonEmpty` guard, not fail-closed middleware.
- At least one transport where the token can be absent (form, JSON, header, query) — and you know *every* carrier, because stripping only counts when all of them are gone.

**Detect:**
1. Baseline first: replay the legit request with the original token → must succeed, or your replay is broken and every later result is noise.
2. One variable at a time, recording status + body + side effect: (a) parameter deleted; (b) renamed (`csrf`, `_csrf`, `xsrf`, `authenticity_token`, `csrfmiddlewaretoken` — frameworks accept several names); (c) pollution `csrf_token=VALID&csrf_token=junk` (PHP/array parsers take first *or* last — determine which half origin reads); (d) carrier moved — token kept in query but stripped from body, or stripped from `X-CSRF-Token` while body keeps it.
3. Use a **fresh cookie jar per attempt**: lazy token initialization means attempt #1 may create the token your later attempts then succeed against.
4. On success, classify immediately: missing vs blank vs wrong — blank is V-07, report the one you actually proved.

**Proof of concept:**
```bash
curl -sS -b '<COOKIE>' -X POST 'https://<TARGET_HOST>/<PATH>' \
  --data '<PARAM>=<VALUE>' -H 'Origin: https://<ATTACKER_ORIGIN>'          # token deleted
curl -sS -b '<COOKIE>' -X POST 'https://<TARGET_HOST>/<PATH>' \
  --data 'csrf_token=<VALID>&csrf_token=stripped&<PARAM>=<VALUE>'          # pollution
```

**Confirm:** cross-origin PoC with the token absent from **every** carrier (inspect the outgoing request: no hidden input, no header, no query), persisted state change re-fetched as victim, and the with-token vs without-token response differential captured for the report — that side-by-side is what convinces triage.

**False positives:** token still riding in a cookie the app mirrors back (double-submit → V-10, the control may still hold); framework reading a header or second param name you didn't delete — deleting only the body field leaves protection intact while a *different* attempt succeeded; cached 200; error JSON with status 200 (read the body); replaying a token after its rotation consumed it — that 403 does not prove absence is blocked.

**Impact:** "attacker can disable CSRF protection by editing the request" — no token knowledge needed, works against any authenticated victim, small fix diff; typically High on sensitive endpoints.

**Remediation:** fail closed — reject any state-changing request whose token is missing, blank, malformed, or previously consumed, validated in global middleware before the handler runs.

**CWE / OWASP:** CWE-352, CWE-301 (Reflection of Input in Security Decision); OWASP A01 (legacy A8:2017).

---

## V-07: Blank or null CSRF token acceptance
**Also known as:** classic "Blank/null CSRF token".
**Mechanism:** the comparison passes when *both* sides are empty — the session's stored token was never issued (lazy init, pre-auth session, fixation) or validation is loose (`"" == null`, JS `==`, JSON `null` coerced to empty string). Distinct from V-06: the parameter is **present** and still accepted, so a presence-gated check happily validates emptiness.

**Preconditions:**
- A token value is present but empty/`null`/`"0"`, and the stored server-side token is blank for that session **or** validation treats blank==blank/absent as success (loose equality, early return).
- Often visible pre-auth, on new sessions, or where the token was issued before login and never rotated (links to V-17).

**Detect:**
1. With a fresh cookie jar *without* logging in: does the app set a CSRF cookie at all, and is it empty? Capture `Set-Cookie` and any pre-auth token endpoint response.
2. Replay the working request — one fresh session each — with `csrf_token=` (empty), `csrf_token=%20`, `csrf_token=null`, `csrf_token=undefined`, `csrf_token=0`; record status+body+side effect per value.
3. JSON shape via V-13: `{"csrf_token": null}` and `{"csrf_token": ""}` — some parsers map JSON null onto empty-string fields before comparison.
4. Replay a known-valid token as control: if valid fails while blank passes, stored-blank is proven (isolates this from V-06).

**Proof of concept:**
```bash
curl -sS -b '<FRESH_JAR>' -X POST 'https://<TARGET_HOST>/<PATH>' \
  --data 'csrf_token=&<BUSINESS_PARAM>=<VALUE>' -H 'Origin: https://<ATTACKER_ORIGIN>'
curl -sS -b '<COOKIE>' -X POST 'https://<TARGET_HOST>/<PATH>' -H 'Content-Type: text/plain' \
  --data '{"csrf_token":null,"<BUSINESS_PARAM>":"<VALUE>"}'
```

**Confirm:** (a) server-side evidence the stored token for *that same session* is blank (token endpoint returns empty, or valid-token control fails while blank passes), (b) cross-origin browser PoC with an empty hidden field producing the persisted state change. The stored-blank proof is what separates this from a misread V-06.

**False positives:** your earlier probe *initialized* the token — fresh jar per attempt is the single most common mistake here; blank accepted only pre-auth where no privileged action exists (no impact → not a finding); `null` rejected but status was still 200 (read the body); loose comparison only on a *secondary* token field while a primary check still fails (test each token field independently); middleware exempting unauthenticated routes by design — prove blank works on an **authenticated** state-changing endpoint.

**Impact:** complete bypass for every session with no properly issued token — including just-registered or just-logged-in victims; report as "blank token accepted on authenticated state-changing endpoint" with the stored-blank evidence attached.

**Remediation:** initialize a CSPRNG token at session creation (never a pre-login placeholder) and reject absent/blank/malformed tokens using strict type-safe comparison.

**CWE / OWASP:** CWE-352, CWE-287 (Improper Authentication of comparison inputs); OWASP A01 (legacy A8:2017).

---

## V-08: CSRF token not tied to the user session
**Also known as:** classic "Token not tied to user session".
**Mechanism:** validation checks only *that* a well-formed token was sent, not that it belongs to this session/user — the value lives in a global store, derives from public data, is client-generated, or is validated by format/length alone. Violated assumption: knowing a token implies it was issued to this victim.

**Preconditions:**
- Token generation/validation decoupled from session identity (shared token service, client-side generator, per-IP/per-installation token, regex or weak-JWT "verification").
- Typical in SSO/multi-tenant apps and mobile-API gateways reused for web; you need two live sessions (own accounts A and B) to test cross-binding.

**Detect:**
1. Log into account A (profile 1) capture `T_A`; account B (fresh profile) capture `T_B`; cross-swap both directions — A-request with `T_B`, B-request with `T_A` — recording status+body+side effect for all four combinations.
2. The exploit-direction test: cross-origin PoC where the *attacker's* token rides with the *victim's* cookie (attacker page embeds their own token in the form; browser attaches victim cookie). Acceptance here is the real condition.
3. Decode the token: base64/JSON/JWT claims containing your user id or a client-checkable signature means format-only verification — try a forged value directly.

**Proof of concept:**
```bash
curl -sS -b 'session=<VICTIM_COOKIE>' -X POST 'https://<TARGET_HOST>/<PATH>' \
  --data 'csrf_token=<T_ATTACKER>&<BUSINESS_PARAM>=<VALUE>' \
  -H 'Origin: https://<ATTACKER_ORIGIN>'
```
Browser: attacker page auto-submits a form whose hidden token field contains `<T_ATTACKER>` (`references/payloads.md`).

**Confirm:** cross-swap succeeds in **both** directions (rules out one-way luck) **and** the cross-origin attacker-token + victim-cookie PoC produces the persisted state change. One direction alone is a lead — an app can accept foreign tokens yet still bind somewhere upstream.

**False positives:** tokens that look machine-readable but are HMACs of the session id — cross-swap fails, so no finding (always swap before writing); token deterministic per user across that user's own devices (per-user ≠ cross-user); you copied the victim's own cookie+body pair in your harness (that is V-10 and is *your* capability, not an attacker's); replaying your own token into your own session and calling it "static" — that is V-09; per-user tokens accepted only within one account.
  **Proving "globally static" rigorously (Vinted 2026-10 pattern, 4 independent sources):** two
  different logged-in accounts → same value; an anonymous cookie-less GET → same value; the
  tester's token captured from a *different country/IP* → same value. Four readings, one value
  rules out session-, account-, and IP-binding without needing cross-swap. Then bound the impact
  honestly before writing severity: a static token is worthless to a browser attacker if the token
  is only accepted via a **custom header** (cross-origin fetch → preflight → no ACAO → blocked,
  confirm by trying form-field/query/`X-Requested-With` variants — all should 403) *and* session
  cookies are `SameSite=Lax` (cross-site POST sends no auth). Static token + unchecked Origin with
  those two brakes intact is a hardening finding, not Critical — say so; it escalates only when a
  CORS reflection, an XSS, or a `GET`/top-level-navigable state change joins the chain.

**Impact:** attacker with any self-obtained token forges victim requests cross-origin; the same defect usually enables login CSRF / session fixation chaining (V-17). Severity High on sensitive actions; state the cross-user acceptance explicitly with both accounts redacted.

**Remediation:** store the token server-side bound to the authenticated session and user id, reject mismatches, regenerate at every privilege transition, and never trust client-supplied tokens as authoritative.

**CWE / OWASP:** CWE-352, CWE-384 (Session Fixation) when chained, CWE-287; OWASP A01 (legacy A8:2017).
