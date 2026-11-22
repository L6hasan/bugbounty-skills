# Variants 1-8 — transaction integrity, workflow, races, discovery, auth, reset, OTP, complexity

Deep playbook for the first eight business logic variants. Each section follows the same
shape: **Mechanism → Preconditions → Detect → Proof of concept → Confirm → False
positives → Impact → Remediation → CWE / OWASP**. Cross-cutting material lives in
`payloads.md`: read the **workflow mapping procedure** before running V-02, the
**race-condition procedure** before V-03, the **edge-value matrix** alongside V-01/V-07,
and the **Host-header templates** before V-06. Every proof assumes the two-account setup
from `payloads.md` and the guardrails in `SKILL.md` section 1: minimal demonstrable
amounts, tester-owned coupons/accounts only, sandbox tenant first.

## Table of contents

- [V-01: Transaction integrity violation via price, quantity, and currency parameter tampering](#v-01-transaction-integrity-violation-via-price-quantity-and-currency-parameter-tampering)
- [V-02: State machine defiance via workflow circumvention and multi-step transaction skipping](#v-02-state-machine-defiance-via-workflow-circumvention-and-multi-step-transaction-skipping)
- [V-03: Concurrent state processing flaws via distributed race conditions (HTTP/2 request overlap)](#v-03-concurrent-state-processing-flaws-via-distributed-race-conditions-http2-request-overlap)
- [V-04: Administrative interface discovery via URL obfuscation and Unicode path bruteforcing](#v-04-administrative-interface-discovery-via-url-obfuscation-and-unicode-path-bruteforcing)
- [V-05: Authentication flow manipulation via insecure token or session state modification](#v-05-authentication-flow-manipulation-via-insecure-token-or-session-state-modification)
- [V-06: Insecure password reset logic via Host header injection or token leakage](#v-06-insecure-password-reset-logic-via-host-header-injection-or-token-leakage)
- [V-07: OTP/2FA verification bypass via response manipulation or parameter nullification](#v-07-otp2fa-verification-bypass-via-response-manipulation-or-parameter-nullification)
- [V-08: Algorithmic complexity attacks as a DoS-style logic flaw (cgroup/resource exhaustion)](#v-08-algorithmic-complexity-attacks-as-a-dos-style-logic-flaw-cgroupresource-exhaustion)

---

## V-01: Transaction integrity violation via price, quantity, and currency parameter tampering

**Mechanism:** The server builds the charge from client-supplied money fields — unit
price, quantity, currency, discount, shipping — instead of re-deriving them from the
catalog row keyed by product ID. The violated assumption: "the totals the browser
displayed are the totals we charge" — the checkout form is treated as an authority
rather than a suggestion.

**Preconditions:**
- Cart/quote/order endpoint reads money fields from query, form, or JSON body.
- A purchasable item with a known catalog price exists to compare against.
- Tester account with a cart; sandbox/staging tenant preferred per guardrails.

**Detect:**
1. Capture the full checkout chain (add-to-cart → quote → order create) and list every
   money-bearing parameter: `unit_price`, `price`, `qty`/`quantity`, `amount`, `total`,
   `currency`, `discount`, `shipping` — including hidden fields the rendered form never
   showed (they live in the JS bundle and API docs).
2. Record the control: submit the unmodified request, then re-fetch the created order
   (`GET /api/orders/<ORDER_ID>`). That persisted total is your baseline.
3. Tamper one parameter at a time: `unit_price=0.01`, `quantity=0`, `quantity=2` with
   the unit price halved (does the server recompute or trust?), `discount=100`,
   `shipping=0`. One variable per request so the delta is unambiguous.
4. Client-total test: keep price and qty legitimate but send `total=0.01` — recompute
   (healthy) vs. accept (finding) separates the two failure modes.
5. Currency class: `USD`→`JPY` (different minor unit), `USD`→`XXX` or an unlisted ISO,
   lowercase `usd`, and a cents value sent as a currency expecting minor units.
6. Edge values on every money field per the matrix in `payloads.md` (0, -1, 0.001,
   `1e3`, overflow strings) — the sign/overflow rows feed V-10 directly.
7. Re-fetch the probe order and diff against step 2 — persistence, not echo, is signal.

**Proof of concept:**
```bash
# Control: untouched request (expected: persisted total == catalog price)
curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/orders' \
  -H 'Content-Type: application/json' \
  -d '{"product_id":"<PRODUCT_ID>","quantity":1,"currency":"USD"}'
# Probe: single tampered money field
curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/orders' \
  -H 'Content-Type: application/json' \
  -d '{"product_id":"<PRODUCT_ID>","quantity":1,"currency":"USD","unit_price":0.01}'
# Read back the server-persisted amount, cache-busted
curl -sS -i -b jar_a.txt '<TARGET_URL>/api/orders/<ORDER_ID_PROBE>?cb=1'
```

**Confirm:** Two persisted orders differ only in the tampered field — probe order
charges `<0.01/wrong currency>`, control charges the catalog price. Re-fetch must come
from a fresh request; an order-creation response echoing your body proves nothing.

**False positives:** Response echo with the DB untouched; client-side price *preview*
endpoints that never create an order; legitimate discounts or FX conversion producing
explainable differences (compare in one currency after the quote settles); demo/$0
products where 0.01 exceeds the real price; rounding (0.999→1.00) mistaken for tampering;
test tenants where checkout is intentionally free — note the environment in the report.

**Impact:** "Any user can purchase `<item>` for `<amount>` by altering `<param>` — order
totals are computed from client input." Report the one demonstrated price, then state
whether the field is honored for all products (sampled), which is where scale lives.

**Remediation:** Re-price every order server-side from the catalog record keyed by
`product_id`, treat all client money fields as display-only, and reject carts whose
submitted total disagrees with the recomputed total beyond a rounding tolerance.

**CWE / OWASP:** CWE-472 (External Control of Assumed-Immutable Web Parameter) / CWE-20;
OWASP Top 10 A04:2021 Insecure Design (A03:2021 where the field also reaches a query).

---

## V-02: State machine defiance via workflow circumvention and multi-step transaction skipping

**Mechanism:** A multi-step flow (cart→pay→ship, KYC→deposit→trade, draft→review→publish)
advances because the *client* walked the UI: each step's endpoint runs without checking
that the required prior state was reached. The violated assumption — "the next button
only appears when the previous step is done" — is enforced in the browser, not in a
server-side transition table.

**Preconditions:**
- Flow with ≥2 server endpoints that mutate a state field (`status`, `stage`, `step`).
- The state is readable afterward (GET the object, or a second account's view).
- Tester controls a fresh object in each state you need; sandbox first.

**Detect:**
1. Run the **workflow mapping procedure** in `payloads.md` first — record the legitimate
   request order and the state before/after each step. Skipping this produces false
   positives (see that section's "why").
2. Drive a fresh object to step 1, then call step 3 directly (skip step 2). Change
   nothing else — same session, same object id.
3. Re-read state from a fresh GET. Watch for *silent revert*: some apps accept any call
   but normalize the status on read or on a queue drain (poll once after ~30s).
4. Order abuse: step 2 before step 1, step 3 twice, the "complete/finish" endpoint twice,
   and returning an object from a terminal state back to an earlier one.
5. Boundary check: does the step-2 endpoint reject with a state-specific error
   (`409 conflict`, `invalid status`) when called out of order? A *specific* error means
   a check exists — look for the sibling endpoint that lacks it.
6. Note where the check lives: edge/WAF (403), app validation (422), or nowhere (success)
   — this drives the remediation sentence.

**Proof of concept:**
```bash
# State machine as mapped: S1 -> S2 -> S3. Object currently in S1:
curl -sS -i -b jar_a.txt '<TARGET_URL>/api/<FLOW>/<OBJECT_ID>?cb=1'   # expect status=S1
curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/<FLOW>/<OBJECT_ID>/<STEP_3>' \
  -H 'Content-Type: application/json' -d '{}'
curl -sS -i -b jar_a.txt '<TARGET_URL>/api/<FLOW>/<OBJECT_ID>?cb=2'   # buggy: status=S3
```

**Confirm:** A fresh server-side read shows the terminal/advanced state while step 2's
own record (audit row, sub-resource, downstream precondition) shows it never ran — plus
a downstream gated action now succeeds (withdraw without KYC, ship without payment).

**False positives:** Endpoints that no-op when unready (re-read state — it did *not*
advance); flows where step 2 is genuinely optional; async pipelines that revert the
status you "skipped to" on the next queue drain (poll before claiming); test tenants
with checks disabled; soft-200 error bodies (`200 {"error":"state invalid"}` is a
rejection, not a skip).

**Impact:** "The `<flow>` state machine is enforced only in the UI; a user can reach
`<terminal state / gated action>` without completing `<prerequisite step>`." Name the
gated action — the skip matters only for what it unlocks.

**Remediation:** Encode allowed transitions in one server-side table
(`from_state → to_state` + precondition checks) applied at every mutating endpoint,
default-denying any transition whose precondition row is absent.

**CWE / OWASP:** CWE-841 (Improper Enforcement of Behavioral Workflow) / CWE-372
(Incomplete Internal State Distinction); OWASP A04:2021 Insecure Design.

---

## V-03: Concurrent state processing flaws via distributed race conditions (HTTP/2 request overlap)

**Mechanism:** A check-then-act sequence (read `uses_left` → validate → decrement) runs
without an atomic guard, so concurrent requests all pass the check before any of them
commits (TOCTOU). HTTP/2 multiplexing lets 10-20 requests share one connection and land
in a millisecond-wide window; behind a load balancer they fan out to *different* workers
that may not share an in-process lock — hence "distributed".

**Preconditions:**
- State-changing endpoint with a server-side limit, one-time flag, or counter.
- A way to fire a synchronized burst (turbo-intruder gate, script template in
  `payloads.md`) and to read the authoritative state afterward.
- A sequential control that correctly rejects the second request (if it doesn't, this is
  a plain missing check → V-02/V-10, not a race).

**Detect:**
1. Pick candidate single-use actions: apply coupon, redeem, withdraw, claim, vote,
   generate invoice, "apply once per user".
2. Run the sequential control: 3 identical requests with 1s gaps — all must be rejected
   after the first. Record the exact rejection shape (status + body).
3. Fire the burst per the race procedure in `payloads.md` (10-20 requests, one gate,
   HTTP/2) and immediately re-read the state with a cache-busted GET — the *ledger/counter*,
   not the response tallies.
4. Repeat 5-10 rounds: distributed races are probabilistic (scheduling-dependent), so a
   single clean round proves nothing either way.
5. Vary the shape: single vs. two connections, H2 vs. H1.1, 0/5/20ms spread — a real
   race's success rate tracks overlap, jitter's doesn't.
6. Watch for partial application under contention (5xx/timeouts in the burst): a 502
   mid-transaction can still leave a half-applied row — re-read state anyway.

**Proof of concept:** (fill slots; full templates in `payloads.md`)
```python
# Turbo Intruder — synchronized burst over one HTTP/2 connection
def queueRequests(target, wordlists):
    engine = Engine.HTTP2
    for _ in range(<BURST_SIZE>):            # 10-20
        engine.queue(target.baseRequest, gate='race1')
    engine.openGate('race1')
def handleResponse(req, interesting):
    table.addColumn(req, 'status')
```

**Confirm:** The authoritative readback shows two or more successes where the sequential
control allowed exactly one — e.g. two distinct order IDs both carrying a 1-use discount
— reproduced in ≥2 rounds, with each order verified in a fresh request. Response-level
"OK" counts alone are not confirmation.

**False positives:** Idempotency keys working correctly (two 200s, same resource id →
one action); jitter — requests merely *arrived* close together but processed sequentially
(see `payloads.md` for the race-vs-jitter test); cached GET reads inflating counts
(cache-buster mandatory); client-side counting; load-balancer retries of one logical
request; the app having locks and correctly rejecting (specific contention errors are a
*health* signal — but still re-read state).

**Impact:** "Concurrent requests bypass the `<limit/one-time>` enforcement on `<action>`,
yielding `<N>` successes where `<1>` was allowed." Report the demonstrated multiplier
(2×, 3×), never "unlimited" unless you bounded it.

**Remediation:** Make check-and-mutate a single atomic operation — conditional
`UPDATE ... WHERE uses < limit`, unique constraints, or row locks held through commit —
plus idempotency keys so replays converge on one result.

**CWE / OWASP:** CWE-362 (Race Condition) / CWE-367 (TOCTOU); OWASP A04:2021
Insecure Design (A05:2021 where the atomicity gap is a misconfiguration).

---

## V-04: Administrative interface discovery via URL obfuscation and Unicode path bruteforcing

**Mechanism:** Admin functionality is "hidden" behind obscure or obfuscated paths and
protected by path filters that disagree with the router about what a path *is*. Encoding,
case, Unicode normalization (homoglyphs, NFC/NFD), and edge-rewrite headers make the
filter see `/index` while the router serves `/admin` — security through obscurity plus a
normalization mismatch.

**Preconditions:**
- Some admin/backoffice surface exists (or you suspect it does).
- A candidate wordlist (small, curated) and the encoder table in `payloads.md`.
- Polite rate limits: discovery is a numbers game — stay at ≤1-2 req/s.

**Detect:**
1. Harvest candidates before fuzzing: JS bundles and sourcemaps, response headers,
   comments in HTML, docs (`/swagger`, `/graphql`), common words (`admin`, `backoffice`,
   `manage`, `internal`, `console`, `staff`, `wp-admin`, `actuator`, `debug`).
2. Establish the 404 fingerprint first: request three known-bad paths, note status +
   body length + title. SPA catch-alls return `200` for *everything* — fingerprint the
   body, never the status.
3. Probe each candidate with the variation ladder from `payloads.md`: case, trailing
   slash, `//`, `;`, `/./`, `%20`, double-encoding, then Unicode — Cyrillic `аdmin`,
   fullwidth `ａｄｍｉｎ`, mixed-script, NFC vs NFD of the same string.
4. Edge-vs-app differential: try `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Path`
   headers carrying `/admin` while the request path stays benign — a 200/302-to-login
   where the plain path 404s means a rewriting layer disagrees with the router.
5. Read the differentials: `302 → /login` = route exists; `403` vs `404` = filter vs.
   router disagreement; `200 + app shell` = candidate alive (confirm via step 2).
6. Separate *discovery* from *execution*: hitting an admin login page is a lead; the
   finding is an admin action executing for your low-priv session or no session at all
   (that is V-06-style BAC — chain with `bac-idor-testing`).

**Proof of concept:** (ffuf template; `-rate` keeps you polite)
```bash
ffuf -u '<TARGET_URL>/FUZZ' -w <ADMIN_WORDLIST> -b jar_a.txt \
  -rate 2 -mc 200,302,403,401 -fs <404_BODY_LENGTH>
# Unicode variant on one promising candidate
curl -sS -i -b jar_a.txt --path-as-is '<TARGET_URL>/<HOMOGLYPH_ADMIN_PATH>'
# Edge rewrite header variant
curl -sS -i -b jar_a.txt -H 'X-Original-URL: /admin' '<TARGET_URL>/index'
```

**Confirm:** The discovered route serves admin *functionality* — a privileged action
executes (verified by its state change) for your standard-user session or with
credentials stripped. "The URL exists" alone is confirmation only of exposure, not of
bypass; say which one you proved.

**False positives:** SPA fallback returning the app shell for every unknown path
(fingerprint vs. known-bad — the #1 bogus "admin found"); WAF block pages served with
200 (HTML body in a JSON app); generic login pages from an SSO gateway on any path;
properly gated 403s (that is the control working — report nothing); publicly reachable
docs/swagger by design; admin routes on an out-of-scope host.

**Impact:** "An administrative interface is reachable at `<path>` via `<variant>` that
bypasses `<filter>`; privileged action `<x>` executes for standard users" — or, if authz
holds, the weaker "admin path disclosed via `<leak>`". Quantify exactly what you
executed, nothing more.

**Remediation:** Default-deny authorization on every admin route regardless of path, and
normalize/decode the path once at the edge before routing so filter and router always
see the same string.

**CWE / OWASP:** CWE-425 (Forced Browsing) / CWE-552 (Files or Directories Accessible
to External Parties) / CWE-179 (Incorrect Normalization); OWASP A01:2021 Broken Access
Control (A05:2021 where only obscurity is deployed).

---

## V-05: Authentication flow manipulation via insecure token or session state modification

**Mechanism:** Part of the authentication state lives where the client can rewrite it: a
readable `auth=1` cookie flag, an unsigned base64 session blob, an `mfa_verified` claim,
a step-up marker, or a session id the server never rotates. The violated assumption —
"the session object is server-authoritative" — fails the moment a client-edited value
enters a security decision.

**Preconditions:**
- You can observe and modify session cookies/tokens (your own session; Burp/curl).
- A pre-auth and post-auth state to compare (login, step-up, or MFA step of your own
  account).
- A gated endpoint to test the modified session against.

**Detect:**
1. Capture the full cookie/token set before login, after login, and after step-up/MFA.
   Diff them: which values *changed*, and which are readable vs. opaque/signed?
2. Flag-flip test: on a fresh pre-auth session, set the post-auth value manually
   (`auth=0`→`auth=1`, `mfa=0`→`mfa=1`) and hit a gated endpoint. Baseline: does an
   untouched pre-auth session get `401`? (If not, your gate is wrong — fix it first.)
3. Token mutation: decode any base64/JSON blob; edit one claim (`uid`, `role`,
   `exp`, `verified`); re-encode and replay. For JWT-shaped tokens run the JWT checklist
   in `bac-idor-testing` instead of hand-rolling — this variant is about *state flags*.
4. Session fixation: note the session id pre-login, log in, check whether the id rotated;
   replay the pre-auth id from a second client and see whether it carries auth now.
5. Prediction/entropy: collect 2-3 session ids (login/logout loops on your own account),
   look for timestamps, counters, short lengths.
6. One-time marker reuse: replay a consumed ticket (verify-email, step-up) — does the
   server accept it a second time?

**Proof of concept:**
```bash
# Control: untouched pre-auth session against the gate (expect 401/302)
curl -sS -i -c jar_pre.txt '<TARGET_URL>/login'   # do not log in
curl -sS -i -b jar_pre.txt '<TARGET_URL>/api/<GATED_FUNCTION>'
# Probe: flip the client-held auth marker, same fresh session
curl -sS -i -b jar_pre.txt -H 'Cookie: auth=1; mfa_verified=1' \
  '<TARGET_URL>/api/<GATED_FUNCTION>'
```

**Confirm:** The modified state is honored on a *fresh, independent request from a
second client* (another curl process / clean jar), and a gated action or data fetch
succeeds that the untouched pre-auth control was denied. Same-response reflection does
not count.

**False positives:** Framework cookies are HMAC-signed — editing invalidates them and
the server silently issues a *new* session (compare ids: if it changed, your edit was
rejected); you edited a stale id while login rotated the real one (session fixation
ruled out by rotation — that's healthy); the flag is echoed in responses but never read
server-side (control request excludes it); test tenants that pre-authenticate every
session; CDN caching a personalized gate response (check `Age`).

**Impact:** "Authentication state `<flag/claim>` is client-controlled; an unauthenticated
user gained `<authenticated capability>` without credentials." If sessions are fixable or
predictable, phrase the demo as "session reuse across authentication" and note ATO
potential separately from what you demonstrated.

**Remediation:** Keep authentication state server-side keyed by an unguessable session id
that rotates on privilege change; any client-held claim must be integrity-protected
(signed/encrypted) and re-verified at each gated decision.

**CWE / OWASP:** CWE-565 (Reliance on Cookies Without Validation) / CWE-384 (Session
Fixation) / CWE-807; OWASP A07:2021 Identification and Authentication Failures.

---

## V-06: Insecure password reset logic via Host header injection or token leakage

**Mechanism:** The reset link is built from attacker-controllable request input (Host,
X-Forwarded-Host), so the emailed token is delivered to a URL the attacker reads — or the
token leaks through channels the flow never considered (response bodies, URL query →
Referer/logs, missing single-use/expiry). The violated assumption: "the link host and
token channel are ours to decide".

**Preconditions:**
- Password-reset flow exists; you can trigger it for **your own** account and read that
  inbox (own address, own test tenant).
- Program rules allow Host-header testing (header injection stays inside scope hosts —
  if a spoofed host would deliver mail externally, keep the demo to your own listener).
- Templates from the Host-header section of `payloads.md` ready.

**Detect:**
1. Trigger a reset for your own address; save the raw email (headers + body). Note
   exactly how the link's domain is constructed and whether the token sits in a query
   string or path.
2. Run the Host-header ladder from `payloads.md`: plain `Host: <ATTACKER_HOST>`,
   `X-Forwarded-Host`, `Forwarded`, `X-Original-URL`-style variants, absolute-form
   request line, duplicate Host headers, port and case mutations.
3. Observe the *emailed link*, not a reflected header in the UI — some apps echo your
   Host in the page (harmless) while the email uses a configured base URL (safe), or the
   reverse (dangerous, easy to miss).
4. Token channel pass: is the token present in the API response body
   (`{"reset_token":...}`)? In a URL query (leaks via history, Referer to third-party
   assets, proxy logs)? In a header? Any of these is a direct finding.
5. Lifecycle pass: reuse a consumed link; wait past stated expiry (short labs: verify
   expiry exists at all); trigger two resets and check the older token dies; compare two
   tokens for predictability; check the reset response for user enumeration.
6. If injection works: receive the link on your own listener in the lab and complete the
   reset **for your own account only** — that is the minimal exploitability proof.

**Proof of concept:** (full templates in `payloads.md`)
```bash
curl -sS -i -X POST '<TARGET_URL>/forgot-password' \
  -H 'Host: <ATTACKER_HOST>' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'email=<YOUR_TEST_EMAIL>'
# then read the inbox: does the reset URL point at <ATTACKER_HOST>?
```

**Confirm:** The email actually contains `<ATTACKER_HOST>` (or the token appears in a
response/URL you control) — a reflected Host header in an unrelated page is not enough.
With delivery proven, completing the reset on your own account demonstrates full
exploitability without touching anyone else's account.

**False positives:** Host reflected in UI but email built from config (read the email!);
an intermediate proxy normalizing Host before the app sees it — test through the real
ingress and note which layer rewrote it; marketing/canonical links in the email template
unrelated to the token URL; tokens in URLs that are rotated-after-use over HTTPS-only
(report as hardening, not takeover); a reset page that 200s for any token (soft failure —
check whether the password actually changed).

**Impact:** "An attacker can obtain password-reset tokens for any user by sending
`Host: <host>` in the reset request → account takeover" — claim ATO only with delivery
proven; otherwise "reset tokens leak to `<channel>`", with the channel named.

**Remediation:** Build reset links exclusively from a server-configured canonical base
URL (never request headers), deliver single-use short-expiry tokens outside the URL
where possible, and rotate/invalidate on use.

**CWE / OWASP:** CWE-640 (Weak Password Recovery Mechanism) / CWE-644 (Improper
Neutralization of HTTP Headers) / CWE-598 (Sensitive Information in URL); OWASP A07:2021
Identification and Authentication Failures.

---

## V-07: OTP/2FA verification bypass via response manipulation or parameter nullification

**Mechanism:** The "verified" verdict is produced or stored somewhere the client can
influence: a success flag the JS flips, a boolean parameter (`otp_verified=true`), an
empty/null code that fails open, or a follow-up request the client sends after *its own*
check — while the server never re-validates. The violated assumption: "the client will
only send `verified=true` after really verifying".

**Preconditions:**
- An OTP/2FA/verification step exists (login MFA, payment confirm, signup phone verify)
  on **your own** account.
- You can intercept the verification request and the follow-up it triggers.
- A fresh server-side signal to check: session claims, object status, gated action.

**Detect:**
1. Map the flow first (workflow mapping in `payloads.md`): which request moves the state
   `pending → verified`? What does the *next* request carry — a flag, a token, nothing?
2. Response manipulation: complete a deliberately **failed** attempt (wrong code), edit
   the response to the success shape the client expects (`success:true`, `verified:true`),
   then send whatever follow-up the client now emits — replay that follow-up directly
   with curl to remove the browser from the loop.
3. Parameter nullification: resend the verification with `code=` (empty), omit `code`,
   `code=null`, `code[]=`/`code[0]=`, and add claims-style fields: `otp_verified=true`,
   `verified=1`, `mfa=1`, `skip_2fa=1`, `bypass=1`.
4. Compare-oracle check: does the response differ between "wrong code" and "no code"
   in a way that hints at comparison semantics? If the code is ever *returned* by an
   API (resend, status, SMS-in-app), that is a direct bypass — report separately.
5. Weakness pass (few probes only, then stop): rate-limit existence (2-3 rapid wrong
   guesses → is there a counter/lockout?), code reuse after success, old code surviving
   a resend (two valid codes at once).
6. Re-read state from a fresh request after each candidate — never trust the response
   your edited client displayed.

**Proof of concept:**
```bash
# Baseline: wrong code must fail (control)
curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/<VERIFY_STEP>' \
  -H 'Content-Type: application/json' -d '{"code":"000000"}'
# Nullification candidates
curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/<VERIFY_STEP>' \
  -H 'Content-Type: application/json' -d '{"code":null,"otp_verified":true}'
curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/<VERIFY_STEP>' \
  -H 'Content-Type: application/json' -d '{}'
# Independent signal: does the gated step now proceed?
curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/<GATED_ACTION>' -d '{}'
```

**Confirm:** A fresh server-side read shows verified/upgraded state (session claim
re-fetched, object status, or one gated action completing) after an attempt with a wrong
or absent code. The verdict must come from the server's own store — a success banner in
your edited browser is a lead.

**False positives:** Editing the response only fools your browser (server never changed —
always replay the follow-up independently); "test mode" tenants with fixed/dev OTPs
(document the environment; still report as config); the action you gated on was itself
optional; soft-fail semantics where the server marks the attempt *expired* rather than
*verified* (read the status enum, not just "no error"); the real check running at the
*next* step rather than this one (test the next step too before concluding either way).

**Impact:** "Two-factor/OTP verification for `<flow>` can be bypassed by `<technique:
empty code / client-side flag / response flip>` → unauthorized `<login / transaction /
account binding>`." Name the gated action — bypassing SMS verify on a throwaway field is
low; on payment confirmation or login it is high/critical.

**Remediation:** Compute the verification verdict exclusively server-side and store the
verified state server-side keyed to the session/object; never accept client-supplied
verification claims, and fail closed on absent/empty codes.

**CWE / OWASP:** CWE-287 (Improper Authentication) / CWE-807 (Reliance on Untrusted
Inputs in a Security Decision); OWASP A07:2021 (+ NIST SP 800-63B for OTP semantics).

---

## V-08: Algorithmic complexity attacks as a DoS-style logic flaw (cgroup/resource exhaustion)

**Mechanism:** An endpoint performs work whose cost grows superlinearly with an
attacker-shaped input — regex backtracking (`pattern`), nested JSON/XML depth, wide
range/limit parameters, polynomial string matching in validation — so a handful of small
requests exhausts CPU or memory inside the container's cgroup and starves co-located
work. This is a *logic* flaw, not a traffic flood: the app accepts unbounded work it
never costed.

**Preconditions:**
- An input that shapes the algorithm: `pattern`/`regex`/`filter`, `q`, `range`, `limit`,
  `depth`, template/language lists, uploaded XML/SVG/YAML.
- Latency measurable from your position; program permits complexity probing (prefer
  staging; never aim for outage — see guardrails).

**Detect:**
1. Baseline the endpoint with a small benign input (measure 3×, take the median).
2. Grow *only the dimension that matters* geometrically: payload 1KB → 10KB → 100KB;
   regex input 100 → 1k → 10k chars; `range=1..1000` → `1..1000000`. Plot time vs. size:
   flat/linear = normal; hockey-stick = candidate.
3. Check boundedness first (cheap, safe): does `limit=999999999`, `range=1..2147483647`,
   `depth=10000`, `size=100000000` get accepted at all? An accepted unbounded parameter
   is already a finding even without a DoS demo.
4. Watch the blast radius: subsequent *other* endpoints slowing down, `502/504` from a
   restarted worker, `503` from an exhausted pool — in a cgroup, one loud request degrades
   neighbors. Log which routes degraded (that's your impact statement).
5. STOP at the first clear curve or first worker hiccup — two escalated measurements are
   enough to prove superlinearity. No loops, no parallel floods, no repeat rounds "to be
   sure". Recheck program DoS rules before every escalation.
6. Mitigation check: is there a WAF `413`/size cap/regex timeout? A cap that fires is a
   *defense*, not a finding — report the gap that isn't covered.

**Proof of concept:** (timing template — one escalated point per dimension, 3 samples each)
```bash
for n in <SIZE_SMALL> <SIZE_MEDIUM> <SIZE_LARGE>; do
  for i in 1 2 3; do
    curl -sS -o /dev/null -b jar_a.txt -X POST '<TARGET_URL>/api/<COSTLY_ENDPOINT>' \
      -H 'Content-Type: application/json' -d "$(printf '{"input":"%s"}' "$(head -c "$n" /dev/zero | tr '\\0' 'a')")" \
      -w "$n %{time_total}\n"
  done
  sleep 2   # let the pool recover between sizes
done
```

**Confirm:** Median latency grows superlinearly with input size *alone* (identical
request shape, one varying dimension, small-input control healthy), and — if you
observed it — co-located routes degraded during the escalated probe. The growth curve is
the evidence; an outage you caused is not required and must not be repeated.

**False positives:** Network jitter (medians of 3, wired connection); cold-start or GC
pauses on the first sample (discard first); caching making later identical probes fast
(vary input content, not just size); linear-but-slow endpoints (plot it — slopes ≠ curves);
WAF `413` rejecting big bodies early (mitigation, see step 6); per-request rate limits
making your *burst* look like the cause when it was throttling.

**Impact:** "A `<O(n²)/exponential>` cost per request lets `<authenticated/unauthenticated>`
users consume disproportionate CPU/memory: a `<X KB / k-char>` input produced `<Y s>`
latency and degraded `<other routes>`." Report the curve and the resource; do not claim
a takedown you did not deliver, and never reproduce it beyond the first demonstration.

**Remediation:** Bound input size and algorithmic cost before expensive processing —
depth/range caps, input length limits, linear-time matchers (RE2-style) or hard timeouts
on regex, and a per-request work budget enforced in the cgroup.

**CWE / OWASP:** CWE-407 (Inefficient Algorithmic Complexity) / CWE-770 (Allocation of
Resources Without Limits); OWASP A05:2021 Security Misconfiguration (A04:2021 where the
unbounded work is a design gap).
