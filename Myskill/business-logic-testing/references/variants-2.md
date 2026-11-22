# Variants 9-15 — concurrency abuse, negative values, session races, form context, OAuth, client gates, registration

The second half of the playbook: races that spend single-use value, arithmetic that
manufactures credit, session/id context that de-synchronizes across steps, and trust
placed in the client at registration and in the OAuth callback. Same section shape as
`variants-1.md`; the race procedure, workflow mapping, edge-value matrix, and OAuth
checklist in `payloads.md` are the operating manuals for V-09, V-10, V-11, V-12, and V-13.

## Table of contents

- [V-09: Coupon and promo code replay via multi-threaded locking failures](#v-09-coupon-and-promo-code-replay-via-multi-threaded-locking-failures)
- [V-10: Negative value input processing flaws leading to account credit generation](#v-10-negative-value-input-processing-flaws-leading-to-account-credit-generation)
- [V-11: Session flashing and race vulnerabilities via concurrent HTTP request overlaps](#v-11-session-flashing-and-race-vulnerabilities-via-concurrent-http-request-overlaps)
- [V-12: ID de-synchronization via multi-stage form context substitution](#v-12-id-de-synchronization-via-multi-stage-form-context-substitution)
- [V-13: Account takeover via OAuth 2.0 dynamic client registration and state spoofing](#v-13-account-takeover-via-oauth-20-dynamic-client-registration-and-state-spoofing)
- [V-14: Business flow evasion through client-side logic interception and response flipping](#v-14-business-flow-evasion-through-client-side-logic-interception-and-response-flipping)
- [V-15: Insecure ID direct assignment during self-registration elevating roles](#v-15-insecure-id-direct-assignment-during-self-registration-elevating-roles)

---

## V-09: Coupon and promo code replay via multi-threaded locking failures

**Mechanism:** Redemption performs check-then-decrement without holding a lock or unique
constraint across the whole transaction: parallel requests each read `uses_left=1`,
validate, and all commit — so one code yields multiple discounts, or a per-user/per-cart
limit is spent twice. It is V-03's race applied to *value*: the check is the coupon
engine, the act is the discount line.

**Preconditions:**
- Coupon/apply/promo endpoint reachable at checkout; discount observable on persisted
  orders.
- A code you control: mint one in the sandbox or use a program-provided test code.
  **Never** race codes or balances belonging to other users (guardrail).
- Sequential double-apply correctly fails (if it succeeds, report the plain missing
  check — that is V-02-family, not a lock failure).

**Detect:**
1. Create/obtain a code with a known limit: 1 global use, or 1 use per user, or a usage
   counter — note which limit the engine *claims* (docs/UI text).
2. Sequential control: apply twice with a 1s gap; record the rejection exactly. Then
   re-read the code's use count and your cart's discount lines (baseline).
3. Run the burst from the race procedure in `payloads.md`: 10-20 identical
   apply/redemption requests, one gate, HTTP/2, against a *fresh* cart.
4. Read back authoritative state: order rows with their discount lines, code use counter,
   your wallet/balance. Count *distinct order IDs* carrying the discount — not OK responses.
5. Repeat 5-10 rounds with fresh carts; vary burst spread (0/5/20ms) — lock failures are
   scheduling-dependent.
6. Adjacent windows worth one probe each: applying the same code to two different carts
   concurrently (per-user limit), racing apply against checkout completion (validate →
   revoke → still used), and revoking a code mid-flight (does in-flight validation still
   commit?). Each is its own claim — report only what you reproduced.

**Proof of concept:** (fill slots; templates in `payloads.md`)
```bash
# After the burst: authoritative check — distinct orders carrying the discount
curl -sS -b jar_a.txt '<TARGET_URL>/api/orders?mine=1&cb=1' | grep -c '<DISCOUNT_MARKER>'
# Sequential control for the report (must show exactly 1)
for i in 1 2; do curl -sS -b jar_a.txt -X POST '<TARGET_URL>/api/coupon/apply' \
  -d 'code=<YOUR_TEST_CODE>'; sleep 1; done
```

**Confirm:** Two or more *distinct* persisted orders (or redemptions) each carry the
discount of a 1-use code, reproduced in ≥2 rounds, while the sequential control stays at
exactly one — and each order is re-fetched individually so idempotent replays are ruled
out. You verified only your own carts and your own code.

**False positives:** Two 200s resolving to the *same* order id (idempotency key working —
one spend, not two); discount applied then reversed by an async validator (wait for the
queue to drain, re-read); jitter with sequential processing (see race-vs-jitter in
`payloads.md` — the counter never exceeds 1); cached order lists (cache-buster); a code
whose limit you misread (re-check: per-user vs global vs per-cart); UI showing discount
pre-commit while the ledger shows none.

**Impact:** "A code restricted to `<1>` use yielded `<N>` redemptions for a single
account via concurrent `<apply>` requests." Use the demonstrated multiplier (2×, 3×);
"unlimited" requires a bounded proof you likely should not run.

**Remediation:** Make redemption a single atomic conditional update
(`UPDATE coupons SET uses = uses + 1 WHERE code = ? AND uses < limit`) or a unique
constraint on `(code, user)` with serialization held through checkout commit, so
losing requests fail cleanly.

**CWE / OWASP:** CWE-362 / CWE-367 (TOCTOU); OWASP A04:2021 Insecure Design
(A07:2021 where the abused limit is an authentication/abuse-prevention control).

---

## V-10: Negative value input processing flaws leading to account credit generation

**Mechanism:** Signed client values flow into arithmetic the server trusts: a negative
quantity on a purchase inverts the transfer (you gain), a negative refund amount turns a
payout into a charge, a negative discount *adds* — no sign, range, or precision check
between the HTTP layer and the ledger. The violated assumption: "quantities and amounts
arriving from a form are non-negative facts".

**Preconditions:**
- An endpoint doing arithmetic on client input: order, refund, transfer, top-up, cart
  totals, wallet ops — on **your own** account in the sandbox tenant.
- Balance/ledger readable before and after (fresh GET).
- Guardrail applies hard here: demonstrate the *minimal* credit once (cent-scale), then
  stop — never loop a credit-generating payload, never touch real balances.

**Detect:**
1. Record the baseline: balance/ledger via fresh GET, plus a legitimate positive-value
   transaction (control) to learn the sign convention of each direction.
2. Send one negative value at a time on a fresh object: `quantity=-1`, `amount=-10`,
   `price=-0.01`, `refund=-1`, `value=-1`, per the edge-value matrix in `payloads.md`.
3. Watch the *direction*: healthy = rejected (`422/400`) or clamped; buggy = balance
   *increases* where a debit was expected (or a refund request charges you).
4. Cross-parameter variants: `total=-1` with positive line items (does the server
   recompute?), `discount=-10`, `shipping=-5`, `quantity[]=-1`, `-0`, `+1`, ` 1`,
   `1e3`, `0x10` — type/parse tricks that sneak a negative past a naive validator.
5. Boundary pass: `2147483648`, `99999999999999999999`, `1.999999999` — unsigned or
   fixed-point wrap can turn "huge" into "small/negative" (report as its own line if the
   wrap produces value: 0-priced or credited).
6. Second-order check: does the *write* accept `-1` while a later *read/calc* path
   multiplies it into a credit? Persisted negative rows are the smoking gun.

**Proof of concept:**
```bash
# Baseline
curl -sS -b jar_a.txt '<TARGET_URL>/api/wallet?cb=0'
# Control: legitimate positive purchase (expect debit)
curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/orders' \
  -d 'product_id=<PRODUCT_ID>&quantity=1'
# Probe: single negative quantity (minimal demonstrable unit)
curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/orders' \
  -d 'product_id=<PRODUCT_ID>&quantity=-1'
# Independent signal: ledger/balance re-read
curl -sS -b jar_a.txt '<TARGET_URL>/api/wallet?cb=1'
```

**Confirm:** The server-side ledger/balance (fresh GET, cache-busted) shows an increase
or an inverted transfer you did not pay for, after exactly one probe request — while the
positive control debited normally. A success response echoing your `-1` is not enough.

**False positives:** Display-only math (ledger unchanged — always re-read); sign
convention unfamiliarity (you misread credit vs debit — the positive control fixes this);
currency minor-unit confusion (cents vs dollars making -1 look like -100); refunds that
*legitimately* credit (verify against the refund you did not trigger); sandbox currency
(note environment — still a finding, impact phrased for the env); promotions that
legitimately produce negative *totals* (rebates) — distinguish from balance *generation*.

**Impact:** "Manipulating `<param>` generates `<minimal demonstrated amount>` of unearned
credit per request; the primitive is per-request repeatable subject to `<rate/limit>`."
State the demonstrated amount first, then the reachable ceiling — conservatively, with
any rate limit you actually observed.

**Remediation:** Validate sign, range, and decimal precision server-side on every numeric
field entering arithmetic (`>= 0`, max bounds, fixed decimal scale), and compute balances
only from server-known ledger entries — client-supplied signed values never reach a debit
path.

**CWE / OWASP:** CWE-20 (Improper Input Validation) / CWE-839 (Numeric Range Comparison
Without Minimum Check); OWASP A04:2021 Insecure Design (A03:2021 where the value also
reaches a query).

---

## V-11: Session flashing and race vulnerabilities via concurrent HTTP request overlaps

**Mechanism:** Concurrent requests mutate the same session (login, logout, verify,
switch-tenant, impersonate) while other requests read it — so a privileged session
"flashes" into existence and can be captured or fixed, a logged-out session stays usable
by a request that started before invalidation, or a one-time token is consumed twice.
The violated assumption: "session writes are serialized per client, and state changes
reach every in-flight request".

**Preconditions:**
- Session-mutating endpoints exist (login/logout/verify/switch) you can overlap (H2
  burst per `payloads.md`).
- A fresh second connection (clean curl/jar) to test the old identifier from.
- Your own two sessions/objects — no other users' sessions are touched (guardrail).

**Detect:**
1. Identify session-mutating actions: login, logout, email/phone verify, tenant/role
   switch, impersonation, CSRF-token rotation. Note which rotate the session id.
2. Overlap read-after-write: fire a burst where one request is `logout` and the rest are
   authenticated reads/actions — do any *post*-logout requests still return private data?
3. Login double-submit: two concurrent logins from one pre-auth session → do you end up
   with two usable authenticated session ids derived from one pre-auth id (fixation
   window), or one?
4. Flash probe: run the action that briefly grants state (verify-email setting a role,
   step-up upgrade) while a parallel request reads the gated resource — does the
   *pre-race* session identifier inherit the new state without re-auth?
5. One-time token double-spend: replay a consumed verify/step-up/CSRF token concurrently
   with its first use — two successes = the token isn't single-use under concurrency.
6. For each candidate, test the *old* identifier from a second connection after the race
   settles — persistence of stale privilege is the finding, not interleaved 200s.

**Proof of concept:**
```bash
# Burst: N reads racing one logout on the same session (slots from payloads.md)
curl -sS -b jar_race.txt -X POST '<TARGET_URL>/logout' &   # mutator
for i in $(seq 1 <BURST_SIZE-1>); do
  curl -sS -b jar_race.txt '<TARGET_URL>/api/<PRIVATE_DATA>' & done
wait
# Settle, then test the original session id from a SEPARATE connection
curl -sS -i -c jar_second.txt -b jar_race.txt '<TARGET_URL>/api/<PRIVATE_DATA>'
```

**Confirm:** A second, independent connection using the pre-race identifier observes the
post-race privileged state (or completes a one-time action a second time), reproduced in
≥2 rounds, while a sequential control behaves correctly — old id denied after logout,
token rejected on replay.

**False positives:** Stateless JWT sessions (no server session object to race — look for
token-invalidation gaps instead and say so); eventual consistency (poll after settle
before claiming stale privilege); load-balancer affinity distributing your own requests
normally; plain interleaving (jitter): responses close in time but state never wrong —
see race-vs-jitter in `payloads.md`; logout that only clears the cookie client-side
(that's V-14-flavored client enforcement, different report); per-request session cloning
by design in serverless stacks (document as architecture, verify invalidation truly
fails).

**Impact:** "Concurrent requests leave `<logged-out / pre-privilege / one-time>` session
state reusable across `<event>`, allowing `<persistence of access / second spend of a
one-time action>`." Phrase the demonstrated effect (what the old id actually did), and
treat ATO potential as a separate, labeled sentence.

**Remediation:** Serialize session-critical mutations behind a per-session lock, rotate
the session id on every privilege change, and invalidate all prior derivatives atomically
so concurrent holders converge on the new state.

**CWE / OWASP:** CWE-362 (Race Condition) / CWE-384 (Session Fixation) / CWE-613
(Insufficient Session Expiration); OWASP A07:2021 Identification and Authentication
Failures.

---

## V-12: ID de-synchronization via multi-stage form context substitution

**Mechanism:** A multi-step form validates against an object id captured at step 1 but
re-reads the id independently at the final commit (hidden field, query param, or a
different body key). Swapping the id *between* steps makes validation authorize object A
while the commit acts on object B — check and action are bound to different identifiers,
so neither mediating layer sees the whole transaction (a split-brain of mediation).

**Preconditions:**
- A ≥2-step flow where each step carries a server-visible object reference
  (`order_id`, `draft_id`, `ref`, `token→id`).
- Two objects you own (A and B) from the two-account setup — same principal first, so
  the pure logic split is proven before any cross-user angle.
- Step-state observable (status field / both objects re-fetchable after the commit).

**Detect:**
1. Map the flow (procedure in `payloads.md`) and list, per step, *every* place the id
   appears: path, query, body, header, and the id embedded in the step token/nonce if
   any.
2. Start the flow on object A; at the final step, substitute B's id — change only the
   id, keep the step token/validation artifacts minted for A.
3. Inverse: start on B, commit with A. Also try swapping the id in just *one* carrier
   when it appears twice (query says A, body says B) — which one wins at commit?
4. Re-fetch **both** objects before/after: the changed object while validation referenced
   the other is the de-sync. Baseline both first so earlier legitimate steps don't
   masquerade as the effect.
5. Cross-user version: substitute `<OBJECT_ID_B>` from Account A — if it works, the flaw
   is now also an IDOR; prove it with `bac-idor-testing`'s two-account matrix and credit
   both skills in the report.
6. Watch for partials: A partially mutated + B untouched = check ran but bound loosely;
   both mutated = id used twice in two places.

**Proof of concept:**
```bash
# Steps 1-2 ran against OBJECT_ID_A (step token minted for A), final commit:
curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/<FLOW>/<OBJECT_ID_A>/confirm' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'step_token=<TOKEN_FOR_A>&order_id=<OBJECT_ID_B>&status=confirmed'
# Diff both objects, cache-busted
curl -sS -b jar_a.txt '<TARGET_URL>/api/<FLOW>/<OBJECT_ID_A>?cb=1'
curl -sS -b jar_a.txt '<TARGET_URL>/api/<FLOW>/<OBJECT_ID_B>?cb=1'
```

**Confirm:** Server-side state shows object B modified even though the step token and
earlier validation artifacts were minted for A (both objects re-fetched fresh; A's
artifacts shown in evidence) — check and action provably bound to different ids.

**False positives:** The app re-validates the id at every step anyway (no split — the
outcome is then a plain IDOR if it touches B, hand to `bac-idor-testing`); the two ids
resolve to the same record (namespace collision — verify with a marker field); B changed
by *your own earlier legitimate step* (the baseline diff excludes this); multi-tab
browser sessions merging (do it with curl, one jar); step token bound to the id and
rejected on swap (403/422 = binding exists here — look for the step that lacks it).

**Impact:** "Validation performed on `<step>` for `<object A>` does not bind the final
commit; an attacker can substitute `<object B>` after checks pass — resulting in
`<wrong-object state change / cross-user write if applicable>`." State which object was
acted on and whether it crossed users.

**Remediation:** Bind the validated object id into server-side step state (stored or
signed into the step token) and verify at commit that the committed id equals the
validated id, rejecting any mismatch.

**CWE / OWASP:** CWE-345 (Insufficient Verification of Data Authenticity) / CWE-638
(Failure to Use Complete Mediation); OWASP A04:2021 (+ A01:2021 when it crosses users).

---

## V-13: Account takeover via OAuth 2.0 dynamic client registration and state spoofing

**Mechanism:** The OAuth login/callback chain trusts attacker-influenceable pieces:
`state` missing or attacker-fixable (login CSRF → session swap), `redirect_uri` matched
loosely so the `code` lands on an attacker host, open dynamic client registration (RFC
7591) letting an attacker register their own `redirect_uri`, missing/downgradable PKCE
enabling code injection, or a replayable authorization code. The violated assumption:
"the code and state in the callback belong to the browser that started the flow".

**Preconditions:**
- App offers "login with X" or acts as an OAuth client/AS you can fully exercise with
  your own tester accounts (attacker + victim, both yours).
- You can observe callbacks: your own listener/redirect endpoint on an in-scope lab host.
- Full test-step checklist lives in `payloads.md` — run it in that order.

**Detect:**
1. Complete a normal login with your account; capture the authorize URL (`state`,
   `nonce`, `code_challenge`), the exact `redirect_uri`, and the callback request.
2. State tests: (a) omission — replay the callback with `state` stripped; (b) fixation —
   start a flow with attacker-chosen `state`, have the victim account complete it; (c)
   reuse — replay a consumed `state`.
3. `redirect_uri` manipulation ladder: path suffix, prefix, subdomain, port, case,
   `@`/`//`/`%2f` tricks, `target.com.evil.tld`, wildcard-prefix matching — record
   exactly which shapes the AS accepts.
4. Dynamic registration: POST to the AS's registration endpoint (`/oauth/register`,
   `/.well-known/...`) — can you register a client with an arbitrary `redirect_uri`?
   If yes, you own the code delivery channel for step 5.
5. PKCE: strip `code_challenge` entirely (downgrade to no-PKCE), swap `S256`→`plain`,
   and inject your code+verifier into the victim's callback (code injection).
6. Code reuse: replay a consumed authorization `code` — must fail; accepted = replay.
7. Token confusion: `aud`/`client_id` mismatches — a token issued for client A used at
   client B; `sub` swapping between linked accounts.
8. Anything hitting the AS's *token lookup*, SQL-shaped params, or SSRF-shaped `jku`-like
   URLs hands off to `sqli-testing` / `ssrf-testing` — stay on flow semantics here.

**Proof of concept:** (test steps, not exploit code — fill from your capture)
```bash
# State omission on the callback (expect: rejected)
curl -sS -i -b jar_victim.txt '<TARGET_URL>/<OAUTH_CALLBACK>?code=<CODE>&state='
# redirect_uri variant at the authorize step
curl -sS -i '<TARGET_URL>/oauth/authorize?client_id=<CLIENT_ID>&redirect_uri=<VARIANT>&response_type=code'
```

**Confirm:** Two tester-controlled accounts demonstrate the end state: victim's login
lands in the attacker's session (login CSRF), or an intercepted `code` is redeemed for
victim's token at an attacker-controlled `redirect_uri` — verified by signing in as the
victim and seeing the linkage/session. Both sides are your own accounts (guardrail);
one-account "worked for me" flows prove nothing about ATO.

**False positives:** `state` validated against your *own* completed flow (only a
cross-session replay proves login CSRF); loose `redirect_uri` matching that still
rejects off-domain hosts (path-only flexibility is a real but lower-severity finding —
say which); PKCE optional for *confidential* clients (spec-permitted; report per program
policy rather than as a bypass); callback returning `200` with an error body (read the
body before claiming acceptance); `state` checked but bypassed only with a token you
yourself minted (that's V-05 territory).

**Impact:** "`<flow>` permits `<login CSRF / code interception via redirect_uri or
dynamic registration / PKCE downgrade>` → account takeover of any user who can be made to
visit one URL (or click one link)." High/critical only with the two-account end-state
demo; otherwise report the individual control failure with its narrower reach.

**Remediation:** Exact-match `redirect_uri` against pre-registered values, random
per-session `state` validated once and invalidated, PKCE (`S256`) required for public
clients, single-use short-TTL codes, and registration-endpoint hardening (no arbitrary
redirects, authenticated developers).

**CWE / OWASP:** CWE-345 (Insufficient Verification of Data Authenticity) / CWE-352
(CSRF, for login CSRF) / CWE-862; OWASP A07:2021; RFC 9700 (OAuth 2.0 Security BCP).

---

## V-14: Business flow evasion through client-side logic interception and response flipping

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
# 1) In proxy: flip the failed-step response to the success shape, capture the
#    follow-up the client then sends, e.g.:
# 2) Replay that follow-up directly — no edited client involved
curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/<COMPLETION_ENDPOINT>' \
  -H 'Content-Type: application/json' \
  -d '{"trial_active":true,"verified":true,"step":"<GATED_STEP>"}'
# 3) Independent readback of the finished flow
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

## V-15: Insecure ID direct assignment during self-registration elevating roles

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
# Control: plain signup (default role) — register in a fresh browser/jar
curl -sS -i -c jar_ctrl.txt -X POST '<TARGET_URL>/api/register' \
  -d 'email=<EMAIL_CTRL>&password=<PASSWORD>'
# Probe: one privileged field added
curl -sS -i -c jar_probe.txt -X POST '<TARGET_URL>/api/register' \
  -d 'email=<EMAIL_PROBE>&password=<PASSWORD>&role=admin'
# Independent signal: fresh login, then a role-gated action
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
