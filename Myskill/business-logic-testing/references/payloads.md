# Payloads, request templates, and cross-cutting material

Shared infrastructure for variants V-01 … V-15: the race-condition testing procedure
(parallel bursts + race-vs-jitter), the workflow mapping procedure that every skip/swap
test depends on, the negative/edge value test matrix, the OAuth 2.0 test-step checklist,
Host-header/password-reset templates, the encoder/obfuscation table for path discovery,
and chain-it-with pointers. Templates never contain live targets — fill every
`<PLACEHOLDER>` from your own engagement notes. Guardrails from `SKILL.md` section 1
apply to everything here: minimal demonstrable amounts, tester-owned coupons/accounts,
sandbox first.

## Table of contents

- [Race-condition testing procedure (parallel bursts)](#race-condition-testing-procedure-parallel-bursts)
- [Telling a real race from jitter](#telling-a-real-race-from-jitter)
- [Workflow mapping procedure (map first, then skip/swap)](#workflow-mapping-procedure-map-first-then-skipswap)
- [Negative / edge value test matrix](#negative--edge-value-test-matrix)
- [OAuth 2.0 testing checklist (test steps)](#oauth-20-testing-checklist-test-steps)
- [Host header & password reset test templates](#host-header--password-reset-test-templates)
- [Encoder / obfuscation tricks (paths & WAF)](#encoder--obfuscation-tricks-paths--waf)
- [Chain it with](#chain-it-with)

---

## Race-condition testing procedure (parallel bursts)

Race tests target a **check-then-act** sequence: the server reads a limit/flag, validates,
then commits — and you make two requests occupy the gap. Procedure:

1. **Classify the action.** Single-use, limited, or counted: coupon apply, redeem,
   withdraw, claim, vote, "one per user", balance transfer. If the endpoint does no check
   at all (sequential double-submit succeeds immediately), you found a missing check
   (V-02/V-10) — stop; there is no race to win.
2. **Sequential control first.** Send the identical request 3× with 1s gaps. Record the
   exact rejection (status + body) and the state readback (counter/balance after each).
   The control is what makes the burst meaningful — a race is *deviation from this*.
3. **Seed fresh state.** New cart/coupon/user object per round, marker string noted,
   balance/counter read with a cache-busted GET (`?cb=$(date +%s%N)`).
4. **Fire the burst.** 10-20 identical requests released simultaneously over one
   HTTP/2 connection (multiplexing puts them in a millisecond-wide window; a load
   balancer then fans them out to different workers — that's where the "distributed"
   gap lives). Three interchangeable ways:

   **a) Burp Turbo Intruder (tightest gate — use for the report-grade attempt):**
   ```python
   # Turbo Intruder race template — check your installed version's API
   def queueRequests(target, wordlists):
       engine = Engine.HTTP2                       # multiplexed on one connection
       gate = 'race1'                              # one gate = simultaneous release
       for _ in range(<BURST_SIZE>):               # 10-20; more is not better
           engine.queue(target.baseRequest, gate=gate)
       engine.openGate(gate)

   def handleResponse(req, interesting):
       table.addColumn(req, 'status')
       table.addColumn(req, 'length')
   ```
   Precondition: `target.baseRequest` is your captured `POST /api/<ACTION>` with
   `<PLACEHOLDER>` slots already filled (cookie, body). Response tallies are *leads* —
   the state readback in step 6 decides.

   **b) Small shell burst (good enough for most TOCTOUs):**
   ```bash
   N=<BURST_SIZE>; : > /tmp/race.$$
   for i in $(seq 1 "$N"); do
     curl -sS --http2 -b jar_race.txt -o - -w '|%{http_code}\n' \
       -X POST '<TARGET_URL>/api/<ACTION>' \
       -H 'Content-Type: application/x-www-form-urlencoded' \
       -d '<POST_BODY>' >> /tmp/race.$$ &
   done
   wait
   grep -c '<SUCCESS_MARKER>' /tmp/race.$$     # response-level count (may mislead)
   rm -f /tmp/race.$$
   ```
   (Same shape with `xargs -P "$N"` or `GNU parallel -j"$N"` if the shell loop is too
   slow to overlap — the goal is launch skew under ~20ms.)

   **c) Barrier script (when launch skew dominates):** an async client that opens all
   sockets first and releases them on one `asyncio.gather` / `threading.Barrier`
   — fill slots `<TARGET_URL>`, `<COOKIE>`, `<POST_BODY>`, `<BURST_SIZE>`,
   `<SUCCESS_MARKER>`; use it when (b)'s skew shows in your results as uniform failure.

   **ffuf note:** `ffuf -rate <N>` *paces* requests down — it is the right tool for the
   **sequential control** and for discovering candidate endpoints
   (`ffuf -u '<TARGET_URL>/api/FUZZ' -w <WORDLIST> -rate 2 -mc 200,403`), and the wrong
   tool for the burst itself. ffuf is also linear, not gated, so it cannot create the
   overlap a race needs.
5. **Vary once, not forever.** Repeat 5-10 rounds; try burst sizes 10 and 20, spread
   0/5/20ms, and one vs. two connections. Distributed races are probabilistic — but stop
   the moment step 6 shows the anomaly, and never scale past what's needed to reproduce.
6. **Read authoritative state.** Fresh cache-busted GET of the ledger/counter/order list:
   count *distinct persisted resources* (two order IDs with the discount, counter = 2),
   not OK responses. Re-fetch each candidate individually to exclude idempotent replays.
7. **Wait out async work.** Some "successes" get reversed by a queue consumer — poll
   once after ~30-60s before writing the finding.

---

## Telling a real race from jitter

Jitter = requests merely *arrived* close together but the server processed them
sequentially. It produces the single most common bogus race report: "two responses said
success". Discriminators, in order of authority:

| Signal | Real race | Jitter / benign |
|---|---|---|
| **Authoritative state readback** | Counter/ledger/rows show 2+ spends (distinct order IDs, doubled balance, uses=2) | State never exceeds 1 no matter how tight the burst |
| **Response tallies** | May match state — but state is the judge | 2+ "OK" responses while state shows 1 (idempotency or echo) |
| **Reproducibility** | Wins in ≥2 of 5-10 rounds; win-rate *rises* as spread shrinks | Either uniform (always fails) or random and uncorrelated with spread |
| **Sequential control** | Stays clean (2nd request rejected every time) | If control also "wins", it's a missing check (V-02), not a race |
| **Resource IDs** | Duplicate successes carry *different* IDs / rows | Same ID returned twice → idempotency key worked (one spend) |
| **Contention errors** | Absent or partial — the gap was open | Consistent `409/423/502` with retry semantics → locks exist; re-read state anyway, partial commits are possible |
| **Transport dependence** | Often easier over HTTP/2 (multiplexed) than H1.1 — that's a real race with a wider window, not a false positive | Wins only with a cached GET or an identical replay byte-for-byte |

Rule: **responses are testimony, state is evidence.** Never report a race from response
counts alone; the finding is a state readback that a sequential world cannot produce.

---

## Workflow mapping procedure (map first, then skip/swap)

Run this before any V-02, V-12, or V-14 test. Skipping it is how logic findings die in
triage.

**Phase 1 — record the legitimate flow (clean session, no tampering):**
1. With a fresh account and a fresh object, walk the flow end-to-end in a proxy,
   preserving order: every request, response status, and redirect, in sequence.
2. For each step record: request shape (method/path/params/headers), the object `<ID>`
   it carries, the state **before** and **after** (`status`/`stage` field from a
   cache-busted GET), and any artifact minted (step token, nonce, one-time code).
3. Mark which endpoints are pure reads vs. state mutators, and note async steps (state
   that changes *after* a delay — poll to settle).
4. Note where each rejection is enforced when you *deliberately* try one out-of-order
   call in this phase (edge 403 vs. app 422 vs. silent success) — it tells you which
   layer owns the check for the report's remediation.

**Phase 2 — derive the test classes from the map (never invent them):**

| Test | How to derive from your map | Variant |
|---|---|---|
| **Skip** | Call step N with the map showing precondition N-1 never ran | V-02 |
| **Swap/reorder** | Run N before N-1; or terminal step first | V-02 |
| **Repeat/replay** | Re-run a step the map marks terminal (double-finish) | V-02, V-11 |
| **Context swap** | Change the `<ID>` between two steps while keeping step artifacts | V-12 |
| **Parallel** | Fire two steps the map treats as mutually exclusive | V-03, V-09, V-11 |
| **Rollback** | Push a terminal-state object back to an earlier mapped state | V-02 |
| **Client-gate** | Find what the *client* waits on in Phase 1, fail it, follow-up anyway | V-14 |

**Why an unmapped workflow produces false positives:** without the recorded baseline you
have no expected transition to diff against, so every alternative explanation survives:
(a) a step you "skipped" is genuinely optional — the map would have shown it on every
legit path; (b) `200 {"error":...}` soft-rejections look like a successful skip — Phase 1
recorded what *healthy* responses look like; (c) client-only transitions — your browser
advanced while the server silently reverted (re-read state; poll for async steps before
claiming); (d) you attacked a finalizer endpoint while the real gate lives two requests
later in a path your spider never visited; (e) you tamper with an id that resolves to the
same record (namespace collision — the map pins which `<ID>` each step truly binds).
Claims of workflow bypass must survive a fresh state re-read after queues drain — the map
is what makes that re-read meaningful.

---

## Negative / edge value test matrix

Apply each value to **one** numeric/type-bearing parameter at a time (money fields: V-01
V-10; verification fields: V-07; limit/range fields: V-08; id fields: V-12). Baseline a
legit transaction first; re-read server state after each probe. Guardrail: when a value
generates credit, capture the single minimal instance and stop — never loop it.

| Input class | Example payload (on `<PARAM>`) | Expected (healthy) behavior | Buggy behavior = reportable | Variant |
|---|---|---|---|---|
| **Zero** | `qty=0`, `amount=0`, `price=0` | `400/422` rejected as invalid, or item removed | Order completes at zero total; `limit=0` read as "unlimited"; division yields free item | V-01, V-08, V-10 |
| **Negative** | `qty=-1`, `amount=-10`, `refund=-1`, `discount=-10` | Rejected by sign check (`422`) or clamped to valid range | Balance *credited*, refund inverts, discount adds — ledger moves the wrong way | V-10, V-01 |
| **Fractional** | `qty=0.001`, `amount=0.001`, `price=0.0000001` | Rejected (int field) or rounded per stated policy | Rounds to free; fractional units accumulate into credit; precision truncation manufactures value | V-01, V-10 |
| **Huge** | `qty=99999999999999999999`, `limit=999999999` | `400` or clamped to max | Accepted verbatim → stock/negative-wrap, unbounded work, or limit bypass | V-08, V-10 |
| **Overflow boundary** | `2147483648` (2^31), `18446744073709551616` (2^64), `1e309` | Rejected as out of range | Wraps to small/negative (int truncation) → 0-priced or credited; `Infinity`/`NaN` accepted as 0 | V-01, V-10 |
| **String (alpha)** | `qty=abc`, `price=free` | Type error `422` | Coerced to 0 (free item) or passed through to a query (→ `sqli-testing`) | V-01, V-07 |
| **String (numeric trick)** | `price=10abc`, `qty=1e3`, `qty=0x10`, `qty=+1`, `qty= 1 ` | Strict parser rejects | Lenient parse truncates (`10abc`→10), scientific/hex notation multiplies, whitespace bypasses a naive filter | V-01, V-10 |
| **Array** | `qty[]=1&qty[]=-1`, `code[0]=`, `amount=1,2` | `422` (scalar expected) | First/last element trusted (check vs. action read different slots); `[-1]` sneaks a negative past scalar validation | V-01, V-10, HPP-adjacent |
| **Null** | `qty=null`, `code=null`, `coupon=null` | `422` missing-value error | `null`→0 price; `code=null` passes an empty-check (OTP fail-open); null coupon disables validation | V-07, V-01, V-10 |
| **Empty string** | `qty=`, `limit=`, `code=` | `422` | Empty read as "no limit"/"skip check"/`==""` compare passes | V-07, V-08 |
| **Negative zero / signed zero** | `qty=-0`, `amount=-0.00` | Treated as 0 or rejected | Passes a `value < 0` sign check while a downstream layer decodes it as negative | V-10 |
| **Boolean-ish flag** | `verified=true`, `admin=1`, `skip=1` | Ignored (not a numeric field) | Security decision honors it — verification/role/step flags are client-set | V-07, V-15, V-14 |
| **Unicode numerals** | `qty=１０` (fullwidth), `qty=١٠` (Arabic-Indic) | Rejected or normalized **before** range validation | Normalized to digits **after** the check → range filter bypassed | V-01, V-10 |
| **Oversized / truncating** | 64KB+ string, `9999999999999999999999999` (truncated by column) | `413`/`400` | Silent truncation changes the value's meaning; or memory/CPU pressure per request (boundedness gap) | V-08, V-10 |

Reading the table: **Expected** is what a server that owns its own arithmetic/type
validation does; **Buggy** rows are findings only when the state readback confirms them.

---

## OAuth 2.0 testing checklist (test steps)

Work in order; record exact request/response per step. Both "attacker" and "victim"
accounts are yours (guardrail). V-13 is the variant; this is its execution order.

1. **Baseline capture.** Log in normally with Account V; capture the authorize URL
   (`client_id`, `redirect_uri`, `state`, `nonce`, `code_challenge`, `response_type`),
   the callback request, and the resulting session. Confirm the flow works unmodified —
   every later result is diffed against this.
2. **`state` omission.** Replay the callback with `state` removed (or empty).
   - Rejected → validated here, continue. Accepted → login-CSRF candidate; escalate to
     step 3 for the cross-session proof (own-flow replay alone proves little).
3. **`state` fixation (cross-session).** Start a flow *you* choose `state` for (attacker
   session), hand the authorize URL to your Account V session, complete login there, and
   observe whether V's authenticated session lands bound to your attacker session/context.
   Verified by V's own view after login. This two-account end state is the reportable
   demo.
4. **`redirect_uri` manipulation.** At the authorize step, substitute variants one at a
   time: path suffix `/evil`, full path on your lab host, subdomain `evil.<TARGET>`,
   `<TARGET>.evil.tld`, port change, case change, `@` and `//` tricks, `%2f` encoding,
   duplicate `redirect_uri` params. Record exactly which shapes the AS accepts — the
   finding is a `code` (or token) delivered off-origin; a rejected variant is a control.
5. **Dynamic client registration (RFC 7591).** Probe `POST /oauth/register` (and
   well-known/registration paths from discovery) with a test client whose
   `redirect_uri` is yours. If registration succeeds unrestricted: use that client in
   step 4/6 — you now own code delivery. Report unrestricted registration itself even if
   you don't complete ATO (auth requirement + allowed URI schemes matter to severity).
6. **PKCE downgrade / code injection.** (a) Drop `code_challenge` from the authorize
   request — is a code issued and redeemable without it? (b) Swap `S256`→`plain`. (c)
   Inject *your* `code` + *your* `verifier` into *V's* callback (code injection — wrong
   session receives the token). Confidential-client-only PKCE absence may be
   spec-permitted: note the client type before claiming.
7. **Code reuse.** Redeem a code once (works = baseline), replay the identical callback
   or token request. Must fail; accepted = single-use violation → report with step order.
8. **Token/subject confusion.** Check `aud`/`client_id` in issued tokens: replay client
   A's token at client B; swap `sub` between your linked accounts; check ID-token
   `nonce` matching at the RP. SQL-shaped `state`/`code` params or SSRF-shaped key URLs
   hand off to `sqli-testing` / `ssrf-testing`.
9. **Write-up gate.** Claim ATO only with the step-3 or step-6 two-account end state.
   Otherwise report the individual control failure with its narrower reach (e.g.
   "redirect_uri accepts path suffixes" — medium), naming which step proved it.

---

## Host header & password reset test templates

All probes use **your own account's email** end-to-end. Template slots: `<TARGET_URL>`,
`<TARGET_HOST>`, `<ATTACKER_HOST>` (your lab listener/in-sink), `<YOUR_TEST_EMAIL>`.

```bash
# R1: classic Host override on the reset trigger
curl -sS -i -X POST '<TARGET_URL>/forgot-password' \
  -H 'Host: <ATTACKER_HOST>' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'email=<YOUR_TEST_EMAIL>'

# R2: forwarding headers (trusts proxy-derived host)
curl -sS -i -X POST '<TARGET_URL>/forgot-password' \
  -H 'Host: <TARGET_HOST>' -H 'X-Forwarded-Host: <ATTACKER_HOST>' \
  -d 'email=<YOUR_TEST_EMAIL>'

# R3: header variants in one ladder (run one at a time, record each)
#   -H 'Forwarded: host=<ATTACKER_HOST>;proto=https'
#   -H 'X-Forwarded-Server: <ATTACKER_HOST>'   -H 'X-Host: <ATTACKER_HOST>'
#   -H 'X-Original-Host: <ATTACKER_HOST>'      -H 'X-HTTP-Host-Override: <ATTACKER_HOST>'

# R4: duplicate / polluted Host (second value wins in some parsers)
curl -sS -i -X POST '<TARGET_URL>/forgot-password' \
  -H 'Host: <TARGET_HOST>' -H 'Host: <ATTACKER_HOST>' \
  -d 'email=<YOUR_TEST_EMAIL>'

# R5: absolute-form request line (seen by forwarding layers first)
curl -sS -i --request-target 'http://<TARGET_HOST>/forgot-password' \
  -H 'Host: <ATTACKER_HOST>' -X POST -d 'email=<YOUR_TEST_EMAIL>'

# R6: token visible in the API response? (direct leak, no header needed)
curl -sS -i -X POST '<TARGET_URL>/api/password-reset' \
  -H 'Content-Type: application/json' -d '{"email":"<YOUR_TEST_EMAIL>"}'

# R7: consumed-token replay (single-use check)
curl -sS -i '<TARGET_URL>/reset-password?token=<CONSUMED_TOKEN>'
```

**Evaluation steps (run after each trigger):**
1. Read the **raw email** — does the reset link's host follow `<ATTACKER_HOST>`?
   Reflection of your Host in the page HTML alone is noise; the email is the oracle.
2. If delivery points at your listener: receive the link in the lab, then complete the
   reset **for your own account only** — that is the ATO proof. Stop there.
3. Leakage pass: token in URL query (→ history/Referer/logs; check whether the reset
   page loads third-party assets while the token is in the query), token in R6's
   response body, token surviving R7 replay, no expiry, two live tokens after two
   requests, and reset-response user enumeration (`known vs unknown email` diffs).
4. Normalization gotcha: an ingress proxy may rewrite `Host` before the app sees it —
   test through the real entry point and state *which layer* (edge vs app) reflected the
   value; that changes the remediation.
5. Report the channel precisely: "reset link host derived from `Host`/`X-Forwarded-Host`
   → token delivered to attacker" vs. "token exposed in `<URL/body>`" vs. "no
   single-use/expiry" — each is its own line with its own CWE (CWE-640 family).

---

## Encoder / obfuscation tricks (paths & WAF)

Use after a plain probe fails — to get past a WAF or edge normalizer, not to hide what
you did. Report the working variant plainly. Primarily for V-04/V-06 and any WAF-blocked
tamper from V-01/V-10.

| Trick | Example | When to use |
|---|---|---|
| Path case variation | `/Admin`, `/ADMIN` | Case-insensitive filter vs. case-sensitive router |
| Trailing / doubled separators | `/admin/`, `//admin`, `/admin;.js`, `/./admin` | Normalization disagreement between filter and router |
| URL-encode one char | `/adm%69n`, `/%61dmin` | WAF pattern-matches raw path only |
| Double-encode | `/%2561dmin` | Edge decodes once, app decodes twice |
| Unicode homoglyph | `/аdmin` (Cyrillic а), `/ａｄｍｉｎ` (fullwidth) | Unicode-aware router vs. byte-matching filter — check NFC/NFD normalization |
| Mixed-script / overlong UTF-8 | `/%c0%afadmin` | Only where the stack is known to accept overlong forms — legacy stacks |
| Method override | `X-HTTP-Method-Override: PUT`, `_method=DELETE` | Only one verb guarded |
| Edge rewrite headers | `X-Original-URL: /admin`, `X-Rewrite-URL: /admin` sent on a benign path | Reversing proxy routes on header, app on path (or vice versa) |
| Param pollution across layers | `?id=<OWN>&id=<THEM>` (see `bac-idor-testing` V-07) | WAF reads first value, app reads second |
| Body format swap | JSON ↔ form ↔ multipart | Check reads query, action reads body |

Keep enumeration polite: ≤1-2 req/s (`ffuf -rate 2`), fingerprint 404s before trusting
any 200, and stop at the first confirmed admin/executable route.

---

## Chain it with

- **`bac-idor-testing`** — *role/ID manipulation.* Business logic flaws and broken access
  control are siblings: V-15's injected `role`/`id` is their V-04 mass assignment feeding
  their V-06 vertical escalation; V-12's substituted `<OBJECT_ID_B>` must be proven with
  their two-account ownership matrix (V-01/V-05 there) before you call it cross-user;
  V-04's discovered admin route becomes a finding only when their function-level check
  fails. If your logic flaw changes *whose* object or *which* role, finish the proof in
  `bac-idor-testing` and cite both variants in one report.
- **`csrf-testing`** — *forced state change.* Every state-changing logic flaw gains a
  victim: a workflow advance (V-02), an OTP "verify" confirm (V-07), a coupon apply
  (V-09), or a role flip (V-15) with no CSRF token / lax `SameSite` / a JSON endpoint
  readable via `text/plain` becomes one-click — the victim's browser spends *their*
  state while the attacker's logic payload rides along. Race + CSRF = victim-driven
  double-spend. See `csrf-testing` for token extraction, tunnel, and CORS/CSWSH chains.
- **`sandbox-escape-testing`** — *if the logic flaw reaches a code-execution context.*
  Escalate only when the primitive actually reaches one: V-08's complexity payloads
  driving a parser that runs inside a vm2/PyJS sandbox; V-01/V-10's overflow values
  feeding a size/offset into a native buffer or deserializer; V-04's admin console
  exposing a template/eval/debug endpoint; V-06/V-13 host/redirect control turning into
  a server-side fetch of attacker content. At that boundary the report's root cause moves
  next door — hand off with your evidence rather than probing escapes here.

The rest of the suite, cross-reference by directory name: `xss-testing` (V-14's
client-side gate can often be *demonstrated* via XSS-assisted flow completion),
`sqli-testing` (string-class rows of the edge matrix reaching lookups), 
`info-disclosure-testing` (reset-token leaks, sourcemaps that reveal workflow endpoints
for Phase 1 mapping), `path-traversal-testing` (V-04's obfuscated paths normalized into
file access), `ssrf-testing` (Host/redirect_uri/registration control reaching
server-side fetches) — when a finding's root cause belongs next door, say so in the
report and keep the chain explicit.
