# business-logic — part 1/1 (6 segment(s))
# content-aware dedupe applied; every unique entry preserved.

## [Bugbountyskills.md] Business Logic Testing Playbook

A methodical playbook for finding and proving business logic flaws: transaction
parameter tampering, workflow/state-machine circumvention, race conditions, client-trust
failures in auth, reset, OTP, and OAuth flows, resource-exhaustion complexity bugs, and
the identity/role confusion that starts at registration.

## [Bugbountyskills.md] V-01: Transaction integrity violation via price, quantity, and currency parameter tampering

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

## [Bugbountyskills.md] Control: untouched request (expected: persisted total == catalog price)

curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/orders' \
  -H 'Content-Type: application/json' \
  -d '{"product_id":"<PRODUCT_ID>","quantity":1,"currency":"USD"}'

## [Bugbountyskills.md] V-03: Concurrent state processing flaws via distributed race conditions (HTTP/2 request overlap)

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

## [Bugbountyskills.md] Business logic (`business-logic-testing`)

| Endpoint | Signal | Status |
|---|---|---|
| `POST /api/proxy/business/signup` | registration-time role assignment | Untested |
| `POST /api/business/massAssignment` | name literally = mass assignment; bulk ticket↔customer mapping | Untested |
| `POST /api/proxy/auth/forgotPassword` / `sendMagicLink` | user enumeration + email abuse | Untested — **avoid, sends mail** |
| `GET /api/proxy/user/checkEmail?email=` | **account enumeration oracle** | probe queued |
| `POST /api/proxy/payment/session` + `GET /payment/checkout/result` | payment state machine; `guest` token in URL | Untested — never execute real payments |
| `GET /api/proxy/business/checkValidationEmailMagicLink?token=` | magic-link oracle (guessable token?) | Untested |
| `/entreprises-et-cse/verification-email`, `/confirmation-email` | email-verification flow | Untested |

### [Bugbountyskills.md] 17.360 A CHECKOUT REQUEST WHOSE TOTAL IS COMPUTED FROM THE SUPPLIED PARAMETER SET IS RE-PRICED BY DELETING THE STATE PARAMETERS THAT DESCRIBE THE CURRENT PAID SUBSCRIPTION — THE SERVER THEN TREATS THE ORDER AS A FRESH PROMOTIONAL PURCHASE (IDR 0.00) (LinkedIn, HackerOne #2131224, "Attackers can *Upgrade and claim offer* on the Premium Trial Subscription with a total price of *IDR0.00* from the original *IDR7,022,061.82*", weakness Business Logic Errors, severity High, reporter `find_me_here`, submitted 2023-09-01, disclosed 2024-06-18; the report is `visibility: no-content`, 0 B body, so the method is read from the researcher's CREDITED PUBLIC WRITEUP — `aidilarf.medium.com` "[PART 2] Anyone can use unlimited Trial Premium…", published 2025-02-07, read in full this pass via the Wayback capture `web.archive.org/web/20250520062247/...`; UNVERIFIED — not reproduced)

SOURCE: https://hackerone.com/reports/2131224  read 2026-11-10.
CLASS: business-logic / pricing (CWE-840 / CWE-639) — the order total is computed from the SUPPLIED parameter set, so OMITTING the parameters that describe the CURRENT paid state makes the server re-price the order as a fresh promotional purchase.
CORE METHOD: (1) THE ENDPOINT, verbatim — `POST /voyager/api/voyagerPremiumDashSubscriptionCheckoutInformation?action=requestCheckoutV2` on `www.linkedin.com`, `Content-Type: application/json; charset=utf-8`, `Accept: application/vnd.linkedin.normalized+json+2.1`, `X-Restli-Protocol-Version: 2.0.0`. (2) THE BASELINE BODY, verbatim — `{"productUrn":"urn:li:premiumProduct:112000","mainPriceId":6455991,"optionalPriceIds":[6455401],"promotionId":65580503,"upsellOrderOrigin":"premium_nav_more_products_panel","serviceIdSwitchingFrom":353397456}` -> the order totals `IDR7,022,061.82`. (3) THE PARAMETERS' ROLES, verbatim — `productUrn` "is used to detect the Premium product you want to use"; `mainPriceId` & `optionalPriceIds` "determines the price of a product you want to buy"; `promotionId` "is used to determine a promotion for a product"; `serviceIdSwitchingFrom` "is the serviceId that is currently in use". (4) BYPASS 1 — DELETE ONE PARAMETER: remove `serviceIdSwitchingFrom` and re-send -> "the result is that we get a total order of IDR 0.00". (5) BYPASS 2 (after the first was fixed) — DELETE TWO PARAMETERS: remove BOTH `optionalPriceIds` and `serviceIdSwitchingFrom` and re-send -> "And we get a total order of IDR 0.00 back. Then we pay and complete the order as the LinkedIn team requested."
DETECTION SIGNAL: a checkout / quote / upgrade / trial-claim request whose body carries STATE identifiers of the CURRENT subscription/plan (`serviceIdSwitchingFrom`, `currentPlanId`, `subscription_id`, `switchingFrom`, `sourceServiceId`) alongside PRICE/PROMOTION identifiers (`mainPriceId`, `optionalPriceIds`, `promotionId`, `couponId`); a total computed server-side from the SUPPLIED set (the writeup's own tell: "Look, there's something strange about that request"); a request where DELETING a parameter changes the computed total instead of erroring.
CHAIN: an authenticated user with an active/expired paid subscription (primitive: an ordinary account) -> the checkout endpoint recomputes the total from the supplied parameter set, with no server-side re-derivation of the current state (primitive: the state parameters are INPUTS, not assertions) -> delete `serviceIdSwitchingFrom` (escalation: the server no longer sees an "upgrade-from" state and re-prices the order as a fresh promotional purchase) -> the total becomes IDR 0.00 and the order can be completed (impact: free premium subscription / monetary loss at scale; program rated High; $2,500 bounty).
TRANSFERABLE TEST: on any checkout / quote / upgrade / trial-claim request, capture the full JSON body and (1) record the baseline total; (2) DELETE each parameter ONE AT A TIME — especially state identifiers naming the current plan/subscription/service and any price/option arrays — and re-send, diffing the computed total each time; (3) then try PAIRS of deletions. A parameter whose removal silently LOWERS the total (rather than 400ing) is the bug. Rule: **the server computes the order total from the SUPPLIED parameter set — a state parameter that describes the current paid subscription is an INPUT, not an assertion, so deleting it (and the price-option array with it) re-prices the order as a fresh promotional purchase.**
WHY IT IS A NEW GENERAL METHOD: 0 hits for `2131224`, `requestCheckoutV2`, `voyagerPremium`, `serviceIdSwitchingFrom`, `optionalPriceIds`, `promotionId`, `premiumProduct`, `IDR0`. The playbook's V-01 (price/quantity/currency VALUE tampering — `unit_price=0.01`, `discount=100`, `total=0.01`) tampers with money FIELDS and never REMOVES a state parameter; the ledger's signed-request boundary-shift entry (the `CustomerEmail=brixamount100abc@host` primitive) re-splits a SIGNED string to inject a field, a different primitive; the ledger's one-time-benefit entries are additive claim endpoints, not a checkout re-price. Slot 17.360.

NOTE — §17 additions 2026-11-10 batch 120 (§17.360 appended from 6 sources read ONE BY ONE in the given order; 2 entries appended to the harvest ledger, 1 §17 slot). Sources: #2131224 (LinkedIn, checkout parameter-removal -> IDR 0.00, `no-content` — technique from the researcher's credited Medium writeup read via the Wayback capture -> §17.360), #960330 (U.S. DoD / Cisco ASA, CVE-2020-3187 WebVPN `token`-cookie path traversal -> harvest ledger + dated file, NO §17 slot — carrier delta of V-12's placement method). DUPLICATE (valid, read, nothing new): #756149 (Nord Security, Sentry source-code-scraping blind SSRF — same method as the recorded HackerOne #374737, which the Nord report itself cites). VALID-BUT-CHAIN-PRIMITIVE-ONLY (reflected-param, no documented chain): #2039384 (MTN Group, reflected XSS in `nin/success?...&nin=<script>`), #714521 (Stripo, reflected XSS in a URL-path slug). INVALID: #2469713 (GitHub, "View private repository NWO of deploy key via internal LFS API", `visibility: no-content`, 0 B — only the program's summary; CVE-2024-6395's public record adds no endpoint/parameter/request shape). 0 fabricated. Full per-source route/honesty records are in the harvest ledger `/root/bugbountyhuntingskills.md` and `/root/hackbot-architecture/knowledge/methodologies-2026-11-10.md`.

