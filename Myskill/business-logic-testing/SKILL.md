---
name: business-logic-testing
description: Deep playbook for business logic bug bounty testing: 15 variants covering price/quantity/currency tampering, workflow state-machine circumvention, race conditions with HTTP/2 overlap, admin interface discovery via obfuscated paths, auth-flow and password-reset manipulation, OTP/2FA bypass, algorithmic-complexity DoS, coupon replay, negative-value credit generation, session flashing, multi-stage form ID swapping, OAuth 2.0 state and dynamic-registration takeover, client-side flow evasion, and registration-time role assignment. Use this skill whenever the user is doing authorized security testing and mentions business logic, logic flaw, price tampering, race condition, workflow or step skipping, OTP or 2FA bypass, coupon or promo abuse, negative quantity, refund or balance manipulation, password reset flaw, Host header injection, OAuth state or redirect_uri, checkout manipulation, or signup privilege escalation; asks how to test whether a multi-step flow can be skipped, reordered, or raced; wants burst/race tool templates, edge-value payload matrices, or OAuth/Host-header test steps; needs to confirm or triage a checkout, redemption, verification, or reset finding; or is writing a report for a business logic bug. Also use it when analyzing a request/response pair, a multi-step flow, or handler code for logic weaknesses.
---

# Business Logic Testing Playbook

A methodical playbook for finding and proving business logic flaws: transaction
parameter tampering, workflow/state-machine circumvention, race conditions, client-trust
failures in auth, reset, OTP, and OAuth flows, resource-exhaustion complexity bugs, and
the identity/role confusion that starts at registration.

## 1. Scope & authorization guardrail

Only test targets the user is authorized to test: a published bug bounty program with
this asset in scope, an explicitly scoped pentest asset, or the user's own lab/CTF.
Refuse out-of-scope hosts, third-party targets, and anything the user cannot show
authorization for. Logic tests touch money and shared state, so extra rules on top of
the usual ones: never generate real money, credits, or discounts beyond the minimal
demonstrable amount (one cent-scale unit, one extra redemption on a code you created
yourself); never consume, burn, or invalidate coupons, balances, or records belonging to
other users; prefer the staging or sandbox tenant whenever the program offers one; and
never run availability-harming payloads — algorithmic-complexity probes stop at the
first clear latency curve, race bursts at 10-20 requests. Quantify impact conservatively
in reports: claim the multiplier or amount you actually demonstrated, and label the
theoretical scale as such. The skill exists to make authorized testing methodical and
to produce reports that hold up under triage.

## 2. Engagement workflow

1. **Recon & endpoint inventory.** Enumerate flows, not just routes: checkout, quote,
   coupon apply, refund, registration, password reset, OTP challenge, step-up
   verification, OAuth callbacks, admin/hidden paths — from JS bundles, mobile traffic,
   OpenAPI/docs, and proxy history. *Why:* logic flaws live in the *transitions* between
   endpoints, and the endpoint that matters (finalize, confirm, apply) is rarely linked
   from the main UI.
2. **Parameter & sink mapping.** Tag each endpoint with the client-trusted values it
   reads: money fields (price, qty, currency, discount, amount), state/step markers,
   identifiers, roles/flags, tokens/OTP, Host-derived URLs. *Why:* every variant here is
   a flavor of "the server trusted a client value it should have derived" — knowing
   which value feeds which decision tells you which of the 15 variants apply.
3. **Variant selection.** Route the symptoms you actually observed through the table in
   section 3 and pick 1-3 variants. *Why:* running all 15 blindly is slow and loud; the
   symptom identifies the broken assumption.
4. **Safe probe.** Smallest reversible test, sandbox tenant first, with a recorded
   baseline: one tampered value, one skipped step, a 10-20 request burst. *Why:* logic
   tests mutate state — the baseline is what separates a bug from an intended feature,
   and small bursts keep you clear of DoS rules.
5. **Confirmation test.** Reproduce with a second independent signal: a fresh cache-busted
   GET of server state, a second tester-controlled account/session, or a re-read after
   async queues drain. *Why:* one response proves nothing — the client can echo, flip,
   or cache anything. The two-account setup lives in `payloads.md`.
6. **Impact proof.** Minimal and quantified: the smallest credit, one extra redemption on
   your own code, one skipped step verified by one gated action. *Why:* guardrails
   require minimal demonstration, and triage trusts "2× on a 1-use code" far more than
   "unlimited money".
7. **False-positive filter.** Walk the chosen variant's **False positives** list and
   demand one discriminating signal a healthy system could not produce. *Why:* soft-200s,
   client-only effects, async reverts, and request jitter mimic logic bugs daily.
8. **Report.** Fill the template in section 5 with exact requests, expected vs. actual
   behavior, and the remediation for the specific missing server-side check.

## 3. Variant selection table

| Signal you observed | Likely variant | Reference |
|---|---|---|
| Order total/price changes when you edit price, qty, currency, or discount fields | V-01 Price/quantity/currency tampering | `references/variants-1.md` |
| A later step completes though the required earlier step never ran (status jumps) | V-02 Workflow circumvention / step skipping | `references/variants-1.md` |
| Two or more concurrent identical requests both pass a single-use/limit check | V-03 Distributed race condition (HTTP/2 overlap) | `references/variants-1.md` |
| Hidden admin/backoffice path responds differently to encodings, or loads for a normal user | V-04 Admin discovery via URL obfuscation / Unicode | `references/variants-1.md` |
| Auth state changes when you edit a token claim, session cookie flag, or step-up marker | V-05 Auth flow manipulation | `references/variants-1.md` |
| Reset link follows a spoofed Host / X-Forwarded-Host, or the reset token shows up in URL/body/logs | V-06 Password reset Host injection or leakage | `references/variants-1.md` |
| OTP accepted with an empty/wrong code, a flipped response, or a `verified=true` style parameter | V-07 OTP/2FA verification bypass | `references/variants-1.md` |
| One small crafted pattern/range/depth request causes disproportionate latency or worker restarts | V-08 Algorithmic complexity DoS | `references/variants-1.md` |
| A promo code applies more times during a burst than its use limit allows | V-09 Coupon replay via locking failure | `references/variants-2.md` |
| Negative quantity/price/refund values increase your balance or invert a charge | V-10 Negative-value credit generation | `references/variants-2.md` |
| Overlapping requests keep a logged-out/rotated session alive, or reuse a one-time token twice | V-11 Session flashing / concurrent overlap | `references/variants-2.md` |
| Final submit acts on a different object than the one validated in earlier steps | V-12 Multi-stage form ID de-synchronization | `references/variants-2.md` |
| OAuth callback works without `state`, accepts a modified `redirect_uri`, or registers an attacker client | V-13 OAuth state spoofing / dynamic registration | `references/variants-2.md` |
| A JS-only gate (payment verified, trial ended, quiz passed) is bypassed by a direct call or response flip | V-14 Client-side flow interception | `references/variants-2.md` |
| Signup accepts `role`, `plan`, `id`, or `tenant_id` and the new account comes back elevated | V-15 Registration-time ID/role assignment | `references/variants-2.md` |

## 4. Verification standard

A **lead** is anything suggestive: a tampered field echoed back, a step that "seemed" to
skip, a burst where two responses said OK. Leads are not findings.

A **confirmed finding** requires all four:

1. **Reproducible request + response pair** — exact curl/template with `<PLACEHOLDER>`
   slots filled, cookies/tokens redacted, with the unmodified control request shown next
   to the probe.
2. **Independent server-state readback** — a fresh cache-busted GET, a second session, or
   a ledger/status row proving the effect persisted. Client-rendered success, flipped
   responses, and echoed request bodies do not count.
3. **Minimal-impact proof** — the smallest demonstration that proves the flaw: one
   cent-scale credit, one extra redemption on a tester-owned code, one skipped step
   verified by one gated action. Never touch other users' balances or coupons. Report
   the demonstrated amount/multiplier first; theoretical scale goes in a clearly labeled
   second sentence.
4. **False-positive check completed** — you can state why each alternative explanation
   (echo, async revert, jitter, idempotency, soft-404, sandbox-tenant config) is
   excluded.

Severity follows demonstrated impact: unauthenticated money generation or account
takeover = critical/high; authenticated manipulation with a bounded gain = medium;
discovery without execution (e.g. an admin URL that still enforces authz) = low.

## 5. Report template

```markdown
## Title: <Flaw> allows <consequence> via <mechanism> (V-<NN> <short variant name>)

**Severity:** <Low/Medium/High/Critical — justify with reach + auth requirement + demonstrated amount>
**Endpoint:** `<METHOD> <path>` (parameters: `<param>`)
**Variant:** V-<NN> <name>

### Summary
<1-3 sentences: which server-side assumption is violated, who can exploit it, what it yields.>

### Steps to reproduce
1. Baseline (control): <legit request → expected server state>.
2. Probe: <tampered / skipped / raced request, placeholders filled>:
   ```bash
   curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/<ACTION>' \
     -H 'Content-Type: application/x-www-form-urlencoded' -d '<TAMPERED_PARAMS>'
   ```
3. Verify server state: <fresh GET / second session / ledger read> → <persisted result>.
4. Control re-check: <unmodified request still behaves as expected>.

### Impact
<Demonstrated effect with exact amount/multiplier/steps, then bounded reach (per-account
caps, rate limits). Conservative wording: demonstrated value first, theoretical scale labeled.>

### Evidence (redacted)
<Request/response pairs + the state readback; cookies, tokens, and other users' data masked.>

### Remediation
<Specific: server-side recompute / atomic conditional update / transition table / state
validation — name the check this variant is missing, not generic "validate input".>

### References
- CWE-<NNN> / OWASP Top 10 2021 — A04:2021 Insecure Design (or A01/A05/A07 per variant)
- <flow spec: e.g. RFC 9700 OAuth 2.0 Security BCP, NIST SP 800-63B for OTP>
```

## 6. Reference pointers

Read `references/variants-1.md` for variants 1-8 and `references/variants-2.md` for
variants 9-15; read `references/payloads.md` when you need request templates, tool
commands, or WAF-evasion encodings.

Do not guess a variant from the title alone — match your observed signal to the table in
section 3, then follow that variant's **Detect → Proof of concept → Confirm** loop.
`references/payloads.md` also contains the race-condition testing procedure (parallel
bursts plus how to tell a real race from jitter), the workflow mapping procedure you
must run before any skip/swap test, the negative/edge value test matrix, the OAuth 2.0
test-step checklist, Host-header and password-reset templates, the encoder/obfuscation
table for path-discovery work, and the chain-it-with pointers to `bac-idor-testing`,
`csrf-testing`, and `sandbox-escape-testing`.
