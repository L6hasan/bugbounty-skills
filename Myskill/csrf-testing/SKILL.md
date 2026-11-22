---
name: csrf-testing
description: 'Deep playbook for CSRF bug bounty testing: 18 variants covering POST/GET state changes, SameSite Lax/Strict bypasses, missing blank reused and predictable tokens, double-submit and Referer/Origin defenses, Content-Type and JSON/form tunnelling, CORS and crossdomain.xml misconfig, CSWSH, and pre-auth token injection. Use this skill whenever the user is doing authorized security testing and mentions CSRF, XSRF, cross-site request forgery, anti-CSRF token, SameSite bypass, double submit cookie, Origin check, CORS with credentials, crossdomain.xml, cross-site WebSocket hijacking, or login CSRF; asks how to test whether an endpoint honors a cross-origin or cross-site request, wants payloads for a CSRF proof of concept, needs to confirm or triage a missing-token report, or is writing a report for a CSRF bug. Also use it when analyzing a request/response pair or code snippet for CSRF weaknesses such as cookie flags, token validation logic, Origin/Referer checks, or permissive CORS headers.'
---

# CSRF Testing

Deep playbook for cross-site request forgery in authorized bug bounty and assessment
work. The classic taxonomy is folded together with the v2.1 deep-mutation set into 18
variants; each variant is a specific, testable failure mode of a anti-CSRF control, not
a generic "no token found" note.

## Scope & authorization guardrail

Only test targets the user is authorized to test: a published bug bounty program with
this asset in scope, a signed assessment engagement, or the user's own lab/CTF. Refuse
out-of-scope hosts, third-party victims, and any request the program rules exclude.
CSRF tests mutate state by design, so NEVER run destructive or DoS payloads (password
changes, fund transfers, deletions of real data, bulk operations) as probes — prove the
bug with the least-impact state change that still demonstrates the cross-site condition.
If intent is unclear, ask for the program/scope before producing payloads.

## Engagement workflow

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

## Variant selection table

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

## Verification standard

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

## Report template

```markdown
# CSRF: <concise endpoint-specific title, e.g. "Change email accepts cross-site POST without token">

**Severity:** <Low/Medium/High/Critical> (justify with exploitability × impact)

**Endpoint:** <METHOD https://host/path> — variant V-<NN> <variant name>

**Summary:**
<2-3 sentences: which control is missing/broken, who can trigger it, what the victim's browser does.>

**Steps to reproduce:**
1. Log in as victim; capture `<PARAM>`/cookie posture (e.g. `SameSite=Lax`, no token).
2. Host `poc.html` on `<ATTACKER_ORIGIN>` with this form/fetch (payload from references/payloads.md).
3. Victim (logged in) opens the PoC page: <browser behavior>.
4. Observe: request carried the session cookie; response `200`; state changed.
5. Re-fetch as victim to verify persistence.

**Impact:**
<state change an attacker forces on the victim, then the escalation path (account
hijack, settings takeover, chained BAC) with the same pattern on sensitive endpoints.>

**Evidence (redacted):**
- `poc.html` (attached)
- Request/response pair with cookies/tokens redacted: <fenced block>
- Screenshot or re-fetch showing the persisted change: <attached>

**Remediation:**
<variant-specific fix: e.g. bind per-session token validated on every state-changing request regardless of method/CT; plus SameSite guidance.>

**References:**
- CWE-352 (Cross-Site Request Forgery); <extra CWE if relevant: CWE-613, CWE-79, CWE-113>
- OWASP Top 10 2021: A01 Broken Access Control (legacy A8:2017 CSRF); OWASP CSRF Prevention Cheat Sheet
```

## Reference pointers

Read `references/variants-1.md` for variants 1-8 and `references/variants-2.md` for
variants 9-18; read `references/payloads.md` when you need request templates, tool
commands, or WAF-evasion encodings. Do not improvise payloads in SKILL.md — the
playbook detail, probe sequences, and false-positive gotchas live in the reference
files.
