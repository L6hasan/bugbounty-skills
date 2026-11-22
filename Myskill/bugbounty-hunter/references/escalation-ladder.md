# Escalation ladder — block → bypass → escalate → chain

Use only on authorized, in-scope assets. Every action below is non-destructive: no DoS, no
writes to other users' data, no persistence. The goal is to prove impact with the fewest
requests and stop.

## 1. Classify the block

| Block | What you see | First move |
|---|---|---|
| WAF / filter | 403/406, generic block page, body changes on payload | Encoding + route variation |
| Input validation | 400, "invalid", value stripped | Type juggling, nesting, alternate content type |
| Output encoding | Payload reflected escaped | Different sink/context, DOM sink, attribute vs text |
| Auth required | 401/302 to login | Alternate route, mobile API, token handling, pre-auth endpoint |
| Role denied | 403 for your role | Role confusion, header spoof, lower route, admin API version |
| Tenant denied | 403/404 with tenant header | Header override, ID swap, subdomain swap, shared object |
| Allow-list | Only known hosts/params accepted | Redirect, parser confusion, DNS rebinding, alternate parameter |
| Rate limit | 429 after N | Slow down and parallelize only within policy; do not brute force |
| Sandbox | Code runs but no output/egress | OOB DNS, timing, error-based, alternate sink |
| Feature disabled | 404/501 | Legacy version, mobile host, internal host, GraphQL |

Log the classification. A wrong classification wastes the whole bypass budget.

## 2. Bypass menu (max 5 attempts / 20 min)

Work top-down; stop on first success.

**Encoding and normalization**
- URL encode once/twice, mixed case, overlong UTF-8, Unicode normalization
- Whitespace/comment injection (`/**/`, `%09`, `%0a`), null byte where the stack allows
- JSON escapes (`\u003c`), HTML entities, double-decoding paths
- Chunked transfer, different `Content-Type` charset

**Route and path**
- Trailing slash/dot, `//`, `..;/`, `%2e%2e/`, case variation
- Path parameters (`/users;id=1`), version downgrade (`/v2` → `/v1`)
- Alternate host: mobile API, internal API, legacy subdomain in scope
- GraphQL vs REST for the same operation

**Method and body**
- GET↔POST, PUT/PATCH/DELETE, `X-HTTP-Method-Override`
- JSON↔form↔multipart↔XML
- Duplicate keys, array instead of scalar, nested object, extra unknown fields (mass assignment)

**Trust boundary**
- `X-Forwarded-For`, `X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`
- Host header, `X-Forwarded-Proto`, internal service headers
- Mobile client UA/version, partner API key header, tenant header

**Parser and logic**
- Parameter pollution, type confusion (`"1"` vs `1` vs `[1]`), boolean coercion
- Numeric edge cases (`0`, `-1`, `1e3`, overflow), Unicode homoglyphs
- Redirect chain to an allow-listed host you control

## 3. When bypass fails — escalate

Do not repeat the same payload with a different case for an hour. Change the axis:

| Axis | Cheapest escalation |
|---|---|
| Object | Same object via sibling route, export, report, GraphQL node |
| Role | Same action as a different role you own; invitation/upgrade path |
| Tenant | Same object with another tenant header/subdomain; shared-link flow |
| Verb | Read → write → delete (with your own object); preview → publish |
| Scale | Single → bulk → export → async job |
| Class | Auth bug → IDOR; SSRF → metadata; XSS → token theft; leak → admin route |
| Time | Race the one-time action with 2–5 parallel requests (policy permitting) |

Escalation is successful when you get a **higher-impact lead**, not when you get a different
error message.

## 4. Chaining

**Validity rules**
1. Every link is demonstrated on the target with your accounts.
2. The chain is end-to-end: input enters at link 1, impact exits at the last link.
3. No assumed "an attacker could". If a link is assumed, the chain is a lead.
4. Severity = final impact. Keep per-link evidence so a triager can follow it.
5. Stop at the first sensitive read/action; do not continue to mass extraction.

**High-yield patterns**

| Link 1 | Link 2 | Final impact |
|---|---|---|
| Open redirect | OAuth `redirect_uri` | Code theft → ATO (P2/P1) |
| IDOR read | Export/bulk endpoint | Mass PII (P1) |
| SSRF | Cloud metadata / internal admin | Credentials → infra (P1) |
| Stored XSS | Admin review queue + CSRF token | Admin action (P1/P2) |
| Info leak (secret) | Internal API / admin panel | Access (P1/P2) |
| Auth bypass | Role change endpoint | Privilege escalation (P1) |
| Logic flaw | Race / replay | Double credit or refund (P2) |
| GraphQL introspection | Hidden mutation | Unauthorized write (P2/P1) |
| Subdomain takeover | OAuth allow-listed origin | Code/token theft (P2) |

**Anti-patterns**
- Chaining two P4s does not automatically make a P2.
- A chain that needs a victim to install something or paste code is not a chain.
- A chain that needs a real user's data to demonstrate is out of bounds.
- Do not claim severity from the *possibility* of a later link.

## 5. Budget and stop

- 5 attempts or 20 minutes per block, whichever comes first.
- 30 minutes per escalation axis; then record the dead end.
- Two hours without a P3 candidate → change asset or class, do not lower the severity floor.
- Hard stop on anything destructive, availability-affecting, or involving real user data.
