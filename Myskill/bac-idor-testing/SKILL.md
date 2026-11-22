---
name: bac-idor-testing
description: Deep playbook for broken access control bug bounty testing: 15 variants covering IDOR/BOLA, RBAC/ABAC function-level bypass, mass assignment, HPP IDOR mutations, weak UUID enumeration, second-order IDOR, GraphQL node access, JWT alg laundering, and cross-tenant leaks. Use this skill whenever the user is doing authorized security testing and mentions IDOR, BOLA/BMAO, broken access control, privilege escalation, horizontal or vertical escalation, mass assignment, IDOR enumeration, JWT tampering, GraphQL unauthorized node access, or tenant isolation; asks how to test whether user A can reach user B's object or an admin-only function; wants curl/payload templates for parameter tampering; needs to confirm or triage a 403-vs-200 mismatch, a role flip, or a cross-account data leak; or is writing a report for a broken access control bug. Also use it when analyzing a request/response pair or handler code for missing object-level or function-level authorization checks.
---

# BAC / IDOR Testing Playbook

A methodical playbook for finding and proving broken access control: IDOR (BOLA/BMAO),
function-level (RBAC/ABAC) bypasses, mass assignment, HPP mutations, predictable IDs,
second-order substitution, version/role/context confusion, GraphQL node access, JWT
algorithm abuse, and multi-tenant boundary failures.

## 1. Scope & authorization guardrail

Only test targets the user is authorized to test: a published bug bounty program with
this asset in scope, an explicitly scoped pentest asset, or the user's own lab/CTF.
Refuse out-of-scope hosts, third-party targets, and anything the user cannot show
authorization for. Never run destructive or availability-harming payloads (bulk DELETE,
unbounded enumeration loops, request floods) — access control bugs are proven with a
handful of requests, not thousands. Keep every proof minimal: when a reachable object
belongs to a real user you do not control, take the smallest redacted sample that proves
the ownership boundary was crossed and nothing more. The skill exists to make authorized
testing methodical and to produce reports that hold up under triage.

## 2. Engagement workflow

1. **Recon & endpoint inventory.** Enumerate every route that carries an object
   identifier or a role gate: JS bundles, OpenAPI/docs (`/swagger`, `/graphql`),
   sitemap, proxy history, mobile API traffic. *Why:* the missed IDOR is almost always
   on an obscure route (export, webhook, attachment, mobile-only API) that no spider
   visited.
2. **Parameter & sink mapping.** Tag each endpoint: identifiers (`id`, `uuid`, `slug`,
   nested path segments, GraphQL global IDs), context inputs (tenant/role headers,
   version prefixes), and sink type (read vs. state-changing). *Why:* this tells you
   which variants apply and keeps destructive calls out of the probe phase.
3. **Variant selection.** Use the table in section 3 to pick 1-3 variants from what you
   actually observed. *Why:* running all 15 blindly is slow and loud; the symptom tells
   you which trust assumption is broken.
4. **Safe probe.** Smallest request that reveals authorization behavior: read-only,
   one identifier, no side effects. *Why:* state changes can corrupt test data and trip
   SOC alerts; a single read is enough to classify the flaw.
5. **Confirmation test.** Reproduce with two accounts the tester controls: session A
   requests object B, then compare against what session B sees for the same object.
   *Why:* one request/response can be explained by caching, soft-404s, or dummy data —
   you need a discriminating signal that only two principals can produce.
6. **Impact proof.** Minimal by design: one record or one action, redacted so only the
   fields proving cross-principal access remain (masked emails, object IDs, a marker
   string). *Why:* minimum-impact proof survives triage and avoids creating your own
   data-disclosure problem.
7. **False-positive filter.** Walk the **False positives** list of the chosen variant
   and demand one independent second signal (B's session reflects the change; the
   admin-only action actually executed; v2 403s where v1 200s). *Why:* a 200 status
   alone proves nothing — many apps return 200 with an error body.
8. **Report.** Fill the template in section 5 with exact requests, expected vs. actual
   behavior, and the remediation for the specific missing check.

## 3. Variant selection table

| Signal you observed | Likely variant | Reference |
|---|---|---|
| Swapping `?id=` or the path ID to another value returns that object | V-01 Direct parameter manipulation | `references/variants-1.md` |
| Endpoint returns full data with cookies/headers stripped (no token at all) | V-02 Unauthenticated endpoint | `references/variants-1.md` |
| You want to sweep many IDs or script an A-vs-B response matrix | V-03 Scripted request validation | `references/variants-1.md` |
| Extra JSON/form fields (`role`, `owner_id`, `admin`, `credits`) persist or change behavior | V-04 Mass assignment | `references/variants-1.md` |
| Read/update/delete another account's object across a whole resource family | V-05 BOLA/BMAO | `references/variants-1.md` |
| Admin route reachable as a normal user, or a method switch (GET→POST) works | V-06 RBAC/ABAC / BFLA bypass | `references/variants-1.md` |
| Repeated params (`id=a&id=b`) or array syntax (`id[]=`) split the check from the action | V-07 HPP mutation | `references/variants-1.md` |
| IDs are UUIDv1 (`...-1...`), snowflake integers, or exact +1 increments | V-08 Weak UUID/ID generation | `references/variants-1.md` |
| An ID is stored (profile/export/callback) and used later in another request | V-09 Second-order IDOR | `references/variants-2.md` |
| Old version (`/v1`, `Accept:` header, `?version=`) behaves weaker than the new one | V-10 Legacy version bypass | `references/variants-2.md` |
| Role/tenant context comes from an editable header/body/cookie (`X-Role: admin`) | V-11 Client-side role flip | `references/variants-2.md` |
| GraphQL `node(id:)` or a typed query returns other users' private fields | V-12 GraphQL node manipulation | `references/variants-2.md` |
| Nested path `/users/<a>/orders/<b>` where only one segment seems checked | V-13 Nested resource traversal | `references/variants-2.md` |
| Token accepted with `alg:none`, RS256→HS256, or edited claims taking effect | V-14 JWT alg laundering | `references/variants-2.md` |
| Data from another org/workspace/tenant appears in your session | V-15 Cross-tenant isolation | `references/variants-2.md` |

## 4. Verification standard

A **lead** is anything suggestive: a guessed ID returning 200, an unknown header echoed
back, an admin route loading. Leads are not findings.

A **confirmed finding** requires all four:

1. **Reproducible request + response pair** — exact curl with `<PLACEHOLDER>` slots
   filled, session cookies redacted, both the expected (403/404) and actual response
   shown.
2. **Two-account proof** — session A performed the access, and the result was verified
   against session B's own view of the same object (or a second independent signal:
   the state change visible to B, an admin action that executed, a differential between
   API versions).
3. **Minimal-impact impact proof** — one object or one action, redacted. If the only
   reachable objects belong to real third-party users, capture the minimum fields that
   prove whose data it is and mask the rest; a redacted proof is enough for a report.
   Never exfiltrate a real user's data beyond that minimum.
4. **False-positive check completed** — you walked the variant's false-positive list
   and can state why each alternative explanation is excluded.

Severity comes from the action (read vs. write vs. delete), the sensitivity of the
data, and whether any identifier is required (unauthenticated, enumerable IDs are
worst). A read-only IDOR on public-ish profile fields is low; a write/delete IDOR on
financial or PII records is high/critical.

## 5. Report template

```markdown
## Title: <Resource/action> accessible across accounts via <missing check> (IDOR/BOLA/<variant>)

**Severity:** <Low/Medium/High/Critical — justify with data sensitivity + action + auth requirement>
**Endpoint:** `<METHOD> <path>` (parameters: `<param>`)
**Variant:** V-<NN> <name>

### Summary
<1-3 sentences: which trust assumption is violated, who can exploit it, what they reach.>

### Steps to reproduce
1. Register/sign in as Account A and Account B (tester-controlled).
2. As Account B, create/locate an object: `<OBJECT_ID_B>` (marker: `<MARKER>`).
3. Send the request as Account A against B's object:
   ```bash
   curl -sS -i -H 'Cookie: session=<SESSION_A>' \
     '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_B>'
   ```
4. Observe: `<actual response — 200 + fields proving ownership>`.
5. Control: the same request as Account B, and/or with credentials stripped: `<expected 403/404/401>`.

### Impact
<Concrete: any authenticated user can read/modify/delete any other user's <records>.
One account reaches <N> objects; data class: <PII/financial/private content>. Minimum-impact demo: 1 record.>

### Evidence (redacted)
<Request/response pair, IDs and PII masked, only ownership-proving fields visible.>

### Remediation
<Specific: enforce server-side ownership/role check bound to the session principal on this route,
default-deny; do not rely on client-supplied <param> or hidden UI controls.>

### References
- CWE-639 (Authorization Bypass Through User-Controlled Key) / CWE-862 (Missing Authorization)
- OWASP Top 10 2021 — A01:2021 Broken Access Control
- OWASP API Security — API1:2023 Broken Object Level Authorization / API5:2023 Broken Function Level Authorization
```

## 6. Reference pointers

Read `references/variants-1.md` for variants 1-8 and `references/variants-2.md` for
variants 9-15; read `references/payloads.md` when you need request templates, tool
commands, or WAF-evasion encodings.

Do not guess a variant from the title alone — match your observed signal to the table
in section 3, then follow that variant's **Detect → Proof of concept → Confirm** loop.
`references/payloads.md` also contains the two-account setup procedure (the backbone of
every proof in this skill), the ID-format catalog, the JWT test checklist, GraphQL probe
templates, enumeration throttle rules, and the chain-it-with pointers.
