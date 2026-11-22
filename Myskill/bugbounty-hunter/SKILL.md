---
name: bugbounty-hunter
description: Portable, self-improving bug bounty loop for any agent. Targets P1/P2/P3 impact only — RCE, SQLi, XSS, BAC/IDOR, auth and OAuth bypass, SSRF, LFI, deserialization, XXE, command/code injection, sandbox escape, business logic, admin access, and secret-to-chain disclosure. Use when asked to hunt, test, pentest, recon, triage, or continue a target; when a scope, policy, disclosed report, or writeup is pasted; or when a hunt is blocked and needs bypass, escalation, or chaining. Runs RESEARCH → UPGRADE → RECON → HUNT → DIG → BYPASS/ESCALATE/CHAIN → VERIFY → REPORT → LEARN, and updates its own playbooks from research. Not for header or cosmetic scanning.
---

# Bug Bounty Hunter — v2

**Self-contained. Portable. Read this file first.** `WORKFLOW.md` and `references/` add depth but
are not required to start. No specific tool is assumed: use whatever HTTP client, browser,
shell, or MCP you have.

## 0. Mission directive — hunt high/critical only (standing order)

The failure mode to avoid is drifting into P4/P5/informational findings. Hunt and report ONLY:
**RCE · command execution · code injection · SQLi (incl. NoSQLi) · XSS (stored/reflected/DOM with
real impact) · BAC · IDOR/BOLA · privilege escalation · auth bypass · OAuth/OIDC/SSO bypass ·
JWT/session forgery · LFI/RFI/path traversal · internal file read · SSRF (incl. XSPA and cloud
metadata) · XXE · insecure deserialization · sandbox/container escape · server- or client-side
misconfiguration WITH demonstrated impact · business-logic error with monetary/account impact ·
sensitive information disclosure WITH PoC · admin panel or internal service access · any
account-takeover chain.**

**Binding cautions.**

- No false positives: nothing is a finding until reproduced twice with your own accounts.
- P4/P5/informational is a **chain primitive**, never a deliverable, never reported standalone.
- Do not report early: hold the primitive and keep digging (bypass → escalate → chain) until
  high/critical impact is demonstrated, or drop it in silence.
- Never report non-sensitive or out-of-scope cases; check the do-NOT-test list every pass.
- Do not burn requests on pointless recon — hit the sensitive surface directly and spend the
  budget on bypassing and chaining it.
- Keep reading reports/writeups (HackerOne Hacktivity, Bugcrowd, Intigriti, PortSwigger,
  PentesterLand, Medium, InfoSec Writeups) and keep upgrading this skill from them.

**Chain material.** Info disclosure, reflected parameters, open redirects, verbose errors, and
weak headers are recorded with evidence, then tested for combination. If no in-scope chain
reaches concrete impact, they go to `findings/rejected.md` — never written up alone.

**Think high-critical per endpoint.** Ask "what is the worst outcome reachable here?" (auth
bypass → admin → RCE; IDOR → ATO; SSRF → metadata → creds → RCE) and work backwards to it.

**Drift audit.** Before reporting anything, list the severity of your last five candidates. Three
or more at P4/P5 ⇒ you are drifting — change asset or class; never lower the floor.

The program's core-ineligible list and the §1 auto-reject list are exclusion standards: they
become reportable only inside a demonstrated chain.

## The loop

```
        ┌──────────────────────────── LEARN ◄──────── REPORT ◄──────── VERIFY ◄──┐
        │                                                                         │
     RESEARCH ──► UPGRADE ──► RECON ──► HUNT ──► DIG ──► BLOCKED? ──► BYPASS ────┤
        ▲                                                │              │        │
        │                                                └── no ──► ESCALATE ──► CHAIN
        └─────────────────────────────────────────────────────────────────────────┘
```

**Rules of the loop**

1. Never skip VERIFY. Nothing is a finding until it is reproduced.
2. HUNT and DIG produce *leads*, not reports.
3. BLOCKED is normal. Try BYPASS, then ESCALATE, then CHAIN — do not grind one payload.
4. LEARN always writes to disk. A session that teaches the skill nothing is a failed session.
5. Research comes before a new target, and upgrades happen after every session.

| State | Goal | Exit criterion | Artifact |
|---|---|---|---|
| RESEARCH | Extract 3 usable attack patterns | 3 cards mapped to target endpoints | `learnings.md` |
| UPGRADE | Turn lessons into skill changes | playbook/changelog updated | `references/playbooks.md` |
| RECON | Map in-scope surface | endpoint inventory with params/roles | `targets/<p>/state.md` |
| HUNT | Test one hypothesis at a time | confirmed lead or clean negative | `targets/<p>/state.md` |
| DIG | Go deep on a promising endpoint | siblings/roles/tenants exhausted or 20 min | `targets/<p>/state.md` |
| BYPASS | Defeat the control that blocked you | 5 attempts or 20 min | `targets/<p>/state.md` |
| ESCALATE | Raise impact via sibling/role/tenant | new higher-impact lead | `targets/<p>/state.md` |
| CHAIN | Combine leads into P1/P2 | demonstrated end-to-end impact | `findings/<date>-<name>.md` |
| VERIFY | Prove impact twice with own accounts | reproducible request/response pair | finding file |
| REPORT | Write a 10-minute repro | report complete, severity justified | `reports/<name>.md` |
| LEARN | Update skill and state | changelog + learnings appended | `learnings.md` |

## 0.1 Hard rules (never skip)

1. **Scope first.** No request to a host until it is confirmed in the program's in-scope list,
   including wildcard rules and exclusions. Write `targets/<program>/scope.md` first. Unsure →
   stop and ask one question.
2. **Check the ineligible list.** If it is on the program's excluded list or the auto-reject
   list below, it is not a finding.
3. **Only accounts you own.** Never read, change, or exfiltrate real user data. Stop at proof.
4. **Non-destructive.** No DoS, no mass scanning, no brute force beyond a handful of requests,
   no writes to other users' records, no persistence, no real payments or shipments. Execution
   proof is read-only (`id`, `hostname`, `sleep 5`, unique OOB token).
5. **Ask when close.** Ambiguous scope, a chain that needs real data, or a bypass that risks
   availability → stop and ask.

## 1. Impact gate — the anti-P4 filter

Report floor is **P3 / Medium, and Medium needs demonstrated data or action**. Default to
P1/P2 until evidence says otherwise. "Best practice" is a note, not a finding.

**Three questions before writing anything:**

1. What exactly do I gain — which data, action, account, or host?
2. Can I show it happening now, twice, with my own accounts?
3. Would a triager pay for this?

Any "nothing" → `findings/rejected.md` with the reason, then move on.

**Auto-reject (do not report, do not spend time proving):** missing/weak headers · CSP gaps ·
clickjacking without a sensitive action · open redirect alone · self-XSS · logout CSRF · CSRF
with no security-relevant action · user/email enumeration · absent rate limit without abuse ·
brute force without a bypass · password policy · session not invalidated on logout · concurrent
sessions · missing HttpOnly/Secure without a theft path · TLS config · SPF/DKIM/DMARC ·
autocomplete · version/stack disclosure · directory listing without sensitive files ·
robots.txt disclosure · subdomain takeover without a proven claim · CORS wildcard without a
credentialed data read · CSV injection without execution · host-header injection without reset
poisoning · cache deception without data · IDOR on public/static objects · introspection alone ·
API docs alone · "could lead to" anything.

These become reportable **only** chained to demonstrated P2+ impact. Write the chain.

**Upgrade examples (copy this reasoning):**
- Open redirect alone P4 → `redirect_uri` returning an OAuth code to my host = **P2 ATO**.
- Self-XSS P4 → stored payload rendered in the admin queue = **P1/P2**.
- Introspection P4 → hidden `updateUser(email)` mutation → reset password = **P1**.
- S3 listing of marketing assets P4 → same bucket holds DB backups/`.env` = **P1**.
- No login rate limit P4 → no lockout + 4-digit OTP = **P2**.

**Effort budget:** 70% BAC/IDOR, auth/OAuth/JWT, SSRF, injection→RCE, logic, secrets→admin;
20% recon that feeds those; 10% everything else. Two hours with no P3 → change asset or class.

**"Think critical" is a search strategy, not a label.** Ask what the worst realistic attacker
outcome is and the shortest in-scope path to it. Before rating anything High or Critical, write
down the exact preconditions the attacker needs and the exact data or action they gain. If the
rating depends on a real victim, a non-default configuration, or an assumed link, it is not
High/Critical yet.

## 2. RESEARCH (before a new target)

Extract **three attack-pattern cards** from *current* disclosures and map each to an endpoint
class on this target. Freshness is part of the method:

- Prefer the **last 6–12 months**. Fetch the page; do not rely on memory or a summarizer.
- **Never cite a writeup you have not opened.** Record `Source URL` and `Accessed` date on every
  card.
- If the technique cannot be reproduced on a lab or your own test setup, mark it **UNVERIFIED**
  and keep it out of `references/playbooks.md` and this file. Unverified does not mean false — it
  means not yet load-bearing.
- A card that cannot name an endpoint on this target is not ready to use.

Card fields: source URL · accessed date · class · precondition · observable signal · request
shape · root cause · bypass · chain potential · applies-to · verification status.

Full rotation, quality filter, and queries: `references/research-loop.md`.

## 3. UPGRADE (the skill improves itself)

After every session, change the skill — not just the notes.

- Technique verified on a lab or confirmed on target → promote into `references/playbooks.md`
  with the exact request shape and the source URL.
- Disproven technique → move to the failed list with the disproof.
- Unverified technique → stays in `learnings.md` marked UNVERIFIED; never promoted.
- New triage pattern → record in `learnings.md` under Triage patterns.
- Contradiction with this file → edit this file and bump the version + changelog.
- No change possible → write one line saying why.

Version format: `MAJOR.MINOR.PATCH` in the changelog. Bump MINOR for a new technique, PATCH for
a correction, MAJOR for a structural change.

## 4. RECON (scope-bounded)

Inventory only in-scope assets: subdomains, endpoints, JS bundles and sourcemaps, API docs,
GraphQL, auth flows, mobile API hosts, upload/export/webhook/invite endpoints.

Highest-yield surface: object IDs in APIs · role/permission endpoints · password reset and
invite · payment/credit/coupon · upload and render · URL fetchers (image proxy, PDF, webhook,
import) · SSO/OAuth callbacks · admin/internal hosts · bulk and export endpoints.

For every endpoint record: object touched, who should be allowed, identifier type, roles,
tenant boundary. Write it to `targets/<program>/state.md` so a later agent can resume.

## 5. HUNT

One hypothesis at a time. State the class and expected impact before the request. Send the
minimum probe, capture request/response, then decide: lead, negative, or blocked.

Do not spray payloads across endpoints. Do not report scanner output. Reproduce or drop.

## 6. DIG (depth before breadth)

Once an endpoint looks promising, spend up to 20 minutes on the depth checklist:

1. Sibling routes and alternate verbs.
2. Hidden/undocumented parameters and JSON fields (mass assignment).
3. API versions and legacy routes (`/v1`, `/internal`, `/beta`, mobile host).
4. Role and tenant variations with your other account.
5. Bulk, batch, export, report, and import variants.
6. GraphQL: mutations, node lookups, aliases, fragments.
7. Client bundles/sourcemaps for the same call with extra fields.
8. Error messages that reveal the backend query or object model.

Record each attempt and result in the state file. Depth on one endpoint beats ten shallow probes.

## 7. BLOCKED → BYPASS → ESCALATE → CHAIN

**Classify the block first:** WAF/filter · input validation · output encoding · auth required ·
role denied · tenant denied · allow-list · rate limit · sandbox · feature disabled.

**BYPASS ladder — max 5 attempts or 20 minutes per block:**

1. Encoding/normalization: URL, double URL, Unicode, case, whitespace, null byte, chunked.
2. Route: alternate path, trailing slash/dot, case, path parameters, version downgrade.
3. Method/content-type: GET↔POST, PUT/PATCH, JSON↔form↔multipart, XML.
4. Parameter shape: duplicate keys, array, nested object, JSON pollution, header override.
5. Trust boundary: `X-Forwarded-*`, host header, internal header, mobile client UA.
6. Alternate surface: GraphQL vs REST, mobile API, legacy host, websocket, export job.

**If bypass fails, stop grinding. ESCALATE:**

- Sibling endpoint or feature with the same object model.
- Higher-privilege or different-tenant account you own.
- Second bug class on the same data path.
- Read → write, or single object → bulk/export.

**Then CHAIN.** A chain is valid only when every link is demonstrated. Severity is judged at the
final impact, not the first. Keep evidence per link.

Patterns: open redirect + OAuth code · IDOR + export · SSRF + metadata · XSS + CSRF token ·
info leak + admin route · auth bypass + privilege escalation · logic + race.

Hard stop: no destructive bypass, no DoS, no real user data, no persistence.

Detailed menu: `references/escalation-ladder.md`. Per-class probes: `references/playbooks.md`.

## 8. VERIFY

- Clean second attempt, minimum request sequence.
- Two accounts you own; show A's object from B's session.
- One-sentence impact a non-technical triager understands.
- Redact tokens and PII.
- Stop at proof; do not escalate to mass extraction.

Cannot reproduce twice → it is a lead, not a finding.

## 9. REPORT

**Pre-report gate — all four must be true before drafting:**

1. The program's core-ineligible / excluded-findings list has been checked against this issue.
2. The chain reaches a concrete impact: account takeover, sensitive data access, RCE, or admin
   functionality. "Could be chained" is not a chain.
3. The exact preconditions and the exact data/action gained are written in the report.
4. Severity is labeled at the demonstrated impact, not the theoretical one.

Use `references/report-template.md`. Exact asset · numbered steps · raw request/response ·
one-sentence impact · CVSS + program label · remediation · "why this is not X". No inflation.
Include rejected candidates and chain material in the session summary.

**Notification gate.** The only approved Telegram send is
`scripts/notify_telegram.py <finding>.json` after VERIFY. It refuses anything without a
confirmed/verified status plus title, description, ≥3 steps, PoC, impact, and a P1–P3 severity.
Never send status updates, progress, candidates, or recon notes to Telegram.

## 10. LEARN

Append to `learnings.md`, update `targets/<program>/state.md`, then close with:

```
Targets covered:
Candidates found (class, asset, status):
Verified findings (severity + one-line impact):
Blocked paths and bypass attempts:
Chains attempted (valid / invalid, why):
Rejected candidates (reason):
Research cards added:
Skill changes (version):
Next steps:
```

## 11. Drift control

- Before every request, name the class and the impact you expect.
- A banner, an error page, or a header difference is not a lead.
- Never report scanner output; reproduce it yourself.
- Never invent an endpoint, parameter, or response. Unknown is a valid value.
- One verified auth bypass beats twenty speculative findings.
- If you have written no finding in two hours, change asset — do not lower the floor.
