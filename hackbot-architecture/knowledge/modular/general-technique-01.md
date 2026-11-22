# general-technique — part 1/45 (119 segment(s))
# content-aware dedupe applied; every unique entry preserved.

## [Bugbountyskills.md] BugbountySkills — Consolidated Bug Bounty Hunter Playbook

*Single root file • `/root/Bugbountyskills.md` • Generated: 2026-10-30 00:30*

> **Purpose:** One consolidated, agent-loadable reference containing EVERY bug bounty
> skill, technique playbook, methodology, domain profile, findings, and lessons on this
> VPS. Every agent can read this file and immediately operate as an authorized,
> evidence-driven bug bounty hunter.
>
> **Authorization rule (from `bug-hunter` skill §0):** Only test targets you are
> authorized to test. Never access out-of-scope assets, another user's real data, or
> perform destructive actions. When in doubt, stop and ask.

---

## [Bugbountyskills.md] TABLE OF CONTENTS

1. [Meta: Skill Spec & Orchestrator](#1-meta)
2. [Technique Skills (11 playbooks)](#2-technique-skills)
3. [Hermes-Provided Bug Bounty Skills](#3-hermes-provided-skills)
4. [Master Prompts / Core Identity](#4-master-prompts)
5. [LESSONS — Learning Log](#5-lessons)
6. [Domain Profiles & Findings](#6-domain-profiles)
7. [Lab Files — Tools & Scope](#7-lab-files)
8. [Credential Reference (no secrets in this file)](#8-credentials)
9. [Validation Script](#9-validation-script)

---

## [Bugbountyskills.md] 0.5 AGENT DECISION TREE — route by observation (READ THIS FIRST)

Never read this file top-to-bottom. Read §0 above (severity doctrine), then run this tree and go
to the ONE branch that matches what you observed. This file is a concatenation of every technique
skill: option A is to route through the tree below; option B is to use the class → skill map.

**Class → skill map.** §1 META & ORCHESTRATOR (skill-build spec, engagement orchestrator) ·
§2 TECHNIQUE SKILLS (BAC/IDOR · business-logic · XSS · SQLi · SSRF · RCE · path-traversal ·
info-disclosure · CSRF · sandbox-escape — each embedded with its `variants-*.md` and `payloads.md`).
The class-indexed technique ledger lives at `/root/bugbountyhuntingskills.md` (§1 XSS, §2 SSRF,
§3 IDOR/BOLA, §7 SQLi, §8 traversal/LFI, §9 source & .git, §10 info disclosure, §11 auth bypass,
§12 ATO chains, §13 command injection/code exec, §17 new intake).
Full routing table (class → minimal test → section): `/root/hackbot-architecture/knowledge/SKILL-TREE.md`.

```
START
│
├─ 0. SCOPE GATE ──────────────────────────────────────────── cannot be skipped
│    IF  asset is not in the program's in-scope list ............ STOP. Send no request.
│    IF  class is on the HackerOne core-ineligible list ......... CHAIN PRIMITIVE only.
│    IF  you cannot prove impact twice, with your own accounts .. it is a LEAD, not a report.
│
├─ 1. ROUTE BY OBSERVATION ────────────── pick exactly ONE, then go to its playbook
│    IF  an API path / query / body carries an object id ....... BAC · IDOR · BOLA
│    IF  there is a login, SSO, OAuth, JWT, or session cookie .. AUTH BYPASS · OAUTH · JWT
│    IF  any feature fetches a URL you influence ............... SSRF (incl. cloud metadata)
│    IF  your input is stored or rendered on any page .......... XSS (stored / reflected / DOM)
│    IF  input reaches a database query ........................ SQLi · NoSQLi
│    IF  input reaches a shell, template, or deserializer ...... RCE · SSTI · deserialization
│    IF  a file, path, archive or export is accepted/served .... LFI · path traversal · file read
│    IF  XML, serialized blobs, or signed cookies are parsed ... XXE · insecure deserialization
│    IF  money, credits, coupons, quota, or a workflow step .... BUSINESS LOGIC
│    IF  source, .git, .env, buckets or backups are exposed .... SECRET → SENSITIVE INFO DISCLOSURE
│    IF  an admin / internal / undocumented route answers ...... ADMIN PANEL · INTERNAL ACCESS
│    ELSE ........................................................ go to RECON, get one of the above
│
├─ 2. BLOCKED? ────────────────────────── classify the block FIRST, then act
│    IF  WAF / filter / validation / encoding stopped you ...... BYPASS LADDER (5 tries / 20 min)
│    IF  auth required, role denied, or tenant denied .......... ESCALATE (sibling / higher account)
│    IF  allow-list, rate limit, sandbox, or feature flag ...... change SURFACE, re-enter at 1
│    IF  bypass failed after 5 attempts or 20 min .............. STOP grinding → CHAIN or change asset
│
├─ 3. PRIMITIVE IN HAND? (P4/P5 — NEVER a report, never queued) ─── chain it or hold it
│    IF  it reads internal or foreign data .................... chain: read → IDOR → disclosure
│    IF  it redirects anywhere ................................ chain: redirect → OAuth/token theft → ATO
│    IF  it leaks a secret, key, or token ..................... chain: secret → auth bypass → admin → RCE
│    IF  it leaks a version, banner, or stack trace ............ chain: version → known CVE or debug route
│    IF  it reflects input .................................... chain: reflect → stored / admin-context XSS
│    IF  it discloses an error or object model ................ chain: error → backend query → SQLi
│    IF  it lets you upload or write a file ................... chain: write → traversal/serve → RCE
│    ELSE ...................................................... HOLD. Do not draft. Do not queue.
│
└─ 4. FINAL IMPACT GATE ──────────────── severity is judged at the LAST link of the chain
     IF  chain reaches high/critical (data · action · money · account · host) → VERIFY → REPORT
     IF  chain never reaches high/critical ..................................... drop it in silence
     ALWAYS  before any draft → DRIFT AUDIT (doctrine §7): grade your last 5 candidates;
             3 or more at P4/P5 ⇒ you are drifting ⇒ change asset or class, never lower the floor.
```

Hard stops: no out-of-scope request · never touch real user data (stop at proof) · non-destructive
only · nothing reported until reproduced twice end-to-end · P4/P5 never ships alone.

---

---

## [Bugbountyskills.md] 1. META & ORCHESTRATOR

## [Bugbountyskills.md] >> SKILL_SPEC — How technique skills are structured

*Source: `/root/Myskill/SKILL_SPEC.md`*

## [Bugbountyskills.md] Skill Build Spec (shared by all 10 bug-bounty skills)

Every skill directory MUST contain:

```
<skill-name>/
├── SKILL.md
└── references/
    ├── variants-1.md      (variants 1-8)
    ├── variants-2.md      (remaining variants; omit if all fit in variants-1.md)
    └── payloads.md        (payload/request templates, tool commands, evasion notes)
```

## [Bugbountyskills.md] 1. SKILL.md frontmatter (exact shape)

```yaml
---
name: <skill-name>
description: <see below>
---
```

The `description` is what triggers the skill. Write it "pushy": state what it does AND
list the situations that should trigger it. Example shape (adapt per skill):

> Deep playbook for <category> bug bounty testing: <count> variants covering <top 5-6 topics>.
> Use this skill whenever the user is doing authorized security testing and mentions
> <keyword list>, asks how to test for <X>, wants payloads/requests for <Y>, needs to
> confirm or triage a <Z> finding, or is writing a report for a <category> bug. Also use it
> when analyzing a request/response pair or code snippet for <category> weaknesses.

## [Bugbountyskills.md] 2. SKILL.md body (target 150-300 lines)

Required sections, in this order:

1. **Scope & authorization guardrail** — short, firm: only test targets the user is
   authorized to test (published bug bounty program, scoped asset, own lab/CTF). Refuse
   out-of-scope or third-party targets, and never run destructive/DoS payloads. Testing
   techniques belong in authorized contexts; the skill exists to make authorized testing
   methodical and to produce reports that hold up.
2. **Engagement workflow** — 6-8 numbered steps: recon & endpoint inventory → parameter
   & sink mapping → variant selection (use the table below) → safe probe → confirmation
   test → impact proof → false-positive filter → report. Explain WHY each step exists
   (e.g. confirm with a second, independent signal before claiming a finding).
3. **Variant selection table** — markdown table: `| Signal you observed | Likely variant | Reference |`
   mapping observable symptoms → variant number → `references/variants-N.md`. This is the
   routing layer; make it genuinely useful (a newcomer should be able to pick a variant
   from an observed symptom alone).
4. **Verification standard** — what counts as a confirmed finding vs. a lead. Require a
   reproducible request + response pair, minimal-impact impact proof, and a
   false-positive check.
5. **Report template** — exact markdown template: Title, Severity, Endpoint, Summary,
   Steps to reproduce, Impact, Evidence (redacted), Remediation, References (CWE/OWASP).
6. **Reference pointers** — explicitly say: "Read `references/variants-1.md` for variants
   1-8 and `references/variants-2.md` for the remainder; read `references/payloads.md`
   when you need request templates, tool commands, or WAF-evasion encodings."

Do NOT paste the full variant playbook into SKILL.md — that lives in references/.

## [Bugbountyskills.md] 3. Variant reference files (deep playbook)

Split the skill's variant list (given in the category prompt) into two files:
`variants-1.md` (first 8) and `variants-2.md` (remainder). Each file starts with a table
of contents (variant number + title, linked by anchor), then one section per variant:

```markdown

## [Bugbountyskills.md] V-01: <Variant name>

**Mechanism:** 1-3 sentences — why it works, the trust/assumption being violated.
**Preconditions:** bullet list — what must be true (auth state, cookie flags, tech stack).
**Detect:**
1. numbered, concrete steps the agent can perform (inspect X, send Y, observe Z)
**Proof of concept:**
- exact request template or payload with `<PLACEHOLDER>` slots
**Confirm:** the independent second signal that proves it is real, not a false positive.
**False positives:** what commonly mimics this variant.
**Impact:** how to phrase realistic impact for a report (data/action at stake).
**Remediation:** one sentence, specific to this variant (not generic "validate input").
**CWE / OWASP:** mapping.
```

Rules for variant content:
- Impersonate 14 years of experience: include the non-obvious gotchas (the detail a
  junior misses) in **False positives** and **Detect**.
- Payloads/requests are templates with placeholders — never hardcoded live targets.
- Include WAF/encoding evasion notes inline where the variant list mentions them.
- Keep each variant 25-45 lines. 15 variants ≈ 400-600 lines per file — that is fine;
  add a TOC at the top of each reference file.
- Use `payloads.md` for cross-cutting material: one table of encoder/obfuscation tricks,
  tool invocations (curl one-liners, sqlmap flags, ffuf, dalfox, etc. — as *templates*),
  and a "chain it with" section pointing at the sibling skills in this suite (e.g. CSRF
  chains with XSS-Assisted CSRF → see `xss-testing`).

## [Bugbountyskills.md] 4. Tone

Imperative, practical, explain the *why*. No "MUST/NEVER" in all caps unless it is a
safety/scope rule. Assume a competent tester who wants speed and precision.

## [Bugbountyskills.md] 5. The suite (sibling skills, cross-reference by directory name)

| Skill | Category |
|---|---|
| `csrf-testing` | CSRF (POST/GET, SameSite, token validation, tunnels, CORS, CSWSH...) |
| `xss-testing` | XSS (reflected/stored/DOM/blind/UXSS/mXSS/CSTI/sandbox evasion) |
| `sqli-testing` | SQLi + NoSQLi (error/union/blind/OOB/stacked/DB-specific/WAF bypass) |
| `bac-idor-testing` | Broken access control, RBAC/ABAC, IDOR, mass assignment, JWT, BOLA |
| `rce-testing` | RCE (cmd injection, code eval, deser, SSTI, upload, argument injection, config/env) |
| `ssrf-testing` | SSRF (basic/blind scanning, cloud metadata, DNS rebinding, protocol smuggling, PDF/render) |
| `path-traversal-testing` | LFI/RFI/traversal, wrappers, log poisoning, zip slip, misconfig |
| `info-disclosure-testing` | Leaks: .git/.env/sourcemaps/buckets/introspection/EXIF/stack traces |
| `business-logic-testing` | Logic flaws: price tampering, race conditions, OTP bypass, OAuth, workflow |
| `sandbox-escape-testing` | Sandbox escapes: vm2, Python/PHP/Java/Node, k8s/docker, WASM, V8 |

## [Bugbountyskills.md] Bug Hunter — engagement orchestrator

You are running an authorized bug bounty engagement. This skill is the spine: it decides
*scope*, *order*, and *memory*. The nine technique skills are the muscle — each one is a
deep playbook you load when a signal points at its category.

The whole point of this system is that it **compounds**. Every engagement leaves a domain
profile, every report the user submits teaches a lesson, and lessons get written back into
the technique skills. Three sessions from now you should be measurably better than you are
today, and you should be able to prove it from the changelog.

## [Bugbountyskills.md] 2. Hunt workflow

Run these phases in order. Do not start active probing before Phase 3 is done — testing
without an inventory is how you burn rate limits on the boring endpoints and miss the
interesting ones.

**Phase 1 — Load intel.** Read `domains/<domain>/SKILL.md`. Note scope, stack, previously
tested surface, confirmed findings, and dead ends. The dead ends are as valuable as the
findings: don't re-test what was already ruled out.

**Phase 2 — Recon (passive first).**
- DNS/subdomains, certificate transparency, DNS zone transfer attempts.
- Technology fingerprinting: headers, cookies, error pages, framework tells, WAF detection.
- Content discovery: robots/sitemap, exposed directories, API surface (Swagger/OpenAPI,
  GraphQL introspection), JS bundles and sourcemaps.
- Public sources: program scope page, GitHub/org repos, npm packages, prior disclosures.
- **`robots.txt` + `security.txt` before anything else** — they are free scope intel: disallowed
  paths map hidden/auth-gated surface, `User-agent` blocks reveal the site's declared agent policy
  (some programs forbid automated account/transaction behavior — treat as binding alongside the
  program brief), and framework tells (e.g. `/apipie/` ⇒ Rails) come for free.
- Record everything into the profile's *Attack surface* section as you go.

**Phase 3 — Attack-surface mapping & technique selection.**
Enumerate endpoints and parameters, then classify each by the signal it presents. Use the
routing table below — it maps an observed signal to the right technique skill. Prioritize
by (a) untested surface, (b) sink richness (file paths, SQL-ish filters, template fields,
auth/session state), (c) business value.

**Phase 4 — Active testing (full, but polite).**
You have the mandate for full active testing within scope. The craft constraints still apply:
- Safe-first ladder everywhere: baseline → differential probe → confirmation → impact proof.
  One callback-class test before any injection attempt.
- **Destructive-verb rule (learned the hard way, 2026-10-21):** never include `DELETE` (or any
  state-destroying method) in a method-discovery matrix sent to a *live object path*. `OPTIONS`
  is useless against routers that 500 on it — accept that and probe method support only on paths
  where every outcome is harmless. To test an authz/CSRF boundary, aim it at a
  **guaranteed-nonexistent ID** (beyond the platform's current id range) so no real object can be
  affected: `401` vs `403` vs `404` vs `200` tells you auth and token enforcement with zero
  collateral. A `200 {"code":0,"message":"Ok"}` from a method probe is not a "pass" — it may be
  an executed feature. Assume every verb does what it says.
- Rate: no hammering. Keep bursts small, respect program limits, back off on 429s and on
  anything that smells like a WAF tripwire (repeated 403/406 after identical requests).
- Two independent signals before you call something a finding. Status 200 alone proves
  nothing; a body that *looks* like a payload reflected proves nothing until you show the
  browser would execute it or the DB would evaluate it.
- Prove impact at the minimum depth that demonstrates the risk: a marker/canary, a boolean
  oracle, a timing differential, a redacted cross-account read. Stop there.
- Chain deliberately: CSRF + XSS-assisted, LFI → RCE, info leak → SQLi credentials. Chains
  are where the serious severity comes from, and the technique skills cross-reference each
  other for exactly this.

**Phase 5 — Findings.**
Write each confirmed finding to `domains/<domain>/findings/<id>-<slug>.md` using the report
template in the technique skill's SKILL.md (Title, Severity, Endpoint, Summary, Steps to
reproduce, Impact, Evidence redacted, Remediation, CWE/OWASP). Keep a raw
`evidence/` request-response pair per finding so reproduction never depends on memory.

**Phase 6 — Writeback.**
Update the domain profile: new surface, what was tested, what was ruled out and why, what
the WAF blocks, auth quirks, juicy endpoints not yet tested. End every session with a
**Next session** list — the highest-value untested surface, ranked.

## [Bugbountyskills.md] 3. Technique routing table

| Observed signal | Load first | Then consider |
|---|---|---|
| Cookie/session state change on a request, token fields, Origin/Referer checks | `csrf-testing` | `xss-testing` (assisted), `bac-idor-testing` |
| Reflected/stored parameter reaching HTML/JS, `innerHTML`/`eval`/template sinks | `xss-testing` | `csrf-testing`, `business-logic-testing` |
| SQL-ish errors, filters, `ORDER BY`/`id=` params, JSON/GraphQL query fields | `sqli-testing` | `info-disclosure-testing` (schema), `rce-testing` (DB exec) |
| Object IDs, `user_id`/`account`/`org` params, role fields, JWTs, GraphQL nodes | `bac-idor-testing` | `business-logic-testing`, `csrf-testing` |
| Command-ish fields (`cmd`, `ping`, `exec`), file upload, templates (`{{ }}`), eval/formula fields, wrapper binaries | `rce-testing` | `path-traversal-testing`, `sandbox-escape-testing` |
| URLs/fetch params, webhooks, link previews, image/PDF generation, metadata-shaped targets | `ssrf-testing` | `rce-testing`, `info-disclosure-testing` |
| File/path params, `?page=`, download endpoints, archive handling, Nginx alias paths | `path-traversal-testing` | `info-disclosure-testing`, `rce-testing` |
| Leaked files/headers/sourcemaps, `.git`/`.env`, open buckets, verbose errors, introspection | `info-disclosure-testing` | `sqli-testing`, `bac-idor-testing` |
| Prices, quantities, coupons, multi-step flows, OTP/reset, OAuth, concurrency | `business-logic-testing` | `bac-idor-testing`, `csrf-testing` |
| Sandbox/VM/jail context, `vm`/`exec` wrappers, containers, WASM, version-specific engines | `sandbox-escape-testing` | `rce-testing`, `path-traversal-testing` |

When a signal fits two rows, load both — the technique skills' *chain it with* sections tell
you which direction the escalation runs.

### [Bugbountyskills.md] 4b. Conversation intake — every conversation gets mined into its category

A conversation does not need to produce a submitted report to teach something. Whenever a
substantive exchange covers a testing technique — the user describing what they found,
walking through a recon or exploitation step, asking how a sink or sink chain works, pasting
a request/response pair, recounting a hunt from another tool — run the same loop at the end
of the exchange:

1. **Name the category.** Map the topic to one of the ten technique skills using the routing
   table in §3. DOM XSS talk → `xss-testing` (V-03 DOM-based). A 403-vs-200 authz probe →
   `bac-idor-testing`. A race on checkout → `business-logic-testing`. If it genuinely spans
   two categories, write to both but pick a *primary*.
2. **Pull the core, not the transcript.** The lesson is the non-obvious detail: the gotcha,
   the false-positive pattern, the tooling trick, the sequencing that worked, the thing that
   silently failed. Not "we talked about XSS" — *what about the discussion was surprising*.
3. **Write it back into that category.** Fold the core into the matching skill's
   `references/variants-*.md` under the right variant — a gotcha under *False positives*,
   a new detect step under *Detect*, a payload shape into `payloads.md`. Deepen the existing
   variant; do not create a new skill or a new file for a single insight.
4. **Log it in `LESSONS.md`** with source `conversation`, the skill touched, and the change.
5. **Skip noise.** If the exchange held no non-obvious detail — pure theory, a definition, a
   task with no security insight — write nothing. Forcing entries for ordinary exchanges
   drowns the signal this file exists to preserve.

The bar: six months from now, when the same topic comes back, the skill should already
contain what this conversation discovered — without anyone remembering it happened.

## [Bugbountyskills.md] 6. Test mailboxes

Authorized disposable inboxes for engagements that need email verification (signup/OTP/reset
flows) live at `~/.config/bughunter/test-mailboxes.env` (mode 600). Read them at time of need.

Three rules, because these are the mistakes that end bug bounty careers:
- **Never copy the credentials into a skill, profile, finding, evidence file, or chat output.**
  Skills are loaded into model context; reports are read by triage and sometimes by the public.
  Reference the env file path instead.
- **Mailbox access does not grant registration rights.** Before signing up anywhere, check that
  program's brief and the target's `robots.txt`/terms for account-creation rules — Vinted's
  explicitly forbids it. Manual signup by the operator, automated testing after, is the pattern.
- Retrieval: prefer an app password over the account password, and prefer the operator
  pasting a verification link over agent mailbox access where either is available.

## [Bugbountyskills.md] 7. File map

```
/root/Myskill/
├── SKILL_SPEC.md                  # how technique skills are structured
├── LESSONS.md                     # report-derived lesson changelog
├── bug-hunter/                    # this skill
│   └── references/domain-template.md
├── csrf-testing/ ... sandbox-escape-testing/   # the nine playbooks
└── domains/
    └── <domain>/SKILL.md          # per-domain profile skills
        └── findings/ + evidence/
```

Technique skills: read `SKILL.md` for the workflow and routing table, `references/variants-1.md`
and `variants-2.md` for the playbooks, `references/payloads.md` when you need request
templates, tool commands, or evasion encodings.

## [Bugbountyskills.md] 2. TECHNIQUE SKILLS

_Each technique skill follows the structure defined in `SKILL_SPEC.md`:_

_`SKILL.md` = workflow + routing table + report template → `references/payloads.md`
= request templates, tool commands, evasion encodings → `references/variants-1.md`
`& variants-2.md` = deep playbook (V-01..V-N)._

## [Bugbountyskills.md] 2. Engagement workflow

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

## [Bugbountyskills.md] 3. Variant selection table

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

## [Bugbountyskills.md] 4. Verification standard

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

### [Bugbountyskills.md] Summary

<1-3 sentences: which trust assumption is violated, who can exploit it, what they reach.>

### [Bugbountyskills.md] Steps to reproduce

1. Register/sign in as Account A and Account B (tester-controlled).
2. As Account B, create/locate an object: `<OBJECT_ID_B>` (marker: `<MARKER>`).
3. Send the request as Account A against B's object:
   ```bash
   curl -sS -i -H 'Cookie: session=<SESSION_A>' \
     '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_B>'
   ```
4. Observe: `<actual response — 200 + fields proving ownership>`.
5. Control: the same request as Account B, and/or with credentials stripped: `<expected 403/404/401>`.

### [Bugbountyskills.md] Impact

<Concrete: any authenticated user can read/modify/delete any other user's <records>.
One account reaches <N> objects; data class: <PII/financial/private content>. Minimum-impact demo: 1 record.>

### [Bugbountyskills.md] Remediation

<Specific: enforce server-side ownership/role check bound to the session principal on this route,
default-deny; do not rely on client-supplied <param> or hidden UI controls.>

### [Bugbountyskills.md] References

- CWE-639 (Authorization Bypass Through User-Controlled Key) / CWE-862 (Missing Authorization)
- OWASP Top 10 2021 — A01:2021 Broken Access Control
- OWASP API Security — API1:2023 Broken Object Level Authorization / API5:2023 Broken Function Level Authorization
```

## [Bugbountyskills.md] 6. Reference pointers

Read `references/variants-1.md` for variants 1-8 and `references/variants-2.md` for
variants 9-15; read `references/payloads.md` when you need request templates, tool
commands, or WAF-evasion encodings.

Do not guess a variant from the title alone — match your observed signal to the table
in section 3, then follow that variant's **Detect → Proof of concept → Confirm** loop.
`references/payloads.md` also contains the two-account setup procedure (the backbone of
every proof in this skill), the ID-format catalog, the JWT test checklist, GraphQL probe
templates, enumeration throttle rules, and the chain-it-with pointers.

## [Bugbountyskills.md] Payloads, request templates, and cross-cutting material

Everything here is shared infrastructure for variants V-01 … V-15: the two-account
procedure, curl replay templates with `<PLACEHOLDER>` slots, an ID-format catalog, the
JWT test checklist, GraphQL probe templates, enumeration throttle rules, encoding tricks,
tool invocations, and chain-it-with pointers. Templates never contain live targets —
fill every `<PLACEHOLDER>` from your own engagement notes.

## [Bugbountyskills.md] Table of contents

- [Two-account testing setup (the backbone)](#two-account-testing-setup-the-backbone)
- [Curl replay templates](#curl-replay-templates)
- [ID-format pattern catalog](#id-format-pattern-catalog)
- [JWT testing checklist (test steps, not exploit code)](#jwt-testing-checklist-test-steps-not-exploit-code)
- [GraphQL introspection & authorization probes](#graphql-introspection--authorization-probes)
- [Enumeration throttle: rate-limit politely, never hammer](#enumeration-throttle-rate-limit-politely-never-hammer)
- [Encoder / obfuscation tricks](#encoder--obfuscation-tricks)
- [Tool invocations (templates)](#tool-invocations-templates)
- [Chain it with](#chain-it-with)

---

## [Bugbountyskills.md] Two-account testing setup (the backbone)

Every proof in this skill is a *cross-principal* comparison. Do this setup before
touching any variant.

### [Bugbountyskills.md] Why one account proves nothing

Authorization is a relation between **who asks** and **what they ask for**. With a single
account, you only ever observe requests where asker and owner are the same principal —
and the server is *supposed* to return your own object. So every possible outcome is
consistent with a perfectly healthy system:

- `200 + your data` → could be "ownership check passed" (correct) or "no check at all" (broken).
- `403/404` → could be a real check, or just a wrong/guessed ID.

There is no discriminating signal. The moment **A requests B's object**, the outcomes
split: a correct system says `403/404`, a broken one says `200 + B's data`. That single
differential is the finding — and the reason one-account "IDOR reports" (usually a
soft-404 or dummy object) get triaged as invalid. Two accounts turn an opinion into
evidence, and the control request (same call as B, or with credentials stripped) gives
you the independent second signal the verification standard demands.

### [Bugbountyskills.md] Procedure

1. **Create both principals.** Account A (probe session) and Account B (target session)
   via the normal signup flow, two distinct emails, both inside program scope. Check the
   program's rules on multiple accounts first — most explicitly allow tester accounts;
   ask the program manager if unclear.
2. **Isolate the sessions.** Separate browser profiles (or containers) and separate curl
   cookie jars — never let one jar overwrite the other, and never replay a request with
   both cookies present. Cross-contaminated sessions are the #1 cause of bogus IDOR
   "confirmations".
   ```bash
   curl -sS -c jar_a.txt '<TARGET_URL>/login' -d 'user=<EMAIL_A>&pass=<PASS_A>' -X POST
   curl -sS -c jar_b.txt '<TARGET_URL>/login' -d 'user=<EMAIL_B>&pass=<PASS_B>' -X POST
   ```
3. **Seed identifiable objects.** Each account creates one object of every class you
   intend to test (note, document, order, file, key) with a unique marker string, e.g.
   B's note body = `B-MARKER-9271`, A's = `A-MARKER-4810`. Markers let you recognize
   whose data a response contains at a glance, even after redaction.
4. **Record the identifiers.** For each object note: `<OBJECT_ID_A>`, `<OBJECT_ID_B>`,
   `<USER_ID_A>`, `<USER_ID_B>`, plus tenant/role ids if the app has them. Classify the
   ID shape using the catalog below — it tells you whether enumeration is even feasible.
5. **Establish controls.** Three reference responses you will reuse in every proof:
   (a) A fetches A's object → expect `200`; (b) A fetches B's object → expect `403/404`;
   (c) no credentials at all → expect `401`. If (a) and (c) don't behave as expected,
   fix your setup before probing — a broken baseline invalidates everything after it.
6. **Prefer tester-owned data for writes.** Destructive probes (PUT/DELETE) run against
   B's *test* objects only — created in step 3 for this purpose. If a program restricts
   destructive testing, read-only proofs (V-01, V-02, V-12, V-15) still stand.
7. **Third-party objects: minimum touch.** Sometimes the only reachable objects belong
   to real users. Request *one* record, capture the minimum fields proving whose data it
   is (mask the rest), and stop. A redacted proof is enough for a report — never
   enumerate or exfiltrate a real user's data beyond that.

---

## [Bugbountyskills.md] Curl replay templates

Fill slots; keep jars separate; `-i` always on so you see status and headers.

```bash

## [Bugbountyskills.md] --- T1: own-object baseline (control A) ---------------------------------

curl -sS -i -b jar_a.txt '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_A>'

## [Bugbountyskills.md] --- T2: cross-principal probe (the actual test) ------------------------

curl -sS -i -b jar_a.txt '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_B>'

## [Bugbountyskills.md] --- T3: no-credentials control (V-02: missing auth vs missing check) ----

curl -sS -i -c /dev/null '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_B>'

## [Bugbountyskills.md] --- T4: write probe — use only on B's tester-created object -------------

curl -sS -i -b jar_a.txt -X PUT '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_B>' \
  -H 'Content-Type: application/json' -d '{"marker":"A-PROOF-1"}'

## [Bugbountyskills.md] --- T5: mass-assignment probe (V-04) ------------------------------------

curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/<RESOURCE>' \
  -H 'Content-Type: application/json' \
  -d '{"name":"probe","role":"admin","owner_id":"<USER_ID_A>"}'

## [Bugbountyskills.md] --- T6: HPP duplicate-parameter probe (V-07) ----------------------------

curl -sS -i -g -b jar_a.txt '<TARGET_URL>/api/<RESOURCE>?id=<OBJECT_ID_A>&id=<OBJECT_ID_B>'
curl -sS -i -b jar_a.txt '<TARGET_URL>/api/<RESOURCE>?id[]=<OBJECT_ID_A>&id[]=<OBJECT_ID_B>'

## [Bugbountyskills.md] --- T7: role/context header flip (V-11) ---------------------------------

curl -sS -i -b jar_a.txt -H 'X-Role: admin' '<TARGET_URL>/api/<ROLE_GATED_FUNCTION>'

## [Bugbountyskills.md] --- T8: version differential (V-10) -------------------------------------

curl -sS -i -b jar_a.txt '<TARGET_URL>/api/v2/<RESOURCE>/<OBJECT_ID_B>'   # expect 403
curl -sS -i -b jar_a.txt '<TARGET_URL>/api/v1/<RESOURCE>/<OBJECT_ID_B>'   # observe

## [Bugbountyskills.md] --- T9: nested-path segment matrix (V-13) -------------------------------

curl -sS -i --path-as-is -b jar_a.txt \
  '<TARGET_URL>/api/users/<USER_ID_A>/orders/<ORDER_ID_B>'
curl -sS -i --path-as-is -b jar_a.txt \
  '<TARGET_URL>/api/users/../users/<USER_ID_B>/orders/<ORDER_ID_B>'

## [Bugbountyskills.md] ID-format pattern catalog

Collect 3-5 legitimate IDs first (your own objects + any public listing), then classify:

| Shape | Example | Detection notes | Enumeration reality |
|---|---|---|---|
| **Sequential int** | `4819`, `4820`, `4821` | Exact `+1` (or small fixed) deltas; low cardinality; often visible in incrementing 404-vs-200 boundaries | Trivially enumerable — one probe per neighbor. Highest severity when unauthenticated. Sweep politely (see throttle note), stop at proof |
| **UUIDv1 (timestamp)** | `b438f2c0-58cc-**1**1e4-a1b2-0800200c9a66` | 3rd group starts with `1` → v1/v2. Decode time fields (60-bit timestamp, 100ns units since 1582-10-15): if it equals the object's known creation time, timestamp leaks are confirmed. Last 12 hex = node/MAC — constant node across IDs means fixed hardware/VM identity | Time-sorted and structurally guessable *around* an ID you own: neighbors exist at predictable timestamps. Test prediction against B's fresh object (V-08 step 5) |
| **UUIDv4 (random)** | `3f1c9a7e-8b2d-**4**e5a-**9**c3f-7a0d2e5b81c4` | 3rd group `4`; variant nibble `8|9|a|b`; no observable order or delta across samples | 122 bits — enumeration is infeasible; do NOT brute-force. Still an IDOR vector: any single leaked/guessed v4 (from logs, sourcemaps, referrers) is enough. IDs ≠ authorization |
| **Hashids / opaque slug** | `Xk3vP9aQ`, `aG9s_5Qw9L`, `invoice-n3x8p` | Mixed alphabet, fixed length, URL-safe chars; test *determinism*: same object id → same string across sessions/encodings indicates reversible encoding with a salt | Often crackable if salt is weak/short (known open-source decoders) — but authz must never rely on opacity. If decode works, you get an ID list for V-01 |
| **Snowflake (time-bucketed int)** | `1849273014589747200` (18-19 digits) | Time-ordered integers, monotonic even across accounts. Decode: `(id >> 22) + custom_epoch_ms` → creation ms; low bits = machine/sequence. Check whether observed creation times match the decoded epoch | Neighbors in time are neighbors in ID space → candidate generation is cheap. Confirm with one predicted ID owned by B |

**Workflow:** classify → pick the matching Detect steps in V-08 → if predictable,
combine with V-01/V-05 (predictability alone is not a vuln; missing authz makes it one).

---

## [Bugbountyskills.md] --- G2: field/arg detail for one type (find $id: ID! entry points) ------

curl -sS -b jar_a.txt -X POST '<TARGET_URL>/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"{ __type(name:\"<TYPE_NAME>\") { fields { name args { name type { name kind } } type { name kind } } } }"}'

## [Bugbountyskills.md] --- G3: partial introspection fallback (full introspection disabled) ----

curl -sS -b jar_a.txt -X POST '<TARGET_URL>/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { queryType { name } } }"}'

## [Bugbountyskills.md] Also probe: { __type(name:\"Query\") { fields { name } } }  and error-based field suggestions.

## [Bugbountyskills.md] --- G4: own-node baseline ----------------------------------------------

curl -sS -b jar_a.txt -X POST '<TARGET_URL>/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"query($id:ID!){ node(id:$id){ ... on <TYPE> { id <PRIVATE_FIELD> } } }","variables":{"id":"<OWN_BASE64_ID>"}}'

## [Bugbountyskills.md] --- G5: cross-principal probe (swap the decoded inner id) ---------------

## [Bugbountyskills.md] Global IDs are usually base64("<Type>:<id>") — encode locally:

## [Bugbountyskills.md] printf '%s' '<TYPE>:<OTHER_USER_NUMERIC_ID>' | base64

curl -sS -b jar_a.txt -X POST '<TARGET_URL>/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"query($id:ID!){ node(id:$id){ ... on <TYPE> { id <PRIVATE_FIELD> } } }","variables":{"id":"<BASE64_TYPE_B_ID>"}}'

## [Bugbountyskills.md] --- G7: field-level authz pass (sensitive fields on your OWN node) ------

curl -sS -b jar_a.txt -X POST '<TARGET_URL>/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"{ me { id email phone internalNotes } }"}'

## [Bugbountyskills.md] Encoder / obfuscation tricks

Use these *after* a plain probe fails — to get past a WAF or an edge normalizer, not to
mask what you did. Report the working variant plainly.

| Trick | Example | When to use |
|---|---|---|
| URL-encode one char | `?id=-1`, `?id=48%20`, `%2d%31` | WAF pattern-matches the raw value |
| Double-encode | `%252f`, `%2527` | Edge decodes once, app decodes twice |
| Path case variation | `/API/Users/<id>` | Case-sensitive router vs. checker mismatch |
| Param name case | `?Id=`, `?ID=`, `?user_ID=` | Parser-level case folding differs across layers |
| Array / index syntax | `id[]=`, `id[0]=`, `id.`, `id_` | V-07 HPP and PHP/ASP/Node parser differences |
| Body format swap | JSON body ↔ form-encoded ↔ multipart | Check reads query, action reads body (or vice versa) |
| Param position swap | query ↔ body ↔ header (`X-Id`) | Layer-specific allow-lists |
| Method override | `X-HTTP-Method-Override: PUT`, `_method=DELETE` | Only one verb is guarded |
| Trailing slash / `;` / `//` | `/api/obj/<id>/`, `/api;/obj/<id>` | Router normalization vs. authz middleware |
| Raw path (`--path-as-is`) | `/api/users/../users/<id>/` | V-13 — curl normally "helpfully" normalizes |

---

## [Bugbountyskills.md] Diff-aware probe: own vs foreign object side by side

diff <(curl -sS -b jar_a.txt "<TARGET_URL>/api/obj/<OBJECT_ID_A>") \
     <(curl -sS -b jar_a.txt "<TARGET_URL>/api/obj/<OBJECT_ID_B>")

## [Bugbountyskills.md] Chain it with

- **`csrf-testing`** — *state-changing endpoints.* A cross-principal write (V-01/V-05
  PUT/DELETE) with no CSRF token, lax `SameSite`, or a simple-JSON endpoint readable by
  `text/plain` POST becomes **one-click**: a victim's browser performs the write on
  another user's object. Test the state-changing IDOR with a CSRF lens — GET-based or
  token-less mutations escalate severity a full step. See `csrf-testing` for token
  extraction, tunnel, and CORS/CSWSH chains.
- **`business-logic-testing`** — *role assignment at registration.* If `role`,
  `tenant_id`, or `plan` can be injected during signup or a workflow step, you have V-04
  mass assignment feeding V-06 vertical escalation from minute one — the vertical bypass
  may be reachable without ever exploiting an authenticated endpoint. Also covers
  workflow/state-machine abuses (approval, OTP, payment steps) that pair with role flips.
  See `business-logic-testing` for registration, workflow, and race-condition chains.
- **`info-disclosure-testing`** — *leaked IDs in sourcemaps, logs, and bundles.* Most
  V-01/V-08 engagements start here: `.map` sourcemaps reveal admin routes and param
  names, `.git`/`.env` and stack traces leak object IDs and UUID examples, JS bundles
  expose GraphQL schemas and versioned paths (V-10/V-12), and open buckets/log files
  hand you the ID corpus that makes enumeration unnecessary. Run it first for recon, and
  cite any leaked ID as the starting point of your IDOR chain.

The rest of the suite: `xss-testing` (UI redress / self-XSS-assisted proofs),
`sqli-testing` (key-lookup injections found in the JWT checklist), `path-traversal-testing`
(V-13's `..` normalization reaching files), `ssrf-testing` (second-order sinks that
fetch attacker URLs, V-05), `sandbox-escape-testing` — cross-reference by directory name
when a finding's root cause belongs next door.

## [Bugbountyskills.md] Table of contents

- [V-01: Direct parameter manipulation via authenticated IDOR security evasion](#v-01-direct-parameter-manipulation-via-authenticated-idor-security-evasion)
- [V-02: Unauthenticated endpoint identification via IDOR resource enumeration](#v-02-unauthenticated-endpoint-identification-via-idor-resource-enumeration)
- [V-03: Scripted request validation and automation via custom cURL IDOR frameworks](#v-03-scripted-request-validation-and-automation-via-custom-curl-idor-frameworks)
- [V-04: Internal variable overwriting via mass assignment object property injection](#v-04-internal-variable-overwriting-via-mass-assignment-object-property-injection)
- [V-05: Horizontal privilege escalation via missing object-level access control (BOLA/BMAO)](#v-05-horizontal-privilege-escalation-via-missing-object-level-access-control-bolabmao)
- [V-06: Vertical privilege escalation via function-level access control evasion (RBAC/ABAC bypass)](#v-06-vertical-privilege-escalation-via-function-level-access-control-evasion-rbacabac-bypass)
- [V-07: Server-side array confusion via HTTP parameter pollution (HPP) IDOR mutations](#v-07-server-side-array-confusion-via-http-parameter-pollution-hpp-idor-mutations)
- [V-08: Cryptographic entity guessing via cryptographically weak UUID/GUID generation routines](#v-08-cryptographic-entity-guessing-via-cryptographically-weak-uuidguid-generation-routines)

---

## [Bugbountyskills.md] Control (A's own object) vs. probe (B's object)

curl -sS -i -H 'Cookie: session=<SESSION_A>' '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_A>'
curl -sS -i -H 'Cookie: session=<SESSION_A>' '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_B>'
```

**Confirm:** Log in as B and fetch the same object; the data A received must match B's
own view (unique marker field, timestamps). One request proves nothing — the same 200
could be dummy data.

**False positives:** Endpoints that echo any ID with a default/dummy object; soft-404s
(HTTP 200 + empty body or `null`); ID namespaces colliding across types (ID `451` is a
different object family than you think); CDN caching a response keyed without the ID;
redirects landing you back on your own object (check the final body, not the 302).

**Impact:** "Any authenticated user can read (or modify) any other user's `<records>` by
changing `<param>` — no enumeration needed beyond possessing an ID." Name the data class
(PII, financial, private content) and the number of objects reachable if you sampled it.

**Remediation:** Enforce a server-side ownership check binding the object to the
session principal on every read/write, deny by default when the binding fails — the ID
must be a lookup key, never an authorization credential.

**CWE / OWASP:** CWE-639 (Authorization Bypass Through User-Controlled Key); OWASP
Top 10 A01:2021 Broken Access Control; OWASP API API1:2023 BOLA.

---

## [Bugbountyskills.md] Strip every credential; use a clean cookie jar so nothing leaks in

curl -sS -i -c /dev/null '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_B>'

## [Bugbountyskills.md] Control: a known-protected sibling

curl -sS -i -c /dev/null '<TARGET_URL>/api/profile'
```

**Confirm:** The same resource ID is *denied* to an unauthenticated caller on a sibling
route but returned in full here — proving this specific route skipped auth rather than
the whole API being public by design.

**False positives:** Genuinely public resources (marketing, shared links with secret
tokens — a long random path is "capability URL", classify differently); browser
extension or proxy auto-injecting an auth header (verify with curl, not Repeater that
still has a rule); shared CDN cache serving a logged-in user's page (check for `Age` and
replay with `Cache-Control: no-cache`); "public profile" pages that are intentional —
compare field depth with the authenticated view.

**Impact:** "The `<resource>` API requires no authentication; anyone on the internet can
read `<data>` for any ID." Unauthenticated findings are typically one severity step above
the authenticated equivalent.

**Remediation:** Put the route behind default-deny authentication middleware shared with
the rest of the API — public access must be an explicit allow-list entry, not an
omission.

**CWE / OWASP:** CWE-306 (Missing Authentication for Critical Function); OWASP A01:2021.

---

## [Bugbountyskills.md] V-04: Internal variable overwriting via mass assignment object property injection

**Mechanism:** The framework binds the request body wholesale onto a model/DTO
(`req.body` → `user.save()`), including fields no client should set: `role`, `is_admin`,
`owner_id`, `verified`, `tenant_id`, `credits`, `price`. The violated assumption is
"input only contains the fields the form showed".

**Preconditions:**
- Body maps to a persistent object (ORM/Active Record/Eloquent, or a Rails
  `params.require(...).permit` misconfig) and a candidate privileged/ownership field
  exists in the model (guess from UI, API docs, client JS, or error messages).

**Detect:**
1. Capture a legitimate state-changing request (profile update, settings save, order
   create) as Account A.
2. Add one extra property at a time to the body: `role`, `admin`, `is_admin`,
   `owner_id`, `user_id`, `verified`, `status`, `credits`, `tenant_id`, `password_hash`
   (read-only probes first).
3. Diff response *and* follow-up behavior: re-fetch the object, then hit a function only
   available at the new privilege/ownership level.
4. Enumerate bindable fields with a canary key: unknown-key errors, a `422` naming
   allowed fields, or silent drop reveals the allow/deny-list shape.
5. Overwrite ownership on *someone else's* object (`owner_id` → A's id on
   `<OBJECT_ID_B>`) — that converts a vertical probe into a takeover.

**Proof of concept:**
```bash
curl -sS -i -X POST '<TARGET_URL>/api/<RESOURCE>' \
  -H 'Cookie: session=<SESSION_A>' -H 'Content-Type: application/json' \
  -d '{"name":"probe","role":"admin"}'          # privileged-field probe

curl -sS -i -X PUT '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_B>' \
  -H 'Cookie: session=<SESSION_A>' -H 'Content-Type: application/json' \
  -d '{"owner_id":"<USER_ID_A>"}'               # ownership-transfer probe
```

**Confirm:** The injected value takes effect through an *independent* path: as A you now
pass a role-gated check, or as B the object is foreign-owned while A can still manage it.
A field echoed back in the response body is not confirmation.

**False positives:** Field accepted and silently discarded (return payload reflects
request, DB does not); role field written but the app re-derives role from a separate
relations table at check time; harmless display preferences behaving as designed;
`null` hydration where absent fields are nulled rather than set (check before/after);
admin flag on a demo tenant where everyone is admin.

**Impact:** "A user can set `<privileged_field>` on their own (or another user's) record,
gaining `<role/action>` or taking ownership of `<resource>`." State whether it persists.

**Remediation:** Bind each endpoint to an explicit per-endpoint allow-list DTO —
never assign request payloads onto the persistence model directly, and set
ownership/role columns only from server-side session context.

**CWE / OWASP:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined
Object Attributes); OWASP A01:2021 + A04:2021 Insecure Design.

---

## [Bugbountyskills.md] V-08: Cryptographic entity guessing via cryptographically weak UUID/GUID generation routines

**Mechanism:** Object identifiers look unguessable but are structurally predictable:
UUIDv1/v2 embed a timestamp (and MAC), DB auto-increment counters leak volume, snowflake
IDs embed a millisecond timestamp with a fixed epoch, and weak PRNGs seed from time.
Knowledge of *your own* IDs reveals *other users'* IDs — turning a "secret URL" into a
list. (Predictability alone is not a vulnerability: it becomes one when combined with a
missing authz check, i.e., it upgrades V-01 from hard to trivial.)

**Preconditions:**
- You can collect 3-5 IDs you legitimately own (or public IDs from listing pages).
- IDs follow one of the cataloged shapes — run the catalog in `payloads.md` first.

**Detect:**
1. Collect several IDs (your objects + any public ones) and lay them side by side.
2. Check UUID version: third group starts with `1` → v1/v2 (timestamp-bearing); with `4`
   → v4 (random — stop here for pure guessing). Decode v1 time fields: does the
   timestamp equal the object's creation time you know? That's a leak by itself.
3. Check the node/MAC field (last 12 hex): a constant value across IDs means a real MAC
   or fixed node — more structure to correlate; random node per ID weakens the attack.
4. Integers: measure deltas (+1, +7, time-bucketed?). Snowflake-shaped 18-19 digit IDs:
   shift right 22 bits, subtract the vendor epoch — does it decode to a plausible
   creation time? Then neighbors in time are neighbors in ID space.
5. Prediction test with two accounts: create a new object as B *after* observing A's
   sequence, generate the candidate ID locally, and fetch it as A. Success = confirmed
   predictability against a real other-principal object.

**Proof of concept:** (structure, not a brute force — see payload catalog for decoders)
```bash

## [Bugbountyskills.md] Candidate derived from your own ID(s); fetch as A

curl -sS -i -H 'Cookie: session=<SESSION_A>' \
  '<TARGET_URL>/api/<RESOURCE>/<PREDICTED_ID_FOR_B_OBJECT>'
```

**Confirm:** You fetch an object belonging to B that you never observed in any response
(predicted from your own IDs), and B's session confirms that object is B's. Optionally,
decoded v1 timestamp equals B's real creation time — an independent structural signal.

**False positives:** RFC 9562 v1/v2 with a random node field (no MAC leak); hashids or
slugged IDs that merely *look* sequential (same input → same output reveals a salt —
check determinism); ID count too small to distinguish pattern from chance; IDs shared
across environments (staging IDs replayed in prod); timestamps present but IDs still
122-bit random for v4.

**Impact:** "Object identifiers are predictable (`<shape>`), so any user can enumerate
other users' `<resource>` — combined with `<existing authz gap>` this yields bulk
enumeration." If the IDs alone leak creation-time metadata, note that as a secondary
information disclosure.

**Remediation:** Issue random (UUIDv4/128-bit) or HMAC-derived opaque IDs server-side,
and never let authorization depend on ID secrecy — predictability must not widen access.

**CWE / OWASP:** CWE-330 (Use of Insufficiently Random Values) / CWE-340
(Predictability); paired with CWE-639 when exploited; OWASP A01:2021 (+ A02:2021 where
crypto primitives are the root cause).

## [Bugbountyskills.md] Table of contents

- [V-09: Second-order IDOR via dynamic session parameter substitution sinks](#v-09-second-order-idor-via-dynamic-session-parameter-substitution-sinks)
- [V-10: API endpoint version bypassing for unprotected legacy resource fetching](#v-10-api-endpoint-version-bypassing-for-unprotected-legacy-resource-fetching)
- [V-11: Contextual role-based state flipping through client-side request mutation](#v-11-contextual-role-based-state-flipping-through-client-side-request-mutation)
- [V-12: GraphQL query object variable manipulation for unauthorized node access](#v-12-graphql-query-object-variable-manipulation-for-unauthorized-node-access)
- [V-13: Nested API resource path traversal for internal object-level access bypass](#v-13-nested-api-resource-path-traversal-for-internal-object-level-access-bypass)
- [V-14: JWT algorithm laundering and signature nullification privilege escalation](#v-14-jwt-algorithm-laundering-and-signature-nullification-privilege-escalation)
- [V-15: Cross-tenant data exposure via insecure multi-tenancy boundary isolation flaws](#v-15-cross-tenant-data-exposure-via-insecure-multi-tenancy-boundary-isolation-flaws)

---

## [Bugbountyskills.md] 1) Store B's object id in a trusted field (write-time check may pass)

curl -sS -i -X PUT '<TARGET_URL>/api/profile' -H 'Cookie: session=<SESSION_A>' \
  -H 'Content-Type: application/json' -d '{"default_document_id":"<OBJECT_ID_B>"}'

## [Bugbountyskills.md] 2) Trigger the sink

curl -sS -i -X POST '<TARGET_URL>/api/exports' -H 'Cookie: session=<SESSION_A>' \
  -H 'Content-Type: application/json' -d '{"type":"default_document"}'
```

**Confirm:** The export contains B's data (marker match) and B's session confirms
ownership — decisively, no trigger-time request carried B's ID: the substitution happened
server-side from stored state.

**False positives:** Value echoed but never used (send a garbage ID — if the sink
doesn't error, it isn't consumed); sink re-derives the owner from the session and returns
your own object anyway; sandbox copies generated per user; queue workers running with a
broad service account (still a finding — classify as over-privileged service context
rather than per-user IDOR); server overwrites your stored id before use.

**Impact:** "Values stored in `<field>` are trusted at use time; a user can cause
`<server-side action>` on another user's `<object>`, delivering `<data>` to the
attacker." Note the cause→effect delay for triage.

**Remediation:** Re-authorize at the point of use: every sink must resolve the stored
reference against the current principal's ownership before querying, not assume
storage-time validity.

**CWE / OWASP:** CWE-639; OWASP A01:2021; OWASP API1:2023 BOLA (second-order variant).

---

## [Bugbountyskills.md] V-11: Contextual role-based state flipping through client-side request mutation

**Mechanism:** The server chooses an authorization context (role, tenant, agency,
impersonation, "view as") from a client-controlled channel — custom header, query param,
non-integrity-protected cookie, or body field — instead of deriving it from the
authenticated session. Flipping the value re-decides your permissions. The violated
assumption is "the client will only send the context it was issued".

**Preconditions:**
- A discoverable context input: `X-Role`, `X-User-Type`, `role`, `as`, `impersonate`,
  `tenant`, `X-Forwarded-Role`, `org` claims in client state, or an interceptable
  role-switcher request.
- Server behavior (data scope, actions, response shape) varies with the context.

**Detect:**
1. Mine context inputs from JS/HTML: role-switch dropdowns, `X-` headers in fetch code,
   `localStorage` keys like `activeRole`, `?org=` in deep links.
2. Capture a normal request, then flip one context value at a time (`role=user` →
   `role=admin`, `X-User-Type: customer` → `staff`, `tenant`/`org` ids swapped to B's).
3. Diff both dimensions: response *content* (new fields, other users' rows) and response
   *capability* (previously 403'd action now succeeds). Capability change = escalation;
   content change alone may be a filter difference.
4. Check persistence: does the flipped context survive refresh (was it written to your
   profile — that's V-04 territory) or is it per-request only?
5. Test the trust chain: if the context arrives in a JWT claim, fold this into V-14; if
   in a cookie without `HttpOnly`/signature, note cookie tampering as the vector.

**Proof of concept:**
```bash
curl -sS -i -H 'Cookie: session=<SESSION_A>' -H 'X-Role: admin' \
  '<TARGET_URL>/api/<FUNCTION_ONLY_ADMANS_HAVE>'
curl -sS -i -H 'Cookie: session=<SESSION_A>' -H 'X-Tenant: <TENANT_ID_B>' \
  '<TARGET_URL>/api/<RESOURCE>'
```

**Confirm:** A function/data set that is only reachable in the flipped role, verified
against an account that legitimately holds that role (or a lab admin account): same
outcome from the forged context and from the real role proves the server honored your
claim. Echoed headers or cosmetic changes don't count.

**False positives:** Header/param echoed into the response but ignored in policy; role
re-derived from the DB at check time (flip accepted, effect null); display-only
context (different UI theme, same data); CDN/bot-management headers with predictable
names that apps merely log; context affecting a sandbox/test mode flag.

**Impact:** "Authorization context is attacker-controlled: by setting `<input>` the user
gains `<role>`'s `<actions/data>` without any role assignment." If the flip reaches
other users' data, cross-reference the tenant/role data class for severity.

**Remediation:** Derive role, tenant, and impersonation state solely from the verified
session/token server-side; strip client-supplied context fields at the edge.

**CWE / OWASP:** CWE-602 (Client-Side Enforcement of Server-Side Security) / CWE-862;
OWASP A01:2021.

---

## [Bugbountyskills.md] V-15: Cross-tenant data exposure via insecure multi-tenancy boundary isolation flaws

**Mechanism:** Tenancy scope should be enforced server-side from session context on every
query, cache key, and background job. When the tenant id comes from the client, is omitted
from a WHERE clause, or is missing from a cache key, records cross the org/workspace
boundary — "sharing the database is safe as long as the UI shows one tenant" is false.

**Preconditions:**
- You can hold sessions in two tenants (two organizations — self-serve signup is the
  normal path; both under your control for the proof).
- Resources exist that are unique to tenant B (marker field set by B).

**Detect:**
1. Establish two tenants (A and B) with uniquely marked objects; record both tenant ids
   (`org_id`, `workspace`, subdomain, `X-Tenant`, token claim).
2. Enumerate tenant carriers: subdomain, path prefix (`/orgs/<id>/`), header, query
   param, JWT claim. Try flipping each to B's value with session A — some apps will
   happily change your *view* even when they don't change your *permissions*.
3. Sweep the read surfaces: detail endpoints (V-01 style), list/search/export endpoints
   (filters are where tenant clauses go missing), autocomplete, and reports.
4. Cache axis: replay B's request under A's session and look for B's response with A's
   CDN headers (`Age`, `X-Cache`) — tenant-agnostic cache keys leak even correct apps.
5. Background surfaces: export jobs and webhooks often run with a tenant-spanning service account.
6. Test both matrices: within-tenant peer escalation and cross-tenant are separate findings.

**Proof of concept:**
```bash

## [Bugbountyskills.md] List-surface sweep (server-side filter check)

curl -sS -i -H 'Cookie: session=<SESSION_A>' '<TARGET_URL>/api/search?q=<B_MARKER_STRING>'
```

**Confirm:** Data that exists *only* in tenant B (marker verified in B's own session)
returns under A's session or A's tenant context — and the no-flip control shows only
A's rows. That four-way differential (A plain / A flipped / B own / A-flipped-then-B-check)
excludes cache and fixture explanations.

**False positives:** Intentionally cross-tenant resources (public templates, marketplace
listings, platform announcements — check sharing mode); demo fixtures visible to all;
shared ID namespace but rows are still your own (verify marker); two accounts accidentally
in the *same* tenant (re-verify tenant ids — the most common self-inflicted waste here).

**Impact:** "A user of tenant `<X>` can read/modify data belonging to tenant `<Y>`
(`<record class>`), i.e., a cross-company data breach in a B2B product — regulatory
exposure (GDPR/CCPA)." State blast radius: one record shown, the record class implied.

**Remediation:** Derive tenant scope exclusively from the verified session and enforce it
at the query layer (repository policy or DB row-level security) plus in every cache key.

**CWE / OWASP:** CWE-639 / CWE-284 (tenant boundary as access-control root); OWASP
A01:2021; OWASP API1:2023 BOLA (tenant-wide manifestation).

## [Bugbountyskills.md] >> business-logic-testing — SKILL.md

*Source: `/root/Myskill/business-logic-testing/SKILL.md`*

## [Bugbountyskills.md] 2. Engagement workflow

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

## [Bugbountyskills.md] 3. Variant selection table

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

## [Bugbountyskills.md] 4. Verification standard

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

## [Bugbountyskills.md] Title: <Flaw> allows <consequence> via <mechanism> (V-<NN> <short variant name>)

**Severity:** <Low/Medium/High/Critical — justify with reach + auth requirement + demonstrated amount>
**Endpoint:** `<METHOD> <path>` (parameters: `<param>`)
**Variant:** V-<NN> <name>

### [Bugbountyskills.md] Summary

<1-3 sentences: which server-side assumption is violated, who can exploit it, what it yields.>

### [Bugbountyskills.md] Steps to reproduce

1. Baseline (control): <legit request → expected server state>.
2. Probe: <tampered / skipped / raced request, placeholders filled>:
   ```bash
   curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/<ACTION>' \
     -H 'Content-Type: application/x-www-form-urlencoded' -d '<TAMPERED_PARAMS>'
   ```
3. Verify server state: <fresh GET / second session / ledger read> → <persisted result>.
4. Control re-check: <unmodified request still behaves as expected>.

### [Bugbountyskills.md] Impact

<Demonstrated effect with exact amount/multiplier/steps, then bounded reach (per-account
caps, rate limits). Conservative wording: demonstrated value first, theoretical scale labeled.>

### [Bugbountyskills.md] Remediation

<Specific: server-side recompute / atomic conditional update / transition table / state
validation — name the check this variant is missing, not generic "validate input".>

### [Bugbountyskills.md] References

- CWE-<NNN> / OWASP Top 10 2021 — A04:2021 Insecure Design (or A01/A05/A07 per variant)
- <flow spec: e.g. RFC 9700 OAuth 2.0 Security BCP, NIST SP 800-63B for OTP>
```

## [Bugbountyskills.md] 6. Reference pointers

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

## [Bugbountyskills.md] Payloads, request templates, and cross-cutting material

Shared infrastructure for variants V-01 … V-15: the race-condition testing procedure
(parallel bursts + race-vs-jitter), the workflow mapping procedure that every skip/swap
test depends on, the negative/edge value test matrix, the OAuth 2.0 test-step checklist,
Host-header/password-reset templates, the encoder/obfuscation table for path discovery,
and chain-it-with pointers. Templates never contain live targets — fill every
`<PLACEHOLDER>` from your own engagement notes. Guardrails from `SKILL.md` section 1
apply to everything here: minimal demonstrable amounts, tester-owned coupons/accounts,
sandbox first.

## [Bugbountyskills.md] Table of contents

- [Race-condition testing procedure (parallel bursts)](#race-condition-testing-procedure-parallel-bursts)
- [Telling a real race from jitter](#telling-a-real-race-from-jitter)
- [Workflow mapping procedure (map first, then skip/swap)](#workflow-mapping-procedure-map-first-then-skipswap)
- [Negative / edge value test matrix](#negative--edge-value-test-matrix)
- [OAuth 2.0 testing checklist (test steps)](#oauth-20-testing-checklist-test-steps)
- [Host header & password reset test templates](#host-header--password-reset-test-templates)
- [Encoder / obfuscation tricks (paths & WAF)](#encoder--obfuscation-tricks-paths--waf)
- [Chain it with](#chain-it-with)

---

## [Bugbountyskills.md] Race-condition testing procedure (parallel bursts)

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

## [Bugbountyskills.md] Telling a real race from jitter

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

## [Bugbountyskills.md] Negative / edge value test matrix

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

## [Bugbountyskills.md] R1: classic Host override on the reset trigger

curl -sS -i -X POST '<TARGET_URL>/forgot-password' \
  -H 'Host: <ATTACKER_HOST>' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'email=<YOUR_TEST_EMAIL>'

## [Bugbountyskills.md] R2: forwarding headers (trusts proxy-derived host)

curl -sS -i -X POST '<TARGET_URL>/forgot-password' \
  -H 'Host: <TARGET_HOST>' -H 'X-Forwarded-Host: <ATTACKER_HOST>' \
  -d 'email=<YOUR_TEST_EMAIL>'

## [Bugbountyskills.md] R3: header variants in one ladder (run one at a time, record each)

## [Bugbountyskills.md] -H 'Forwarded: host=<ATTACKER_HOST>;proto=https'

## [Bugbountyskills.md] -H 'X-Forwarded-Server: <ATTACKER_HOST>'   -H 'X-Host: <ATTACKER_HOST>'

## [Bugbountyskills.md] -H 'X-Original-Host: <ATTACKER_HOST>'      -H 'X-HTTP-Host-Override: <ATTACKER_HOST>'

## [Bugbountyskills.md] R4: duplicate / polluted Host (second value wins in some parsers)

curl -sS -i -X POST '<TARGET_URL>/forgot-password' \
  -H 'Host: <TARGET_HOST>' -H 'Host: <ATTACKER_HOST>' \
  -d 'email=<YOUR_TEST_EMAIL>'

## [Bugbountyskills.md] R5: absolute-form request line (seen by forwarding layers first)

curl -sS -i --request-target 'http://<TARGET_HOST>/forgot-password' \
  -H 'Host: <ATTACKER_HOST>' -X POST -d 'email=<YOUR_TEST_EMAIL>'

## [Bugbountyskills.md] Encoder / obfuscation tricks (paths & WAF)

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

## [Bugbountyskills.md] Chain it with

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

## [Bugbountyskills.md] >> business-logic-testing — variants-1.md (variant playbook)

*Source: `/root/Myskill/business-logic-testing/references/variants-1.md`*

## [Bugbountyskills.md] Table of contents

- [V-01: Transaction integrity violation via price, quantity, and currency parameter tampering](#v-01-transaction-integrity-violation-via-price-quantity-and-currency-parameter-tampering)
- [V-02: State machine defiance via workflow circumvention and multi-step transaction skipping](#v-02-state-machine-defiance-via-workflow-circumvention-and-multi-step-transaction-skipping)
- [V-03: Concurrent state processing flaws via distributed race conditions (HTTP/2 request overlap)](#v-03-concurrent-state-processing-flaws-via-distributed-race-conditions-http2-request-overlap)
- [V-04: Administrative interface discovery via URL obfuscation and Unicode path bruteforcing](#v-04-administrative-interface-discovery-via-url-obfuscation-and-unicode-path-bruteforcing)
- [V-05: Authentication flow manipulation via insecure token or session state modification](#v-05-authentication-flow-manipulation-via-insecure-token-or-session-state-modification)
- [V-06: Insecure password reset logic via Host header injection or token leakage](#v-06-insecure-password-reset-logic-via-host-header-injection-or-token-leakage)
- [V-07: OTP/2FA verification bypass via response manipulation or parameter nullification](#v-07-otp2fa-verification-bypass-via-response-manipulation-or-parameter-nullification)
- [V-08: Algorithmic complexity attacks as a DoS-style logic flaw (cgroup/resource exhaustion)](#v-08-algorithmic-complexity-attacks-as-a-dos-style-logic-flaw-cgroupresource-exhaustion)

---

## [Bugbountyskills.md] Probe: single tampered money field

curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/orders' \
  -H 'Content-Type: application/json' \
  -d '{"product_id":"<PRODUCT_ID>","quantity":1,"currency":"USD","unit_price":0.01}'

## [Bugbountyskills.md] Read back the server-persisted amount, cache-busted

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

## [Bugbountyskills.md] V-02: State machine defiance via workflow circumvention and multi-step transaction skipping

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

## [Bugbountyskills.md] Turbo Intruder — synchronized burst over one HTTP/2 connection

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

## [Bugbountyskills.md] Unicode variant on one promising candidate

curl -sS -i -b jar_a.txt --path-as-is '<TARGET_URL>/<HOMOGLYPH_ADMIN_PATH>'

## [Bugbountyskills.md] Edge rewrite header variant

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

## [Bugbountyskills.md] then read the inbox: does the reset URL point at <ATTACKER_HOST>?

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

## [Bugbountyskills.md] Baseline: wrong code must fail (control)

curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/<VERIFY_STEP>' \
  -H 'Content-Type: application/json' -d '{"code":"000000"}'

## [Bugbountyskills.md] Nullification candidates

curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/<VERIFY_STEP>' \
  -H 'Content-Type: application/json' -d '{"code":null,"otp_verified":true}'
curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/<VERIFY_STEP>' \
  -H 'Content-Type: application/json' -d '{}'

## [Bugbountyskills.md] Independent signal: does the gated step now proceed?

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

## [Bugbountyskills.md] V-08: Algorithmic complexity attacks as a DoS-style logic flaw (cgroup/resource exhaustion)

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

## [Bugbountyskills.md] >> business-logic-testing — variants-2.md (variant playbook)

*Source: `/root/Myskill/business-logic-testing/references/variants-2.md`*

## [Bugbountyskills.md] Table of contents

- [V-09: Coupon and promo code replay via multi-threaded locking failures](#v-09-coupon-and-promo-code-replay-via-multi-threaded-locking-failures)
- [V-10: Negative value input processing flaws leading to account credit generation](#v-10-negative-value-input-processing-flaws-leading-to-account-credit-generation)
- [V-11: Session flashing and race vulnerabilities via concurrent HTTP request overlaps](#v-11-session-flashing-and-race-vulnerabilities-via-concurrent-http-request-overlaps)
- [V-12: ID de-synchronization via multi-stage form context substitution](#v-12-id-de-synchronization-via-multi-stage-form-context-substitution)
- [V-13: Account takeover via OAuth 2.0 dynamic client registration and state spoofing](#v-13-account-takeover-via-oauth-20-dynamic-client-registration-and-state-spoofing)
- [V-14: Business flow evasion through client-side logic interception and response flipping](#v-14-business-flow-evasion-through-client-side-logic-interception-and-response-flipping)
- [V-15: Insecure ID direct assignment during self-registration elevating roles](#v-15-insecure-id-direct-assignment-during-self-registration-elevating-roles)

---

## [Bugbountyskills.md] V-09: Coupon and promo code replay via multi-threaded locking failures

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

## [Bugbountyskills.md] After the burst: authoritative check — distinct orders carrying the discount

curl -sS -b jar_a.txt '<TARGET_URL>/api/orders?mine=1&cb=1' | grep -c '<DISCOUNT_MARKER>'

## [Bugbountyskills.md] V-10: Negative value input processing flaws leading to account credit generation

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

## [Bugbountyskills.md] Baseline

curl -sS -b jar_a.txt '<TARGET_URL>/api/wallet?cb=0'

## [Bugbountyskills.md] Control: legitimate positive purchase (expect debit)

curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/orders' \
  -d 'product_id=<PRODUCT_ID>&quantity=1'

## [Bugbountyskills.md] Probe: single negative quantity (minimal demonstrable unit)

curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/orders' \
  -d 'product_id=<PRODUCT_ID>&quantity=-1'

## [Bugbountyskills.md] Independent signal: ledger/balance re-read

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

## [Bugbountyskills.md] V-12: ID de-synchronization via multi-stage form context substitution

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

## [Bugbountyskills.md] Diff both objects, cache-busted

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

## [Bugbountyskills.md] State omission on the callback (expect: rejected)

curl -sS -i -b jar_victim.txt '<TARGET_URL>/<OAUTH_CALLBACK>?code=<CODE>&state='

