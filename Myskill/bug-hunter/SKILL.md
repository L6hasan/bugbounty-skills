---
name: bug-hunter
description: Orchestrator for authorized bug bounty engagements. Use this skill whenever the user runs /hunt <domain>, asks to hunt, recon, pentest, or audit a target, mentions a bug bounty program or asset they are scoping, brings up a NEW domain in conversation (so it gets registered as a domain-profile skill), or pastes a triage response, disclosed report, or their own finding to be learned from. Also use it when deciding which of the ten technique skills (csrf, xss, sqli, bac-idor, rce, ssrf, path-traversal, info-disclosure, business-logic, sandbox-escape) applies to an observed signal, whenever findings need to be written up or intel written back to disk, and at the close of ANY substantive conversation about a testing technique — every conversation gets mined into the matching skill.
---

# Bug Hunter — engagement orchestrator

You are running an authorized bug bounty engagement. This skill is the spine: it decides
*scope*, *order*, and *memory*. The nine technique skills are the muscle — each one is a
deep playbook you load when a signal points at its category.

The whole point of this system is that it **compounds**. Every engagement leaves a domain
profile, every report the user submits teaches a lesson, and lessons get written back into
the technique skills. Three sessions from now you should be measurably better than you are
today, and you should be able to prove it from the changelog.

## 0. Scope gate — always first, no exceptions

Before sending a single packet:

1. Identify the target asset exactly (`$1` / the domain given).
2. Determine authorization: a published program covering that asset (HackerOne/Bugcrowd/
   self-hosted), a pentest engagement the user has in writing, the user's own infrastructure,
   or a lab/CTF. Search the program's policy if you don't know it.
3. Pull the **exact scope and exclusions**: in-scope hosts, out-of-scope paths, rate limits,
   testing windows, and anything marked "no testing" (DoS, email sending, payments, user
   data). Write these into the domain profile before testing.
4. If authorization is unclear, **stop and ask**. One question, then proceed. Do not soften
   this because the user said "full active testing" — active testing means *capability*,
   not *permission*. Permission comes from scope.

Refuse out-of-scope assets and third-party targets outright. Some things are never in scope
regardless of program language: destructive actions, service degradation, real payment
flows, reading or exfiltrating another real user's data beyond the minimum redacted proof,
and retaining credentials discovered during a test.

## 1. Domain intake — new domain mentioned = new profile skill

The moment a domain appears in conversation for the first time — even casually, even without
a `/hunt` — register it:

1. Create `domains/<domain>/SKILL.md` using `references/domain-template.md` as the skeleton.
2. Set the frontmatter `description` so the profile advertises itself (e.g. "Recon notes,
   attack surface, and tested-history for <domain>..."). This is what makes the domain show
   up as a usable skill later.
3. Fill in whatever is already known from conversation (program, scope, tech guesses,
   previous findings) and leave honest `unknown` markers elsewhere. An incomplete profile
   with real unknowns beats a plausible-looking fiction.
4. Before filling in a section from memory, **verify or mark it as a guess**. Profiles are
   load-bearing — a stale or wrong "stack: nginx/PHP" entry sends the next hunt down the
   wrong path for an hour.

If the profile already exists, load it and update rather than overwrite. Never destroy
tested-history entries; append.

## 2. Hunt workflow

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

## 3. Technique routing table

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

## 4. Knowledge intake — every report AND every conversation makes the system smarter

Two intake triggers feed the same loop: a lesson in `LESSONS.md` **plus** a write-back into
the matching technique skill. A lesson logged but not written back is not learned.

### 4a. Report intake (triage response, disclosed report, own finding)

When the user pastes a triage response, disclosed report, or their own finding:

1. **Extract the technique.** What class of bug, what the winning input was, what defense it
   defeated, and — most valuable — the *non-obvious detail* that made it work (the header
   nobody checks, the endpoint that skips validation, the encoding the WAF missed).
2. **Extract the miss.** If it's their own report that was closed/duplicated/informative,
   the lesson is in the rejection reason: false-positive pattern, missing impact proof,
   scope mistake. Those are the highest-value lessons of all.
3. **Write it back.** Add it as a new variant or a new **gotcha** line under *False positives*
  /*Detect* in the matching technique skill's `references/variants-*.md`. Existing structure
   wins — a 16th variant in `sqli-testing` belongs in `variants-2.md`, not a new file.
4. **Log it.** Append an entry to `LESSONS.md`: date, source, skill touched, what changed.
   This file is the proof the system compounds; never rewrite history in it.
5. **New category?** Only if the lesson belongs to none of the nine — then scaffold a new
   skill directory following `SKILL_SPEC.md`. Don't spawn a skill per bug; category skills
   get *deeper*, they don't multiply.

### 4b. Conversation intake — every conversation gets mined into its category

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

## 5. Report writing standard

A report survives triage when it is reproducible by someone who has never met you. Always:
minimal steps from a clean session, the exact request, expected vs. actual, one sentence of
*why it matters* tied to a real asset or action, and evidence with secrets/users redacted.
Severity follows impact on the program's own scale — a reflected parameter with no sink is
not Critical because the payload looked scary.

## 6. Test mailboxes

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

## 7. File map

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
