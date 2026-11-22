# SEVERITY DOCTRINE — HIGH/CRITICAL ONLY  (standing order from Kr Hasan, 2026-11-07)

Authority: this file is the FIRST thing every hunt / validate / research stage reads.
It overrides any earlier "report what you find" habit. If a stage prompt contradicts
this file, this file wins.

Reference: HackerOne — Core Ineligible Findings
https://docs.hackerone.com/en/articles/8494488-core-ineligible-findings
(the P4/P5 list below is that document; treat it as the exclusion standard for every program).

---

## 1. REPORT ONLY THESE CLASSES

RCE · command execution · code injection · SQLi (incl. NoSQLi) · XSS (stored/reflected/DOM
with real impact) · broken access control (BAC) · IDOR/BOLA · privilege escalation
(horizontal + vertical) · authentication bypass · OAuth/OIDC/SSO bypass · JWT/session
forgery · LFI/RFI/path traversal · internal file read · SSRF (incl. XSPA + cloud metadata) ·
XXE · insecure deserialization · sandbox/container escape · server-side security
misconfiguration WITH demonstrated impact · client-side security misconfiguration WITH
demonstrated impact · business-logic error with monetary/account impact · sensitive
information disclosure WITH PoC · admin panel / internal service access · account takeover
(any chain).

Everything else is NOT a finding. There is no "informational report" in this pipeline.

## 2. INELIGIBLE — NEVER REPORT STANDALONE (HackerOne Core Ineligible Findings)

Use these ONLY as a chain primitive. If the chain never reaches real impact, drop it
silently — do not report it, do not draft it, do not queue it for validation.

(a) Theoretical / unlikely circumstances: issues only on unsupported or EOL browsers/OS;
    broken-link hijacking; tabnabbing; content spoofing / text injection; attacks needing
    physical device access; self-XSS / self-DoS.
(b) No demonstrated real-world impact: clickjacking on pages with no sensitive action;
    CSRF on non-sensitive actions (e.g. logout); permissive CORS without demonstrated
    impact; software version disclosure / banner identification / descriptive error
    messages or headers / stack traces; CSV injection; open redirect with no added impact.
(c) Hardening / missing best practice: SSL-TLS configuration; missing certificate pinning;
    missing jailbreak detection; cookie flags (HttpOnly/Secure/SameSite); CSP configuration
    opinions; SPF/DKIM/DMARC; most rate-limiting issues.
(d) Hazardous testing (never attempt unless explicitly authorised): excessive
    traffic/requests, DoS/DDoS, anything affecting availability; social engineering;
    noisy notification/form spam.

Also never reported: out-of-scope assets/classes (read the scope file's do-NOT-test list
every pass), duplicates of a decided finding, and anything already in rejected.jsonl /
archive.jsonl.

## 3. OPERATING RULES

1. SEVERITY FLOOR. Below the §1 list = not a finding. P4/P5/informational is a CHAIN
   PRIMITIVE, not a deliverable.
   ROUTING: before choosing what to test, run the decision tree in
   `/root/hackbot-architecture/knowledge/SKILL-TREE.md` (mirrored at the top of
   `/root/bugbountyhuntingskills.md` §0 and `/root/Bugbountyskills.md` §0.5) — it routes an
   observed signal to one class, one minimal test, one playbook section.
2. DO NOT REPORT EARLY. Hold the primitive, keep digging — bypass → escalate → chain —
   until the chain reaches high/critical impact, or drop it. An unproven chain is silence,
   not a draft.
3. NO NON-SENSITIVE, NO OUT-OF-SCOPE, NO BEST-PRACTICE findings. Ever.
4. EFFICIENCY — do not burn requests on pointless recon/enumeration sweeps. Go straight at
   the SENSITIVE surface: auth/login/token, admin, account/profile, payment, file
   upload/download/export, internal & undocumented API, GraphQL, WebSocket/RPC, mobile BFF.
   Spend the budget on BYPASSING and CHAINING those, not on breadth.
5. EVERY REPORT NEEDS: demonstrated impact (CIA), a reproducible PoC, and a CVSS vector in
   the program's own P1/P2/P3 (+critical/high/medium) vocabulary. Measured negatives are
   recorded as closed, never dressed up as findings.
6. CONFIDENCE GATE. Unproven → REJECTED. "Sink real, vector unproven" is a LEAD, never P2.
   Screenshot/MD5/byte-exact evidence or it did not happen.
7. When a class is measured closed (e.g. no caching configured → cache poisoning
   unreachable; no ACAO anywhere → CORS closed), write it as a MEASURED NEGATIVE and move
   to a new class — do not re-tread it next cycle.

## 4. HIGH-CRITICAL THINKING (per endpoint)

Ask "what is the WORST outcome reachable here?" then work backwards to it:
- auth bypass → admin/intranet → RCE
- IDOR/BOLA → cross-tenant data → account takeover
- SSRF → cloud metadata → IAM creds → RCE
- upload + path traversal / parser → RCE
- insecure deserialization / SSTI / XXE → RCE
- OAuth redirect_uri / postMessage / origin check → token theft → ATO
- business logic (price, balance, refund, signup, coupon) → monetary loss at scale
One deep, fully-chained high/critical beats ten shallow observations. Prefer a class where
the same bug maps across sibling endpoints (one report per chain, not per endpoint).

## 5. RESEARCH LOOP — KEEP UPGRADING THE SKILL (never stops)

Continuously read and mine:
HackerOne Hacktivity (disclosed reports) · Bugcrowd published reports · Intigriti writeups
· PentesterLand · Medium bug-bounty tag · InfoSec Writeups · HackerOne program docs (incl.
Core Ineligible Findings) · program scope/VRT/changelogs.

For every item extract: the CLASS, the entry point, the BYPASS technique, the CHAIN, and the
exact transferable test — never just the CVE number. Then:
- append it to the skill file(s): /root/bugbountyhuntingskills.md (harvest ledger) and
  /root/Bugbountyskills.md (consolidated playbook) using the SOURCE / CORE METHOD /
  TRANSFERABLE TEST shape already used there;
- fold the reusable technique into the hunting skill (web-vulnerability-hunting) and this
  doctrine's §4 when it changes how we think about a class;
- record the date + source so a technique is traceable.
Never re-derive a bypass already recorded. A read pass that appends nothing new must say so
explicitly ("nothing new — N sources checked") rather than manufacture an entry.

## 6. SCORING QUICK TABLE (use the program's own vocabulary)

P1/Critical  = RCE, auth bypass to admin, ATO at scale, full PCI/PII exposure, SSRF→RCE
P2/High      = SQLi/XXE/deserialization with data or code impact, BAC/IDOR on sensitive
               data or write actions, stored XSS with session impact, SSRF with internal
               reach, OAuth bypass, business logic with real monetary loss
P3/Medium    = reflected XSS requiring interaction but on a sensitive flow, limited
               cross-user data read, misconfiguration with proven access gain
P4/P5/info   = everything in §2 — CHAIN PRIMITIVE ONLY, never reported.

## 7. DRIFT AUDIT — the P4/P5 correction (standing order, 2026-11-07)

Known failure mode: the agent keeps shipping P4/P5/informational findings. That is a PROCESS
failure, not a reporting choice — fix it before the next draft, not in triage.

1. BEFORE writing any draft, list the severity of your last five candidates out loud. Three or
   more at P4/P5/informational ⇒ you are drifting. Change ASSET or CLASS. Never lower the floor
   to make a pass "produce a finding", and never dress a primitive up as a finding.
2. A pass that ends with only primitives ends with the line
   `no reportable finding — N primitives held as leads`. It never ends with an informational report.
3. The P4/P5 surface (headers, banners, version disclosure, CORS, cookie flags, CSP opinions,
   rate limits, open redirect, self-XSS, CSV injection, clickjacking/CSRF without a sensitive
   action) is where the request budget goes to die. Touch it ONLY as step one of a live chain.
4. Aim high-critical on every endpoint: name the worst reachable outcome, then work backwards
   to it and spend the budget on BYPASS → ESCALATE → CHAIN. One fully-chained high/critical
   beats ten shallow observations.

## 8. EVIDENCE & FRESHNESS DISCIPLINE (standing order, 2026-11-07)

**Research freshness**
1. FETCH RECENT MATERIAL — target the last 6–12 months. Do not rely on memory, and never import
   a technique just because it "sounds right". Bypasses age; a 2019 trick is usually patched.
2. NEVER cite or save a writeup you have not actually opened. Every entry carries its SOURCE URL
   and the date it was read. No URL + date ⇒ the entry is not admitted to the ledger.
3. REPRODUCE OR TAG. A technique not reproduced on a lab or your own test setup is recorded as
   `STATUS: UNVERIFIED (not reproduced)`. If it cannot be reproduced at all, discard it. Only
   reproduced techniques are promoted into the playbooks as fact.

**Severity judgment**
4. PRECONDITIONS + GAIN, WRITTEN BEFORE THE RATING. Before calling anything High or Critical,
   state (a) the exact preconditions an attacker needs — auth? which role? user interaction? who
   clicks what? — and (b) the exact data or action they gain. No (a) + (b) ⇒ it is not High/Critical.
5. "Think critical" means working out the worst REALISTIC outcome inside scope and how to reach
   it. It never means labelling a finding above what the evidence supports. Inflated severity gets
   the report downgraded and burns the program's trust in every later report.
6. The floor still holds: P4/P5/informational is chain material. Record it WITH its evidence, test
   whether it combines into a concrete impact (account takeover, sensitive data access, RCE, admin
   functionality), and report only the chain that reaches that impact.

**Core-ineligible check** (repeat of §2, because it is the most common self-inflicted rejection):
before drafting, re-read the program's ineligible list and confirm the chain escapes it. An
excluded class that reaches real impact is reported as the impact, never as the excluded class.
