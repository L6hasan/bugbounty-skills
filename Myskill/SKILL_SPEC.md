# Skill Build Spec (shared by all 10 bug-bounty skills)

Every skill directory MUST contain:

```
<skill-name>/
├── SKILL.md
└── references/
    ├── variants-1.md      (variants 1-8)
    ├── variants-2.md      (remaining variants; omit if all fit in variants-1.md)
    └── payloads.md        (payload/request templates, tool commands, evasion notes)
```

## 1. SKILL.md frontmatter (exact shape)

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

## 2. SKILL.md body (target 150-300 lines)

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

## 3. Variant reference files (deep playbook)

Split the skill's variant list (given in the category prompt) into two files:
`variants-1.md` (first 8) and `variants-2.md` (remainder). Each file starts with a table
of contents (variant number + title, linked by anchor), then one section per variant:

```markdown
## V-01: <Variant name>
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

## 4. Tone

Imperative, practical, explain the *why*. No "MUST/NEVER" in all caps unless it is a
safety/scope rule. Assume a competent tester who wants speed and precision.

## 5. The suite (sibling skills, cross-reference by directory name)

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
