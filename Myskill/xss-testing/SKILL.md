---
name: xss-testing
description: >
  Deep playbook for XSS bug bounty testing: 18 variants covering the classic
  reflected/stored/DOM/blind taxonomy plus RXSS context-boundary evasion, DOM source-to-sink
  analysis, blind XSS out-of-band tracking engines, UXSS, DOMPurify mXSS, CSTI
  (AngularJS/Vue), prototype-pollution-assisted XSS, universal polyglots, JSFuck/JJEncode
  non-alphanumeric obfuscation, double-encoding WAF evasion, indirect eval sinks,
  SVG/PDF/Markdown/XML vectors, client-side cache second-order XSS, RPO, MIME-sniffing XSS
  and Trusted Types bypass. Use this skill whenever the user is doing authorized security
  testing and mentions XSS, cross-site scripting, reflected/stored/DOM/blind XSS, payload
  crafting, sanitizer bypass, DOMPurify, AngularJS/Vue expression injection, prototype
  pollution gadgets, polyglots, WAF bypass for script tags, RPO, MIME sniffing or Trusted
  Types — or asks how to test, confirm, triage, mitigate or report an XSS finding. Also use
  it when analyzing a request/response pair or a client-side code snippet for reflection
  points, dangerous sinks (innerHTML, eval, document.write, setTimeout strings, location
  assignment) or sanitizer misconfigurations.
---

# XSS Testing Playbook

18 advanced variants. The classic taxonomy is folded into the front of the playbook:
reflected context-boundary testing is V-02, DOM-based is V-03, stored is V-04, and blind
is V-05 — learn those four first, everything else is a specialization of them. Payload
templates, probe sets, WAF-evasion encodings and tool commands live in `references/`.

## 1. Scope & authorization guardrail

Only test targets you are authorized to test: a published bug bounty program with the asset
in scope, a client engagement with written rules of engagement, or your own lab/CTF. If the
user names a third-party domain, ask for the program link or scope statement before doing
anything else; refuse out-of-scope assets and never argue someone into "probably fine".

Hard limits inside authorized scope:

- No destructive or availability-impacting payloads: no self-replicating scripts, no
  mass-mailing loops, no resource-exhaustion payloads, no payloads that delete or modify
  other users' data.
- Prove execution with inert markers (`alert(document.domain)`, a DOM element you inserted,
  an out-of-band ping to your own collaborator domain). Never exfiltrate real users' cookies,
  tokens, or content — if you need a "look, I got data" proof, exfiltrate your own test
  account's marker string.
- Blind XSS (V-05) fires in someone else's browser, often an admin's. Collect the minimum
  context needed to prove the point (origin, path, role label), redact it in the report, and
  state clearly in the report what was and was not accessed.
- UXSS (V-06) is a browser-vendor bug. If you find one while testing a web app, it is
  context for the app report at most — the finding belongs to the browser program.

The skill exists to make authorized testing methodical and to produce reports that hold up
under triage. Follow it and your findings will be reproducible, minimal, and unambiguous.

## 2. Engagement workflow

1. **Recon & endpoint inventory.** Enumerate every entry point before testing anything:
   query parameters, form fields (GET and POST), JSON body keys, multipart filenames,
   headers that get logged and rendered (User-Agent, Referer, X-Forwarded-For), cookies,
   stored fields (profile, comments, tickets), and anything embedded into the DOM
   server-side (JSON-LD, `window.__DATA__` blobs). Fingerprint the stack: JS framework,
   sanitizer library and version, CSP header, cookie flags, cache layers. *Why:* 80% of
   missed XSS is a missed parameter, and the right variant depends entirely on the stack.

2. **Parameter & sink mapping.** Classify each entry point as reflect-now, store-then-render,
   or client-side-only. For client-side paths, map sources (`location.*`, `document.URL`,
   `window.name`, `postMessage`, `localStorage`) to sinks (`innerHTML`, `document.write`,
   `eval`/`Function`/string-`setTimeout`, `.src`/`.href` assignment, jQuery `$(...)` in
   HTML mode). *Why:* you cannot pick a variant without knowing where the tainted bytes
   actually land — server-rendered, framework-compiled, or sink-assigned.

3. **Variant selection.** Use the table in section 3 to map your observations to 2-3
   candidate variants. Do not spray forty payloads at one parameter; a focused probe set
   that respects the reflection context finds more and trips fewer WAFs.

4. **Safe probe.** Send a harmless, unambiguous marker (`<zz1>`, `'><zz2>`) and inspect the
   raw response bytes: where exactly does it land (tag text, quoted attribute, JS string,
   URL position), and what encoding was applied? *Why:* the reflection position decides the
   entire payload family; guessing this from the URL path is how juniors burn their one
   clean payload slot.

5. **Confirmation test.** Replace the marker with a context-correct payload that proves
   execution without touching data — typically `alert(document.domain)` or an element the
   payload inserts. Run it in a real browser (headless is fine) and capture console output
   or the rendered DOM. *Why:* a reflected string is not XSS; execution is.

6. **Impact proof.** Escalate only as far as needed to justify severity: show the executing
   origin, whether CSP/Trusted Types/HttpOnly blocked any step, and who else can trigger it
   (self-only vs. stored-for-others vs. blind-admin). Use your own test account's data for
   any "stolen value" demonstration.

7. **False-positive filter.** Before writing anything, re-check the classic mimics: HTML-
   encoded echo that looks like a hit in a grep, JS-escaped JSON that never reaches a sink,
   self-XSS requiring an unrealistic user action, WAF error pages echoing your probe, and
   client-side-only execution on a page you control yourself. Confirm with a second,
   independent signal — a different browser, a clean session, or the raw response bytes.

8. **Report.** Use the template in section 5. Include the exact request/response pair, the
   context analysis (which is what makes triage fast), the execution proof, honest severity
   with the mitigating controls named, and per-variant remediation.

## 3. Variant selection table

| Signal you observed | Likely variant | Reference |
|---|---|---|
| Input echoes into HTML body unencoded on the same request | V-02 (reflected, HTML context) | variants-1.md |
| Only POST/JSON/form parameters reflect; GET does not (or vice versa) | V-01 multi-transport matrix | variants-1.md |
| Reflection lands in a quoted/unquoted attribute or event handler | V-02 (attribute / event-handler context) | variants-1.md |
| Reflection lands in `href`/`src`/`action`/`formaction` URL position | V-02 (URL context), possibly V-13 | variants-1.md |
| Input passes through Angular/Vue/Svelte interpolation (`{{...}}`, `${...}`) | V-08 CSTI | variants-1.md |
| Payload appears in a later request/response, not the one you sent | V-04 stored | variants-1.md |
| Nothing in any response; you control an admin-seen field (ticket, comment, log) | V-05 blind / OOB | variants-1.md |
| Input flows from URL/hash/postMessage/localStorage into a JS sink | V-03 DOM-based | variants-1.md |
| Sanitizer present but payload mutates into active markup after a parse/serialize round-trip | V-07 mXSS | variants-1.md |
| Attacker-controlled JSON changes `Object.prototype`, then the page misbehaves or executes | V-09 prototype-pollution XSS | variants-1.md |
| SOP seems broken / cross-origin DOM access works — suspect the browser, not the app | V-06 UXSS | variants-1.md |
| One payload family should work in several places; reflection context unknown | V-10 polyglots | variants-2.md |
| Keyword filters block `script`/`alert` but symbol-only payloads pass | V-11 non-alphanumeric encoding | variants-2.md |
| WAF 403s obvious payloads, but the app double-decodes or renders entities | V-12 encoding evasion | variants-2.md |
| Input reaches `eval`, `Function`, string-`setTimeout`, `$.globalEval`, `location=` | V-13 indirect sinks | variants-2.md |
| Upload/preview/export of SVG, PDF, Markdown, or XML files | V-14 file/vector formats | variants-2.md |
| Payload fires on a later visit, or a clean session sees your input via the cache | V-15 second-order / cache | variants-2.md |
| Page loads relative `script src`/CSS paths; you influence path resolution | V-16 RPO | variants-2.md |
| User content served with wrong/missing Content-Type, no `nosniff`, sniffable body | V-17 MIME sniffing | variants-2.md |
| CSP contains `require-trusted-types-for 'script'` | V-18 Trusted Types | variants-2.md |
| HTML entity/Unicode escapes survive intact into the rendered DOM | V-12 (entity/Unicode notes) | variants-2.md |
| Legacy IE target; `VBScript:` or `language=VBScript` relevant | V-02 (VBScript sub-context) | variants-1.md |

## 4. Verification standard

A **confirmed finding** requires all four:

1. A reproducible request + response pair (raw bytes, not a browser screenshot of the URL
   bar) showing the unencoded/decodable reflection or the storage-then-render path.
2. Execution proof in a real browser for the exact origin: console alert, debugger hit at
   the sink, or an inert DOM marker the payload created.
3. A second independent signal: same result from a second browser engine or a clean
   session, plus the context analysis showing *why* it executes (which tag/attribute/string
   was broken out of).
4. Honest mitigation notes: CSP directives and whether they blocked anything, HttpOnly,
   Trusted Types, sandbox attributes, interaction required (click vs. load).

Anything less is a **lead**: reflection without execution evidence, a payload that only
works encoded-decoded in your tooling but never in a browser, or a stored value you could
not observe rendering. Label leads as leads; claiming unexecuted reflections as XSS is the
fastest way to lose credibility in a program.

## 5. Report template

```markdown
# <Title: e.g. Reflected XSS in /search via q parameter (HTML text context)>

**Severity:** <Critical/High/Medium/Low — state the deciding factor, e.g. "stored,
fires on any visitor, CSP not present">
**Endpoint:** <METHOD https://host/path?param=...>

## Summary
<2-3 sentences: which parameter, which context, which variant, who can trigger it.>

## Steps to reproduce
1. <Auth state / prerequisite, e.g. "Log in as a free-tier user.">
2. Send: <exact request, redacted, with placeholders for secrets>
3. Observe: <raw response bytes OR rendered DOM / console output>
4. <Browser + version used for execution proof>

## Impact
<What an attacker achieves, in data/action terms: e.g. "Arbitrary JS runs in
victims' sessions on host.origin; an attacker can perform actions as the victim,
including <top-privilege-role> if they visit the stored comment. CSP absent.">

## Evidence (redacted)
```http
<request/response pair with real host redacted, payload kept verbatim>
```
<Console screenshot or DOM snippet showing the inert execution marker>

## Remediation
<Per-variant specific fix — e.g. "Context-aware output encoding at the template
layer for the q reflection; do not rely on the client-side sanitizer.">

## References
- CWE-79 (Improper Neutralization of Input During Web Page Generation)
- OWASP Top 10:2021 A03 Injection
- <variant-specific refs, e.g. DOMPurify advisory, Trusted Types docs>
```

## 6. Reference pointers

Read `references/variants-1.md` for variants 1-9 and `references/variants-2.md` for variants
10-18; read `references/payloads.md` when you need request templates, tool commands, or
WAF-evasion encodings. Do not improvise payloads from memory when the reference files have
a template for the context — the placeholders exist so you never paste a live target into
the playbook and never send the wrong context's payload.
