---
name: rce-testing
description: Deep playbook for RCE bug bounty testing: 9 variants covering OS command injection, code argument injection via eval/assert, insecure deserialization, web-shell file uploads, SSTI via template engine fingerprinting, memory-corruption triggers, Unix argument injection, insecure config loading, and blind env-var/shell-expansion RCE. Use this skill whenever the user is doing authorized security testing and mentions RCE, command injection, code injection, SSTI, template injection, deserialization, web shell, file upload execution, argument injection, eval/assert sinks, config override, cron/job injection, or asks how to test whether input reaches code execution, wants payloads or request templates for command/code sinks, needs to confirm or triage an RCE finding, or is writing a report for a code-execution bug. Also use it when analyzing a request/response pair or code snippet for command-building, template-rendering, eval, or deserialization weaknesses. (Server-side request forgery lives in `ssrf-testing`.)
---

# RCE Testing — Deep Playbook

Code execution bugs are the highest-severity class in most bug bounty
programs — and the easiest to over-claim. This skill makes the work
methodical: inventory sinks, pick the variant that matches the sink, probe
safely (callback or marker first, never a shell as a first step), confirm
with a second independent signal, prove impact with the minimum action
needed, and write reports that survive triage.

## 1. Scope & authorization guardrail

Only test targets you are authorized to test: a published bug bounty program
with this asset in scope, a client engagement with written scope, or your own
lab/CTF. If the target is out of scope, belongs to a third party, or you cannot
verify authorization, refuse and stop. Never run destructive payloads (mass
scanning of third-party infrastructure, fork bombs, resource exhaustion),
never establish persistence or backdoors, and never exfiltrate data beyond the
minimum needed to prove impact.

Skill-specific hard rules:

- **No shells as a first step.** The first signal for any injection is an
  out-of-band callback to a domain or collaborator you control (DNS or HTTP),
  an arithmetic marker, or a short time differential. Code execution proofs
  come last, and only a single benign command (`whoami`, `id`) at the
  impact-proof stage.
- **No persistence, no web shells left behind.** If an upload executes, prove
  it with one benign marker request, then delete it or disclose it to the
  program immediately.
- **Exploitation depth belongs in a container or lab.** Deserialization gadget
  chains, sandbox escapes, memory-corruption exploits, and config-override
  RCE chains get developed against in-scope docker/k8s targets or your own
  lab clone — not against production.
- Cloud metadata is **not** this skill's territory — SSRF that reaches
  `169.254.169.254` routes to `ssrf-testing` (identity-only evidence rules
  apply there).

## 2. Engagement workflow

1. **Recon & endpoint inventory.** Enumerate every endpoint that accepts data
   flowing toward a code or shell sink: anything named `cmd`, `exec`, `ping`,
   `run`, `eval`, `render`, `template`, `convert`, `export`, file-ish params
   (`file`, `path`, `upload`, `document`), formula/query fields, and
   cookies/params carrying serialized blobs. Pull routes from JS bundles,
   OpenAPI/Swagger specs, mobile API dumps, and historical responses. This
   comes first because sink coverage — not payload cleverness — determines
   what you can find at all.
2. **Parameter & sink mapping.** For each candidate, classify the sink: a
   shell string built by concatenation, a code evaluator (`eval`, `assert`,
   `subprocess`), a template render, a deserializer, a file write, a wrapper
   binary invoked with argv, or a config loader. Trace source→sink when you
   have code (leaked source, source maps, stack traces); otherwise infer from
   response behavior. Record existing filters (allowlists, strip lists) —
   they decide which variant and which encoding you need.
3. **Variant selection.** Route the observed signal through the table in §3 and
   read the matching variant section in `references/variants-1.md` or
   `references/variants-2.md`. One signal often maps to several variants (a
   reflected hostname result could be command injection *or* SSTI); test the
   cheapest discriminators first. URL-fetching sinks with no execution path
   belong to `ssrf-testing` — don't conflate.
4. **Safe probe.** Send the lowest-risk discriminating payload from
   `references/payloads.md`: a DNS/HTTP callback to your collaborator, a
   time-based differential, or `{{7*7}}`-style marker arithmetic. No shells,
   no file writes at this stage.
5. **Confirmation test.** Reproduce the effect with a second, independent
   signal: OOB DNS plus reflected output, time delay plus callback, marker
   arithmetic plus a template stack trace. A single signal has plausible
   alternative explanations; two orthogonal signals do not. This is the step
   juniors skip and the reason reports get rejected in triage.
6. **Impact proof.** Demonstrate the minimum real impact: `whoami`/`id`, a
   marker-file read. Stop there. "I ran one benign command" beats "I dumped
   everything and got banned" in both bounty outcomes and report quality.
7. **False-positive filter.** Work through each variant's **False positives**
   section: WAF interstitials that reflect your input, cached 200s, generic
   error handlers that interpolate your string, client-side eval. Rule every
   alternative explanation out before writing anything up.
8. **Report.** Use the template in §5. Redact tokens, credential material,
   and internal hostnames beyond what proves impact. Attach raw
   request/response pairs with your collaborator domain shown as a
   placeholder.

## 3. Variant selection table

| Signal you observed | Likely variant | Reference |
|---|---|---|
| Command output, shell error text, or timing change after injecting `;`, `&&`, `\|`, backticks, `$(...)` | V-01 OS command string injection | `references/variants-1.md` |
| App evaluates expressions; `eval`/`assert`/`Function`-style sinks; formula or query-language fields | V-02 code argument injection | `references/variants-1.md` |
| Cookies/params carry serialized blobs (Java `rO0AB`, PHP `O:`, Python `gASV`, Ruby `BAh7`); `readObject`-style errors | V-03 insecure deserialization | `references/variants-1.md` |
| Upload feature accepts images/archives; weak extension checks; uploads served from web root | V-04 file upload → web shell | `references/variants-1.md` |
| `{{...}}`/`${...}`/`<%= %>` input comes back computed; template errors leak engine names | V-05 SSTI | `references/variants-1.md` |
| Crashes, worker restarts, segfault-ish 500s around image/font/archive/XML processing | V-06 memory corruption / GC triggers | `references/variants-2.md` |
| Input concatenated as a separate argv to a fixed binary (`git`, `tar`, `convert`, `ffmpeg`) | V-07 argument injection | `references/variants-2.md` |
| Debug/config endpoints; uploadable YAML/INI/ENV; framework config or `PHP_VALUE` override | V-08 insecure config loading | `references/variants-2.md` |
| Input stored then consumed later by jobs/scripts; env/hostname headers; weird uploaded filenames | V-09 blind env-var RCE | `references/variants-2.md` |
| `url`/`host`/`ip` param fetches content; callback-only hits; cloud metadata reachable — no execution path | → `ssrf-testing` | sibling skill |

## 4. Verification standard

A confirmed RCE finding requires all of the following; anything less is a
lead and gets reported as a lead:

1. **Reproducible request + response pair.** The exact HTTP request (headers,
   body, auth state) and the server's response, captured at least twice with
   the same result. Paste-ready for triage.
2. **A second, independent signal.** Two orthogonal proof channels: e.g. OOB
   DNS callback *and* reflected output; sleep-scaling *and* callback; SSTI
   arithmetic *and* engine stack trace. One signal can be mimicked by WAFs,
   frontends, and caching layers; two cannot plausibly co-occur by accident.
3. **Minimal-impact impact proof.** One benign command (`whoami`), one marker
   read. Never credential dumps, never data theft, never destructive
   commands — impact phrasing describes what an attacker *could* do; the
   evidence shows only the minimum they did.
4. **False-positive audit documented.** Name the alternative explanations you
    ruled out (client-side eval, cached response, reflection-only, scanner
    noise) in the report's evidence section.

## 5. Report template

```markdown
### Title
`<Vuln type> in <parameter/feature> at <endpoint> (V-XX)`

**Severity:** <Critical/High/...> — one-line justification
**Endpoint:** `POST /api/<path>` — parameter `<param>` (<auth state required>)
**Summary:** 2-3 sentences: the sink, the controllable source, the proven effect.

**Steps to reproduce:**
1. <Authenticate as <role> / no auth required>
2. Send: `<redacted raw request with <PLACEHOLDER> for collaborator values>`
3. Observe: <collaborator hit at <timestamp> / 7s delay / `49` reflection / uid>

**Impact:** What an attacker gains (code execution as which user, reachable
paths, secrets class) and the realistic worst case.

**Evidence:** Redacted request/response pairs; collaborator log with your
domain masked; timestamps. Show proof of effect, not payloads that dump data.

**Remediation:** One specific fix for this sink (exec with argv array,
expression parser, template sandbox, serialization replacement, etc.).

**References:** CWE-<XX>; OWASP Top 10 <A0X:2021>; variant V-XX in
rce-testing skill.
```

## 6. Reference pointers

Read `references/variants-1.md` for variants 1-5 and `references/variants-2.md`
for variants 6-9; read `references/payloads.md` when you need request
templates, tool commands, or WAF-evasion encodings.

Each variant section is self-contained: mechanism, preconditions, numbered
detect steps, a proof-of-concept template with `<PLACEHOLDER>` slots, the
independent confirmation signal, false positives, impact phrasing, a
sink-specific remediation, and the CWE/OWASP mapping. Match your observed
signal to §3, open that variant, and work top to bottom.
