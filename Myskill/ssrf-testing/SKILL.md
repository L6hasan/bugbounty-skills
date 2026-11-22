---
name: ssrf-testing
description: Deep playbook for SSRF bug bounty testing: 6 variants covering basic SSRF scanning and internal network mapping, blind async SSRF pipelines, cloud metadata extraction (AWS IMDSv1/v2 bypass, GCP/Azure/Alibaba, ECS, K8s), DNS rebinding and redirect-based filter bypass, Gopher/DICT/FTP protocol smuggling, and PDF/image rendering SSRF with exfiltration channels. Use this skill whenever the user is doing authorized security testing and mentions SSRF, server-side request forgery, blind callback, cloud metadata, IMDS, DNS rebinding, gopher, webhook URL fields, link preview, import-from-URL, PDF generation SSRF, or asks how to test whether the server fetches attacker-controlled destinations, wants payloads or request templates for URL-fetching sinks, needs to confirm or triage an SSRF finding, or is writing a report for a server-side request bug. Also use it when analyzing a request/response pair or code snippet for URL-fetching, headless-browser, webhook, or renderer weaknesses. (Code execution sinks live in `rce-testing`.)
---

# SSRF Testing — Deep Playbook

Server-side request forgery turns the server's network position into the
attacker's: localhost, internal ranges, and cloud metadata become reachable
from anywhere the app can be talked into fetching a URL. The bug is easy to
over-claim (echo ≠ fetch) and easy to under-scope (blind ≠ absent). This
skill makes the work methodical: inventory fetch points, prove server-side
fetch first, climb the ladder only as far as authorization requires, confirm
with a second independent signal, and stop at identity-level evidence for
cloud metadata.

## 1. Scope & authorization guardrail

Only test targets you are authorized to test: a published bug bounty program
with this asset in scope, a client engagement with written scope, or your own
lab/CTF. If the target is out of scope, belongs to a third party, or you cannot
verify authorization, refuse and stop. Never mass-scan third-party or
out-of-scope internal infrastructure, never run destructive payloads against
internal services, and never exfiltrate data beyond the minimum needed to
prove impact.

Skill-specific hard rules:

- **Cloud metadata findings are proven by identifying the role/instance — not
  by dumping credentials.** If you can reach `169.254.169.254`, fetch the IAM
  role name or the instance identity document, then stop. Do not retrieve,
  copy, screenshot, or retain temporary credentials; redact anything
  token-like from evidence.
- **The first signal is an out-of-band callback to a domain or collaborator
  you control.** A hit from the app's egress IP with a non-browser UA proves
  server-side fetch; anything less is a lead. Client-side fetches (link
  previews rendered in the victim's browser) are not SSRF.
- **Protocol-smuggling write primitives stay in the lab.** Gopher'd writes to
  Redis/Memcached/SMTP get demonstrated against your own listener first;
  internal-state-changing chains are lab-depth, described in prod reports.
- **No job floods, no scan loops against production.** Pacing (two samples
  per probe plus a control) is part of the no-destructive rule.
- Code execution reached *through* an SSRF (gopher → internal RCE, metadata
  → privilege pivot) reports as the chain it is; the execution-side framing
  lives in `rce-testing`.

## 2. Engagement workflow

1. **Recon & fetch-point inventory.** Enumerate every endpoint that accepts
   data flowing toward a server-side fetch: URL-ish params (`url`, `next`,
   `callback`, `webhook`, `dest`, `host`, `ip`, `endpoint`, `target`),
   import-from-URL/export features, link previews/oEmbed, avatar/logo fetch,
   PDF/print/HTML-render features, sitemap/news crawlers, health/check-site
   tools. Pull routes from JS bundles, OpenAPI/Swagger specs, mobile API
   dumps, and historical responses. Sink coverage — not payload cleverness —
   determines what you can find at all.
2. **Sink classification.** Synchronous fetch with visible result vs async
   worker (blind); scheme handling (`http/https` only vs pass-through);
   destination validation (none, blocklist, allowlist, resolve-and-pin);
   redirect following; verb/header control (needed for IMDSv2 and gopher).
   This classification picks your variant and your evidence channel.
3. **Variant selection.** Route the observed signal through the table in §3
   and read the matching variant section in `references/variants-1.md`. One
   signal often maps to several variants (an allowlisted-hostname fetch could
   be parser-differential *or* rebinding); test the cheapest discriminators
   first — the redirect-based bypass costs one request and often is the whole
   finding.
4. **Safe probe.** Rung 1 only: point the fetch at
   `http://<OOB_DOMAIN>/ssrf-<TOKEN>` and wait out the async window. Confirm
   the hit's source IP/ASN is the app's egress, not your own browser. No
   internal addresses, no metadata, no schemes beyond http(s) at this stage.
5. **Confirmation test.** Reproduce with a second, independent signal:
   collaborator hit *plus* reflected internal content; hit *plus* reproducible
   timing differential against a control port; identity field fetch *plus*
   repeatability. A bare DNS hit or a single slow response is a lead.
6. **Impact proof.** Demonstrate the minimum real impact: the rungs reached
   (localhost, link-local, RFC1918), one internal hostname, the cloud role
   *name*. Stop there.
7. **False-positive filter.** Work through each variant's **False positives**
   section: browser-side fetches, CDN edge fetches, hostname reflection
   without fetch, security-gateway unfurling, single-sample timing claims.
   Rule every alternative explanation out before writing anything up.
8. **Report.** Use the template in §4. Redact internal hostnames, tokens,
   and credential material beyond what proves impact. Attach raw
   request/response pairs with your collaborator domain shown as a
   placeholder.

## 3. Variant selection table

| Signal you observed | Likely variant | Reference |
|---|---|---|
| `url`/`host`/`ip` param fetches content; internal addresses return data or timing differs by port | V-01 basic SSRF scanning | `references/variants-1.md` |
| Callback-only hit with no response change; feature is an async job/queue/webhook test | V-02 blind SSRF pipelines | `references/variants-1.md` |
| App can reach `169.254.169.254`, `metadata.google.internal`, Azure `metadata` endpoint | V-03 cloud metadata extraction | `references/variants-1.md` |
| Filter blocks direct IPs but allows your hostname; hostname is in your control; filter checks URL only, your box redirects | V-04 DNS rebinding / redirect bypass | `references/variants-1.md` |
| URL param passes `gopher://`, `dict://`, `ftp://`, `file://` schemes through | V-05 protocol smuggling | `references/variants-1.md` |
| PDF generation, wkhtmltopdf/Chromium print, image conversion, HTML→PDF export features | V-06 PDF/image rendering SSRF | `references/variants-1.md` |
| Command output/timing after `;`, computed `{{7*7}}`, serialized blobs, upload execution | → `rce-testing` | sibling skill |

## 4. Verification standard

A confirmed SSRF finding requires all of the following; anything less is a
lead and gets reported as a lead:

1. **Reproducible request + response pair.** The exact HTTP request (headers,
   body, auth state) and the server's response, captured at least twice with
   the same result. Paste-ready for triage.
2. **A second, independent signal.** Two orthogonal proof channels: e.g.
   collaborator HTTP hit from the app's egress IP *and* reflected internal
   content; identity field *and* repeatability. One signal can be mimicked by
   browsers, CDNs, and link unfurlers; two cannot plausibly co-occur by
   accident.
3. **Minimal-impact impact proof.** Rungs reached, one internal hostname, the
   cloud role *name*. Never credential dumps, never bulk internal data, never
   state-changing commands against internal services.
4. **False-positive audit documented.** Name the alternative explanations you
    ruled out (client-side fetch, CDN edge, hostname echo, scanner
    unfurling) in the report's evidence section.

## 5. Report template

```markdown
### Title
`SSRF in <parameter/feature> at <endpoint> (V-XX)`

**Severity:** <Critical/High/...> — one-line justification
**Endpoint:** `POST /api/<path>` — parameter `<param>` (<auth state required>)
**Summary:** 2-3 sentences: the fetch sink, the controllable destination, the proven reach.

**Steps to reproduce:**
1. <Authenticate as <role> / no auth required>
2. Send: `<redacted raw request with <PLACEHOLDER> for collaborator values>`
3. Observe: <collaborator hit from <EGRESS_IP> at <timestamp> / internal
   content marker / role name `NAME`>

**Impact:** What an attacker gains (destination control from app egress,
rungs reached, which cloud role and what its policy implies) and the
realistic worst case. For metadata access: name the role and permissions —
never include credentials or tokens.

**Evidence:** Redacted request/response pairs; collaborator log with your
domain masked; timestamps; source-IP/ASN of the callback.

**Remediation:** One specific fix for this sink (egress allowlist at network
layer + resolve-once-pin-IP validation, scheme allowlist after parsing,
IMDSv2 hop limit 1, renderer network namespace).

**References:** CWE-918; OWASP Top 10 A10:2021; variant V-XX in
ssrf-testing skill.
```

## 6. Reference pointers

Read `references/variants-1.md` for all six variants (V-01 … V-06); read
`references/payloads.md` when you need the probing ladder, request
templates, tool commands, or evasion encodings.

Each variant section is self-contained: mechanism, preconditions, numbered
detect steps, a proof-of-concept template with `<PLACEHOLDER>` slots, the
independent confirmation signal, false positives, impact phrasing, a
sink-specific remediation, and the CWE/OWASP mapping. Match your observed
signal to §3, open that variant, and work top to bottom.
