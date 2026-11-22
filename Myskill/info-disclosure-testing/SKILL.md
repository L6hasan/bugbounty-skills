---
name: info-disclosure-testing
description: Deep playbook for information disclosure bug bounty testing: 15 variants covering exposed .git/.svn/.bak repositories, server banner and stack trace leaks, internal IP/schema mapping, directory indexing, hardcoded keys and secrets, GraphQL introspection, Heartbleed memory extraction, source map leakage, public S3/GCP buckets, exposed .env/config files, Swagger/Postman documentation, verbose log directories, SMTP header internal hostname leaks, and document metadata (EXIF) extraction. Use this skill whenever the user is doing authorized security testing and mentions information disclosure, data leakage, exposed .git, .env files, source maps, bucket misconfiguration, S3 enumeration, introspection, stack traces, server banners, exposed backups, hardcoded secrets, Swagger endpoints, or EXIF metadata; asks how to test whether a leaked file or bucket is actually a finding, wants recon path wordlists or curl templates for leak hunting, needs to confirm or triage an information disclosure report (is it sensitive enough to count?), or is writing a report for a leak bug. Also use it when analyzing a response body, header set, or fetched file for sensitive data exposure.
---

# info-disclosure-testing: Leaks & Disclosure Deep Playbook

## 1. Scope & authorization guardrail

Only test targets you are authorized to test: a published bug bounty program with the
asset in scope, a client-engagement target, or your own lab/CTF. Refuse out-of-scope
hosts, third-party assets (including third-party buckets and CDNs you stumble onto),
and any request to enumerate or exfiltrate data from a system you do not have
permission for. When in doubt, ask for the program URL or scope statement before
touching a target. Note that many programs scope *buckets and file storage* by name —
a bucket that resolves from a domain you found is not automatically in scope.

Two rules that are not negotiable:

- **Read-only means read-only.** Never modify, upload to, delete from, or "clean up"
  anything you find — no `PUT`/`DELETE` against buckets, no writing into exposed
  `.git` or log directories, no renaming objects to prove access. For bucket work,
  listing and reading are the proof; changing state is both a scope violation and a
  crime on someone else's infrastructure. Never run memory-extraction loops (V-08)
  against production at volume — Heartbleed probes can crash the service (DoS guardrail).
- **Never paste live secrets into reports, chat logs, or screenshots.** Redact to the
  pattern + location (see `payloads.md` §6). A report that leaks the very credential it
  reports becomes the leak. Capture hashes, truncated values (`AKIA…7Q`), or masked
  samples instead.

This skill exists to make authorized testing methodical and to produce reports that
hold up under triage review. The hard part of this category is not discovery — it is
**triage**: most things you find are not bugs, and the skill teaches where the line is.

## 2. Engagement workflow

1. **Recon & surface inventory.** Collect every host, path, and artifact the target
   exposes: domains and subdomains, response headers on every response you already
   have, JS bundles, downloaded documents, error pages triggered during normal
   browsing, and any storage/API endpoints. *Why:* disclosure hunting is mostly
   passive — the richest leaks (banners, source maps, headers) arrive for free before
   you probe anything.

2. **Path & artifact sweep.** Run the recon wordlists in `payloads.md` §1 against
   in-scope hosts (`/git/HEAD`, `/.env`, `/backup.zip`, `/.map`, `/swagger.json`,
   `/logs/`, etc.). Record status **and** content-type **and** body hash — a 200 is
   not a finding, it is a lead. *Why:* soft-404s, catch-all marketing pages, and WAF
   interstitials return 200 for everything; only body inspection separates them from
   real exposures.

3. **Variant selection.** Use the routing table in §3 to map each observed signal to
   1-2 variants and read the matching section in `references/variants-1.md` or
   `references/variants-2.md` before improvising — each has preconditions and
   false-positive traps that will burn your credibility if skipped.

4. **Safe verification.** Confirm each lead with the minimal read the variant calls
   for: pull `.git/HEAD` and one object, fetch one sourcemap, run one introspection
   query, list one bucket. No bulk harvesting yet. *Why:* you need to know the lead is
   real before you invest — and some "exposures" (honeypot git dirs, sample buckets)
   are traps that waste hours.

5. **Sensitivity triage (the step juniors skip).** Ask: what did this actually expose?
   Version string only → usually informational, not reportable alone. Source code with
   a hardcoded production credential → high. Public directory listing of backup files
   containing user data → high/critical. A 403'd bucket → not a bug. A public bucket
   with PII → report it. Classify each confirmed leak against the impact bar in §4
   before spending more time on it. *Why:* programs triage hundreds of "your nginx
   version is visible" reports; teaching yourself the line now saves everyone.

6. **Impact proof (minimal, redacted).** Prove capability, not haul: demonstrate the
   `.git` is fully recoverable by checking out one file, show the first redacted
   secret found in `.env`, extract one introspection field that proves schema access,
   or show one bucket object listing. Do not exfiltrate user data to prove user data
   is exposed — the listing plus one redacted example is the proof.

7. **False-positive filter.** Rule out: soft-404 pages, default install artifacts
   (Tomcat example pages, phpinfo left by a framework), synthetic/lab data, honeypot
   repos, cached CDN copies of removed files (check origin vs cache headers), secrets
   that are public by design (published PGP keys, OAuth client IDs, mobile app
   embedded keys documented as public), and staging/test environments explicitly
   excluded by scope. Re-fetch with cache-busting headers before claiming a live leak.

8. **Report.** Write it with the template in §5: exact request, redacted evidence,
   the data *class* exposed (not the data itself), and remediation naming the actual
   root cause (file served by webroot, debug flag on, bucket ACL, missing authz on
   the introspection endpoint).

## 3. Variant selection table

| Signal you observed | Likely variant | Reference |
|---|---|---|
| `/git/HEAD` returns `ref: refs/heads/…`; `.svn`, `.bak`, `.old` files download | Exposed VCS repos / backup files | `references/variants-1.md` §V-01 |
| `Server:`, `X-Powered-By:`, `X-AspNet-Version:` or odd micro-service headers reveal versions/infrastructure | Server banner & infrastructure footprinting | `references/variants-1.md` §V-02 |
| Stack traces, framework debug pages, `Whoops`, Django DEBUG, JSP dumps on error | Debug exception / stack trace leak | `references/variants-1.md` §V-03 |
| Responses embed internal IPs (10.x, 172.16-31.x, 192.168.x, 127.x), internal hostnames in redirects/errors/HTML comments | Internal IP / network schema leakage | `references/variants-1.md` §V-04 |
| `Index of /` listings, autoindex, listing filters expose files not linked anywhere | Unprotected directory indexing | `references/variants-1.md` §V-05 |
| Keys/tokens in JS bundles, mobile APKs, page source, client configs (`apiKey`, `aws_secret`, JWT signing key) | Hardcoded keys / client secrets | `references/variants-1.md` §V-06 |
| `{"data": {"__schema": …}}` returned for an introspection query | GraphQL introspection leakage | `references/variants-1.md` §V-07 |
| TLS heartbeat responds with extra process memory; openssl `heartbeat` probe returns adjacent heap | Heartbleed-style memory extraction | `references/variants-1.md` §V-08 |
| `//# sourceMappingURL=` comments, `.js.map` files fetchable, `sourcesContent` present | Client-side source map leakage | `references/variants-2.md` §V-09 |
| `s3.amazonaws.com`, `storage.googleapis.com`, `s3://` URLs; bucket listable or objects world-readable | Open cloud storage bucket | `references/variants-2.md` §V-10 |
| `/.env`, `/config.json`, `application.yml`, `settings.py` downloadable with real secrets | Exposed environment/config files | `references/variants-2.md` §V-11 |
| `/swagger.json`, `/openapi.json`, `/api-docs`, `/v2/api-docs`, Postman collection URLs respond | Public API documentation (Swagger/Postman) | `references/variants-2.md` §V-12 |
| `/logs/`, `/log/`, `error.log`, `access.log` fetchable; log directories autoindexed | Verbose log file leakage | `references/variants-2.md` §V-13 |
| Email headers expose `X-Originating-IP`, internal mail hosts (`*.internal`, `*.corp`, `mail01`), SMTP banners | Internal domain via SMTP/email headers | `references/variants-2.md` §V-14 |
| Uploaded/downloadable images or docs carry EXIF (GPS, device, author, internal paths) | Document metadata (EXIF) extraction | `references/variants-2.md` §V-15 |
| Anything found in JS bundles or downloaded files that feeds another class of attack | Chain: credentials → `sqli-testing`, IDs → `bac-idor-testing`, internal hosts → `ssrf-testing` | `references/payloads.md` §7 |

## 4. Verification standard

A **confirmed finding** requires all three:

1. **Reproducible request/response pair** — the exact URL/method/headers, plus the
   response (or headers) demonstrating the disclosure, reproducible 3× from a clean
   session. For file/git/bucket work, include the command template with placeholders
   and the observed output, redacted.
2. **A demonstrated data class** — not just "the endpoint responds", but a statement
   of *what* leaked: source code, credential, internal IP, PII, schema, memory
   fragment. Name the class; never paste the payload of the secret itself.
3. **A false-positive check** — evidence it is not a soft-404, honeypot, cached
   remnant, public-by-design artifact, or sample data. Note what you ruled out.

A **lead** (not reportable alone): a 200 on a probe path with no interesting body, a
banner showing only `nginx` with no version, a directory listing with only public
assets, introspection disabled but a GraphQL endpoint present, a bucket that returns
`AccessDenied`/403, an error page with no trace. Escalate leads with the next rung of
the variant's Detect steps, or discard.

Severity framing: exposed `.git`/credentials/PII/production secrets → high-critical
(context-dependent); full introspection schema on a production API → medium (raise if
it reveals privileged mutations or authz-sensitive fields); stack trace with internal
paths/IPs → low-medium; banners and versions alone → informational (usually not worth
reporting alone unless paired with a known CVE in that exact version); EXIF with GPS
→ medium, EXIF with only camera model → informational. Programs frequently pay only
for the higher tiers — triage accordingly before reporting.

## 5. Report template

```markdown
# <Class> exposed via <mechanism> at <location>

**Severity:** <High/Medium/Low — CVSS vector if the program wants it>
**Endpoint:** `https://<target.example>/<path>` (auth: <none/cookie/token>)
**Summary:** <Path/endpoint/artifact> is served without access control and discloses
<redacted data class: e.g. a full Git repository / a production API key pattern /
a listing of user-uploading objects>. Reproduced <N>× from an unauthenticated session.

## Steps to reproduce
1. Visit `https://<target.example>/<path>` with a plain unauthenticated request.
2. Request follows (placeholders filled in):
   ```http
   <GET /<path> HTTP/1.1>
   Host: <target.example>
   ```
3. Observe: <response body/headers> contain <evidence description>. Content-class:
   <what it proves>.

## Impact
<Concrete attacker capability, e.g. "Any unauthenticated visitor can reconstruct the
full application source via Git object recovery and has obtained <N> live credentials
from .env, granting <access level> to <system>."> State auth level required (none).

## Evidence
<Redacted request/response pairs. Secrets shown as pattern + last 4 chars or hash:
e.g. AWS key `AKIA••••••••7Q`, DB URL `postgres://app@<host>/•••`. Never the live value.>

## Remediation
<Specific root cause fix: remove deployed artifacts from webroot (.git, .env, backups),
disable directory listing and debug mode, add authz on the endpoint, bucket policy
with public-access-block, rotate the exposed credential — rotation is part of the fix.>

## References
- CWE-538 / CWE-200 / CWE-540 (source code on web server), CWE-798 (hardcoded credentials), CWE-209 (error exposure)
- OWASP A01:2021 Broken Access Control; WSTG-INFO-* (fingerprinting, enumerate application)
```

## 6. Reference pointers

Read `references/variants-1.md` for variants 1-8 and `references/variants-2.md` for
variants 9-15; each file opens with a table of contents linking every section. Read
`references/payloads.md` when you need the recon path wordlists (git/env/backup/
sourcemap/swagger/log candidates), the `.git` exposure validation procedure
(including the soft-404 gotcha), curl capture templates with `<PLACEHOLDER>` slots,
the S3/GCP bucket enumeration-and-verify procedure, the secret redaction checklist,
or the "chain it with" cross-skill notes.

The suite cross-references by directory name: leaked schema and credentials feed
`sqli-testing` (pair table names with `.env` DB credentials); leaked IDs and GraphQL
nodes feed `bac-idor-testing` (BOLA on object IDs); leaked internal hosts and
metadata endpoints feed `ssrf-testing` (cloud metadata, internal pivots); leaked
file paths and backup filenames feed `path-traversal-testing` (which file params can
be forced to read them). Disclosure is rarely the end of an attack chain — it is the
map.
