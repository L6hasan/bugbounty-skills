---
name: path-traversal-testing
description: Deep playbook for path traversal / LFI & RFI bug bounty testing: 15 variants covering LFI filter breaks, RFI wrapper pipelines, ../ traversal, /etc/passwd & Windows win.ini isolation mapping, null-byte injection, double URL encoding (%252e%252e%252f), RPO script masquerading, Apache/Nginx/SSH log poisoning to RCE, PHP wrappers (php://filter, php://input, data://), Zip Slip archive unpacking, symlink upload bypasses, Unicode slash WAF evasion, PHP session file poisoning, nginx alias misconfiguration, and static-asset config file reads. Use this skill whenever the user is doing authorized security testing and mentions path traversal, LFI, RFI, directory traversal, file inclusion, wrappers, log poisoning, zip slip, symlink, alias misconfig, double encoding, or arbitrary file read, asks how to test for reads outside a web root, wants payloads or request templates for file-path sinks, needs to confirm or triage a traversal/LFI finding, or is writing a report for a file-access bug. Also use it when analyzing a request/response pair or code snippet for file-path handling, include/require, archive extraction, or static-serving weaknesses.
---

# Path Traversal / LFI & RFI Testing — Deep Playbook

Arbitrary file read is the bread-and-butter high-severity class in bug bounty —
and one of the easiest to over-claim, because reflection, SPA fallbacks, and
WAF pages all mimic "I read a file". This skill makes the work methodical:
inventory path sinks, pick the variant that matches the observed signal, probe
with a harmless canary first, confirm with a second independent signal, prove
impact with the minimum evidence the report needs, and write it up so triage
cannot reject it on false-positive grounds.

## 1. Scope & authorization guardrail

Only test targets you are authorized to test: a published bug bounty program
with this asset in scope, a client engagement with written scope, or your own
lab/CTF. If the target is out of scope, belongs to a third party, or you cannot
verify authorization, refuse and stop. Never run destructive payloads, never
mass-scan third-party infrastructure (wordlist runs stay in-scope and
rate-limited), and never exfiltrate data beyond the minimum needed to prove
impact.

Skill-specific hard rules:

- **Canary-first, entitlement-first proof.** Prove impact by reading a harmless
  canary (a file you planted, `/etc/hostname`, a known public asset) or a file
  you are already entitled to (your own account's export, avatar, session data).
  Do not open the evidence phase with system or user files.
- **Minimal redacted evidence when traversal reaches sensitive system files.**
  Capture only what proves the read: one signature line of `/etc/passwd`
  (`root:x:0:0:…` with usernames intact is fine; hashes do not exist there), the
  `[fonts]` header of `win.ini`, a key *name* from a config with its value
  redacted. Never request or dump `/etc/shadow`, private keys, cloud
  credentials, session stores wholesale, other users' data, or `/proc/*/environ`
  contents — if the traversal implies they are reachable, say "reachable" and
  stop.
- **Write-class proof creates new files only.** For Zip Slip and symlink
  variants, plant a *new* benign canary file; never overwrite or delete
  existing files on a production target. Overwrite/execution demonstrations
  belong in a lab clone.
- **Execution proofs are lab-only.** Log poisoning, session poisoning, and
  `php://input`/`data://` code execution get read-back proof in production
  (your injected marker returns through the include) and full execution proof
  only against an in-scope container or your own lab.

## 2. Engagement workflow

1. **Recon & endpoint inventory.** Enumerate every place a path or URL enters
   the system: path-ish params (`file`, `path`, `page`, `template`, `doc`,
   `lang`, `include`, `download`, `export`, `img`, `res`), URL-path segments
   and static locations (`/static/`, `/assets/`, `/img/`, `/files/`), archive
   and backup import/extract features, upload features, and remote-URL params
   (`url`, `src`, `load`, `fetch`). Pull routes from JS bundles, OpenAPI specs,
   and historical responses. Sink coverage — not payload cleverness — determines
   what you can find at all.
2. **Parameter & sink mapping.** Classify each candidate: an `include`/
   `require` (code-bearing, escalates), a `readFile`/`fopen`/`sendfile` (read
   class), a webserver-served static location (bypasses app auth entirely), an
   archive extractor (write class), or a remote fetch (RFI/SSRF). Record decode
   layers (edge proxy, WAF, framework auto-decode) and existing filters
   (strip-lists, `basename()`, extension allowlists) — they decide which
   variant and which encoding rung you need.
3. **Variant selection.** Route the observed signal through the table in §3 and
   read the matching section in `references/variants-1.md` or
   `references/variants-2.md`. One signal often maps to several variants
   (`../` blocked *and* `%252e` passing could be V-06 or V-12); test the
   cheapest discriminator first.
4. **Safe probe.** Start with a canary read from `references/payloads.md` §4:
   your own entitled file, a public asset, then `/etc/hostname`. Establish the
   existing-vs-missing oracle (does the app behave differently for files that
   exist?) before any deeper ladder. No system-file reads, no execution
   payloads at this stage.
5. **Confirmation test.** Reproduce with a second, *independent* signal: canary
   content **plus** an error/path differential, an encoded payload working
   **while** the plain one is blocked, a marker that changes when you re-inject
   it. A single signal has plausible alternative explanations (reflection,
   fallback pages, caching); two orthogonal signals do not. This is the step
   juniors skip and the reason traversal reports die in triage.
6. **Impact proof.** Demonstrate the minimum: canary or own-account file read,
   one redacted signature line from a system file, one attacker-controlled
   marker read back from a poisoned log. Stop there. Describe what an attacker
   *could* reach; show only the minimum they did.
7. **False-positive filter.** Work through the variant's **False positives**
   list: input reflection, SPA/404 fallback HTML, WAF challenge pages, cached
   200s, client-side routers, entitled-access reads. Rule every alternative
   explanation out — explicitly — before writing anything up.
8. **Report.** Use the template in §5. Redact secret values, tokens, and other
   users' data; attach raw request/response pairs with canary paths shown as
   placeholders.

## 3. Variant selection table

| Signal you observed | Likely variant | Reference |
|---|---|---|
| `../`-style path param returns files or path-revealing errors; depth sweep changes the response | V-03 directory separation invalidation via `../` | `references/variants-1.md` |
| Plain `../` blocked but `....//`, `..././`, `..%2f` works — single-pass strip filter | V-01 LFI filter breaks | `references/variants-1.md` |
| URL-ish param fetched from your server and its content rendered/included in the response | V-02 RFI wrapper pipelines | `references/variants-1.md` |
| First line of `/etc/passwd` or `win.ini` `[fonts]` comes back; tenant dirs mapped by path segment | V-04 core system profile access / isolation mapping | `references/variants-1.md` |
| Behavior changes only when `%00` is present; extension check seems defeated on an old stack | V-05 null byte character injection | `references/variants-1.md` |
| `%252e%252e%252f` (or triple encoding) succeeds where `%2e%2e%2f` is blocked; input echoed double-decoded | V-06 double URL encoding evasion | `references/variants-1.md` |
| Relative `src=`/`href=`/CSS `url()` asset refs + attacker-influenced URL depth; 404 pages carry relative refs | V-07 RPO script masquerading | `references/variants-1.md` |
| Marker injected via User-Agent/URL/username appears when including `/var/log/...` | V-08 log file stalking (log poisoning) | `references/variants-1.md` |
| `php://filter`, `php://input`, `data://`, `zip://` accepted in a path param | V-09 PHP wrapper execution flow | `references/variants-2.md` |
| Archive import/extract feature; entry names containing `../` or absolute paths | V-10 Zip Slip (nested archive unpacking) | `references/variants-2.md` |
| tar/zip/git upload possible; read/serve/hash of uploaded files; link entries accepted | V-11 symlink upload invalidation | `references/variants-2.md` |
| WAF blocks plain `../` but a Unicode/overlong/backslash variant returns file content | V-12 Unicode/UTF-8 slash WAF bypass | `references/variants-2.md` |
| You control `PHPSESSID` and LFI can reach `/var/lib/php/sessions/sess_<id>` (or `/tmp/sess_`) | V-13 PHP session file poisoning | `references/variants-2.md` |
| nginx `static`-style locations; boundary probes like `/static../` return out-of-root files | V-14 nginx alias misconfiguration | `references/variants-2.md` |
| `.env`, `.git/HEAD`, backup files (`~`, `.bak`) served at root or via `/assets/..%2f` | V-15 static-asset mapping misconfiguration | `references/variants-2.md` |

## 4. Verification standard

A confirmed path traversal / file inclusion finding requires all of the
following; anything less is a lead and gets reported as a lead:

1. **Reproducible request + response pair.** Exact request (headers, encoding,
   auth state) and the server's response, reproduced at least twice with the
   same result. Paste-ready for triage.
2. **A second, independent signal.** Two orthogonal proof channels — e.g. canary
   content *plus* an existence/error oracle; encoded payload succeeding *while*
   the plain payload is blocked; a poisoned-log marker that changes when you
   re-inject it *plus* a working canary LFI. One signal can be mimicked by
   reflection, fallbacks, and caching; two cannot plausibly co-occur by accident.
3. **Minimal-impact impact proof.** A canary or own-entitlement file read, or a
   single redacted signature line from an OS file. Never `/etc/shadow`,
   credential dumps, bulk user data, or full config contents in evidence —
   describe reachability, show only the minimum.
4. **False-positive audit documented.** Name the alternatives you ruled out
   (reflection, SPA fallback, WAF page, cached response, entitled access,
   client-side routing) in the report's evidence section.

## 5. Report template

```markdown
### Title
`<Vuln type> in <parameter/feature> at <endpoint> (V-XX)`

**Severity:** <Critical/High/...> — one-line justification
**Endpoint:** `GET /<path>` — parameter `<param>` (<auth state required>)
**Summary:** 2-3 sentences: the sink, the controllable source, the proven effect.

**Steps to reproduce:**
1. <Authenticate as <role> / no auth required>
2. Send: `<raw request with <PLACEHOLDER> for canary paths>`
3. Observe: <canary content / redacted signature line / encoded-vs-plain
   differential / marker read-back>

**Impact:** What an attacker gains (which file classes are reachable as
`<user>`, whether app auth is bypassed for static-served files, escalation
path to RCE if an include sink executes) and the realistic worst case.
Describe reachability of secrets — never paste the secrets.

**Evidence:** Redacted request/response pairs; canary proof first; system-file
proof reduced to a single redacted signature line; timestamps for
reproducibility. Show proof of the read, not dumps of data.

**Remediation:** One specific fix for this sink (allowlist lookup, canonical
prefix check on the final path, alias slash fix, archive entry validation…).

**References:** CWE-<XX>; OWASP Top 10 <A0X:2021>; variant V-XX in
path-traversal-testing skill.
```

## 6. Reference pointers

Read `references/variants-1.md` for variants 1-8 and `references/variants-2.md`
for variants 9-15; read `references/payloads.md` when you need request
templates, tool commands, or WAF-evasion encodings.

Each variant section is self-contained: mechanism, preconditions, numbered
detect steps, a proof-of-concept template with `<PLACEHOLDER>` slots, the
independent confirmation signal, false positives, impact phrasing, a
sink-specific remediation, and the CWE/OWASP mapping. Match your observed
signal to §3, open that variant, and work top to bottom.
