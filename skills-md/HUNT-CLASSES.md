# HUNT-CLASSES — taxonomy → minimal test → bypass → escalation

Companion to `/root/HUNT-WORKFLOW.md`. One class per pass. Each block gives you the observable
signal, the cheapest test that can confirm it, the bypass ladder when blocked, and the escalation
that turns it into a reportable finding.

**Read the program's non-qualifying list BEFORE you spend a pass on a class.** A disqualifying
class is not a finding even when exploitable.

**Deep dives live in the technique skills** — route by class name:
`xss-testing` · `sqli-testing` · `bac-idor-testing` · `ssrf-testing` · `rce-testing` ·
`path-traversal-testing` · `info-disclosure-testing` · `business-logic-testing` ·
`csrf-testing` · `sandbox-escape-testing`.
Ledger offsets: `/root/hackbot-architecture/knowledge/SKILL-CORE.md` → `SKILL-INDEX.md`.

---

## 1. Cross-Site Scripting (XSS)

Ten subtypes, each a different test. **Test all ten — reflected-only is how hunters leave money
on the table.** Measured in the field: stored and blind variants pay multiples of reflected.

| Subtype | Observable signal | Minimal test | Where it lives |
|---|---|---|---|
| **Reflected (RXSS)** | your bytes in the immediate response | unique marker `<zz1>` → find exact byte position → context-correct payload | search, error, filter, lang, `returnUrl` |
| **Stored / Persistent** | input saved, rendered later (often to another role) | write marker in profile/comment/ticket → read as second role | admin queue, exports, emails, PDFs |
| **DOM-based** | value never leaves the browser | map `location.*`/`document.URL`/`window.name`/`localStorage` → `innerHTML`/`eval`/`document.write`/`.src` | SPAs, hash routers, `postMessage` |
| **Blind** | executes in staff/log/back-office context | unique OOB payload; wait for callback with origin+path+role | support tickets, feedback, UA/Referer logs |
| **UXSS** | browser/extension flaw | not an app bug — context only; belongs to the browser vendor | — |
| **Self-XSS** | only the victim pasting it | chain: does a flow *place* attacker text into a paste/copy context? | dev consoles, "paste this" flows |
| **POST-based** | reflected only via body | same as RXSS but in form/JSON fields, `multipart` filename | forms, JSON APIs, importers |
| **GET-based** | reflected via query | RXSS on `?param=` including path segments | links, shares, redirects |
| **Mutation (mXSS)** | sanitizer output re-parses differently | round-trip: feed to sanitizer, re-serialize, re-parse — look for parser disagreement (`<noscript>`, `<svg>`, `<math>`, nested `<form>`) | DOMPurify-backed rich text |
| **Polyglot** | one payload, many contexts | `jaVasCript:/*-/*`*/`/*\`/*'/**/(/**/oNcl\`ick=alert(1)//`-*/`*/` */` | when reflection context is unknown |

**Context-boundary discipline (RXSS):** locate the exact landing context before payloading —
HTML text, quoted attr, unquoted attr, URL attr (`href`/`src` — needs `javascript:` or `data:`),
JS string, JS template, JSON-in-HTML, CSS. Each has a different break-out. A payload that
"doesn't work" is almost always a wrong context, not a hardened target.

**Bypass ladder (when blocked):** alternate tag/attr (`<img src=x onerror>`, `<svg onload>`,
`<details open ontoggle>`) → alternate encoding (HTML entities, `\u`, double URL, unicode
normalization) → parser confusion (`<scr<script>ipt>`) → CSP analysis (`unsafe-inline`?
`unsafe-eval`? JSONP endpoint on an allowlisted host?) → sanitizer version → known mXSS.

**Escalation:** reflection → stored → **admin/staff context** (P1) · XSS + session cookie
without `HttpOnly` → ATO · XSS in an email/PDF renderer → internal network (SSRF/RCE axis) ·
XSS + CSRF token read → CSRF bypass. *Self-XSS, and XSS that cannot impact another user, is
program-disqualified — chain it or drop it.*

---

## 2. SQL Injection / NoSQLi

**Signal:** any param that shapes a query — search, filter, sort, `ORDER BY`, id, pagination,
report builder, export, "advanced search", GraphQL arg, XML/SOAP body, JSON field.

**Minimal test (in order, cheapest first):**
```
'                     -> error/500 vs 200
'||'1'='1             -> boolean diff
' AND 1=1-- - / ' AND 1=2-- -   -> body/row-count diff
' OR SLEEP(5)-- -     -> time diff (only if allowed)
```
Then `sqlmap -r req.txt --batch --level=3 --risk=2` **only** after manual confirmation and only
if the program allows automated scanning. Rate-limit yourself.

**Subtypes worth checking:** error-based · union · boolean blind · time blind · OOB (DNS/HTTP) ·
stacked queries · **second-order** (stored value used in a later query — most missed) · JSON/XML/
GraphQL parametric · `ORDER BY`/`GROUP BY` structural · DB-specific exec (`xp_cmdshell`,
`COPY PROGRAM`, `INTO OUTFILE`, `LOAD_FILE`) · WAF comment/whitespace bypass · truncation
injection · NoSQL operator substitution (`{"$ne":null}`, `{"$where":...}`, `$regex`).

**Escalation:** data read → PII/ATO · file read/write → RCE · auth table write → admin ·
`$where` JS → RCE (Mongo). A single-row read of your own data is not a finding; cross-user data
or execution is.

---

## 3. IDOR / BOLA / Broken Access Control

**Signal:** any object id, GUID, slug, filename, or tenant/org identifier in path, query, body,
header, or GraphQL node.

**Minimal test:** the two-account loop in `HUNT-MODES.md §G2` — baseline, probe, B-baseline,
noauth control. **Never conclude from the probe alone.**

**Variants:** horizontal (same role, other user) · vertical (higher role's object) · mass
assignment (send extra privileged fields: `role`, `isAdmin`, `tenantId`, `verified`) · HPP
(`?id=A&id=B`) · weak id enumeration (sequential ints, short GUIDs, base64 global ids —
`base64("Type:123")`) · second-order (object created safely, referenced unsafely) · GraphQL node
access (`node(id:)` bypassing query-level scoping) · JWT claim laundering · cross-tenant leaks.

**Verdict discipline:** `200` + identical body = confirmed. `200` + empty body needs a third
signal. `404` on foreign object but `200` on own object = **check exists** → try sibling route.
`500` on foreign object = a handler decision, inspect the error class (see the authorization
oracle in `HUNT-WORKFLOW.md §4`).

**Escalation:** read → write · own-role → admin-role · one tenant → all tenants · object read →
PII mass export · write on another user's object → ATO (change email/password/MFA).

---

## 4. Authentication / OAuth / SSO / JWT

**Signal:** login, signup, invite, reset, SSO redirect, `redirect_uri`, `state`, `postMessage`,
any token in URL, `alg` header, session cookie format.

**Minimal tests:**
- Header-based bypass: `X-User`, `X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`,
  `X-Forwarded-Host`, internal hostname in `Host`.
- Path/route bypass: `/admin` → `/Admin`, `/admin/`, `/admin/.`, `/admin%2f`, `;/admin`,
  `/./admin`, double-slash.
- Token forgery: `alg:none`, empty/default HMAC key, `kid` traversal, weak secret (hashcat),
  claim swap (`sub`, `role`, `tenant`), signature stripping.
- Reset flow: token in response body, token predictability, Host-header injection into reset
  link, token reuse after use, reset by email change without confirmation.
- OAuth: `redirect_uri` allowlist regex (unescaped dot, missing anchor, path suffix,
  `@`, userinfo), missing `state` → login CSRF, scope escalation, dynamic client registration.
- MFA/OTP: response manipulation, code reuse, no attempt limit + short code, backup-code leak.

**Escalation:** any of the above → ATO · pre-account-takeover via OAuth is disqualified in most
programs · login/logout CSRF is disqualified — chain it to a sensitive action.

---

## 5. SSRF / XSPA

**Signal:** any param that is a URL, host, webhook, image, PDF/HTML render, import-from-URL, RSS,
proxy, "preview", "fetch metadata", SAML metadata URL, avatar upload by URL.

**Minimal test:** `127.0.0.1`, `localhost`, `[::ffff:127.0.0.1]`, `2130706433`, `0x7f000001`,
`127.1`, DNS-rebind host, `http://169.254.169.254/latest/meta-data/` (AWS), GCP
`metadata.google.internal/computeMetadata/v1/` + `Metadata-Flavor: Google`, Azure
`169.254.169.254/metadata/instance?api-version=`, Alibaba `100.100.100.200`, K8s
`kubernetes.default.svc`.

**Protocol smuggling:** `gopher://` (Redis, SMTP, FastCGI), `dict://`, `file://`, `ftp://`,
`ldap://`. Redirect-based bypass when the first hop is allowlisted.

**Escalation:** metadata → IAM creds → cloud account · internal service (Redis/Solr/Elasticsearch/
Jenkins) → RCE · blind SSRF alone is **disqualified** — prove a read or a write.

---

## 6. RCE / command & code injection

**Signal:** any input reaching a shell, template engine, deserializer, eval-like sink, file
upload that gets executed/served, archive extraction, config loader, cron/job scheduler.

**Minimal tests:** `;id`, `|id`, `$(id)`, backticks, `%0aid`, newline injection in a header/arg;
SSTI polyglot `{{7*7}} ${7*7} #{7*7} <%= 7*7 %>` then engine fingerprint then sandbox escape;
deserialization: signed-vs-unsigned, gadget probe, OOB DNS; upload: extension+content-type+
magic-byte differential, zip-slip, symlink.

**Escalation:** read-only exec proof (`id`, `hostname`) is enough for the report but the *report*
needs a stated worst case: web shell, data access, lateral movement. Argument injection
(`--config`, `-o`) counts and is badly under-tested.

---

## 7. Path traversal / LFI / RFI / XXE

**Signal:** filename, path, template name, language file, export path, static-serve route,
archive entry, XML/SOAP/SVG/Office upload.

**Minimal tests:** `../../../../etc/passwd`, `..%2f`, `%252e%252e%252f`, `....//`, unicode slash
`%ef%bc%8f`, null byte `%00`, absolute path, Windows `win.ini`/`..\..\`. Wrappers:
`php://filter`, `php://input`, `data://`, `expect://`. XXE: external entity, parameter entity,
OOB via collaborator, SVG/Office variants.

**Escalation:** source read → secrets → admin · log poisoning → RCE · zip-slip write → RCE ·
XXE → internal SSRF → metadata. **Path/stack disclosure alone is disqualified** — must read
something sensitive.

---

## 8. Information disclosure (with PoC)

**Signal:** `.git`/`.svn`, `.env`, `*.bak`, source maps, `swagger.json`/`openapi.json`,
`actuator/*`, directory listing, buckets, backups, Postman collections, verbose errors, SMTP
header leaks, EXIF.

**Rule:** disclosure is only reportable if it grants access or reveals data that matters
(credentials, tokens, PII, internal endpoints that then yield data). `robots.txt`, banner,
stack trace, version, directory listing without sensitive files = **not a finding** per nearly
every modern program.

**Escalation:** `.git` → source → secret → live admin · `.env` → DB/API key → data · bucket →
backups → PII · swagger → hidden admin route → BAC.

---

## 9. Business logic

**Signal:** money, credits, coupon, quota, refund, workflow step, invite, referral, trial,
multi-stage form, cart.

**Minimal tests:** negative quantity/price · currency swap · rounding · coupon replay/stacking ·
step skip (call step 3 directly) · state replay (re-send a completed step) · race (parallel
identical requests, HTTP/2 single-packet) · id swap between stages · limit/plan bypass · trial
extension · refund without return.

**Escalation:** monetary loss at scale, plan bypass, free goods, quota exhaustion of a paid
resource. A one-cent rounding bug is not a finding; the *pattern* that scales is.

---

## 10. CSRF

**Signal:** state-changing request that authenticates only by cookie.

**Minimal test:** replay the state-changing request from a foreign `Origin` with no token, then
with a bogus token, then with a *reused* token. Check `SameSite` empirically, not by reading the
cookie.

**Rule:** logout/login/cart-update CSRF is disqualified almost everywhere. Reportable only when
the action is security-relevant (email change, password change, MFA disable, admin action,
funds transfer). Chain: CSRF + missing `Origin` check + JSON content-type confusion.

---

## 11. Host header / cache / smuggling / desync

**Signal:** password-reset links, absolute-URL generation, CDN in front, multiple proxies.

**Tests:** `Host: attacker`, `X-Forwarded-Host`, `X-Original-URL`; cache deception
(`/account/profile.css`), cache poisoning via unkeyed headers; CL.TE / TE.CL / TE.TE smuggling
via `Content-Length`/`Transfer-Encoding` leniency; header-line delimiter leniency (bare LF, lone
CR). **Only reportable with demonstrated impact** — reset-token theft, cache poisoning of a
victim, request-queue poisoning.

---

## 12. Cloud / sandbox / supply chain

**Signal:** container, k8s, CI, package manifest, IaC, chart, plugin system, WASM, `vm2`,
`SecurityManager`, FaaS.

**Tests:** the deep playbook is `sandbox-escape-testing` — Node `vm`/`vm2` context extraction,
Python jail MRO walk, PHP `disable_functions` bypass, Docker socket, hostPath, eBPF verifier,
`$SAFE`, Lua bytecode, content-provider leakage, WASM overflow, hypervisor IOCTL.

**Escalation:** tenant escape, host compromise, CI secret theft → supply-chain RCE.

---

## 13. The universal bypass ladder (memorise this)

When any test is blocked, try these in order and timebox to **5 attempts / 20 minutes**:

1. **Encoding** — double URL, unicode normalization, case, trailing dot/slash, `%00`, HTML entities.
2. **Parser** — same field as JSON ↔ form ↔ multipart ↔ XML; duplicate keys; array/object wrap.
3. **Trust** — the header the app trusts instead of the cookie/claim; internal hostname; port.
4. **Version/path** — `/v1` vs `/v2`, `/internal`, `/legacy`, `/mobile`, `/api/v3`, `?format=json`.
5. **Role** — the same object via the higher role's route with the lower role's session.
6. **Timing/state** — race two requests; replay a completed step; interleave tenants.

If it still fails: **stop grinding.** Go to CHAIN with what you have, or change asset. A blocked
pass with a written negative result is a success; a pass spent re-trying one payload is not.

---

## 14. Class coverage checklist (per engagement)

Copy into `state.md` and put a verdict next to each. A coarsely-claimed class is NOT covered
until every subtype has a verdict (`tested-clean` / `lead` / `confirmed` / `n/a`).

```
XSS      : RXSS stored DOM blind UXSS self POST GET mXSS polyglot
Injection: SQLi error union bool time OOB stacked second-order NoSQL cmd SSTI XXE
Access   : IDOR horiz vert mass-assign HPP weak-id 2nd-order GraphQL JWT cross-tenant
Auth     : header bypass path bypass JWT forge reset OAuth state MFA/OTP
SSRF     : basic blind metadata protocol-smuggle PDF/image redirect
RCE      : cmd arg code deser upload archive config cron
Traversal: LFI RFI `../` double-encode null-byte wrapper zip-slip symlink alias
Disclose : git env map swagger bucket backup log email EXIF
Logic    : price qty currency coupon refund workflow race step-skip invite trial
CSRF     : token-absent reuse SameSite Origin JSON-tunnel CSWSH
Infra    : host header cache smuggle desync cloud sandbox supply-chain
```
