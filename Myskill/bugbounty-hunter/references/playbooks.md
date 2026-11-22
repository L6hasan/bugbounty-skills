# Playbooks — probes, proof, and false-positive traps

Only for authorized, in-scope targets. Every proof below is read-only or uses your own
accounts. Stop at the minimum evidence that demonstrates impact.

## BAC / IDOR / BOLA (highest yield)

**Signals:** numeric/UUID IDs in paths, query, JSON body, GraphQL args; `userId`, `accountId`,
`tenantId`, `orgId`; export/download/report endpoints; "my X" APIs that also accept an ID.

**Probes (use accounts A and B you own):**
1. Capture A's request; replace A's object ID with B's and B's with A's.
2. Swap the tenant/org header or subdomain while keeping the session.
3. Try the object ID in a different verb (`GET` vs `PUT`/`DELETE`/`PATCH`) and a sibling route
   (`/api/v1/invoices/123` vs `/api/v1/admin/invoices/123`).
4. Send no ID, an array of IDs, a wildcard, or a nested object (`{"id":{"$ne":null}}` only on
   JSON APIs that show NoSQL behavior).
5. Compare UI-hidden fields: the API may return `role`, `email`, `internalNotes` not shown.

**Proof:** B's session returns A's object, or B's write changes A's object. Show both
responses and the object ownership.

**FP trap:** object is public by design; the ID is a share token that already grants access;
the endpoint enforces ownership but the UI merely hides it (still verify server-side).

## Auth, session, JWT, OAuth/OIDC/SAML

**Signals:** `/login`, `/reset`, `/invite`, `/verify`, `/sso`, `/callback`, `redirect_uri`,
`state`, `next=`, `returnUrl=`, JWT in cookie/header, `kid`, `jku`, `alg`.

**Probes:**
- Password reset: host-header poisoning of the reset link, token in Referer, token reuse,
  token not bound to user, response leaks the token, email change without re-auth.
- JWT: `alg:none`, HS256 signed with the public key, `kid` path traversal, `jku`/`x5u` to my
  host, weak secret cracked offline from a captured token, claims trusted from the client.
- OAuth: `redirect_uri` path/parameter tricks (`/callback/../evil`, `?redirect_uri=`, appended
  `@evil`, open subdomain), missing/ignored `state`, code replay, token in fragment leaked via
  Referer, implicit flow.
- Session: fixation, cookie without rotation after login, session accepted after logout,
  cross-tenant session acceptance.

**Proof:** log into my own second account via the forged/redirected flow, or access a
protected page with a token I minted. Never touch a real user's session.

**FP trap:** `state` missing but the flow is same-site and code-bound; `alg:none` rejected by
the library (verify with a real request, not the decoder).

## SQLi

**Signals:** `id=`, `sort=`, `filter=`, search, login, GraphQL args, JSON numeric fields;
errors that change with quote count.

**Probes:** `'` / `''` differential, boolean pair (`AND 1=1` vs `AND 1=2`), time delay
(`SLEEP(5)` / `pg_sleep(5)`), `ORDER BY` column count, DB-specific version function. On
JSON/NoSQL: `{"$ne":null}`, `{"$gt":""}`.

**Proof:** extract a value only I could know — DB version, my own test row — or a stable
time delta. One row, then stop.

**FP trap:** WAF block page mistaken for injection; generic 500 on any malformed input;
timeouts from load, not the payload (repeat and compare).

## XSS

**Signals:** reflected parameters, stored profile/comment/ticket fields, `innerHTML`,
`dangerouslySetInnerHTML`, template rendering, filename/metadata rendering, admin review queues.

**Probes:** context-aware breakout (`<img src=x onerror=...>`, `"><svg onload=...>`,
`javascript:` in URL sinks), DOM sinks via `#` fragment, stored payload in a field an admin
views, file name/metadata rendered in a dashboard.

**Proof:** execution in a *different* user's or privileged context, or a stored payload that
reaches a sensitive action (CSRF token theft, email change). Screenshot/DOM evidence of
`alert`/`document.domain` in that context.

**FP trap:** self-XSS requiring the victim to paste; payload only in my own browser profile;
CSP blocks execution (test it, don't assume); input sanitized server-side but reflected in a
non-executing context.

## SSRF

**Signals:** image/URL import, PDF/screenshot generators, webhooks, "fetch from URL", link
previews, import-from-URL, proxy params, SAML metadata URL.

**Probes:** collaborator/OAST host first. Then `127.0.0.1`, `localhost`, `[::1]`, decimal/hex
IP forms, `127.0.0.1.nip.io`, DNS rebinding if allowed, redirect to internal host, `file://`
only if the parser supports it. Cloud metadata `169.254.169.254` read-only, short timeout.

**Proof:** my collaborator receives the request with target-controlled headers, or the response
contains a read-only internal page/metadata value. Redact credentials.

**FP trap:** the server fetches only allow-listed domains but the error text mentions the URL;
blind DNS-only hit from a third-party scanner, not the target.

## RCE / command injection / SSTI / deserialization

**Signals:** file converters, image processing, PDF/video tools, `eval`-ish params, template
names, `{{ }}` reflection, Java/PHP serialized cookies, `viewstate`, `__proto__`, YAML/XML
import, plugin upload.

**Probes:** arithmetic proof (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`), time delay (`; sleep 5`),
OOB DNS with a unique token, harmless command (`id`, `hostname`). Deserialization: OOB gadget
probe only; never a destructive gadget.

**Proof:** arithmetic result rendered, time delta reproducible, or OOB callback tied to my
token. One read-only command, then stop.

**FP trap:** template syntax rendered as text; 500 from malformed input; sandbox blocks the
sink (confirm execution, not reflection).

## LFI / path traversal / file read

**Signals:** `file=`, `page=`, `template=`, `lang=`, `download=`, `path=`, report/export names.

**Probes:** `../../../../etc/passwd`, encoded variants (`%2e%2e%2f`, `..%2f`, double encode),
null byte on old stacks, absolute path, wrapper schemes only where the language supports them
(`php://filter` read-only).

**Proof:** file contents that only exist on the server (passwd, app config, `.env`). Do not read
user data or write files.

**FP trap:** the parameter is allow-listed and the error just echoes my path; traversal works
only on a path that is already public.

## XXE

**Signals:** XML/SOAP/SAML upload or body, `DOCTYPE`, SVG/DOCX/XLSX import, RSS feed parser.

**Probes:** external entity to my collaborator, then `file:///etc/passwd` read-only, parameter
entities for blind. Disable nothing; do not attempt SSRF-to-metadata chains without approval.

**Proof:** OOB callback or file content in the response/error.

**FP trap:** parser has external entities disabled but echoes the DOCTYPE; entity expanded
locally only.

## Business logic / race

**Signals:** coupons, credits, refunds, quantity, price, tier upgrades, invite/referral,
withdrawal, voting, workflow steps, trial abuse.

**Probes:** negative/zero/huge quantity, price tampering in the client request, coupon stacking
or reuse, applying a coupon from another account, skipping a workflow step by calling the next
endpoint, replaying a one-time action, parallel requests on a balance (single-packet race with
2-5 requests max).

**Proof:** a real gain reproduced twice (extra credit, free item, double refund, role upgrade),
with before/after balances. Do not withdraw real money or ship a real order.

**FP trap:** the server recalculates price server-side; the "double" is a UI cache; the second
request is rejected but the UI lies.

## Admin panel / server misconfig

**Signals:** `/admin`, `/internal`, `/debug`, `/actuator`, `/console`, `/manager`, `/swagger`,
`/.git/`, `/.env`, exposed Jenkins/Grafana/Kibana/Sentry, default creds on an in-scope host.

**Probes:** unauthenticated access, low-priv access, forced browsing of admin routes, API
version downgrade (`/v1/admin` still live), source maps, `.git/config`, backup files.

**Proof:** admin data or function reachable, or a secret that unlocks a chain. Screenshot the
data, then stop.

**FP trap:** a login page at `/admin` is not access; a 200 with a generic SPA shell is not
access; `/.git/HEAD` alone without object recovery is low value.

## Info disclosure / secrets

**Signals:** JS bundles, source maps, `.env`, CI logs, Postman collections, mobile APK strings,
error pages, GraphQL schema, S3/GCS listings, public repos.

**Proof:** a live credential or key that grants access to an in-scope system, PII, or internal
infra. Verify the key against the in-scope asset only, read-only.

**FP trap:** example/placeholder keys, expired tokens, keys scoped to a third party, stack
traces without secrets.
