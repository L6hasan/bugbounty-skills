# api-graphql — part 1/1 (49 segment(s))
# content-aware dedupe applied; every unique entry preserved.

## [Bugbountyskills.md] --- G1: full introspection (schema inventory) ---------------------------

curl -sS -b jar_a.txt -X POST '<TARGET_URL>/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name } } } }"}'

## [Bugbountyskills.md] Polite sequential-ID sweep (single endpoint, tiny wordlist, 1 req/s)

seq <START_ID> <END_ID> | ffuf -u '<TARGET_URL>/api/<RESOURCE>/FUZZ' \
  -b 'session=<SESSION_A>' -w - -rate 1 -mc 200,403,404 -fs <SOFT404_LENGTH>

## [Bugbountyskills.md] V-10: API endpoint version bypassing for unprotected legacy resource fetching

**Mechanism:** Authorization middleware was added when v2 shipped, but v1 (or a
`legacy`/`beta` prefix, or content-negotiated variants) is still deployed without it for
backward compatibility. Old code paths carry old — absent — checks: the violated
assumption is "deprecating a version removes its risk".

**Preconditions:**
- Multiple versions/variants exist: `/api/v1`, `/api/v2`, `/legacy`, version headers
  (`X-API-Version`, `Accept: application/vnd.app.v1+json`), `?version=`, subdomains
  (`api-old.`).
- Same logical operation reachable on at least two of them.

**Detect:**
1. Inventory versions from JS bundles, OpenAPI files (`/v1/swagger.json`),
   `Deprecation`/`Sunset` headers, and error messages that name versions.
2. Replay the identical operation as low-priv A across versions; record status +
   response depth for each.
3. Read the differential: v2 `403` for `<OBJECT_ID_B>` while v1 returns `200` + data is
   the clean signal; also compare field exposure (v1 may return more fields than v2 even
   when both "work" — that's BOPLA on the legacy path).
4. Test the *auth* dimensions separately per version: session cookie vs. API key vs.
   legacy static token; old versions sometimes accept a revoked/weak credential type.
5. Try version selection via non-path channels (header, query, body `version` field) —
   the app may honor a downgraded version string inside an otherwise v2 request.

**Proof of concept:**
```bash
curl -sS -i -H 'Cookie: session=<SESSION_A>' '<TARGET_URL>/api/v2/<RESOURCE>/<OBJECT_ID_B>'   # expect 403
curl -sS -i -H 'Cookie: session=<SESSION_A>' '<TARGET_URL>/api/v1/<RESOURCE>/<OBJECT_ID_B>'   # observe response
curl -sS -i -H 'Cookie: session=<SESSION_A>' -H 'Accept: application/vnd.app.v1+json' \
  '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_B>'
```

**Confirm:** Same session, same object, different version → denied vs. returned. The
A/B differential proves the gap is version-scoped middleware, not a flaky check; back it
with B's session confirming object ownership.

**False positives:** v1 returns `200` but only *your own* or sanitized data (old
serialization may mask rows differently — check whose object it is); v1 is a documented
stub returning canned responses; v1 requires an API key with intentionally broader
scope (report as over-scoped credential, not version bypass); v1 routes actually
aliasing v2 middleware in the router (compare bodies byte-for-byte); cached v1 responses.

**Impact:** "The deprecated `/v1` path lacks the authorization enforcement added in `/v2`,
letting any authenticated user fetch other users' `<resource>`; v1 remains reachable
with `<credential type>`."

**Remediation:** Retire legacy versions (410 after a sunset window) and apply the same
authorization middleware/version-agnostic policy layer to every route regardless of
version.

**CWE / OWASP:** CWE-284 (Improper Access Control); OWASP A01:2021 — report as an
over-scoped legacy credential instead when the version's broader scope is documented by design.

---

## [Bugbountyskills.md] V-04: Internal network schema mapping via server-leaked IP address points

**Mechanism:** Responses leak addressing: HTML comments (`<!-- lb-01 10.0.4.12 -->`),
redirects to `http://10.x.internal/`, connection strings in configs/errors,
`X-Backend-Server` headers, health endpoints listing pod IPs. Violated assumption:
"users can't route to RFC1918" — they can't, but they don't need to: the leak *is* the
map for SSRF targeting and trust-boundary discovery.

**Preconditions:**
- Some surface (header, body, error, comment, config) carries an IP or internal hostname.
- Value compounds with a request-forging primitive (→ `ssrf-testing`) — the leak maps, the chain exploits.

**Detect:**
1. Grep everything you already have for `10.x`, `172.16-31.x`, `192.168.x`, `127.x`,
   `169.254.x` (cloud metadata), IPv6 ULA `fc00::/7`, and internal hostnames
   (`*.local`, `*.internal`, `*.corp`, `*.svc.cluster.local`, `db-primary`, `redis-02`).
2. Sources: response headers (`X-Backend-Server`, `Via`, `X-Real-IP` set by origin),
   HTML/JS comments, `Location:` on auth redirects, WebSocket URLs, error pages (V-03),
   `.env`/config (V-11), `/actuator/env`, `/server-status`.
3. Correlate: an address in two independent responses = a node; hostname+IP pairs give
   the DNS scheme to brute later.
4. Optional passive corroboration for in-scope hosts (check program rules on
   third-party scanning first): passive DNS, CT logs.

**Proof of concept:**
```http
GET /<path-with-comment-or-error> HTTP/1.1
Host: <TARGET.HOST>
```
Observed (redacted): body comment `<!-- upstream: <service> 10.0.<a>.<b> -->` plus a
second response `Location: http://<service>.<domain>.local:<port>/callback`. Document
as a table: source → address → inferred role.

**Confirm:** Two independent signals per node: same address/hostname from a different
endpoint or disclosure class (header vs body vs config), or an in-scope reverse lookup
resolving to the same internal name. One mention on one page is a lead.

**False positives:** Public CDN/LB IPs (not internal — don't claim them); `X-Forwarded-For`
echoing *your own* IP (normal proxy behavior); RFC1918 examples copied from tutorials
(`192.168.1.1` in a snippet — verify against real roles); localhost in generic banners;
sample fixtures. And don't conflate leak with exploit: visible internal IP ≠ SSRF exists
— report which one you have.

**Impact:** "Unauthenticated responses disclose internal topology (N hosts, roles,
ports), removing discovery for a follow-on SSRF/RCE." Medium standalone when
corroborated; normally booked as step one of a chain — with an SSRF present, this leak
upgrades that finding because internal targeting becomes deterministic.

**Remediation:** Strip internal headers/comments from edge responses, redact addresses
in client-facing errors, and put health/debug endpoints behind authz.

**Field notes (2026-10-21, Envoy/k8s sidecar on a public subdomain):**
- **`x-envoy-decorator-operation` hands over the internal Kubernetes service FQDN.**
  `eventlogger-publisher-frontend.eventlogger.svc.cluster.local:80/*` tells you the mesh
  (Envoy), the namespace, the service name, the target port *and* the component's
  purpose in one header — a whole V-04 map from a single unauthenticated `GET`. Add it to
  the Detect sweep alongside `X-Backend-Server`/`Via`/`X-Real-IP`; it is emitted on
  **every** response from that host, not just errors.
- **Corroborate before you claim it as the app's.** Same session, same CDN: the header was
  present on every `el.*` response and absent on `quizlet.com`, `study.*` and `jg7y.*`
  responses → it is that one service's, not a zone-wide CDN injection. Scope your claim to
  the host that emits it, and note the pairing that makes it matter: this host was also an
  unauthenticated POST-only event sink, so a future SSRF lands one hop from the service the
  header names.
- **The mesh header arrives with the origin-infrastructure header.** `via: 1.1 google`
  alongside Envoy headers means GCP L7 LB → mesh → pod; the *chain* is the useful map
  (internet → CF → Google LB → Envoy → k8s Service), not either header alone.
- **Cheap adjacent route check:** a service like this usually has a `/status`, `/metrics`
  or `/healthz`. Probe them — and if the WAF hard-blocks exactly that path, that block is
  itself evidence the endpoint exists and is worth re-testing from an allowed network
  rather than "ruling it out".

**CWE / OWASP:** CWE-200, CWE-668 (Exposure of Resource to Wrong Sphere) — OWASP
A05:2021; WSTG-INFO-02/05.

---

## [Bugbountyskills.md] V-07: GraphQL introspection query data schema leakage exploitation

**Mechanism:** Introspection (`__schema`, `__type`) is enabled by default in most
GraphQL stacks and returns the entire API surface: types, fields, arguments, and — the
good part — mutation names hinting at privileged operations (`adminResetPassword`,
`internalTransfer`). Violated assumption: "introspection is a dev convenience" — in
production it's a complete API map for unauthenticated clients.

**Preconditions:**
- A GraphQL endpoint exists (`/graphql`, `/api/graphql`, `/gql`).
- Introspection not disabled (`disableIntrospection`, depth limits, WAF stripping `__schema`).

**Detect:**
1. Locate: `POST /graphql` with `{"query":"{__typename}"}` →
   `{"data":{"__typename":"Query"}}` confirms GraphQL; HTML back → try other paths/GET `?query=`.
2. Minimal introspection (template in `payloads.md` §5): `{ __schema { types { name } } }`
   → resolves = ON; `Field "__schema" is not defined` = OFF (a negative, not a finding).
3. Dump deeper: `queryType`/`mutationType` (write ops), `subscriptionType` (a separate
   WS surface), ENUM types (status/role vocab), `deprecationReason` (removed-but-present
   features).
4. If blocked, try the bypass ladder: `__type(name:"Query")`, fragment-based variants,
   the `graphql-ws` transport, GET/`?query=` form — some WAFs match POST bodies only.
   A depth-limit error on a `__schema` query still proves introspection exists (evasion: `payloads.md` §5).

**Proof of concept:**
```http
POST /<graphql-path> HTTP/1.1
Host: <TARGET.HOST>
Content-Type: application/json

{"query":"{ __schema { queryType { name } mutationType { name } types { name kind } } }"}
```
Observed: 200 with `{"data":{"__schema":{…,"types":[{"name":"User",…},{"name":"Admin",…}]}}}`.
Follow up: `{ __type(name:"User") { fields { name type { name kind } } } }`.

**Confirm:** Beyond the type list: issue one benign, read-only operation naming a
disclosed field (`{ <disclosedField> { id } }`, your own data only) — schema matching
live behavior. A schema nothing resolves against is often stale/ornamental.

**False positives:** Disabled-introspection errors (negative result); deliberately
published schemas (docs sites, demo playgrounds — check scope/ownership); gateway
returning `__typename` only; proxied third-party APIs (different owner); sample apps
(Hasura/Dgraph demo schema). And the sensitivity line: a public content API's schema
(blog posts) isn't a finding — schema matters when it exposes sensitive types, roles,
PII fields, or privileged mutations.

**Impact:** "Unauthenticated attackers obtain the complete API schema including <M>
mutations — notably `<privileged-mutation>` — converting blind fuzzing into targeted
testing of <role-bearing> operations." Medium alone; escalate with privileged mutation
names or authz-sensitive fields, and always note the schema is the *map* feeding
`bac-idor-testing`.

**Remediation:** Disable introspection in production (`NoSchemaIntrospectionCustomRule`,
`introspection: false`), gate any schema access behind auth, and rate-limit `__schema`
at the WAF while publishing docs separately if desired.

**CWE / OWASP:** CWE-200, CWE-16 — OWASP A05:2021; WSTG-INFO-08; OWASP GraphQL Cheat Sheet.

---

## [Bugbountyskills.md] V-12: API documentation leaks via public Swagger / Postman collection endpoints

**Mechanism:** Frameworks mount docs at `/swagger`, `/swagger-ui`, `/api-docs`,
`/openapi.json`, `/v2/api-docs` (Spring), `/redoc`, `/graphql/altair`; Postman
collections (with example requests carrying tokens/URLs) get pushed to Git or served
raw. Violated assumption: "docs are for our team" — public docs hand over the full
endpoint inventory, auth scheme, and often *hidden/deprecated admin routes* the UI
never links.

**Preconditions:**
- A docs artifact is reachable unauthenticated (or at low-priv — note auth level).
- The spec reflects the *live* API (stale specs are common — confirm against real endpoints).

**Detect:**
1. Probe (`payloads.md` §1): `/swagger.json`, `/openapi.json`, `/swagger-ui.html`,
   `/api-docs`, `/v2/api-docs`, `/v3/api-docs`, `/redoc`, `/rapidoc`,
   `/postman-collection.json`, `/.well-known/openapi`.
2. Validate it's a spec, not a soft-404: JSON/YAML with `openapi:`/`swagger:` keys and
   non-empty `paths` — status 200 proves nothing.
3. Mine it: `paths` (API map), `securityDefinitions` (auth type), undocumented
   `/admin/*`/`/debug/*` paths (note, don't attack yet), parameter names for
   `bac-idor-testing`, `servers[].url` (internal/staging hosts → V-04), and *example*
   values that are real tokens (grep `examples`/`default` for secret patterns → V-06).
4. Postman: fetch and grep `{{variables}}` **and** response examples; check
   `info.name`/authorship to distinguish official published docs from a leak.

**Proof of concept:**
```http
GET /openapi.json HTTP/1.1
Host: <TARGET.HOST>
```
Observed: 200, `{"openapi":"3.0.1","paths":{"/users/{id}":{…},"/admin/reset":{…}}}` —
evidence = path-list excerpt + operation count (redact any secret in examples).

**Confirm:** Two signals: (a) a spec `paths` entry answers live (issue one benign GET —
non-404 proves the spec is current), and (b) at least one *interesting* item from step 3
(admin path, leaked example credential, internal `servers`) — that's what separates a
finding from by-design public reference docs.

**False positives:** Vendor deliberately-published API docs (check their site first —
"your public API has documentation" isn't a bug); demo/sandbox subdomains; gateway
specs whose paths are all `/{proxy+}` (content-free); stale specs where nothing
resolves; third-party specs (Stripe's openapi on someone's mirror); Swagger UI *without*
a reachable spec (no leak beyond knowing the tool exists); official developer-posted
Postman collections.

**Impact:** "Unauthenticated access to the live API specification discloses <N>
endpoints including <privileged/deprecated ones> plus auth scheme details — attackers
enumerate the entire API without traffic analysis." Medium for structure alone (the map
value); high when examples contain real credentials/PII, internal `servers` are listed,
or undocumented admin mutations are exposed.

**Remediation:** Serve specs behind auth or on an internal docs host, strip real
`examples` values at build time, and keep admin/debug paths out of production entirely,
not just out of the spec.

**CWE / OWASP:** CWE-200, CWE-615 — OWASP A01/A05:2021; WSTG-INFO-08.

---

## [Bugbountyskills.md] Quick Reference - Endpoint Naming Patterns

- Versioned APIs: /v3/affsrv/, /v2/agentwebserv/, /v3/agentwebserv/
- SaaS platforms: /api/v1/, /api/v2/, /api/v3/, /graphql
- Internal APIs: /_api/, /internal/, /actuator/*, /debug/pprof/
- Microservices: /services/*, /svc/*, /k8s/*

### [Bugbountyskills.md] Phase 2 — API Endpoint Discovery

1. `gau <domain> 2>/dev/null | grep -E '/api/|/graphql|/octo|/v[0-9]/' | sort -u` — historical API endpoints
2. For Vue.js SPA portals: download JS bundles from `cdn.klook.com` and grep for `/v3/affsrv/`, `/v2/agentwebserv/`, `/api/v2/` patterns
3. Compile endpoint list from JS bundles (e.g., affiliate's `index.<hash>.js`)

### [Bugbountyskills.md] I. Information Disclosure and Hidden Endpoints

- Sensitive error messages and stack traces.
- Debug interfaces and development artifacts.
- Public source maps and source-code exposure.
- Exposed backup files and configuration files.
- Inadvertently exposed tokens, credentials, and secrets.
- Insecure exports, logs, and reports.
- API documentation and endpoint discovery.
- DNS and infrastructure information leakage.
- Cross-user and cross-tenant data exposure.

Public visibility alone does not establish a vulnerability. Evaluate sensitivity, authorization, intended exposure, and practical impact.

## [Bugbountyskills.md] Traversal in endpoint path

curl -i -s "https://target.com/api/v1/users/..;/admin" \
     -H "Authorization: Bearer <LOW_PRIV_TOKEN>"

## [Bugbountyskills.md] Spring Boot Actuator endpoints

curl -i -s "https://target.com/actuator/env"
curl -i -s "https://target.com/actuator/heapdump" -o heapdump.hprof

### [Bugbountyskills.md] Endpoints

| Endpoint | Params | Auth | Signal / sink | Tested? |
|---|---|---|---|---|

<!-- exact-duplicate entries folded in: 2 -->

### [Bugbountyskills.md] API / GraphQL

<introspection state, schema notes, versioning>

### [Bugbountyskills.md] Endpoints

| Endpoint | Params | Auth | Signal / sink | Tested? |
|---|---|---|---|---|
| `/` | — | — | 403 Akamai | yes (HEAD/GET) |
| `/robots.txt` | — | — | 404 custom AIDA page | yes |
| `/.well-known/security.txt` | — | — | 404 custom AIDA page | yes |
| `/libs/granite/core/content/login.html` | — | — | 403 (AEM path shape) | yes (status only) |
| `/systemstatus` | — | — | 403 | yes (status only) |

### [Bugbountyskills.md] API / GraphQL

`unknown` — nothing reachable past the edge.

### [Bugbountyskills.md] API / GraphQL

unknown — check /swagger, /graphql introspection

### [Bugbountyskills.md] Endpoints

| Endpoint | Params | Auth | Signal / sink | Tested? |
|---|---|---|---|---|
| `GET /` | — | **Basic 401** | Apache default 401 | ✅ 401 |
| `GET /index.html`, `/index.php`, `/phpinfo.php`, `/favicon.ico`, `/robots.txt`, `/admin`, `/checkout`, `/shop`, `/api/` | — | **Basic 401** | identical 421-byte 401 | ✅ all 401 |
| `GET /.well-known/`, `/.well-known/security.txt` | — | **403 (not 401)** | different layer — auth boundary NOT uniform | ✅ 403 / 956B |
| `GET /server-status` | — | **403** | mod_status present but denied (or generic deny) | ✅ 403 |

**Every unauthenticated path is a dead end at Apache.** No application code, no PHP,
no query parameters, no dynamic input were reachable this session.

### [Bugbountyskills.md] Endpoints (complete BFS crawl 2026-10-24 — 16 HTML + 1 PHP)

| Endpoint | Params | Auth | Signal / sink | Tested? |
|---|---|---|---|---|
| `/bgp_procedures_new_form.php` | POST: 18 reflecting fields (asn, domain, circuit, peer, address, city, state, zip, name, phone, email, brand, model, tranas, upstream, upstreamas, special, prefix) + silent (registry, app_type, ram, routes, transit) | none | reflected into quoted `value="…"` (inputs) and `<textarea>`; **entity-encoded** | yes — no XSS as of 2026-10-24 |
| `/` `/index.html` | none | none | static | query params do not reflect |
| `/bgp.html` `/general.html` `/static.html` `/bilateral_peering.html` (+regions/dampening) `/bgp_options.html` `/bgp_policy.html` `/bgp_procedures_new.html` `/bgp_procedures_new_asn.html` `/bgp_procedures_existing.html` `/bgp_procedures_existing_filters.html` `/bgp_support.html` `/swip_help.html` `/vls_tutorial.html` `/ipchange.html` `/menu.html` `/notfound.html` | none | none | static, no forms (only nav jump `<select>`); `notfound.html` is an **orphan** — not wired as ErrorDocument (real 404s = default Apache on both hosts) | yes — POST/GET ignored, no reflection; menu/notfound surfaced only by the common.txt `.html` sweep |
| `/bgp_policy.pdf` `/bilateralpeering_policy.pdf` | – | none | static PDFs | not tested (no reflection sink) |
| `/images/` | – | none | static dir, 301→listing-off | n/a |
| `/ftr-sys-theme/**` | – | none | static theme assets (jquery-3.5.1, bootstrap-3.4.1, jump.js, accordion.js) | JS reviewed: no DOM sinks fed by location/URL (jump.js uses hardcoded `<option>` values only) |
| `/themes/` (dir) | – | none | exists: bare → 301 to **http://** (scheme-downgrade quirk), `/themes/` → 403, children resolvable (404 control) | 37 theme names + common.txt sweep → nothing reachable yet |
| `/envvars/global.php` | none observed | none | executes, **200 / 0 bytes always** (silent config) | GET/POST/7 query/debug variants → empty; no backups |
| `/.config.php` | none observed | none | executes, **200 / 0 bytes always** (silent config, dotfile) | same probe matrix → empty; no backups |
| `/.gitignore` | – | none | **served 200/3954b — finding 001** | yes |
| `/server-status` | – | none | 403 with control `/server-statuz`→404 ⇒ mod_status real but restricted | no bypass attempted (info only) |
| `/.git/**` | – | none | wholesale 403 incl. nonexistent children → deny rule, existence unprovable, not clonable | yes |

### [Bugbountyskills.md] API / GraphQL

None. No swagger/openapi/graphql/robots.txt/security.txt/sitemap (all 404).

## [Bugbountyskills.md] 4. Endpoint inventory tested for the same class

- BFS crawl (both hosts): 16 HTML pages + 1 PHP; no other page contains a form
  (only the shared nav `<select>`), no inline `<script>` blocks anywhere.
- Static pages: query params AND POST bodies ignored (Apache serves bytes verbatim).
- jump.js / accordion.js: no user-controlled source→sink chains (option values hardcoded).
- ffuf: 210 custom × {dirs, .php, .html} on bgp.*; `.php` on ipadmin.*; common.txt (4751)
  × {dirs, .php} on bgp.* → only dynamic endpoint is `bgp_procedures_new_form.php`.
- Wayback CDX (both hosts): historical endpoints all dead (404), incl.
  `bgp_procedures_new_form.html`, `bilateralpeering`, `bilateralpeering_policy`.

**Conclusion: no second reflected-XSS endpoint exists on the two in-scope hosts; the
originally reported one does not reproduce.**

## [Bugbountyskills.md] Finding 002 — Internal config endpoints and directories web-accessible (silent)

**Severity:** Informational–Low (no output today; exposure of internal config surface with
no compensating auth — becomes High the day any of them emits debug/backup content)
**Endpoints (both hosts, unauthenticated):**
- GET https://bgp.frontier.com/envvars/global.php → 200, Content-Length: 0
- GET https://bgp.frontier.com/.config.php → 200, Content-Length: 0
- GET https://bgp.frontier.com/themes/ → 403 (directory exists, listing denied)
- GET https://bgp.frontier.com/envvars/ → 403 (directory exists, listing denied)

All four behave identically on `ipadmin.frontier.com`.

### [Bugbountyskills.md] Endpoints

| Endpoint | Params | Auth | Signal / sink | Tested? |
|---|---|---|---|---|
| GET / | — | none | SPA shell, 2292 B | yes (baseline) |
| GET robots.txt | — | none | blanket disallow | yes |
| GET /.well-known/security.txt | — | none | SPA fallback (soft-404) | yes |

### [Bugbountyskills.md] API / GraphQL

**161 `/api/*` routes mined from live `main.js`** (see `evidence/recon/api-endpoints.txt`).
Auth model confirmed by differential probing:
- **Public (200 unauth):** `/api/server-configurations` (leaks OpenSearch cred — F-01),
  `/api/healthz` (returns hubId/version/isEnabled/isStorageAccessible), `/api/user-ip`
  (echoes caller IP), `/api/vaults/public` returns 401 (not public despite name).
- **Auth-gated (401 empty body):** users, vaults, invitations, groups, roles, favorites,
  dashboard-widgets, messages, mfa, licenses, searches/entries, emergency-key, gateways,
  pam, lucid/*, approval/vaults, reports/siem, transaction-states, user-devices, user-tags.
- **Method-gated (405 on GET, 401 on correct POST):** `/api/searches/entries`,
  `/api/licenses/product`, `/api/vault-entries/count`.
- **No GraphQL / Swagger / OpenAPI** discovered. `/api/zzqqxx` → SPA fallback (soft-404).
- **No stack traces on malformed JSON** (401 empty, no verbose errors).
No auth-bypass found unauthenticated. Deeper testing needs an authenticated session.

### [Bugbountyskills.md] Endpoints (from JS bundle static analysis — `endpoints.json` in this dir)

| Method | Endpoint | Params | Auth | Signal / sink | Tested? |
|---|---|---|---|---|---|
| GET | `/api/proxy/products/prices` | `productCode,startDate,endDate` | none | SQLi-ish filters | ✅ 200 public |
| GET | `/api/proxy/products/prices/periods` | — | none | public | ✅ 200 |
| GET | `/api/proxy/products/datedPrices` | `startDate` | none | SQLi-ish date | ✅ 200 (108KB) |
| GET | `/api/proxy/products/getAvailabilitiesByProduct` | `startDate,endDate,productCode` | none | **`productCode` = best unauth input** | ⚠️ differential blocked by bot throttle |
| POST | `/api/proxy/products/prices/business/periods` | body + `token` | token | — | not tested |
| GET | `/api/proxy/orders` | — | **user token** | IDOR list | ✅ 401 |
| GET | `/api/proxy/orders/{id}` | — | **user token** | **IDOR object read** | ✅ 401 w/ fake id |
| GET | `/api/proxy/orders/{id}/{itemId}` | — | **user token** | **IDOR download** | not tested |
| GET | `/api/proxy/auth/me` | — | token | current-user PII | ✅ 401 |
| PATCH | `/api/proxy/auth/me` | body | token | mass-assign profile? | not tested |
| PATCH | `/api/proxy/auth/changePassword` | body | token | — | not tested |
| POST | `/api/proxy/auth/forgotPassword` | body | none | enumeration / email abuse | not tested (sends mail) |
| POST | `/api/proxy/auth/resetPassword` | body + `token` | token | token guessing | not tested |
| POST | `/api/proxy/auth/checkToken` | — | none | guest-token mint | not tested |
| GET | `/api/proxy/auth/checkMagicLink?token=` | `token` | token | magic-link oracle | not tested |
| GET | `/api/proxy/auth/sendMagicLink` (POST) | body | none | email abuse | not tested (sends mail) |
| GET | **`/api/proxy/user/checkEmail?email=`** | `email` | none | **user enumeration** | ⏳ probe queued |
| POST | **`/api/business/massAssignment`** | multipart file | ? | **file upload, NOT under `/api/proxy`** | ⏳ probe queued |
| POST | `/api/proxy/business/signup` | body | none | registration | not tested |
| GET | `/api/proxy/business/checkValidationEmailMagicLink?token=` | `token` | none | token oracle | not tested |
| POST | `/api/proxy/business/associateTicketsToCustomers` (+`Express`) | body + `token` header | token | **PII: maps tickets↔customers** | not tested |
| POST | `/api/proxy/business/desassociateTicket` | body + `token` header | token | state change | not tested |
| POST | `/api/proxy/business/payment/createOrder` | body + `token` header | token | payment | not tested — **never execute real payments** |
| POST | `/api/proxy/payment/bankTransfer` | body + `token` header | token | payment | not tested |
| POST | `/api/proxy/payment/session` | body (`excludeGuestToken`) | none/guest | mints `guestToken` | not tested |
| DELETE | `/api/proxy/payment/session?paymentRef=` | `paymentRef` | ? | state change | not tested |
| GET | `/api/proxy/payment/checkout/result` | `code,guest,language` | guest | **`guest` param = guest token in URL** | not tested |
| GET | `/api/proxy/payment/getUrl?paymentRef=` | `paymentRef` | ? | **returns URL → open-redirect candidate** | ⏳ probe queued |
| GET | `/api/proxy/payment/methods` | `id` | token | — | ✅ 401 |
| GET | `/api/proxy/business` · `/business/products` | — | token | — | ✅ 401 |
| GET | `/api/proxy/smtp/contactForm` (POST) | `customer_form{firstName,lastName,email,phone,subject,message,rgpd}`, **`email_to`** | none | **recipient field is client-supplied** → abuse | not tested (sends email) |
| GET | `/admin/orders` | `skippedGuests,skippedUsers,columnToSearch,columnToFilter,orderBy,search,status,token` | **`?token=` okta** | **admin search over customer orders → PII** | ✅ 401 w/ bad token |
| PATCH | `/admin/orders/{tx}/refund?isGuest=&token=` | — | `?token=` | **refund — destructive, DO NOT call** | not tested (destructive) |
| PATCH | `/admin/orders/{tx}/relaunch?isGuest=&token=` | — | `?token=` | re-send | not tested |
| GET | `/admin/orders/{id}/tickets?token=` | — | `?token=` | **ticket download → PII** | not tested |
| PATCH | `/admin/orders/{tx}/email?token=` | `{newEmail,isGuest}` | `?token=` | **change order email — destructive** | not tested |
| PATCH | `/admin/business/users/authorize?token=` | `{userId}` | `?token=` | **privilege grant** | not tested |
| POST | `/admin/business/users/import?token=` | `{gtsVisionId}` | `?token=` | — | not tested |
| PATCH | `/admin/business/users/modify?token=` | `{userId,gtsVisionId}` | `?token=` | — | not tested |

**Client-side sinks found (static):** 32 `dangerouslySetInnerHTML`, 9 `location.href=`,
7 `innerHTML=`, 5 `location.assign`, 1 `eval(`. App-level ones render **Prismic CMS content or
i18n strings only** (`custom_html` slice, `oembed.html`, translation lookups) → not user-reachable
without CMS write access. The `eval(` and remaining `innerHTML` are inside Adyen/React/vendor bundles.

## [Bugbountyskills.md] Endpoint

```
GET /api/proxy/user/checkEmail?email=<address>
Host: www.jardindacclimatation.fr
Accept: application/json
```

No authentication required (the route is called from the checkout/login drawer before any
session exists). Server-side input validation applies: a syntactically invalid address is
rejected with `400`, so probing is limited to well-formed addresses only.

### [Bugbountyskills.md] Endpoints (from 8,000 archived URLs — Wayback CDX, IA was offline for live fetches)

| Route | Params | Auth | Signal / sink | Tested? |
|---|---|---|---|---|
| `/{id}/{slug}-flash-cards/` | `funnelUUID` (251×) | none | public set page | ❌ challenged |
| `/{id}/view-screen` | **`redir`** (8×, value is a URL-encoded path) | ? | **open-redirect candidate** | ❌ challenged |
| `/{id}/{slug}/embed/`, `/{id}/flashcards/embed`, `…/familiarize/embedv2` | `hideLinks`, `height`, `amp;height` | ? | iframe embedding → clickjacking/XSS surface | ❌ challenged |
| `/{id}/test` | `answerTermSides`, `promptTermSides`, `questionCount`, `questionTypes`, `showImages` | ? | parameter-driven rendering | ❌ challenged |
| `/{id}/{slug}/`, `/{id}` | `setIdOrUsername` (accepts ID **or** username) | ? | **IDOR / ID-enumeration candidate** | ❌ challenged |
| `/{id}/edit`, `/{id}/delete`, `/{id}/new`, `/{id}/recreate-set`, `/{id}/autosaved`, `/{id}/scores` | — | session | state-changing → CSRF/IDOR | ❌ challenged |
| `/{id}/learn`, `/flashcards`, `/test`, `/scatter`, `/speller`, `/microscatter`, `/print`, `/export`, `/gravity`, `/match`, `/spacerace`, `/write`, `/spell` + `/starred` variants | `_pjax`, `type`, `limit` | mixed | study modes (cheating mechanics excluded by scope) | ❌ challenged |
| `/.well-known/oauth-authorization-server` | — | none | **reachable**, OAuth config | ✅ tested |
| `/.well-known/assetlinks.json`, `apple-app-site-association` | — | none | reachable | ✅ tested |
| `/.well-known/change-password` | passes query string through | none | 308 → `/forgotten/password` | ✅ tested |
| `oauth/authorize`, `oauth/token` | `code_challenge`, `redirect_uri` (S256) | OAuth | **PKCE / redirect_uri / state** | ❌ challenged (incl. POST) |
| `api.quizlet.com/3.0/…` | Bearer | OAuth | API authz / IDOR | ❌ challenged |
| `el.quizlet.com/` (POST) | JSON body | none | event ingestion, 202 `{}` | ✅ tested |
| `el.quizlet.com/status` | — | ? | hard-blocked by WAF rule | ❌ blocked |
| `jg7y.quizlet.com/{i,b4d71/tz9,com.snowplowanalytics.snowplow/tp2,rt}` | Snowplow event params | none | collector | ✅ tested |
| `study.quizlet.com/*` | — | ? | 4,751 paths → **0** non-404 | ✅ fuzzed (ffuf) |

### [Bugbountyskills.md] API / GraphQL

- `api.quizlet.com/3.0` in scope; `2.0` out of scope. `/graphql`, `/api`, `/v1`, `/v2` on `study.*` all 404 — no GraphQL endpoint found on reachable hosts. Introspection **untested** (host challenged).

### [Bugbountyskills.md] Endpoints

| Endpoint | Params | Auth | Signal / sink | Tested? |
|---|---|---|---|---|
| `/` | — | none | marketing SPA/SSR page, GTM + GA preload w/ nonce | recon only |
| `/users/sign_in`, `/users/sign_up` | authenticity_token | none | Devise auth flow; POST = session state change ⇒ CSRF class | pending |
| `/help`, `/help/vulnerability-bug-bounty-program` | — | none | help center (scope intel source) | read (scope gate) |
| `/rest-api-documentation` | — | ? | **REST API docs ⇒ full endpoint inventory** | pending |
| `/.well-known/security.txt` | — | none | app 404 (no security.txt published) | 404 |
| `/robots.txt` | — | none | **nginx 404** (static-served) | 404 |

### [Bugbountyskills.md] API / GraphQL

Unknown — `/rest-api-documentation` not yet fetched. No GraphQL seen yet.

### [Bugbountyskills.md] API / GraphQL

unknown

### [Bugbountyskills.md] Endpoints & params (pre-auth)

| Endpoint | Params | Signal | Tested? |
|---|---|---|---|
| `/` | `utm_source`, `next` | reflected (URL-encoded) into signup `ref_url` href + RSC payload | ✅ 2026-10-21 |
| `/catalog` | `zz9x` (test), `page`, `price_from`, `brand_id[]` | reflected into `<link canonical>`, hreflang, nav/pagination hrefs; typed filters | ✅ 2026-10-21 |
| `/member/signup/select_type` | `ref_url` | consumes `next`/return path — **open-redirect chain candidate (auth-required)** | ❌ next |
| `/member/`, `/inbox`, `/checkout`, `/util`, `/admin_alert/new` | — | robots-disallowed; auth-gated areas | ❌ next |
| `/sitemaps/us/*.xml` | pages, help, brands, catalogs, items, fresh-items | discovery index (items.xml = listing IDs) | partially |
| `/.well-known/security.txt` | — | `security@vinted.com`; expires 2026-11-04 | ✅ |

### [Bugbountyskills.md] 17.28 GraphQL write mutation resolves public handle → private email in the RESPONSE, before consent (HackerOne SaveCollaboratorsMutation)

SOURCE: https://hackerone.com/reports/2032716 — HackerOne `SaveCollaboratorsMutation` (High, CVSS 8.3, $12,500)  read 2026-11-07
CLASS: sensitive information disclosure / missing field-level authorization on a mutation response
CORE METHOD:
  1. Invite an arbitrary user handle to a report you own; leave the invite PENDING (never accepted) — 2 invites max per report in this case.
  2. Intercept the invite-editor request: `POST /graphql` `operationName: SaveCollaboratorsMutation`, `variables.input = {report_id, collaborators:[{username_or_email:"<handle>"}]}`.
  3. The RESPONSE resolves the handle and returns the user's private email although the invite was never accepted — repeat per handle for platform-wide PII.
DETECTION SIGNAL: mutation input takes a public identifier (username/handle/slug/phone/id) while the response or `errors.message` resolves a private field (email/phone/name/address); PENDING invite/member objects already carrying invitee data; write mutations returning the full object graph with no field-level authz.
CHAIN: any authenticated user with one record → invite arbitrary handle → response resolves handle → private email of a non-consenting user at scale → phishing / reset+2FA social engineering ($12,500).
TRANSFERABLE TEST: For every handle-accepting feature (invite/share/add-member/follow/transfer/@-resolve) read the raw RESPONSE and ERRORS, not the UI; send a target you do not control, then batch handles and foreign object ids and look for other users' data echoed back before consent.

NOTE — read pass 2026-11-07 (honesty record): https://hackerone.com/reports/1328546 (TikTok intelbot, Critical, $15,000) is NOT publicly readable (`.json` returns empty `vulnerability_information`; mirror says "No vulnerability information available") and its one-sentence program summary teaches no concrete method → INVALID, nothing recorded. https://hackerone.com/reports/911606 (Snapchat JFrog creds on GitHub, $15,000) is likewise summary-only, and its method is already covered by §9.5 (GitHub dorking) + §17.8 (Artifactory) → valid but no duplicate appended.

### [Bugbountyskills.md] 17.87 One-time-benefit CLAIM endpoint is not idempotent and does not burn the offer id — replay stacks the benefit without limit (Stripe #1849626)

SOURCE: https://hackerone.com/reports/1849626 — Stripe, "Fee discounts can be redeemed many times, resulting in unlimited fee-free transactions" (Business Logic Errors; reporter ian; disclosed 2023-02-25; 230 votes; bounty yes)  read 2026-11-07 (full body 1,230 B from the local disclosed-reports dataset)
CLASS: business-logic error — no idempotency / no offer-burn on a one-time benefit claim · CWE-837 / CWE-799
CORE METHOD:
  1. Entry point: `POST /ajax/accept_fee_discount_offer` — the dashboard "accept the fee-discount offer" action (offer $20,000).
  2. A race was not even required: calling the endpoint 30 times applied 30 discounts, i.e. $600,000 of fee-free processing.
  3. The only requirement is a valid `fdo_` (fee-discount-offer) id; the endpoint can be called indefinitely. Each $20k discount abused costs the provider ~3% (~$600).
DETECTION SIGNAL: any claim/accept/redeem/apply/activate endpoint for a ONE-TIME benefit (discount, credit, coupon, trial, quota, top-up, invite, refund); the effect ADDS to a counter/balance instead of being idempotent; a one-time OFFER id that is not consumed/burned after first use; no idempotency key, no per-claim nonce.
CHAIN: one legitimately offered benefit id -> the claim endpoint is replayable -> the discount/credit stacks without limit -> direct monetary loss at scale.
TRANSFERABLE TEST: capture the accept/claim request for any one-time benefit and REPLAY it N times (sequentially, then a concurrent single-packet burst); read the account balance/discount/credit after each call — growth per call = non-idempotent claim + unburned offer id; quantify the monetary impact by the stacked amount.

NOTE — read pass 2026-11-07 (batch 19; §17.85–17.87 appended from 6 sources read; #470380 is `no-content`/unreachable — NOT invented). Bodies: #1930763, #1213237, #1849626, #426944 from the LOCAL disclosed-reports dataset mirrors (`/tmp/h1_train|test.parquet`, read with `/usr/bin/python3.12`); #1551176 is `visibility: no-content` (0 B) but its Reddit team summary + full PoC rendered via `r.jina.ai`; #470380 (Mail.ru, "Cross application scripting via account.mail.ru", Stored XSS, High 8.8, $5,000) is `visibility: no-content` AND Cloudflare-walled (`web_extract` SPA shell, `r.jina.ai` 403, browser bot-check, Wayback empty) -> class + title alone is below the entry bar -> no entry, NOT invented. §17.85 is a NEW general method (validation/sanitisation enforced on ONE render path — publish — while a SUBORDINATE path — draft/scheduled/preview/edit — re-uses the raw stored value) — distinct from the existing `javascript:` sinks (desktop chat §17.58, post-login redirect §17.83) and from the mXSS/DOMPurify differential playbook in §1. §17.86 is a NEW general method (a setuid-root binary resolving a helper by a BARE name through untrusted `$PATH`) — the only prior `setuid` mention is an escalation hint inside the upload->shell-job command-injection variant, not a local-LPE method → this is the read-/shell-side sibling of the existing flag-injection / PATH-shadowing material. §17.87 is a NEW general method (a one-time-benefit CLAIM endpoint with NO idempotency and an unburned offer id — the INVERSE of the race/double-spend tests already recorded, which treat an idempotent replay as a FALSE POSITIVE). #1213237 (RedditGifts IDOR DELETE, missing object-ownership check) and #1551176 (Reddit ads mass-assignment `email` that is implicitly marked verified then trusted by the invite-accept flow) are recorded in the harvest ledger `/root/bugbountyhuntingskills.md` and the dated knowledge file but got NO §17 slot — IDOR/BOLA is already covered (V-01/V-05/BOLA playbooks) and mass assignment is already covered (V-04 "Internal variable overwriting via mass assignment", §17.19/§17.37); only #1551176's twist (the mass-assigned email being also implicitly verified and trusted downstream) is new and is noted here. Full per-source route/honesty records are in the harvest ledger and `/root/hackbot-architecture/knowledge/methodologies-2026-11-07.md`.

### [Bugbountyskills.md] 17.124 An UNAUTHENTICATED federation/OCM `notifications` endpoint that trusts a `sharedSecret` the attacker already holds → `RESHARE_CHANGE_PERMISSION` rewrites a read-only federated share / public link to read+write+share (Nextcloud, HackerOne #1170024)

CLASS/METHOD: Nextcloud's OCM notification endpoint `index.php/ocm/notifications` processes a JSON notification with no authentication. An attacker creates and accepts a federated share to their OWN instance, reads the `remote id` + `token` from their own `oc_share_external` row (a secret they legitimately hold), then POSTs `{"notificationType":"RESHARE_CHANGE_PERMISSION","resourceType":"file","providerId":<remote id>,"notification":{"sharedSecret":"<token>","permission":["read","write","share"]}}` to the VICTIM server. The server authenticates the message by the `sharedSecret` alone and rewrites the share's permission set — the read-only share becomes writable. It works for any federated share the attacker holds, not just public links.
DETECTION SIGNAL: a federation/OCM route (`/ocm/notifications`, `/ocm/shares`, WebFinger/OCM-discovered) reachable UNAUTHENTICATED that accepts a `sharedSecret`/token payload as sufficient to MUTATE share state; a permission-change notification type (`RESHARE_CHANGE_PERMISSION`) handled without re-checking who may change permissions; share secrets retrievable from the attacker's own federation table/API.
CHAIN: attacker holds a legitimately-issued federated-share secret (primitive) → unauthenticated OCM permission-rewrite notification (primitive) → read-only share escalated to WRITE → attacker overwrites/adds files in any federated share or public link → integrity compromise across all federated/public shares (High).
TRANSFERABLE TEST: create a READ-ONLY federated share to your own instance, read the share secret, POST a permission-change notification with `sharedSecret`=that token and `permission:["read","write","share"]` to the victim's `/ocm/notifications`; if the share becomes writable, the endpoint authenticates the message with a token the attacker already owns.
WHY IT IS A NEW GENERAL METHOD: the file's federation content is SAML/`federated app` assertion-wrapping (auth bypass by forged assertion). §17.124 is its first OCM/SHARE-PERMISSION-REWRITE primitive — an unauthenticated "notify" endpoint where a context secret the attacker already owns is the sole authorisation for a privilege change, and it escalates a legitimate low-privilege share rather than forging an identity.

### [Bugbountyskills.md] 17.199 A checkout accepts a CLIENT-SUPPLIED PAYMENT INSTRUMENT with no ownership binding — the selection endpoint hands out other users' `wallet_id`s (with their owner ids) and the capture endpoint charges the instrument the request names (Zomato Gold, HackerOne #938021)

SOURCE: https://hackerone.com/reports/938021 — Eternal (Zomato), "Availing Zomato gold by using a random third-party `wallet_id`" (Business Logic Errors; **Critical — CVSS 9.3**, scope CHANGED, C low / I high; $2,000; 116 votes; reporter `pandaaaa`; submitted 2020-07-23, disclosed 2020-08-07, asset `*.zomato.com` max_severity critical)  read 2026-11-08. The report BODY is `visibility: "no-content"` (live `.json` -> HTTP 200, 9,498 B, `vulnerability_information` 0 B; HF split `hf_test.parquet` row 938021 also `no-content`); the request shapes and the root cause below are the report's PUBLIC PROGRAM SUMMARY, read this pass from the mirror `raw.githubusercontent.com/ajaysenr/HackerOne-Disclosed-Reports/main/reports/938021.md` (HTTP 200, 5,689 B).
CLASS: business-logic / broken access control on a PAYMENT INSTRUMENT (funding source) — object ownership is never checked, so one user's purchase is charged to another user's wallet.
CORE METHOD: Gold membership on `https://www.zomato.com/php/pk_handler.php` is an ordered sequence. (1) Selection call `case=getpaymentsdataphone=XXXXXXXcart_value=999.00service_type=REDonline_payments_flag=1country_id=X` returns "all the payment methods available and the last payment method used for a user" — every third-party wallet object carries its OWNER's ids: `"wallet_id": 8XXXXXXX3, "balance": 0.01, "user_id": "14XXXXX2", "entity_id": "14XXXX2", "status": "active", "vault": "paytm", "storage_state": "retained", "wallet_type": "third_party_wallet", "display_text": "Paytm", "recharge_available": 1` (only `third_party_wallet` + `status: active` matter). (2) Capture call on `https://www.zomato.com/php/red/desktop_payments_handler.php`: `payment_method_id=8XXXXXX1payment_method_type=walletphone=XXXXXXXXXXXXXXXXXcartValue=999.00voucher_code=action=paymentis_renewal=0user_id=1XXXXX2tnc_accepted=false` -> `{"status":"success","track_id":"ZRD-…","response_message":"Capture Successful","amount":999,"text":"You are now a Zomato Gold member","redirect_url":"https://www.zomato.com/gold/payment-success?…"}`. (3) Root cause, verbatim: "There was no check while performing the transaction to validate if the `wallet id` actually belonged to the user who initiated the call"; the flow had appeared with "a recent code change that went live 13 hours ago". Impact as the vendor rated it: "It was considered critical since a random user's wallet could have been used for unauthorized membership purchases. This was only possible on third party wallets with `status - active` flag."
DETECTION SIGNAL: a checkout whose FUNDING INSTRUMENT is a client-supplied identifier (`payment_method_id`, `wallet_id`, `card_id`, `instrument_id`, `source`, `payment_source_id`) and is not derived from the session; a selection/intent endpoint that RETURNS other users' instruments with their `user_id`/`entity_id` (the ids are visibly decoupled, so the response alone proves they are not scoped); a capture request sending `payment_method_id` and `user_id` as two independent fields; instrument listings including `status: active` third-party vaults you do not own.
CHAIN: any user (no privilege, no user interaction) -> the selection endpoint discloses other users' `wallet_id`s together with their owner ids (primitive: unauthorised read of instruments) -> the capture call accepts `payment_method_id:<victim wallet>` for the attacker's own purchase (primitive: instrument not bound to the session) -> the membership activates on the attacker's account while the victim's wallet is debited (primitive: cross-user debit) -> repeatable across enumerable instrument ids = a random user's wallet drained into memberships (Critical 9.3, scope CHANGED). The vendor's own abuse check found only the two test transactions, and the fix landed within 2h17m.
TRANSFERABLE TEST: (1) hit the payment-method SELECTION call and grep the response for instrument ids whose `user_id`/`entity_id` is not yours — that is the primitive; (2) replay the CAPTURE call with your own instrument id as the control, then another user's, keeping amount/`user_id`/phone exactly as your own request; (3) confirm the debit on the sibling account and vary the instrument id ±1 to show enumerability. Rule: **a payment instrument is an object like any other — load it THROUGH the session (`where(user_id: current_user)`) before charging it; listing instruments for the UI and accepting an instrument id at checkout are two separate authorization decisions and usually only one of them is implemented.**
WHY IT IS A NEW GENERAL METHOD: the recorded billing entry (harvest ledger ~3048/3055) has the TARGET account/recipient as the client-supplied parameter — the attacker PAYS and the victim's account is mutated, escalating through a recovery field; here the attacker pays NOTHING and the missing binding is on the FUNDING SOURCE, so the entry point is the instrument id at capture and the impact is a cross-user debit. Reusable rule: **instrument id at capture is an authorization boundary — the selection response that leaks owner ids marks the whole flow as unbound, and one instrument id is a monetary write on someone else's balance.** Slot 17.199. UNVERIFIED (not reproduced) — no Zomato purchase was made this pass.

### [Bugbountyskills.md] 17.200 In a two-step money flow the capture endpoint re-reads the AMOUNT from the client instead of from the stored order — pay an arbitrary amount, receive the full ordered credit (Zomato wallet top-up, HackerOne #1408782)

SOURCE: https://hackerone.com/reports/1408782 — Eternal, "Add upto 10K rupees to a wallet by paying an arbitrary amount" (Business Logic Errors; **High — CVSS 7.5**, AV network / AC low / PR none / UI none / C none / I high; $2,000; 132 votes; reporter `ashoka_rao`; submitted 2021-11-24, disclosed 2022-02-23, asset `com.application.zomato` max_severity critical)  read 2026-11-08. Report BODY is `visibility: "no-content"` (live `.json` -> HTTP 200, 8,167 B, `vulnerability_information` 0 B; HF split `hf_train.parquet` row 1408782 also `no-content`); both requests and the quoted analysis are from the report's PUBLIC PROGRAM SUMMARY via the mirror `raw.githubusercontent.com/ajaysenr/HackerOne-Disclosed-Reports/main/reports/1408782.md` (HTTP 200, 2,789 B).
CLASS: business-logic — VALUE BINDING between a stored order and its payment capture is missing (the value PAID and the value CREDITED are independent; the order id is the only link).
CORE METHOD: (1) create the order: `POST /gw/payments/zomato_money/order` body `{"country_id":"1","service_type":"ZM_RECHARGE","cart":"null","amount":"1000.0"}` -> `{"order_id": "XXXX"}`. (2) capture: `POST /v2/sdk/make_payment` body `amount=XX&order_id=XXX&order_type=ZM_RECHARGE`, sending an ARBITRARY amount. Verbatim: "The amount requested to generate the `order_id - XXXX` was `1000` but while paying one could have passed an arbitrary amount instead of `1000` against the `order_id`, which was not cross-checked." Outcome, verbatim: "still get the entire amount defined in order added to your wallet (limited to 10K INR)". Scope caveat: "Other Payment methods and consumers including online ordering were not vulnerable to this." The vendor's timeline shows the fix deployed the same day (14:47 IST), severity set to High 7.5 (14:48) and a full bounty plus bonus awarded (23:15).
DETECTION SIGNAL: a two-step create-order -> capture pair where the SECOND request restates the value (`amount`, `price`, `value`, `total`, `currency`, `quantity`) while the create response's only binding token is an id (`order_id`, `payment_intent`, `intent_id`, `reference`); the tell is that the capture route accepts a NARROWER body than the create route (here a single scalar `amount=`), i.e. the thinner, cheaper-looking endpoint is where the binding was dropped; an order-type/service-type field (`order_type=ZM_RECHARGE`) selecting the credit branch without re-checking the value; a per-transaction ceiling in the code (10K INR) proving the developer considered abuse of VALUE but not binding.
CHAIN: attacker runs the ordinary top-up flow and creates an order for the amount they want credited (normal endpoint, primitive) -> the capture call takes the paid amount as an independent client parameter (primitive: no cross-check between the stored order value and the paid value) -> the full ordered amount is credited for an arbitrary smaller payment (primitive: monetisable difference) -> wallet balance inflated per order up to the 10K INR ceiling, repeatable = direct monetary loss (High 7.5, integrity-only per the CVSS vector). Doctrine §4 "price/balance -> monetary loss at scale".
TRANSFERABLE TEST: take any order/intent-create call, note the value V it stores, then replay ONLY the capture/confirm call with (a) `amount=1` (or `0.01`), (b) `amount` omitted, (c) a different `currency`, (d) a duplicated `amount` parameter — all against the SAME order id — and check what the account/app receives. Rule: **in a two-step money flow the value must be READ BACK from the stored order at capture; if the second request can restate the amount, the only question left is which copy the server believes.**
WHY IT IS A NEW GENERAL METHOD: the file's payment material is a signature-canonicalization flaw (delimiter-less HMAC concatenation -> in-flight parameter smuggling, harvest ledger ~3118), §17.89 (server-owned review/lifecycle STATE fields writable through an object PATCH -> skip a payment gate) and the one-time-benefit REPLAY entry (~3625, non-idempotent claim). None records the missing READ-BACK between an order and its capture, where every value in the flow is legitimate on its own and only the linkage is absent. Reusable rule: **order state is the source of truth for money — any amount appearing again in the capture request is an attacker-controlled field until proven otherwise.** Slot 17.200. UNVERIFIED (not reproduced) — the Zomato wallet flow was not exercised this pass.

## [Bugbountyskills.md] §17.276 (mirror) — Hasura anonymous-role introspection = permission map; 0-row write-grant probing (VERIFIED live 2026-11-08, subspace.money db.subspace.money/v1/graphql; Hasura EE v2.51.0)

SOURCE: own hunt, live target — `https://db.subspace.money/v1/graphql` (Hasura GraphQL Engine, Enterprise Edition v2.51.0), in-scope program asset "Subspace hasura graphql api". Read 2026-11-08.
STATUS: VERIFIED (live, reproduced twice; request/response transcript in /root/.hermes/cache/scratch/subspace/transcript.txt and /root/hackbot-architecture/state/recon/subspace/).

CLASS: missing authentication / missing authorization on a GraphQL data layer (CWE-306/862/200) → unauth bulk data exposure + anonymous write grants. Reportable as HIGH/CRITICAL under SEVERITY_DOCTRINE §1 (sensitive disclosure with PoC + misconfig with demonstrated impact), NOT as a chain primitive.

THE MECHANISM: a Hasura endpoint answers every request that carries no `Authorization` header and no
`x-hasura-*` role header as its **anonymous** role. Crucially, **Hasura filters introspection by role
permissions**, so an unauthenticated introspection dump is not "just the schema" — it is the exact list
of tables, columns, filters and mutations that anonymous may use. Entries that appear = grant exists;
entries the role lacks come back as a validation error, which is your built-in negative control.

ENTRY POINT: any path serving Hasura (`/v1/graphql` is the default; the API may be mounted under a
prefix or a custom path). Fingerprint with `GET /v1/version` → `{"server_type":"ee","version":"v2.51.0"}`
(excluded as version disclosure on its own — use it only to confirm Hasura and its EE/CE edition).

TEST SEQUENCE (all read-only; ~6 requests total, no guessing):
1. `POST <url> {"query":"{ __schema { queryType { name } mutationType { name } } }"}` (browser User-Agent,
   `Content-Type: application/json`, no auth header). `{"data":{"__schema":{"queryType":{"name":"query_root"},...}}}` ⇒ the anonymous role is open.
2. Full introspection: dump `queryType.fields`, `mutationType.fields`, and the `OBJECT`/`INPUT_OBJECT`
   types. Read `*_insert_input` / `*_set_input`: **Hasura filters those input objects to the columns the
   role may write**, so they tell you exactly what an attacker could set. On subspace that showed
   `insert_superpay_payment_requests` exposing `upi_id, phone, service_id, product_ids, data` (a payment
   table writable by anonymous, with an attacker-controllable UPI ID).
3. Read real rows unauthenticated: `query { <table>(limit: 2) { <cols> } }`. Quantify with
   `<table>_aggregate { aggregate { count } }` where the role has the aggregate grant; where it does not,
   use `limit`+`offset` probes (a row returned at `offset: N` proves N+1 rows) — never page a table to
   exhaustion. Measured on subspace: 44,797 order items (exact aggregate), ≥5,001 orders incl.
   `status: delivered`, ≥5,001 rows of live visitor IP/UA/referer, ≥3,003 user-linked search queries,
   977 user full names + subscription prices, 277 WebAuthn device ids, 20 payment requests, staff e-mails.
4. PROVE WRITE GRANTS WITHOUT MUTATING ANYTHING (the key move): `mutation { insert_x(objects: []) { affected_rows } }`
   → `{"affected_rows":0}` means the INSERT grant exists (0 objects ⇒ 0 rows written). Because Hasura
   drops an ungranted mutation from the role's schema, the control is a validation error
   (`field 'insert_x' not found in type: 'mutation_root'`) — the same error shape you can observe on a
   table the role really cannot touch, which makes this a clean differential. For UPDATE/DELETE use
   `where: {id: {_eq: "00000000-0000-0000-0000-000000000000"}}` (impossible predicate ⇒ 0 rows).
   On subspace this proved anonymous INSERT on a payment table, UPDATE of `passkey_authenticators.device_id`
   (passkey credential rebinding!) and DELETE on a content table — all without writing a single row.
   **Never insert a real row to demonstrate a write grant.**
5. Admin surface differential: `/v1/metadata`, `/v1/query`, `/v2/query`, `/v1alpha1/pg_dump`, `/apis/rest`
   → 404 means closed; `/console` → 200 means the admin UI is exposed (still gated by the admin secret —
   try the default `hasura` ONCE, it was correctly refused on subspace). A 200 on `/console` is context,
   not a finding.
6. Actions/functions reachable by the anonymous role deserve their own probe because their **declared
   output type** is a schema-level statement about what they can return: on subspace `purchaseTest` was
   callable with no auth and its output type is `{ amount, cardNumber, cardPin, orderId, validity }`
   while its input takes a **caller-supplied `user_id`** — reported as a LEAD (unverified) because
   proving it would create a real order. Same rule for `authMintSession(client, refresh_token, user_id)`
   / `authRefreshToken(refresh_token, user_id)` / `refreshToken(request: {refresh_token, user_id})`:
   a caller-supplied identity next to a refresh token is an ATO-by-id-swap hypothesis, report it as a
   LEAD until reproduced, never as a finding.

TRAFFIC NOTE: Cloudflare fronts these endpoints. A bare `python-urllib` User-Agent got HTTP 403 on the
same URL in the same minute that `curl` with a normal desktop browser UA got HTTP 200 — so a 403 from a
scripted client is NOT evidence of a WAF block on the target. Set a browser UA before concluding anything
about reachability; conversely, when a 403 persists with a real browser UA, treat it as WAF and switch to
artifact-driven work.

IMPACT SHAPE (reusable): the finding is not "introspection is on" (that is excluded as version/
config disclosure on its own). It is: **anonymous holds select AND write grants over production data**,
which is simultaneously a mass personal-data breach (GDPR/DPDP-reportable: IP + user ids + names +
purchase prices in one unauth query), a targeting source for ATO (user ids, passkey device ids, staff
e-mails) and an integrity issue (anonymous INSERT into payment tables). Score it as one finding with
C:H/I:H — e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1 — rather than splitting read and
write into two reports that share the same root cause.

REMEDIATION SHAPE (what to tell the program): treat the `anonymous` role as a public allow-list, not as
"left at defaults" — re-grant only the explicitly public catalogue tables column-by-column, delete every
anonymous insert/update/delete grant, put the private API behind Hasura JWT mode
(`HASURA_GRAPHQL_JWT_SECRET`), and disable introspection for non-admin roles
(`HASURA_GRAPHQL_ENABLE_INTROSPECTION=false` or per-role filtering).

DEDUPE: no prior §17 entry covers Hasura role-permission enumeration with 0-row write-grant probing
(greps on `hasura`, `anonymous role`, `objects: []`, `affected_rows`, `_insert_input` before append).

### [Bugbountyskills.md] 17.299 Unauthenticated record DELETION via a REST delete-by-id endpoint — the per-ENTITY permission oracle (403 vs "Not found") proves the guest role holds delete grants on most entities (Magentrix Cloud / Opirus, bugbounty.magentrixcloud.com, 2026-11-09)

SOURCE: first-hand, reproduced live against the program's own test tenant on 2026-11-09 (engagement: on-demand hunt for Kr Hasan). No public writeup — this is a direct finding.
STATUS: VERIFIED (reproduced end-to-end; the state change was observed before and after, with a negative control).

CLASS: broken access control / missing authentication for a critical function (CWE-306 + CWE-862) — unauthenticated destructive action.

CORE METHOD:
  1. FIND THE DELETE-BY-ID ROUTE. `POST /rest/2.0/delete/{id}` takes ONLY an id — no entity, no body
     needed. The entity is inferred from the record id's KEY PREFIX (Salesforce-style: `004` = Case,
     `7NT` = User, `00C` = Course, `7Ot` = Document, `7Oc` = SecuritySetting, `001` = Account,
     `006` = Contact, `7NU` = Role, `00l` = BlogPost, `027` = WikiPage, `01u` = PublicEvent).
  2. THE PER-ENTITY PERMISSION ORACLE. Send the delete for a NON-EXISTENT id under each prefix.
     - `403 "Permission Denied"`  -> the entity-level check EXISTS and denies the caller.
     - `200 {"Id":"Not found","HasError":true}` -> the caller was let INTO the delete path; only the
       record lookup failed. The missing check is the defect.
     This oracle is SAFE (no record exists, so nothing is destroyed) and it enumerates exactly which
     entities the unauthenticated role may delete.
  3. PROVE THE STATE CHANGE, NOT A NO-OP. Pick a record the anonymous role can already READ
     (`GET /api/3.0/entity/{Type}` on the public entity list), delete it, then re-read it two ways:
     the live query (`/api/3.0/query`) must drop it and the including-deleted query
     (`/api/3.0/queryall`) must show `IsDeleted: true`. A soft delete still counts — it is a real
     integrity change and it is recoverable by an admin.
  4. THE NEGATIVE CONTROL IS MANDATORY. Deleting a non-existent id must return
     `HasError: true, Id: "Not found"`. That contrast is what proves step 3 was a genuine delete
     rather than an endpoint that returns `HasError: false` for everything.

DETECTION SIGNAL: a REST route of the shape `/rest/<ver>/delete/{id}` (or `/entity/{Type}/{id}` with
DELETE) whose authorization is decided by the record's entity rather than by the caller's session.
COMPANION TELL: the same API family exposes a public entity list and an anonymous entity read
(`/api/3.0/entity`, `/api/3.0/entity/{Type}`) — those reads hand the attacker BOTH the record ids and
the field values, so a delete-by-id route is directly reachable with ids the app itself disclosed.

CHAIN: anonymous read of the public entity list and its records (primitive: discloses ids + content)
-> the delete-by-id route has no session check for most entities, proven by the 403-vs-"Not found"
oracle (primitive: function-level authorization absent on a destructive action) -> unauthenticated
soft-delete of a real record (impact: integrity/availability — content and configuration records
destroyable at scale by any visitor, including User, Course, Document and SecuritySetting whose
prefixes the oracle shows are reachable).

TRANSFERABLE TEST: on any REST API with a delete-by-id route, fire the delete for a non-existent id
under each entity's key prefix and sort the answers into `403` vs `200 "Not found"`. Every prefix that
answers "Not found" is an entity the caller may delete; then confirm with ONE real record from an
entity the anonymous role can read, and prove it with a live-vs-including-deleted query pair plus the
non-existent-id control. Rule: **never infer "it deleted" from a 200 — read the record back both with
and without the deleted filter, and always run the non-existent-id control.**

DEDUPE: 0 hits in either ledger for `delete/by-id` + `permission oracle`, `403 vs Not found`,
`unauthenticated delete`, `Magentrix`, `Opirus`. Related-but-different recorded material reviewed and
NOT re-recorded: the ledger's CSRF entries cover state-changing GETs on an AUTHENTICATED session
(victim click) — this is the absence of any session at all; the ledger's IDOR entries cover READS of
other tenants' objects — this is a destructive WRITE/DELETE; the "missing function-level authorization"
GraphQL entries concern VALUE-typed mutations with no object id, whereas here the object id is the only
input and the defect is a per-entity check that is present for some entities and absent for others.
New general method -> §17.299.

### [Bugbountyskills.md] 17.419 A ROLE PERSISTED AT INVITE TIME MUST BE RE-VALIDATED AT ACCEPTANCE — POST THE HIGHEST ROLE TO THE INVITE ENDPOINT AND CHECK WHETHER THE ALLOWLIST IS ENFORCED SERVER-SIDE (HackerOne WordPress #3942522, "wordpress.org Rosetta: invite stores unvalidated role — Editor can assign site Administrator despite editable_roles", disclosed 2026-08-15; High; UNVERIFIED — not reproduced). THE DEFECT, verbatim: "on `admin_action_adduser` it persists the invite option with `role` taken directly from `$_REQUEST['role']` before consulting `get_editable_roles()`." THE ACCEPTANCE, verbatim: "Core's `/newbloguser/{key}/` path then applies the stored role via `add_existing_user_to_blog()` → `set_role()` with no `wp_ensure_editable_role()` re-check." THE EXPLOIT, verbatim: "An Editor can therefore POST `role=administrator` (not offered in the UI dropdown), create a valid invite, and elevate an account to site Administrator (`manage_options` on that blog)." DETECTION SIGNAL: an invite/member-add endpoint accepting a `role` param; a role allowlist enforced in the UI/`editable_roles` but not re-checked at persistence or acceptance; a two-step invite->accept flow. TRANSFERABLE TEST: capture the invite request, add/replace `role` with the highest role, submit, accept (or have a second account accept) and check the granted role; also test a pending invite whose inviter is later removed. Rule: **a role persisted at invite time must be re-validated at acceptance — POST the highest role to the invite endpoint and check whether the allowlist is enforced server-side.**

### [Bugbountyskills.md] 17.465 A SEAT LIMIT ENFORCED ONLY WHEN THE INVITATION IS CREATED IS NOT A LIMIT — A PENDING INVITATION IS A PRE-AUTHORISED SEAT, SO SIGN UP EVERY INVITED ADDRESS AND THE PER-TENANT CAP IS BYPASSED (Dust, HackerOne #3102890, "User Limit Bypass via Pending Invitations in Workspace System", weakness Business Logic Errors, severity medium, reporter `kbrx` (verified), submitted 2025-04-21 / disclosed 2025-04-29, resolved, asset dust.tt, bounty no; `visibility: full`, body read in full this pass on the live `.json` route; UNVERIFIED — not reproduced). THE LIMIT, verbatim: "The platform enforces a limit of 3 users per workspace for low tier accounts unless you have higher subscription." THE BYPASS, verbatim: "However, this limit can be bypassed by inviting additional users ahead of time. As long as a user has a pending invitation, they are able to join the workspace simply by signing up and verifying their email — even if the workspace has already reached its user limit." THE STEPS, verbatim: "Create a workspace under a normal tier account. (i used Free Security Researchers account) / invite 3 users or any number you want / now go sign up with one of the users you invited and now you're in / then go back to your account and try to invite more, the website will tell you that the workspace reached its limit, you have to upgrade your subscription, however this is broken / go sign up with another email you invited, you will see that you joined the workspace." THE SCALE, verbatim: "now i can invite 100 users and they can join easily because the limitation is broken, and btw to have 100 users in your workspace you need enterprise plan, this is a huge loss to the company". THE EXPECTED BEHAVIOUR, verbatim: "Once a workspace reaches the 3-user limit, no additional users should be allowed to join — even if they were previously invited. unless the admin get a higher subscription like the website said". DETECTION SIGNAL: any SaaS with a per-tenant seat/user/member COUNT limit enforced at INVITE time; an invitation object that is a PRE-AUTHORISED seat (the invitee only signs up and verifies an e-mail to occupy it); a join/accept path that checks "is there a pending invite for this e-mail?" but never re-checks the CURRENT member count; a workspace at its cap whose UI still shows the invite control (or whose invite API still accepts); a plan/tier page stating the seat cap. TELL: the cap is enforced on the WRITE that creates the invitation, and the ACCEPT path that consumes it does not consult the counter. TRANSFERABLE TEST: on ANY tiered SaaS with a seat/user/member cap — (1) create the lowest tier and read the documented cap; (2) invite users until the UI/API refuses and reports the cap; (3) now sign up with an address that ALREADY has a pending invite (or accept a pending invite from the invitee side) — if the account lands in the workspace despite the cap, the cap is invite-time-only; (4) repeat for every pending invite to show the bypass scales; (5) also test the reverse order (join first, then hit the cap) and the re-invite path after a member leaves. Rule: **a seat limit enforced only when the invitation is CREATED is not a limit — a pending invitation is a pre-authorised seat, so sign up every invited address and the cap is bypassed for all of them.** WHY IT IS A NEW GENERAL METHOD: 0 hits across all three write targets for `3102890`, `kbrx`, or a pending-invitation seat-cap bypass. The recorded invite material is a DIFFERENT defect each time — §17.322 (Omise #3303136, a role-bearing invite not invalidated when the inviter is removed: an orphaned-grant bug, not a seat-cap bug), §17.419 (WordPress #3942522, an unvalidated ROLE persisted at invite time), the invite-acceptance endpoint that trusts a client-supplied invite id, and the invite-flow identifier/PII-disclosure entries — plus the generic V-14 "client-side gate" / UI-only-restriction family. The nearest recorded item is the Dust folder-limit RACE (#3104355, declined as duplicate of V-03): that is a CONCURRENT check-then-act race on a counter, whereas this is a SEQUENTIAL re-check that never happens at join time — no race, no concurrency, no timing. Slot 17.465. UNVERIFIED (not reproduced).

### [Bugbountyskills.md] §17.802 — THE AGENT/RPC ENDPOINT IS THE UN-GATED TWIN OF A PER-CONTROLLER GATE: JSON-RPC `tools/call` AGAINST A PASSWORD-PROTECTED SURFACE

SOURCE: https://hackerone.com/reports/4062639 (Shopify, Informative — dev-store design, disclosed 2026-11-12)  read 2026-11-17
CLASS: broken access control — a coarse gate implemented per route while a new agent surface is uncovered.
CORE METHOD: 1. establish the gate (password-protected storefront: `GET /` → 302 `/password`); 2. call the agent endpoint with NO cookies/token/password: `POST /api/ucp/mcp`, `Content-Type: application/json`, `Accept: application/json, text/event-stream`, body `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_catalog","arguments":{"meta":{"ucp-agent":{"profile":"…/agent-profiles/<date>/valid-with-capabilities.json"}},"catalog":{"context":{…}}}}}`; 3. `lookup_catalog` (`catalog.ids[]`) and `get_product` (`catalog.id`) return full product objects (ids, titles, handles, prices, variants, availability, media, options, tags, collections), and `search_catalog` accepts a keyword `query` plus pagination → selective enumeration; 4. the control: normal product pages still redirect to `/password`.
DETECTION SIGNAL: MCP/agent/JSON-RPC surfaces (`/api/<name>/mcp`, `/mcp`, `tools/call`, `tools/list`, `ucp-agent`/agent-profile docs) on apps that also have a coarse gate (password protection, maintenance mode, staging/dev flag, SSO-only); gates added to UI routes rather than middleware.
CHAIN: unauthenticated caller → gate bypassed on the twin endpoint → catalogue disclosure; on a non-dev deployment or a tool with write scope, the same pattern is data modification / PII access. DISPOSITION: Informative in the source program — treat as a chain primitive and auth-boundary probe, never a standalone report. DEDUPE: `4062639`,`api/ucp/mcp`,`tools/call` as an auth boundary,`ucp-agent` = 0 hits. HONESTY: not reproduced; requests, redirect control and `x-request-id` list verbatim from the report.

### [bugbountyhuntingskills.md] 2.1 User-controlled URL parameter on an unauthenticated endpoint

**Source:** HackerOne #3165242 — Lichess, *"SSRF via Game Export API"*, Critical 9.8.

**Core method**
- Enumerate API parameters that semantically *reference a resource* (`players`, `url`, `callback`,
  `feed`, `avatar`, `webhook`, `import`).
- Send your own listener as the value:
  `/api/games/export/_ids?players=[URL]`
  with alternates `/api/games/user/[USERNAME]?players=[URL]`.
- Confirm out-of-band with a collaborator/webhook.site hit — never rely on response body alone.
- Note it needed **no authentication**, which is what pushed severity to critical.

**Transferable test.** Build a param-name wordlist from the API docs + JS bundle, then fire
`http://<collaborator>/` at every one. Record which produce a callback, and from what source IP
(tells you the egress path and whether you're behind a proxy).

---

### [bugbountyhuntingskills.md] 2.3 Feature that "tests" a user URL — webhook validation button

**Source:** HackerOne #2301565 — HackerOne, *"SSRF in webhook functionality"*, Medium 4.9.

**Core method**
- Create the webhook, then use the **"Test request"** button — the admin-only validation flow is the
  SSRF primitive, and it is often less protected than the runtime delivery path.
- Read the webhook *logs* UI: it surfaced the response header `server: EC2ws`, which is the
  signature of the AWS metadata endpoint. The tell was in the app's own logging, not a raw response.
- Severity was medium because the fetch was constrained (no full body returned) — an honest
  self-assessment that kept credibility.

**Transferable test.** Every integration that validates connectivity (webhooks, S3 bucket checks,
SMTP test, RSS import, Jira/GitLab connector test, PDF-from-URL) is an SSRF candidate. Use the
product's own log/delivery-history viewer as your oracle.

---

### [bugbountyhuntingskills.md] 3.4 GraphQL mutation enumeration

**Sources:** HackerOne #2633771 (`AddTagToAssets` mutation IDOR); #2218334 (HackerOne Copilot
`DestroyLlmConversation` mutation — unreleased feature, fixed same day).

**Core method**
- Dump the schema (introspection, or reconstruct from the client bundle when introspection is
  disabled). Collect every `Mutation` and every `ID!`-typed argument.
- For each mutation taking an object ID, invoke it with a foreign ID and a valid session. GraphQL
  resolvers frequently implement field-level auth and skip object-level auth.
- Prioritise **unreleased / beta / hidden** features: they are reachable in production but were never
  through a security review. The Copilot `DestroyLlmConversation` mutation is the archetype.

**Transferable test.** `__schema` introspection → list mutations → for each, replay with a
second-account object ID → check for a `200` with a success payload rather than an authz error.

---

### [bugbountyhuntingskills.md] 3.5 Zombie endpoints extracted from a mobile binary

**Source:** HackerOne #3085742 — Bykea, *"IDOR on in-app hardcoded zombie endpoint"*.

**Core method**
- Decompile the Android APK (`jadx`, `apktool`) and grep for hardcoded URLs, hostnames, and route
  fragments — including ones no longer referenced by the current UI.
- Legacy endpoints remain deployed long after the app stops calling them, and they usually predate
  whatever authorization middleware was added later.
- Here the retired endpoint leaked sensitive user details with a simple identifier swap.

**Lesson.** The mobile binary is a historical record of the API's surface. Old endpoints are
low-traffic, unmonitored, and typically miss the controls added to the current ones. Diff the APK's
strings against the documented API and test the *difference*.

**Transferable test.** `strings`/`jadx` the APK → extract URL patterns → probe each for
auth requirements → compare authz behaviour against the equivalent current endpoint.

---

### [bugbountyhuntingskills.md] 10.3 REST user enumeration and PII endpoints

**Source:** HackerOne #1735586 — MTN, `/wp-json/wp/v2/users/`.

**Core method**
- Default WordPress REST route returns every author with `id`, `name`, `slug`, `description`:
  ```http
  GET /wp-json/wp/v2/users/ HTTP/1.1
  ```
- Names → usernames → password-spray target list. The report's impact is the *reduction in
  attacker effort*, which is why it is often graded Low/Medium — write it as a precursor to
  credential attacks, not as "information disclosure" in the abstract.
- Other CMS equivalents: `/jsonapi/user/user`, `/api/users`, Drupal `/user/1?_format=json`,
  Joomla `/administrator/manifests/files/joomla.xml` (version), Laravel `/api/user`.

**Lesson.** Enumeration endpoints are severity-elastic: alone they are Low, chained with a weak
password policy or a login oracle they become the first step of an ATO. Report the chain.

---

## [bugbountyhuntingskills.md] Knowledge intake — report-reader pass 2026-11-08 (batch 81: 6 assigned sources, read one by one in the given order — the Adobe Flash Player TVSDK `com.adobe.tvsdk.mediacore` memory-corruption family. ALL SIX VALID and read IN FULL via the report JSON endpoint; NONE appended: 0 entries. NOTHING NEW — 6 sources checked.)

- ROUTE MAP (batch 81): all six readable on the FIRST route — `curl -A "<desktop UA>" -H 'Accept: application/json' https://hackerone.com/reports/<id>.json` returned HTTP 200 `application/json` with `visibility: "full"` and a populated `vulnerability_information` for every report (#138516 10,676 B JSON, #138518 10,559 B, #138517 10,580 B, #145265 10,040 B, #145266 10,057 B, #145267 9,897 B). No fallback route (browser, `r.jina.ai`, Wayback) was needed; no other network surface was touched and no target was touched.
- SOURCES (all VALID, all read in full; all by the same reporter `hhj4ck`, all team `Internet Bug Bounty`, all weakness `Memory Corruption - Generic`, all Adobe Flash Player 21, all credited "Wen Guanxing from Pangu LAB", all disclosed 2019-11-12, no bounty field, no severity field):
  1. #138516 "Adobe Flash Player ContentFactory class Memory Corruption Vulnerability" — CVE-2016-1098, apsb16-15, submitted 2016-05-13T01:10:41Z. Body: "improper validation of ContentFactory.retrieveAdPolicySelector() … If retrieveAdPolicySelector() function is invoked directly with invalid parameter, some inner class instance will be absent, which will cause a memory crash." `III. Impact`: "Memory Corruption". PoC: `var obj:ContentFactory = ps.createDefaultContentFactory(); obj.retrieveAdPolicySelector(mt);` where `mt:MediaPlayerItem` is declared uninitialized (null).
  2. #138518 "…OpportunityGenerator class…" — CVE-2016-1100, apsb16-15, 01:14:16Z. Same shape on `OpportunityGenerator.update()`; `III. Impact`: "Memory Corruption". PoC: `ps.createOpportunityGenerator(0).update(1,tr);` with `tr:TimeRange` uninitialized.
  3. #138517 "…Metadata class…" — CVE-2016-1099, apsb16-15, 01:12:37Z. Same shape on `Metadata.setMetadata()`; `III. Impact`: "Memory Corruption". PoC: `new Metadata().setMetadata("test",mt);` with `mt:Metadata` uninitialized. Only this one names the test host: "Latest version of Adobe Flash Player has been tested under Windows 7 x64."
  4. #145265 "…ShimContentFactory class…" — CVE-2016-4150, apsb16-18, submitted 2016-06-17T00:51:55Z. Same shape on `ShimContentFactory.retrieveOpportunityGenerators()`; `III. Impact`: "Memory Corruption"; no PoC in the public body.
  5. #145266 "…ShimContentFactory.retrieveResolvers…" — CVE-2016-4151, apsb16-18, 00:54:50Z. Same shape on `ShimContentFactory.retrieveResolvers()`; `III. Impact`: "Memory Corruption"; no PoC in the public body.
  6. #145267 "…ShimContentResolver.configure…" — CVE-2016-4152, apsb16-18, 00:56:58Z. Same shape on `ShimContentResolver.configure()`; `III. Impact`: "Memory Corruption"; no PoC in the public body.
- WHY NOTHING IS APPENDED (doctrine check, stated before any rating): (a) CLASS — memory corruption is NOT one of the enumerated hunting classes in SEVERITY_DOCTRINE §1, and the freshest ruling in this ledger (batch 78, on OpenSSL #1352429; restated in batch 80 for #119657/#201897/#30567) is that memory corruption gets NO slot without a reproducible chain on a live surface. (b) NO STATED ESCALATION — in all six, the "III. Impact" section says exactly "Memory Corruption" and nothing more: no code-execution claim, no attacker-controlled dispatch, no escalation, no payload — unlike the batch-26 Flash entries (e.g. #151043 PSDK `release()` UAF) whose bodies DID state an escalation and which were admitted under a bar this ledger has since superseded. (c) DEAD SURFACE + ALREADY-RECORDED FAMILY — every one is Flash Player 21 (EOL 2020-12-31, ~10.4 yrs old, far outside the 6–12-month freshness window) on the very `com.adobe.tvsdk.mediacore` API surface already recorded at batch 26 (the same reporter's PSDK / `ASnative` family, bbhskills ~3994-4010 and ~4059-4070); so even under the old bar they would be method-duplicates of the already-recorded "invoke a native SDK entry point directly, with a stale or absent inner object → memory corruption" technique.
- TRANSFERABLE READING (folded into practice, NOT a new slot): the one general idea this family teaches is an API-SURFACE PRECONDITION BYPASS — a public SDK/wrapper member whose argument validation lives in the CALLER's higher-level path, so invoking the member DIRECTLY with an uninitialized/null object (or an out-of-range selector index, as in `createOpportunityGenerator(0)`) skips the guard and reaches code that assumes the object exists, dereferencing absent/`null` inner state. Web analogue to test on live targets: call a documented sub-resource / internal API method DIRECTLY instead of the UI/aggregate path that normally pre-validates, and pass a reference the aggregate would never have forwarded — the bug is the guard living upstream of the entry point you reached. Chain-primitive note only (P4/P5); no live surface demonstrated it.
- DUPLICATE CHECK before deciding (grepped across all three write targets): `138516` 0, `138518` 0, `138517` 0, `145265` 0, `145266` 0, `145267` 0; `retrieveAdPolicySelector` 0, `OpportunityGenerator` 0, `setMetadata` 0, `ShimContentFactory` 0, `ShimContentResolver` 0, `retrieveResolvers` 0, `retrieveOpportunityGenerators` 0, `apsb16-15` 0, `apsb16-18` 0, `CVE-2016-1098` 0, `CVE-2016-1099` 0, `CVE-2016-1100` 0, `CVE-2016-4150` 0, `CVE-2016-4151` 0, `CVE-2016-4152` 0, `Pangu` 0, `ContentResolver` 0. The nonzero hits `tvsdk` 1, `mediacore` 1, `PSDK` 6, `Wen Guanxing` 1, `hhj4ck` 4 are ALL the batch-26 Flash family already in this ledger (line ~3262 the FileReference UAF by "Wen Guanxing from Venustech"; ~3994-4005 the PSDK `release()` UAF; ~4002 the "reclaim the freed allocation with a same-size AS3 object" escalation; ~4059-4065 the batch-26 route/dupe notes) — context, not a prior copy of these six IDs.
- STATUS: 0 entries appended; 6 assigned sources read IN FULL, all VALID; 0 invalid/unreachable; 6 read-but-NOT-recorded (out-of-class memory corruption, no stated escalation, EOL Flash Player 21, family already recorded at batch 26). SECTION 17 UNCHANGED — no new general method was taught, so no slot is added (§17 still runs to §17.275). Knowledge intake only — no target was touched, no lab built, no request reached a target.

## [bugbountyhuntingskills.md] §17.276 — Hasura GraphQL: the per-role introspection dump IS the permission map (unauth read + write grants) — LIVE-VERIFIED 2026-11-08 (subspace.money, SUB-2026-001)

SOURCE: own hunt, live target — `https://db.subspace.money/v1/graphql` (Hasura GraphQL Engine, Enterprise Edition v2.51.0), in-scope program asset "Subspace hasura graphql api". Read 2026-11-08.
STATUS: VERIFIED (live, reproduced twice; request/response transcript in /root/.hermes/cache/scratch/subspace/transcript.txt and /root/hackbot-architecture/state/recon/subspace/).

CLASS: missing authentication / missing authorization on a GraphQL data layer (CWE-306/862/200) → unauth bulk data exposure + anonymous write grants. Reportable as HIGH/CRITICAL under SEVERITY_DOCTRINE §1 (sensitive disclosure with PoC + misconfig with demonstrated impact), NOT as a chain primitive.

THE MECHANISM: a Hasura endpoint answers every request that carries no `Authorization` header and no
`x-hasura-*` role header as its **anonymous** role. Crucially, **Hasura filters introspection by role
permissions**, so an unauthenticated introspection dump is not "just the schema" — it is the exact list
of tables, columns, filters and mutations that anonymous may use. Entries that appear = grant exists;
entries the role lacks come back as a validation error, which is your built-in negative control.

ENTRY POINT: any path serving Hasura (`/v1/graphql` is the default; the API may be mounted under a
prefix or a custom path). Fingerprint with `GET /v1/version` → `{"server_type":"ee","version":"v2.51.0"}`
(excluded as version disclosure on its own — use it only to confirm Hasura and its EE/CE edition).

TEST SEQUENCE (all read-only; ~6 requests total, no guessing):
1. `POST <url> {"query":"{ __schema { queryType { name } mutationType { name } } }"}` (browser User-Agent,
   `Content-Type: application/json`, no auth header). `{"data":{"__schema":{"queryType":{"name":"query_root"},...}}}` ⇒ the anonymous role is open.
2. Full introspection: dump `queryType.fields`, `mutationType.fields`, and the `OBJECT`/`INPUT_OBJECT`
   types. Read `*_insert_input` / `*_set_input`: **Hasura filters those input objects to the columns the
   role may write**, so they tell you exactly what an attacker could set. On subspace that showed
   `insert_superpay_payment_requests` exposing `upi_id, phone, service_id, product_ids, data` (a payment
   table writable by anonymous, with an attacker-controllable UPI ID).
3. Read real rows unauthenticated: `query { <table>(limit: 2) { <cols> } }`. Quantify with
   `<table>_aggregate { aggregate { count } }` where the role has the aggregate grant; where it does not,
   use `limit`+`offset` probes (a row returned at `offset: N` proves N+1 rows) — never page a table to
   exhaustion. Measured on subspace: 44,797 order items (exact aggregate), ≥5,001 orders incl.
   `status: delivered`, ≥5,001 rows of live visitor IP/UA/referer, ≥3,003 user-linked search queries,
   977 user full names + subscription prices, 277 WebAuthn device ids, 20 payment requests, staff e-mails.
4. PROVE WRITE GRANTS WITHOUT MUTATING ANYTHING (the key move): `mutation { insert_x(objects: []) { affected_rows } }`
   → `{"affected_rows":0}` means the INSERT grant exists (0 objects ⇒ 0 rows written). Because Hasura
   drops an ungranted mutation from the role's schema, the control is a validation error
   (`field 'insert_x' not found in type: 'mutation_root'`) — the same error shape you can observe on a
   table the role really cannot touch, which makes this a clean differential. For UPDATE/DELETE use
   `where: {id: {_eq: "00000000-0000-0000-0000-000000000000"}}` (impossible predicate ⇒ 0 rows).
   On subspace this proved anonymous INSERT on a payment table, UPDATE of `passkey_authenticators.device_id`
   (passkey credential rebinding!) and DELETE on a content table — all without writing a single row.
   **Never insert a real row to demonstrate a write grant.**
5. Admin surface differential: `/v1/metadata`, `/v1/query`, `/v2/query`, `/v1alpha1/pg_dump`, `/apis/rest`
   → 404 means closed; `/console` → 200 means the admin UI is exposed (still gated by the admin secret —
   try the default `hasura` ONCE, it was correctly refused on subspace). A 200 on `/console` is context,
   not a finding.
6. Actions/functions reachable by the anonymous role deserve their own probe because their **declared
   output type** is a schema-level statement about what they can return: on subspace `purchaseTest` was
   callable with no auth and its output type is `{ amount, cardNumber, cardPin, orderId, validity }`
   while its input takes a **caller-supplied `user_id`** — reported as a LEAD (unverified) because
   proving it would create a real order. Same rule for `authMintSession(client, refresh_token, user_id)`
   / `authRefreshToken(refresh_token, user_id)` / `refreshToken(request: {refresh_token, user_id})`:
   a caller-supplied identity next to a refresh token is an ATO-by-id-swap hypothesis, report it as a
   LEAD until reproduced, never as a finding.

TRAFFIC NOTE: Cloudflare fronts these endpoints. A bare `python-urllib` User-Agent got HTTP 403 on the
same URL in the same minute that `curl` with a normal desktop browser UA got HTTP 200 — so a 403 from a
scripted client is NOT evidence of a WAF block on the target. Set a browser UA before concluding anything
about reachability; conversely, when a 403 persists with a real browser UA, treat it as WAF and switch to
artifact-driven work.

IMPACT SHAPE (reusable): the finding is not "introspection is on" (that is excluded as version/
config disclosure on its own). It is: **anonymous holds select AND write grants over production data**,
which is simultaneously a mass personal-data breach (GDPR/DPDP-reportable: IP + user ids + names +
purchase prices in one unauth query), a targeting source for ATO (user ids, passkey device ids, staff
e-mails) and an integrity issue (anonymous INSERT into payment tables). Score it as one finding with
C:H/I:H — e.g. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N = 9.1 — rather than splitting read and
write into two reports that share the same root cause.

REMEDIATION SHAPE (what to tell the program): treat the `anonymous` role as a public allow-list, not as
"left at defaults" — re-grant only the explicitly public catalogue tables column-by-column, delete every
anonymous insert/update/delete grant, put the private API behind Hasura JWT mode
(`HASURA_GRAPHQL_JWT_SECRET`), and disable introspection for non-admin roles
(`HASURA_GRAPHQL_ENABLE_INTROSPECTION=false` or per-role filtering).

DEDUPE: no prior §17 entry covers Hasura role-permission enumeration with 0-row write-grant probing
(greps on `hasura`, `anonymous role`, `objects: []`, `affected_rows`, `_insert_input` before append).

### [bugbountyhuntingskills.md] §INTAKE-2026-11-17/6 — THE AGENT/JSON-RPC TWIN OF A GATED UI: `tools/call` ENDPOINTS ARE ADDED AS NEW ROUTES AND THE COARSE GATE (PASSWORD PROTECTION / MAINTENANCE MODE) IS IMPLEMENTED PER-CONTROLLER

SOURCE: https://hackerone.com/reports/4062639 (Shopify — "Unauthenticated UCP/MCP catalog access on a password-protected dev store", weakness Improper Access Control, disclosed 2026-11-12, RESOLUTION: Informative)  read 2026-11-17
ROUTE: HackerOne disclosed-report mirror (full report body + the program's summary and its closing rationale).
STATUS: UNVERIFIED (not reproduced this pass) + DISPOSITION RECORDED HONESTLY: Informative — the program closed it because dev stores skip the storefront password for these endpoints by design, and it is now a listed known issue. USE AS A CHAIN PRIMITIVE / AUTH-BOUNDARY PROBE, never as a standalone report (doctrine §2/§3).
CLASS: broken access control — an access-control gate implemented per route, with an un-gated agent/JSON-RPC endpoint as its twin.
CORE METHOD (as the report states it):
  1. Establish the gate: with Online Store password protection on, `GET /` on the storefront returns `302` → `/password`.
  2. Enumerate the agent-facing surface and call its tools with NO cookies, NO storefront password and NO API token: `POST /api/ucp/mcp` with `Content-Type: application/json` and `Accept: application/json, text/event-stream`, body `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_catalog","arguments":{"meta":{"ucp-agent":{"profile":"https://shopify.dev/ucp/agent-profiles/<date>/valid-with-capabilities.json"}},"catalog":{"context":{"address_country":"US","currency":"USD"}}}}}`.
  3. Same shape reaches `lookup_catalog` (`catalog.ids[]` of `gid://…/Product/<id>`) and `get_product` (`catalog.id`) → product ids, titles, handles, prices, variants, availability, media URLs, options, tags and collections; `search_catalog` also takes a `query` keyword AND supports pagination, so the catalogue can be enumerated selectively (competitor/product-name searches).
  4. The control that defines the bug class: the normal storefront product page still redirects to `/password`, and Shopify's own docs/staff said these endpoint(s) are expected to sit behind the same gate.
DETECTION SIGNAL: any agent/MCP/JSON-RPC surface on an app that also has a COARSE gate — `/api/<name>/mcp`, `/mcp`, `/api/mcp`, JSON-RPC `methods` `tools/call` / `tools/list`, `ucp`/`ucp-agent`/`agent-profile` strings, "AI agent capabilities" docs; a password-protected store / staging / dev / maintenance-mode / SSO-only environment; gates implemented per-controller (a redirect added to the UI route) rather than in middleware.
CHAIN: unauthenticated caller → the gate is bypassed on the agent endpoint while normal routes stay gated → full catalogue enumeration (private/competitive product data) → on a NON-dev deployment, or on a tool with write scope (cart/order/profile tools), the same twin-endpoint pattern is a direct data-modification or PII path. The reported instance stopped at catalogue read/disclosure, and the program classified that exposure as by-design for dev stores.
TRANSFERABLE TEST: for every gated environment in scope (password-protected storefront, staging, dev, maintenance mode): (1) `GET /` and confirm the gate's redirect; (2) enumerate agent/MCP endpoints (`/api/*/mcp`, `/mcp`) and call `tools/list` then each read tool with NO credentials and `Accept: application/json, text/event-stream`; (3) diff the gated route's status against the endpoint's; (4) if any tool has write scope, stop and treat it as a high-severity lead (state preconditions + gain before rating). Rule: **a new agent/RPC surface is a new read path — re-test every gate against it, and never assume a gate implemented as a UI redirect covers it.**
DEDUPE/DELTA: `4062639`, `api/ucp/mcp`, `tools/call` as an auth boundary, `ucp-agent` = 0 hits pre-append. Existing MCP/agent material REVIEWED (LLM-agent tool enumeration, MCP-server takeover via XSS) — NEW atom: the AGENT ENDPOINT as the un-gated TWIN of a gated UI (the gate is per-controller, the new surface is not covered).
HONESTY: not reproduced this pass; the requests, the redirect control and the `x-request-id` list are verbatim from the report, and the program's Informative disposition is recorded as-is rather than upgraded.

---

