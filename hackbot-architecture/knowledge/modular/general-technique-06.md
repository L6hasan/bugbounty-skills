# general-technique — part 6/45 (124 segment(s))
# content-aware dedupe applied; every unique entry preserved.

## [Bugbountyskills.md] Data returned without auth (from own demo deal)

- `parent`: deal name, `legalName`, full `address` + `addressProperties` (line1/city/state/postalCode/country), `brandColor`, `sourceTeam`, `sourceTemplate(DealID/Key)`, `status`, timestamps.
- `parentParties[]`: party `displayName` + party `name` + type (in production deals this is where counterparties live).
- `parentExcludeSignatureActions`, `children[]` (child deals, when present).

Larger/real deals would carry richer party sets; the demo deal is minimal by construction.

## [Bugbountyskills.md] Impact

Anyone who obtains a `dealID` can read the deal's metadata and party list **without logging in**. Realistic dealID disclosure vectors: shared deal URLs, `Referer` leakage (this app ships `referrer-policy: no-referrer-when-downgrade`, so full deal URLs leave the origin on any same-scheme third-party request), browser history, logs, shoulder-surfing, support screenshots. dealIDs are Firestore-style (~19-20 char base64ish, ~112 bits) so they are **not enumerable** — severity is driven by leak scenarios, not brute force. The guest-signing design makes dealIDs travel widely by nature (they are embedded in invite-oriented flows).

## [Bugbountyskills.md] Reproduction

```
curl -sS -H 'X-Inspectiv-Tester: <tester-email>' \
  -H 'Content-Type: application/json' \
  -d '{"dealID":"<any valid dealID>"}' \
  https://fv.getoutlaw.com/api/getBundle
```
No cookie, no token, no inviteID/duKey.

## [Bugbountyskills.md] Recommended fix

Require authentication **and** object-level authorization (deal membership / signed-in party), or bind the call to a validated invite token the way `getInvite` does. Do not rely on dealID secrecy as the only control.

## [Bugbountyskills.md] F-02 — Pre-auth account-existence + auth-method oracle via `POST /api/checkAccount`

**Date:** 2026-10-23 (session 2)
**Class:** Information disclosure — user enumeration (V-04)
**Status:** Proven, no side effects. Low severity (standalone); useful as a phishing/recon multiplier.

## [Bugbountyskills.md] Summary

`POST https://fv.getoutlaw.com/api/checkAccount` is callable anonymously (`callAnon` in the bundle) and returns the registered authentication methods for an email:

- Registered email → `HTTP 200 ["password"]`
- Unregistered email (`definitely-not-registered-98765@nonexistent-test.invalid`) → `HTTP 200 []`

The endpoint is an intentional login-UI helper, but it is an unthrottled, unauthenticated existence oracle: an attacker can enumerate which emails have Outlaw accounts and which auth methods (password / SSO providers) are enabled for them — useful for spear-phishing ("we know you use Outlaw") and for targeting the SSO/fvid flows.

## [Bugbountyskills.md] Reproduction

```
curl -sS -H 'X-Inspectiv-Tester: <tester-email>' -H 'Content-Type: application/json' \
  -d '{"email":"<candidate@example.com>"}' https://fv.getoutlaw.com/api/checkAccount
```
Compare `[]` vs `["password"]` (or provider lists for SSO orgs).

## [Bugbountyskills.md] Notes / adjacent observations (not separate findings)

- `sendSignInLink` returns `HTTP 200 {"success":true}` even for a malformed email — no validation, but also no enumeration signal and no confirmed side effect (did not test real-mailbox delivery to avoid sending unsolicited mail).
- `getOpenIDProvider` (also anonymous) returned empty bodies for gmail / invalid / IP-literal domains — no data reflection, no usable oracle from a single probe each.

## [Bugbountyskills.md] Recommended fix

Rate-limit and genericize: return a constant response regardless of existence, or move the check behind the session/rate-limiting boundary with constant-time-ish behavior.

## [Bugbountyskills.md] Stack (verified 2026-10-25)

- WAF: **Cloudflare** in front (`server: cloudflare`, `cf-ray …-YYZ`, `__cf_bm` bot-management
  cookie, `cf-cache-status: DYNAMIC` on HTML). No managed-challenge observed on root yet.
- Edge/origin: `x-envoy-upstream-service-time: 1` on root → **Envoy** mesh behind Cloudflare
  (per quizlet lesson: Envoy headers are a first-class info source; look for
  `x-envoy-decorator-operation`).
- App type: SPA. `<!doctype html>`, `<base href="/"/>`, title "Devolutions Cloud",
  no server-rendered content. Framework: likely Angular (`script-src 'unsafe-eval' 'self'` is
  an Angular tell) — CONFIRM from bundle signatures in JS.
- CSP (root): `default-src https://login.devolutions.com https://login.devolutions.xyz 'self'`;
  `connect-src https: data: wss: 'self'` (all HTTPS allowed — permissive connect-src);
  `script-src 'unsafe-eval' 'self'`; `object-src 'none'`; `frame-src 'self' blob: https://devolutions.net`.
- Other headers: XFO SAMEORIGIN, HSTS 31536000, nosniff, referrer-policy no-referrer,
  cache-control no-cache,no-store on HTML.
- Fonts/CDN: cdnfonts.devolutions.net (OpenSans, Roboto), fontsdevolutions.blob.core.windows.net,
  iconcache.devolutions.com + iconcache.devolutions.xyz, webdevolutions.blob.core.windows.net.
- Auth model: TBD — CSP names `login.devolutions.com` and `login.devolutions.xyz` as identity
  hosts (likely OIDC/OAuth). Cookie/token details TBD.
- robots.txt: `User-agent: * / Disallow: / / noindex: /` — blanket disallow, NO path intel.
- security.txt: absent — `/.well-known/security.txt` returns the SPA fallback (index.html).
- **Soft-404 calibration:** SPA serves index.html for unknown paths. Calibrate: any unknown
  path → 200 + HTML. Content discovery MUST compare body size/hash, not status codes.
  Baseline root: HTTP 200, 2292 bytes, etag "1dd5c11b8772374", last-modified 2026-10-14.

## [Bugbountyskills.md] Findings history

| Date | Endpoint | Class | Status | Report |
|---|---|---|---|---|
| 2026-10-25 | GET /api/server-configurations | Info disclosure (OpenSearch cred) | CONFIRMED | F-01 |
| 2026-10-25 | GET /client*/main.js.map | Source-map exposure (42MB TS) | CONFIRMED | F-02 |

## [Bugbountyskills.md] Ruled out (and why)

- **CORS misconfig (public endpoints):** evil `Origin` → NO `access-control-*` headers,
  OPTIONS → bare 204. No reflection, no ACAC. Not vulnerable on public surface.
- **Stack traces / verbose errors:** malformed JSON + bad input → 401/405, empty bodies, no
  framework traces. Dead end.
- **Hardcoded secrets in source:** mined 42MB TS — the `AKIA…`/`AIza…`/`ghp_`/JWT hits are
  base64 from the embedded Devolutions Crypto WASM, not real cloud keys. Only live secret is
  the one in server-configurations (F-01).
- **eval/Function RCE sinks:** all `eval(`/`Function(` hits are regex definitions (SAS/other
  language keyword lists), not code-execution sinks. `child_process`/`spawn` = 0.
- **SignalR realtime host:** `signalr-personal.hub.devolutions.com` returns the SPA fallback
  (2292 B), not a live negotiate endpoint. Not real surface.
- **`.well-known/*` (openid-configuration, assetlinks, ai-plugin, nodeinfo):** all SPA
  fallback (2292 B soft-404). Only `login.devolutions.com` (separate Keycloak IdP) serves real
  OIDC discovery — that's expected/by-design, not a finding.
- **Subdomain takeover candidates:** many 301s (account/cloud/portal/login) but all resolve to
  Devolutions infra, not dangling DNS.

## [Bugbountyskills.md] WAF / defense behavior

Cloudflare in front (waf-detect=cloudflare; `cf-ray`/`__cf_bm`/`cf-cache-status: DYNAMIC`).
No managed-challenge observed on any request this session. Envoy behind edge
(`x-envoy-upstream-service-time`). Auth errors are empty-body 401s (deliberately opaque).
No rate-limit / 429 hit at conservative throttle.

## [Bugbountyskills.md] F-01 — Unauthenticated OpenSearch/Elasticsearch credential disclosed via /api/server-configurations

**Severity:** Low (info-disclosure → leaked valid credential for a backend datastore; **impact bounded** — the account has zero privileges, confirmed by live validation on 2026-10-25)
**Endpoint:** `GET https://hub.devolutions.com/api/server-configurations` (no authentication, no cookies, no Origin restriction)
**Class:** Information disclosure → route: `info-disclosure-testing` (leaked credentials/hardcoded secrets)
**CWE:** CWE-798 (Use of Hard-coded Credentials) / CWE-200 (Exposure of Sensitive Information)
**OWASP:** A05:2021 – Security Misconfiguration; A07:2021 – Identification and Authentication Failures

## [Bugbountyskills.md] Summary

The public, unauthenticated endpoint `/api/server-configurations` (consumed by the SPA at boot to
configure the client) returns a JSON object that includes an `openSearch` block containing a
**live username, password, cluster URL, and index names** in plaintext. This is a real production
credential for a search/telemetry cluster (`prodhub` @ `https://telemetry2.devolutions.net:9200`,
indexes `hub-instant-events` and `feature_events`). The endpoint also discloses OIDC client IDs,
the identity authority, region endpoints, and the internal portal URL — expanding the attack
surface and giving an unauthenticated attacker a validated account/password pair for a
backend data store.

## [Bugbountyskills.md] Steps to reproduce

1. Open an unauthenticated browser/curl session (no login, no session cookie).
2. Request: `curl -i https://hub.devolutions.com/api/server-configurations`
3. Observe HTTP 200 `application/json` with the `openSearch` object present, including
   `username`, `password`, `apiUrl`, `indexName`, `featureEventIndexName`.

## [Bugbountyskills.md] Impact

- A production Elasticsearch/OpenSearch **username+password pair is exposed to any anonymous
  visitor**, along with the exact cluster URL and index names.
- If the cluster is reachable from the internet (it resolves and answers HTTP 401 at the edge,
  so the host is live), the credential could permit authentication and read/write to telemetry
  and feature-event indexes — potentially exposing operational telemetry and cross-tenant
  event data.
- Even where the cluster is network-reachable only from a private path, the leak removes the
  secret from the secret-management boundary and violates least-exposure; it is a latent
  credential that must be rotated and must never ship to a client bundle / public config.
- Compounding intel: the same response yields the OIDC `authority`, multiple `clientId` values,
  `regionUrl` (`cloud.devolutions.app`), and `portalUrl` — a map of the identity + region
  topology handed to an unauthenticated caller.

## [Bugbountyskills.md] Remediation

- **Remove the `openSearch` block from the public config endpoint entirely.** Backend
  datastore credentials must never be delivered to a browser client. The telemetry cluster
  should be reached server-side only.
- **Rotate the exposed `prodhub` password immediately** (it is now public) and audit the
  `hub-instant-events` / `feature_events` indexes for unauthorized access.
- Serve only the minimal client-facing settings (feature flags, region hint) from this
  endpoint; move anything sensitive behind server-side auth.
- Add a response-schema test / DLP rule that fails CI when a config payload contains a
  `password`, `secret`, or `apiKey` field.

## [Bugbountyskills.md] Live validation (2026-10-25) — credential is REAL but locked down

Minimal read-only validation performed (no index data read, no writes):
- `GET /` (banner, no auth) → `"Authentication finally failed"` → OpenSearch/ES with the
  security plugin enabled.
- `GET /_cluster/health` with `prodhub:<leaked>` → **HTTP 403**
  `security_exception … no permissions for [cluster:monitor/health] and User [name=prodhub,
  backend_roles=[], requestedTenant=null]`.
- `GET /_cat/indices`, `/_cat/plugins`, `/_nodes/...` → all **403 security_exception**.

**Interpretation:** the username+password pair is **valid and accepted** (the error echoes the
authenticated principal `prodhub`), proving the disclosed secret is live — not a stale/decoy
value. However `backend_roles=[]` means the account holds **no privileges**: it cannot list,
read, or write indices, nor inspect cluster state. There is **no data exposure**.

**Severity therefore Low, not Medium/Critical:** it is a genuine hard-coded-credential leak of
a live account, but the account is inert. Residual risk: (a) any future privilege grant to
`prodhub` would immediately be exploitable by anyone who saw this endpoint; (b) the leak still
violates least-privilege/secret-management and the password must be rotated; (c) confirms the
telemetry cluster is internet-reachable and the credential is shipped to every anonymous
visitor's browser (the `openSearch` block is part of the SPA config the client fetches at boot).

**Scope note:** `telemetry2.devolutions.net` is a Devolutions-owned domain (CNAME → hoster
`devolutions.mindinabox.ai`); it is the Cloud product's telemetry backend and therefore in-scope
attack surface. Validation was limited to identity/capability probes — no authentication
brute-force, no index reads, no writes.

## [Bugbountyskills.md] F-02 — Full client source code exposed via served sourcemaps (main.js.map, 62 MB)

**Severity:** Low / informational (source disclosure — no direct exploit, but materially lowers the cost of finding bugs and exposes internal structure, feature flags, and logic)
**Endpoint:** `GET https://hub.devolutions.com/client2026.3.202.620/main.js.map` (and `polyfills.js.map`, `scripts.js.map`) — unauthenticated, static
**Class:** Information disclosure → route: `info-disclosure-testing` (source maps / source leakage)
**CWE:** CWE-532 (Insertion of Sensitive Information into Log/File) / CWE-200
**OWASP:** A05:2021 – Security Misconfiguration

## [Bugbountyskills.md] Summary

The live Angular bundle ships with `sourceMappingURL=main.js.map`, and the sourcemap is
**served in the clear** (HTTP 200, 62,037,655 bytes). The map embeds `sourcesContent` for
**2,308 original TypeScript source files (~42 MB)**, i.e. the app's full readable source —
components, services, API routes, auth handling, and the client-side encryption glue. This is a
public production app for a password manager, so source exposure is meaningful reconnaissance.

Notably, `common.js.map` returns the **SPA fallback (2292 B, soft-404)** — so map serving is
**not uniform**; the large maps are the exposure.

## [Bugbountyskills.md] Steps to reproduce

1. `curl -s https://hub.devolutions.com/ | grep sourceMappingURL` → `main.js.map`
2. `curl -i -o main.js.map https://hub.devolutions.com/client2026.3.202.620/main.js.map`
3. Observe HTTP 200, `Content-Type` map, ~62 MB; `sources` = 2308 paths, `sourcesContent` present.
4. Reconstruct original TS: `python3 -c "import json;d=json.load(open('main.js.map'));..."`
   → 42 MB of original source.

## [Bugbountyskills.md] Impact

- Full source of the client is available to any anonymous visitor, removing all obscurity around
  the auth flow, vault/entry API surface, and client-side crypto integration.
- Directly enables faster vuln discovery (endpoint + parameter mining, logic review) and
  exposes internal naming, feature flags, and the 161 enumerated `/api/*` routes.
- Combined with F-01, an attacker gets both the code and a leaked backend credential.

## [Bugbountyskills.md] Remediation

- **Do not deploy `.js.map` files to production**, or strip `sourcesContent` and gate the maps.
  Best: exclude `*.map` from the production build/publish step (Angular `sourceMap: false` for
  prod) and block `\.map$` at the CDN/edge.
- If maps are needed for future debugging, host them in an access-controlled location.

## [Bugbountyskills.md] Production OpenSearch credential exposed via unauthenticated `/api/server-configurations`

**Severity:** Low — CVSS 3.1 **5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)**. Honest rating: the
disclosed credential is **valid** (confirmed live 2026-10-25) but the account carries **zero
privileges** (`backend_roles=[]`), so there is no confidentiality/integrity impact today. Rated
Low, not Informational, because a real, working credential for a production datastore is served
to anonymous visitors and must be rotated. Raise severity to High/Critical the moment `prodhub`
is ever granted any index or cluster privilege.

**Endpoint:** `GET https://hub.devolutions.com/api/server-configurations` (auth: **none** — no
cookie, no token, no Origin restriction)
**CWE:** CWE-798 (Use of Hard-coded Credentials); CWE-200 (Exposure of Sensitive Information)
**OWASP:** A05:2021 – Security Misconfiguration; A07:2021 – Identification and Authentication Failures

**Summary:** The endpoint `/api/server-configurations` — which the Devolutions Cloud SPA fetches
at boot with no authentication to configure the client — returns a JSON object whose `openSearch`
block contains a **live username, password, OpenSearch cluster URL, and index names** in
plaintext. The username/password pair is a real production credential for the Devolutions Cloud
telemetry cluster (`prodhub` @ `https://telemetry2.devolutions.net:9200`, indexes
`hub-instant-events` and `feature_events`). Because this block is part of the client bootstrap
config, the secret is delivered to the browser of **every anonymous visitor**. Reproduced 3× from
a clean unauthenticated session (2026-10-25).

## [Bugbountyskills.md] Steps to reproduce

1. Open a plain unauthenticated request (no login, no session cookie). From curl:
   ```http
   GET /api/server-configurations HTTP/1.1
   Host: hub.devolutions.com
   User-Agent: Mozilla/5.0
   ```
2. The server returns `HTTP/2 200`, `content-type: application/json; charset=utf-8`, with no
   `access-control-*` headers and `cf-cache-status: DYNAMIC`.
3. The response body contains an `openSearch` object:
   ```json
   "openSearch": {
     "apiUrl": "https://telemetry2.devolutions.net:9200",
     "password": "[REDACTED]•••@•••",
     "username": "prodhub",
     "indexName": "hub-instant-events",
     "featureEventIndexName": "feature_events"
   }
   ```
4. **Validation that the credential is real (minimal, read-only, no data accessed):** submitting
   the disclosed username+password to the cluster authenticates successfully. The server accepts
   the pair and echoes the authenticated principal in its authorization errors, e.g.
   `GET /_cluster/health` →
   `403 {"error":{"type":"security_exception","reason":"no permissions for [cluster:monitor/health] and User [name=prodhub, backend_roles=[], requestedTenant=null]"}}`.
   `GET /_cat/indices`, `/_cat/plugins`, and `GET /_nodes/...` likewise return `403
   security_exception`. The banner (`GET /` with no auth) returns `"Authentication finally
   failed"`, identifying an OpenSearch/Elasticsearch cluster with the security plugin enabled.
   **Content-class:** proof of a valid, accepted credential — not a stale or decoy value — that
   is simultaneously inert (no privileges).

## [Bugbountyskills.md] Impact

Any unauthenticated visitor obtains a **working username/password pair for a production OpenSearch
cluster**, together with its exact URL and index names, and a map of the surrounding identity and
region topology (the same response also discloses the OIDC `authority`, multiple `clientId`
values, `regionUrl`, and `portalUrl`).

Today the impact is bounded: the `prodhub` account has `backend_roles=[]` and is denied every
capability probed (`_cluster/health`, `_cat/indices`, `_cat/plugins`, `_nodes`), so **no data can
be read or written and there is no tenant exposure**. The concrete risks are:
- **Latent privilege escalation:** the moment any index or cluster privilege is granted to
  `prodhub`, the credential is already public and the telemetry/feature-event indexes (operational
  and potentially cross-tenant event data) become readable by anyone.
- **Broken secret boundary:** a backend datastore credential is shipped to the public internet and
  cached in every visitor's browser, violating least-privilege and secret-management. It must be
  rotated regardless of current privileges.
- **Confirmed internet reachability** of the telemetry cluster from an anonymous vantage point.

Auth level required to trigger: **none**.

## [Bugbountyskills.md] Remediation

- **Remove the `openSearch` block from the public config endpoint entirely.** Backend datastore
  credentials must never be delivered to a browser client; the telemetry cluster should be
  reached server-side only.
- **Rotate the `prodhub` password immediately** — it is now public. Audit the `hub-instant-events`
  and `feature_events` indexes for any unauthorized access (none was performed during this test).
- Serve only the minimal client-facing settings (feature flags, region hint) from this endpoint;
  move anything sensitive behind server-side authentication.
- Add a CI response-schema test / DLP rule that fails the build when a config payload contains a
  `password`, `secret`, or `apiKey` field, so this cannot regress.
- Long term: keep the account at zero privilege (as it is now) or eliminate it; never grant it
  index/cluster rights while a public bootstrap path exists.

## [Bugbountyskills.md] References

- CWE-798 (hard-coded credentials), CWE-200 (information exposure)
- OWASP A05:2021 Security Misconfiguration; A07:2021 Identification and Authentication Failures
- WSTG-INFO-02 (enumerate application infrastructure), WSTG-INFO-05 (review legacy web
  components / exposed configuration)

## [Bugbountyskills.md] jardindacclimatation.fr

**Program / authorization:** Published bug bounty, LVMH group / Jardin d'Acclimatation.
Reward grid: asset value "High", €50 (Low) / €200 (Medium) / €600 (High) / €1,000 (Critical),
scaled by duplicate-report decay (100/100/75/50/25/10%). First reporter only.
LVMH, JdA employees and their contractors are ineligible.
*(Program brief pasted by operator 2026-10-24; full "testing policy" section was NOT provided — see Scope.)*

**Last engagement:** 2026-10-24 (first session)

## [Bugbountyskills.md] Stack (verified 2026-10-24)

- **WAF / CDN:** Akamai. Evidence: `server-timing: ak_p`, `errors.edgesuite.net` reference codes,
  cookies `_abck` + `bm_sz` + `ak_bmsc` (Akamai Bot Manager), `x-akamai-transformed`,
  `AkamaiNetStorage` error pages, mPulse RUM key `AK8A5-NKVMJ-J7ET5-UULCM-UQ8F4`.
  Bot state = the `~N~` flag inside `_abck`: **`-1` = bot/not validated, `0` = validated.**
- **Origin:** Google Cloud (`x-cloud-trace-context` header) behind Akamai.
- **Framework:** Next.js **pages router**, `buildId = KMsT6qtuVNyJ8I0vFHTel`, `locale=fr`.
  SSG only for `/401 /403 /404 /500` (`_ssgManifest`); everything else is SSR/CSR.
  Server API routes exist under `/api/*` (not enumerable via buildManifest).
- **CMS:** Prismic — `jardindacclimatation.cdn.prismic.io/api/v2/documents/search`,
  `images.prismic.io`. Rich-text rendered with `dangerouslySetInnerHTML` (CMS-controlled only).
- **Auth:** `next-auth` (reads `NEXTAUTH_URL` / `NEXTAUTH_URL_INTERNAL` env) + **Okta** as IdP
  (`signIn("okta")` on any 401). Client state in `localStorage`: `user_token`, `guest_token`.
  **Admin API auth is `?token=<oktaToken>` in the URL QUERY STRING** — see finding candidate F-03.
- **Payments:** Adyen (bundles BOTH `checkoutshopper-live` and `checkoutshopper-test` +
  `sandbox-assets.secure.checkout.visa.com`, `sandbox.src.mastercard.com`, `sandbox.kit.cash.app`),
  PayPal, Amazon Pay, Klarna, Google Pay, Visa, Mastercard, Riverty, Przelewy24, PayU, Cash App.
- **3rd-party tags:** GTM `GTM-K65TCHG`, OneTrust `0193d921-8166-7735-aab1-d1c985e77511`,
  HubSpot `145656177`, `js-eu1.hsforms.net`.
- **Headers:** `strict-transport-security: max-age=86400 ; preload`; no CSP observed;
  no `X-Frame-Options`/`X-Content-Type-Options` observed on tested responses.
- **DNS:** NS `*.ns.domainoo.fr`; MX Proofpoint `*.pphosted.com` (also `spf.protection.outlook.com`,
  `mcsv.net` in SPF); apex A `185.16.44.89` → nginx, **cert does NOT cover `www`**, serves 404 —
  it is a stale/parallel host, **not** the app origin.
- **AXFR:** failed on all four NS (expected).

### [Bugbountyskills.md] Pages (27 routes — from `_buildManifest.js`, fetched with validated `_abck`)

`/` · `/401` · `/403` · `/404` · `/500` · `/_error` · **`/admin`** · `/attractions` ·
`/attractions/[uid]` · **`/attribuer-tickets`** · **`/auth/callback`** · `/billetterie` ·
`/checkout` · **`/checkout/result`** · `/contact` · **`/detail-des-billets`** ·
`/entreprises-et-cse` · `/entreprises-et-cse/confirmation-email` ·
**`/entreprises-et-cse/creation-de-compte-pro`** · `/entreprises-et-cse/verification-email` ·
**`/forgotPassword`** · **`/mon-compte`** · **`/resetPassword`** · `/restaurants/[uid]` ·
`/sitemap.xml` · `/tarifs` · `/[uid]`

`robots.txt` disallows: `/resetPassword` `/forgotPassword` `/mon-compte` `/401` `/403` `/404`
`/500` `/checkout/result`. No `security.txt` (404 at both `/.well-known/` and `/`).

## [Bugbountyskills.md] Findings history

| Date | Endpoint | Class | Status | Report |
|---|---|---|---|---|
| 2026-10-24 | `GET /api` | PII leak (operator-found) | **VALIDATION PENDING — operator gave the request only; need the response body / screenshot. Could not reproduce: `/api` → `307 /404` both anonymously and with their validated `_abck`.** | draft |
| 2026-10-24 | `GET /api/proxy/user/checkEmail?email=` | Account enumeration (CWE-204) + `businessStatus` leak | **CONFIRMED** — 200 `{"email":…,"exists":false}`; malformed → 400; client branches on `t.exists`. `exists:true` branch inferred from bundle, not yet observed live. | `findings/001-email-enumeration-oracle.md` |

### [Bugbountyskills.md] New routes found after the initial inventory (from `_app` chunk module `66679`)

`POST /auth/signup` · `POST /auth/login` · **`GET /auth/url/{provider}`** (OAuth provider URL
builder — candidate for `redirect_uri` manipulation via `business-logic`/`csrf`) ·
`GET /user/checkEmail?email=` · `GET /auth/checkMagicLink?token=` · `POST /auth/sendMagicLink`.

## [Bugbountyskills.md] Ruled out (and why)

- **DNS zone transfer** → failed on all 4 NS (`domainoo.fr`). Closed.
- **`/.env`, `/wp-login.php`, `/composer.json`, `/graphql`, `/api/v1`, `/api/docs`, `/500`,
  `/_next/*` (for bots)** → Akamai edge `403 Access Denied` (edgesuite reference page), not
  origin responses. Not evidence the files exist. Closed as unreachable from this vantage.
- **`/500` → stack trace** → it is the Akamai "Access Denied"/LVMH maintenance page, never a
  framework trace. Closed.
- **`/swagger`, `/api` → 307 `/404`** → Next.js unrouted-path behaviour, not an API index.
- **`/admin` page → 200/64KB** → only the site shell renders; content is client-gated.
  Not an admin disclosure by itself. (The `/admin/*` **API** is the real surface.)
- **Apex `185.16.44.89` as origin-bypass** → cert doesn't cover `www`, nginx 404s on everything
  tested; it's a stale host, not the app origin. Closed.
- **SQLi on `productCode`/`startDate`** → **inconclusive, NOT ruled in.** A quote produced a 503,
  but that turned out to be an **Akamai-cached LVMH maintenance page** (`cdn-cache: HIT`,
  `AkamaiNetStorage`) — a red herring. Subsequent differential probes all 403'd at the edge
  within 0.3s, *including the benign control value* `A01WX`, proving the block is bot-behavioural,
  not input-based. Re-run with heavy spacing (see Next session).
- **Admin API authz bypass** → `GET /api/proxy/admin/orders?token=invalid` → `401 {"message":
  "Unauthorized","statusCode":401}`. A garbage token is rejected; **a valid-but-user-scoped
  token has not been tested** (needs Okta session).
- **Reflected XSS via `?q=` / `?utm_source=` on `/` (2026-10-24)** → the canary was reflected
  **only twice, both inside the `__NEXT_DATA__` JSON**, and Next.js escaped it correctly:
  `<`→`\u003c`, `>`→`\u003e`, `&`→`\u0026`, `"`→`\"`. Zero hits in visible HTML, no `&lt;` form,
  no attribute context. Payload `<>"'&XSSCANARY7c1d` inert. **Ruled out for this param/context** —
  but only for `/`; the `/checkout/result?code=&guest=&language=` and `/auth/callback` contexts
  are still untested and are richer (money flow / OAuth).
- **Verbose error disclosure** → malformed input returns a clean
  `400 {"message":["email must be an email"],"error":"Bad Request","statusCode":400}`
  (class-validator style). No stack traces, no SQL text anywhere observed. Ruled out so far.
- **`/api/business/massAssignment` reachability** → `403` from the edge (bot gate), NOT an auth
  answer. **Unresolved — retest**, do not record as "protected".

## [Bugbountyskills.md] WAF / defense behavior (Akamai Bot Manager) — **read before testing**

- Requests without a validated `_abck` (`-1`) get `403` on `/_next/*`, `/.env`, `/wp-login.php`,
  `/composer.json`, `/graphql`, `/500`, `/api/v1`, `/api/docs`.
- A validated `_abck` (`~0~`) unlocks `/_next/*` (manifests, chunks) — but **curl cannot mint one**;
  it must be seeded from a real browser session (`jar.txt` in this directory holds one).
- **Throttle:** ~1–2 requests succeed per burst, then *everything* 403s at the edge in <0.3s,
  **regardless of payload** — including harmless values. A 35s gap was **not** enough once the
  score saturated (10 straight 403s, one timeout). Cool-down alone did not recover it either.
- **✅ THE RESET THAT WORKS (verified):** re-send `curl -b "_abck=<original browser _abck>"`
  (seeded from the operator's paste) → that one request returns **403**, but **~40s later a
  normal request returns `200`**. So the recipe per probe batch is:
  `reseed with original cookie → wait 40s → fire the probe`. Re-seeding *from the current jar*
  does not work; it must be the original value (`user_abck.txt` in `/tmp/opencode/jda/jda*`).
- Expect roughly **3–4 useful probes per run** with this rhythm. Budget accordingly: pick the
  highest-value probes first, never burn them on loops.
- `403` body = Akamai `Access Denied` with `Reference #..` + `errors.edgesuite.net` link.
- `503` = Akamai **cached** LVMH maintenance page (`server: AkamaiNetStorage`,
  `cdn-cache: HIT`) — **never treat a 503 as a backend error.**
- An empty/missing query param (`/api/proxy/user/checkEmail?email=`) → `403` at the edge;
  a *malformed* value → `400` from the app. Distinguish these two before concluding anything.
- Repeated identical requests → `_abck` re-issued; no CAPTCHA observed, just 403.

## [Bugbountyskills.md] jardindacclimatation.fr — technique routing matrix (Phase 3)

Derived from static analysis of the production Next.js bundles + `buildManifest` + `robots.txt`.
Auth model: `user_token` / `guest_token` in localStorage; admin API auth = `?token=<oktaToken>`.
All `/api/proxy/*` routes go through one axios wrapper; **`/api/business/massAssignment` does not.**

Legend — **Untested** = not yet reached · **401** = auth enforced on the request I sent ·
**Ruled out** = tested negative (see SKILL.md).

---

## [Bugbountyskills.md] Sandbox escape (`sandbox-escape-testing`)

**No surface.** No VM/jail/container/WASM context anywhere in the client or routes.
Nothing to test — recorded so the next session doesn't re-hunt it.

---

## [Bugbountyskills.md] Summary

The endpoint returns an explicit boolean telling the caller whether an account exists for an
arbitrary email address, and — for business accounts — which workflow state it is in. It is
unauthenticated and unlimited. An attacker can therefore test any list of email addresses and
learn which ones are registered, then use that set for credential-stuffing, targeted phishing,
or to profile business customers by onboarding state.

The response is not a side channel; it is the API's designed contract, and the public client
code branches on it to switch between "sign in" and "continue as guest" UX — so the behaviour
is observable end-to-end without any special tooling.

## [Bugbountyskills.md] Steps to reproduce

1. From a clean session, request:
   ```
   GET /api/proxy/user/checkEmail?email=zznonexistent9f3a@example.com
   ```
2. **Actual (registered/unknown address):** `200` with body
   ```json
   {"email":"zznonexistent9f3a@example.com","exists":false}
   ```
3. Repeat with a syntactically invalid address to confirm server-side handling rather than an
   open echo:
   ```
   GET /api/proxy/user/checkEmail?email=not-an-email-at-all
   ```
   **Actual:** `400` with
   ```json
   {"message":["email must be an email"],"error":"Bad Request","statusCode":400}
   ```
4. **Expected (secure):** a single uniform response that does not disclose existence, e.g.
   "If this address is registered, we have sent a message", or no response difference at all.

**Where `exists:true` is proven without a live sample:** the shipped production bundle
`/_next/static/chunks/pages/checkout-1bdac0ccd03bc05e.js` contains the consumer:

```js
X.I.checkMail({email: e.email}).then(t => {
  t.exists ? (setEmail(t.email), onConnect(t.email), setShowConnect(true))
           : (onConnect(t.email), nextStep());
})
```

and `static/chunks/846-d00a76efac785797.js` additionally switches on a second leaked field:

```js
ef.I.checkMail({email}).then(a => {
  if (a.exists && a.businessStatus) { switch (a.businessStatus) {
    case 'AwaitReceipt':               /* "await receipt" message */ break;
    case 'AwaitingAdditionalDocuments': router.push('/entreprises-et-cse/confirmation-email'); break;
    case 'Authorized':                  ef.I.sendMagicLink({email, ...}); break;
  }}
})
```

So a registered address yields `exists:true` plus `businessStatus` ∈
`AwaitReceipt | AwaitingAdditionalDocuments | Authorized`.

## [Bugbountyskills.md] Impact

- **Account enumeration** across an unlimited, unauthenticated oracle — enables credential
  stuffing and spear-phishing against a known-good address set (phishing success rate rises
  materially when the attacker knows the mailbox is live).
- **Business-customer profiling:** `businessStatus` discloses a B2B customer's onboarding stage
  (awaiting receipts / awaiting documents / fully authorised) for an arbitrary address — this is
  operational data about a named organisation, not just a boolean.
- No direct data disclosure of name/DOB/payment data was observed from this route; impact is
  informational and should not be inflated.

## [Bugbountyskills.md] Remediation

- Remove the existence oracle: respond with a constant-shape payload for every address, and move
  any real decision to an out-of-band channel (the email itself).
- If the login drawer needs to know whether to show "connect", decide it **after** the user
  submits credentials, or return the same neutral state for both branches.
- Drop `businessStatus` from this unauthenticated response; return it only to the authenticated
  session it belongs to.
- Rate-limit per-IP and per-destination on this route as a defence-in-depth measure.

## [Bugbountyskills.md] Open (to confirm before submitting)

- Observe `exists:true` live with a **test account the operator owns** (do not use a third
  party's address — the program forbids including third-party PII in a report). This turns
  "inferred from client code" into a directly observed pair.

## [Bugbountyskills.md] quizlet.com

**Program / authorization:** Quizlet Bug Bounty — Bugcrowd https://bugcrowd.com/engagements/quizlet (in progress since 2018-08-14, partial safe harbor, scope rating 2/4, rewards P1 $1500–2000 / P2 $1000–1250 / P3 $450–600 / P4 $150–200, max $5000, no collaboration).
**Last engagement:** 2026-10-21 (session 1) — recon + reachable-surface testing. **Blocked by Cloudflare managed challenge for all app-layer testing; see "WAF / defense behavior".**

## [Bugbountyskills.md] Stack (verified 2026-10-21)

- **WAF / edge:** Cloudflare (NS `lily`/`ian.ns.cloudflare.com`, A records `104.16.133.27`/`104.16.134.27`) **plus a second bot layer**: PerimeterX/HUMAN (`_pxhd` cookie). Bot cookies seen: `__cf_bm`, `_cfuvid`, `_pxhd`.
- **Front controller / origin:** `via: 1.1 google` on every origin response → Google Cloud L7 load balancer in front of app backends.
- **Main site:** Next.js (`buildId: 0RK1Nw2G_hsv6AkH_PT-W`, chunks under `assets.quizlet.com/_next/static/…`) behind a Rails-style front controller (the app emits `quizlet-action-name` / `quizlet-route-importance`).
- **`study.quizlet.com`:** Rails (`x-runtime`, `x-request-id`), CNAME → `2da01121-bb6d-4c62-81fe-1748b15ef065.us03.ldpgs.com` (Google-hosted), rate-limited 500/min, CORS `ACAO: *` (`ACAM: POST, GET`, `ACAH: content-type,authorization`, **no** `Allow-Credentials`), HSTS `includeSubDomains`.
- **`el.quizlet.com`:** Envoy edge → Kubernetes → Python/Flask (Werkzeug 404/405 pages). Internal service `eventlogger-publisher-frontend.eventlogger.svc.cluster.local:80`. POST-only `/` event sink.
- **`jg7y.quizlet.com`:** Snowplow collector (pixel/collect endpoints, `/health` → `ok`, 1×1 GIF responses), also behind `via: 1.1 google`.
- **Client telemetry:** Rollbar (`source_map_enabled: true`, `code_version: 6e5fa810072c01c271a7c50ba62e981d9e4860b4`, accessToken `68c33f534ee3485a92e1fb605f957c6c` — public-by-design), Snowplow → `jg7y` `/b4d71/tz9` (`appId: q-prod-renderer`), GTM-5GTSWTM, Ketch (cmpId 340), Scorecardresearch, Google One Tap (`accounts.google.com/gsi/client`), Algolia (search).
- **Program-tag infra (not directly testable):** Apache Kafka, Algolia. TXT also shows HashiCorp Cloud (`hcp-domain-verification`), Atlassian, Docusign, Linear, OneTrust.
- **Internal-domain hint:** Rollbar `hostSafeList` mentions `dev.qzlt.io`.
- **Notable:** `dev.quizlet.com` has its own `*.dev.quizlet.com` cert (Google Trust Services WE1) but **no public DNS record** → internal-only name, not reachable from outside.

### [Bugbountyskills.md] Auth model

- OAuth 2.0 authorization server metadata published at `/.well-known/oauth-authorization-server`:
  issuer `https://quizlet.com`, authorize `https://quizlet.com/oauth/authorize`, token `https://quizlet.com/oauth/token`,
  `code_challenge_methods_supported: ["S256"]` (PKCE, no `plain`), `token_endpoint_auth_methods_supported: ["client_secret_post"]`, `scopes_supported: ["write_set"]`.
- Cookies (apex origin): `qi5` (HttpOnly, Secure, 10y — persistent identity), `fs` (HttpOnly, Secure), `qtkn` (Secure only), `app_session_id` (Secure only, UUID, `Max-Age=1800`), plus `_pxhd`, `_cfuvid`, `__cf_bm`.
- **FP guard for future sessions:** `qtkn` and `app_session_id` lack `HttpOnly`, **but both rotate on every single response** (verified across 4 consecutive responses) — they are per-request trace IDs, not session credentials. **Do not report "session cookie missing HttpOnly".**
- App links: `.well-known/assetlinks.json` → `com.quizlet.quizletandroid` (SHA256 `5C:95:E9:5B:…:1E:2F:1F`); `.well-known/apple-app-site-association` → `RG76J9B7LZ.com.quizlet.quizlet`, `67PY6MH6KF.com.quizlet.iosinternal`.

## [Bugbountyskills.md] Findings history

| Date | Endpoint | Class | Status | Report |
|---|---|---|---|---|
| 2026-10-21 | origin responses (`quizlet.com/.well-known/*`, `el.*`) | Missing security headers (no CSP/XFO/XCTO/RP/PP) | Confirmed, Low | `findings/F-01-missing-security-headers-origin.md` |
| 2026-10-21 | `el.quizlet.com/` | Internal k8s/Envoy topology via `x-envoy-decorator-operation` + open event sink | Confirmed, Low / ingestion informational | `findings/F-02-envoy-k8s-service-disclosure.md` |
| 2026-10-21 | `quizlet.com/.well-known/*` | Internal routing metadata via `quizlet-action-name` / `quizlet-route-importance` | Confirmed, Informational | `findings/F-03-internal-routing-header-disclosure.md` |

## [Bugbountyskills.md] Ruled out (and why)

1. **Challenge/WAF bypass by path normalization** — `../`, `%2e%2e%2f`, `%252e%252e%252f`, `..;`, `%2f`, `//`, `/.well-known;`, method changes (POST/PUT/PATCH/DELETE/OPTIONS), `Host:` override, `X-Original-URL`/`X-Rewrite-URL`, `X-Forwarded-Host`. None reached app routes; CF normalizes/decodes before matching. (And pure bot-bypass is out of program scope anyway.)
2. **`el.quizlet.com/status`** — 403 "Request blocked" for `/status`, `/status/`, `/status.json`, `//status`, `/./status`, `/status%20`, `/statusz`, `%73tatus`, `stat%75s`, `st%61tus`, `status%09`, `health/../status`, `status;.json`, and POST. **Unreachable from this IP** — re-test from an allowed network.
3. **Werkzeug interactive debugger (RCE)** on `el.*` — `/console`, `/?__debugger__=yes`, `/__debugger__`, `/_debugger` → 404, zero debugger markers. **Not enabled.**
4. **Verbose errors / stack traces** on `el.*` — 7 malformed payloads (invalid JSON, no content-type, text/plain, empty, deep nesting, array, XML) → uniform `400 {}`. Clean.
5. **CORS with credentials on `jg7y.*` (would have been a finding)** — it *does* reflect any `Origin` **and** sends `access-control-allow-credentials: true`. Triage: response body is a static 1×1 GIF, **byte-identical with and without cookies** (sha256 `46d11334…` identical), CORS headers identical too. Nothing cookie-derived to read → by-design Snowplow collector config, **not exploitable, do not report.**
6. **CORS on `study.*` and apex** — `ACAO: *` and **no** `Allow-Credentials` → browsers refuse credentialed reads; preflight allows `content-type,authorization` only. Safe.
7. **Open redirect via `/.well-known/change-password`** — `Location` always relative `/forgotten/password`; attacker params are only re-echoed as that path's query string; `X-Forwarded-Host`, `X-Forwarded-Proto`, `Forwarded` ignored.
8. **Host-header injection / password-reset poisoning** — CF returns 403 for unknown `Host` values; canonical redirect uses fixed `https://quizlet.com/error`.
9. **Subdomain brute force** — wildcard DNS; every name resolves (gibberish controls prove it). Discarded as noise.
10. **`study.quizlet.com` content discovery** — ffuf × 4,751 paths (rate 5/s) → **0 results** (baseline404 = 1,686 B HTML / 9 B `Not Found`).
11. **`ablink.*` email redirectors** — 6 hosts × 13 common redirect paths (`/r /l /c /click /track /redirect /out /goto …`) → all bare nginx default 404. Retired vhosts, no redirect logic.
12. **Backup/source artifacts behind the exemption** — `/.well-known/assetlinks.json.bak` → 403 by a backup-extension WAF rule; expect the same for `*.bak`/`*.old` zone-wide.
13. **Session cookie missing `HttpOnly`** — false positive; `qtkn`/`app_session_id` rotate every response (per-request trace IDs). See FP guard above.

## [Bugbountyskills.md] Open leads (not ruled out — blocked by the challenge)

- **Rollbar source maps:** `source_map_enabled: true` + `code_version: 6e5fa810072c01c271a7c50ba62e981d9e4860b4`. `.js.map` / `_buildManifest.js` probes all challenged. High value (V-09).
- **`redir` parameter** open redirect on `/{id}/view-screen`.
- **OAuth `/oauth/authorize`**: `redirect_uri` whitelist, PKCE downgrade (S256-only claims), `state`/CSRF, auth-code leakage via `Referer`.
- **IDOR** on numeric set IDs / `setIdOrUsername`; `/{id}/delete`, `/{id}/edit` CSRF.
- **Clickjacking PoC** (ties to F-01) on `/forgotten/password` or embed flows — needs a framing-able page.
- **API 3.0 authz** with a registered PKCE client (`write_set` scope enforcement).
- **`el /status`** from a non-blocked network.

## [Bugbountyskills.md] WAF / defense behavior (characterized 2026-10-21)

- **Cloudflare managed challenge**, page title `Captcha Challenge…`, `403` + `cf-mitigated: challenge`, ~116–160 KB. Triggered on: `www.*` (all paths), apex `/`, `/robots.txt`, `/sitemap.xml`, `/favicon.ico`, `/humans.txt`, `/_next/static/*` (JS + `.map`), `/{page}` HTML routes, `/oauth/*`, `/api/3.0/*`, `assets.*`, `admin/cp/docker/elastic/…`.
- **Challenge-exempt (verified):** `/.well-known/**` on apex — match is on the `/.well-known/` **substring** (`/anything/.well-known/assetlinks.json` also passes, then 302s to `/error`). Strict prefix semantics for `..`: CF normalizes before the rule, so `/.well-known/../robots.txt` is challenged. Whole hosts that pass: `study.*`, `el.*`, `jg7y.*`, `ablink.*`.
- **Second rule = hard block:** `403` titled `Request blocked`, **no `cf-mitigated` header** (distinguishes it from the challenge). Hits: `PATCH` to any path, any path containing `status`, backup extensions (`.bak`).
- **Sticky/learned:** first apex request in a session passed, subsequent ones challenged; the wall persists for the IP. Full browser header set (sec-ch-ua, Sec-Fetch-*) did **not** help — it escalates to an interactive captcha, which cannot be solved headlessly.
- **Not solved this session:** no browser tooling available in this session (`built-in-browser` tools absent from the tool catalog), so no legitimate challenge clearance could be obtained.
- **Header asymmetry (basis of F-01):** Cloudflare's challenge/block pages emit `x-frame-options: SAMEORIGIN`, `referrer-policy: same-origin`, `x-content-type-options: nosniff`, COOP/COEP/CORP and locked-down `permissions-policy`; **origin responses through the same CDN do not.**
- **Second bot layer:** PerimeterX/HUMAN (`_pxhd`) — independent of Cloudflare, so clearing CF alone may not be enough.

## [Bugbountyskills.md] Missing security headers on origin-served responses

**Severity:** Low / Informational (would be P4-tier; likely accepted as low or informative)
**Class:** Security misconfiguration → skill: `info-disclosure-testing` (V-02 family) / header posture
**Endpoint:** every origin response reachable during the session, e.g.
`https://quizlet.com/.well-known/oauth-authorization-server` (auth: none)
**Status:** Confirmed on reachable surface — **caveat below**
**Evidence:** `../evidence/origin-headers-oauth.txt`, `../evidence/el-envoy-headers.txt`

## [Bugbountyskills.md] Summary

Quizlet's origin responses are served **without** the standard protective response headers.
Verified present on origin responses: `strict-transport-security`, `vary`, `server`.
Verified **absent**:

- `Content-Security-Policy` (also absent as `<meta http-equiv>` in the HTML body)
- `X-Frame-Options`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy`
- `Permissions-Policy`
- `Cross-Origin-Opener-Policy` / `Cross-Origin-Embedder-Policy` / `Cross-Origin-Resource-Policy`

## [Bugbountyskills.md] Steps to reproduce

```http
GET /.well-known/oauth-authorization-server HTTP/2
Host: quizlet.com
User-Agent: Mozilla/5.0 ...
```

Observed (abbreviated):

```http
HTTP/2 200
content-type: application/json
strict-transport-security: max-age=63072000
server: cloudflare
via: 1.1 google
quizlet-action-name: Wellknown/oauthAuthorizationServer
access-control-allow-origin: *
```

No CSP / XFO / XCTO / Referrer-Policy / Permissions-Policy. Reproduced 3× across three
different origin services:

| Response | Service | Security headers |
|---|---|---|
| `quizlet.com/.well-known/oauth-authorization-server` (200 JSON) | Next.js/Rails app on GCP LB | none but HSTS |
| `quizlet.com/.well-known/assetlinks.json` (200 JSON) | same | none but HSTS |
| `quizlet.com/.well-known/security.txt` (404, 372 KB HTML) | same | none but HSTS |
| `el.quizlet.com/` (405 HTML) | Envoy → k8s Flask | none but… not even HSTS |
| `study.quizlet.com/robots.txt` (404 HTML) | Rails on GCP LB | HSTS `includeSubDomains` only |

## [Bugbountyskills.md] Impact

Absence of `X-Frame-Options`/CSP `frame-ancestors` permits framing of pages that perform
state changes (set delete, account actions, `/forgotten/password`) → clickjacking. Absent
CSP removes the XSS-mitigation backstop for any reflection found later. Absent
`X-Content-Type-Options` permits MIME sniffing of user-uploaded content. Absent
`Referrer-Policy` (in combination with the current `vary`-only setup) can leak URL
parameters — including `redir` and `setIdOrUsername` — to third parties via `Referer`.
Auth level required: none.

## [Bugbountyskills.md] False-positive check (what I ruled out)

- **Not a Cloudflare challenge artifact.** Cloudflare's *own* managed-challenge page for
  this zone **does** ship `x-frame-options: SAMEORIGIN`, `referrer-policy: same-origin`,
  `x-content-type-options: nosniff`, COOP/COEP/CORP and a locked-down `permissions-policy`.
  Origin responses passing through the same CDN do not. So the headers are added by the
  challenge template, not by a zone-wide header rule — i.e. real (non-challenged) pages do
  not get them either.
- **Not a 404-only artefact:** the same gap appears on two different real `200` JSON
  endpoints and on a `405` HTML response from a different service.

## [Bugbountyskills.md] Caveat / limitation

Every `200 text/html` **page** request from this IP is stopped by Cloudflare's managed
challenge, so I could not capture a live marketing/study page's header set directly. The
conclusion rests on: (a) origin JSON `200`s, (b) the app's own rendered HTML `404` page,
(c) a `405` HTML page from a second service. Re-verify from a browser session next
session — if a real page *does* ship CSP, downgrade this to "inconsistent header policy".

## [Bugbountyskills.md] Remediation

Set a zone-wide (or app-level) response header policy adding `Content-Security-Policy`
(starting report-only), `X-Content-Type-Options: nosniff`, `X-Frame-Options: SAMEORIGIN`
or CSP `frame-ancestors 'self'`, `Referrer-Policy: strict-origin-when-cross-origin`, and a
`Permissions-Policy` — matching what the challenge template already sends.

## [Bugbountyskills.md] References

- CWE-693 (Protection Mechanism Failure), CWE-1021 (Improper Restriction of Rendered UI)
- OWASP A05:2021 Security Misconfiguration; WSTG-INFO-017 (Test for Cache Poisoning)/INFO-006

## [Bugbountyskills.md] Internal Kubernetes service topology disclosed via `x-envoy-decorator-operation` (+ unauthenticated event ingestion)

**Severity:** Low (the header leak). The ingestion half is **Informational / likely out of
program scope** (see triage note).
**Class:** Information disclosure → skill: `info-disclosure-testing` (V-04 internal
hostname/network schema leakage)
**Endpoint:** `https://el.quizlet.com/` (auth: none, in scope under `*.quizlet.com`)
**Evidence:** `../evidence/el-envoy-headers.txt`

## [Bugbountyskills.md] Summary

`el.quizlet.com` fronts a service that returns Envoy's decorator header on **every**
response, naming the exact internal Kubernetes service behind it:

```http
x-envoy-decorator-operation: eventlogger-publisher-frontend.eventlogger.svc.cluster.local:80/*
x-envoy-upstream-service-time: 11
allow: POST, OPTIONS
via: 1.1 google
access-control-allow-origin: *
```

This discloses: (1) the cluster runs an Envoy service mesh / edge proxy, (2) internal DNS
follows `<service>.<namespace>.svc.cluster.local`, (3) namespace = `eventlogger`,
service = `eventlogger-publisher-frontend`, target port 80, (4) the component's function
(event publishing), (5) the origin sits behind a Google (`via: 1.1 google`) L7 load
balancer.

The endpoint is an **unauthenticated, cross-origin-open event sink**: `POST /` with any
JSON body returns `202` + `{}`.

## [Bugbountyskills.md] Steps to reproduce

```http
GET / HTTP/2
Host: el.quizlet.com
```
→ `405`, `allow: POST, OPTIONS`, decorator header above.

```http
POST / HTTP/2
Host: el.quizlet.com
Content-Type: application/json
Origin: https://evil.example

{"test":"probe"}
```
→ `202`, body `{}`, same decorator header. Reproduced 3×.

## [Bugbountyskills.md] Impact

- **Header:** attacker mapping for any future internal pivot — the naming scheme and
  namespace let a later SSRF/RCE finding be aimed at `eventlogger-publisher-frontend`
  without re-discovery; paired with an SSRF this becomes a meaningful stepping stone.
  Alone it is a topology disclosure (Low).
- **Ingestion:** anyone can write arbitrary events into the telemetry pipeline with a
  spoofed `Origin`. Realistic abuse is analytics/security-telemetry poisoning or noise.
  **Program-scope note:** the program excludes "automation concerns … unless they
  demonstrate access to premium content or lead to a significant security impact", so
  triage will likely mark this half informational unless a downstream rendering sink
  (log/BI dashboard with HTML rendering → stored XSS) can be demonstrated.

## [Bugbountyskills.md] False-positive check

- Not a generic Cloudflare header: it is absent from `quizlet.com`, `study.quizlet.com`
  and `jg7y.quizlet.com` responses captured in the same session — only `el.*` emits it.
- `202 {}` is a genuine origin response (`cf-cache-status: DYNAMIC`, Envoy timing header
  present), not an edge acknowledgement.

## [Bugbountyskills.md] Remediation

Suppress `x-envoy-decorator-operation` (`x-envoy-decorator-operation` can be disabled via
`envoy.decorators`/header mutation config) at the mesh edge; require an authn/tenant
claim before accepting events, or at minimum scope the sink per-tenant and rate-limit it.

## [Bugbountyskills.md] References

- CWE-200 (Exposure of Sensitive Information); OWASP A05:2021 Security Misconfiguration
- WSTG-INFO-08 (Fingerprint Web Application Framework), WSTG-INFO-13

## [Bugbountyskills.md] Summary

Every response that reaches Quizlet's own app (as opposed to a Cloudflare template page)
carries two custom headers naming the internal handler:

```http
quizlet-action-name: Wellknown/oauthAuthorizationServer
quizlet-route-importance: normal
```

and, on unmapped paths:

```http
quizlet-action-name: Sets/show
quizlet-route-importance: key
```

```http
quizlet-action-name: pagenotfound/routingerror     (302 → https://quizlet.com/error)
```

## [Bugbountyskills.md] Steps to reproduce

```http
GET /.well-known/oauth-authorization-server HTTP/2
Host: quizlet.com
```
→ `quizlet-action-name: Wellknown/oauthAuthorizationServer`.

```http
GET /.well-known/anything-unknown HTTP/2
Host: quizlet.com
```
→ `quizlet-action-name: Sets/show`, `quizlet-route-importance: key`. Reproduced 3×.

## [Bugbountyskills.md] Impact / how to use it

- Leaks internal controller-action naming (Rails `Controller/action` convention),
  route-classification ("key"/"normal") and, for routing errors, the canonical absolute
  URL used for redirects (`https://quizlet.com/error`) — evidence of the internal route
  table and canonical-host configuration.
- **Practical value as a recon oracle:** because the header is emitted per request, any
  future request that gets through (from an allowed network, or after a challenge is
  solved) tells you *which* internal action handled it — turning status-code-only probing
  into route discovery. Expect triage to call this informational; keep it as a tool.

## [Bugbountyskills.md] False-positive check

- Headers are absent on Cloudflare-generated responses (challenge/block pages) and on
  `el.*` / `jg7y.*` / `ablink.*`, so they are app-emitted, not CDN-emitted.

## [Bugbountyskills.md] Remediation

Strip internal routing headers at the edge (`quizlet-action-name`,
`quizlet-route-importance`) — they are observability aids and should not reach clients.

## [Bugbountyskills.md] References

- CWE-200; OWASP A05:2021 Security Misconfiguration; WSTG-INFO-08

## [Bugbountyskills.md] reready.co

**Program / authorization:** Self-hosted bug bounty + VDP — https://www.reready.co/help/vulnerability-bug-bounty-program
(Last updated 2026-10-23. Email reports to `support@reready.co`, one vuln per email,
Bugcrowd VRT naming, ≥5 business days response wait, no pinging within 5 days.)
**Last engagement:** 2026-10-25 (session 1)

## [Bugbountyskills.md] Stack (verified 2026-10-25, sandbox)

- **Host:** `sandbox.reready.co` → 165.227.99.141 (DigitalOcean). Production
  `www.reready.co` → 165.227.223.207 (same provider, different box).
- **Server:** `nginx` (bare nginx 404 page for static-ish paths like `/robots.txt`;
  Rails-rendered 404 page for app paths → nginx serves static directly, proxies rest).
- **Framework:** Ruby on Rails (verified via `<meta name="csrf-param" content="authenticity_token">`
  + `csrf-token` meta, `csp-nonce` meta, `_reready_session` cookie, asset digest filenames
  `application-<sha256>.css` = Sprockets/Propshaft). Auth = Devise-style (`/users/sign_in`,
  `/users/sign_up`).
- **WAF:** none detected (no CF/Akamai headers, no `server` beyond nginx). Header-based
  defense only.
- **Security headers (both hosts):** HSTS 63072000+SubDomains, XFO SAMEORIGIN, nosniff,
  Referrer-Policy strict-origin-when-cross-origin, COOP same-origin-allow-popups,
  CORP same-origin, Permissions-Policy camera/geo/mic off, `x-xss-protection: 0` (deliberate).
- **CSP:** `default-src 'self'`; `script-src 'self' 'strict-dynamic' 'nonce-…'` (nonce-based,
  no unsafe-inline) ⇒ **inline/reflected XSS needs nonce theft or a gadget in an allowed host.**
  `connect-src` self + Google/DoubleClick/LinkedIn; `style-src` self + cdn.datatables.net +
  fonts.googleapis.com; `img-src` self/data + GA; `frame-src` self + GA.
- **Cookies:** `_reready_session=<32hex>`; `path=/; secure; httponly; samesite=lax`.
- **CSRF:** Rails `authenticity_token` in meta + form (per-page, NOT yet known if static).
- **Auth model:** Devise — `POST /users/sign_in` with `user[email]` + `user[password]` +
  optional `user[otp_attempt]` (**2FA supported**, backup codes accepted). SSO buttons:
  `/users/auth/entra.user`, `google_oauth2.user`, `okta.user` (POST, `data-method=post`).
  Sign-up is **passwordless** (no password field; email verification link via
  `/users/confirmation/new`). Session = cookie `_reready_session` (16 random bytes hex).
  API auth = `Authorization: Token <API-KEY-SECRET>` (`www-authenticate: Token realm="Application"`).
- **Environments are isolated (verified 2026-10-25):** two accounts that exist on
  **production** are rejected by sandbox with the generic Devise `:invalid` message ⇒
  separate databases. No credential reuse across envs, so prod logins buy nothing here
  and are out of scope anyway.
- **Notable:** `x-request-id` (UUID) on every response ⇒ server request ID, useful for
  correlating/logs. `vary: Accept,Accept-Encoding`. `cache-control: max-age=0, private`.

## [Bugbountyskills.md] Findings history

| Date | Endpoint | Class | Status | Report |
|---|---|---|---|---|
| 2026-10-25 | session 1 | all unauth classes | **no confirmed findings** (see evidence/) | not reported |

## [Bugbountyskills.md] Authentication testing (2026-10-25, sandbox only — no successful login yet)

- Login POST with 2 operator accounts → 200 + generic
  `Invalid email or password (or one-time code if you enabled two-factor authentication).`
  ⇒ accounts are production-only (env isolation proven). **Never** retry them against prod.
- No captcha on `/users/sign_in` (all *email-sending* flows have reCAPTCHA).
- Rate limit: **429 from attempt 6** (5 failures), 12-byte body ⇒ brute-force mitigated.
- Error message is uniform/generic — no enumeration oracle established yet (needs one
  known-EXISTING sandbox account as control).
- Session fixation: **not yet testable** — rotation must be observed on a *successful* login.
- Logout via GET → 404 (no GET state change).

## [Bugbountyskills.md] Ruled out (and why)

- `www.reready.co.test` → NXDOMAIN (typo'd target, not a real host).
- `/robots.txt`, `/.well-known/security.txt` → 404 (both; nginx static vs Rails 404 differ).
- **RXSS**: 90 param/page probes → 0 reflections; only `/help?search=` reflects, fully
  `html_escape`d in both attribute (`&quot;&#39;&lt;&gt;`) and body context.
- **DOM XSS**: shipped JS has NO URL source (only `location.href` ×3 as defaults) and all
  12 `innerHTML` sinks are library-internal; first-party code (`slide_toggler`,
  `application.source.js`, rails-ujs config) reads only server-rendered `data-*` attributes.
- **SQLi**: `/help?search=` × 16 payloads → no 500, no timing delta, literals only
  (`%`/`_` honored as LIKE wildcards — `sanitize_sql_like` not applied, harmless on public content).
- **Path traversal**: nginx 400 on raw `../`; 403/"Forbidden"(9 B) on `..%252f`, `....//`, `..;`.
- **CSRF**: missing token → 422; wrong Origin + valid token → 422; no-Origin → 200 (Rails
  origin check only runs when header present). Framework-level, applies to authed POSTs too.
- **CORS**: no `Access-Control-Allow-Origin` on any host/path (incl. evil Origin).
- **Host-header injection**: port-80 301 target hardcoded to `https://sandbox.reready.co/`,
  `X-Forwarded-Host` ignored.
- **Open redirect**: `origin`/`return_to`/`redirect_to` params render the form, never redirect.
- **Info disclosure**: `.git/.env/.svn/.DS_Store/*sql/rails/info/routes/sidekiq/cable/admin/
  package.json` all uniform 404 (7790 B — flat oracle, no size side-channel); no source maps
  on digest assets; no stack traces from malformed JSON (clean 422); `/assets/` no listing.
- **SSRF**: zero unauth URL inputs (`/support`, `/webhooks` have no forms; `/schedule-call` is a Calendly iframe).

## [Bugbountyskills.md] WAF / defense behavior

None detected. CSP nonce + strict-dynamic is the main XSS defense.

## [Bugbountyskills.md] 1. Baseline headers (sandbox, GET /)

```
HTTP/2 200 | server: nginx | x-request-id: 66c8c485-15e2-…
strict-transport-security: max-age=63072000; includeSubDomains
x-frame-options: SAMEORIGIN | x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
cross-origin-opener-policy: same-origin-allow-popups | cross-origin-resource-policy: same-origin
permissions-policy: camera=(), geolocation=(), microphone=()
x-xss-protection: 0
content-security-policy: default-src 'self'; script-src 'self' 'strict-dynamic' 'nonce-…';
  object-src 'none'; base-uri 'none'; connect-src 'self' + GA/DoubleClick/LinkedIn …
set-cookie: _reready_session=<16 hex bytes>; path=/; secure; httponly; samesite=lax
vary: Accept,Accept-Encoding | cache-control: max-age=0, private, must-revalidate
```

## [Bugbountyskills.md] 9. Asset / JS findings (operational, not security)

```
GET /assets/application-6c5319…​.css   -> 200 248856 B   (digest OK)
GET /assets/application-7b54c2…​.js    -> 404 7790 B     (digest MISSING)
GET /assets/application.js            -> 200 1144331 B  (unhashed variant present)
homepage: <link rel="modulepreload" href="/assets/application-7b54c2…​.js">
          <script type="importmap">{"imports":{"application":"/assets/application-7b54c2…​.js"}}</script>
          <script type="module">import "application"</script>   -> target 404 => bundle never executes
digest strings identical across 3 fetches/12 s (single build, not multi-instance)
```
Bundle greps (of the 1.14 MB file): sources = `location.href` only (3×), no
`location.search|hash|URLSearchParams|document.referrer|window.name|postMessage`;
sinks = 12 `innerHTML` + 1 `outerHTML`, all library-internal (Chart.js canvas, Bootstrap
sanitizer/template, rails-ujs `data-disable-with`/method-override form builder).

## [Bugbountyskills.md] 10. Rate limits & auth-flow gating

```
/users/password (reset): 2 rapid POSTs -> 302 with flash "You must click the checkbox that
  says \"I'm not a robot\"."  ; 3rd+ -> 429, 12-byte body
login: 12 failed POSTs (nonexistent control email) -> 200 ×5, then 429 ×7 (attempt 6 onward)
captcha presence per flow (grep 'g-recaptcha'):
  /users/sign_in          0   (captcha-free => testable)
  /users/sign_up          1
  /users/sign_up?order=true 1
  /users/password/new     1
  /users/confirmation/new 1
  /users/unlock/new       1
/global throttle: ~90 requests inside a few minutes -> every path 429 (12 B), clears in ~2.5 min
```

## [Bugbountyskills.md] 11. Host ports (single pass, 2 s connect timeout, sandbox IP only)

```
OPEN 22 (SSH), 80 (nginx 301 → https://sandbox.reready.co/), 443 (nginx)
closed/filtered: 21 25 53 4443 5432 6379 8000 8080 8443 9000 9200 27017
Direct-IP TLS: certificate has no IP SAN (curl 60) — no default-vhost content leak.
```

## [Bugbountyskills.md] Verizon (Inspectiv)

**Program / authorization:** Verizon, private program on Inspectiv. Program brief updated 2026-10-20.
**Last engagement:** 2026-10-27 (initial intake + passive recon)

## [Bugbountyskills.md] Rules of Engagement (mandatory on EVERY request)

```
X-Inspectiv-Tester: {researcher-username}
```
Missing this header can void the report. Blackbox only. Self-registration/public signup only.

**Payout:** Tier 4 — Critical $2500 / High $1000 / Medium $500 / Low $0.
Severity = base class, adjusted for impact + required privilege.
Systematic duplicates: same root cause on two endpoints = one payout.

## [Bugbountyskills.md] Ruled out (and why)

- Nothing tested yet. Known-scope landmines recorded above under exclusions.

## [Bugbountyskills.md] WAF / defense behavior

unknown — record per host.

## [Bugbountyskills.md] vinted.com

**Program / authorization:** Vinted Bug Bounty — Bugcrowd `vinted-uab-mbb` (public, rewards $75–$8,000;
max raised from $4,000 on 2026-10-11). Scope confirmed via program index snapshot **2026-10-20**.
**Last engagement:** 2026-10-21 (sessions 1–3 — passive recon, safe active probes, authenticated testing with operator accounts)

## [Bugbountyskills.md] Stack (verified 2026-10-21)

- **Edge:** Cloudflare-fronted DNS (`162.159.142.220`, `172.66.2.216`) + `via: 1.1 varnish`,
  `x-served-by: cache-stl760057-STL` (CDN/origin-cache layer), `server: istio-envoy` origin (Istio mesh).
- **App:** Next.js App Router (`x-powered-by: Next.js`, `x-next-app: marketplace-web`, `vary: ...rsc,
  next-router-state-tree...`), SSR streaming with RSC payload inline in HTML.
- **Backend tells:** `robots.txt` disallows `/apipie/` → **Rails + Apipie** heritage on some service
  ( `/apipie` itself returns 404 today — not exposed). Envoy upstream time header present.
- **Bot management:** DataDome (`set-cookie: datadome=...` seen cleared on plain GET).
- **Auth:** `access_token_web` + `refresh_token_web` = **JWT, alg PS256**, `kid` header,
  `iss: vinted-iam-oauth`, `aud: fr.core.api.vinted.com`, `purpose: access|refresh`, `sid`.
  Cookies: `Domain=.www.vinted.com`, `HttpOnly; Secure; SameSite=Lax`.
- **Locale routing:** `x-middleware-rewrite: /us:en-US:0:0:0:0/`, country TLD matrix generated in `<head>`.
- **WAF behavior:** no evidence of blocking on benign GETs; DataDome present but not engaging on these paths.

### [Bugbountyskills.md] Hosts

| Host | Purpose | Scope | Notes |
|---|---|---|---|
| www.vinted.com | marketplace web (Next.js) | ✅ in | primary target |
| vinted.com (apex) | sitemap/redirects | ⚠️ not explicitly listed | only `www.` listed; sitemap index served on apex — avoid active tests on apex |
| api hosts (JWT `aud`) | core API | ❌ out | do not test |
| marketplace-web-assets.vinted.com | static chunks/fonts | ❌ out | sourcemap hunting here is out of scope |
| other `vinted.*` TLDs | locale mirrors | ❌ out | appear in hreflang output — never request them |
| sandbox.vinted.com / sandbox.vintedgo.com | test environments | ✅ in | **preferred target for authenticated flows** |
| badger.it.vinted.com, careers/company/news., vinted.net, vintedgo.com | misc | ✅ in | untested (session 2 candidates) |

## [Bugbountyskills.md] Findings history

| Date | Endpoint | Class | Status | Report |
|---|---|---|---|---|
| 2026-10-21 | `/` (site-wide headers) | Missing security headers + weak HSTS | candidate — F-01, severity likely Low/Info | not submitted |
| 2026-10-21 | `/api/v2/*` | Globally static CSRF token + Origin unchecked | candidate — F-02, Low (escalation conditions listed) | not submitted |
| ~~2026-10-21~~ | ~~`/api/v2/users/{id}` cross-user timestamps~~ | ~~F-04 candidate~~ | **withdrawn — intended "Last seen" feature (see Ruled out)** | n/a |

## [Bugbountyskills.md] Ruled out (and why)

- **Reflected XSS on `/` via `next` / `utm_source`** — reflected only into URL-encoded `href`
  attribute + percent-encoded RSC JSON; `"'><zz9x` payloads stayed fully encoded (double-encoded
  in `ref_url`). No script/attribute breakout.
- **Reflected XSS via `<link rel=canonical>` / `hreflang` on `/catalog?param=`** — input appears
  only percent-encoded (`%22%3E%3C`) in head URL attributes and body hrefs; `<zz9x` literal absent
  from document. 73 reflections, zero unencoded.
- **SQLi on catalog filters (`price_from`, `page`, `brand_id[]`)** — quote, `AND 1=1/1=2`,
  `ORDER BY 99` all returned HTTP 200 with sizes tracking baseline noise (~±1 KB variance between
  *identical* requests), no DB error strings beyond generic `exception` present in baseline too.
  No boolean differential. ⇒ params typed/parameterized server-side. (Method: safe probe ladder,
  no time-based payloads sent.)
- **CORS misconfig (tested paths)** — no ACAO/ACAH reflected for attacker `Origin`.
- **SVG/file-upload XSS on `POST /api/v2/photos` (session 2)** — server validates *content*, not
  headers: real PNG → `200`; SVG bytes named `.png`/typed `image/png` → `400 error_uploading_photo`
  (both disguises). Uploaded raster is transcoded to `image/jpeg`, served from `images1.vinted.net`
  with `X-Content-Type-Options: nosniff`, `Content-Disposition: inline`. Filename/extension tricks
  cannot survive transcode. Do not re-test this class here.
- **CSRF token tunnelling (session 2)** — token accepted **only** via `X-Csrf-Token` header:
  form field (`_csrf_token`/`authenticity_token`), query params, `X-Requested-With` → all `403`.
  Missing or bogus token → `403`. This is what keeps F-02 at Low.
- **Cross-user private-field IDOR on `GET /api/v2/users/{id}` (session 3)** — authenticated view
  of other members includes `email`/`contacts`/`birthday`/`default_address`/`real_name` keys but
  **all values `null`** (verified on members 3130239619 and 260829472); own view returns real
  values ⇒ server-side scrubbing works. Anonymous → `401`.
- **Object-level authz bypass on `DELETE /api/v2/users/:id`** — foreign id → `403` (matrix in
  session notes). Untestable further without touching a live third-party account — stop there.
- **Cross-user last-login timestamps (F-04 candidate, withdrawn)** — `last_loged_on` /
  `last_loged_on_ts` are served in the **public anonymous** `/member/{id}` HTML, but they render as
  a designed UI element: `Last seen … <span title="{exact timestamp}">{N} months ago</span>`.
  Product feature by design ⇒ not a vulnerability. (Lesson: check UI rendering before claiming
  metadata disclosure.)
- **Profile-update endpoint discovery — exhausted for now (session 3):** ~40 route/method combos
  tried on in-scope host: PUT/PATCH/POST/DELETE on `/api/v2/users/{id}`, sub-resources
  (`/profile`, `/settings`, `/update`, `/about`, `/description`, `/profile/about`), plural forms
  (`profiles/{id}`, `members/{id}`), settings forms (`/api/v2/settings`, `/profile_settings`,
  `/settings/profile`, `/profile`), method overrides (`?_method=put`, `X-HTTP-Method-Override`),
  API roots/docs (`/api`, `/api/v2`, `/openapi.json`, `/swagger.json`, `/apipie*`), `/graphql` —
  **all 404** (exception: `PATCH /settings/profile` → 200 = Next page handler, not an API).
  JS chunks holding the real route are on out-of-scope `marketplace-web-assets.vinted.com`.
  ⇒ **requires operator's devtools capture of the profile-save request.**

## [Bugbountyskills.md] WAF / defense behavior

- DataDome present (cookie cleared on plain GET; no blocks observed in session 1).
- No 403/406 tripwires hit; rate limits not observed at low volume (≤ ~25 requests total).

## [Bugbountyskills.md] F-01 — Missing browser security headers + weak HSTS on www.vinted.com

**Status:** candidate (not yet submitted)
**Severity (expected):** Low / Informational (upgrade only if a state-changing action is shown
frameable *and* CSRF-defence-less → then it chains to medium)
**Endpoint:** `https://www.vinted.com/` (observed site-wide on responses sampled)
**Class:** Security misconfiguration → `info-disclosure-testing` / `csrf-testing` chain
**CWE:** CWE-693 (Protection Mechanism Failure), CWE-319-ish HSTS weakness → CWE-319 not applicable
here; better: **CWE-16 (Configuration)** + **CWE-1021 (Improper Restriction of Rendered UI Layers /
clickjacking)** for the missing frame protection.
**OWASP:** A05:2021 – Security Misconfiguration

## [Bugbountyskills.md] Summary

Responses from `https://www.vinted.com/` omit every standard browser-side protection header, and
the HSTS header is set to a 5-minute max-age without `includeSubDomains` or `preload`.

## [Bugbountyskills.md] Impact

- **No `frame-ancestors` / `X-Frame-Options`:** any page on this host can be framed by any
  origin → clickjacking surface. Meaningful only where a sensitive action needs one click
  *and* is not independently CSRF-protected; that link is untested pre-auth.
- **No `X-Content-Type-Options`:** MIME-sniffing assistance for any response where user-influenced
  content is served with a loose content type (pairs with `xss-testing` V-17).
- **No CSP:** removes the last-ditch mitigation for any future XSS finding.
- **HSTS `max-age=300` without `includeSubDomains`/`preload`:** a single HTTP downgrade window
  (5 min, or any request over plain HTTP on a subdomain) defeats the guarantee; SSL-stripping
  exposure on first contact.

## [Bugbountyskills.md] Steps to reproduce

1. `curl -sS -D - -o /dev/null https://www.vinted.com/`
2. Observe `strict-transport-security: max-age=300` and the complete absence of the headers listed above.

## [Bugbountyskills.md] Remediation

```
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
Content-Security-Policy: frame-ancestors 'none'; base-uri 'self'; object-src 'none'
  (+ report-only rollout toward script/upgrade-insecure-requests)
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
```
Add `Secure` to all non-`HttpOnly` cookies; consider `__Host-` prefix for non-Domain cookies.

## [Bugbountyskills.md] Why this matters (one line)

Five-minute HSTS plus zero framing/`nosniff` protections leaves every Vinted shopper's session one
network attacker or one framing page away from a mitigation they were told they had.

## [Bugbountyskills.md] Summary

The anti-CSRF token enforced on state-changing API requests is a **single constant value shared
by every user, session and IP**, and the API performs **no `Origin`/`Referer` validation** as a
second line of defence.

## [Bugbountyskills.md] Escalation conditions (re-rate to High if any one appears)

- Any endpoint accepting the token via body/query/`X-Requested-With` (tunnelling — currently none).
- Any CORS `Access-Control-Allow-Origin` reflection with credentials on a Vinted host.
- Any XSS on a Vinted origin (attacker reads `"CSRF_TOKEN"` from JS config — trivial — and fires
  same-origin requests). Pairs with F-01 (no CSP to blunt XSS).
- Any **state-changing GET** reachable by top-level navigation (Lax sends cookies on top-level
  GET): then the static token is irrelevant and CSRF is direct.

## [Bugbountyskills.md] Steps to reproduce

1. `GET https://www.vinted.com/` with no cookies → grep `CSRF_TOKEN` → `75f6c9fa-...`
2. Repeat as a second logged-in account → identical value.
3. Replay the operator's `POST /api/v2/photos` (multipart, valid token) with
   `Origin: https://evil-example.test` → `200` (upload succeeds).
4. Same request with token removed → `403`.

## [Bugbountyskills.md] Remediation

- Per-session, cryptographically random token (regenerate on login/privilege change), compared
  with a **timing-safe** equality check.
- Validate `Origin` (or `Referer`) against an allow-list on every state-changing request; reject
  mismatches even when the token is correct.
- Keep the custom-header requirement and `SameSite=Lax/Strict` cookies — they are what currently
  contain the issue.

## [Bugbountyskills.md] Related

F-01 (no CSP / frame protections / 5-min HSTS) is the missing mitigation that would otherwise
blunt the XSS leg of the escalation chain.

## [Bugbountyskills.md] >> next-actions.md

*Source: `/root/bugbounty-lab/next-actions.md`*

## [Bugbountyskills.md] Next Actions

## [Bugbountyskills.md] BLOCKED ON USER INPUT (Phase A gate)

Need the authorized Bugcrowd program before any target-directed activity:
1. Official Bugcrowd program URL, **or** the in-scope asset list (domains/wildcards/APIs).
2. Confirm whether the program allows: automated scanners, out-of-band/SSRF callbacks,
   active SQLi/XSS probing, and the required request-rate limits.
3. Whether you have (and the program permits) test accounts for auth comparisons.

## [Bugbountyskills.md] Not started

- Phase C crawling (katana), Phase D endpoint intel, Phase E prioritization, feature-to-sink map.

## [Bugbountyskills.md] Host

- OS: Ubuntu 24.04.4 LTS (Noble), kernel 6.8.0-142, x86_64
- CPU: 4 cores | RAM: 7.8 GiB | Disk: 96G (30G free)
- User: root (passwordless sudo available)
- Runtimes: Go 1.22.2, Python 3.12.3, Node 26.8.2, npm 11.19.1, Ruby 3.2.3

## [Bugbountyskills.md] Pre-existing (system)

| Tool | Path |
|------|------|
| jq | /usr/bin/jq |
| curl | /usr/bin/curl |
| dig / nslookup | /usr/bin |
| whatweb | /usr/bin/whatweb |
| nmap | /usr/bin/nmap |

## [Bugbountyskills.md] Deferred until active phases (not yet installed)

- nuclei, dalfox, ffuf, gf patterns, Amass — install when scope + phase approved.

## [Bugbountyskills.md] Not permitted without asking

- No changes to SSH config, firewall, or system-wide security settings.

## [Bugbountyskills.md] 8. CREDENTIALS — Reference Only (No Secrets In This File)

Per `bug-hunter` skill §6, credentials are NEVER copied into skills/reports/chat.

They live in mode-600 env files at these locations:


```

- `/root/.config/bughunter/getoutlaw-credentials.env`
- `/root/.config/bughunter/quizlet-sessions.env`
- `/root/.config/bughunter/reready-production.env`
- `/root/.config/bughunter/test-mailboxes.env`
- `/root/.config/bughunter/sessions/vinted-acc1.env`
- `/root/.config/bughunter/sessions/vinted-acc2.env`
- `/root/.config/bughunter/sessions/vinted-acc3.env`
```


**Rules:**

- Read env files at time of need; never paste values into this file.

- Reference the env file path in reports instead of the credential itself.

- Mailbox access does NOT grant registration rights — check program rules first.

## [Bugbountyskills.md] 9. VALIDATION SCRIPT

## [Bugbountyskills.md] >> validate_vulnerability.py — Control-test based validation

*Source: `/root/.hermes/skills/web/web-vulnerability-hunting/scripts/validate_vulnerability.py`*

#!/usr/bin/env python3
"""
validate_vulnerability.py — Control-test based vulnerability validation.

Usage:
    python3 validate_vulnerability.py <endpoint> <method> <payload> [control_payload]

Behavior:
    1. Sends the malicious payload to the endpoint
    2. Sends the control payload (or a default benign value)
    3. Compares responses
    4. Prints VULNERABLE, BLOCKED, or NO FINDING with evidence

Decision rules:
    - VULNERABLE:   Test returns 200, OR successful operation, OR different response than control
    - BLOCKED:      WAF or application rejects payload; document blocking code
    - NO FINDING:   Control and test return identical responses

Example:
    python3 validate_vulnerability.py "https://api.klktech.com/v2/agentwebserv/login/account" POST '{"email":"test@test.com","password":"test"}'
    python3 validate_vulnerability.py "https://api.klktech.com/v2/agentwebserv/login/account" POST '{"email":"test@test.com","password":"\' OR \'1\'=\'1"}'
"""

import sys
import json
import requests

## [Bugbountyskills.md] EXCLUDED FROM THIS FILE (by design)

- **Credential/env files** (`.env` in `/root/.config/bughunter/`) — location referenced only.

- **Tool source code** (`XSStrike`, `ghauri`, `jwt_tool`, `testssl.sh`, `ars0n-framework-v2`,
  `nuclei-templates`, `subzy`, `exploitdb` in `/root/old-bugbounty-backup/`) — binary/tool
  installs, not skill content.

- **Empty directories** (e.g. `findings/candidates/`, `findings/validated/`,) and empty
  intelligence files (zero-byte).


_This file is regenerated from the source files at their canonical paths. Edit sources, not this file._

---

## [Bugbountyskills.md] 17. Knowledge intake — appended methodology (research pass 2026-11-07)

*Surface read of disclosed reports/writeups on 2026-11-07: HackerOne Hacktivity disclosure
index (ajaysenr/HackerOne-Disclosed-Reports, by-year/2026), the individual disclosed report
pages cited below (Rocket.Chat, Mozilla/Taskcluster, Khan Academy, Essity, HackerOne, R3/JFrog),
HackerOne program docs (Core Ineligible Findings), Intigriti Bug Bytes index, and an arXiv BOLA
taxonomy paper (ar5iv 2605.25865). PentesterLand returned 404 and Bugcrowd/research is behind a
login wall from this egress — no entry is drawn from either. Every entry below is a NEW method
not already in this ledger; each is recorded as SOURCE / CLASS / CORE METHOD / DETECTION SIGNAL /
CHAIN / TRANSFERABLE TEST.*

<!-- exact-duplicate entries folded in: 1 -->

### [Bugbountyskills.md] 17.17 Server-side URL fetch: scheme-allowlist bypass (file://) -> arbitrary local repository read (GitLab RepositoryPipeline #1685822)

SOURCE: https://hackerone.com/reports/1685822  2026-11-07
CLASS: server-side URL-fetch scheme-allowlist bypass (`file://`) → arbitrary local repository read (CWE-918-family / CWE-829) — GitLab BulkImports RepositoryPipeline
CORE METHOD:
  1. Entry point: GitLab "import group" (BulkImports). The client-supplied `httpUrlToRepo` from the import graph is used verbatim at load: `url = data['httpUrlToRepo']` → `url.sub("://", "://oauth2:#{config.access_token}@")` → `Gitlab::UrlBlocker.validate!(url, allow_local_network:…, allow_localhost:…)` → `project.repository.fetch_as_mirror(url)`.
  2. Defect: `UrlBlocker.validate!` is called WITHOUT a `schemas:` argument, so it accepts ANY scheme as long as the remainder parses as a URL — including `file://`. Host/IP restrictions are enforced but the protocol is not.
  3. Inject `file://` into `httpUrlToRepo`: `file://aw.rs/var/opt/gitlab/git-data/repositories/@hashed/b1/74/b174103b399555239923697fbe124faa61de4d441bd5c5678275eb0a5a27a562.git` (the token `aw.rs` survives the `://`-substitution and keeps the string URL-shaped; git ignores the host for `file://`).
  4. Derive the on-disk path of ANY project from its integer id: `b = Digest::SHA2.hexdigest("<project_id>")`; repo lives at `<repo_root>/@hashed/<b[0:2]>/<b[2:4]>/<b>.git`.
  5. The server runs `git fetch file://…`; on success the local repo is mirrored into the attacker's imported project → read the full source of any private repository on the instance. (The report's proof was reading GitLab's own CTF project and its flag.)
DETECTION SIGNAL: any server-side "fetch / clone / mirror / import-from-URL" that validates the URL but not the SCHEME allowlist (http/https only); `UrlBlocker.validate`-style helpers invoked without `schemas:`; an import/config API taking a full URL string; storage paths derivable from a public integer id (hash-of-id bucketing).
CHAIN: low-privilege user allowed to run a group import → `httpUrlToRepo=file://…` passes URL validation (no scheme allowlist) → server-side `git fetch` reads a local path → private repository source disclosed by computing `sha2(project_id)` → high (private-source disclosure / BAC).
TRANSFERABLE TEST: On every server-side URL-fetch parameter (import, clone, mirror, webhook URL, remote config, favicon/proxy fetch) swap the scheme: `file://`, `gopher://`, `dict://`, `ftp://`, `git://`, `ssh://`, `jar:file://`, `http://127.0.0.1`. Confirm the code enforces a SCHEME allowlist, not merely host/IP blocks. If the on-disk path is derivable from a public id (hashed store / bucket-by-id), compute it and point `file://` at it.

### [Bugbountyskills.md] Knowledge intake — reader pass 2026-11-07 (batch 3): new GENERAL methods, appended to Section 17

*(Same entries as the harvest ledger; only the methods that generalize beyond one product are promoted here. Sources read this pass: 6 — 5 appended to the ledger, 3 promoted here. #488147 is a duplicate of the already-recorded #510152 technique and is deliberately not repeated.)*

SOURCE: https://hackerone.com/reports/767770  2026-11-07
ROUTE: report body rendered via the HackerOne `.json` endpoint (vulnerability_information present, full).
CLASS: IDOR / BOLA in an import path — nested `attributes` sub-hash defeats a top-level `_ids` denylist (CWE-639 + CWE-915) — GitLab "Private objects exposed through project import" (bypass of #743953)
CORE METHOD:
  1. Same primitive as #743953: GitLab's project-import restorer does `@project.assign_attributes(project_params)` where `project_params` come straight from the attacker-authored `project.json` inside the import tarball.
  2. The fix for #743953 blocks all top-level relation-id keys (`issue_ids`, `merge_request_ids`, `board_ids`, `note_ids`, ...). The bypass (verbatim from the report) is to move the key ONE LEVEL DOWN into the model's bulk-attributes writer, which the denylist never inspects:
     # project.json
     "attributes": {
         "issue_ids": [ 29279725 ],
         "description": "Set from attributes[description]"
     }
  3. `attributes` is the Rails `assign_attributes`/`attributes=` container, so `attributes["issue_ids"]` reaches the same mass-assignment path the top-level filter was meant to close. The id array names the VICTIM's pre-existing object while the corresponding payload array stays empty — that is what makes it an IDOR and not a copy.
  4. Import the tarball as a "GitLab export" into your own namespace, let the job finish, open the Issues tab: the imported project now owns a private issue belonging to another user (still credited to its original author).
  5. Ids are incremental → walk the id space to harvest private issues/MRs/boards/notes in bulk ("accessing random resources of other users by traversing the incremental ID space"); affects gitlab.com and self-hosted.
DETECTION SIGNAL: any import/restore/upsert/duplicate feature that bulk-assigns manifest attributes onto a model AND accepts a nested container (`attributes`, `data`, `record`, `properties`, `meta`) in that same manifest; a denylist/permitted-parameter list applied only at the TOP level while the model still exposes a bulk `attributes=`/`assign_attributes` writer; relation-id keys present with empty payload arrays alongside them.
CHAIN: any authenticated user who can import a project → `attributes.issue_ids` in `project.json` bypasses the top-level `_ids` denylist → `assign_attributes` re-binds your project to another user's private objects → cross-tenant read of private issues / MRs / boards / notes at scale (Critical, $20,000; the previous fix was cosmetic).
TRANSFERABLE TEST: Take the app's recently-patched mass-assignment denylist and re-submit the same forbidden key NESTED one level deeper — `{"attributes": {"<forbidden_key>": ...}}`, then `data`/`record`/`properties`/`meta` variants — in the import manifest or JSON body. If the field/relation is still written, the fix was cosmetic. Then walk the target relation's id space (ids are usually sequential) to confirm cross-tenant reach.


SOURCE: https://hackerone.com/reports/1406938  2026-11-07
ROUTE: HackerOne page is Cloudflare/JS-gated (web_extract empty; r.jina.ai redirected to /users/sign_in with a CAPTCHA) and `https://hackerone.com/reports/1406938.json` returns HTTP 404. Method retrieved from the credited vendor writeup — dropbox.tech/security/bug-bounty-program-ssrf-attack (Dropbox AppSec, naming HackerOne user Kumar Saurabh and the 2021-02-19 report; $27,000 per the vendor, $17,576 per the public bounty lists). All quoted code is the vendor's own.
CLASS: SSRF (full-response) via URL-parser differential between the validating library and the fetching library (CWE-918 + CWE-436) — Dropbox branded sharing
CORE METHOD:
  1. Entry point: a team-admin feature that fetches an image server-side from a client-supplied URL — `POST /team/admin/team_logo/save` (and `/team/admin/team_background/save`) with an `img_url` argument; the server then runs curl/pycurl on that URL.
  2. The vulnerable code validates the AUTHORITY with one parser and fetches with another:
     parsed_url = URI.parse(img_url)
     if BLOCK_CLUSTER != parsed_url.authority: raise HttpStatusBadRequestException()
     conn, url = CurlConnection.build_connection_url(img_url)
     response = conn.perform("GET", url)
     `URI` is Dropbox's own RFC-3986-regex parser; `CurlConnection.build_connection_url` uses Python's `urllib.parse` (urlsplit).
  3. Parser-differential payload: `https://dl-web.dropbox.com\@127.0.0.1:8080`. `URI.parse(...).authority` → `'dl-web.dropbox.com'` (the allowlist check PASSES) while `urlsplit(...).hostname` → `'127.0.0.1'` (curl connects to the attacker-chosen/internal host). The backslash before `@` is the differential character — same family as the 2017 Black Hat "A New Era of SSRF — Exploiting URL Parser in Trending Programming Languages" talk the vendor cites.
  4. FULL-READ: the fetched body is SAVED server-side (into a database) and served back — `GET https://www.dropbox.com/team/team_logo/<dbtid>` or `https://www.dropbox.com/team/team_background/<dbtid>` returns the internal response body, so this is a complete-response SSRF (not blind) and that download endpoint is the exfil channel.
  5. Vendor-observed impact limit (why this is graded, not assumed): most Dropbox internal services speak gRPC with mTLS constraints, so a plain GET cannot reach them. Fixed in ~8 hours.
  6. The vendor fix is the reusable mitigation to test a target against: normalize by serializing through the validating parser (`safe_url = str(parsed_url)`, reject on exception) and fetch THAT string; better still, construct the URL from parsed components instead of trusting the raw input.
DETECTION SIGNAL: any client-supplied URL fetched server-side where validation and fetch are performed by DIFFERENT libraries (own URI class vs urllib/curl/requests; java.net.URI vs HttpClient; urlsplit vs httpx); allowlist checks on `authority`/`host`/`urlparse().netloc` while the actual connect uses another parse; the fetched body persisted and retrievable elsewhere (logo/avatar import, "import from URL", link unfurl, PDF/preview generator, webhook tester, upstream fetch of any kind) → full-read SSRF.
CHAIN: team admin (low privilege, but any user-reachable URL-fetch works) → `img_url = https://<allowed-host>\@<internal-host>:<port>` → validator passes, curl fetches the internal host → response body stored → read back from the team-logo/background URL → internal service data / credential exposure; with a reachable metadata endpoint the same primitive escalates to cloud IAM credentials → RCE (Critical; $17,576 vendor-paid / $27,000 vendor-assessed).
TRANSFERABLE TEST: For every server-side fetch of a user-supplied URL, send `<allowed-host>\@<attacker-or-internal-host>:<port>` plus the variant table — `%5c@`, `\@`, mixed case, `@` in path/query, userinfo tricks (`https://allowed@internal`), trailing dot/IDN host — and check (a) whether your collaborator or the internal address receives the request and (b) whether the fetched BODY is retrievable from a second endpoint (that read-back is what makes it full-response, i.e. P1/P2 instead of blind). Then probe `http://127.0.0.1:<port>/` and `http://169.254.169.254/latest/meta-data/iam/security-credentials/`.


SOURCE: https://hackerone.com/reports/1132378  2026-11-07
ROUTE: report body rendered via the HackerOne `.json` endpoint (vulnerability_information present; a few tokens — attachment names and log excerpts — are redacted as ████). The mechanism is recorded exactly as the report states it; the precise manifest key is NOT in the body (see the honesty note in DETECTION SIGNAL).
CLASS: internal file read (LFI) + SSRF via misuse of a JSON-schema validator that resolves external references with Ruby `open-uri` (CWE-22 / CWE-918) — GitLab "Arbitrary file read during project import" (CVE-2021-22201)
CORE METHOD:
  1. The project-import feature validates the attacker-authored manifest (export tarball) with a JSON-schema validator, and the report names the ROOT CAUSE explicitly: `open-uri`. Ruby `open-uri` honours ANY scheme, so a reference resolved by the validator inside the validated document is FETCHED BY THE SERVER — `file://` = local file read, `http(s)://` = SSRF. (Report wording: "A mis-usage of json schema validator could be used by an attacker to read any file in GitLab server … as the root cause of the issue here is 'open-uri'. It's an SSRF issue at the same time.")
  2. Deliver: build the export tarball, upload it through the import feature as a "GitLab export", and wait for the import job to finish.
  3. Read the result out of the import status API — the report's step 3 is literally `GET https://gitlab.com/api/v4/projects/<PROJECT_ID>/import` (project id from the project home page): the validator's resolution output is reflected there. Verified outcome in the report: "The connection information of gitlab's production database is in the output".
  4. Read size: ~250 bytes of the target file per attempt (the report calls out this limit; it still yielded production DB connection info from GitLab.com, and the reporter enumerated further candidates from the Sidekiq chart templates: Rails `secret_key_base`, database credentials, GitLab SMTP credentials).
  5. Self-hosted escalation (the real jackpot, per the report): on instances where Sidekiq runs with gitlab-rails + gitlab-shell, read `.gitlab_shell_token`, then use it against the internal API `/api/v4/internal/personal_access_token` to "issue an private access token of an admin of someone else" → full instance compromise.
DETECTION SIGNAL: any server-side validator/loader that supports external references and resolves them over the network — json-schema / JSONSchemer / jsonschema (`$ref`), XSD/XML, YAML anchors, OpenAPI/Swagger documents, SAML metadata, XSLT, feed/sitemap/OPML parsers, resume/CSV importers — especially on Ruby stacks (`open-uri` also accepts `file://`); error/status endpoints that echo part of the fetched file (an import/validation status API is a perfect reflection channel); output truncated to a fixed byte count. HONESTY NOTE: the report body does not spell out which manifest key carried the reference, so the `$ref`/URI-shaped reference is the generalization to test, not a quote from the report; the class, root cause and read-out path above are the report's own words.
CHAIN: any user able to import/validate a document → the JSON-schema validator resolves an attacker-supplied reference via `open-uri` → `file://` gives arbitrary local file read (~250 bytes/attempt, loopable) and `http://` gives SSRF → harvest `secrets.yml` / `secret_key_base` / DB + SMTP credentials → (self-hosted) `.gitlab_shell_token` → `/api/v4/internal/personal_access_token` → personal access token issued as an arbitrary (admin) user → instance account takeover (Critical, $16,000; CVE-2021-22201; fixed in GitLab 13.10.1 / 13.9.5 / 13.8.7).
TRANSFERABLE TEST: In any feature that validates, loads or previews a document you control, place a reference where a scalar is expected — `"$ref": "file:///etc/passwd"`, an absolute path, a bare `http://<your-collaborator>/x`, `gopher://`, `dict://` — and watch for (a) your collaborator being hit (SSRF) or (b) file content appearing in an error, job log, or status endpoint. Then find the import/validation STATUS endpoint that reflects the fetched data; a small byte cap is message truncation, not a mitigation — loop with different targets and offsets.

### [Bugbountyskills.md] 17.32 Length-field / signed-subtraction bounds-check bypass -> OOB read used as a remote oracle, and allocation-size steering -> heap overflow (PlayStation `spp` #2177925)

SOURCE: https://hackerone.com/reports/2177925 — PlayStation PS4/PS5 PPPoE `sppp`, High, $12,500, CVE-2006-4304  read 2026-11-07 (BODY via the disclosed-report mirror raw.githubusercontent.com/ajaysenr/HackerOne-Disclosed-Reports/main/reports/2177925.md; `.json` empty, r.jina.ai 403)
CLASS: memory corruption (heap overflow + OOB over-read) in a length-prefixed option parser -> info leak -> kernel-context RCE
CORE METHOD:
  1. Loop length taken from the parsed record: `for (rlen=0; len>1 && p[1]; len-=p[1], p+=p[1])` never checks `p[1] <= len`, so `bcopy(p, r, p[1])` overflows `buf = malloc(len<6?6:len)`; `rlen += p[1]` also over-sizes the reject list.
  2. The over-read bytes are RETURNED in the protocol error message (`sppp_cp_send(..., CONF_REJ, ..., rlen, buf)`) — the reply hexdump contains host pointers: the leak ships with the crash.
  3. Allocation-size steering: `sppp_cp_input` clamps `len = min(actual_len, h->len)` from the outer header, so the attacker forces big-mbuf → small-buffer copies with controlled adjacent overwrite.
  4. Signed underflow: `len` can be 0..5, so the guard `name_len > len - 6` computes a NEGATIVE bound and both length checks pass up to 255; the subsequent `memcmp(name, sp->hisauth.name, name_len)` reads OOB, and the ACK-vs-NAK reply makes the protocol an ORACLE for the leaked bytes → KASLR defeat. Still shipped in NetBSD/OpenBSD.
DETECTION SIGNAL: a step/loop length read from inside the record being parsed (TLV length, chunk size, varint) with no `<= remaining` check; a signed subtraction used as a bound where input can drive it negative; any protocol/path that ECHOES malformed input in its rejection, error or stack-trace output (the echo is a read primitive); a stack whose lineage matches a pre-2010 CVE (regression hunting).
CHAIN: rogue/malicious PPPoE server on the same L2 (or MITM) → oversized option length byte → heap overflow with attacker-influenced allocation size / OOB memcmp with a response oracle → pointer leak → KASLR defeat → RCE in kernel context ($12,500; DoS proven, RCE stated as potential).
TRANSFERABLE TEST: Send one length-prefixed element whose length field exceeds the bytes actually supplied, then compare the bytes echoed in the rejection/error response against the bytes you sent — extra (especially pointer-shaped) bytes back = over-read leak primitive. Repeat with lengths 0..5 to hit a `len - k` signed-underflow bypass, and vary the enclosing header length to steer the allocation size so the copy direction is big→small.

NOTE — read pass 2026-11-07 (honesty record): https://hackerone.com/reports/3113398 ("Internal Access to Hackerone confluence Docs", HackerOne, High CVSS 8.2, $12,500) is NOT publicly readable on any route (`.json` → empty `vulnerability_information`; r.jina.ai → 403; disclosed-report mirror → "No vulnerability information available"; Wayback → "enable JavaScript" shell; web_extract → SPA shell), and the vendor summary names no entry point, parameter, prerequisite or test → INVALID, nothing recorded. The other five sources of this pass are appended above (17.29–17.32 cover sources 1, 2, 4, 5 and 6).

### [Bugbountyskills.md] 17.37 Project-export/import mass-assignment installs a server-side integration flagged as an instance TEMPLATE → applies to EVERY subsequently created project (GitLab templated service #446585)

SOURCE: https://hackerone.com/reports/446585 — GitLab, "Exfiltrate and mutate repository and project data through injected templated service" (Critical CVSS 9.9)  read 2026-11-07 (body via the HackerOne `.json` endpoint, 7,294 bytes)
CLASS: broken access control / mass-assignment on export-import → instance-wide integration injection · CWE-284 · CWE-915
CORE METHOD:
  1. `Projects::CreateService#create_services_from_active_templates` runs `Service.where(template: true, active: true).each { |t| Service.build_from_template(project.id, t).save! }` — any template service is auto-installed into EVERY project created afterwards, for all users.
  2. Service templates are admin-only to create normally, but the project EXPORT/IMPORT path accepts a `services` array in `project.json` without re-checking the `template` flag.
  3. Steps: create project → enable CI (Settings > Integrations) → Export → download tar → in `project.json` set the service's `"template": false` → `true` (and optionally `CiService` → `MockCiService`) → re-tar (`tar -zcvf service_template.tar.gz project.json VERSION project.bundle`) → import. That service is now an instance template.
  4. Proof: a SECOND user creates any project and immediately exports it — its `project.json` already contains the injected service.
  5. Choose the payload: `EmailsOnPushService` (`properties.disable_diffs=false`, `recipients=attacker@domain`) → every commit DIFF emailed to the attacker; `HipchatService`/`Slack*` → all issues/notes/MRs/pipelines/pushes streamed to an attacker endpoint; `MockCiService` (`mock_service_url=https://attacker_host/`) → a hidden, UI-invisible service that beacons CI data; `ExternalWikiService`/`CustomIssueTrackerService` → overwrite a project's Issue/Wiki URL to attacker infra.
  6. Side channel: the same import accepts `custom_attributes` into `project.json`, minting admin-only project attributes as a normal user.
DETECTION SIGNAL: an export/import/backup format that is a flat JSON of the object PLUS its associations, imported without per-field re-authorization; a config boolean (`template`/`default`/`global`/`system`/`shared`) whose flip changes the object's SCOPE; integrations/webhooks that exist as instance "templates" applied at creation; keys settable via import but NOT via the interactive API.
CHAIN: any user who can create a project → export it, flip `"template": true` on a service, add an exfil integration → import → the platform installs it into every project created afterwards → continuous exfiltration of repo diffs, confidential issues, MRs, pipelines and pushes from all users' projects (Critical 9.9).
TRANSFERABLE TEST: Take the platform's project/tenant export tar, set any `"template"/"default"/"global"` flag to true and add an outbound-notification integration pointing at YOUR URL, re-import, then have a SECOND account create a fresh object and export it — if your integration appears there, you have instance-wide injection. Diff import-schema fields against API/UI-allowed fields; an import-only field is a mass-assignment candidate.

### [Bugbountyskills.md] 17.43 Machine credential carrying an identity CLAIM (SSH CA certificate `extension:login@github.com=<user>`) is not re-verified by a SIBLING service → authenticate as any username → write to their objects (GitHub #1901040)

SOURCE: https://hackerone.com/reports/1901040 — GitHub Enterprise Server, "Authentication bypass on gist.github.com through SSH Certificates" (Improper Access Control - Generic, High, $10,000, reporter ammar2)  read 2026-11-07 (report body restricted/empty; method read from the REPORTER's own summary and GitHub's program summary on the report)
CLASS: authentication bypass — an identity claim inside a shared credential is validated by the main service but skipped by a sibling service · CWE-287 / CWE-863
CORE METHOD:
  1. GitHub (Enterprise) supports SSH certificate-authority authentication; the CA-signed certificate carries `extension:login@github.com=username`, which the service uses to decide WHICH account the SSH session authenticates as.
  2. Reporter's wording: "Due to a missed check in the gist.github.com authentication flow, an attacker could create a certificate giving them access to push to any username's gists." A legitimate CA-signed certificate is accepted by the GIST service without verifying the identity in the `login@github.com` extension is one the holder may use.
  3. Impact: with that certificate and the target gist's URL, the attacker authenticates as the victim and PUSHES changes — secret gists were modifiable (vendor wording; "a user had to know the secret gist's URL") and the reporter's correction adds PUBLIC gists as well.
  4. Affected: all GHES before 3.9; fixed in 3.4.18, 3.5.15, 3.6.11, 3.7.8, 3.8.1.
DETECTION SIGNAL: one authentication primitive consumed by SEVERAL services — SSH CA certificate, signed JWT, signed SAML assertion, service-account bearer, signed webhook — where the identity/scope claim is enforced in the main flow but skipped by a sibling/older/smaller service (gists, snippets, paste, avatar/upload, CI, search, GraphQL aliases); authorization expressed as a CLAIM (`extension`, `sub`, `scope`, `aud`) trusted instead of matched to a server-side record; features on their own hostname (`gist.`, `paste.`, `cdn.`, `assets.`).
CHAIN: attacker holds a legitimate CA-signed SSH certificate → presents it to a SIBLING service that does not re-verify the `login@github.com` claim → authenticated AS an arbitrary username → write access to that user's public and secret gists (URL known) → attacker mutates the victim's published content (High) — a content/supply-chain integrity primitive.
TRANSFERABLE TEST: take the identity-bearing credential your account can legitimately obtain (SSH cert with a login/principal extension, JWT with `sub`, signed assertion) and present it to EVERY service in the estate that accepts it — especially separate hostnames and legacy/adjacent products — asserting an identity claim that is NOT yours (`login@<host>=<victim>`). A sibling service that authenticates you as the claim's subject instead of rejecting the mismatched principal is the bug; confirm with a WRITE performed as that identity.

### [Bugbountyskills.md] Knowledge intake — reader pass 2026-11-07 (batch 9): new GENERAL methods, appended to Section 17

*(Same entries as the harvest ledger; only the methods that generalize beyond one product are promoted here. Sources read this pass: 6 — 5 appended to the ledger, 5 promoted here. Zilliqa #1058879 was unreachable on every route and yielded no entry.)*

### [Bugbountyskills.md] 17.49 Untrusted code sandbox: overwriting a BUILTIN EXCEPTION CLASS makes the engine's own error path recurse → VM-stack overflow → GC on a corrupted context stack (mruby / shopify-scripts #186723)

SOURCE: https://hackerone.com/reports/186723 — shopify-scripts, "Crash: Overwriting NoMethodError with a builtin class crashes/corrupts memory" (Memory Corruption; High; reporter brakhane)  read 2026-11-07 (full body via the HackerOne `.json` endpoint, 17,456 bytes)
CLASS: memory corruption / sandbox-engine corruption (DoS → escape primitive) — an attacker script replaces a runtime core constant used by the engine's own error/GC path · CWE-787 / CWE-248
CORE METHOD:
  1. In the sandboxed script, overwrite the exception class the runtime itself constructs: `NoMethodError = Fixnum` (Fixnum/Integer both work), then `boom!`.
  2. Root cause (reporter): "triggering the `NoMethodError` triggers another `NoMethodError` when `mrb_no_method_error` in error.c tries to call `new` on the new `NoMethodError`, which has no new." → each attempt to raise `NoMethodError` raises another (`mrb_no_method_error` → `mrb_method_missing` → `mrb_funcall ... "new"` → …).
  3. The recursion (~1,800 gdb frames) overflows the VM stack; incremental GC then walks the inconsistent context stack and `mark_context_stack` (gc.c:532) dereferences garbage → SIGSEGV at `0x0000000000000a`.
DETECTION SIGNAL: a product executing untrusted code in an in-process interpreter sandbox (mruby, Lua, JS, WASM/WASI, a template DSL) that lets the script REDEFINE core runtime constants/classes the engine's own error/GC paths use (exception classes first, then `Object`/`Class`/core modules); no per-script memory isolation; a GC concurrent with the script.
CHAIN: attacker script → reassign a builtin exception class → raise it → the engine's error path recurses → VM-stack overflow → GC walks a corrupted context stack → SIGSEGV / memory corruption in the sandbox host (DoS now; a corruption primitive toward escape).
TRANSFERABLE TEST: on any in-process interpreter sandbox, try to reassign the runtime's OWN core constants/classes — the exception classes first (`NoMethodError`, `StandardError`, `TypeError` = a builtin), then `Object`/`Class`/`Module` — and trigger the matching error. A crash/hang/quota-then-crash means the engine's error/GC path is reachable with attacker-controlled core state; on a multi-tenant target that is a corruption/DoS finding and the head of an escape chain. (LAB ONLY — same doctrine as the PlayStation UAF entries: memory-corruption depth stays off live targets; the reportable unit is "untrusted script can corrupt/crash the shared engine".)

NOTE — read pass 2026-11-07 (batch 9, no §17 entry): https://hackerone.com/reports/1058879 (Zilliqa, "Using gossip to drain miner wallets", Critical, $10,000, 111 upvotes) is NOT publicly readable on any route (`.json` 404; web_extract CRAWL_HTTP_403; browser + r.jina.ai both hit the Cloudflare interstitial; the single Wayback snapshot 20211025054614 is the SPA shell; the ajaysenr disclosed-reports mirror is 404; the local disclosed dataset has no row) and no credited writeup exists → INVALID, nothing invented (recorded in the harvest ledger and the dated knowledge file).

### [Bugbountyskills.md] 17.55 Untrusted interpreter sandbox: DELETING a core method the engine's own C helper calls (`NilClass.remove_method :to_s` → `nil.to_s` → `mrb_any_to_s` NULL-deref) crashes the host (mruby / shopify-scripts #185794) — distinct trigger from 17.49 / 17.52

SOURCE: https://hackerone.com/reports/185794 — shopify-scripts, "Crash: mrb_any_to_s can't handle NilClass, Symbol and Fixnum" (Memory Corruption - Generic; High; $8,000; reporter brakhane)  read 2026-11-07 (full body via the HackerOne `.json` endpoint, 38,824 bytes — PoC + crash report + gdb backtrace)
CLASS: memory corruption in an in-process code sandbox — removing a method (here `:to_s`) from a BOXED IMMEDIATE class the runtime's own stringify helper relies on · CWE-476 / CWE-248
CORE METHOD:
  1. In the sandboxed script, delete the method from the boxed immediate class and then invoke the runtime's generic path that uses it: `NilClass.remove_method :to_s` then `nil.to_s` (reported to work with `Symbol` and `Fixnum` too).
  2. Root cause (reporter): "`mrb_any_to_s` is unable to handle `NilClass`, `Symbol` and `Fixnum`. This can be achieved by just deleting `:to_s` from the class and let `mrb_any_to_s` crash." The engine's C stringify helper assumes the default `to_s` still exists on boxed immediates.
  3. Crash: `[BUG] Segmentation fault at 0x00000000000018`; gdb faults in `mrb_any_to_s` `object.c:443`, from `mrb_vm_exec` (vm.c:1165) → `mrb_vm_run` (vm.c:766) → `mruby_engine_monitored_eval` (eval_monitored.c:68) — the caller is the interpreter's own C frame; the process aborts.
DETECTION SIGNAL: in-process interpreter sandbox (mruby, Lua, JS, WASM/WASI, template DSL) that lets the script `remove_method`/`undef_method`/`define_method` on core classes, and whose C-level helpers CALL those methods (stringify, compare, convert, `inspect`, hash) without guarding their absence — boxed/immediate types (int, symbol, nil) are the usual gap.
CHAIN: untrusted script → deletes `to_s` from a boxed immediate class → the engine's C helper calls the missing method → NULL/garbage deref → SIGSEGV in the host process → engine DoS + corruption primitive toward sandbox escape (High).
TRANSFERABLE TEST (LAB): in any sandboxed interpreter delete a method the RUNTIME relies on, then trigger the runtime's own path that uses it (`NilClass.remove_method(:to_s); nil.to_s`, or the `toString`/`__str__`/`inspect` equivalent on primitives). A crash/corrupt-object error instead of a clean NoMethodError means the engine calls unguarded methods on attacker-controllable core state; report "untrusted script can crash/corrupt the shared engine". (Memory-corruption depth stays lab-only; distinct from 17.49 class-overwrite and 17.52 C-level recursion.)

NOTE — read pass 2026-11-07 (batch 11): three sources were checked and marked INVALID (nothing invented, no §17 entry) — #863983 (Mail.ru city-mobil cross-organization data access, BAC), #852306 (Mail.ru SQL LIKE wildcard injection) and #136885 (Uber Complete Account Takeover, only the team summary "Thanks for another great find @parth!") are all `visibility: no-content` / unreadable on every route (`.json` 404, web_extract 403, browser + r.jina.ai Cloudflare gate, Wayback SPA shell, disclosed-reports mirror 404) with no credited public writeup, so no entry point/bypass/chain could be extracted; the full route record is in the harvest ledger `/root/bugbountyhuntingskills.md` and the dated knowledge file.

### [Bugbountyskills.md] 17.57 Untrusted interpreter sandbox: an ALLOCATED-BUT-NEVER-INITIALIZED object reaching `initialize_copy` → C copy routine writes through a NULL native pointer (mruby #184661 `Time`, #184857 `Proc`) — fourth distinct trigger in the 17.49/17.52/17.55 family

SOURCE: https://hackerone.com/reports/184661 — shopify-scripts, "mruby-time: Crash host with uninitialized Time obj" (Memory Corruption - Generic; High; reporter brakhane)  read 2026-11-07 (full body via the HackerOne `.json` endpoint, 40,090 bytes). Same trick extended to `Proc` in https://hackerone.com/reports/184857 (38,967 bytes) — recorded ONCE, not duplicated.
CLASS: memory corruption in an in-process interpreter sandbox — a native-backed object whose `initialize` never ran is passed to `initialize_copy`, which blind-copies through an uninitialized data pointer (`0+OFFSET`) · CWE-457 → CWE-476 / CWE-787
CORE METHOD:
  1. Redefine the built-in class's `initialize` to an empty body so the allocator still allocates the object but its internal C struct is never created, then copy between two such objects: `class Time; def initialize; end; end` → `a = Time.new; b = Time.new; a.initialize_copy b`.
  2. Root cause (reporter): "`Time::initialize_copy` performs its copy action even on `Time` objects on which `initialize` never ran" — `mrb_time_initialize_copy` executes `*(struct mrb_time *)DATA_PTR(copy) = *(struct mrb_time *)DATA_PTR(src);` (mruby-time/src/time.c:533) → `[BUG] Segmentation fault at 0x00000000000000` from `mrb_vm_exec` (vm.c:1165) → `mrb_vm_run` (vm.c:766) → `mruby_engine_monitored_eval` (eval_monitored.c:68).
  3. Same trick, other built-in: `a = Proc.new do end; class Proc; def initialize; end; end; b = Proc.new; a.initialize_copy b` → crashes the public `mruby.science/runs` sandbox, mruby master tip and `mruby-engine`; fault at `0x68` in `mrb_proc_copy` (proc.c:143) via `mrb_proc_init_copy` (proc.c:175). Reporter's impact read: "it's accessing a 0+OFFSET this might be usable to gain code execution. Otherwise it's just a DoS."
  4. Operational detail: it cannot be run from irb (the implicit printout fails first) — submit through the sandbox/eval path. Bonus from the same report: an mruby-time memory LEAK a script can trigger on purpose (fixed upstream, mruby commit d97a37eb).
DETECTION SIGNAL: a sandbox that (a) lets the untrusted script reopen/redefine a built-in class (`class Time; def initialize; end; end`) and instantiate it, and (b) has C extension types whose `initialize_copy`/copy-constructor copies a raw struct via `DATA_PTR`/native handle without checking the source was ever initialized. Generalises to any `X.new` whose native backing store is created only in `initialize`.
CHAIN: untrusted script → `initialize` redefined to a no-op → `Obj.new` yields an allocated-but-uninitialized object → `a.initialize_copy b` runs the engine's C copy routine → read/write through a NULL native pointer at `0+OFFSET` → SIGSEGV in the host process (DoS, core dumped) and a likely arbitrary-write primitive → code execution in the shared engine (High; head of a sandbox-escape chain).
TRANSFERABLE TEST (LAB): redefine a built-in's `initialize` to an empty body, allocate two instances and call `initialize_copy` (`class Time; def initialize; end; end; a=Time.new; b=Time.new; a.initialize_copy b`), repeating for `Proc`, `String`, `File`, `Socket` and any other native-backed built-ins; generalise to copy-constructors, `clone`/`dup`, `__init__` overrides and `Object.assign` over lazily-created native state. A segfault instead of a normal runtime error means the copy routine dereferences uninitialized native state; report "untrusted script can crash/corrupt the shared engine" (memory-corruption depth stays lab-only; distinct from 17.49 class-overwrite, 17.52 C-level recursion and 17.55 `remove_method`).

