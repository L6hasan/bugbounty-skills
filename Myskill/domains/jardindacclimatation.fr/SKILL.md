---
name: jardindacclimatation.fr
description: Recon notes, scope, attack surface, tested history and open leads for www.jardindacclimatation.fr (Jardin d'Acclimatation / LVMH) — use when hunting on this target, resuming the engagement, or when a conversation mentions jardindacclimatation.fr or Jardin d'Acclimatation.
---

# jardindacclimatation.fr

**Program / authorization:** Published bug bounty, LVMH group / Jardin d'Acclimatation.
Reward grid: asset value "High", €50 (Low) / €200 (Medium) / €600 (High) / €1,000 (Critical),
scaled by duplicate-report decay (100/100/75/50/25/10%). First reporter only.
LVMH, JdA employees and their contractors are ineligible.
*(Program brief pasted by operator 2026-10-24; full "testing policy" section was NOT provided — see Scope.)*

**Last engagement:** 2026-10-24 (first session)

## Scope
- In scope (confirmed): `https://www.jardindacclimatation.fr/` — the asset the operator named.
- Inferred in-scope: the registrable domain `jardindacclimatation.fr` (apex serves a bare nginx,
  not the app — see Attack surface).
- **Out of scope / unconfirmed: ALL subdomains.** 24 subdomains exist in CT logs including
  `preprod`, `int`, `pp`, `pp-api-ticket-v9/v10/v11`, `gtm-origin`, `octime`.
  These look like staging/integration infrastructure. **Do not actively test them until the
  operator pastes the program's explicit scope list.** Passive CT/DNS recon only.
- **Binding constraints taken from the program brief (treat as rules, not advice):**
  - **No PII in the report. REDACT/OBFUSCATE all PII in PoCs** (screenshots, responses, JSON).
  - **For a sensitive-information leak: DO NOT extract/copy every exposed document or record.
    Limit yourself to DESCRIBING AND LISTING what is exposed.** This caps proof depth for the
    known PII leak — describe the class and shape of data, do not harvest records.
  - Do not alter compromised accounts (no create/delete/modify of data).
  - Do not use compromised accounts to hunt post-auth bugs (not eligible anyway).
  - Exposed credentials/secrets: verify validity only, do not exercise.
  - Report needs: textual description, exploitability, impact, remediation, screenshots with
    PII redacted, complete repro steps.
- Rate limits / testing windows: **unspecified — be conservative.** Akamai Bot Manager throttles
  hard anyway (see WAF section); there is effectively a built-in ~1 request/burst limit.
- Assume standard exclusions not yet read: no DoS, no social engineering, no spam/email bombing,
  no destructive actions, no real payment execution.

## Stack (verified 2026-10-24)
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

## Attack surface

### Subdomains & hosts
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

### Pages (27 routes — from `_buildManifest.js`, fetched with validated `_abck`)
`/` · `/401` · `/403` · `/404` · `/500` · `/_error` · **`/admin`** · `/attractions` ·
`/attractions/[uid]` · **`/attribuer-tickets`** · **`/auth/callback`** · `/billetterie` ·
`/checkout` · **`/checkout/result`** · `/contact` · **`/detail-des-billets`** ·
`/entreprises-et-cse` · `/entreprises-et-cse/confirmation-email` ·
**`/entreprises-et-cse/creation-de-compte-pro`** · `/entreprises-et-cse/verification-email` ·
**`/forgotPassword`** · **`/mon-compte`** · **`/resetPassword`** · `/restaurants/[uid]` ·
`/sitemap.xml` · `/tarifs` · `/[uid]`

`robots.txt` disallows: `/resetPassword` `/forgotPassword` `/mon-compte` `/401` `/403` `/404`
`/500` `/checkout/result`. No `security.txt` (404 at both `/.well-known/` and `/`).

### Endpoints (from JS bundle static analysis — `endpoints.json` in this dir)
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

## Findings history
| Date | Endpoint | Class | Status | Report |
|---|---|---|---|---|
| 2026-10-24 | `GET /api` | PII leak (operator-found) | **VALIDATION PENDING — operator gave the request only; need the response body / screenshot. Could not reproduce: `/api` → `307 /404` both anonymously and with their validated `_abck`.** | draft |
| 2026-10-24 | `GET /api/proxy/user/checkEmail?email=` | Account enumeration (CWE-204) + `businessStatus` leak | **CONFIRMED** — 200 `{"email":…,"exists":false}`; malformed → 400; client branches on `t.exists`. `exists:true` branch inferred from bundle, not yet observed live. | `findings/001-email-enumeration-oracle.md` |

### New routes found after the initial inventory (from `_app` chunk module `66679`)
`POST /auth/signup` · `POST /auth/login` · **`GET /auth/url/{provider}`** (OAuth provider URL
builder — candidate for `redirect_uri` manipulation via `business-logic`/`csrf`) ·
`GET /user/checkEmail?email=` · `GET /auth/checkMagicLink?token=` · `POST /auth/sendMagicLink`.

## Ruled out (and why)
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

## WAF / defense behavior (Akamai Bot Manager) — **read before testing**
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

## Next session (ranked)
1. **Validate the operator's `GET /api` PII leak** — still the top item and still blocked.
   `/api` → `307 /404` for me **both anonymously and with their validated `_abck`**, so either
   the path was different from what was pasted, or the response came from a state I can't
   reproduce (their cookie is from 2026-09-25). **Ask for the raw response body or a screenshot
   with PII redacted** — per program rules, describe/list only, never bulk-extract.
2. **`POST /api/business/massAssignment`** — the one API route *outside* the `/api/proxy`
   wrapper (may skip the shared authz layer). The 403 was the bot gate, not an auth answer.
   Upload a tiny non-executable CSV; also check filename handling (path traversal).
3. **Re-run the `productCode` SQLi differential** using the reseed→40s→probe recipe:
   baseline vs `'` vs benign `A01WX` vs time-based. Only ~4 probes. Must settle the 503
   red herring.
4. **Confirm `exists:true`** with an operator-owned test account (never a third party's
   address — the program forbids third-party PII in reports). Closes finding 001.
5. **XSS on the richer contexts:** `/checkout/result?code=&guest=&language=` and
   `/auth/callback?code=&state=&error=` — both currently untested, both higher-value than `/`.
6. **`GET /auth/url/{provider}`** — OAuth provider URL; probe `redirect_uri`/`state` handling
   (csrf-testing + business-logic-testing). `/auth/callback` alongside it.
7. **IDOR on `/api/proxy/orders/{id}` and `/orders/{id}/{itemId}`** — needs an Okta session.
   Probe a guaranteed-nonexistent ID first for the 401-vs-404 signal, then two self-owned
   accounts.
8. **`GET /api/proxy/payment/getUrl?paymentRef=`** — open-redirect / SSRF-ish (returns a URL).
9. **`/api/proxy/smtp/contactForm` `email_to`** — client supplies the recipient → mail relay.
   ONE request only (email sending is likely policy-restricted).
10. **Token-in-URL (`?token=<oktaToken>`) on all `/admin/*` routes** → Referer/log/history leak.
    Static-confirmed already; reportable standalone as info-disclosure.
11. **Sourcemaps** (`/*.js.map`) — retest with the reseed recipe; 403 earlier was the bot gate.
12. **Subdomain scope:** ask the operator for the program's explicit in-scope host list before
    touching `preprod` / `int` / `pp` / `pp-api-ticket-v9-v11` / `octime`.
13. **Read the rest of the program's testing policy** (only the reward-eligibility section was
    provided) — specifically account-creation rules, before any signup-based test.
