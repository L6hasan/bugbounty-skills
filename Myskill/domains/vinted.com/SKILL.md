---
name: vinted-com
description: Recon notes, scope, attack surface, tested history and open leads for www.vinted.com (Vinted Bug Bounty, Bugcrowd vinted-uab-mbb) — use when hunting on Vinted, resuming the engagement, or when a conversation mentions vinted.com / vinted.net / vintedgo.com.
---

# vinted.com

**Program / authorization:** Vinted Bug Bounty — Bugcrowd `vinted-uab-mbb` (public, rewards $75–$8,000;
max raised from $4,000 on 2026-10-11). Scope confirmed via program index snapshot **2026-10-20**.
**Last engagement:** 2026-10-21 (sessions 1–3 — passive recon, safe active probes, authenticated testing with operator accounts)

## Scope
- **In scope (12 targets):** `https://www.vinted.com`, `https://www.vinted.net`, `https://www.vintedgo.com`,
  `https://sandbox.vinted.com`, `https://sandbox.vintedgo.com`, `https://test-escalations.vintedgo.com`,
  `https://badger.it.vinted.com`, `https://careers.vinted.com`, `https://company.vinted.com`,
  `https://news.vinted.com`, iOS app `id632064380`, Android app `fr.vinted`
- **Program rule:** *"Testing is only authorised on the targets listed as in scope."* Any unlisted
  Vinted property is out of scope — **including `*.vinted.fr/.de/.uk/...` (other locales), `api.vinted.com`
  / `fr.core.api.vinted.com` (seen in JWT `aud`), and `marketplace-web-assets.vinted.com` (asset host).**
- **Exclusions / rate limits: UNKNOWN — full brief is behind Bugcrowd login.** Confirm before
  authenticated or automated-heavy testing. Targets are confirmed; exclusions are not.
- **Site-declared restrictions (`/robots.txt`), treat as binding:**
  - `User-agent: ClaudeBot / GPTBot / Google-Extended / Amazonbot / CCBot → Disallow: /`
  - AI agents may **not** create/register/manage accounts, add to cart, purchase, checkout, pay,
    or simulate customer interaction — "Any automated transactional behavior is considered unauthorized."
  - `ai-train=no`, `ai-input=no` for the AI-crawler block; content is being read here purely for
    authorized security testing, never scraped/trained on.
  - Practical consequence: **no automated registration, no cart/checkout/payment flows, low request
    volume, targeted requests only.** Authenticated testing ⇒ user's own account, manual, or on
    the in-scope `sandbox.vinted.com`.

## Stack (verified 2026-10-21)
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

## Security posture observed (session 1)
- **Missing on `https://www.vinted.com/`:** `Content-Security-Policy`, `X-Frame-Options` /
  `frame-ancestors`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`,
  `Cross-Origin-Opener/Resource-Policy`. **HSTS `max-age=300`** (5 min, no `includeSubDomains`, no `preload`).
  → finding F-01.
- **Cookies without `Secure`/`HttpOnly`:** `anon_id`, `anonymous-iso-locale`,
  `non_dot_com_www_domain_cookie_buster` (low — HSTS partially mitigates; also note 5-min HSTS).
- **CORS:** no `Access-Control-Allow-*` reflected for `Origin: https://evil-example.test` on
  `/` or `/robots.txt` — no permissive-CORS signal on those paths.
- **soft-404 baseline:** unknown path → HTTP 404, 18,230 bytes, title present (distinguishable).

## Attack surface
### Hosts
| Host | Purpose | Scope | Notes |
|---|---|---|---|
| www.vinted.com | marketplace web (Next.js) | ✅ in | primary target |
| vinted.com (apex) | sitemap/redirects | ⚠️ not explicitly listed | only `www.` listed; sitemap index served on apex — avoid active tests on apex |
| api hosts (JWT `aud`) | core API | ❌ out | do not test |
| marketplace-web-assets.vinted.com | static chunks/fonts | ❌ out | sourcemap hunting here is out of scope |
| other `vinted.*` TLDs | locale mirrors | ❌ out | appear in hreflang output — never request them |
| sandbox.vinted.com / sandbox.vintedgo.com | test environments | ✅ in | **preferred target for authenticated flows** |
| badger.it.vinted.com, careers/company/news., vinted.net, vintedgo.com | misc | ✅ in | untested (session 2 candidates) |

### Endpoints & params (pre-auth)
| Endpoint | Params | Signal | Tested? |
|---|---|---|---|
| `/` | `utm_source`, `next` | reflected (URL-encoded) into signup `ref_url` href + RSC payload | ✅ 2026-10-21 |
| `/catalog` | `zz9x` (test), `page`, `price_from`, `brand_id[]` | reflected into `<link canonical>`, hreflang, nav/pagination hrefs; typed filters | ✅ 2026-10-21 |
| `/member/signup/select_type` | `ref_url` | consumes `next`/return path — **open-redirect chain candidate (auth-required)** | ❌ next |
| `/member/`, `/inbox`, `/checkout`, `/util`, `/admin_alert/new` | — | robots-disallowed; auth-gated areas | ❌ next |
| `/sitemaps/us/*.xml` | pages, help, brands, catalogs, items, fresh-items | discovery index (items.xml = listing IDs) | partially |
| `/.well-known/security.txt` | — | `security@vinted.com`; expires 2026-11-04 | ✅ |

## Findings history
| Date | Endpoint | Class | Status | Report |
|---|---|---|---|---|
| 2026-10-21 | `/` (site-wide headers) | Missing security headers + weak HSTS | candidate — F-01, severity likely Low/Info | not submitted |
| 2026-10-21 | `/api/v2/*` | Globally static CSRF token + Origin unchecked | candidate — F-02, Low (escalation conditions listed) | not submitted |
| ~~2026-10-21~~ | ~~`/api/v2/users/{id}` cross-user timestamps~~ | ~~F-04 candidate~~ | **withdrawn — intended "Last seen" feature (see Ruled out)** | n/a |

### Authenticated session notes (2026-10-21, sessions 2–3)
- Session replay from a **different IP works** (`cf_clearance`/`datadome` did not bind to the
  operator's IP) — curl-based testing is viable.
- **Accounts:** acc1 (`testerokk`, uid 3196844241) **deleted** by an unintended
  `DELETE /api/v2/users/:id` during method discovery (API 401, `/member/:id` 404, session 307;
  soft-delete presumed, `is_deleted` field exists — operator to log in within restore window).
  **acc2 (`cromeuser`, uid 3196850623) valid; acc3 (`mytest1`, uid 3201846803, cc=US, created
  2026-10-21) valid.** Sessions in `~/.config/bughunter/sessions/` (600, never copy into skills).
- **DELETE `/api/v2/users/:id` authz matrix (all probed with guaranteed-nonexistent or
  already-deleted IDs only):** unauthenticated → `401 invalid_authentication_token`; authenticated
  without `X-Csrf-Token` → `403 access_denied`; valid auth+CSRF + nonexistent id → `404 not_found`;
  valid auth+CSRF + **foreign (other-user) id** → `403 access_denied` ⇒ ownership enforced; with
  own id it executed the intended self-delete. ⇒ deletion of acc1 was authorized self-delete, not
  a vulnerability (my methodology error, see LESSONS 2026-10-21).
- `X-Csrf-Token: 75f6c9fa-dc8e-4e52-a000-e09dd4084b3e` — **5th independent confirmation** (acc3,
  new account, same value) — see F-02.
- Discovery: `GET /api/v2/users/{id}` = profile resource (own → 93 keys incl. `email`, `is_god`,
  `moderator`; cross-user → 70 keys, anonymous → `401`); `POST /api/v2/photos` = multipart upload;
  **PUT/PATCH/POST on `/api/v2/users/{id}` → 404** ⇒ profile-update route still unknown;
  `OPTIONS` on any `/api/v2/*` → uniform `500`; all 58 JS chunks live on out-of-scope
  `marketplace-web-assets.vinted.com` (cannot fetch ⇒ endpoint discovery needs the operator's
  browser capture of the profile-save request).

## Ruled out (and why)
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

## WAF / defense behavior
- DataDome present (cookie cleared on plain GET; no blocks observed in session 1).
- No 403/406 tripwires hit; rate limits not observed at low volume (≤ ~25 requests total).

## Next session (ranked)
1. **Operator captures the profile-save request** (edit "About me" in browser devtools on
   `www.vinted.com/settings/profile`, paste request) → run stored-XSS cycle: inject marker
   (`zz9x_stored_*<img src=x onerror=alert(document.domain)>`) into `about`/`first_name` →
   read back via `GET /api/v2/users/{id}` → check encoding on `/member/{id}` → **revert**.
2. **Confirm F-04 scope**: is `last_loged_on` rendered on public `/member/{id}`? If not shown in
   UI → unintended metadata disclosure (Info/Low report). Then submit F-01 + F-02 (+ F-04).
3. **IDOR field-diff deepening** (read-only, redacted): `/api/v2/users/{id}` with
   `?locale=`/`?catalog=` variants, other object types (item IDs from sitemaps, `msg` threads) —
   never mutate third-party objects.
4. **Authenticated flows on `sandbox.vinted.com`** (in scope, intended for this): CSRF state-change
   tests (`csrf-testing`), `ref_url`/`next` open-redirect chain (`/member/signup/select_type`).
5. **`badger.it.vinted.com`, `company./careers./news.`, `www.vinted.net`** — untested in-scope hosts;
   different stacks, likely lower hardening → `info-disclosure-testing` + `path-traversal-testing` first.
6. **Source map / bundle audit on `www.vinted.com` local `/_next/static`** (same-host only; assets
   host is out of scope).
