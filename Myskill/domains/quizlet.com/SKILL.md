---
name: quizlet.com
description: Recon notes, scope, attack surface, tested history and open leads for quizlet.com (Quizlet Bug Bounty, Bugcrowd) — use when hunting on Quizlet, resuming the engagement, or when a conversation mentions quizlet.com / *.quizlet.com.
---

# quizlet.com

**Program / authorization:** Quizlet Bug Bounty — Bugcrowd https://bugcrowd.com/engagements/quizlet (in progress since 2018-08-14, partial safe harbor, scope rating 2/4, rewards P1 $1500–2000 / P2 $1000–1250 / P3 $450–600 / P4 $150–200, max $5000, no collaboration).
**Last engagement:** 2026-10-21 (session 1) — recon + reachable-surface testing. **Blocked by Cloudflare managed challenge for all app-layer testing; see "WAF / defense behavior".**

## Scope
- In scope: `https://*.quizlet.com` (Cloudflare-fronted), 3.0 API, Quizlet iOS app, Quizlet Android app.
- Out of scope / exclusions:
  - `api.quizlet.com/2.0` (explicit)
  - `help.quizlet.com` (Zendesk, explicit)
  - `get.quizlet.com` (explicit)
  - slader.com (explicit, since 2025-01-14)
  - **Any Quizlet property not listed in targets** — anything outside `*.quizlet.com` + the listed app/API assets.
  - Rate limiting, scraping of publicly available content, automation concerns — out of scope *unless* premium-content access or significant security impact. **Consequence: Cloudflare challenge/WAF bypass alone is NOT reportable here.**
  - Cheating mechanisms in gaming/testing features, academic-dishonesty manipulation — explicitly not in scope.
  - Never: DoS, payment flows, real user data beyond minimum redacted proof.
- Rate limits & testing windows: unspecified on program page. `study.quizlet.com` advertises `x-ratelimit-limit: 500` (per minute) in headers — stay well under it; small bursts, back off on 429/WAF tripwires.
- Note: `api.quizlet.com/2.0` excluded but **3.0 API** is a listed in-scope target → `api.quizlet.com/3.0` in scope, `2.0` out.
- Scope-hygiene note: `help.quizlet.com` (302) and `get.quizlet.com` (200) were touched **once each** purely to classify reachability; they are out of scope and will not be tested.

## Stack (verified 2026-10-21)
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

### Auth model
- OAuth 2.0 authorization server metadata published at `/.well-known/oauth-authorization-server`:
  issuer `https://quizlet.com`, authorize `https://quizlet.com/oauth/authorize`, token `https://quizlet.com/oauth/token`,
  `code_challenge_methods_supported: ["S256"]` (PKCE, no `plain`), `token_endpoint_auth_methods_supported: ["client_secret_post"]`, `scopes_supported: ["write_set"]`.
- Cookies (apex origin): `qi5` (HttpOnly, Secure, 10y — persistent identity), `fs` (HttpOnly, Secure), `qtkn` (Secure only), `app_session_id` (Secure only, UUID, `Max-Age=1800`), plus `_pxhd`, `_cfuvid`, `__cf_bm`.
- **FP guard for future sessions:** `qtkn` and `app_session_id` lack `HttpOnly`, **but both rotate on every single response** (verified across 4 consecutive responses) — they are per-request trace IDs, not session credentials. **Do not report "session cookie missing HttpOnly".**
- App links: `.well-known/assetlinks.json` → `com.quizlet.quizletandroid` (SHA256 `5C:95:E9:5B:…:1E:2F:1F`); `.well-known/apple-app-site-association` → `RG76J9B7LZ.com.quizlet.quizlet`, `67PY6MH6KF.com.quizlet.iosinternal`.

## Attack surface

### Subdomains & hosts
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

### Endpoints (from 8,000 archived URLs — Wayback CDX, IA was offline for live fetches)

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

### API / GraphQL
- `api.quizlet.com/3.0` in scope; `2.0` out of scope. `/graphql`, `/api`, `/v1`, `/v2` on `study.*` all 404 — no GraphQL endpoint found on reachable hosts. Introspection **untested** (host challenged).

## Findings history
| Date | Endpoint | Class | Status | Report |
|---|---|---|---|---|
| 2026-10-21 | origin responses (`quizlet.com/.well-known/*`, `el.*`) | Missing security headers (no CSP/XFO/XCTO/RP/PP) | Confirmed, Low | `findings/F-01-missing-security-headers-origin.md` |
| 2026-10-21 | `el.quizlet.com/` | Internal k8s/Envoy topology via `x-envoy-decorator-operation` + open event sink | Confirmed, Low / ingestion informational | `findings/F-02-envoy-k8s-service-disclosure.md` |
| 2026-10-21 | `quizlet.com/.well-known/*` | Internal routing metadata via `quizlet-action-name` / `quizlet-route-importance` | Confirmed, Informational | `findings/F-03-internal-routing-header-disclosure.md` |

## Ruled out (and why)
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

## Open leads (not ruled out — blocked by the challenge)
- **Rollbar source maps:** `source_map_enabled: true` + `code_version: 6e5fa810072c01c271a7c50ba62e981d9e4860b4`. `.js.map` / `_buildManifest.js` probes all challenged. High value (V-09).
- **`redir` parameter** open redirect on `/{id}/view-screen`.
- **OAuth `/oauth/authorize`**: `redirect_uri` whitelist, PKCE downgrade (S256-only claims), `state`/CSRF, auth-code leakage via `Referer`.
- **IDOR** on numeric set IDs / `setIdOrUsername`; `/{id}/delete`, `/{id}/edit` CSRF.
- **Clickjacking PoC** (ties to F-01) on `/forgotten/password` or embed flows — needs a framing-able page.
- **API 3.0 authz** with a registered PKCE client (`write_set` scope enforcement).
- **`el /status`** from a non-blocked network.

## WAF / defense behavior (characterized 2026-10-21)
- **Cloudflare managed challenge**, page title `Captcha Challenge…`, `403` + `cf-mitigated: challenge`, ~116–160 KB. Triggered on: `www.*` (all paths), apex `/`, `/robots.txt`, `/sitemap.xml`, `/favicon.ico`, `/humans.txt`, `/_next/static/*` (JS + `.map`), `/{page}` HTML routes, `/oauth/*`, `/api/3.0/*`, `assets.*`, `admin/cp/docker/elastic/…`.
- **Challenge-exempt (verified):** `/.well-known/**` on apex — match is on the `/.well-known/` **substring** (`/anything/.well-known/assetlinks.json` also passes, then 302s to `/error`). Strict prefix semantics for `..`: CF normalizes before the rule, so `/.well-known/../robots.txt` is challenged. Whole hosts that pass: `study.*`, `el.*`, `jg7y.*`, `ablink.*`.
- **Second rule = hard block:** `403` titled `Request blocked`, **no `cf-mitigated` header** (distinguishes it from the challenge). Hits: `PATCH` to any path, any path containing `status`, backup extensions (`.bak`).
- **Sticky/learned:** first apex request in a session passed, subsequent ones challenged; the wall persists for the IP. Full browser header set (sec-ch-ua, Sec-Fetch-*) did **not** help — it escalates to an interactive captcha, which cannot be solved headlessly.
- **Not solved this session:** no browser tooling available in this session (`built-in-browser` tools absent from the tool catalog), so no legitimate challenge clearance could be obtained.
- **Header asymmetry (basis of F-01):** Cloudflare's challenge/block pages emit `x-frame-options: SAMEORIGIN`, `referrer-policy: same-origin`, `x-content-type-options: nosniff`, COOP/COEP/CORP and locked-down `permissions-policy`; **origin responses through the same CDN do not.**
- **Second bot layer:** PerimeterX/HUMAN (`_pxhd`) — independent of Cloudflare, so clearing CF alone may not be enough.

## Next session (ranked)
1. **Unblock first.** Ask the user to open `www.quizlet.com` in their own browser and either test from their network or supply their own `cf_clearance` cookie for `quizlet.com`. Everything below depends on it. (Do not attempt captcha automation — out of scope and inappropriate.)
2. **`redir` open redirect** — fetch `https://quizlet.com/<id>/view-screen?redir=%2F...`, mutate to `https://evil.example`, `//evil.example`, `/\evil.example`, `@`-form; check `Location`.
3. **OAuth `/oauth/authorize`** — `redirect_uri` suffix/prefix matching, unregistered URI, PKCE `code_verifier` bypass, `state` omission, response-mode probing, auth-code in `Referer` to third parties.
4. **IDOR** on `/100000000/…` sets and `setIdOrUsername`; then create two test accounts and try `/{id}/delete`, `/{id}/edit`, `/{id}/scores` cross-account. (bac-idor skill.)
5. **Sourcemaps** — pull `assets.quizlet.com/_next/static/chunks/*.js.map` and Rollbar `code_version` maps → full source → hardcoded secrets, `write_set` endpoint list. (info-disclosure V-09/V-06.)
6. **Clickjacking PoC** for F-01 (frame `/forgotten/password` or the embed flows) to lift F-01 from informational to Low.
7. **API 3.0** with a PKCE client: scope enforcement, Bearer token authz, mass assignment on set update. (bac-idor / business-logic.)
8. **`el.quizlet.com/status`** from a clean network — if it returns internal state, F-02 escalates.
9. **`study.quizlet.com`** — one API-oriented wordlist (e.g. raft-large-words) + verb matrix; it answers with `x-runtime` but nothing routed yet.
10. Re-check `crt.sh` (502 all session), Wayback (offline all session), OTX (429) for a fuller subdomain set.
