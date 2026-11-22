---
name: getoutlaw
description: Recon notes, scope, attack surface, tested history and open leads for fv.getoutlaw.com (Outlaw bug bounty, Inspectiv) — use when hunting on this target, resuming the engagement, or when a conversation mentions getoutlaw.com / fv.getoutlaw.com / Outlaw.
---

# getoutlaw.com

**Program / authorization:** Outlaw bug bounty program (hosted on Inspectiv) — program brief provided verbatim by operator 2026-10-23. Contact: programs@inspectiv.com. Payout Tier 6.
**Last engagement:** 2026-10-23 (session 2 — 5-URL technique sweep; findings F-01/F-02 written)

## Scope
- In scope: `http://fv.getoutlaw.com/` (Web Application, production) — the only asset listed In Scope.
- Out of scope / exclusions (program-specific):
  - Broken Access Control relying on WebSocket connections or overly permissive WebSocket information disclosure
  - MITM / physical access attacks; any 3rd party outside the program's domain spaces
  - Arbitrary file upload **without** proof/evidence of the uploaded file
  - DoS / DDoS including Rate Limiting disruption
  - Broken Link Hijacking; Blind SSRF without negative impact; Clickjacking/Tapjacking
  - CVEs published <90 days; CVEs without PoC; CORS misconfig on non-sensitive endpoints or without negative impact
- **MANDATORY header on ALL requests:** `X-Inspectiv-Tester: hasansec+3@wearehackerone.com` (operator's email = username; confirmed by operator 2026-10-23). **Browser caveat:** send this header ONLY to getoutlaw.com hosts — sending it cross-origin (identitytoolkit.googleapis.com) breaks Google's CORS preflight (403) and Firebase login fails with `auth/network-request-failed`. Route-scope the header in Playwright (`ctx.route`).
- Authenticated testing: credentials at `~/.config/bughunter/getoutlaw-credentials.env` (mode 600; never copy into this profile). Firebase login OK — test account is **standard (non-admin)**; admin endpoints (`/users/search`, `/teams/search`, `/tools/inspect-url`) return "Admin access required". Tokens live ephemerally in `/tmp/opencode/fv/tokens.env`.
- Record hygiene: **no mass create/delete/change of records.** Own test records go in the *second organization* if applicable.
- **Cross-account access = STOP immediately and report.** Do not continue probing once another account's data is reachable.
- Rate limits & testing windows: unspecified — be conservative (rate limiting itself is out of scope, so bursts look like DoS).

## Stack (verified 2026-10-23)
- WAF: **Cloudflare** (cf-ray present; dotfile paths like `/.env`, `/.git/*` → CF block page 403). `via: 1.1 google` → GCP origin behind CF.
- Server / framework: SPA (React, webpack bundle `outlaw.<hash>.js` ~10.9MB, no sourcemaps — `.map` → 404). `window.environment='prod-filevine'`, `INSTANCE:"filevine"`, `INSTANCE_DISPLAY:"Filevine"` — this is a Filevine-hosted instance. CSP nonce-based, per-request nonces; static `'nonce-firebase-auth-helper'` entry in script-src (potential CSP bypass primitive — chain only).
- Auth model: **Firebase Auth** (`identitytoolkit.googleapis.com/v1/accounts:signInWithPassword`, `/v1/token` refresh; public web API key in bundle, projectId `outlaw-filevine`) + custom `/auth/fvid-link`, `/auth/fvid-enabled`, Okta SSO at `/auth/okta/{teamId}/callback`. Tokens via Firebase idToken/refreshToken.
- API: `API_BASE_URL=https://fv-api.getoutlaw.com` (separate host — **operator confirmed in-scope 2026-10-23** as the backend of the listed app). Endpoints seen in bundle: `/v1/token`, `/v1/projects`, `/v1/recaptchaParams`, `/v2/passwordPolicy`, `/v2/recaptchaConfig`, `/v2/accounts`, `/v2/accounts:mfaEnrollment|mfaSignIn`, `/auth/fvid-link`, `/tools/inspect-url`, `/users/search`, `/teams/search`, `/lfw/exports`.
- Other intel: Sentry DSN (bundle, public by design), Pendo key `37db06b7-…`, Firebase config public (normal). CT shows 83 getoutlaw.com subdomains — **only fv.getoutlaw.com + fv-api.getoutlaw.com authorized**; do not touch others.
- Notable middleware: CSP with per-request nonce + `x-xss-protection`, HSTS includeSubDomains, referrer-policy `no-referrer-when-downgrade` (weak but low value), no robots.txt/sitemap/security.txt (SPA fallback 200 for all).

## Attack surface
### Hosts
| Host | Purpose | Auth | Notes |
|---|---|---|---|
| fv.getoutlaw.com | SPA + same-origin API proxy `/api/*` → Cloud Functions | Firebase Bearer | `/api/{fn}` routes to `us-central1-outlaw-filevine.cloudfunctions.net/{fn}` server-side; anon allowed only for callAnon fns |
| fv-api.getoutlaw.com | Backend REST (`/users/{id}`, `/teams/{id}`, `/deals/{id}`, `/auth/*`, `/v1/*`, `/v2/*`) | Firebase Bearer | operator-confirmed in-scope |
| us-central1-outlaw-filevine.cloudfunctions.net | GCP RPC layer (same project) | Firebase Bearer | no CORS headers at all; treat as app backend (same operator ruling as fv-api); direct calls mostly 404 except real fn names |
| outlaw-filevine-default-rtdb.firebaseio.com | Firebase RTDB | `?auth=<idToken>` (Bearer format rejected) | rules deny root + unauth; own-deal path read OK |

### RPC functions (via fv.getoutlaw.com/api/*)
| Function | Auth | Signal | Tested |
|---|---|---|---|
| getDeals | Bearer | raw ES response (took/_shards/nbHits/aggregations); scope = own org only | yes — injection probes clean, tenant isolation holds |
| **getBundle** | **NONE** | **full deal bundle for any dealID — FINDING F-01** | yes |
| checkAccount | NONE | returns ["password"]/[] per email — enumeration, FINDING F-02 | yes |
| getInvite | NONE | properly access-controlled (403 without inviteID+duKey) | yes |
| sendSignInLink / sendPasswordResetEmail | NONE | 200 success even for malformed input; no oracle | yes (light) |
| getOpenIDProvider | NONE | empty body for all probed domains (no SSRF reflection) | yes (light) |
| importDocxTemplate | Bearer | validates `templateData.team` before file handling (400) | yes (validation stage only) |
| mergeAccounts | Bearer | redirect param → history.replace (browser SecurityError on cross-origin) | yes |
| convertDocument, tasks, getDocumentData | Bearer | export/convert sinks; filename flows to `/api/storage?filename=` | light |
| users/search, teams/search, tools/inspect-url | **Admin** | search + SSRF sink (`inspect-url`) — unreachable as standard user | blocked by role |

### Other routes
- `/api/storage?taskID=&taskType=&filename=` — checks taskID first (404 before filename used); traversal filename not reachable without valid task. `/api/pdf?dealID=` exists (timed out on generation).
- Firebase Storage resumable upload (`X-Goog-*` internals in bundle) — client→GCS direct; app-level upload endpoint not separately identified; `uploadAttachmentDOCX/PDF`, `uploadPDF` keys present.
- 5 SPA routes (`/account/debug-settings` → Profile page, `/dashboard`, `/dashboard/contracts` = Saved Filters w/13 inputs, `/dashboard/team`, `/deals/{id}/contract`) all render authenticated, all client-side only.

## Findings history
| Date | Endpoint | Class | Status | Report |
|---|---|---|---|---|
| 2026-10-23 | POST /api/getBundle | BAC — unauthenticated object read | **Proven** (anon==authed byte-identical; 2 objects; 404 control) | `findings/F-01-getbundle-unauthenticated.md` |
| 2026-10-23 | POST /api/checkAccount | User enumeration oracle | Proven | `findings/F-02-checkaccount-enumeration.md` |

## Ruled out (and why)
- **Reflected XSS (5 URLs):** params reflected only into `og:url` meta, URL-encoded; raw `<`/`"` in URL → CF 400. No executable context.
- **DOM XSS:** `location.hash`×1, `location.search`×9, no `document.URL`/`window.name` sources; zero source→innerHTML/document.write flows. `props.html`→innerHTML is the internal contenteditable editor (server-authored content). `vkt.xss()` sanitizes vis-timeline innerHTML. Query/hash payloads on all 5 routes in real Chromium → no execution.
- **Stored XSS:** own `fullName` canary `zzstore1 <img src=x onerror=…>` renders React-escaped on /account/profile (text node).
- **CSRF:** Bearer-only (no Set-Cookie anywhere; Firebase token in JS storage) — browsers never attach it cross-site. Preflight lacks ACAO for foreign origins; evil-Origin PATCH returns 200 but is meaningless without ambient creds. Bearer-in-localStorage = CSRF not applicable.
- **Open redirect:** `login?redirect=//evil.example/zz` → `history.replace` throws browser `SecurityError` on cross-origin — blocked, not exploitable.
- **IDOR/BAC:** `/users/{id}` PATCH self-only (cross-user 403 "User not authorized."); GET admin-gated. `/teams/{id}` same pattern. Mass-assignment (`info.role`, `info.admin`) → 200 but ignored: admin endpoints still inaccessible after PATCH. `getDeals query="*"` → nbHits=1 (own deal only) — tenant isolation holds. RTDB root/rules denied; own-deal path OK. `getInvite` access-checked. No second account available for two-account proof.
- **SQLi/ES injection:** `query=")("` → safe empty; sort-as-array / `_script` sort → 500 empty body (no data/stack leak); string sort accepted (field-name only).
- **RCE:** no server-side code-exec sink; formula `eval` is a client-side spreadsheet parser on template config (self-view only, no user-input flow from URL).
- **LFI / path traversal:** encoded `..%2f` → CF 400; unencoded → SPA 200; null byte → CF 400; `/api/storage` validates taskID before filename.
- **SSRF:** `/tools/inspect-url` is admin-gated (403/404 for standard user); `getOpenIDProvider` returns empty bodies (no fetch reflection) incl. IP-literal probe. Cloud Functions return no ACAO (no cross-origin read).
- **CORS:** fv host /api — no ACAO for evil origins (actual POST + preflight); cloudfunctions.net — no CORS headers at all.

## WAF / defense behavior
- Cloudflare edge: 400 on raw `<`, `>`, `"` in URL path/query; 400 on encoded traversal (`..%2f`, `%2e%2e`) and null bytes; dotfiles → CF 403 block page. Unencoded `../` normalized → SPA 200.
- SPA fallback: every unmatched path → index.html 200 (~3.6KB, per-request CSP nonce, og:url echoes full request URL URL-encoded).
- API throttling: repeated `/api/getDeals` bursts → request hang/timeout (no 429, connection just stalls); back off and retry after ~45s.
- CSP: nonce-based; static `'nonce-firebase-auth-helper'` entry in script-src — chain primitive only, unproven.
- RTDB: rules deny unauth and root even with valid token; Bearer header format rejected, only `?auth=` query works.

## Next session (ranked)
1. **Submit F-01 (getBundle) to Inspectiv** — evidence files listed in the finding doc; ask operator whether program wants a foreign-deal demo (STOP rule: cross-account = stop+report, so clarify handling before ever touching a foreign dealID).
2. Admin-role surface: `/tools/inspect-url` SSRF sink, `/users/search`, `/teams/search` BAC — need admin creds (ask operator for an admin test account; two-account IDOR proof also needs a second account).
3. `importDocxTemplate` with valid `templateData` (single own-template creation is within record rules) — filename/handling once validation passes; needs proof of stored file per program.
4. File-upload XSS: exercise the in-app attachment upload (uploadAttachmentDOCX/PDF keys) on own deal, then verify served content-type/disposition of the stored object.
5. `/api/pdf?dealID=` and `/api/storage` with a real export taskID — filename handling end-to-end.
6. Chain candidate: CSP static `'nonce-firebase-auth-helper'` entry — verify whether any script actually carries that nonce (would turn any future HTML-injection into full XSS).
