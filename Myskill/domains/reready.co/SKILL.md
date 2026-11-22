---
name: reready.co
description: Recon notes, scope, attack surface, tested history and open leads for reready.co (ReReady / Add Four LLC) — use when hunting on this target, resuming the engagement, or when a conversation mentions reready.co, sandbox.reready.co or the ReReady bug bounty program.
---

# reready.co

**Program / authorization:** Self-hosted bug bounty + VDP — https://www.reready.co/help/vulnerability-bug-bounty-program
(Last updated 2026-10-23. Email reports to `support@reready.co`, one vuln per email,
Bugcrowd VRT naming, ≥5 business days response wait, no pinging within 5 days.)
**Last engagement:** 2026-10-25 (session 1)

## Scope

⚠️ **The program's hard rule (quoted):** *"You must use our sandbox environment for all
testing… If you perform unauthorized testing in our production environment NOT your
accounts will suspended and your reports rejected."*

- **In scope:** `sandbox.reready.co` (http/https) — "No approvals are required, and sandbox
  accounts are free… identical to production except:" sandbox **WILL** send emails, will
  **NOT** send texts / process payments / create shipping labels / trigger fulfillments.
  AI-agent testing explicitly welcomed ("responsible and does not degrade our environment").
- **Out of scope:** `www.reready.co` + `reready.co` production — testing there = account
  suspension + report rejection. Read-only public-page browsing of production for scope intel
  only; **no active probing, no payload requests against production.**
- Also out of scope by policy: DoS/degradation of any kind (no fuzz floods, no large-body
  tests), third-party hosts (Stripe, Google, LinkedIn, Zendesk…) — report-chain only.
- **No bounty for:** re-reports within 5 business days, P5 email-exposure, expected behavior
  (password re-use allowed, ordinary users managing payment methods/addresses/orders).
- **Bounties:** P1 $1,000 / P2 $500 / P3 $200 / **P4 $0 / P5 $0 since 2026-10-23**
  → P4/P5 findings = findings, but no payout; prioritize P3+.
- Rate limits & testing windows: unspecified — be conservative (policy says "does not degrade
  our environment"). Small bursts, back off on 429/403 patterns.

Note: the literal host `www.reready.co.test` in the original request is **NXDOMAIN** — it was
a garbled parse of `reready.co` + "test …" prose. Verified 2026-10-25.

## Stack (verified 2026-10-25, sandbox)

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

## Attack surface

### Subdomains & hosts
| Host | Purpose | Stack | Notes |
|---|---|---|---|
| `sandbox.reready.co` | **authorized test env** | nginx + Rails | 165.227.99.141 |
| `www.reready.co` | production | nginx + Rails (same app) | 165.227.223.207 — **out of scope for active testing** |
| `reready.co` | apex → prod | — | resolves to prod IP range |

### Endpoints
| Endpoint | Params | Auth | Signal / sink | Tested? |
|---|---|---|---|---|
| `/` | — | none | marketing SPA/SSR page, GTM + GA preload w/ nonce | recon only |
| `/users/sign_in`, `/users/sign_up` | authenticity_token | none | Devise auth flow; POST = session state change ⇒ CSRF class | pending |
| `/help`, `/help/vulnerability-bug-bounty-program` | — | none | help center (scope intel source) | read (scope gate) |
| `/rest-api-documentation` | — | ? | **REST API docs ⇒ full endpoint inventory** | pending |
| `/.well-known/security.txt` | — | none | app 404 (no security.txt published) | 404 |
| `/robots.txt` | — | none | **nginx 404** (static-served) | 404 |

### API / GraphQL
Unknown — `/rest-api-documentation` not yet fetched. No GraphQL seen yet.

## Findings history
| Date | Endpoint | Class | Status | Report |
|---|---|---|---|---|
| 2026-10-25 | session 1 | all unauth classes | **no confirmed findings** (see evidence/) | not reported |

## Authentication testing (2026-10-25, sandbox only — no successful login yet)
- Login POST with 2 operator accounts → 200 + generic
  `Invalid email or password (or one-time code if you enabled two-factor authentication).`
  ⇒ accounts are production-only (env isolation proven). **Never** retry them against prod.
- No captcha on `/users/sign_in` (all *email-sending* flows have reCAPTCHA).
- Rate limit: **429 from attempt 6** (5 failures), 12-byte body ⇒ brute-force mitigated.
- Error message is uniform/generic — no enumeration oracle established yet (needs one
  known-EXISTING sandbox account as control).
- Session fixation: **not yet testable** — rotation must be observed on a *successful* login.
- Logout via GET → 404 (no GET state change).

## Ruled out (and why)
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

## WAF / defense behavior
None detected. CSP nonce + strict-dynamic is the main XSS defense.

## Next session (ranked)
1. **BLOCKER — get a sandbox account:** operator must sign up at
   `https://sandbox.reready.co/users/sign_up` (free, no approval, reCAPTCHA requires a human;
   email goes to the mailbox referenced in `~/.config/bughunter/test-mailboxes.env`). Signup is
   passwordless — complete the emailed confirmation link, then set/confirm the password and hand
   me the credentials (mode-600 file, never in chat/skills). Everything below is gated on this.
2. Authenticated session tests: **session id rotation on login** (fixation), logout invalidation
   (replay pre-auth cookie), idle timeout, session revocation after password change, concurrent
   sessions, 2FA enrollment + backup-code handling.
3. API key lifecycle + **cross-account IDOR** with the 2nd account:
   `GET/PATCH /api/v1/device_transfers/:uuid`, `/api/v1/shipments/:id` — cross-user 403 vs 404 oracle.
4. Stored XSS: `organization_name`, `name`, `phone_number`, transfer `notes.body`,
   `ticket_reference` → then confirm CSP (`strict-dynamic` + nonce) actually blocks execution.
5. CSRF on authed state-changing POSTs (profile update, API-key create, order create) — same
   token/Origin matrix, plus login CSRF with a live session.
6. Mass assignment on profile/order PATCH (probe `user[role]`, `admin`, `api_key`, `otp_required`,
   `organization_id`) — form only exposes a subset.
7. SSRF: webhook URL fields, integrations (bamboohr/jamf/zenefits), any import-from-URL.
8. SQLi on authed list endpoints (`page`, `order`, `sort`, filters) with a real oracle.
9. Path traversal on any download/export/upload endpoint; upload → XSS/RCE via filename.
10. Business logic: sandbox payment simulation (Stripe test cards), plan/seat limits,
    address/payment-method flows (explicitly *expected behavior* for normal users → low value).

## Recons done (don't redo)
- Source-level: `application.js` (1.14 MB) + `application.js.map` (168 KB, **publicly served**)
  decompose the bundle — Chartkick 5.0.1, Chart.js 4.5.1, chartjs-adapter-date-fns 3.0.0,
  date-fns 2.30.0, popper 2.11.8, Bootstrap 5.3.8, rails-ujs + first-party `slide_toggler`,
  `bootstrap_popover/tooltip` init, `rails_ujs_config` (disables rails-ujs remote `dataType:'script'`
  — deliberate hardening), `application.source.js` (11 lines).
- **Original `.source.js` files are directly fetchable** (Sprockets live compile, unhashed logical
  paths): `application.source.js` (235 B = the `//= require` manifest listing ALL dependencies),
  `slide_toggler.source.js` (2344 B), `rails_ujs_config.source.js` (692 B),
  `rails-ujs.source.js` (24 KB). Also served unhashed: `application.css` (248 KB),
  `activestorage.js` (30.5 KB), `actiontext.js` (34 KB) ⇒ **Active Storage + Action Text are in
  the stack** (attachment/direct-upload endpoints = next-session surface; `channels/consumer.js`
  404 ⇒ no ActionCable).
- **First-party JS is only ~2 files**, both read exclusively server-rendered `data-*` attributes
  (`data-slide-toggler-target`, `data-toggle-target-class`) into `querySelectorAll` — no URL
  input reaches any sink anywhere in shipped JS. Selector is only attacker-influenced if HTML
  already is (i.e. needs a prior XSS) ⇒ DOM XSS dead at source level, independent of CSP.
- jQuery **not** bundled: `/blog` and `/help` load `code.jquery.com/jquery-3.7.1.min.js` +
  `cdn.datatables.net/3.0.3/js/dataTables.min.js` from CDN (nonced); app asset
  `datatables.js` (174 B) just inits `$('.datatable')`.
- No secrets/keys/emails/internal URLs/server paths anywhere in the bundle; source maps expose
  *file names only* (`sourcesContent` absent).
- Assets: `application-<digest>.js` **404s** (importmap target!) while unhashed
  `/assets/application.js` 200s ⇒ **first-party bundle never executes in-browser** → DOM-XSS
  sweeps here would false-clean; assert script execution before trusting zeros.
