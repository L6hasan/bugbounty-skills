---
name: hub.devolutions.com
description: Recon notes, scope, attack surface, tested history and open leads for hub.devolutions.com (Devolutions Cloud) — use when hunting on this target, resuming the engagement, or when a conversation mentions hub.devolutions.com or Devolutions Cloud.
---

# hub.devolutions.com — Devolutions Cloud

**Program / authorization:** Devolutions Inc. private bug bounty on YesWeHack (invitation-only).
Operator is ENROLLED — program guideline pasted by operator on 2026-10-25 as proof of
invitation/permission. Public policy page: https://devolutions.net/security. Out-of-program
issues → security@devolutions.net.
**Last engagement:** 2026-10-25 (session 1 — unauthenticated pass; 2 findings: F-01, F-02)

## Scope
- In scope: **Devolutions Cloud** (cloud password manager for teams) — `hub.devolutions.com`
  verified as the Cloud app (`<title>Devolutions Cloud</title>`). Likely Cloud-adjacent hosts:
  `login.devolutions.com`, `login.devolutions.xyz` (identity), API hosts TBD from JS bundles.
  Also in scope: **Devolutions Crypto** open-source crypto library (GitHub review).
- Out of scope / exclusions:
  - Third-party crypto primitives (Devolutions Crypto section).
  - Third-party infrastructure: Cloudflare edge IPs (172.65.90.4-7 are Cloudflare anycast —
    scanning them = scanning Cloudflare, NOT Devolutions), Azure Blob hosts
    (`*.blob.core.windows.net`), Google/Gravatar, Outlook mail protection.
  - **Real customers' data — MUST NOT be read, altered, or impacted.** The operator's pasted
    scope says the trial environment is PRODUCTION: "real customers could be impacted by the
    tests, so we ask to be careful."
  - Conservative defaults (pasted guideline was truncated before the full testing-policy
    list): no DoS/service degradation, no brute-force/credential stuffing, no account
    enumeration against real users, no social engineering.
- Permitted explicitly: creating **multiple trial accounts** to test data segregation and
  access controls (relevant for a future authenticated session).
- Rate limits & testing windows: none stated in paste — be conservative: small bursts,
  back off on 429/WAF signals, throttle scanners.

## Stack (verified 2026-10-25)
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

## Attack surface
### Subdomains & hosts
| Host | Purpose | Stack | Notes |
|---|---|---|---|
| hub.devolutions.com | Devolutions Cloud app | CF + Envoy + SPA | 172.65.90.4-7 (Cloudflare) |
| login.devolutions.com | identity (guess) | TBD | named in CSP default-src |
| login.devolutions.xyz | identity (guess) | TBD | named in CSP default-src |
| *.blob.core.windows.net | fonts/icons | Azure | third-party, out of scope |

### Endpoints
| Endpoint | Params | Auth | Signal / sink | Tested? |
|---|---|---|---|---|
| GET / | — | none | SPA shell, 2292 B | yes (baseline) |
| GET robots.txt | — | none | blanket disallow | yes |
| GET /.well-known/security.txt | — | none | SPA fallback (soft-404) | yes |

### API / GraphQL
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

## Findings history
| Date | Endpoint | Class | Status | Report |
|---|---|---|---|---|
| 2026-10-25 | GET /api/server-configurations | Info disclosure (OpenSearch cred) | CONFIRMED | F-01 |
| 2026-10-25 | GET /client*/main.js.map | Source-map exposure (42MB TS) | CONFIRMED | F-02 |

## Session-2 follow-up (2026-10-25): F-01 validated, RCE + SQLi investigated
- **F-01 VALIDATED:** leaked `prodhub` credential is real — authenticates to
  `telemetry2.devolutions.net:9200` (OpenSearch + security plugin), 403 with
  `backend_roles=[]` on every capability probe (`_cluster/health`, `_cat/indices`, `_nodes`).
  Inert account → severity dropped Medium→Low. No data read.
- **RCE "sandbox" = FALSE LEAD (unauth).** 645 `powershell` + 2323 `terminal` + 482 `wasm`
  refs are: (1) RDM **client-side connection-launch metadata** (`*EmbeddedPowerShellScript`,
  `ExecutionPolicy`, `Invoke-Expression` in XML connection templates — executes on the
  CUSTOMER's machine when they open a connection, by design), and (2) bundled node_modules
  `new Function(` in `web-ssh-gui` / `web-terminal-gui` / `iron-remote-desktop-vnc` /
  `jszip` / `picky` — **browser-side** remote-session rendering engines. NO server-side
  exec/SQL surface in client source (no child_process/spawn; SqlServer/Dapper/Postgres hits
  are node_modules). Requires an authenticated session + real target to even reach, and
  executes on the RDM client, not the Hub server. Not a server RCE.
- **SQLi = NOT FOUND (unauth).** sqlmap level1/risk1 on the only reachable unauth 200
  endpoint (`/api/server-configurations`) → "all tested parameters do not appear injectable".
  nuclei sqli/injection templates (high+crit) → 0 confirmed. Manual time-based differential
  on `POST /api/searches/entries` (`SLEEP(5)`) → payload 0.14s vs baseline 0.29s (no delay;
  and the route 401s unauth anyway). All real data endpoints are auth-gated (401 empty).

## Ruled out (and why)
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

## WAF / defense behavior
Cloudflare in front (waf-detect=cloudflare; `cf-ray`/`__cf_bm`/`cf-cache-status: DYNAMIC`).
No managed-challenge observed on any request this session. Envoy behind edge
(`x-envoy-upstream-service-time`). Auth errors are empty-body 401s (deliberately opaque).
No rate-limit / 429 hit at conservative throttle.

## Session-1 recon artifacts (evidence/recon/)
`gau-urls.txt` (485), `wayback-urls.txt` (1), `api-endpoints.txt` (161), `main-*.js`,
`main.js.map`, `embedded-source.ts` (42MB), `server-configurations.json` (raw cred),
`server-config-redacted.json`, `server-config.headers`, `subs-{com,net}.txt`,
`cand-subs.txt`. Recon tools available & confirmed installed: waybackurls, gau, arjun,
dalfox, katana, xsstrike, httpx, subfinder, amass, nmap, ffuf, nuclei, sqlmap, jq.

## Next session (ranked)
0. **Rotate/validate F-01 with Devolutions** — confirm the `prodhub` password is rotated and
   the `openSearch` block removed from the public config. (Report-ready; severity Low.)
1. **Authenticated trial session** (program explicitly allows multiple trials) → IDOR /
   cross-tenant data segregation / mass-assignment on the 401-gated routes (users, vaults,
   vault-entries, invitations, roles). Highest value; unauth surface is well-gated.
2. **Trace `SafeHtmlPipe` / `MarkdownPipe` (`bypassSecurityTrustHtml`)** — find whether
   user-controlled vault entry fields (names, notes, markdown) reach them → stored DOM-XSS.
   Needs auth + a trial vault entry to test.
3. **Devolutions Crypto GitHub review** (in-scope: algorithm impl, CSPRNG, memory mgmt) —
   static review of the open-source lib shipped in the bundle.
4. **F-01 follow-up:** determine cluster reachability boundary (public vs private route) —
   do NOT authenticate; report reachability only. Recommend rotation regardless.
5. **Dalfox/xsstrike** on any reflected param found once a real (non-soft-404) reflective
   surface is identified; none found unauthenticated so far (SPA routes are client-side).
6. **CSWSH on SignalR:** re-probe `signalr-personal.hub.devolutions.com` from an authenticated
   browser context — negotiate only works with a session; check Origin validation on the WS.

## Bounding rules carried from program scope
- Real customers could be impacted → NO data exfiltration of real tenants; only prove at
  marker/boolean depth. Third-party infra (Cloudflare edge IPs, Azure Blob, mindinabox
  telemetry cluster) is OUT of scope — do not authenticate to the leaked OpenSearch cluster.
- Conservative defaults (pasted guideline truncated): no DoS, no brute-force, no account enum
  against real users.
