---
name: frontier.com
description: Recon notes, scope, attack surface, tested history and open leads for bgp.frontier.com and ipadmin.frontier.com (Frontier BGP / IP Admin, Inspectiv engagement) — use when hunting on this target, resuming the engagement, or when a conversation mentions bgp.frontier.com, ipadmin.frontier.com, Frontier BGP or the Frontier IP Admin form.
---

# frontier.com — bgp/ipadmin scope

**Program / authorization:** Inspectiv managed bug bounty (private program — no public
policy page; scope confirmed directly by operator 2026-10-24). Origin of engagement: a
researcher report against `/bgp_procedures_new_form.php` (reflected XSS claim, Inspectiv
PoC headers present in the pasted report).
**Last engagement:** 2026-10-24

## Scope
- In scope (operator-confirmed 2026-10-24): **bgp.frontier.com** (all paths), **ipadmin.frontier.com**
  (all paths), HTTP + HTTPS. Unauthenticated testing is enough (no test account in play).
- Out of scope: every other `*.frontier.com` host. crt.sh shows 376 names (sso, api-prod,
  partnerportal2-qat, solr, fybrlabs, speedtest, webmail, payment-*, …) — **do not touch
  without new scope confirmation**. Archived in `references/ct-names.txt`.
- Exclusions: DoS/rate abuse, authenticated actions without an operator-supplied session,
  retaining any discovered credentials.
- Rate limits: unspecified — be conservative. Fuzzing used ≤15 req/s, ≤6 threads.

## Stack (verified 2026-10-24)
- WAF / LB: **Radware Alteon** (`AlteonP=` persistence cookie, `Vary: SSLProxy`). No
  payload-specific blocking observed: 200 KB POST body accepted, `<script>` never 403'd;
  the only WAF-ish behavior is Apache returning **400** for invalid characters in `Host`.
- Server: Apache (`Server: Apache`, default iso-8859-1 error pages, dir listing 403,
  `.phps`/`.swp`-style source extensions generically 403'd, unknown `.php` → real PHP 404).
- App language: PHP — sole dynamic endpoint `/bgp_procedures_new_form.php`
  (PATH_INFO `/…php/xxx` accepted → 200, no PATH_INFO reflection).
- Output encoding: **all reflected POST fields entity-encoded**
  (`<`→`&lt;` `>`→`&gt;` `"`→`&quot;` `'`→`&#039;` `&`→`&amp;`) inside quoted
  `value="…"` / `<textarea>` contexts. No double-decode (`%2522` stays literal `%22`).
- CSP: **none** anywhere (no CSP/Trusted Types/X-Content-Type-Options headers observed) —
  if an injection ever opens up there is no browser-level mitigation.
- Cookies: `AlteonP` set without HttpOnly/Secure/SameSite.
- Auth model: **none observable unauthenticated** — no login form on either host. The
  original report's "authenticated Frontier administrator" surface (a management layer) is
  not reachable from these two hosts unauthenticated; UNKNOWN whether it exists.
- Two vhosts, one app: `/` and `/bgp_procedures_new_form.php` returned **md5-identical**
  bodies on bgp.* and ipadmin.* (same backend, different vhosts).

## Attack surface

### Subdomains & hosts
| Host | Purpose | Stack | Notes |
|---|---|---|---|
| bgp.frontier.com | BGP application info + BGP routing request form | Apache+PHP+Alteon | primary scope |
| ipadmin.frontier.com | same app, mirrored vhost | same | byte-identical responses |

### Endpoints (complete BFS crawl 2026-10-24 — 16 HTML + 1 PHP)
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

### API / GraphQL
None. No swagger/openapi/graphql/robots.txt/security.txt/sitemap (all 404).

## Findings history
| Date | Endpoint | Class | Status | Report |
|---|---|---|---|---|
| pre-2026-10-24 | /bgp_procedures_new_form.php (asn) | reflected XSS (attribute injection) | **researcher report (Inspectiv)** — claimed unquoted `value=` reflection; NOT reproducible 2026-10-24: reflection is quoted + entity-encoded. Possibly fixed after report, or report was a false positive. | user-pasted report, status unknown |
| 2026-10-24 | `/.gitignore` (both hosts) | info disclosure — internal structure | confirmed, evidence saved | `findings/001-gitignore-structure-disclosure.md` |
| 2026-10-24 | `/envvars/global.php`, `/.config.php`, `/themes/`, `/envvars/` (both hosts) | exposed internal config surface (silent) | confirmed, evidence saved | `findings/002-exposed-internal-config-endpoints.md` |

## Ruled out (and why)
- GET query params on form endpoint → no reflection at all (POST-only rendering).
- Host header injection → 301 body echoes Host but Apache **400s** special chars; `Location:` is static (`https://frontier.com`), no open redirect.
- 404 path reflection → absent (default Apache error page).
- Cookie / User-Agent / Referer / X-Forwarded-For reflection → none.
- PATH_INFO reflection → none.
- Double URL-encoding bypass (`%2522`) → no second decode; `%22` decoded then encoded.
- Multipart vs urlencoded vs full valid-data submission → identical encoding; no second "review" template exists (app_type=new/existing both re-render same form).
- Unknown extra POST params (page/file/template/lang/redirect/url/next/view/debug/preview/format/callback/target) → silent; only the 18 known fields reflect.
- Error-path reflection (malformed multipart boundary, 200 KB payload) → no warnings/stack traces echoed, no 413 (also means: no body-size guard).
- Static `.html` pages: query params and POST bodies ignored (Apache serves them verbatim).
- Source/backup disclosure (`*.bak/.old/.swp/~/.phps/…`) → `.phps` and friends are generic 403s for ANY name (extension deny rule), others 404 — no source leak.
- Directory listing → 403 everywhere.

## WAF / defense behavior
- Alteon: no evidence of XSS-payload blocking (all probes 200).
- Apache: 400 on invalid Host characters (kills Host-based XSS/header injection).
- App-level: consistent entity encoding of `< > " ' &` on every reflecting field —
  this, not any WAF, is what currently defeats the reported XSS.

## Test log (2026-10-24)
- BFS crawl: 16 HTML pages + 1 PHP (complete link graph, incl. orphan `ipchange.html` found via Google).
- ffuf: 210-word custom list × {dirs, .php, .html} on bgp.*; same .php pass on ipadmin.* → only known endpoints. `common.txt` (4751) dirs+php on bgp.* → new: `.gitignore`, `/themes`, `server-status`, `.config.php`.
- Reflection matrix: all 24 form fields, special-char marker `ZMQ9<>'"&ZMQ9`; full bypass set (see `evidence/xss-retest-2026-10-24.md`).
- **Browser verification (Playwright + local Chromium 1234 — use `executable_path`, installed rev ≠ playwright rev):** 3 inert payloads via file:// auto-submit form → zero execution, DOM shows encoded `value="…"`.
- Config-surface discovery chain + 1,800-name fuzz inside `/envvars/` (see `evidence/config-surface-2026-10-24.md`).
- `/themes/` content discovery: 37 theme names + `common.txt` × {name, .php} → only
  generic `.ht*` 403s; nothing reachable inside yet (css/html/json passes skipped — dir
  has shown no content under 9,500 guesses).
- Archive/backup sweep at root (`backup.zip … themes.zip`, 21 names incl. `.sql/.tar.gz`)
  → all 404.
- HTTP (port 80) → every path 301s to HTTPS; no cleartext fallback.
- Completeness sweeps (2026-10-24 close): `common.txt` × `.html` on bgp.* → only 2
  previously-unlinked static pages (`menu.html`, `notfound.html` — both inert, links all
  known); `common.txt` × `.php` on ipadmin.* → only `.config.php` (parity). **Endpoint
  inventory is closed: 18 HTML (2 orphan) + 1 PHP (+2 silent config PHP) per host.**
- Sensitive files: `.git/HEAD`403 (generic child-deny), `.env`404, `composer/package.json`404, `.well-known/security.txt`404, `robots.txt`/`sitemap.xml`404.
- Wayback CDX: historical endpoints all dead; archive.org was briefly offline then recovered.
- Reachability: ports 80/443 only.

## Open leads (ranked)
1. `/themes/` contents — only css/html/json passes remain (name+php exhausted at ~9,500
   guesses, nothing reachable); low expectation.
2. Authenticated surface (the admin layer the original report references) — needs an
   operator-supplied session cookie; nothing unauthenticated hints at it.
3. Ask the original reporter for raw request/response bytes (date + full body) of the
   unquoted `asn` rendering — diff against current behavior to confirm patch vs false positive.
4. `.config.php` / `envvars/global.php` — locate source via any future backup/debug slip;
   re-check for `*.phps` real rule changes (currently generic deny) and for error-triggering
   inputs (bad types, missing includes) that could turn `display_errors` on.
5. `server-status` — restricted (403); revisit only if deny rule changes.
6. Wayback historical content diff of `/bgp_procedures_new_form.php` GET snapshots
   (template evolution) — GET never reflected input, so low value.
7. Other *.frontier.com hosts (376 CT names in `references/ct-names.txt`) — OUT OF SCOPE
   unless operator extends.
