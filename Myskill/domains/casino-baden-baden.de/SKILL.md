---
name: casino-baden-baden.de
description: Recon notes, scope, attack surface, tested history and open leads for shop-staging.casino-baden-baden.de and casino-baden-baden.de — use when hunting on this target, resuming the engagement, or when a conversation mentions Casino Baden-Baden, casinop-baden-baden or shop-staging.
---

# casino-baden-baden.de

**Program / authorization:** Published bug bounty. Operator pasted the **qualifying /
non-qualifying vulnerability lists** on 2026-10-24 as proof of permission.
⚠️ **The pasted text contains NO scope host list and NO program name** — only the
qualifying/non-qualifying tables. Host in-scope status rests on the operator's claim.
**Confirm the scope list before deep testing.**

**Last engagement:** 2026-10-24 (first session)

## Scope
- **Original target given: `shop-staging.casinop-baden-baden.de` → NXDOMAIN (does not exist).**
  The apex `casinop-baden-baden.de` is also NXDOMAIN — the operator's hostname had an extra `p`.
- **Corrected target (operator-confirmed): `https://shop-staging.casino-baden-baden.de`**
  → `178.16.58.223`. Sibling `shop.casino-baden-baden.de` resolves to the **same IP**
  (likely same box, different vhost). `staging.casino-baden-baden.de` has no A record.
- Related live hosts found passively (NOT confirmed in scope, **do not test**):
  `casino-baden-baden.de` / `www.` → 92.205.22.180, `casinobadenbaden.de` → 88.198.116.121,
  `casino-baden-baden.com` → Cloudflare.

### Program exclusions that shape this engagement (from the pasted policy)
- **Denial of Service (DoS) → NON-QUALIFYING.** ⇒ `CVE-2026-109618.yaml`
  ("Active Crash Detection", 1/8/20 MiB OOM payloads) is **out of scope — never run it here.**
- **"Recently disclosed CVEs (less than 30 days since patch release)" → NON-QUALIFYING.**
  php2shell is dated **2026-10-21** (`php.net/archive/2026.php`, ref `2026-10-21-5`).
  From 2026-10-24 that is **3 days old → php2shell reports are non-qualifying until ~2026-11-20.**
- **"CVEs without exploitable vulnerabilities and PoC" → NON-QUALIFYING.**
- **"Disclosure of information without exploitable vuln and PoC (…software versions, IP
  disclosure, directory listings…)" → NON-QUALIFYING.** ⇒ pure version/tech fingerprint = intel only.
- **"Lack or bypass of rate-limiting, brute-forcing or captcha issues" → NON-QUALIFYING.**
  ⇒ **Do not brute-force the HTTP Basic Auth** — it would be wasted and against the rules.
- **"User enumeration" → NON-QUALIFYING.**
- Also excluded: malicious file upload (EICAR/.EXE), SQLi-as-CVE-without-PoC, low-severity CSRF,
  GraphQL introspection alone, subdomain takeover without full PoC.
- **Qualifying (what to aim at):** SQLi, XSS, RCE, IDOR, priv-esc, auth bypass, business logic,
  LFI/RFI/XXE/SSRF/XSPA, CORS with real impact, CSRF with real impact, open redirect, exposed
  secrets affecting an in-scope asset.

## Stack (verified 2026-10-24)
- **WAF / CDN:** none detected. Direct host, no CDN headers, no bot-managed cookies.
- **Server:** `Apache` — **version NOT disclosed** (`server: Apache` only).
- **TLS:** Let's Encrypt `YR2`, `notBefore 2026-09-06`, `notAfter 2026-12-05`,
  SAN = `shop-staging.casino-baden-baden.de` only (per-host cert, not the wildcard).
- **Auth model:** **HTTP Basic Auth on essentially everything.**
  `WWW-Authenticate: Basic realm="Passwortgeschützter Bereich"` (German).
  `GET /` → `401`, 421-byte Apache default body, `charset=iso-8859-1`.
- **PHP: NOT CONFIRMED.** The operator stated "they are using php language" — **unverified.**
  - No `X-Powered-By` on any response.
  - `nuclei …/php-detect.yaml` → **no match**.
  - `nuclei …/adem-CVE-2026-109619.yaml` (version check) → **0 matches / 1 request**.
  - The 401/403 bodies are Apache's own default pages, served **before** any application
    code could run, so they cannot confirm or deny PHP.
  - Mark as **guess** until credentials or a backend confirmation is available.

## Attack surface
### Subdomains & hosts
| Host | Purpose | Stack | Notes |
|---|---|---|---|
| `shop-staging.casino-baden-baden.de` | staging shop | Apache + Basic auth | **in scope (operator-confirmed)** |
| `shop.casino-baden-baden.de` | shop (prod?) | Apache | same IP 178.16.58.223 — scope UNCONFIRMED |
| `casino-baden-baden.de` / `www.` | main site | 92.205.22.180 | scope UNCONFIRMED |
| `casinobadenbaden.de` | alt domain | 88.198.116.121 | scope UNCONFIRMED |

CT logs only contain `casino-baden-baden.de` + `*.casino-baden-baden.de`; the staging host
has its own separate LE cert and does not appear in CT.

### Endpoints
| Endpoint | Params | Auth | Signal / sink | Tested? |
|---|---|---|---|---|
| `GET /` | — | **Basic 401** | Apache default 401 | ✅ 401 |
| `GET /index.html`, `/index.php`, `/phpinfo.php`, `/favicon.ico`, `/robots.txt`, `/admin`, `/checkout`, `/shop`, `/api/` | — | **Basic 401** | identical 421-byte 401 | ✅ all 401 |
| `GET /.well-known/`, `/.well-known/security.txt` | — | **403 (not 401)** | different layer — auth boundary NOT uniform | ✅ 403 / 956B |
| `GET /server-status` | — | **403** | mod_status present but denied (or generic deny) | ✅ 403 |

**Every unauthenticated path is a dead end at Apache.** No application code, no PHP,
no query parameters, no dynamic input were reachable this session.

## Findings history
| Date | Endpoint | Class | Status | Report |
|---|---|---|---|---|
| 2026-10-24 | — | — | **no findings** — entire surface behind Basic auth; PHP unconfirmed | — |

## Ruled out (and why)
- **php2shell CVE-2026-109619 (version-based)** → `nuclei adem-CVE-2026-109619.yaml`:
  **0 matches / 1 request.** No `X-Powered-By: PHP` header exists. Ruled out *as a detectable
  condition from this vantage*, not as a statement about the backend.
- **PHP presence** → `php-detect.yaml` no match; `apache/*` detect no match. Unconfirmed.
- **Apache version disclosure** → `server: Apache` with no version token. Not leaky.
- **Stack traces / path disclosure** → only Apache stock 401 (421B) and 403 (956B) bodies.
- **`shop-staging.casinop-baden-baden.de`** → NXDOMAIN; domain does not exist. Closed (typo).
- **Refusing to run:** `CVE-2026-109618.yaml` crash probe (DoS = excluded by policy);
  `php2shell-quarantine/php2shell-session-fixation.yaml` (operator's own quarantine note says it
  matches **patched 8.4.27 too** — proven false positive, "Do NOT re-enable for production
  scanning"); `adem-php2shell-session-injection-lfi.yaml` and `adem-php2shell-handler-mismatch.yaml`
  (hardcoded **lab** defaults `/vuln.php?page=`, `/tmp/sessions/sess_`, `/app/upload.php`,
  `/api/endpoint.php` — meaningless against a real host until variables are supplied).

## WAF / defense behavior
- No WAF/CDN observed. The **only** gate is Apache HTTP Basic Auth.
- `401` = auth-protected (Apache stock page). `403` = directory-level deny, applies to
  `/.well-known/*` and `/server-status` **before/independent of** the auth realm — i.e. the
  `Require`/`<Location>` config is not uniform. Worth re-mapping once authenticated.
- No rate-limiting observed on 401 responses (but brute-forcing is excluded by policy anyway).

## Test mailbox / credentials
- **No credentials available.** Staging Basic auth blocks everything.
- Check `~/.config/bughunter/test-mailboxes.env` only if the flow needs email; **do not**
  brute-force the realm (policy-excluded).

## Next session (ranked)
1. **Get staging credentials.** Everything is blocked without them — this is the single
   blocker. Ask the operator/client for the Basic-auth user/pass, or a VPN/allowlist.
   Once inside, re-run the full safe template set and start real web testing.
2. **Confirm whether PHP is even in the stack** (ask the client's dev team, or observe it
   after auth). If it isn't, the whole php2shell line of enquiry is moot for this asset.
3. **Obtain the program's actual scope list.** Only qualifying/non-qualifying tables were
   provided — confirm `shop-staging` (and decide on `shop.` / apex) before deep testing.
4. **Re-map the auth boundary** once authenticated — `/.well-known/*` and `/server-status`
   already behave differently from `/`, so the Apache config has uneven rules.
5. **php2shell re-check after 2026-11-20** (30 days post-patch, when it becomes
   non-excluded) — but ONLY after: (a) repairing the quarantined template so it stays silent
   on 8.2.35/8.3.36/8.4.27/8.5.12, (b) wiring real `lfi_path`/`session_path`/`write_path`/
   `read_path` instead of lab defaults, (c) confirming PHP presence, (d) never using the
   crash probe (DoS-excluded).
6. **Standard qualifying tests behind auth:** SQLi, XSS, IDOR, auth bypass, business logic,
   LFI/XXE/SSRF, CORS/CSRF with real impact, open redirect, exposed secrets.
