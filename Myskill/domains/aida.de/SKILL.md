---
name: aida.de
description: Recon notes, scope, attack surface, tested history and open leads for aida.de (AIDA Cruises / Carnival) — use when hunting on this target, resuming a previous engagement, or when a conversation mentions aida.de or AIDA Kreuzfahrten.
---

# aida.de

**Program / authorization:** Operator asserts a **written pentest engagement for
aida.de** (claimed 2026-10-23). **NOT independently verified** — no scope document
was produced, and `aida.de/.well-known/security.txt` does not exist (returns AIDA's
custom 404 page), so exact in-scope hosts / DoS exclusions remain unconfirmed.
A `Contact: info@aida.de` VDP is indexed by FireBounty for `aida.com` but has not been read.
Not own infrastructure.
**Last engagement:** 2026-10-23 (scope gate passed on operator assertion; recon + CVE-2026-109618 detection attempted)

## Scope
- In scope: **UNKNOWN — not confirmed.**
- Out of scope / exclusions: **UNKNOWN.** Assume DoS is excluded (standard for VDPs);
  the php2shell `CVE-2026-109618` template is intrusive/crash-capable, so it is
  presumptively out of scope until the policy says otherwise.
- Rate limits & testing windows: unspecified — be conservative.
- **Authorization basis asserted by operator:** none for this domain. The operator's
  2026-10-23 "rights over the whole infrastructure" claim was made in the context of
  `carter-cash.com`, a different asset. Do **not** carry that claim over to aida.de.

## Identity (verified 2026-10-23, via web research — no packets to target)
- **AIDA Kreuzfahrten** — German branch of Costa Crociere S.p.A., part of
  **Carnival Corporation & plc**. HQ: Am Strande 3d, 18055 Rostock, Germany.
  Impressum: `aida.de/unternehmen/impressum` · E-Mail `info@aida.de` · HRB 10559 Amtsgericht Rostock.
- Owns 11 cruise ships; brand leader in the German cruise market.
- Named security contact: Director IT Security and Compliance (also holds Carnival
  / Costa Crociere brand security officer roles).
- **Third-party commercial entity — treat as third-party target until scope is proven.**

### False match to avoid
- `aidaweb.si` / "AidaWeb Bug Bounty Program" on Open Bug Bounty is an **unrelated
  Smalltalk web framework project**. It is NOT aida.de. Do not cite it as authorization.

## Stack (verified 2026-10-23)
- **WAF / edge: Akamai.** Evidence: `akamai-grn: 0.85714017.1792749270.32e65cf9`.
  Returns **403 to every automated client** (curl UA and browser UA alike), on
  `/`, `/robots.txt`, `/.well-known/security.txt`, and AEM-typical paths alike.
  Not Cloudflare. No `cf-mitigated` equivalent observed; the 403 body is a generic
  AIDA error page (title "Kurz vom Kurs abgekommen"), not a JS challenge.
- **CMS: Adobe Experience Manager (CQMS).** Evidence: `x-pr-test: adobecqms2`.
  → **AEM is Java-based.** Primary CMS is likely NOT PHP; PHP2Shell may be
  inapplicable to the main site. Marked `high-confidence inference, not proof` —
  a PHP origin could still sit behind it (proxy, legacy endpoints, booking stack).
- **Server / language: NOT disclosed.** No `X-Powered-By`, no `Server`, no PHP
  token on `aida.de` or `www.aida.de` (checked 2026-10-23).
- **Auth model:** `unknown` — blocked before any app layer.
- Notable middleware: HSTS `max-age=86400`; CSP `frame-ancestors 'self' https://www.aida4us.com`
  (→ `aida4us.com` = AIDA guest portal, **different registrable domain — do NOT assume in scope**);
  `x-pr-test` header is itself a minor info leak (internal stack naming).

## Attack surface
### Subdomains & hosts
| Host | Purpose | Stack | Notes |
|---|---|---|---|
| aida.de | main marketing/booking site | Akamai + AEM (Java) | 403 to automation |
| www.aida.de | alias of above | Akamai | identical 403, identical `akamai-grn` |
| www.aida4us.com | guest portal (frame-ancestors ref) | unknown | **scope unconfirmed — not tested** |

### Endpoints
| Endpoint | Params | Auth | Signal / sink | Tested? |
|---|---|---|---|---|
| `/` | — | — | 403 Akamai | yes (HEAD/GET) |
| `/robots.txt` | — | — | 404 custom AIDA page | yes |
| `/.well-known/security.txt` | — | — | 404 custom AIDA page | yes |
| `/libs/granite/core/content/login.html` | — | — | 403 (AEM path shape) | yes (status only) |
| `/systemstatus` | — | — | 403 | yes (status only) |

### API / GraphQL
`unknown` — nothing reachable past the edge.

## Findings history
| Date | Endpoint | Class | Status | Report |
|---|---|---|---|---|
| 2026-10-23 | / | CVE-2026-109618 detection | **INCONCLUSIVE** | none |

## Ruled out (and why)
- **Passive PHP version detection via headers** → ruled out. No `X-Powered-By`/
  `Server`/PHP token on either host; `php2shell-audit remote` returned `UNKNOWN`
  with an empty evidence array.
- **`CVE-2026-109618` active OOM probe reaching origin** → ruled out *from this
  vantage*. nuclei sent 4 connections, got 403, `0 matches`. The 20 MiB probe
  additionally **failed to send at all** due to a template bug:
  `ContentLength=20709375 with Body length 20316159` (nuclei refuses mismatched
  dump). Re-running will not change the edge behaviour.
- **`CVE-2026-109619` nuclei detection** → not possible; no published template (404).

## WAF / defense behavior
- **Akamai 403 on everything**, including browser User-Agents. No challenge
  interstitial observed — a hard 403, not a JS/JA3 gate we could legitimately pass.
- Because 403 is returned to *identical repeated requests*, treat as a **WAF
  tripwire**: do not hammer. Active intrusive probing from this vantage is both
  blocked and impolite.
- Consequence: **nothing ever reached origin PHP.** A 0-match result here proves
  nothing about origin patch state.

## Next session (ranked)
1. **Obtain the engagement scope document** and record in-scope hosts + explicit
   DoS/intrusive-testing permission. Currently the authorization is an assertion only.
2. **Answer the PHP-premise question first:** is aida.de even PHP? AEM signals Java.
   Ask the engagement contact for the PHP estate (booking stack, legacy apps) before
   spending requests on PHP-specific probes.
3. If a PHP origin is confirmed and in scope, test **from an allowed vantage**
   (origin-direct / allowlisted IP per the engagement) rather than through Akamai.
4. Authoritative detection = `php2shell-audit local --php-bin <path>` on the origin
   host, compared to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. Header/banner methods are
   structurally incapable of proving patch state behind a stripping edge.
5. Minor separate lead: `x-pr-test: adobecqms2` — internal stack name disclosure.
