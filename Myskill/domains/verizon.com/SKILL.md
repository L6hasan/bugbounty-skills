---
name: verizon.com
description: Recon notes, scope, attack surface, tested history and open leads for Verizon (verizon.com and the 25+ sibling registrable domains in the Inspectiv program) — use when hunting on this target, resuming the engagement, or when a conversation mentions Verizon, verizonwireless.com, tracfone.com, straighttalk.com, visible.com, vzconnect.com, telogis.com, fleetmatics.com, or the Inspectiv Verizon program.
---

# Verizon (Inspectiv)

**Program / authorization:** Verizon, private program on Inspectiv. Program brief updated 2026-10-20.
**Last engagement:** 2026-10-27 (initial intake + passive recon)

## Scope

**Registrable domains with a wildcard in scope (all Tier 4, blackbox/self-signup only):**
`*.verizon.com`, `*.verizonwireless.com`, `*.verizonbusiness.com`, `*.verizonenterprise.com`,
`*.verizon.net`, `*.vzw.com`, `*.vzbi.com`, `*.vzwcorp.com`, `*.onetalk.com`, `*.fios.tv`,
`*.tracfone.com`, `*.straighttalk.com`, `*.totalwireless.com`, `*.safelinkwireless.com`,
`*.pagepluscellular.com`, `*.simplemobile.com`, `*.net10wireless.com`, `*.myfamilymobile.com`,
`*.visible.com`, `*.vzconnect.com`, `*.telogis.com`, `*.fleetmatics.com`, `*.vespm.com`,
`*.mblogin.verizonwireless.com`, `*.odi-device.verizonwireless.com`, plus `gosmartmobile.com`,
`1010987.com`, `empirecitysubway.com`, `omniroot.com` hosts.

**Tier 4 named hosts (highest-value, tractable):** www.verizon.com, www22.verizon.com,
enterpriseportal.verizon.com, tv.verizon.com, activate.verizon.com, api.verizon.com,
ondevice.verizon.com, experience.verizon.com, partnerportal.verizon.com, legalintake.verizon.com,
mycareer.verizon.com, teamindia.verizon.com, thingspace.verizon.com, core.thingspace.verizon.com,
thingspaceportal.verizon.com, webexcallingus.verizon.com/control/main,
autochatva.verizon.com/cv/cbav/#/virtualassistant, noaccess.verizon.com/bwg/,
cms-cmsgax.verizon.com/gax/, cms-cmspulse.verizon.com/pulse/,
login.lighting.verizon.com, verizonmdm.vzw.com, lifeonverizon.verizonwireless.com,
cim.verizonwireless.com, roms.verizonwireless.com, indirectorders.verizonwireless.com,
wbbc.verizonbusiness.com, e-meetings.verizonbusiness.com, mss-sso.verizonbusiness.com/sso/login,
conferencing.verizonbusiness.com, performancereporting.verizonbusiness.com,
plnr.verizonbusiness.com, dnr.emea.verizonbusiness.com,
cmsvoicecallback.verizonenterprise.com, gridwideportal.verizonenterprise.com,
login.platform.telogis.com, wanaka.telogis.com, rhino.it-fleetmatics.com,
work2.fleetmatics.com/Admin/Default.aspx, login.us.vzconnect.com, reg.mci.com/service,
cloud.iboss.com, crl.a.mcs.omniroot.com, cadmin.a.mcs.omniroot.com/user/dashboard.
Mobile apps also in scope (MyVerizon, Care Smart, plusHome, HUM, Protect, etc.).

**Out of scope / exclusions — PROHIBITED (do not send a packet):**
- sitemail.webhosting.verizon.net, sitecontrol.webhosting.verizon.net,
  order.domains.verizon.net, reports.webhosting.verizon.net
- myverizonenterprise.verizon.com (pulled 2026-09-25), vzretailsupport.com/*
- wits3portal.verizon.com, wits3app.verizon.com, sao.verizon.com, saocentral.verizon.com
- eis.verizongov.com, federaleis.verizongov.com, federalextauth.verizongov.com,
  verizongov.com (whole wildcard removed), NetworxEnterprise.verizon.com,
  networxuniversal.verizon.com
- mss-60.verizonbusiness.com, mss-fed-sso.verizonbusiness.com, mss-54.verizonbusiness.com
- Apogee-mt.ops.cybertrust.com
- www.movildata.com

**Out of scope — vulnerability classes / specific known bugs:**
- RXSS on `*.verizon.com/SpeedTest/learnSpeedTest.aspx?bypassSpeed=`
- Broken Access Control on `www.verizon.com/externalportal/api/*`
- HTMLi + RXSS via template-engine params on `extras.tracfone.com/en/*`,
  `extras.totalwireless.com/en/*`, `extras.pagespluscellular.com/en/*` (all language variants)
- XSS/HTMLi on the Upland PostUp/StormPost email platform (click1., email., anything serving
  `/Subscribe.do`, all assets) — this is the big one to avoid, MX/email click trackers are everywhere
- RXSS from unsanitised `ga` function at mysite.tracfone.com; RXSS at g.tracfone.com
- SQLi on webview.email2.tracfone.com; Support ticket exposure at enterpriseportal.verizon.com
- Domain mys.tracfone.com
- RXSS on www22.verizon.com/wholesale/*
- Generic no-pay: clickjacking/tapjacking, CORS on non-sensitive endpoints, CSRF with no impact
  (or on anonymous forms/logout), CSV injection, rate-limit/brute-force, self-XSS,
  banner/version/stack-trace disclosure, missing security headers, OPTIONS/TRACE,
  open S3 listing of public files, SPF/DKIM/DMARC, SSL config, token expiry, user enum,
  session issues without demonstrated impact, weak captcha, WP XMLRPC, blind SSRF w/o impact,
  host-header injection w/o impact, request smuggling w/o impact, broken-link hijacking,
  IP loggers, autocomplete/password-manager, MITM/physical, social engineering,
  CVEs <90 days old or without PoC, "violation of secure design principles".
- **Subdomain takeover IS in scope but needs a live PoC.**

**Rate limits & testing windows:** no stated window. Code of conduct caps traffic — do not exceed
10 req/sec and do not sustain for >10 seconds. No mass record creation/deletion. Do not use
leaked credentials. Do not contact support for accounts. Stop immediately on cross-account access.

## Rules of Engagement (mandatory on EVERY request)
```
X-Inspectiv-Tester: {researcher-username}
```
Missing this header can void the report. Blackbox only. Self-registration/public signup only.

**Payout:** Tier 4 — Critical $2500 / High $1000 / Medium $500 / Low $0.
Severity = base class, adjusted for impact + required privilege.
Systematic duplicates: same root cause on two endpoints = one payout.

## Stack (verified — pending first recon pass)
- WAF: unknown — expect Akamai/Imperva on www.verizon.com; record per host.
- Server / framework / language: unknown (many .aspx endpoints ⇒ ASP.NET/IIS on legacy hosts;
  `control/main` on webexcallingus looks like a Java/Spring or webMethods path).
- Auth model: unknown. Expect SSO (mss-sso.verizonbusiness.com, login.us.vzconnect.com,
  login.platform.telogis.com) fronting most portals.
- Notable middleware: `cms-*` hosts look like a shared CMS platform; `*.thingspace.verizon.com`
  is the IoT API platform (separate, well-tested by others).

## Attack surface
### Subdomains & hosts
Populated by the passive/active recon pass. See `recon/` for raw output.

### Endpoints
| Endpoint | Params | Auth | Signal / sink | Tested? |
|---|---|---|---|---|

### API / GraphQL
unknown

## Findings history
| Date | Endpoint | Class | Status | Report |
|---|---|---|---|---|

## Ruled out (and why)
- Nothing tested yet. Known-scope landmines recorded above under exclusions.

## WAF / defense behavior
unknown — record per host.

## Next session (ranked)
1. Run the writeup's recon chain (subfinder+findomain+assetfinder → httpx → katana/gau/urlfinder
   → uro → kxss) restricted to Tier 4 named hosts + the small marketing-brand domains.
2. Hunt reflected params with `kxss`, then test the hidden-input `content-visibility` payload
   on any hidden-input reflection.
3. Look for campaign-style predictable URL patterns (`PREFIX###_DA###_ENS`-like) on
   straighttalk/tracfone/visible/totalwireless marketing paths, then ffuf clusterbomb.
4. Open-redirect sweep on SSO/marketing hosts: `?redirect=`, `?return=`, `?url=`,
   `?next=`, `?callback=` with `target.evil.com` (suffix-confusion), and check `-preprod`/
   `-staging` siblings of every hit.
