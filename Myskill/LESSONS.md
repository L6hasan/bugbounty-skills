# LESSONS — report- and conversation-derived learning log

Every report the user shares **and every substantive conversation about a technique** gets
mined here, then written back into the technique skills. Append-only: never rewrite or
delete past entries. New entries go at the bottom.

**Format:**

```
## YYYY-MM-DD — <source: own-report / triage-response / disclosed / third-party / conversation>
- Lesson: <the non-obvious detail — what actually made it work or fail>
- Class: <bug class> → skill: <skill-directory>
- Change: <new variant / gotcha under False positives / Detect / workflow change> @ <file>
- Repeat signal: <why this matters — is it a pattern?>
```

**Mining rules** (see `bug-hunter` skill, section 4 — 4a reports, 4b conversations):

1. The *non-obvious* detail is the lesson. "SQLi is bad" teaches nothing; "the WAF only
   parsed `Content-Type` once, so a second `charset` beat it" teaches everything.
2. A rejection/closure is a lesson too — false-positive patterns and missing impact proof
   are the highest-value entries in this file.
3. Write the change into the matching technique skill in the same pass; a lesson logged but
   not written back is not learned.
4. New skill directories only when a lesson belongs to none of the nine categories —
   scaffolds must follow `SKILL_SPEC.md`.
5. Conversations count. At the close of any substantive exchange about a technique, map the
   topic to its category skill (DOM XSS → `xss-testing` V-03, etc.), pull the core — the
   gotcha, the FP pattern, the tooling trick — and write it into that skill's variant file
   in the same pass as this entry. No non-obvious detail? Write nothing.

---

## 2026-10-21 — system initialized
- Lesson: Built the initial suite — 9 technique skills (135+ variants) from the user's
  taxonomy, plus this learning loop, the `bug-hunter` orchestrator, `/hunt` command, and
  domain-profile skills.
- Class: n/a → skill: all
- Change: initial creation of `csrf-testing`, `xss-testing`, `sqli-testing`,
  `bac-idor-testing`, `rce-ssrf-testing`, `path-traversal-testing`,
  `info-disclosure-testing`, `business-logic-testing`, `sandbox-escape-testing`
- Repeat signal: baseline entry — future entries show what compounding.

## 2026-10-21 — own-engagement (vinted.com session 1)
- Lesson: three reusable tricks from the first live run. (1) `robots.txt` is a first-class scope
  source — it exposed `/apipie/` (Rails backend hint), disallowed areas (`/checkout`, `/member/`,
  `/inbox`), a soft-404-differentiable path set, **and** site-declared agent restrictions that
  constrain testing behavior. (2) Next.js App Router reflects a query param up to three times —
  `href` attribute, inline RSC JSON, and `next-router-state-tree` — plus `<link rel=canonical>`
  and every `hreflang` mirror; all were percent-encoded, so "it appears 73 times" ≠ "it reflects
  unencoded": verify encoding state per occurrence, not occurrence count. (3) Differential size
  comparisons on SSR pages are noise by default — identical requests varied by ~1 KB — so boolean
  SQLi conclusions need repeated matched pairs, never one baseline.
- Class: XSS / SQLi / scoping → skill: `xss-testing` (V-02 detect), `sqli-testing` (V-03 confirm),
  `bug-hunter` (scope gate)
- Change: gotcha lines added to `xss-testing/references/variants-1.md` (V-02 False positives) and
  `sqli-testing/references/variants-1.md` (V-03 False positives); scope-source step folded into
  `bug-hunter/SKILL.md` Phase 2.
- Repeat signal: 1st entry of this type — expect these three to recur on every SSR/Next target.

## 2026-10-21 — own-engagement (vinted.com session 2, authenticated) + incident
- Source: own-engagement, authenticated testing with operator-provided test accounts.
- Lesson A (incident): a **method-discovery matrix including `DELETE` sent to a live object path**
  (`/api/v2/users/<own-id>`) executed the app's real self-delete feature — `200 {"code":0,"message":"Ok"}` —
  destroying test account #1 (`testerokk`, id 3196844241): API went 401, `/member/<id>` went 404,
  session redirected 307. Method matrices must only ever touch paths where every verb outcome is
  harmless; probe authz/CSRF boundaries against a guaranteed-nonexistent ID instead
  (unauth → `401 invalid_authentication_token`; authed-without-CSRF → `403 access_denied` — both
  proven on this target with zero collateral). Recovery expectation: soft-delete (schema has
  `is_deleted`) → operator logs in within the restore window.
- Lesson B (finding, F-02): **globally static CSRF token.** `75f6c9fa-dc8e-4e52-a000-e09dd4084b3e`
  identical across two accounts, anonymous vs authenticated, and two countries/IPs — while
  `Origin`/`Referer` are **not validated** (evil-Origin request → 200). Exploitability bounded:
  token accepted *only* via `X-Csrf-Token` header (form field / query param / `X-Requested-With`
  → 403), so cross-origin use needs a preflight that fails, plus `SameSite=Lax` auth cookies.
  Report as hardening, escalate only with a CORS/XSS/GET-state-change chain.
- Lesson C (ruled out): **SVG upload XSS dead by design** — server validates *content*, not
  headers (`SVG bytes as .png` → 400, real PNG → 200) and transcodes everything to `image/jpeg`
  served with `X-Content-Type-Options: nosniff` + `inline`. Filename/extension tricks cannot
  survive a transcode; stop re-testing this class on rasterizing uploaders.
- Class: CSRF / file-upload XSS / access-control → skills: `csrf-testing` (V-08 gotcha added),
  `bug-hunter` (Phase 4 destructive-verb rule added), `xss-testing` (V-04 upload transcode note)
- Change: `csrf-testing/references/variants-1.md` V-08 False positives; `bug-hunter/SKILL.md`
  Phase 4; this entry.
- Repeat signal: static-token + unchecked-Origin appears again on any Rails/Next stack — and the
  destructive-probe rule now fires on every future method matrix.

## 2026-10-21 — suite restructure: rce-ssrf-testing split in two
- Source: own-maintenance, user directive ("RCE and SSRF as 2 different skills").
- Lesson: the combined 15-variant skill had two disjoint sink classes (code-execution vs
  server-side fetch) sharing one selection table, which blurred routing — an observed
  URL-fetch signal and an observed exec signal both landed on the same skill page. Split at
  the class boundary: `rce-testing` (9 variants: V-01 cmd injection, V-02 code eval, V-03
  deser, V-04 upload→shell, V-05 SSTI, V-06 memcorrupt, V-07 arg injection, V-08 config
  loading, V-09 env-var RCE) and `ssrf-testing` (6 variants: V-01 basic scanning, V-02 blind
  pipelines, V-03 cloud metadata, V-04 rebinding, V-05 protocol smuggling, V-06 render SSRF).
  Payloads split too: cmd/SSTI/upload ladders → rce, probing ladder + metadata recipes → ssrf.
  Cross-skill refs in all 9 siblings + bug-hunter routing table updated; guardrails preserved
  on both sides (metadata identity-only rule → ssrf; no-shells-first + no-persistence → rce).
- Class: suite maintenance → skill: `bug-hunter` (routing), `SKILL_SPEC.md` (suite table),
  every sibling's chain-it-with sections
- Change: new `rce-testing/` + `ssrf-testing/` dirs per SKILL_SPEC; old `rce-ssrf-testing/`
  retired pending deletion; bug-hunter table row split into command-ish → rce vs URL-fetch → ssrf.
- Repeat signal: first restructure — if another class splits later (e.g. pure LFI vs RFI),
  same procedure: split at sink boundary, renumber within each skill, fix all cross-refs in
  the same pass, log here.

## 2026-10-21 — SPA DOM-XSS hunting on a hashed-bundle PhantomBuster app
- Source: user engagement — "check https://v2staging.phantombuster.io/ and test any more
  DOM xss"; found one report on `/redirect`, hunted for more.
- Method (V-03 static→dynamic funnel, worked well): (1) reconstruct the chunk/route graph
  from the lazy-import map in the main bundle + the route constants table; (2) download every
  chunk (3.1MB / 76 chunks); (3) intersect source chunks (location.search/hash, document.URL,
  window.name, postMessage, URLSearchParams) with sink chunks (innerHTML/outerHTML/
  insertAdjacentHTML/document.write/eval/location.replace/assign/href=/setAttribute);
  (4) hand-trace each intersection's source→sink dataflow; (5) confirm exploitability of the
  ambiguous ones in a real browser; (6) dynamic sink-hook sweep over reachable routes as a
  backstop. Static analysis correctly predicted every dynamic result.
- Findings: confirmed the reported DOM XSS (source `location.search` → sink
  `location.replace(e)`, no scheme/host check, `javascript:` accepted). Ruled out everything
  else with concrete reasons (see below). Side finding (auth class, not XSS): a preview-token
  URL param is read and pushed into a session setter — flag for an auth-capable reviewer, do
  not force into an XSS bucket.
- Two false-positive sinks that LOOKED exploitable and were NOT — memorize the reasons:
  (a) react-router `Link to={urlParam}` / `history.push(urlParam)`: v5 `createHref`
  normalizes a raw `javascript:`/`https://evil` value by prepending `/`, turning it into a
  same-origin path (inert). Only a protocol-relative `//host` survives, and only as an
  open-redirect gated on a modifier click (ctrl+click / open-in-new-tab). Empirically tested
  with a local react-router-dom@5 harness. Apparent `window.location.replace(urlParam)` may
  actually be a route-builder that hardcodes a leading `/` — trace before calling it.
  (b) postMessage → innerHTML: if the handler gates on `e.origin === <fixed const>`, it is
  not attacker-reachable unless that exact host is separately compromised — chain, not a
  standalone bug.
- Tooling that mattered: Playwright (see gotchas) + `--break-system-packages` for pip; a
  local react-router harness to settle router-normalization questions offline.
- Hook gotcha (cost me two wasted runs): a greedy dynamic-sink-hook init script that
  overrode the `Function` constructor crashed Vite module init → app never booted → 0 hits
  looked like "clean." Add a positive control on a KNOWN-working sink on every sweep; if the
  control doesn't fire, fix the instrumentation before believing any zeros.
- Class: technique → skill: `xss-testing` (V-03 dynamic funnel + the two FP patterns);
  `bug-hunter` (chunk/route enumeration)

## 2026-10-21 — intake rule widened: conversations now mined like reports
- Source: own-maintenance, user directive ("i want my every single conversation setup as skill —
  if i talk about DOM XSS, add the core of the conversation onto the DOM XSS category").
- Lesson: the write-back loop was previously gated on *pasted reports* (bug-hunter §4), so
  technique talk that never became a report left no trace — the PhantomBuster DOM-XSS session
  only survived because it happened to produce findings. The rule now triggers on any substantive
  technique exchange: map topic → category skill (§3 routing table) → pull the non-obvious core →
  fold into that skill's `references/variants-*.md` under the right variant → log here with source
  `conversation`. Noise guard kept: exchanges with no non-obvious detail produce no entry, so the
  log doesn't drown.
- Class: suite maintenance → skill: `bug-hunter` (§4 split into 4a reports / 4b conversations),
  `LESSONS.md` (header, format, mining rule 5)
- Change: `bug-hunter/SKILL.md` §4 + frontmatter description trigger; this entry.
- Repeat signal: second user-directed restructure — same procedure as the rce/ssrf split: apply
  directive, fix cross-refs in the same pass, log here.

## 2026-10-21 — unauthenticated info-disclosure sweep (PhantomBuster staging, continuation)
- Source: own-engagement (v2staging.phantombuster.io + api-staging.phantombuster.io), user directive
  ("go for unauthenticated information disclosure testing if you get any server side information
  or sensitive or potential let me know"), skill: info-disclosure-testing.
- Findings reported to user:
  (a) POTENTIAL — hardcoded Customer.io credentials (site id + API key + testing key) in every
      public JS bundle (PB2_CUSTOMER_IO_*); impact = possible read of customer PII profiles /
      message triggering via Customer.io API. NOT actively validated (key belongs to a third-party
      vendor host = out-of-scope per SKILL §1) → reported for vendor-side validation + rotation.
  (b) api-staging credential oracle: "Missing session cookie or API key" vs "API key not found"
      split confirms per-key validation; error message also discloses keys accepted in QUERY
      STRING (?key=) → leak-prone auth design. Chain with earlier CORS reflect-any-Origin +
      credentials finding.
  (c) LOW — Lambda@Edge gate 401 body leaks Node runtime "22.23.2"; robots.txt maps every private
      route (admin/, dev/, workspace-settings...); security.txt discloses the reporting channel
      (Yogosha program "the-phantom-company" with tokenized URL); bundle config enumerates extra
      staging surface (api-staging.tealde.io + *.tealde.io v3, staging Zendesk/Quaderno/Stytch
      tenants, dev Disqus shortname, Sentry DSN+release hash, local.gist.build dev endpoints).
- Clean/negative: .git/.env/backups unreachable (gate exact-path allowlist; all encoding bypasses
  still 401); .well-known/* sits past gate but only security.txt exists; source maps referenced via
  sourceMappingURL but never served (404 soft-404, 3/3 spot-checks); no AKIA/ghp_/AIza/JWT/private-key
  patterns anywhere; no stack traces/internal IPs from any malformed-input probe (uniform JSON,
  400/401/403/405 only, TRACE disabled); S3 listing denied on both config-disclosed buckets
  (403 AccessDenied XML — single read-only root GET each, stopped there); static host config files
  (spa_config_staging/prod.json) fetchable but benign (banner text + incident script IDs).
- Method lessons (folded into skill): read 4xx BODIES not just statuses (version leak); calibrate
  existence oracle with known-existing vs known-missing before trusting it (extension hypothesis was
  wrong — allowlist is exact-path); md5 error bodies to detect catch-all auth (no oracle);
  generic secret regex ≠ enough — add app-config-block grep ([A-Z0-9_]*API_KEY: pattern); compare
  credential-error MESSAGES for missing/invalid splits (= key-validation oracle + auth-mechanism
  disclosure). Details in info-disclosure-testing/references/variants-1.md (V-02 + V-06 field notes).
- Scope: user has still not confirmed program scope for v2staging (security.txt suggests Yogosha
  "the-phantombuster-company" is the disclosure channel); tealde.io hosts reported but NOT probed
  (different registrable domain).
- Class: technique → skill: info-disclosure-testing (V-02, V-06 field notes); bug-hunter (engagement log)

## 2026-10-21 — conversation
- Lesson: On a Cloudflare **managed-challenge** zone (quizlet.com, public bug bounty), the
  challenge is not zone-uniform. `/.well-known/**` on the apex is exempt (match is on the
  `/.well-known/` substring, so `/anything/.well-known/x` passes too), and four whole hosts
  pass through (`study`, `el`, `jg7y`, `ablink`). Those origin responses carry the real
  header/cookie/CORS posture — enough to confirm three findings while every HTML/JS path was
  blocked. Also: a challenge (`cf-mitigated: challenge`) and a deny rule (`403 "Request blocked"`,
  **no** `cf-mitigated`) are different rules — PATCH, paths containing `status`, and `.bak`
  hit the deny rule while GET/POST on the same path hit the challenge.
- Class: WAF/bot-wall characterization + security-header posture → skill: info-disclosure-testing
- Change: field-notes block on the challenge-vs-block distinction, `.well-known` origin window,
  "CF decodes before matching so don't burn requests on encodings", and "never credit the CDN's
  challenge-template headers to the app" (CF's challenge page ships XFO/nosniff/RP/COOP/COEP/CORP
  while origin responses through the same CDN ship none) @ info-disclosure-testing/references/variants-1.md (V-02)
- Repeat signal: strong — the same `.well-known`-allowlist observation already existed from a
  CloudFront-gated SPA; now confirmed on a different CDN and a different program. This is a
  standing step for gated targets, not a one-off.

## 2026-10-21 — conversation
- Lesson: `*.quizlet.com` publishes wildcard DNS (gibberish names resolve to the same Cloudflare
  IPs), so a 150-name DNS brute force returned ~100% false positives and had to be discarded.
  Two gibberish control queries would have caught it in ten seconds. Real enumeration came from
  CT SANs via certspotter (18 names, incl. an internal-only `dev.quizlet.com` that has its own
  `*.dev.quizlet.com` cert but **no public DNS**), and CNAME lookup (with a wildcard in place, a
  CNAME is the only DNS record that reveals the true backend — `study` CNAMEs to a Google-hosted
  target).
- Class: recon / subdomain enumeration → skill: info-disclosure-testing
- Change: "run a wildcard-DNS control before any subdomain sweep" gotcha + certspotter URL and
  CNAME-first advice @ info-disclosure-testing/references/payloads.md (§1)
- Repeat signal: strong — wildcard + CDN-fronted zones are the norm on large public programs.

## 2026-10-21 — conversation
- Lesson: `x-envoy-decorator-operation` returned a complete internal Kubernetes map in one
  unauthenticated header: `eventlogger-publisher-frontend.eventlogger.svc.cluster.local:80/*`
  (mesh = Envoy, namespace, service, port, purpose) on every response from `el.quizlet.com`,
  combined with `via: 1.1 google` (internet → CF → GCP L7 LB → Envoy → k8s Service). The same
  host accepted unauthenticated `POST /` (202 `{}`, `ACAO: *`) — an open event sink one hop from
  the service the header names. And when the WAF hard-blocked exactly `/status` on that host, the
  block itself was evidence the endpoint exists rather than grounds to rule it out.
- Class: information disclosure / internal topology → skill: info-disclosure-testing
- Change: field notes on `x-envoy-decorator-operation` as a first-class V-04 Detect source, the
  "corroborate it is app-emitted, not CDN-emitted, before claiming it" scoping step, and
  "WAF-blocked exact path = endpoint probably exists, re-test from an allowed network"
  @ info-disclosure-testing/references/variants-1.md (V-04)
- Repeat signal: medium — the header is Envoy-default and cheap to check; it appears on any
  k8s/Envoy-fronted service.

## 2026-10-21 — conversation
- Lesson: Credentialed-CORS triage trap: `jg7y.quizlet.com` (a Snowplow collector) reflected any
  `Origin` **and** sent `access-control-allow-credentials: true` — the classic CORS-misconfig
  signature — but the response is a static 1×1 GIF, byte-identical with and without cookies
  (sha256 `46d11334…` identical, CORS headers identical). Nothing session-derived to read ⇒
  by-design collector config ⇒ **not a finding**. The check that closed it: same URL twice,
  bare vs `Cookie:`-stuffed, compare `sha256sum` of both body and `access-control-*` headers.
- Class: CORS misconfiguration → skill: csrf-testing
- Change: added the "reflected Origin + ACAC but cookie-independent body" entry (with the
  sha256 comparison recipe) under False positives of the CORS variant
  @ csrf-testing/references/variants-2.md (V-14)
- Repeat signal: strong — public analytics/beacon collectors ship this combination by design, and
  it is easy to file as a false High.

## 2026-10-23 — conversation
- Lesson: Program-mandated custom headers are a browser-harness trap. Sending
  `X-Inspectiv-Tester` on every request including cross-origin subrequests put it into the
  CORS preflight to `identitytoolkit.googleapis.com`, which Google 403s → Firebase login
  failed with `auth/network-request-failed` — indistinguishable from an app/network bug until
  the preflight was compared with vs without the header (403 vs 200 + ACAO). Fix: scope the
  header to in-scope hosts via `ctx.route`. Same session: playwright package (1248) lagged the
  cached chromium build (1234) — use `executable_path`, not a reinstall. And because every
  protected SPA route silently redirects to /login, a failed login means the whole DOM-XSS
  sweep is testing the login view — always assert `page.url` + a post-login heading first.
- Class: DOM XSS browser verification → skill: xss-testing
- Change: added the Playwright harness block (header scoping, executable_path, login assert)
  @ xss-testing/references/payloads.md (§5, browser confirmation)
- Repeat signal: strong — any engagement with a mandatory custom header + SPA + token-auth
  (Firebase/Cognito/Okta) hits all three failure modes.

## 2026-10-24 — conversation
- Lesson: When the task is "find the same bug in other endpoints", retest the REPORTED
  endpoint first — the pasted report's context claim may be stale. The frontier.com report
  claimed an unquoted `value=` reflection for `asn`; live (2026-10-24) it renders quoted +
  entity-encoded (`<`→`&lt;` `"`→`&quot;`), payload family inert in curl AND a real browser
  (Playwright file:// auto-submit, inert `document.title` markers, zero fires) across the
  full bypass matrix (double-encoding, content negotiation, multipart, valid-data flow,
  PATH_INFO, Host/Cookie/UA/Referer, error paths). Consequence: the same-class hunt on that
  host had no living exemplar — one endpoint turned out to be the entire dynamic surface
  (BFS crawl + 4751-word ffuf ×2). Two exits from "report doesn't reproduce": patched after
  submission vs false positive — ask for the original raw bytes; don't assume either.
  Same session, second thread: a publicly served `.gitignore` was the highest-yield recon
  artifact of the engagement — it turned into a filename wordlist that found
  `envvars/global.php` + `/.config.php` (both 200/0, silent), and the
  "403-on-dir + 404-on-random-child = real enumerable dir" control (vs `.git` where random
  children also 403 ⇒ blanket deny) is what proved existence rather than trusting the 403.
- Class: RXSS retest + dotfile/structure disclosure → skills: xss-testing, info-disclosure-testing
- Change: gotcha added to V-02 False positives @ xss-testing/references/variants-1.md
  (stale report context; retest-before-hunting); 403/404 existence-control + .gitignore-as-wordlist
  gotcha added to V-01 False positives @ info-disclosure-testing/references/variants-1.md
- Repeat signal: medium-strong — any "variants of this report" hunt where the original may
  have been patched; any engagement where dotfiles are served.

## 2026-10-24 — conversation (jardindacclimatation.fr first engagement)
- Lesson: Two separate "the WAF blocked me" errors were both wrong, and both were
  diagnosable from headers alone. (a) Akamai Bot Manager throttles ~1–2 requests per burst
  and then 403s *everything* in <0.3s at the edge **including a benign control value** — the
  control (`A01WX` 403'ing after baseline `A01W` returned 200) is what proves the block is
  behavioural, not payload-triggered, so a "differential" where every variant 403s is
  unproven, not blocked-by-WAF; cool-down ~30–45s. (b) A `503` that appeared only on the
  quote payload — the likeliest "I found SQLi" moment of the session — turned out to be an
  edge-**cached** LVMH maintenance page (`server: AkamaiNetStorage`,
  `server-timing: cdn-cache; HIT`), i.e. unrelated to the payload. `cdn-cache`/`Server` now
  get read before any error is credited to injection. Corollary that paid off: the same
  bot gate 403s `/_next/*` while serving HTML fine, and an operator-pasted `_abck` cookie
  gets re-issued by Akamai as validated (`~0~`), unlocking buildManifest + all 41 chunks —
  which turned out to be the highest-yield recon artifact of the whole session (27 page
  routes incl. unlinked `/admin` and `/auth/callback`, ~40 server routes with verbs/params,
  auth = Okta/next-auth, admin auth = `?token=` query param, and one API route deliberately
  outside the shared `/api/proxy` wrapper: `/api/business/massAssignment`).
- Class: recon via client bundles + WAF/bot false positives → skills: info-disclosure-testing, sqli-testing
- Change: field notes added to V-06 @ info-disclosure-testing/references/variants-1.md
  (endpoint inventory from `_buildManifest.js` + wrapper-prefix grep; `_abck ~0~` bot gate;
  wrapper-external routes as authz suspects; `?token=` in query); false-positive gotcha added
  to V-11 @ sqli-testing/references/variants-2.md (benign-control discriminator for bot
  throttling; CDN-cached error page ≠ backend error).
- Repeat signal: strong — any CDN-fronted SPA (Akamai/Cloudflare bot management) where curl
  gets partial access, and any engagement where injection testing stalls on 403/503.

## 2026-10-24 — conversation (casino-baden-baden.de first engagement, php2shell templates)
- Lesson: The most valuable output of the session happened before a single packet was sent.
  (a) **Read your own quarantine notes before running your own templates.** `WHY-QUARANTINED.md`
  recorded the session-fixation template matching *patched* 8.4.27 byte-identically to vulnerable
  8.4.26 — the operator had already proven the false positive and written "Do NOT re-enable."
  A scan run from that directory would have produced a high-severity finding that was
  demonstrably wrong. (b) **Cross-check the template against the program's own exclusion list.**
  `CVE-2026-109618.yaml` is a memory-exhaustion crash probe (1/8/20 MiB multipart bodies →
  PHP OOM longjmp path) and the pasted policy excluded DoS outright; the php2shell advisory
  date (2026-10-21) was 3 days old against a "CVEs less than 30 days since patch release →
  non-qualifying" rule. Both exclusions were readable from the text the operator had just
  pasted — the request as phrased ("detect the CVE") could not have produced a qualifying
  report that day. Templates needing lab variables (`/vuln.php?page=`, `/tmp/sessions/sess_`,
  `/app/upload.php`) were also silently meaningless against a real host.
  (c) **Verify the hostname exists before anything else.** `shop-staging.casinop-baden-baden.de`
  was NXDOMAIN — an extra `p` in the registrable domain. Sanity-checking `google.com` and the
  previous target against the same resolver first is what separated "typo" from "DNS egress
  broken here," which is a real confounder in sandboxed environments (public resolvers on :53
  were unreachable; only the system resolver worked).
- Lesson: **A 401 wall makes "they're using technology X" unfalsifiable, and that is itself
  the finding.** The operator asserted PHP. Every probe said nothing: no `X-Powered-By`,
  `php-detect` no match, version template 0/1 — but the 401 (421 B, `charset=iso-8859-1`,
  `server: Apache`) is Apache's *own* stock error page, emitted before any application code
  runs. So the negative is not evidence of absence, only of an uninformative vantage point.
  Recording it as "PHP unconfirmed (guess)" rather than "no PHP" is what stops the next
  session from chasing a phantom. The one asymmetry worth keeping: `/.well-known/*` and
  `/server-status` returned **403/956 B** while everything else returned **401/421 B** —
  a different config layer, proof the Apache `Require`/`<Location>` rules are non-uniform,
  and the first thing to re-map once credentials exist.
- Class: template pre-flight + target verification + auth-wall reconnaissance → skills:
  rce-testing, info-disclosure-testing, sandbox-escape-testing (quarantine rationale)
- Change: no technique-skill writeback this round — the novel artifact is the domain profile
  at `domains/casino-baden-baden.de/SKILL.md`, which carries the pasted policy's full
  non-qualifying table (DoS, <30-day CVEs, version disclosure, brute-forcing, user enum) as
  scope rules, plus the refused-template list with reasons, so the next session never
  re-derives them.
- Repeat signal: strong — every engagement opening with "run my nuclei templates against X":
  check quarantine/reason-for-exclusion files, diff template advisory dates against the
  program's CVE-age rule, confirm the hostname resolves, and remember that unauthenticated
  probing behind a front-door 401 can neither confirm nor deny the stack.

## 2026-10-25 — own-engagement (reready.co session 1, unauthenticated-only)
- Source: own-engagement (sandbox.reready.co), user directive ("unauthenticated testing only").
- Scope gate outcome worth remembering: the program authorizes **only** `sandbox.reready.co`
  ("You must use our sandbox environment for all testing… unauthorized testing in our
  production environment → accounts suspended and reports rejected"), so `www.reready.co`
  was refused despite the request naming it, and the literal requested host
  `www.reready.co.test` turned out to be a **garbled parse of `reready.co` + the prose
  "test all …"** — same NXDOMAIN-typo class as casino-baden-baden's extra `p`, plus a
  `.test` TLD appended by the prompt. Resolving the real host before asking anything took
  two commands.
- Lessons (non-obvious detail only):
  (a) **reCAPTCHA coverage is a map of what automated testing can reach.** Every Devise flow
  that *sends email* (sign_up, password/new, confirmation/new, unlock/new) carries
  `g-recaptcha` and fails with the app's generic flash *"You must click the checkbox that says
  I'm not a robot"* — that string is the captcha-failure message, so it distinguishes
  "bot-gated" from "validation error" in one probe. `/users/sign_in` had **no** captcha, so
  login-CSRF, token/Origin matrix and rate-limit tests all ran unauthenticated. Enumerate
  captcha per flow (one GET each, grep `g-recaptcha`) *before* planning an authenticated phase.
  (b) **Rails Origin-check false positive (now in csrf V-13):** valid token + wrong Origin →
  422, valid token + *no* Origin → 200, no token → 422. Reading only the no-Origin case claims
  "Origin unvalidated" — wrong. The 422 body is generic; the **(a)-vs-(b) status differential**
  is the evidence.
  (c) **importmap/modulepreload 404 = the bundle never runs (now in xss V-03):** the sandbox's
  `<link rel="modulepreload" href="/assets/application-<digest>.js">` + `import "application"`
  target 404'd (unhashed `/assets/application.js` 200'd instead), so jQuery/Bootstrap/rails-ujs
  were dead code — any DOM-XSS sweep there would have "cleaned" for a deploy reason, not a
  security reason. One status check precedes every hook-based sweep now.
- Ruled out with evidence (for the profile + future retests): RXSS on `/help?search=` (only
  reflection found anywhere across 90 param/page probes; both contexts fully `html_escape`d,
  `&#39;`/`&quot;`/`&lt;`); SQLi there (16 payloads — literals, no 500, no timing; `%`/`_`
  honored as wildcards = `sanitize_sql_like` not applied, harmless on public content);
  path traversal (nginx 400 raw `../`, 403/9-byte "Forbidden" on `..%252f`/`....//`/`..;`);
  CORS (no ACAO anywhere incl. evil-Origin), host-header 301 injection (301 target hardcoded,
  XFH ignored), open-redirect params (none), `.git/.env/sourcemaps/rails/info` (uniform
  7790-byte app 404), stack traces (malformed JSON → clean 422), GET state changes
  (`/users/sign_out` GET = 404). Rate limits **do** work: login 429 from attempt 6,
  password/new 429 after ~3 (both with 12-byte bodies).
- Class: scope gate / auth-flow recon / CSRF / DOM-XSS → skills: `bug-hunter`, `csrf-testing`
  (V-13), `xss-testing` (V-03), `info-disclosure-testing` (existence-oracle calibration reused)
- Change: V-13 three-armed Origin control @ csrf-testing/references/variants-2.md; importmap
  404 pre-check @ xss-testing/references/variants-1.md V-03; this entry; profile
  `domains/reready.co/SKILL.md` + evidence log `domains/reready.co/evidence/2026-10-25-unauth.md`.
- Repeat signal: (b) and (c) are framework-level and will recur on every Rails/importmap target;
  (a) recurs on any email-sending auth flow.

## 2026-10-30 — conversation (new category skill: infra-fingerprinting)
- Lesson: Stack fingerprinting is being promoted from a recon sub-step to a first-class
  *routing layer*: website fundamentals — which trust decisions the client makes on the
  server's behalf, and which server-side sinks/stores/version footprints exist — are the
  source of logic-bypass hypotheses and skill selection. Non-obvious part: the requested
  companion dataset `comprehensive_infrastructure_recon_map.pdf` (30 components / 600+
  sub-technologies) is NOT on this host (`/home/krhasan` absent; filesystem-wide find for
  `*infrastructure_recon*`/`*recon_map*` → no match), so the skill ships with an explicit
  §8 INGEST POINT instead of an invented table. Fabricating an un-ingested knowledge graph
  would misroute every later session — fingerprints must be `verified`/`guess`-marked.
- Class: recon / fingerprinting / trust-boundary mapping → skill: infra-fingerprinting (new category)
- Change: new `## >> infra-fingerprinting` section in Bugbountyskills.md §2 (client-side
  signal table, server-side signal table, trust-boundary map, signal→technique-skill
  routing table, two-signal verification standard, fingerprint report template, pending
  §8 INGEST POINT); TOC "9 playbooks" → "11 playbooks" @ Bugbountyskills.md
- Repeat signal: fingerprint→routing now starts every engagement; when the operator
  provides the PDF, paste it at §8 in the given table shape and mark each row
  Verified?=verified(evidence)/guess before relying on version→CVE mappings.

## 2026-10-30 — third-party source (Chalmers thesis: modular black-box SQLi scanning)
- Lesson: Core methods extracted from Degerman & Dubrefjord, "Modular Blackbox SQL
  Injection Vulnerability Web Scanning" (Chalmers MSc, 2021): (1) the nine-class attack
  taxonomy (Doupé et al. + Clarke OOB) used as a *coverage checklist* — a failed stacked
  probe proves nothing about the other eight; (2) the "node" abstraction
  {url, parameters, data, cookies, method} with dedup + per-node detection — coverage
  gates discovery, so 0 vulns means "what did we never reach?", not "which payload
  failed?"; (3) eight scanner failure modes *proven by Xdebug coverage traces*, biggest
  non-obvious one: default sqlmap stops testing a form after the FIRST vulnerable param
  (both username AND password were injectable in their login.php; plain sqlmap found one
  — fix `--answers=keep testing=Y`); also JS-event-generated param names, iframe-blind
  crawlers (3 previously-unknown vulns hidden behind iframes), auth-gated content
  requiring register+re-crawl, hidden params in real POST bodies, inter-state dependency
  links created by prior form submissions, crawler loops eating >90% of requests, and
  coverage≠detection (ZAP reached the code, missed the bug); (4) response length alone
  is not an oracle — TRUE/FALSE varies for unrelated reasons, freeze volatility,
  repeat 3-5x, corroborate on a second channel; (5) defense recognition: (int) typecast,
  addslashes/real_escape_string, is_numeric/FILTER_VALIDATE_EMAIL validators, true
  prepared binds — each dictates which payloads are even possible, and "validator
  rejection" ≠ "WAF block" ≠ "not injectable"; (6) no scanner in the study found the
  second-order bug (WackoPicko similar.php) — manual plant-and-trigger discipline.
- Class: SQLi (method layer, all variants) → skill: sqli-testing
- Change: new block `## >> sqli-testing — core black-box scanning methods (book extract:
  Degerman & Dubrefjord, Chalmers 2021)` with §B-1..§B-6 (taxonomy→variant map, node
  method + verbatim sqlmap command shape, failure-mode rules, detection reliability,
  defense table, coverage-first loop) @ Bugbountyskills.md; §6 Reference pointers updated
  to point at it.
- Repeat signal: every sqli engagement starts with the §B-1 class checklist and ends the
  crawl phase with the §B-3 gap review; `keep testing=Y` belongs in every sqlmap
  invocation until proven otherwise.

## 2026-10-30 — third-party source (16 public black-box pentest/bug-bounty writeups)
- Lesson: Consolidated extraction from 16 operator writeups (2 paywalled/promo flagged as
  such, nothing invented). Highest-value non-obvious details: (1) upload bypass by
  *studying the sanitizer's normalization* — leading special chars stripped, middle ones
  replaced with `_` → `.%php` prefix dodged the extension blocklist, then a magic-byte-only
  content check was beaten by keeping a real PNG header + appending `<?php` (W-1);
  (2) wildcard DNS (ANSWER:1 on random hosts) is both an FP trap for subdomain enum AND
  a possible cross-tenant vector when the app does per-tenant subdomains (W-1);
  (3) cert pivoting — Censys cert→hosts for origin IP, crt.sh Org/SAN field search finds
  assets DNS never showed (W-11/W-16); (4) passive-first isn't just stealth: active
  scanners disclose your IP and get firewalled at scale, so Shodan/Censys/Fofa/ZoomEye
  run in parallel with Amass, httpx triages to ~100 live targets (W-16); (5) username
  enumeration via Burp content-length diffs, not error text; three separate rate-limit
  classes (bruteforce/email-flood/workflow-flood) with "no rate-limit" ≠ "insufficient
  lockout" (W-13); (6) WP: author-redirect loop + oembed + readme.txt version truth +
  xmlrpc system.multicall throttle bypass (W-9); (7) k8s: anonymous-API error string is
  the apiserver oracle, SelfSubjectAccessReview reason names your granting CRB, verify
  each rung before advancing (W-12); (8) AI-agent FP patterns to pre-empt: CORS spam,
  severity inflation, unverified stored XSS (headless-browser proof needed), intended-
  functionality flags (W-2); (9) honeypot tells: ancient banners + instant login with
  random password, then egress test from inside (W-8); (10) "story" method — pick one
  narrative (guest→data, input→RCE) over random bug-chasing; chain over checkbox (W-3);
  (11) report skeleton: 9-section client report incl. risk-methodology definitions,
  findings table, attack-chain narrative, 0-7d/7-30d remediation tiers (W-15);
  (12) triage: communication quality, not severity, decides escalation; calibrate for
  dozens of reports/day (W-6 preview).
- Class: cross-category methodology (recon, auth, chain, reporting) → skills: bug-hunter,
  info-disclosure, bac-idor, csrf, business-logic, xss, rce
- Change: new block `## >> blackbox-writeups — core methods from 16 public black-box
  pentest/bug-bounty writeups (source index + §W-A..§W-I: sequencing ladder, recon
  tradecraft, content discovery, WP/k8s/PHP/BaaS platform playbooks, auth/rate-limit
  methods, chain methods, FP discipline, 9-section report skeleton, operational restraint)
  @ Bugbountyskills.md
- Repeat signal: §W-A ladder and §W-F upload/normalization chain feed every future
  engagement; platform playbooks (WP/k8s) are reusable whole; the sanitizer-normalization
  lesson belongs in any future upload-bypass variant work.

## 2026-11-07 — conversation (Kr Hasan standing order)
- Lesson: The agent was producing P4/P5/informational findings instead of the commanded
  high-severity classes. The gap was not knowledge — the class list and ineligible list were
  already written down in four places — it was ENFORCEMENT. Nothing told the agent to notice
  it was drifting, so "report nothing unvalidated" got quietly relaxed into "report the low
  thing I can actually prove".
- Class: cross-category process → skills: bug-bounty-methodology, web-vulnerability-hunting,
  bugbounty-hunter; file: SEVERITY_DOCTRINE.md
- Change: added a DRIFT AUDIT rule (severity doctrine §7) and mirrored it into
  bugbounty-hunter/SKILL.md §0 Mission Directive, bug-bounty-methodology SKILL.md, the
  web-vulnerability-hunting severity block, and Bugbountyskills.md §0 rule 7: before any draft,
  list the severities of your last five candidates — three or more at P4/P5 = drifting, change
  asset or class, never lower the floor; a primitives-only pass closes with "no reportable
  finding — N primitives held as leads". Also re-stated the binding cautions (no false
  positives, no early reports, no non-sensitive/out-of-scope, no wasted recon, keep mining
  writeups, aim high-critical per endpoint).
- Repeat signal: any time the reported-severity mix skews low, check for floor-drift before
  hunting harder — the fix is a harder target/class, not a softer report.

## 2026-11-07 — conversation (Kr Hasan: continuous intake loop + agent-readable skill tree)
- Lesson: Asking an agent to "keep reading reports and upgrade the skill" is worthless as an
  instruction — it needs a deterministic source harvest, a per-report validity test, a counter,
  and a milestone notifier, or it silently does nothing and reports success. Also: a skill file
  that is a 20k-line concatenation is unusable by any agent; the fix is a routing tree at the
  top, not a rewrite of the body.
- Class: cross-category process + knowledge plumbing → files: report-reader.sh,
  report-reader-loop.sh, report-reader.service, knowledge/SKILL-TREE.md, SEVERITY_DOCTRINE.md
- Change: built the intake loop (harvest → read one-by-one → append technique → count → Discord
  every 100) and the decision tree. Verified source access first, then wrote against what
  actually returns 200: HackerOne disclosed reports come from the reddelexc/hackerone-reports
  `data.csv` (15,049 rows with a real `vuln_type` taxonomy — NOT from hackerone.com/hacktivity,
  which is a JS shell); PentesterLand's index is an HTML table in
  `pentesterland/pentesterland.github.io:_pages/list-of-bug-bounty-writeups.md` with a
  "Vulnerability" column (the live /writeups/ page is JS-only); PortSwigger lab solutions come
  from `/sitemap.xml` filtered to `/web-security/*/lab-*`; Bugcrowd has NO public per-report
  feed (crowdstream.json is program metadata only, /disclosures 404s) so Bugcrowd writeups are
  covered via PentesterLand + the curated reference index + the Medium/InfoSec feeds.
- Repeat signal: before wiring any harvester, curl the endpoint and check the byte count and
  content-type — three of the six "obvious" sources here were JS shells or dead paths. And any
  long-running LLM loop must print a machine-readable result line (`READER_RESULT READ=… `) or
  the wrapper cannot count what happened.

## 2026-11-07 — conversation (Kr Hasan: evidence bar, freshness, severity honesty)
- Lesson: Three failure modes that quietly destroy a hunter's signal, and the rules that stop them:
  (1) techniques imported from memory instead of from a source opened this month — bypasses age out
  and unopened citations are unverifiable; (2) knowledge with no verification status — a writeup's
  claim silently becomes "fact" and then gets pasted into a report; (3) severity assigned by vibes —
  the label comes first and the preconditions get back-filled, which is exactly how a padded report
  gets downgraded and the researcher's credibility is spent.
- Class: cross-category methodology (evidence + rating discipline) → files: SEVERITY_DOCTRINE.md §8,
  report-reader.sh, bugbountyhuntingskills.md entry contract, Bugbountyskills.md §0 rules 8-9,
  bug-bounty-methodology SKILL.md
- Change: added a binding EVIDENCE & FRESHNESS DISCIPLINE — entries now carry
  `STATUS: VERIFIED | UNVERIFIED (not reproduced)` alongside SOURCE url + read date; unopened
  sources are not admitted; only last 6-12 months preferred; unverifiable techniques are discarded
  rather than saved. Severity must state the exact attacker preconditions AND the exact data/action
  gained BEFORE a High/Critical rating, with "think critical" defined as worst realistic in-scope
  outcome, not as a bigger label. Low-signal findings are chain material with recorded evidence,
  never standalone entries. Wired into the reader-loop prompt so harvested entries are tagged at
  intake instead of being trusted by default.
- Repeat signal: any time a technique is about to be written into the skill, the two questions are
  "did I open this source, and did I reproduce it?" — if either answer is no, it is a lead, not
  knowledge.

## 2026-11-14 — operator paid-corpus intake (25 accepted/bounty-paid reports)

- Change: extracted 10 new general methods (§17.778–§17.787) + 8 carrier-delta entries into
  /root/bugbountyhuntingskills.md, 10 variants (V-19…V-28) + 10 routing rows into /root/Bugbountyskills.md,
  the loadable atom playbook into skill `web-vulnerability-hunting`
  (`references/paid-corpus-atoms-2026-11.md`), day-one recon atoms into skill `bug-bounty-methodology`
  (`references/recon-atoms-2026-11.md`), and 10 runnable automations into that skill's `scripts/`.
- Lesson: judge a filter/guard bypass by the ERROR-CODE **LAYER**, not the status code — a security-layer
  code (`OB_SEC_*`, "captcha validation failed") on the canonical path moving to a business-layer code
  ("missing parameters") with a path-shape suffix proves the filter was skipped and the handler ran.
- Lesson: run the CONTROL first, always — every paid report in this corpus contains one matched control
  (wrong last-4 → error; `%` → another record; literal `*` → 403; no/wrong key → 401; canonical path →
  guard code). A manipulation without its control is not evidence.
- Lesson: if the CLIENT can compute it, the attacker can — a bundle-shipped AES passphrase/HS256 secret or an
  `*_KEY`/`*_SECRET` pair means the app's own token is mintable; reproduce the envelope and prove acceptance
  with the BUSINESS answer, never with a 200.
- Lesson: a "last 4 digits"-style factor is a LIKE pattern until proven otherwise — probe identity fields
  with `%`/`_`/prefixes and diff the returned identity; one non-secret shared co-factor key makes it a mass
  harvest rather than a single-record leak.
- Lesson: when a program says "we fixed it / we added a WAF", that is an invitation — replay the exact old
  payload (control), entity-encode every operator, swap the sink tag/event, and test the SIBLING parameters
  (one `search.cgi` had three params that each fired).
- Lesson: a dependency the org does not own is attack surface — whois every third-party `src`/`@import` host
  and every published email domain for registrability, and `dig +trace` the NS cut with a `+norecurse` SOA
  to every delegated nameserver (REFUSED on all = dangling delegation). Capture the evidence BEFORE claiming;
  claiming destroys it.
- Lesson: the UI is not the authorization layer — for every precondition (verify/enable/be-a-manager/lock
  state) replay the underlying request from the unqualified account, and from a read-only account tabulate
  SIBLING actions: enforced ones answer 401/403, and the single deviating row (200/302/303 with no UI
  control) IS the finding.
- Lesson: state the report's own boundary — booking/payment acceptance unverified, plugin activation
  assumed, other frames untouched — and name ONE impact mechanism, never a menu of five.
- Repeat signal: resource-exhaustion testing (malformed multipart, nested-array names, empty boundary) is
  authorization-bound and ineligible on most programs — recorded as a hardening atom only, never to be run
  against a live target on spec.

## 2026-11-14 — operator report corpus (Magentrix Cloud / Opirus server-rendered platform, 12 unique reports)
- Lesson: a content DENYLIST on a create API is not a control on the RENDER path — the fix rejected the literal
  token but accepted the same logic built at runtime (`new string(new char[]{(char)60,…})`), because the filter
  inspects the submitted TEXT and the compiler executes the assembled STRING. Name the artefact the validator
  INSPECTS and the artefact the sink CONSUMES; the gap between the two nouns is the bug. Validate semantics
  (decode/evaluate constant expressions) or allow-list the page grammar — never publish the token list.
- Class: validation-bypass → RCE → skill: `web-vulnerability-hunting` (V-29, §17.788)
- Change: new variant V-29 + atoms in `references/technique-atoms.md` @ `/root/Bugbountyskills.md`,
  `/root/bugbountyhuntingskills.md`, `/root/.hermes/skills/web/web-vulnerability-hunting/references/technique-atoms.md`
- Repeat signal: this is the generic "denylist over text vs. compiler semantics" class — replay it on every
  content validator (C#/JS/SQL/SSTI), always paired with the literal-token control.

- Lesson: every accepted WRITE primitive is a write to every writable directory — the platform wrote accepted
  page content to `~/Contents/{Version}/aspx/{Name}.ascx` and compiled it from disk on render, so a
  filter-accepted `XDocument.Parse(...).Save(path)` overwrote a DIFFERENT page's template; the victim's first
  render (lazy compile) executed it, and the file survived deletion of the record. Template directories must not
  be worker-writable; on any server-rendered platform, map every write path against every compile/serve path.
- Class: arbitrary file write → template injection/RCE → skill: `web-vulnerability-hunting` (V-29, §17.789)
- Change: V-29 mechanism (b) + `references/technique-atoms.md` @ all three write targets
- Repeat signal: "lazy compile on first render" is the quiet-victim trigger; persistence outliving the record is
  what makes it admin-visible and worth a re-test after any fix.

- Lesson: extract-then-validate — a ZIP whose ENTRY NAME was `..\..\6.0\aspx\<page>.ascx` wrote into the
  template directory while the API answered `success:false, "Invalid TinCan folder…"`. The content filter never
  saw the payload (it arrived as file bytes), and the error is cosmetic evidence of ordering, not of safety.
  Never accept a response flag as proof; verify placement by reading the artefact back through the app.
- Class: Zip-Slip → RCE (validation-order) → skill: `web-vulnerability-hunting` (V-30, §17.790)
- Change: V-30 + atoms @ all three write targets
- Repeat signal: test BOTH `../` and `..\` entry names — validators routinely strip only the forward slash.

- Lesson: `String.replace(PLACEHOLDER, userValue)` is a mini-template engine — `$'` in the value expands to the
  TEMPLATE'S OWN TAIL, so `"` and `\n` reach the artifact without ever appearing in the value and a 4-character
  blocklist is irrelevant. Two chained tokens declared a git 2.54 `[hook]` section that the backend's own
  `git commit` executed (`command=env` returned the process environment, FLAG included). Fix: a function
  replacer (`() => value`) or pass the value as a CLI argument.
- Class: config/template injection → command execution → skill: `web-vulnerability-hunting` (V-31, §17.791)
- Change: V-31 + atoms @ all three write targets
- Repeat signal: probe `$'`, `` $` ``, `$&`, `$1` at every server-side placeholder substitution, and treat the
  PRESENCE of a value blocklist as the signal that the value is mishandled.

- Lesson: containment is per PARAMETER and per VERB — the filename was sanitized and `renameasset` rejected `../`,
  yet the folder parameter (`P-SelectedFolder`, and `path` on createfolder/deleteasset) traversed freely, writing
  and OVERWRITING files at the site root. A sibling verb that DOES validate proves intent and localises the
  missing check; the terminal (overwriting `/_assets/jsbundles/site.js`) is same-origin stored XSS for every user
  including administrators. Enumerate the feature's whole verb set and every non-filename parameter.
- Class: path traversal in a file store → stored XSS → skill: `web-vulnerability-hunting` (V-32, §17.792)
- Change: V-32 + atoms @ all three write targets
- Repeat signal: one sanitized input proves nothing about its siblings — this is the recurring "validate the wrong
  field" shape, same family as the create-filter-vs-render-path lesson above.

- Lesson: silent sinks still have loud oracles — an opaque `fil=` parameter reaching a filter EXPRESSION language
  with a `SQL.Eval("<sql>",0)` escape hatch was blind, but the document COUNT (page byte size) was the boolean;
  and a sort clause handed verbatim to the ORM turned TRUE/FALSE into 503/200 through T-SQL type unification
  (sort an NVARCHAR as INT → conversion error). Extract with LEN + `SUBSTRING(expr,k,1) <= '<mid>'` binary search
  (case-insensitive collation hides case — use ASCII codes), and probe `IS_ROLEMEMBER('db_owner')`/`DB_NAME()` to
  size the privilege honestly.
- Class: blind SQLi oracles (filter language, ORDER BY) → skill: `web-vulnerability-hunting` (V-33, §17.793/§17.794)
- Change: V-33 + atoms @ all three write targets
- Repeat signal: whitelist sort keys; treat any evaluator exposing a database function as an injection point.

- Lesson: an SSRF that STORES what it fetched is an exfiltration channel — the fetch feature never echoed the
  body, but the generated asset was served anonymously (`/playbookgallery/assetimage/{imgId}`), so the internal
  `openapi.json` (22 endpoints) and a health endpoint came back in full; the low-privilege sibling's parser error
  text ("not an allowed feed format") was the private-network reachability oracle and divergent connection errors
  enumerated ports. Always hunt the store-then-serve route of any URL-fetching feature.
- Class: SSRF → internal content disclosure → skill: `web-vulnerability-hunting` (V-34, §17.795)
- Change: V-34 + atoms @ all three write targets
- Repeat signal: "200 to my listener" is not a finding — the stored body is what makes it reportable.

- Lesson: if the payload can name its own class and the worker calls whatever the object `respond_to?`s, the
  attacker owns the code path — `Oj.load(job.payload)` honoured `{"^o":"Node","args":[…]}` and the dispatcher
  called `run_find`, whose `Open3.capture3("find", *@args)` needed NO shell: argv injection (`-exec cat {} ;`)
  was total. Audit queue pipelines for the serializer's type tag plus duck-typed dispatch, then test the gadget's
  CLI for argument injection rather than shell metacharacters.
- Class: insecure deserialization → RCE → skill: `web-vulnerability-hunting` (V-35, §17.796)
- Change: V-35 + atoms @ all three write targets
- Repeat signal: `safe_load`/`mode: :strict` + class allow-lists; never splat user-derived arrays into a CLI.

- Lesson: the low-privilege account is the impact claim, not an obstacle — the same ReadOnly session that read the
  tenant user table through a raw-query REST endpoint could rewrite a victim's identity field through a generic
  entity-edit endpoint (`e=User`, `data={"Id":…,"Email":…}`) and complete the chain with the standard
  forgot-password mail (admin ATO). Test identity-field writes (email/phone) as a CHAIN STEP, and report the
  chain, never the single missing check.
- Class: SQLi/IDOR → account takeover → skill: `bac-idor-testing` / `bug-bounty-methodology` (DELTA-II)
- Change: carrier deltas in the ledger NOTE @ `/root/bugbountyhuntingskills.md`
- Repeat signal: enumerate the SIBLING VERBS and SIBLING ENTITIES of any edit endpoint, and always look for the
  password-reset terminal behind an email/phone write.

## 2026-11-18 — own-engagement (MicroFocus/OpenText SaaS, pass 1) — workflow + first recon
- Lesson: three transferable items from building the case-by-case workflow and its first live pass.
  (1) **The authorization oracle.** On .NET/`rest-*` product APIs the *class* of error tells you
  whether an authorization check exists: `{"Message":"An internal server error occurred."}` means
  routing/serialization/DI died *before* business logic (wrong request shape — not a finding),
  while `<CommonApiException><ErrorCode>5000</ErrorCode>` means the handler ran and rejected the
  *object* (an authz decision — that is where IDOR/BAC lives). Grading a 500 as "vulnerable" is
  the single fastest route to a rejected report. (2) **Decorative CSRF tokens.** A token that is
  present, absent, or bogus with an identical response is not a gate — measure it, do not assume
  it. On this target `X-Xsrf-Header` was accepted as bogus on `POST /rest-pcweb/runs/collate`
  (204 all three ways), which means the route's real gate is the session cookie alone. Record that
  as chain material for CSRF, never as a report of its own. (3) **Hash-table chunk recovery.**
  An Angular `main.<hash>.js` that only imports a micro-frontend hides the whole product: the
  `remoteEntry.js` chunk-hash table (`.u=s=>...(N:"<16hex>"...)`) plus the base path (`.p`)
  reconstructs every lazy chunk URL — 386 files here — which is where the route table, the legacy
  `.asmx` services and the *second* embedded SPA (`/HTML/EditScriptParameters/templates/`, a Vue
  app on a WebSocket at `.../FrontEnd`) all surfaced. Fetch the chunk table before crawling.
- Class: BAC/IDOR + recon → skill: `hunt-workflow`, `bac-idor-testing`, `info-disclosure-testing`
- Change: wrote `/root/HUNT-WORKFLOW.md`, `/root/HUNT-MODES.md`, `/root/HUNT-CLASSES.md`; fixed 4
  missing referenced files and added a per-target state contract + the oracle table to
  `hunt-workflow/SKILL.md`; new domain profile
  `/root/Myskill/domains/microfocus-saas/SKILL.md` @ `/root/.config/opencode/skills/hunt-workflow/`
- Repeat signal: yes — (a) always establish the *success shape* (204-empty vs 200-body) before
  judging a probe, (b) a second SPA hiding behind a path in the first SPA's chunk strings is a
  recurring pattern, (c) check the program's **closed-report class distribution** before choosing a
  class: 8/11 here were CWE-284, so a plain missing-authz read is saturated and the play is a
  different *scope* of the same flaw (tenant-scoped rather than object-scoped).

## 2026-11-18 — own-engagement (MicroFocus SaaS, pass 2) — the negative-result discipline
- Lesson: a pass that ends in **zero findings is the normal case**, and the value is the written
  negative. Four measured negatives worth reusing: (1) **A route that 500s identically with and
  without a session is dead, not vulnerable** — `GetDashboardLayout` returned the same
  `{"Message":"An internal server error occurred."}` authed and unauthed for every `runId`, which
  by the pre-business-logic signature means the request shape is wrong, never that authz is
  missing. (2) **IIS traversal is clean here** — 7 encodings of `../../web.config` under
  `/loadtest/Files/` all returned 403 (and `..%00` → 400); do not re-run this. (3) **ASP.NET
  `customErrors` hides the stack** — the 3504-byte "Runtime Error" page is the *generic* one, so
  it is not an info-disclosure even though it looks like one. (4) **Read the product's own
  validation strings before hypothesising XSS** — the i18n bundle declares
  `ForbiddenChars_TestName` = `\\/:\\"?\\'<>|*%` and `ForbiddenChars_TrendWidgetName` with `<>` too,
  i.e. the product blocks the angle brackets client-side; a stored-XSS hypothesis that ignores the
  product's declared forbidden-character set is how you waste a pass. The bundle told me the
  answer for free.
- Class: recon/validation discipline → skill: `hunt-workflow`, `xss-testing`
- Change: added the "route that 500s identically authed/unauthed is dead" rule and "read the
  product's own validation strings before hypothesising XSS" to the leak-hunting discipline;
  recorded pass-2 results in `/root/state/recon/microfocus/state.md`
- Repeat signal: yes — **the JS bundle usually contains the validator**. Grepping
  `ForbiddenChars_*`/`Invalid_*`/`Allowed_*` i18n keys is a 30-second check that can kill or
  confirm an injection hypothesis before a single request is sent. Also: ASMX/WCF services leak
  their method names through `<faultstring>` when called with the wrong SOAP action — that is an
  enumeration oracle, not a vulnerability.

## 2026-11-18 — own-engagement (MicroFocus SaaS, pass 3) — sweep + two bypasses, and why they are not reports
- Lesson: the pass produced two genuine filter bypasses and **zero reportable findings**, and the
  reason is the most transferable part. The `addUrlAttachment` URL fetch blocks `127.0.0.1`,
  `[::1]`, `10.0.0.1`, `169.254.169.254` and `gopher://` (all 403) but accepts
  **`http://example.com@127.0.0.1/`** (userinfo authority confusion) and **`file:///etc/passwd`**
  (scheme not filtered) with a 204. That is a real, reproducible allowlist bypass — and it is still
  not reportable, because the read-back endpoint `GET /test/getAttachments?id=` returns
  `ErrorCode 2009 "User unauthorized. Please check your permissions."` **for our own entity**. The
  program excludes *blind SSRF without exploitable PoC*, so a bypass with no read is a lead. Write
  the primitive down, name the exact missing link (a route that echoes the fetched body), and do not
  draft. This is the discipline that separates paying hunters from rejected ones.
- Lesson 2: **`filterType=` is the authorization boundary on the net-auto product.** One endpoint,
  `query.execute.do`, is a generic object dispatcher; `filterType=Device|User|Session|Event|Diagnostic`
  return data while `UserGroup|Task|Policy|Acl|Configuration` return the Error Page — i.e. a single
  parameter carries the whole authz model. That is the highest-leverage fact for any future pass on
  this host, and it was found by sweeping rather than guessing.
- Lesson 3: a **200 with a smaller body than the form is a success signal** (fields consumed and
  cleared). Diffing body sizes beat relying on status codes, which were 200 for success, block and
  error alike.
- Class: SSRF + BAC + recon → skill: `ssrf-testing`, `bac-idor-testing`, `hunt-workflow`
- Change: recorded the allowlist-oracle table and the `filterType` authz boundary in
  `/root/Myskill/domains/microfocus-saas/SKILL.md`; harness bug fixed in the sweep method
  (never `tr '\n' ';'` a cookie jar — it silently serves the login page and fakes 200-but-empty
  results); added the same rule to `hunt-workflow` recon discipline
- Repeat signal: yes — (a) **userinfo-authority confusion (`http://allowed@internal`) is a top-3
  filter bypass** and belongs in the SSRF ladder; (b) **non-HTTP schemes (`file:`, `gopher:`) are
  routinely missed** when the filter only reasons about hosts; (c) before drafting any SSRF, identify
  the read-back route *first* — if none exists, the finding does not exist.

## 2026-11-18 — own-engagement (MicroFocus SaaS, pass 4) — payload work and four hard negatives
- Lesson: four measured negatives, each of which cost a real test and should never be re-run.
  (1) **A quote on a parameter the page ignores proves the SQLi test.** `index.jsp?x='` returned the
  same abnormal-condition 500 as `filterType=Device'` — so the blocklist is global and pre-DB, and
  every "SQLi" hit was the filter. Always include an ignored-parameter control before believing an
  injection error. (2) **Carelessness with a `<script>` marker also proves the XSS test**:
  `<script>` → 500, `"`/`>` → 200 ⇒ character-specific filter, and zero reflection across 22 routes
  × 8 params. (3) **Every POST logging you out is a fingerprint, not a bug** — reproduced with the
  app's *own* favorites call, correct Origin/Referer and a fresh `nmsObturate` that rotates per
  login. Write testing on that product needs a real browser; stop paying for curl attempts.
  (4) **A stored-XSS sink I cannot write to is not a finding.** `device.view.do` renders hostname raw
  inside an anchor while escaping it in `<title>` — genuine inconsistent encoding — but the write
  form is not rendered for a viewer and a forged POST changed nothing. Report only what I can
  reproduce with my own account.
- Class: SQLi/XSS/BAC → skill: `sqli-testing`, `xss-testing`, `bac-idor-testing`
- Change: added the "ignored-parameter control" rule to `HUNT-CLASSES.md` §2 and the
  "every-POST-logs-out = CSRF handshake, use a browser" rule to `HUNT-MODES.md` §G;
  recorded the full verdict tables in the target profile
- Repeat signal: yes — **the control that invalidates an injection finding is usually one extra
  request with a parameter the app ignores.** And a confirmed sink with an unreachable write is
  still worth recording verbatim (with the exact escaped-vs-raw evidence) so a later pass with a
  higher-privilege account can inject and report it in one step.

## 2026-11-18 — own-engagement (MicroFocus SaaS, pass 5) — the placeholder trap
- Lesson: I nearly reported a Cisco running-config as a credential disclosure. `device.config.detail.htm`
  really does return the full `show running-config` (`enable secret 5 xxx`, `username admin privilege
  15 password xxx`, `snmp-server community xxx`, `line vty password xxx`) — and **every single
  secret is the literal placeholder `xxx`** on a scrubbed lab box (`ip domain name aws.net`,
  `snmp-server location BTP-AWS`). The page also offers "View Config" to the viewer role. So the
  correct verdict is inventory/demo data, not a leak. **Always grep the secret values, not just the
  secret keys** — `enable secret` matching is worthless if the value is `xxx`. This is the cheapest
  way to avoid the most embarrassing class of false positive.
- Lesson 2: **the same stored value reached a second sink I had not enumerated** —
  `recenttask.query.execute.do` renders the hostname raw in its table cell, while `device.view.do`
  renders it raw in an anchor and `devicelist`/`query.execute.do` escape it. One unescaped write is
  usually N unescaped sinks; enumerate the *renderers*, not the writer.
- Lesson 3: **rotating object IDs are a scoping tell.** Task IDs changed between two passes in the
  same session (90001 → 88921) and `task.view.htm?taskID=1|2|80000|99999` all return the same
  55.8 KB empty shell, while real ids return 66 KB. That is what a correct object-level check looks
  like — record it as a clean negative and stop.
- Class: XSS / info-disclosure / IDOR → skill: `xss-testing`, `info-disclosure-testing`, `bac-idor-testing`
- Change: added "grep the secret VALUE, not just the key" and "one unescaped write = N unescaped
  sinks, enumerate renderers" to the skill; recorded both sinks + the full device sub-resource map
  and the denied-route list in the target profile

## 2026-11-18 — own-engagement (MicroFocus SaaS, pass 5b) — the unescape audit of my own evidence
- Lesson: I reported a **second** stored-XSS sink (`recenttask`) that did not exist. The cause was my
  own analysis pipeline: I ran `html.unescape()` over the response before counting `<img`, so an
  escaped payload looked raw. Re-measured in raw bytes, `recenttask` has **0 raw / 4 escaped** while
  `device.view.do` has **1 raw / 4 escaped** — one real sink, one phantom. The fix is mechanical and
  belongs in every evidence check: **count the dangerous token in the bytes as received, before any
  decoding.** An `html.unescape()` in the analysis path is as dangerous as a bug in the target.
- Lesson 2: **`enable secret xxx` is not a leak.** The running-config is real and complete
  (`version 15.2`, `hostname R2`, `aaa new-model`, `interface FastEthernet0/0`, `line vty … transport
  input telnet ssh`) but every secret value is the literal placeholder `xxx` on a scrubbed lab box
  (`ip domain name aws.net`, `snmp-server location BTP-AWS`). Grep the **value**, not the key.
- Lesson 3: a self-consistency rule that would have caught both: **for every "finding", re-derive it
  from a second artifact** (here: the raw byte count and the `<title>` twin). If the two disagree,
  the artifact is the suspect, not the target.
- Class: XSS / info-disclosure → skill: `xss-testing`, `info-disclosure-testing`
- Change: added the "raw-bytes before decode" rule and the "re-derive from a second artifact" rule;
  both the pass note and the target profile corrected with a visible retraction

## 2026-11-18 — own-engagement (MicroFocus SaaS, pass 6) — server side, and the shape-invariant fault
- Lesson: I found an **unauthenticated SOAP API** (`/soap/` on net-auto) by directory probing alone —
  it answers `POST` with real `SOAP-ENV:Fault` envelopes and needs no session. The important part is
  how I closed it: **any `<!DOCTYPE …>` returns `529 "Unable to create envelope from given source:"`**
  while a no-DTD envelope reaches the namespace logic (`632 NAMESPACE_ERR`). That one comparison
  proves the DTD is rejected *before* entity expansion — XXE, OOB parameter entities and
  billion-laughs are all dead, with 4 requests. **The control pair (with-DTD vs without-DTD) is the
  whole test; you do not need a collaborator or a file payload to close XXE.**
- Lesson 2: **a shape-invariant error proves nothing about the operation set.** 14 guessed SOAP
  operation names all returned the identical `NAMESPACE_ERR`, because the error happens while
  *building the response* and is independent of the request's shape. Do not report "SOAP endpoint
  enumerable"; report "namespace unknown, web bundles do not contain it" and stop. Compare with the
  ASMX case earlier, where the fault *did* name the method.
- Lesson 3: **three different 404 bodies mean three different layers.** 74 b `<title>Error</title>`
  for `/WEB-INF/` is a container deny; 403 2508 for `/lib/`, `/scripts/` is a directory rule;
  183 b is the app's own page. A developer who reads the first as "WEB-INF reachable" files a false
  positive; the correct read is "protected-path handler, no exposure".
- Lesson 4: **an unparameterised endpoint can be proven unparameterised.** 16 param names on
  `localizer.jsp` left the response md5 identical — that is the cheapest possible kill for an LFI
  hypothesis, and it is a writeable negative.
- Class: XXE / SSRF / LFI / open-redirect → skill: `ssrf-testing`, `path-traversal-testing`, `rce-testing`
- Change: added the "with-DTD vs without-DTD control pair" as the canonical XXE closure test, the
  "shape-invariant error proves nothing" rule, and the three-404-handlers reading discipline;
  full surface recorded in `SERVERSIDE-PASS-6.md` and the target profile
