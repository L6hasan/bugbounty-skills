# learnings.md — bugbounty-hunter

Append-only. Read at session start, append at session end. Newest entries at the top of each
section. Only a technique **verified on a lab or confirmed on target** gets promoted into
`references/playbooks.md`; unverified techniques stay here marked UNVERIFIED. Never cite a
writeup you have not opened; every real card carries a source URL and accessed date.

## Research queue

- [ ] OAuth redirect_uri path/suffix confusion — source: fetch current — applies to SSO callback — priority H
- [ ] Client-side authz on UUID object APIs — source: fetch current — applies to "my X" endpoints — priority H
- [ ] SSRF via URL preview / image proxy — source: fetch current — applies to import/preview — priority H
- [ ] Race on one-time credit/coupon redemption — source: fetch current — applies to checkout — priority M
- [ ] JWT `kid`/`jku` trust — source: fetch current — applies to any JWT-based API — priority M

Keep 5–10 items. Fill in the exact URL when you open the source; never fabricate one. A checked
item must be promoted (verified) or moved to Failed with a reason.

## Skill version

- Current: **2.3.0** (2026-11-07)
- Version bump rules: MINOR = new verified/promoted technique or rule · PATCH = correction ·
  MAJOR = structural change to the loop.

## Confirmed techniques

<!-- Seed cards below were written from general, well-known technique patterns, not from an
opened disclosed report. They carry no source URL, are marked UNVERIFIED, and must not be cited
or promoted until reproduced on a lab or confirmed on a target. -->

### 2026-11-07 — OAuth redirect_uri prefix/path confusion (seed)
Source URL: none — general pattern, not from an opened writeup
Accessed: n/a
Verified: unverified
Class: OAuth
Precondition: authorization-code flow; server validates redirect_uri by prefix or host-contains.
Signal: `client_id` + `redirect_uri` in the authorize URL; callback accepts extra path segments.
Request shape: `GET /authorize?client_id=..&redirect_uri=https://app.example/callback/../<my-host>&response_type=code&scope=..`
Root cause: string prefix match or unnormalized path instead of exact-match allow-list.
Bypass: encoded `..`, `@`, appended subdomain, or an open redirect on an allow-listed host.
Chain potential: code delivery to attacker → account takeover (P2/P1).
Applies to: any in-scope app with SSO or third-party login.
Status: untested

### 2026-11-07 — Client-side authorization on object IDs (seed)
Source URL: none — general pattern, not from an opened writeup
Accessed: n/a
Verified: unverified
Class: IDOR/BOLA
Precondition: SPA/API with UUIDs; object fetched by ID, role/ownership checked only in UI.
Signal: API returns full object including fields the UI hides; ID appears in a JS bundle or
another user's response.
Request shape: `GET /api/v1/<objects>/<uuid>` with account B's session for account A's uuid.
Root cause: endpoint loads by primary key with no ownership/tenant predicate.
Bypass: read via export, report, or GraphQL node lookup when the REST route is patched.
Chain potential: cross-tenant data access, PII exposure (P2).
Applies to: every "my X" API and every admin list endpoint.
Status: untested

### 2026-11-07 — SSRF through URL preview / image proxy (seed)
Source URL: none — general pattern, not from an opened writeup
Accessed: n/a
Verified: unverified
Class: SSRF
Precondition: feature fetches a user-supplied URL server-side (preview, import, avatar, PDF).
Signal: request body accepts a URL; response embeds remote content or metadata.
Request shape: `POST /api/preview {"url":"http://<collaborator>/x"}` then
`{"url":"http://169.254.169.254/latest/meta-data/"}` read-only.
Root cause: no egress allow-list / no metadata IP block.
Bypass: decimal IP, `[::1]`, DNS rebinding, redirect to internal host.
Chain potential: cloud credential theft → infrastructure access (P1).
Applies to: upload, import, webhook, and link-preview endpoints.
Status: untested

## Failed / false positives

- Header/CSP/TLS findings: rejected as informational every time. Do not test.
- Open redirect with no token or credential in the URL: P4. Only pursue as an OAuth/SSO chain.
- GraphQL introspection alone: accepted as informational at best. Only pursue hidden mutations.
- Missing rate limit on login without OTP/lockout bypass: P4.
- Self-XSS in a profile field: not a finding; needs a stored cross-user context.
- `/.git/HEAD` reachable but no object recovery: low value; only pursue if source is recoverable.

## Triage patterns

- Programs reject "could lead to" language. Report only reproduced impact.
- A chain is judged at the impact of its last step, but every link must be demonstrated.
- Severity vocabulary differs by platform; use the program's labels, add CVSS separately.
- A 200 on an admin URL is not access — verify data or function.
- Duplicate risk rises with generic findings; prioritize logic and multi-step chains.
- Low findings are chain material: record evidence, test combination, and only report the chain
  if it reaches ATO, sensitive data, RCE, or admin functionality.
- Before any draft, re-read the program's core-ineligible list; a clean chain to an ineligible
  class still fails.

## Playbook promotions

<!-- Move methods here once a finding is confirmed. Include the exact request shape. -->

## Changelog

- 2026-11-07 — **v2.3.0** — Telegram is now finding-only. Added `scripts/notify_telegram.py`, the
  single approved sender; it refuses anything not confirmed/verified or missing title,
  description, ≥3 steps, PoC, impact, or P1–P3 severity. Disabled the bot's background-session
  notifications (`TRACK_BACKGROUND_SESSIONS=false`). No status, candidate, or progress pings.
- 2026-11-07 — **v2.2.0** — Added §0 Mission Directive (report-only class list, ineligible items
  as chain primitives, five cautions, five-candidate drift audit), the operator "low findings are
  chain material" rule, a pre-report gate that checks the core-ineligible list and requires
  concrete impact (ATO / sensitive data / RCE / admin), research freshness (6–12 months, opened
  URL + accessed date, lab/target verification before promotion), and severity honesty
  (preconditions + exact gain before High/Critical). Seed cards marked UNVERIFIED with no source.
  Full standing order mirrored at `/root/hackbot-architecture/SEVERITY_DOCTRINE.md`.
- 2026-11-07 — **v2.0.0** — Restructured into a portable 11-state loop (RESEARCH → UPGRADE →
  RECON → HUNT → DIG → BYPASS/ESCALATE/CHAIN → VERIFY → REPORT → LEARN). Added `AGENTS.md`
  universal entry, `WORKFLOW.md` state machine with timeboxes and resume protocol,
  `references/escalation-ladder.md` (block taxonomy, 5-attempt bypass menu, chain patterns),
  `references/research-loop.md` (source rotation, promotion/pruning rules), and
  `targets/_template/state.md` for resumable hunts. Self-contained: SKILL.md works without
  references.
- 2026-11-07 — **v1.1.0** — Rewrote skill around a P1–P3 severity floor, explicit P4/P5 reject
  list, three-question impact gate, per-class minimum-proof table, writeup mining gate, and
  append-only learnings loop. Added playbooks, writeup sources, report template, scope template.
## Session notes

### 2026-11-07 — swisslos.ch session (reachable-app pivot)
- When the primary edge is IP-blocked, pivot to subdomains on different platforms
  (Vercel/Netlify/Lenaxis/Cloudflare). `adventslos`/`roadshow`/`winforlife` were
  reachable while `www`/`git`/`registry` were TCP-dead.
- Next.js `/api/*` probing: unknown paths return the platform 403/404 catch-all with a
  constant body length; filter by that length, not by status alone.
- `GET /api/test_nl_inx` pattern: test/debug routes left in prod leak integration config
  (campaign, templates, credential-present booleans). Always enumerate
  `test|debug|hello|ip_check|status` on Next.js apps.
- Password-only export dashboards (`/export/login`) are P3 unless a weak/default password
  or bypass is proven; never online-guess.
- CORS: `Vary: Origin` alone is not a lead; require ACAO reflection + credentials + a
  data read. Reachable APIs here returned no ACAO.
- Failed: guessing `/api/confirm` parameter names; dead DOM-XSS sink where the code uses
  `getElementById` but the page only has a class.

### 2026-11-08 — swisslos.ch session (pass 9: image-optimizer + path-normalization negatives)
- Next.js self-hosted image optimizer: a clean 400 `"url" parameter is not allowed` on external
  targets (vs 200 for local relative paths) confirms `remotePatterns`/`localPatterns` is locked to
  local — a fast, non-collaborator way to rule out image-proxy SSRF.
- Route-level auth in Next.js App Router survives double-slash / case / `%2f` / dot-dot
  normalization (308 canonical redirects or still-401/404); path normalization is not a viable
  bypass when the gate lives in a catch-all route handler, not nginx location matching.
- No skill version bump: nothing new promoted to the playbooks (two clean negatives only).

### 2026-11-08 — swisslos.ch session (pass 15: reader-proxy SSRF/LFI disambiguation)
- When testing SSRF/LFI through a third-party reader proxy (r.jina.ai), distinguish three empty-ish
  outcomes: (a) target returns an EMPTY body -> proxy emits `{"code":422,"name":"AssertionFailureError",
  "message":"Unexpected empty file"}` — this means the param was treated as a missing local path, i.e.
  NOT a URL fetcher; (b) the proxy's OWN anti-SSRF filter returns a "Cloudflare Attention Required"
  page for metadata/link-local IPs (169.254.169.254) — that is a proxy constraint, not a target
  response, and must not be read as the target fetching metadata; (c) a benign relative path returns
  real content (the baseline). Use (a) vs (c) to prove the param is a local file reader, and treat
  (b) as untestable-through-this-proxy rather than a lead.
- A Citrix NetScaler AppFirewall LFI signature can key off the FILENAME (`passwd`, `etc`, `WEB-INF`)
  and not just `../`: absolute `/etc/passwd` and relative `etc/passwd` both 403 while `lobby/1.jpg`
  passes — so don't assume a traversal filter means absolute-path reads are still worth trying.
