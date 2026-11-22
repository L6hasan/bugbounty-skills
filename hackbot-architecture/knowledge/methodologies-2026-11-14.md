# Methodologies — operator-supplied PAID-REPORT CORPUS intake, 2026-11-14

Knowledge intake only. Source = 25 accepted/bounty-paid reports the OPERATOR handed over (their own work):
PostAuto (2), DBS India (1), DBS Singapore (2), DBS Indonesia (1), Europcar DK/AU/UK (5), Aboard (3),
Fortum (2), Harman/Samsung (1), OCBC (2), shbc.com.sg (1), service.post.ch (2), hellowork (1), Gandi (1),
JBL (1). No live target was touched for this extraction; the only executable testing this pass was a local
self-test server built for the new scripts.

## Where this batch landed (all four surfaces, so nothing is orphaned)

| surface | content |
|---|---|
| `/root/bugbountyhuntingskills.md` | 10 new slots §17.778–§17.787 + 8 carrier-delta entries (DELTA-A…DELTA-H) + the batch NOTE |
| `/root/Bugbountyskills.md` | batch section: variants V-19…V-28, 10 routing rows, 5 binding habits |
| skill `web-vulnerability-hunting` | `references/paid-corpus-atoms-2026-11.md` (A-01…A-19, the loadable playbook) + 10 `scripts/` automations + `Phase 3c` in SKILL.md |
| skill `bug-bounty-methodology` | `references/recon-atoms-2026-11.md` (day-one dependency / `/public/` / bundle / guard-layer recon) + items 19b–19d in SKILL.md |

Dedupe headline (0-hit families across the three write targets = genuinely new): `matrix param` 0,
`url-encoded wildcard`/`%2A`-as-bypass 0, `LIKE pattern`/`wildcard oracle` 0, `typo domain` 0,
`escapeFunctionCall` 0, `REACT_APP_` 0, `security image` 0, `public secret`/`client-side secret` 0,
`script src takeover` 0, `SVN tag` 0, `index name` 0, `shards` 0, `hashchange` 0, `&#61;` 0, `portalId` 0.
Families the corpus only EXTENDS (delta entries, no slot): dangling-CNAME takeover, cross-tenant write,
UI-is-not-authorization, WAF bypass, GET-based CSRF, DOM-XSS, username enumeration, open redirect,
RelayState, plugin-changelog reasoning.

## §17 slots assigned this pass (full text in the ledger)

§17.778 Path-shape suffix skips a PATH-matched SECURITY layer while the handler runs; proof = the error-code
LAYER changes (security-layer code on the canonical path → business-layer code with `;`). SOURCE: DBS SG
onboarding dedupe (paid) → NRIC+DOB returned address/mobile/email unauthenticated. AUTOMATE:
`guard_suffix_bypass.sh`.
§17.779 Pattern-query (LIKE) oracle on an identity field — the "last 4 digits" factor as a wildcard returns
ANOTHER person's record; a non-unique, non-secret co-factor (mobile) turns it into a mass-PII harvest.
SOURCE: DBS India (paid). AUTOMATE: `pattern_oracle_probe.sh`.
§17.780 Bundle-derived client crypto material (AES passphrase + `Salted__` EVP envelope + HS256 secret) →
mint the application's own token; prove acceptance with the BUSINESS answer, not the status.
SOURCE: DBS India (paid). AUTOMATE: `bundle_secret_sweep.sh`.
§17.781 Encoded-metachar edge bypass (`*`→`%2A`) into a URL-segment-as-index search proxy → whole-cluster
anonymous read (2,545 shards; 3,266 unpublished merchant records with contact PII). SOURCE: DBS ID (paid).
AUTOMATE: `es_proxy_probe.sh`.
§17.782 WAF literal-match vs application entity-decoding asymmetry (`&#61;`/`&#47;`/`&#32;` in a POST body)
+ the 5-step retest-after-fix protocol incl. the sibling-parameter sweep. SOURCE: emobg `search.cgi`
×3 params + Europcar `ftype` (4 paid reports). AUTOMATE: `waf_metachar_ladder.sh`.
§17.783 External-dependency takeover frontier: script-src host for sale (JS in-origin under the page's own
CSP), published contact-email domain for sale (impersonation/interception), delegated-NS reclaim (repeat
hosted-zone create/delete until a DELEGATED nameserver is assigned — matched on attempt 63) with a
Let's Encrypt cert under the victim's brand. SOURCE: DBS (paid $1,000), OCBC + JBL, Fortum + Harman/Samsung.
AUTOMATE: `dependency_takeover_recon.sh`, `dangling_ns_check.sh`.
§17.784 UI-gate-only preconditions (account verification / role level / object lock) + the sibling-action
status differential as the detector; escalate your own role with `_method=PATCH` inside a POST body.
SOURCE: Gandi PAT, Aboard role escalation, Aboard read-only archive, Aboard read-approval (4 paid reports).
§17.785 Unauthenticated server-computed quote manipulation by aberrant quantity/sign (2,597.76 → 2.24 with
`totalExtraPrice: -2600,00`, `bookStatus: ok`), with the server-vs-display discriminator and an explicit
boundary statement. SOURCE: Europcar DK (paid). AUTOMATE: `quote_fuzz.sh`.
§17.786 `/public/`-marked unauthenticated API surface + two-step identifier chaining (metadata endpoint leaks
the `userUuid` the document reader needs). SOURCE: service.post.ch (paid €1,200 ×2).
§17.787 Plugin/source-diff proof standard: version → official tag source → missing sanitiser → changelog
AFTER → live input acceptance, without admin access. SOURCE: shbc.com.sg Contact Form DB 2.9.15 (paid).

## Carrier-delta entries (no slot)

DOM XSS hash "load + base64 decode + inject" gadget (PostAuto `dl`); state-changing GET CSRF fired by
LOADING the URL (hellowork delete-by-resumeId — corroborates the Microkeeper `tsvr.php` lead);
SAML `RelayState` base64 → `CRLF + Content-Type: text/html + <script>` injection (europcar access,
CVE-2025-12101 class); cross-tenant multipart write via client-supplied `portalId` (+ placement
verification); read-only-level archive / approval-request BAC; login security-image as an existence oracle
(authorization-bound credential verification, display-only proof); multi-slash path open redirect
[primitive]; multipart/nested-array-name memory exhaustion **[HAZARD — DoS, ineligible on most programs,
authorization required; recorded as a hardening atom only]**.

## Binding habits this corpus adds (they made these reports get paid)

1. **Control-first, always** — every manipulation carries a matched control that isolates the server's
   behaviour (wrong last-4 → error; `%` → another record; literal `*` → 403; no/wrong key → 401; canonical
   path → guard code).
2. **Read the error-code LAYER**, not the status code, when judging a filter bypass.
3. **A minted token must be proven accepted by the business answer**, never by a 200.
4. **The report states its own boundary** (booking acceptance unverified, plugin activation assumed, other
   frames untouched) and names ONE impact mechanism, not a menu.

HONESTY: this batch is an EXTRACTION of the operator's own paid reports — the mechanisms are recorded as
those reports state them; none was reproduced by this pass, and no target was queried while extracting. The
only live execution was against a local self-test server (`skills/web/web-vulnerability-hunting/scripts/
_selftest_server.py`) used to verify four of the new scripts produce real output
(`guard_suffix_bypass.sh` layer differential, `pattern_oracle_probe.sh` control-vs-wildcard,
`es_proxy_probe.sh` literal-403 vs `%2A`-200 + index enumeration, `bundle_secret_sweep.sh` secret detection).
FRESHNESS: n/a (operator corpus, not a disclosure feed).

---

# Batch 308 — operator report corpus: a server-rendered template platform (Magentrix Cloud / Opirus, `bugbounty.magentrixcloud.com`), 2026-11-14

Sources: the operator's Magentrix/Opirus report set — 14 pasted entries = 12 unique sources (the static-asset
path-traversal report and the SQLi→IDOR→forgot-password report each appear twice verbatim). Read in full
2026-11-14; knowledge intake only — no target touched, no credential exercised.

| surface | content |
|---|---|
| `/root/bugbountyhuntingskills.md` | 9 new slots §17.788–§17.796 + 5 carrier-delta entries (DELTA-I…DELTA-V) + the batch NOTE with the 0-hit dedupe ledger |
| `/root/Bugbountyskills.md` | batch section: variants V-29…V-35, 8 routing rows, 5 binding habits |
| skill `web-vulnerability-hunting` | `references/technique-atoms.md` (server-rendered-template / file-store / blind-oracle atoms) + `references/aspnet-route-oracles.md` (the Opirus/ASP.NET REST + template surface) |
| `/root/Myskill/LESSONS.md` | 7 lessons (one rule each) |

Dedupe headline (0-hit families across the three write targets = genuinely new): `XDocument` 0, `new string(new char` 0,
`char[]` 0, `ascx` 0, `TinCan` 0, `Lms/UploadFile` 0, `MarketplaceListingReview` 0, `UpdateReview` 0, `GetReviews` 0,
`data-rev-id` 0, `getfeeddata` 0, `GenerateThumbForVideo` 0, `assetimage` 0, `P-SelectedFolder` 0, `createfolder` 0,
`deleteasset` 0, `renameasset` 0, `profileTemplate` 0, `git config` 0, `Oj.` 0, `respond_to` 0, `Open3` 0,
`run_find` 0, `RubitMQ` 0, `ORDER BY CASE WHEN` 0, `IS_ROLEMEMBER` 0, `DB_NAME` 0, `SQL.Eval` 0, `MEQL` 0,
`AspxPage` 0, `web.config` 0, `/contents/temp` 0. Families only EXTENDED (delta, no slot): IDOR/BOLA on
write+moderation verbs, client-side-secret mining in a public bundle, CSRF on a destructive admin route,
blind-SQLi oracles as a class, raw-query REST passthrough, "write to a served path → anonymous read".

## §17 slots assigned this pass (full text in the ledger)

§17.788 A create-time content DENYLIST is not a control on the RENDER path — a text filter dies to any construct
that assembles the token at runtime (`new string(new char[]{…})`); validate semantics/allow-list the page grammar.
§17.789 TEMPLATE POISONING by an accepted write primitive into the compiled-template directory — the filter guards
create, the compiler reads disk; the victim's FIRST render (lazy compile) is the trigger; the file outlives the record.
§17.790 EXTRACT-BEFORE-VALIDATE — a `..\..\<page>.ascx` archive entry lands in the compile directory and the API still
answers `success:false`; the content filter never sees the payload (it arrived as file bytes).
§17.791 `String.replace` SUBSTITUTION TOKENS (`$'`, `` $` ``, `$&`) — `$'` inserts the template's own tail, smuggling
`"`/`\n` past a 4-char blocklist → a new git config-hook section the backend's own `git commit` executes.
§17.792 Containment is per PARAMETER and per VERB — a sanitized filename does not protect the folder/path parameter of
upload/createfolder/deleteasset → webroot write/overwrite/delete → served-bundle overwrite = origin-wide stored XSS.
§17.793 A filter-EXPRESSION language with a DB escape hatch (`SQL.Eval("<sql>",0)`) injected through a list parameter;
oracle = response SIZE (document count), extraction by ASCII binary search (collation hides case).
§17.794 A sort clause handed verbatim to the ORM (unknown key + aggregate) is SQLi; oracle = T-SQL type-unification
conversion error (503 = TRUE / 200 = FALSE); `IS_ROLEMEMBER('db_owner')` sizes the privilege.
§17.795 SSRF that STORES what it fetched — the anonymously served asset route is the exfiltration channel; the
low-privilege sibling's parser error text is a private-network reachability + port oracle.
§17.796 Deserialization gadget chosen BY THE PAYLOAD (`{"^o":"Node"}`) plus `respond_to?` dispatch in the worker →
the gadget's `Open3.capture3("find", *@args)` = argv injection into a trusted CLI.

## Carrier-delta entries (no slot)

Review write/delete/MODERATION IDOR with ids published in the read path's HTML (`data-rev-id`); the
raw-query REST endpoint → generic entity-edit (identity-field mass assignment) → forgot-password → admin ATO chain;
public-bundle env object carrying `username`/`password`/`refreshToken` (grep shape for §9.3); CSRF on the
user-management delete route (DELIVERY primitive for the template write, never a standalone finding);
"execution → read config → write under a served path → fetch without cookies" as the standard way to convert a
blind RCE into anonymous-disclosure evidence.

## Binding habits this corpus adds

1. Name the two nouns of every validator: the artefact it INSPECTS vs. the artefact the SINK consumes — the gap
   is the bug class (§17.788/§17.790/§17.792/§17.794 are four instances of one idea).
2. Every accepted write primitive reaches every writable directory: map where the runtime COMPILES and SERVES.
3. Response flags describe intent, not the filesystem — verify by reading the artefact back through the app.
4. When a fix closes a finding, re-run the old request as the CONTROL, then attack the CLASS (a denylist's shape
   tells you what it cannot see).
5. Silent sinks still have loud oracles: status/conversion errors, list-page byte size, a fetcher's parser text.

HONESTY: this batch is an EXTRACTION of the operator's own reports — every mechanism is recorded as those reports
state it, preserving their reproduced/not-reproduced boundary (the ActivePage filter bypass, template poisoning,
Zip-Slip, asset traversal, SSRF pair, `fil` injection, ORDER BY injection, the ATO chain and the deserialization
gadget all carry the reporter's PoC/screenshots against the program's test tenant). Nothing was reproduced by
this pass and no target was queried. FRESHNESS: operator corpus dated 2026-08…2026-11 — inside the preferred window.
