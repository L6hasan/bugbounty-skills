# Magentrix — Reconcile / Postmortem / Coverage-driven retest
Date: 2026-11-14 · Target: https://bugbounty.magentrixcloud.com (only in-scope asset)
Program: YesWeHack PGM42089 (report IDs YWH-PGM42089-63/75 seen in the supplied reports)
Scope file: /root/scope/magentrix-in-scope.txt
Evidence this run: /root/.hermes/cache/scratch/mag-postmortem/ (HACKBOT_A_reports.txt, live_probe_*.log, validate.sh)

Mode: READ-ONLY. GET/HEAD/OPTIONS + delete-oracle probes aimed ONLY at NON-EXISTENT record ids.
No writes executed, no real record touched, no internal host contacted, no credential used.

## Hackbot A report inventory (supplied pastes) — deduped: 15 distinct + 3 dupes
HA-01 ActivePage RCE, filter-bypass#1 (runtime-built tokens + render-time .aspx write) [paste_1_081947 = dup paste_7_182500]
HA-02 ActivePage RCE, basic (Content <% %> runs; web.config -> /contents/temp/, unauth served) [paste_3_082121 = dup paste_9_182644]
HA-03 ActivePage RCE, filter-bypass#2 (XDocument.Save overwrites another page's .ascx) [paste_1_181934]
HA-04 LMS Zip-Slip (.ascx into Contents/6.0/aspx/) [paste_2_182030]
HA-05 SQLi /sys/document/index `fil` -> SQL.Eval() blind oracle, @@VERSION [paste_4_182234]
HA-06 SQLi /rest/2.0/query ORDER BY (MEQL blacklist bypass) blind oracle, DB_NAME() [paste_6_182406]
HA-07 SQLi /rest/2.0/query + IDOR /rest/2.0/edit -> admin email change -> reset -> ATO [paste_11_182757 = dup paste_16_183308]
HA-08 IDOR /MarketplaceListingReview/UpdateReview (+Delete/+MarketplaceSetting/UpdateReview) [paste_3_182146]
HA-09 Missing authz: ReadOnly creates SecuritySetting via POST /rest/2.0/create [paste_2_082037]
HA-10 SSRF /magicpagesetting/getfeeddata?q= + /PlaybookGallery/GenerateThumbForVideo -> internal 192.168.100.112:8002 [paste_5_182327]
HA-11 Path traversal /sys/staticasset/{uploadasset,createfolder,deleteasset} (P-SelectedFolder) -> write site root [paste_10_182724 = dup paste_15_183211]
HA-12 Insecure deserialization (Ruby Oj.load / Node#run_find / Open3.find) [paste_12_182919]
HA-13 CSRF user delete at /sys/role/index [paste_13_182947]
HA-14 Hardcoded creds in public JS /_assets/scripts/iris/app.W5VXL3Fq.js [paste_14_183113]
HA-15 CSRF-on-GET course delete via GET /rest/2.0/delete/{id} [paste_4_082217]
(plus paste_5_082506 = program rules text, not a finding)

## Live validation results (2026-11-14, non-destructive)
- GET /rest/2.0/delete/{nonexistent} -> 400 "Delete: This endpoint requires POST."  => HA-15 REFUTED
- GET / -> 302 /aspx/Admin ; GET /aspx/Admin -> 302 /User/Login ; GET /api/3.0/entity -> 200 (8 entities)
- /_assets/scripts/iris/app.W5VXL3Fq.js -> 404 (IIS static 404) ; /_assets/scripts/iris/ -> 403 (dir exists)  => HA-14 NOT REPRODUCIBLE
- site.js (the bundle the app loads) -> 0 hits for refreshToken / iris / "get env" / baseUrl  => HA-14 structure absent
- /magicpagesetting/getfeeddata (no q) -> 200 anonymous {"feed":{"entries":[]}}; with q=https://example.com/ AND q=*.invalid -> IDENTICAL empty feed (no fetch differential) => anonymous SSRF not reproducible
- /playbookgallery/assetimage/{uuid} -> 200 image/jpeg anonymous (asset-serving is anonymous; returns placeholder)
- /MarketplaceListingReview/GetReviews (no id) -> 200 "Error" page (param required) ; /MarketplaceListingReview/UpdateReview -> 302 PageNotFound (GET)
- /Lms/UploadFile, /sys/staticasset/*, /PlaybookGallery/GenerateThumbForVideo -> 302 /Home/PageNotFound (GET/OPTIONS)
- /sys/document/index, /sys/role/index -> 302 /User/Login (routes exist, auth-gated)  => HA-05/HA-13 endpoints exist
- /aspx/BB_leak_1787744925, /aspx/BB_CMD_20261028183634 -> 404 ; /contents/temp/ -> 404 ; /contents/ -> 403
- POST /rest/2.0/delete/{nonexistent, Account prefix} -> 403 "Permission Denied"
- POST /rest/2.0/delete/{nonexistent, Case prefix}    -> 200 "Not found"  (oracle re-confirmed, zero state change)
- Tech fingerprint: ASP.NET MVC (__RequestVerificationToken_Lw__ cookie, x-frame-options, CSP frame-ancestors 'self', IIS).
  /rails/info, /rack -> 302 hard-stop => no Ruby/rack surface.

## My own Magentrix findings (the comparison baseline)
MAG-2026-001 Critical 9.1 - unauth soft-delete via POST /rest/2.0/delete/{id} (+ 9-entity permission oracle). Confirmed 2026-11-09.
MAG-2026-002 High 7.5    - unauth cross-entity PII via MEQL lookup / includes expansion. Confirmed 2026-11-09.
=> my ledger holds 2 distinct confirmed issues, not 3 (the "3" in the brief is not matched by the ledger; possibly counts MAG-2026-002's two vectors).
