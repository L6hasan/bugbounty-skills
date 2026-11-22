# general-technique INDEX — grep this, then read_file(<part>, offset=<line-1>)
# 843 segments / 45 part(s)

general-technique-01.md|4|BugbountySkills — Consolidated Bug Bounty Hunter Playbook
general-technique-01.md|19|TABLE OF CONTENTS
general-technique-01.md|33|0.5 AGENT DECISION TREE — route by observation (READ THIS FIRST)
general-technique-01.md|99|1. META & ORCHESTRATOR
general-technique-01.md|101|>> SKILL_SPEC — How technique skills are structured
general-technique-01.md|105|Skill Build Spec (shared by all 10 bug-bounty skills)
general-technique-01.md|118|1. SKILL.md frontmatter (exact shape)
general-technique-01.md|136|2. SKILL.md body (target 150-300 lines)
general-technique-01.md|164|3. Variant reference files (deep playbook)
general-technique-01.md|172|V-01: <Variant name>
general-technique-01.md|199|4. Tone
general-technique-01.md|204|5. The suite (sibling skills, cross-reference by directory name)
general-technique-01.md|219|Bug Hunter — engagement orchestrator
general-technique-01.md|230|2. Hunt workflow
general-technique-01.md|292|3. Technique routing table
general-technique-01.md|310|4b. Conversation intake — every conversation gets mined into its category
general-technique-01.md|337|6. Test mailboxes
general-technique-01.md|352|7. File map
general-technique-01.md|370|2. TECHNIQUE SKILLS
general-technique-01.md|378|2. Engagement workflow
general-technique-01.md|410|3. Variant selection table
general-technique-01.md|430|4. Verification standard
general-technique-01.md|456|Summary
general-technique-01.md|460|Steps to reproduce
general-technique-01.md|472|Impact
general-technique-01.md|477|Remediation
general-technique-01.md|482|References
general-technique-01.md|489|6. Reference pointers
general-technique-01.md|501|Payloads, request templates, and cross-cutting material
general-technique-01.md|509|Table of contents
general-technique-01.md|523|Two-account testing setup (the backbone)
general-technique-01.md|528|Why one account proves nothing
general-technique-01.md|545|Procedure
general-technique-01.md|580|Curl replay templates
general-technique-01.md|586|--- T1: own-object baseline (control A) ---------------------------------
general-technique-01.md|590|--- T2: cross-principal probe (the actual test) ------------------------
general-technique-01.md|594|--- T3: no-credentials control (V-02: missing auth vs missing check) ----
general-technique-01.md|598|--- T4: write probe — use only on B's tester-created object -------------
general-technique-01.md|603|--- T5: mass-assignment probe (V-04) ------------------------------------
general-technique-01.md|609|--- T6: HPP duplicate-parameter probe (V-07) ----------------------------
general-technique-01.md|614|--- T7: role/context header flip (V-11) ---------------------------------
general-technique-01.md|618|--- T8: version differential (V-10) -------------------------------------
general-technique-01.md|623|--- T9: nested-path segment matrix (V-13) -------------------------------
general-technique-01.md|630|ID-format pattern catalog
general-technique-01.md|647|--- G2: field/arg detail for one type (find $id: ID! entry points) ------
general-technique-01.md|652|--- G3: partial introspection fallback (full introspection disabled) ----
general-technique-01.md|657|Also probe: { __type(name:\"Query\") { fields { name } } }  and error-based field suggestions.
general-technique-01.md|659|--- G4: own-node baseline ----------------------------------------------
general-technique-01.md|664|--- G5: cross-principal probe (swap the decoded inner id) ---------------
general-technique-01.md|666|Global IDs are usually base64("<Type>:<id>") — encode locally:
general-technique-01.md|668|printf '%s' '<TYPE>:<OTHER_USER_NUMERIC_ID>' | base64
general-technique-01.md|673|--- G7: field-level authz pass (sensitive fields on your OWN node) ------
general-technique-01.md|678|Encoder / obfuscation tricks
general-technique-01.md|698|Diff-aware probe: own vs foreign object side by side
general-technique-01.md|703|Chain it with
general-technique-01.md|730|Table of contents
general-technique-01.md|743|Control (A's own object) vs. probe (B's object)
general-technique-01.md|771|Strip every credential; use a clean cookie jar so nothing leaks in
general-technique-01.md|775|Control: a known-protected sibling
general-technique-01.md|803|V-04: Internal variable overwriting via mass assignment object property injection
general-technique-01.md|861|V-08: Cryptographic entity guessing via cryptographically weak UUID/GUID generation routines
general-technique-01.md|891|Candidate derived from your own ID(s); fetch as A
general-technique-01.md|919|Table of contents
general-technique-01.md|931|1) Store B's object id in a trusted field (write-time check may pass)
general-technique-01.md|936|2) Trigger the sink
general-technique-01.md|964|V-11: Contextual role-based state flipping through client-side request mutation
general-technique-01.md|1021|V-15: Cross-tenant data exposure via insecure multi-tenancy boundary isolation flaws
general-technique-01.md|1049|List-surface sweep (server-side filter check)
general-technique-01.md|1074|>> business-logic-testing — SKILL.md
general-technique-01.md|1078|2. Engagement workflow
general-technique-01.md|1112|3. Variant selection table
general-technique-01.md|1132|4. Verification standard
general-technique-01.md|1158|Title: <Flaw> allows <consequence> via <mechanism> (V-<NN> <short variant name>)
general-technique-01.md|1164|Summary
general-technique-01.md|1168|Steps to reproduce
general-technique-01.md|1179|Impact
general-technique-01.md|1184|Remediation
general-technique-01.md|1189|References
general-technique-01.md|1195|6. Reference pointers
general-technique-01.md|1210|Payloads, request templates, and cross-cutting material
general-technique-01.md|1221|Table of contents
general-technique-01.md|1234|Race-condition testing procedure (parallel bursts)
general-technique-01.md|1308|Telling a real race from jitter
general-technique-01.md|1329|Negative / edge value test matrix
general-technique-01.md|1358|R1: classic Host override on the reset trigger
general-technique-01.md|1365|R2: forwarding headers (trusts proxy-derived host)
general-technique-01.md|1371|R3: header variants in one ladder (run one at a time, record each)
general-technique-01.md|1373|-H 'Forwarded: host=<ATTACKER_HOST>;proto=https'
general-technique-01.md|1375|-H 'X-Forwarded-Server: <ATTACKER_HOST>'   -H 'X-Host: <ATTACKER_HOST>'
general-technique-01.md|1377|-H 'X-Original-Host: <ATTACKER_HOST>'      -H 'X-HTTP-Host-Override: <ATTACKER_HOST>'
general-technique-01.md|1379|R4: duplicate / polluted Host (second value wins in some parsers)
general-technique-01.md|1385|R5: absolute-form request line (seen by forwarding layers first)
general-technique-01.md|1390|Encoder / obfuscation tricks (paths & WAF)
general-technique-01.md|1414|Chain it with
general-technique-01.md|1446|>> business-logic-testing — variants-1.md (variant playbook)
general-technique-01.md|1450|Table of contents
general-technique-01.md|1463|Probe: single tampered money field
general-technique-01.md|1469|Read back the server-persisted amount, cache-busted
general-technique-01.md|1497|V-02: State machine defiance via workflow circumvention and multi-step transaction skipping
general-technique-01.md|1529|Turbo Intruder — synchronized burst over one HTTP/2 connection
general-technique-01.md|1565|Unicode variant on one promising candidate
general-technique-01.md|1569|Edge rewrite header variant
general-technique-01.md|1600|then read the inbox: does the reset URL point at <ATTACKER_HOST>?
general-technique-01.md|1630|Baseline: wrong code must fail (control)
general-technique-01.md|1635|Nullification candidates
general-technique-01.md|1642|Independent signal: does the gated step now proceed?
general-technique-01.md|1673|V-08: Algorithmic complexity attacks as a DoS-style logic flaw (cgroup/resource exhaustion)
general-technique-01.md|1741|>> business-logic-testing — variants-2.md (variant playbook)
general-technique-01.md|1745|Table of contents
general-technique-01.md|1757|V-09: Coupon and promo code replay via multi-threaded locking failures
general-technique-01.md|1792|After the burst: authoritative check — distinct orders carrying the discount
general-technique-01.md|1796|V-10: Negative value input processing flaws leading to account credit generation
general-technique-01.md|1830|Baseline
general-technique-01.md|1834|Control: legitimate positive purchase (expect debit)
general-technique-01.md|1839|Probe: single negative quantity (minimal demonstrable unit)
general-technique-01.md|1844|Independent signal: ledger/balance re-read
general-technique-01.md|1876|V-12: ID de-synchronization via multi-stage form context substitution
general-technique-01.md|1911|Diff both objects, cache-busted
general-technique-01.md|1942|State omission on the callback (expect: rejected)
general-technique-02.md|4|V-14: Business flow evasion through client-side logic interception and response flipping
general-technique-02.md|42|1) In proxy: flip the failed-step response to the success shape, capture the
general-technique-02.md|44|follow-up the client then sends, e.g.:
general-technique-02.md|46|2) Replay that follow-up directly — no edited client involved
general-technique-02.md|52|3) Independent readback of the finished flow
general-technique-02.md|84|V-15: Insecure ID direct assignment during self-registration elevating roles
general-technique-02.md|120|Control: plain signup (default role) — register in a fresh browser/jar
general-technique-02.md|125|Independent signal: fresh login, then a role-gated action
general-technique-02.md|157|Engagement workflow
general-technique-02.md|199|Variant selection table
general-technique-02.md|222|Verification standard
general-technique-02.md|244|Reference pointers
general-technique-02.md|252|Table of contents
general-technique-02.md|263|Minimal HTML form PoC
general-technique-02.md|298|GET trigger templates (img / script / navigation)
general-technique-02.md|321|Tunnelling note: text/plain and application/json
general-technique-02.md|349|2) variant matrix — change ONE thing per run, log status + body + side effect
general-technique-02.md|351|d) Origin null            → -H 'Origin: null'
general-technique-02.md|353|e) Origin regex-buster    → -H 'Origin: https://<TARGET_HOST>.evil.tld'
general-technique-02.md|355|f) no Origin/Referer      → delete both header lines
general-technique-02.md|357|g) method mutation        → -X GET with params in the query string
general-technique-02.md|359|h) CT reshaping           → -H 'Content-Type: text/plain' / -F 'a=b' (multipart)
general-technique-02.md|361|WAF evasion: encodings and obfuscations
general-technique-02.md|386|V-14 preflight vs actual, side by side
general-technique-02.md|393|V-15 policy fetch
general-technique-02.md|405|Chain it with
general-technique-02.md|435|Table of contents
general-technique-02.md|448|V-03: SameSite cookie restrictions and the Lax top-level navigation window
general-technique-02.md|484|Table of contents
general-technique-02.md|499|V-10: Double submit cookie bypass with CRLF response splitting
general-technique-02.md|534|V-11: Referer and Origin validation bypass via stripping and loose regex
general-technique-02.md|556|browser: <iframe sandbox="allow-forms allow-scripts" srcdoc="…auto-submit form…"> → Origin: null
general-technique-02.md|572|V-12: Content-Type manipulation and multipart reshaping
general-technique-02.md|610|V-13: JSON and form tunnelling with parser flexibility
general-technique-02.md|646|V-16: Cross Site WebSocket Hijacking
general-technique-02.md|683|fixate <T_FIX> (+SID) onto victim, victim logs in, then:
general-technique-02.md|701|2. Engagement workflow
general-technique-02.md|754|3. Variant selection table
general-technique-02.md|775|4. Verification standard
general-technique-02.md|803|<Class> exposed via <mechanism> at <location>
general-technique-02.md|811|Steps to reproduce
general-technique-02.md|822|Impact
general-technique-02.md|828|Remediation
general-technique-02.md|834|References
general-technique-02.md|840|6. Reference pointers
general-technique-02.md|858|Table of contents
general-technique-02.md|870|2. .git exposure validation: real HEAD/objects vs soft-404 and honeypots
general-technique-02.md|913|3. curl capture templates: headers, banners, sourcemaps
general-technique-02.md|938|2) fetch and validate structure
general-technique-02.md|959|200 + Content-Type + ETag → world-readable object even with listing denied
general-technique-02.md|961|403 AccessDenied → read blocked; 404 → key wrong
general-technique-02.md|973|6. Redaction checklist for discovered secrets
general-technique-02.md|1011|7. Chain it with (suite cross-references)
general-technique-02.md|1046|Table of contents
general-technique-02.md|1059|V-01: Exposed version control repositories and backup management leakage
general-technique-02.md|1125|V-05: Arbitrary resource harvesting via unprotected directory indexing filters
general-technique-02.md|1178|V-08: Heartbleed-style memory dump extraction via protocol heartbeat vulnerabilities
general-technique-02.md|1204|expected vulnerable output (redacted):
general-technique-02.md|1206|| ssl-heartbleed: VULNERABLE:
general-technique-02.md|1208||   The TLS/DTLS Heartbeat extension returns raw memory
general-technique-02.md|1210||   State: VULNERABLE
general-technique-02.md|1236|Table of contents
general-technique-02.md|1248|→ {"version":3, "sources":87, "has_content":true}
general-technique-02.md|1278|V-11: Leaked infrastructure secrets via exposed environmental files (.env, config.json)
general-technique-02.md|1335|V-13: Verbose log file leaks via unsecured log rotation directories (/log/, /logs/)
general-technique-02.md|1397|observed fields (values redacted):
general-technique-02.md|1399|Author        : <redacted — real name>
general-technique-02.md|1401|Company       : <internal-company-name>
general-technique-02.md|1403|Last Modified By : <redacted — employee name>
general-technique-02.md|1436|>> path-traversal-testing — SKILL.md
general-technique-02.md|1440|2. Engagement workflow
general-technique-02.md|1485|3. Variant selection table
general-technique-02.md|1505|4. Verification standard
general-technique-02.md|1526|Title
general-technique-02.md|1556|6. Reference pointers
general-technique-02.md|1568|0. Safe-first proof ladder
general-technique-02.md|1593|1. Encoding & normalization matrix
general-technique-02.md|1619|2. PHP wrapper templates — read-only proof patterns
general-technique-02.md|1627|READ-ONLY impact proof (production-appropriate)
general-technique-02.md|1631|round-trip check — must decode to exact canary bytes:
general-technique-02.md|1636|Read-only variants (still no execution)
general-technique-02.md|1643|Relative anchors when the app prefixes a base dir
general-technique-02.md|1649|Archive/pack wrappers (read-only; need an upload first → V-10/V-11)
general-technique-02.md|1654|LAB ONLY — execution escalation (never against production):
general-technique-02.md|1663|3. Filter-bypass ladder
general-technique-02.md|1715|4. Safe canary files per OS
general-technique-02.md|1732|--- ffuf: depth sweep (../ x N) against a path param ---
general-technique-02.md|1738|--- ffuf: wrapper fuzzing (rung 4) ---
general-technique-02.md|1744|traversal-encodings.txt  →  ../  ....//  %2e%2e%2f  %252e%252e%252f  ..%5c  ..;/
general-technique-02.md|1746|dot-depths.txt           →  ../  ../../  ../../../  …  ../../../../../../../../
general-technique-02.md|1748|php-wrappers.txt         →  php://filter/convert.base64-encode/resource=
general-technique-02.md|1750|data://text/plain,  zip://  phar://  file://
general-technique-02.md|1752|--- curl: wrapper proof with round-trip check ---
general-technique-02.md|1757|--- payload encoding without shell mangling ---
general-technique-02.md|1761|--- Burp workflow: Decoder for stacked decodes, Repeater match/extract for the
general-technique-02.md|1763|canary marker, Intruder with payload positions on the path param; compare
general-technique-02.md|1765|block-page signatures (V-12) between plain and encoded variants. ---
general-technique-02.md|1769|6. Path catalogue (probe candidates)
general-technique-03.md|4|7. Chain it with
general-technique-03.md|26|>> path-traversal-testing — variants-1.md (variant playbook)
general-technique-03.md|30|Table of contents
general-technique-03.md|41|V-05: String parsing termination via null byte character injection (%00)
general-technique-03.md|108|V-06: Directory matching evasion via double URL encoding string sequences (%252e%252e%252f)
general-technique-03.md|180|V-07: Relative path overwrite (RPO) context confusions for script masquerading
general-technique-03.md|259|>> path-traversal-testing — variants-2.md (variant playbook)
general-technique-03.md|263|Table of contents
general-technique-03.md|273|lab only (execution):
general-technique-03.md|305|craft (template):
general-technique-03.md|348|V-11: Local file access via symbolic link (symlink) file upload invalidation
general-technique-03.md|387|craft (template):
general-technique-03.md|424|2. Engagement workflow
general-technique-03.md|468|3. Variant selection table
general-technique-03.md|483|4. Verification standard
general-technique-03.md|503|Title
general-technique-03.md|529|6. Reference pointers
general-technique-03.md|541|0. Safe-first detection ladder
general-technique-03.md|563|interactsh — OOB DNS + HTTP with full request logging
general-technique-03.md|569|Burp: Collaborator tab → "Copy to file" then poll
general-technique-03.md|573|Simple HTTP callback logger (if you control a public box)
general-technique-03.md|577|DNS-only probe without HTTP:
general-technique-03.md|582|1. Command-injection differential templates
general-technique-03.md|611|3. Encoder / obfuscation tricks
general-technique-03.md|629|4. Upload-testing checklist
general-technique-03.md|651|OOB hit confirmation with attribution
general-technique-03.md|655|Callback listener during labs
general-technique-03.md|659|Upload fuzzing
general-technique-03.md|664|6. Chain it with
general-technique-03.md|683|Table of contents
general-technique-03.md|691|V-04: File upload and malicious web shell execution architectures
general-technique-03.md|760|Table of contents
general-technique-03.md|767|file=@<PLACEHOLDER_MALFORMED_FILE>    # crafted against CVE-<ID>, lab-verified
general-technique-03.md|795|>> sandbox-escape-testing — SKILL.md
general-technique-03.md|799|Sandbox Escape Testing — Deep Playbook
general-technique-03.md|812|2. Engagement workflow
general-technique-03.md|856|3. Variant selection table
general-technique-03.md|876|4. Verification standard
general-technique-03.md|901|Title
general-technique-03.md|934|6. Reference pointers
general-technique-03.md|947|Payloads & Templates — Sandbox Escape Testing
general-technique-03.md|956|0. Safe-first rule
general-technique-03.md|963|2. Benign probe library
general-technique-03.md|985|3. Proof depth ladder
general-technique-03.md|1017|4. Per-ecosystem version & advisory context
general-technique-03.md|1052|5. Encoder / obfuscation & evasion notes
general-technique-03.md|1072|container context
general-technique-03.md|1076|k8s capability
general-technique-03.md|1081|android statics
general-technique-03.md|1085|windows
general-technique-03.md|1090|eBPF surface
general-technique-03.md|1094|advisory habit (no payloads, just matching)
general-technique-03.md|1096|search: <product> <version> sandbox escape advisory   → GHSA / NVD / vendor notes
general-technique-03.md|1098|7. Chain it with
general-technique-03.md|1124|>> sandbox-escape-testing — variants-1.md (variant playbook)
general-technique-03.md|1128|Sandbox Escape Variants — Part 1 (V-01 … V-08)
general-technique-03.md|1136|Table of contents
general-technique-03.md|1147|V-01: Node.js context extraction via VM/VM2 sandbox evasion control breaks
general-technique-03.md|1186|lab harness, version-matched:
general-technique-03.md|1222|V-03: System restriction evasion via PHP disable_functions runtime bypass
general-technique-03.md|1293|read-only and read a marker file YOU placed there — never copy data out
general-technique-03.md|1323|V-05: Java SecurityManager execution bypass via reflection API interception
general-technique-03.md|1396|V-06: Chromium V8 sandbox evasion via type confusion optimization flaws
general-technique-03.md|1469|V-07: eBPF kernel sandbox escape via verifier logic flaw invalidation
general-technique-03.md|1505|lab-only (your version-matched kernel VM):
general-technique-03.md|1535|V-08: Ruby $SAFE sandbox circumvention via vulnerable core method clones
general-technique-03.md|1574|lab only: <PUBLIC_BYPASS_FROM_RESEARCH> → benign proof: read marker file / puts `id`
general-technique-03.md|1604|>> sandbox-escape-testing — variants-2.md (variant playbook)
general-technique-03.md|1608|Sandbox Escape Variants — Part 2 (V-09 … V-15)
general-technique-03.md|1615|Table of contents
general-technique-03.md|1625|V-09: Lua sandbox evasion via bytecode manipulation and arbitrary memory writes
general-technique-03.md|1694|V-10: Kubernetes pod escape via HostPath volume mount exploitations
general-technique-03.md|1729|benign capability proof
general-technique-03.md|1734|lab/staging: minimal read-only hostPath pod
general-technique-03.md|1741|benign in-pod proof: diff /host/etc/hostname vs ./hostname, or read a
general-technique-03.md|1743|marker file you placed on the node — nothing else
general-technique-03.md|1774|NT AUTHORITY\SYSTEM once, then stop — no persistence, no new accounts
general-technique-03.md|1806|V-12: Android app sandbox evasion via insecure content providers data leakage
general-technique-03.md|1847|V-13: WebAssembly linear memory escape via integer overflow sinks
general-technique-03.md|1915|V-14: Serverless FaaS environment persistence via writable /tmp code hijacking
general-technique-03.md|1956|lab only: drop a benign module printing a marker on import into the
general-technique-03.md|1958|first writable import path; observe the marker in a later invocation
general-technique-03.md|1960|V-15: Virtual machine hypervisor escape via vulnerable emulated hardware driver IOCTLs
general-technique-03.md|2000|lab only: <PUBLIC_POC_FOR_<HYPERVISOR>_<VER>> → benign proof: host marker
general-technique-03.md|2002|2. Engagement workflow
general-technique-04.md|4|3. Variant selection table
general-technique-04.md|29|4. Verification standard
general-technique-04.md|53|Steps to reproduce
general-technique-04.md|68|Impact
general-technique-04.md|75|Remediation
general-technique-04.md|82|References
general-technique-04.md|88|6. Reference pointers
general-technique-04.md|112|Table of contents
general-technique-04.md|125|1. Detection ladder: safe probe → differential → confirmation
general-technique-04.md|167|2. Payload templates per DBMS
general-technique-04.md|173|Oracle
general-technique-04.md|188|4. WAF-evasion encoding / obfuscation table
general-technique-04.md|224|5. Header-based vectors (User-Agent, Referer, Cookie)
general-technique-04.md|248|6. Blind OOB HTTP/SMB variants (no DNS egress)
general-technique-04.md|268|8. Chain it with (suite cross-references)
general-technique-04.md|278|Table of contents
general-technique-04.md|291|V-06: Multi-stage query execution via stacked command separators and batch execution
general-technique-04.md|345|Table of contents
general-technique-04.md|358|V-11: WAF impedance mismatch via inline comment obfuscation and whitespace bypass techniques
general-technique-04.md|425|V-15: Second-order blind inferential character-by-character verification extraction
general-technique-04.md|491|Cross-cutting notes
general-technique-04.md|496|Header-based vectors (User-Agent, Referer, Cookie)
general-technique-04.md|511|Encoding bypasses (URL / hex / base64 / unicode, double encoding)
general-technique-04.md|521|Case-sensitivity and alternative-logical-operator bypasses
general-technique-04.md|528|String-concatenation obfuscation
general-technique-04.md|538|Blind OOB HTTP/SMB variants (when DNS is blocked but HTTP/SMB isn't)
general-technique-04.md|553|B-1. Attack taxonomy → coverage checklist (Doupé et al. [10]; OOB per Clarke [3])
general-technique-04.md|583|B-2. The node method: inventory → dedup → per-node detection
general-technique-04.md|611|thesis appendix (full-crawl mode)
general-technique-04.md|617|per-node mode (their wrapper's construction):
general-technique-04.md|619|-u <url>  --cookie <cookies>  --data <body>   (when method==post)
general-technique-04.md|621|--forms                                          (when method==get)
general-technique-04.md|623|-p <parameters>                                  (explicit param list)
general-technique-04.md|627|B-4. Detection reliability → why the differential method exists
general-technique-04.md|645|B-5. Defense recognition → which payloads are even possible
general-technique-04.md|659|B-6. Coverage-first engagement loop (the thesis's headline result)
general-technique-04.md|677|2. Engagement workflow
general-technique-04.md|718|3. Variant selection table
general-technique-04.md|730|4. Verification standard
general-technique-04.md|750|Title
general-technique-04.md|780|6. Reference pointers
general-technique-04.md|792|0. Safe-first detection ladder
general-technique-04.md|817|DNS-only probe when HTTP egress is filtered:
general-technique-04.md|822|2. Filter-bypass & evasion tricks
general-technique-04.md|840|OOB hit confirmation with attribution
general-technique-04.md|844|DNS rebinding automation
general-technique-04.md|846|own authoritative NS with TTL-0 alternating A records, or a rebinding
general-technique-04.md|848|service; probe order: public→127.0.0.1, then public→169.254.169.254
general-technique-04.md|852|4. Chain it with
general-technique-04.md|874|Table of contents
general-technique-04.md|883|V-04: Network restriction bypass via automated TTL DNS rebinding
general-technique-04.md|923|then: 169.254.169.254 → identity proof only (V-03 rules apply)
general-technique-04.md|950|then:  src=http://127.0.0.1/ or http://169.254.169.254/... (identity only)
general-technique-04.md|952|exfil: src=http://<internal>/admin → marker appears in returned PDF
general-technique-04.md|980|2. Engagement workflow
general-technique-04.md|1027|3. Variant selection table
general-technique-04.md|1054|4. Verification standard
general-technique-04.md|1073|Summary
general-technique-04.md|1077|Steps to reproduce
general-technique-04.md|1084|Impact
general-technique-04.md|1090|Remediation
general-technique-04.md|1095|References
general-technique-04.md|1102|6. Reference pointers
general-technique-04.md|1110|1. Context-disambiguation flow: where is the input? → which payload family
general-technique-04.md|1165|2. Representative payload templates per context
general-technique-04.md|1167|2.1 HTML text context
general-technique-04.md|1179|2.2 Attribute context
general-technique-04.md|1190|2.3 JavaScript context (inside a `<script>` or JS file)
general-technique-04.md|1202|2.4 Event-handler context
general-technique-04.md|1214|2.5 URL / URI context (href, src, action, formaction, xlink:href)
general-technique-04.md|1226|2.6 VBScript context (legacy IE only)
general-technique-04.md|1233|2.7 Framework expression context (CSTI — V-08)
general-technique-04.md|1244|2.10 File/format vectors (V-14)
general-technique-04.md|1256|4. WAF-evasion encoding table
general-technique-04.md|1288|dalfox — parameter scanning from a URL list (pipe mode)
general-technique-04.md|1294|dalfox — one high-value URL with custom proof payload
general-technique-04.md|1300|Confirm execution in a real browser (headless chromium marker check)
general-technique-04.md|1305|Playwright (python) full login+sweep harness — two self-interference traps that
general-technique-04.md|1307|masquerade as app behavior (learned on Outlaw 2026-10-23):
general-technique-04.md|1309|party 403s the preflight, and Firebase login dies with
general-technique-04.md|1311|auth/network-request-failed that looks like a network/app bug but is yours.
general-technique-04.md|1319|2) Cached browser build may lag the playwright package (chromium-1234 vs 1248):
general-technique-04.md|1321|Always assert login actually succeeded (page.url + a known post-login heading)
general-technique-04.md|1323|the login page, so a failed login tests the login view, not your routes.
general-technique-04.md|1325|Collaborator-style OOB watch (blind, V-05) — interactsh example
general-technique-04.md|1335|6. Chain it with (the suite)
general-technique-04.md|1352|Table of contents
general-technique-04.md|1366|full proof payloads per context: payloads.md §2 — swap in the marker the ladder selected
general-technique-04.md|1382|Mutation = executable node present after round-trip, absent before.
general-technique-04.md|1398|V-08: Framework expression sandbox evasion (CSTI — AngularJS / Vue / Svelte)
general-technique-04.md|1431|Table of contents
general-technique-04.md|1445|V-11: Non-alphanumeric execution (JJEncode / AAEncode / JSFuck)
general-technique-04.md|1478|V-12: Double encoding obfuscation (WAF evasion: URL / HTML entity / Unicode)
general-technique-04.md|1512|V-14: Vector insertion via file formats (SVG / PDF / Markdown / XML)
general-technique-04.md|1547|V-16: Relative path overwrite (RPO) context confusion
general-technique-04.md|1584|2. Engagement workflow
general-technique-04.md|1626|3. Client-side fundamentals — signal → what it tells you → bugs it unlocks
general-technique-04.md|1647|4. Server-side fundamentals — signal → what it tells you → bugs it unlocks
general-technique-04.md|1665|5. Trust-boundary map — where "logic bypass" hypotheses come from
general-technique-05.md|4|6. Signal → technique skill routing table
general-technique-05.md|23|7. Verification standard
general-technique-05.md|45|Summary
general-technique-05.md|49|Steps to reproduce
general-technique-05.md|55|Impact
general-technique-05.md|60|Remediation
general-technique-05.md|65|References
general-technique-05.md|71|10. Reference pointers
general-technique-05.md|81|3. HERMES-PROVIDED BUG BOUNTY SKILLS
general-technique-05.md|83|Bug Bounty Methodology
general-technique-05.md|85|Always-On Rules (User Preferences)
general-technique-05.md|94|Workflow Steps
general-technique-05.md|98|Step 2: Extract Methodologies
general-technique-05.md|112|Step 3: Analyze for Patterns
general-technique-05.md|122|Step 4: Store and Apply
general-technique-05.md|128|Methodology Database Format
general-technique-05.md|133|Quick Reference — Methodology Templates
general-technique-05.md|135|Bug Chaining (Higher Payout)
general-technique-05.md|144|Source Priority (Use in Order)
general-technique-05.md|153|>> blackbox-writeups — core methods from 16 public black-box pentest/bug-bounty writeups (extraction 2026-10-30)
general-technique-05.md|162|Source index
general-technique-05.md|183|W-A. Engagement sequencing — the composite ladder
general-technique-05.md|213|W-D. Platform playbooks
general-technique-05.md|221|Plugin/theme versions via readme.txt (NOT assumed from paths)
general-technique-05.md|225|Brute force with multicall throttle-bypass: one XML-RPC request wraps N wp.getUsersBlogs calls
general-technique-05.md|262|W-F. Chain & client-side methods
general-technique-05.md|288|W-G. Verification & false-positive discipline
general-technique-05.md|307|W-I. Operational rules (stealth, rate, restraint)
general-technique-05.md|323|Always-On Rules (User Preferences)
general-technique-05.md|330|Step 2: Extract Methodologies
general-technique-05.md|343|Step 3: Analyze for Patterns
general-technique-05.md|353|Step 4: Store Knowledge
general-technique-05.md|364|Step 5: Apply to Next Hunt
general-technique-05.md|372|Methodology Templates
general-technique-05.md|374|Bug Chaining (Higher Payout)
general-technique-05.md|385|AUTO-IMPROVEMENT (DAILY)
general-technique-05.md|394|>> web-vulnerability-hunting — Full OWASP Top 10 hunting with control tests
general-technique-05.md|398|Web Vulnerability Hunting
general-technique-05.md|400|When to Use
general-technique-05.md|424|Procedures
general-technique-05.md|426|Phase 3 — Vulnerability Testing (MANDATORY CONTROL TESTS)
general-technique-05.md|436|==============================
general-technique-05.md|442|Summary output:
general-technique-05.md|454|Prerequisites
general-technique-05.md|458|Note: subzy installation failed (module fetch error). Use nuclei + manual crawling instead.
general-technique-05.md|460|nuclei binaries are available at:
general-technique-05.md|462|- /root/go/bin/nuclei (v3.11.1)
general-technique-05.md|464|- /root/nuclei-templates/ (template directory)
general-technique-05.md|468|Validation & False Positive Filtering (MANDATORY GATE)
general-technique-05.md|472|The Control Test Pattern
general-technique-05.md|490|Step-by-step Validation Process
general-technique-05.md|498|Common False Positives to Filter Out
general-technique-05.md|511|>> web-vulnerability-hunting — testing-payloads.md
general-technique-05.md|515|Testing Payloads Reference
general-technique-05.md|517|Decision rules:
general-technique-05.md|523|Detection payloads
general-technique-05.md|533|Boolean-based
general-technique-05.md|541|UNION-based
general-technique-05.md|549|WAF bypass (test each, compare with control)
general-technique-05.md|559|Mass assignment
general-technique-05.md|571|Internal targets
general-technique-05.md|582|Parameter names to test
general-technique-05.md|591|Rate: Multiple payloads tested = Multiple control runs
general-technique-05.md|599|>> blocked-page-recovery — 403/429/paywall/WAF recovery ladder
general-technique-05.md|603|Blocked-Page Recovery
general-technique-05.md|610|The ladder
general-technique-05.md|629|Provenance discipline (non-negotiable)
general-technique-05.md|642|Manual routes
general-technique-05.md|644|1. Wayback Machine (best provenance, try first)
general-technique-05.md|648|Then fetch archived_snapshots.closest.url
general-technique-05.md|664|2. archive.today (paywalls, deleted content)
general-technique-05.md|679|3. Jina Reader (requires JINA_API_KEY)
general-technique-05.md|692|4. API-first pivot
general-technique-05.md|703|Fake successes — routes that LIE
general-technique-05.md|721|Proxy relays: don't
general-technique-05.md|728|4. MASTER PROMPTS / CORE IDENTITY
general-technique-05.md|730|>> BUG_HUNTING_MASTER_PROMPT — Hermes master instructions for senior bug bounty research
general-technique-05.md|734|HERMES MASTER INSTRUCTIONS — SENIOR BUG BOUNTY RESEARCH AGENT
general-technique-05.md|736|1. ROLE AND MISSION
general-technique-05.md|750|2. PERSISTENT WORKSPACE
general-technique-05.md|809|3. LEARN FROM PUBLIC SECURITY RESEARCH
general-technique-05.md|841|Research rules
general-technique-05.md|855|Extract useful knowledge from every selected write-up
general-technique-05.md|874|4. VULNERABILITY TAXONOMY
general-technique-05.md|878|B. Cross-Site Request Forgery
general-technique-05.md|890|H. JavaScript and Frontend Source Analysis
general-technique-05.md|912|5. RESEARCH WORKFLOW
general-technique-05.md|916|Phase 2: Application understanding
general-technique-05.md|923|Phase 3: Hypothesis generation
general-technique-05.md|937|Phase 4: Validation
general-technique-05.md|947|Phase 6: Learning loop
general-technique-05.md|959|6. RESEARCH AND EXECUTION SAFETY
general-technique-05.md|981|7. WORKING STYLE
general-technique-05.md|999|8. INITIAL TASKS
general-technique-05.md|1018|>> bug-hunter-main-prompt — Core bug bounty hunter identity & workflow
general-technique-05.md|1022|🎯 Bug Bounty Hunter — Core Identity
general-technique-05.md|1027|Identity
general-technique-05.md|1034|🛠️ Language & Injection Expertise (Fully Qualified)
general-technique-05.md|1094|🌐 Networking Mastery (Network Core Protocols & the OSI Model)
general-technique-05.md|1126|⚠️ SKILL-FIRST HUNTING (ALWAYS ACTIVE)
general-technique-05.md|1136|Core Rules
general-technique-05.md|1149|Target Prioritization
general-technique-05.md|1158|Attack Methodology
general-technique-05.md|1169|Skills (Installed — ALWAYS LOAD THE MATCHING ONE BEFORE HUNTING)
general-technique-05.md|1192|Skill → Vuln Class Quick Map
general-technique-05.md|1211|Case sensitivity check
general-technique-05.md|1238|OpenAPI / Swagger specs
general-technique-05.md|1262|4. Diagnostic Scripting with curl
general-technique-05.md|1268|Silence output (-s), include response headers (-i), print HTTP status code (-w)
general-technique-05.md|1279|Agents (Installed — Delegate When Useful)
general-technique-05.md|1293|Common Attack Chains
general-technique-05.md|1306|Legal & Ethics
general-technique-05.md|1314|5. LESSONS — LEARNING LOG
general-technique-05.md|1316|2026-10-21 — system initialized
general-technique-05.md|1327|2026-10-21 — conversation
general-technique-05.md|1346|2026-10-21 — conversation
general-technique-05.md|1360|2026-10-21 — conversation
general-technique-05.md|1377|2026-10-21 — conversation
general-technique-05.md|1392|2026-10-23 — conversation
general-technique-05.md|1409|2026-10-24 — conversation
general-technique-05.md|1433|2026-10-24 — conversation (jardindacclimatation.fr first engagement)
general-technique-05.md|1460|2026-10-24 — conversation (casino-baden-baden.de first engagement, php2shell templates)
general-technique-05.md|1502|Stack (verified <date>)
general-technique-05.md|1509|Attack surface
general-technique-05.md|1513|Findings history
general-technique-05.md|1520|Ruled out (and why)
general-technique-05.md|1524|WAF / defense behavior
general-technique-05.md|1528|Rules
general-technique-05.md|1538|aida.de
general-technique-05.md|1548|Identity (verified 2026-10-23, via web research — no packets to target)
general-technique-05.md|1558|False match to avoid
general-technique-05.md|1563|Stack (verified 2026-10-23)
general-technique-05.md|1581|Findings history
general-technique-05.md|1587|Ruled out (and why)
general-technique-05.md|1599|WAF / defense behavior
general-technique-05.md|1609|Stack (verified 2026-10-23)
general-technique-05.md|1616|Ruled out (and why)
general-technique-05.md|1620|WAF / defense behavior
general-technique-05.md|1624|casino-baden-baden.de
general-technique-05.md|1634|Stack (verified 2026-10-24)
general-technique-05.md|1651|Findings history
general-technique-05.md|1657|Ruled out (and why)
general-technique-05.md|1673|WAF / defense behavior
general-technique-05.md|1681|Test mailbox / credentials
general-technique-05.md|1687|Stack (verified 2026-10-24)
general-technique-05.md|1708|Findings history
general-technique-05.md|1716|Ruled out (and why)
general-technique-05.md|1731|WAF / defense behavior
general-technique-05.md|1738|Test log (2026-10-24)
general-technique-05.md|1759|Open leads (ranked)
general-technique-05.md|1776|Raw responses (bgp.frontier.com; ipadmin identical — parity spot-checked)
general-technique-05.md|1808|Conditional-output probes (all 200 / 0 bytes)
general-technique-05.md|1813|/themes/ content search
general-technique-05.md|1818|ipadmin parity spot-check (identical status+size)
general-technique-05.md|1823|1. Reflection matrix (all form fields, POST, marker `ZMQ9<>'"&ZMQ9`)
general-technique-05.md|1835|2. Bypass probes (all failed)
general-technique-05.md|1852|3. Browser execution proof (Playwright + Chromium 1234, file:// auto-submitting form)
general-technique-05.md|1868|Finding 001 — Public .gitignore discloses internal application structure
general-technique-05.md|1874|Summary
general-technique-05.md|1881|Steps to reproduce
general-technique-05.md|1900|Impact
general-technique-05.md|1909|Remediation
general-technique-05.md|1915|References
general-technique-05.md|1921|Summary
general-technique-05.md|1929|Steps to reproduce
general-technique-05.md|1944|Impact
general-technique-05.md|1954|Remediation
general-technique-05.md|1960|References
general-technique-05.md|1966|getoutlaw.com
general-technique-05.md|1971|Stack (verified 2026-10-23)
general-technique-05.md|1980|Hosts
general-technique-05.md|1989|RPC functions (via fv.getoutlaw.com/api/*)
general-technique-05.md|2004|Other routes
general-technique-05.md|2010|Findings history
general-technique-05.md|2017|Ruled out (and why)
general-technique-05.md|2031|WAF / defense behavior
general-technique-05.md|2039|Summary
general-technique-06.md|4|Data returned without auth (from own demo deal)
general-technique-06.md|12|Impact
general-technique-06.md|16|Reproduction
general-technique-06.md|26|Recommended fix
general-technique-06.md|30|F-02 — Pre-auth account-existence + auth-method oracle via `POST /api/checkAccount`
general-technique-06.md|36|Summary
general-technique-06.md|45|Reproduction
general-technique-06.md|53|Notes / adjacent observations (not separate findings)
general-technique-06.md|58|Recommended fix
general-technique-06.md|62|Stack (verified 2026-10-25)
general-technique-06.md|87|Findings history
general-technique-06.md|94|Ruled out (and why)
general-technique-06.md|113|WAF / defense behavior
general-technique-06.md|120|F-01 — Unauthenticated OpenSearch/Elasticsearch credential disclosed via /api/server-configurations
general-technique-06.md|128|Summary
general-technique-06.md|139|Steps to reproduce
general-technique-06.md|146|Impact
general-technique-06.md|161|Remediation
general-technique-06.md|173|Live validation (2026-10-25) — credential is REAL but locked down
general-technique-06.md|200|F-02 — Full client source code exposed via served sourcemaps (main.js.map, 62 MB)
general-technique-06.md|208|Summary
general-technique-06.md|219|Steps to reproduce
general-technique-06.md|227|Impact
general-technique-06.md|235|Remediation
general-technique-06.md|242|Production OpenSearch credential exposed via unauthenticated `/api/server-configurations`
general-technique-06.md|265|Steps to reproduce
general-technique-06.md|296|Impact
general-technique-06.md|316|Remediation
general-technique-06.md|330|References
general-technique-06.md|337|jardindacclimatation.fr
general-technique-06.md|347|Stack (verified 2026-10-24)
general-technique-06.md|374|Pages (27 routes — from `_buildManifest.js`, fetched with validated `_abck`)
general-technique-06.md|387|Findings history
general-technique-06.md|394|New routes found after the initial inventory (from `_app` chunk module `66679`)
general-technique-06.md|400|Ruled out (and why)
general-technique-06.md|433|WAF / defense behavior (Akamai Bot Manager) — **read before testing**
general-technique-06.md|456|jardindacclimatation.fr — technique routing matrix (Phase 3)
general-technique-06.md|467|Sandbox escape (`sandbox-escape-testing`)
general-technique-06.md|474|Summary
general-technique-06.md|486|Steps to reproduce
general-technique-06.md|533|Impact
general-technique-06.md|544|Remediation
general-technique-06.md|554|Open (to confirm before submitting)
general-technique-06.md|560|quizlet.com
general-technique-06.md|565|Stack (verified 2026-10-21)
general-technique-06.md|578|Auth model
general-technique-06.md|587|Findings history
general-technique-06.md|595|Ruled out (and why)
general-technique-06.md|611|Open leads (not ruled out — blocked by the challenge)
general-technique-06.md|621|WAF / defense behavior (characterized 2026-10-21)
general-technique-06.md|631|Missing security headers on origin-served responses
general-technique-06.md|640|Summary
general-technique-06.md|653|Steps to reproduce
general-technique-06.md|684|Impact
general-technique-06.md|694|False-positive check (what I ruled out)
general-technique-06.md|705|Caveat / limitation
general-technique-06.md|713|Remediation
general-technique-06.md|720|References
general-technique-06.md|725|Internal Kubernetes service topology disclosed via `x-envoy-decorator-operation` (+ unauthenticated event ingestion)
general-technique-06.md|734|Summary
general-technique-06.md|756|Steps to reproduce
general-technique-06.md|774|Impact
general-technique-06.md|787|False-positive check
general-technique-06.md|794|Remediation
general-technique-06.md|800|References
general-technique-06.md|805|Summary
general-technique-06.md|826|Steps to reproduce
general-technique-06.md|840|Impact / how to use it
general-technique-06.md|851|False-positive check
general-technique-06.md|856|Remediation
general-technique-06.md|861|References
general-technique-06.md|865|reready.co
general-technique-06.md|872|Stack (verified 2026-10-25, sandbox)
general-technique-06.md|906|Findings history
general-technique-06.md|912|Authentication testing (2026-10-25, sandbox only — no successful login yet)
general-technique-06.md|924|Ruled out (and why)
general-technique-06.md|947|WAF / defense behavior
general-technique-06.md|951|1. Baseline headers (sandbox, GET /)
general-technique-06.md|967|9. Asset / JS findings (operational, not security)
general-technique-06.md|983|10. Rate limits & auth-flow gating
general-technique-06.md|999|11. Host ports (single pass, 2 s connect timeout, sandbox IP only)
general-technique-06.md|1007|Verizon (Inspectiv)
general-technique-06.md|1012|Rules of Engagement (mandatory on EVERY request)
general-technique-06.md|1023|Ruled out (and why)
general-technique-06.md|1027|WAF / defense behavior
general-technique-06.md|1031|vinted.com
general-technique-06.md|1037|Stack (verified 2026-10-21)
general-technique-06.md|1052|Hosts
general-technique-06.md|1064|Findings history
general-technique-06.md|1072|Ruled out (and why)
general-technique-06.md|1115|WAF / defense behavior
general-technique-06.md|1120|F-01 — Missing browser security headers + weak HSTS on www.vinted.com
general-technique-06.md|1132|Summary
general-technique-06.md|1137|Impact
general-technique-06.md|1149|Steps to reproduce
general-technique-06.md|1154|Remediation
general-technique-06.md|1166|Why this matters (one line)
general-technique-06.md|1171|Summary
general-technique-06.md|1177|Escalation conditions (re-rate to High if any one appears)
general-technique-06.md|1186|Steps to reproduce
general-technique-06.md|1194|Remediation
general-technique-06.md|1203|Related
general-technique-06.md|1208|>> next-actions.md
general-technique-06.md|1212|Next Actions
general-technique-06.md|1214|BLOCKED ON USER INPUT (Phase A gate)
general-technique-06.md|1222|Not started
general-technique-06.md|1226|Host
general-technique-06.md|1233|Pre-existing (system)
general-technique-06.md|1243|Deferred until active phases (not yet installed)
general-technique-06.md|1247|Not permitted without asking
general-technique-06.md|1251|8. CREDENTIALS — Reference Only (No Secrets In This File)
general-technique-06.md|1278|9. VALIDATION SCRIPT
general-technique-06.md|1280|>> validate_vulnerability.py — Control-test based validation
general-technique-06.md|1311|EXCLUDED FROM THIS FILE (by design)
general-technique-06.md|1327|17. Knowledge intake — appended methodology (research pass 2026-11-07)
general-technique-06.md|1340|17.17 Server-side URL fetch: scheme-allowlist bypass (file://) -> arbitrary local repository read (GitLab RepositoryPipeline #1685822)
general-technique-06.md|1354|Knowledge intake — reader pass 2026-11-07 (batch 3): new GENERAL methods, appended to Section 17
general-technique-06.md|1410|17.32 Length-field / signed-subtraction bounds-check bypass -> OOB read used as a remote oracle, and allocation-size steering -> heap overfl
general-technique-06.md|1425|17.37 Project-export/import mass-assignment installs a server-side integration flagged as an instance TEMPLATE → applies to EVERY subsequent
general-technique-06.md|1440|17.43 Machine credential carrying an identity CLAIM (SSH CA certificate `extension:login@github.com=<user>`) is not re-verified by a SIBLING
general-technique-06.md|1453|Knowledge intake — reader pass 2026-11-07 (batch 9): new GENERAL methods, appended to Section 17
general-technique-06.md|1457|17.49 Untrusted code sandbox: overwriting a BUILTIN EXCEPTION CLASS makes the engine's own error path recurse → VM-stack overflow → GC on a 
general-technique-06.md|1471|17.55 Untrusted interpreter sandbox: DELETING a core method the engine's own C helper calls (`NilClass.remove_method :to_s` → `nil.to_s` → `
general-technique-06.md|1485|17.57 Untrusted interpreter sandbox: an ALLOCATED-BUT-NEVER-INITIALIZED object reaching `initialize_copy` → C copy routine writes through a 
general-technique-07.md|4|17.65 Length-prefixed decoder: bounds checks hoisted OUT of the `do/while` that advances both cursors; continuation path guarded only by a D
general-technique-07.md|20|17.67 A message-staged GLOBAL POINTER as the fake-object stage: unchecked `slot` into a static `.data` array → vtable call at offset 8 → RIP
general-technique-07.md|32|17.75 Unauthenticated observability backend (`/config`) + exposed Go pprof (`/debug/pprof/cmdline?debug=1`, `heap`) → secrets in config/argv
general-technique-07.md|46|17.85 Draft/preview render path re-uses raw link values while scheme validation and sanitisation run only on the PUBLISH path — a stored `ja
general-technique-07.md|59|17.89 Server-owned approval/lifecycle STATE fields are writable through the object PATCH — self-approve and skip the payment/review gate (Re
general-technique-07.md|72|17.102 A server-validated one-time SECRET is brute-forceable through a DIFFERENTIAL RESPONSE-LENGTH oracle plus a user-set prefix that shrin
general-technique-07.md|86|17.103 A protocol FEE/BOND DERIVED from a measured value can be inflated arbitrarily by an attacker who controls BOTH the measurement and it
general-technique-07.md|101|17.107 Client-side MEMORY-CORRUPTION primitives reachable from untrusted script in a plugin/runtime — UAF via an explicitly exposed `release
general-technique-07.md|115|17.109 Hostname validation/resolution DIFFERENTIAL — a fixed 256-byte truncation makes the string the validator checks differ from the strin
general-technique-07.md|129|17.113 Client-side desync (CSD) — an over-declared `Content-Length` on an INCOMPLETE POST desyncs the VICTIM's browser socket, and the error
general-technique-07.md|143|17.114 TRAILER-SECTION line-skipping — a trailer line WITHOUT a colon makes the parser swallow the next request's headers, so that request's
general-technique-07.md|158|17.128 A desync that needs NO malformed bytes at all — PAUSE-BASED desync, where a server-level responder times out a partial request and le
general-technique-07.md|166|17.130 A PDF generator that EXECUTES the injected JavaScript — the breakout is `</script><script>` and the fetched secret comes back inside 
general-technique-07.md|176|17.134 When the injected `--output` path is written by TWO SEQUENTIAL invocations, the LAST writer decides — so the primitive splits into "w
general-technique-07.md|186|17.138 A policy VALIDATOR that normalizes only SOME of the input TYPES its sink accepts is bypassed by the same value in another accepted ty
general-technique-07.md|194|17.146 An access-control gate enforced on the PUBLIC render path but not on a SIBLING preview path — an unauthenticated preview-link generat
general-technique-07.md|204|17.147 A postMessage listener's escape loop MUTATES the object it was handed and skips NON-OWN properties — deliver the sink value through a
general-technique-07.md|213|17.149 External protocol handler bypasses the app's proxy/anonymity confinement → real-IP deanonymization + local-network reach (Tor Browser
general-technique-07.md|228|17.150 A markup renderer's OPTIONAL scripting extension is enabled by a successful `require` — and the escape is the renderer's OWN home-wri
general-technique-07.md|243|17.161 A SELF-SERVICE account mutation in ONE client silently CORRUPTS an UNRELATED security/privacy setting — the account's protected statu
general-technique-07.md|257|17.167 An identifier that was PUBLIC when the object was public remains a BEARER CREDENTIAL after the object goes private — the API still re
general-technique-07.md|271|17.174 Over HTTP/2, the ORDER in which two concurrent multiplexed responses arrive (not elapsed time) is a jitter-proof boolean oracle usabl
general-technique-07.md|285|17.184 The CLIENT trusts a user-replaceable BACKEND (the RPC node the wallet talks to) and injects the node's response as JavaScript — code 
general-technique-07.md|298|17.186 A validator that shares a realm with the code it constrains is bypassable by monkey-patching the built-ins the CHECK itself calls — o
general-technique-07.md|308|17.191 Combined client SAFETY/STATE options act on the WRONG OBJECT — (a) cleanup-on-error deletes the file the overwrite guard protected, (
general-technique-08.md|4|17.201 A SPLIT CREDENTIAL whose missing half parses to `nil` matches every record whose credential COLUMN IS NULL — `<victim_id>-` authentic
general-technique-09.md|4|17.201 A SPLIT CREDENTIAL whose missing half parses to `nil` matches every record whose credential COLUMN IS NULL — `<victim_id>-` authentic
general-technique-10.md|4|17.201 A SPLIT CREDENTIAL whose missing half parses to `nil` matches every record whose credential COLUMN IS NULL — `<victim_id>-` authentic
general-technique-10.md|65|17.277 A MITIGATION's own bound check is off by one against the SCALED index it guards — the single admitted boundary value indexes one past
general-technique-10.md|80|17.278 An object property the runtime RESOLVES THROUGH AN ACCESSOR YOU CONTROL is resolved INSIDE the runtime's own operation — call the obj
general-technique-10.md|96|17.286 AN ORIGIN-UNCHECKED `postMessage` INTO A THIRD-PARTY SDK'S COMMAND QUEUE IS ARBITRARY SDK-API EXECUTION — and any SDK option string-c
general-technique-10.md|106|17.303 A GROUP-LEVEL DEFAULT setting is interpolated unescaped into a generated terminal-command sample on a project landing page — store th
general-technique-10.md|123|17.304 An ENTITLEMENT JSON boolean computed client-side is rewriteable with a proxy Match-and-Replace — the test is whether a paid ACTION no
general-technique-10.md|140|17.309 A workspace settings POST whose ACTION is in the PATH and whose VALUE is in the JSON body has no server-side role check — replay it u
general-technique-10.md|158|17.311 A driver's OWN `driverrequest` response hands back the `tender.id` + `order_id`, and `getTenderStatus` keyed only by those ids return
general-technique-10.md|194|§17 additions — reader pass 2026-11-11 batch 162 (1 entry appended, §17.472)
general-technique-10.md|196|§17 additions — reader pass 2026-11-11 batch 163 (2 entries appended, §17.473–§17.474)
general-technique-10.md|198|============================================================================
general-technique-10.md|202|============================================================================
general-technique-10.md|213|V-19: Guard-layer bypass by path shape, judged by the error-code LAYER
general-technique-10.md|235|V-20: `/public/` unauthenticated API surface + two-step identifier chaining
general-technique-11.md|4|V-21: Unauthenticated server-computed quote manipulation (aberrant quantity / sign)
general-technique-11.md|20|V-24: Data-store proxy read — URL segment as index + encoded-metachar edge bypass
general-technique-11.md|34|V-28: Component finding proved from public source (version → tag source → changelog-after → live input)
general-technique-11.md|46|Routing rows added (append to the technique routing table)
general-technique-11.md|61|Binding habits this batch adds
general-technique-11.md|73|============================================================================
general-technique-11.md|83|V-29: Server-rendered template platform — the create-time content filter is not the render path
general-technique-11.md|112|V-30: Extract-before-validate — archive entry names write payloads into compiled/served paths
general-technique-11.md|131|V-32: File-store containment is per parameter AND per verb
general-technique-11.md|152|V-33: Blind-injection oracles on filter and sort parameters (size + type-error)
general-technique-11.md|172|Routing rows added (append to the technique routing table)
general-technique-11.md|185|Binding habits this batch adds
general-technique-11.md|202|§17 additions — knowledge-intake 2026-11-17 (7 entries: §17.797–§17.803)
general-technique-11.md|206|§17.800 — AN ACL IMPLEMENTED AS A QUERY FILTER DOES NOT COVER THE BY-ID READ PATH: RESTRICTED CONTAINERS, PUBLIC CHILD STATUS, AND A SINGLE-
general-technique-11.md|214|§17.803 — A PER-RESPONSE SECRET THAT SURVIVES A COOKIELESS REQUEST IS A CACHE LEAK: MISSING `Vary: Cookie` ON AN AUTHENTICATED RESPONSE, AND
general-technique-11.md|222|Bug Bounty Hunting Skills
general-technique-11.md|256|0. AGENT DECISION TREE — route by observation (READ THIS FIRST)
general-technique-11.md|323|1.5 Filter-logic bypass by shape, not by payload list
general-technique-11.md|347|1.6 Third-party / infrastructure inheritance (dangling CNAME)
general-technique-11.md|365|2.5 Known-vulnerable component with a URL parameter
general-technique-11.md|384|2.6 Probing localhost services from inside a browser context
general-technique-11.md|402|3.1 Swap the identifier in a path parameter, then enumerate
general-technique-11.md|425|4. Cross-cutting methodology extracted from the set
general-technique-11.md|449|5. Reusable test checklist
general-technique-11.md|467|6. Source index
general-technique-11.md|507|8.1 Non-recursive filter removal — `....//`
general-technique-11.md|528|8.2 Validate-then-decode ordering + hashed upload names
general-technique-11.md|555|8.5 When the app appends an extension: null byte, truncation, wrappers
general-technique-11.md|581|9. Source code, `.git`, `.env` and GitHub exposure
general-technique-11.md|583|9.1 Exposed `.git/` → full source → credentials → admin
general-technique-11.md|613|9.2 `.env` reachable only through the origin/CNAME
general-technique-11.md|635|9.4 Backup archives and `.bak` files
general-technique-11.md|661|9.5 GitHub dorking with the API (not the web UI)
general-technique-11.md|695|9.6 CI/CD as a credential store — anonymous Jenkins
general-technique-11.md|716|10.1 A framework upgrade changed serialization semantics — HackerOne `.json`
general-technique-11.md|743|11. Authentication and header-based bypass
general-technique-11.md|745|11.6 Miscellaneous bypass patterns worth a permanent slot
general-technique-11.md|761|12.2 Cookie theft is not the impact — replaying it is
general-technique-11.md|780|12.5 Zero-click variants (what "zero-click" actually means here)
general-technique-11.md|794|13.1 Template value → shell string (Airflow example DAGs)
general-technique-11.md|827|13.2 Chat-command arguments → `$()` substitution
general-technique-11.md|850|13.4 Import pipeline: branch name → command execution (GitHub)
general-technique-11.md|869|13.8 Command-injection detection ladder
general-technique-11.md|884|14. Dorking tradecraft (how to actually run the templates)
general-technique-11.md|901|Source / git / env
general-technique-11.md|906|Auth / header
general-technique-11.md|911|15. Master checklist (Part II)
general-technique-11.md|960|16. Source index — Part II
general-technique-11.md|1019|VALID BUT NOT APPENDED (nothing new, nothing invented)
general-technique-11.md|1030|Batch 145 — 6 sources, read ONE BY ONE in the assigned order (2026-11-11)
general-technique-11.md|1034|RESULT: 2 entries appended (2 new §17 slots); 6 sources read, 0 fabricated
general-technique-11.md|1072|VALID BUT NOT APPENDED (nothing new, nothing invented)
general-technique-11.md|1138|VALID BUT NOT APPENDED (nothing new, nothing invented)
general-technique-11.md|1148|PASS 2026-11-11 (batch 144) — NOTHING NEW, 0 APPENDED
general-technique-12.md|4|PASS 2026-11-11 (batch 147) — NOTHING NEW, 0 APPENDED
general-technique-13.md|4|PASS 2026-11-11 (batch 147) — NOTHING NEW, 0 APPENDED (continued 2/3)
general-technique-14.md|4|PASS 2026-11-11 (batch 147) — NOTHING NEW, 0 APPENDED (continued 3/3)
general-technique-14.md|68|Batch 159 — 6 sources, read ONE BY ONE in the assigned order (2026-11-11)
general-technique-14.md|74|RESULT: 2 entries appended (2 new §17 slots); 6 sources read, 0 fabricated
general-technique-14.md|129|Batch 160 — 6 sources, read ONE BY ONE in the assigned order (2026-11-11)
general-technique-14.md|135|RESULT: 1 entry appended (1 new §17 slot); 6 sources read, 0 fabricated
general-technique-14.md|178|Batch 161 — 6 sources, read ONE BY ONE in the assigned order (2026-11-11)
general-technique-14.md|184|RESULT: 2 entries appended (2 new §17 slots); 6 sources read, 0 fabricated
general-technique-14.md|239|Batch 162 — 6 sources, read ONE BY ONE in the assigned order (2026-11-11)
general-technique-15.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented
general-technique-16.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 2/31)
general-technique-17.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 3/31)
general-technique-18.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 4/31)
general-technique-19.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 5/31)
general-technique-20.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 6/31)
general-technique-21.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 7/31)
general-technique-22.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 8/31)
general-technique-23.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 9/31)
general-technique-24.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 10/31)
general-technique-25.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 11/31)
general-technique-26.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 12/31)
general-technique-27.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 13/31)
general-technique-28.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 14/31)
general-technique-29.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 15/31)
general-technique-30.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 16/31)
general-technique-31.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 17/31)
general-technique-32.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 18/31)
general-technique-33.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 19/31)
general-technique-34.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 20/31)
general-technique-35.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 21/31)
general-technique-36.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 22/31)
general-technique-37.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 23/31)
general-technique-38.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 24/31)
general-technique-39.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 25/31)
general-technique-40.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 26/31)
general-technique-41.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 27/31)
general-technique-42.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 28/31)
general-technique-43.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 29/31)
general-technique-44.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 30/31)
general-technique-45.md|4|RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented (continued 31/31)
general-technique-45.md|256|§17.789 — TEMPLATE POISONING BY AN ACCEPTED WRITE PRIMITIVE INTO THE COMPILED-TEMPLATE DIRECTORY: THE FILTER GUARDS THE CREATE PATH, THE COM
general-technique-45.md|277|CARRIER-DELTA ENTRIES (no §17 slot; recorded so no later pass re-opens them)
general-technique-45.md|291|KNOWLEDGE-INTAKE BATCH 2026-11-17 (research agent pass) — 7 entries appended
general-technique-45.md|299|§INTAKE-2026-11-17/4 — VISIBILITY ENFORCED ONLY BY A QUERY FILTER IS NOT VISIBILITY: THE CONTAINER IS RESTRICTED, THE CHILD ROWS STAY `publi
general-technique-45.md|319|PASS NOTE — 2026-11-17 knowledge-intake (research agent)
