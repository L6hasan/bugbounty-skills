# SKILL INDEX — line-offset router for the bug-bounty skill ledgers
#
# WHY: the two ledgers are 4.3 MB + 8.0 MB (47,429 lines). No LLM can read them whole.
# USE:  grep -n -i '<class/keyword>' /root/hackbot-architecture/knowledge/SKILL-INDEX.md
#       read_file(<ledger path>, offset=<line-5>, limit=200)
# COLS: file | line | depth | heading

===== FILE A: /root/Bugbountyskills.md =====
A|1|1|BugbountySkills — Consolidated Bug Bounty Hunter Playbook
A|15|2|  0. SEVERITY DOCTRINE — HIGH/CRITICAL ONLY (Kr Hasan standing order, 2026-11-07)
A|73|2|  TABLE OF CONTENTS
A|88|2|  0.5 AGENT DECISION TREE — route by observation (READ THIS FIRST)
A|154|1|1. META & ORCHESTRATOR
A|157|2|  >> SKILL_SPEC — How technique skills are structured
A|161|1|Skill Build Spec (shared by all 10 bug-bounty skills)
A|174|2|  1. SKILL.md frontmatter (exact shape)
A|192|2|  2. SKILL.md body (target 150-300 lines)
A|220|2|  3. Variant reference files (deep playbook)
A|227|2|  V-01: <Variant name>
A|253|2|  4. Tone
A|258|2|  5. The suite (sibling skills, cross-reference by directory name)
A|274|2|  >> bug-hunter — Engagement orchestrator (scope → recon → hunt → validate → report)
A|278|1|Bug Hunter — engagement orchestrator
A|289|2|  0. Scope gate — always first, no exceptions
A|309|2|  1. Domain intake — new domain mentioned = new profile skill
A|328|2|  2. Hunt workflow
A|390|2|  3. Technique routing table
A|408|2|  4. Knowledge intake — every report AND every conversation makes the system smarter
A|413|3|    4a. Report intake (triage response, disclosed report, own finding)
A|432|3|    4b. Conversation intake — every conversation gets mined into its category
A|459|2|  5. Report writing standard
A|467|2|  6. Test mailboxes
A|482|2|  7. File map
A|501|1|2. TECHNIQUE SKILLS
A|511|2|  >> bac-idor-testing — SKILL.md
A|515|1|BAC / IDOR Testing Playbook
A|522|2|  1. Scope & authorization guardrail
A|534|2|  2. Engagement workflow
A|566|2|  3. Variant selection table
A|586|2|  4. Verification standard
A|612|2|  5. Report template
A|615|2|  Title: <Resource/action> accessible across accounts via <missing check> (IDOR/BOLA/<variant>)
A|621|3|    Summary
A|624|3|    Steps to reproduce
A|635|3|    Impact
A|639|3|    Evidence (redacted)
A|642|3|    Remediation
A|646|3|    References
A|652|2|  6. Reference pointers
A|665|2|  >> bac-idor-testing — payloads.md (request templates, tool commands, evasion)
A|669|1|Payloads, request templates, and cross-cutting material
A|677|2|  Table of contents
A|691|2|  Two-account testing setup (the backbone)
A|696|3|    Why one account proves nothing
A|713|3|    Procedure
A|748|2|  Curl replay templates
A|753|1|--- T1: own-object baseline (control A) ---------------------------------
A|756|1|--- T2: cross-principal probe (the actual test) ------------------------
A|759|1|--- T3: no-credentials control (V-02: missing auth vs missing check) ----
A|762|1|--- T4: write probe — use only on B's tester-created object -------------
A|765|1|then verify in B's session:  curl -sS -i -b jar_b.txt '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_B>'
A|767|1|--- T5: mass-assignment probe (V-04) ------------------------------------
A|772|1|--- T6: HPP duplicate-parameter probe (V-07) ----------------------------
A|776|1|--- T7: role/context header flip (V-11) ---------------------------------
A|779|1|--- T8: version differential (V-10) -------------------------------------
A|783|1|--- T9: nested-path segment matrix (V-13) -------------------------------
A|789|1|--- T10: tampered-token replay (V-14, token from the JWT checklist) ------
A|799|2|  ID-format pattern catalog
A|816|2|  JWT testing checklist (test steps, not exploit code)
A|868|2|  GraphQL introspection & authorization probes
A|873|1|--- G1: full introspection (schema inventory) ---------------------------
A|877|1|--- G2: field/arg detail for one type (find $id: ID! entry points) ------
A|881|1|--- G3: partial introspection fallback (full introspection disabled) ----
A|884|1|Also probe: { __type(name:\"Query\") { fields { name } } }  and error-based field suggestions.
A|886|1|--- G4: own-node baseline ----------------------------------------------
A|890|1|--- G5: cross-principal probe (swap the decoded inner id) ---------------
A|891|1|Global IDs are usually base64("<Type>:<id>") — encode locally:
A|892|1|printf '%s' '<TYPE>:<OTHER_USER_NUMERIC_ID>' | base64
A|896|1|--- G6: no-token control ------------------------------------------------
A|900|1|--- G7: field-level authz pass (sensitive fields on your OWN node) ------
A|904|1|--- G8: error-shaping oracle (does "not found" vs "not authorized" leak existence?)
A|917|2|  Enumeration throttle: rate-limit politely, never hammer
A|941|2|  Encoder / obfuscation tricks
A|961|2|  Tool invocations (templates)
A|964|1|Polite sequential-ID sweep (single endpoint, tiny wordlist, 1 req/s)
A|968|1|Diff-aware probe: own vs foreign object side by side
A|972|1|Header/context flip fuzzing (V-11) — small curated list, not a wordlist dump
A|978|1|JWT checklist driver (test-step execution, per section above)
A|982|1|Mass-assignment field enumeration (V-04): small candidate list, one field at a time
A|986|1|SQLi hand-off when V-14 step 5 shows a query-shaped kid lookup:
A|995|2|  Chain it with
A|1023|2|  >> bac-idor-testing — variants-1.md (variant playbook)
A|1027|1|Variants 1-8 — IDOR core, function-level, and ID-shape flaws
A|1035|2|  Table of contents
A|1048|2|  V-01: Direct parameter manipulation via authenticated IDOR security evasion
A|1075|1|Control (A's own object) vs. probe (B's object)
A|1102|2|  V-02: Unauthenticated endpoint identification via IDOR resource enumeration
A|1128|1|Strip every credential; use a clean cookie jar so nothing leaks in
A|1130|1|Control: a known-protected sibling
A|1157|2|  V-03: Scripted request validation and automation via custom cURL IDOR frameworks
A|1214|2|  V-04: Internal variable overwriting via mass assignment object property injection
A|1272|2|  V-05: Horizontal privilege escalation via missing object-level access control (BOLA/BMAO)
A|1329|2|  V-06: Vertical privilege escalation via function-level access control evasion (RBAC/ABAC bypass)
A|1385|2|  V-07: Server-side array confusion via HTTP parameter pollution (HPP) IDOR mutations
A|1441|2|  V-08: Cryptographic entity guessing via cryptographically weak UUID/GUID generation routines
A|1470|1|Candidate derived from your own ID(s); fetch as A
A|1498|2|  >> bac-idor-testing — variants-2.md (variant playbook)
A|1502|1|Variants 9-15 — second-order, version/context, GraphQL, JWT, and tenancy flaws
A|1508|2|  Table of contents
A|1520|2|  V-09: Second-order IDOR via dynamic session parameter substitution sinks
A|1547|1|1) Store B's object id in a trusted field (write-time check may pass)
A|1550|1|2) Trigger the sink
A|1577|2|  V-10: API endpoint version bypassing for unprotected legacy resource fetching
A|1634|2|  V-11: Contextual role-based state flipping through client-side request mutation
A|1691|2|  V-12: GraphQL query object variable manipulation for unauthorized node access
A|1748|2|  V-13: Nested API resource path traversal for internal object-level access bypass
A|1805|2|  V-14: JWT algorithm laundering and signature nullification privilege escalation
A|1834|1|Replay the tampered test token produced by the checklist against a gated resource
A|1862|2|  V-15: Cross-tenant data exposure via insecure multi-tenancy boundary isolation flaws
A|1889|1|A's session asking for B's tenant scope
A|1893|1|List-surface sweep (server-side filter check)
A|1918|2|  >> business-logic-testing — SKILL.md
A|1922|1|Business Logic Testing Playbook
A|1929|2|  1. Scope & authorization guardrail
A|1945|2|  2. Engagement workflow
A|1979|2|  3. Variant selection table
A|1999|2|  4. Verification standard
A|2025|2|  5. Report template
A|2028|2|  Title: <Flaw> allows <consequence> via <mechanism> (V-<NN> <short variant name>)
A|2034|3|    Summary
A|2037|3|    Steps to reproduce
A|2047|3|    Impact
A|2051|3|    Evidence (redacted)
A|2054|3|    Remediation
A|2058|3|    References
A|2063|2|  6. Reference pointers
A|2079|2|  >> business-logic-testing — payloads.md (request templates, tool commands, evasion)
A|2083|1|Payloads, request templates, and cross-cutting material
A|2094|2|  Table of contents
A|2107|2|  Race-condition testing procedure (parallel bursts)
A|2181|2|  Telling a real race from jitter
A|2202|2|  Workflow mapping procedure (map first, then skip/swap)
A|2245|2|  Negative / edge value test matrix
A|2274|2|  OAuth 2.0 testing checklist (test steps)
A|2318|2|  Host header & password reset test templates
A|2324|1|R1: classic Host override on the reset trigger
A|2330|1|R2: forwarding headers (trusts proxy-derived host)
A|2335|1|R3: header variants in one ladder (run one at a time, record each)
A|2336|1|-H 'Forwarded: host=<ATTACKER_HOST>;proto=https'
A|2337|1|-H 'X-Forwarded-Server: <ATTACKER_HOST>'   -H 'X-Host: <ATTACKER_HOST>'
A|2338|1|-H 'X-Original-Host: <ATTACKER_HOST>'      -H 'X-HTTP-Host-Override: <ATTACKER_HOST>'
A|2340|1|R4: duplicate / polluted Host (second value wins in some parsers)
A|2345|1|R5: absolute-form request line (seen by forwarding layers first)
A|2349|1|R6: token visible in the API response? (direct leak, no header needed)
A|2353|1|R7: consumed-token replay (single-use check)
A|2375|2|  Encoder / obfuscation tricks (paths & WAF)
A|2399|2|  Chain it with
A|2432|2|  >> business-logic-testing — variants-1.md (variant playbook)
A|2436|1|Variants 1-8 — transaction integrity, workflow, races, discovery, auth, reset, OTP, complexity
A|2447|2|  Table of contents
A|2460|2|  V-01: Transaction integrity violation via price, quantity, and currency parameter tampering
A|2493|1|Control: untouched request (expected: persisted total == catalog price)
A|2497|1|Probe: single tampered money field
A|2501|1|Read back the server-persisted amount, cache-busted
A|2528|2|  V-02: State machine defiance via workflow circumvention and multi-step transaction skipping
A|2559|1|State machine as mapped: S1 -> S2 -> S3. Object currently in S1:
A|2589|2|  V-03: Concurrent state processing flaws via distributed race conditions (HTTP/2 request overlap)
A|2621|1|Turbo Intruder — synchronized burst over one HTTP/2 connection
A|2656|2|  V-04: Administrative interface discovery via URL obfuscation and Unicode path bruteforcing
A|2692|1|Unicode variant on one promising candidate
A|2694|1|Edge rewrite header variant
A|2724|2|  V-05: Authentication flow manipulation via insecure token or session state modification
A|2756|1|Control: untouched pre-auth session against the gate (expect 401/302)
A|2759|1|Probe: flip the client-held auth marker, same fresh session
A|2790|2|  V-06: Insecure password reset logic via Host header injection or token leakage
A|2830|1|then read the inbox: does the reset URL point at <ATTACKER_HOST>?
A|2859|2|  V-07: OTP/2FA verification bypass via response manipulation or parameter nullification
A|2894|1|Baseline: wrong code must fail (control)
A|2897|1|Nullification candidates
A|2902|1|Independent signal: does the gated step now proceed?
A|2932|2|  V-08: Algorithmic complexity attacks as a DoS-style logic flaw (cgroup/resource exhaustion)
A|3001|2|  >> business-logic-testing — variants-2.md (variant playbook)
A|3005|1|Variants 9-15 — concurrency abuse, negative values, session races, form context, OAuth, client gates, regis...
A|3013|2|  Table of contents
A|3025|2|  V-09: Coupon and promo code replay via multi-threaded locking failures
A|3059|1|After the burst: authoritative check — distinct orders carrying the discount
A|3061|1|Sequential control for the report (must show exactly 1)
A|3092|2|  V-10: Negative value input processing flaws leading to account credit generation
A|3125|1|Baseline
A|3127|1|Control: legitimate positive purchase (expect debit)
A|3130|1|Probe: single negative quantity (minimal demonstrable unit)
A|3133|1|Independent signal: ledger/balance re-read
A|3164|2|  V-11: Session flashing and race vulnerabilities via concurrent HTTP request overlaps
A|3197|1|Burst: N reads racing one logout on the same session (slots from payloads.md)
A|3202|1|Settle, then test the original session id from a SEPARATE connection
A|3235|2|  V-12: ID de-synchronization via multi-stage form context substitution
A|3269|1|Steps 1-2 ran against OBJECT_ID_A (step token minted for A), final commit:
A|3273|1|Diff both objects, cache-busted
A|3303|2|  V-13: Account takeover via OAuth 2.0 dynamic client registration and state spoofing
A|3340|1|State omission on the callback (expect: rejected)
A|3342|1|redirect_uri variant at the authorize step
A|3375|2|  V-14: Business flow evasion through client-side logic interception and response flipping
A|3412|1|1) In proxy: flip the failed-step response to the success shape, capture the
A|3413|1|follow-up the client then sends, e.g.:
A|3414|1|2) Replay that follow-up directly — no edited client involved
A|3418|1|3) Independent readback of the finished flow
A|3449|2|  V-15: Insecure ID direct assignment during self-registration elevating roles
A|3484|1|Control: plain signup (default role) — register in a fresh browser/jar
A|3487|1|Probe: one privileged field added
A|3490|1|Independent signal: fresh login, then a role-gated action
A|3522|2|  >> csrf-testing — SKILL.md
A|3526|1|CSRF Testing
A|3533|2|  Scope & authorization guardrail
A|3543|2|  Engagement workflow
A|3585|2|  Variant selection table
A|3608|2|  Verification standard
A|3630|2|  Report template
A|3633|1|CSRF: <concise endpoint-specific title, e.g. "Change email accepts cross-site POST without token">
A|3666|2|  Reference pointers
A|3675|2|  >> csrf-testing — payloads.md (request templates, tool commands, evasion)
A|3679|1|CSRF payloads, request templates and evasion notes
A|3685|2|  Table of contents
A|3696|2|  Minimal HTML form PoC
A|3731|2|  fetch / XHR PoC (no-cors + credentials)
A|3774|2|  GET trigger templates (img / script / navigation)
A|3797|2|  Tunnelling note: text/plain and application/json
A|3825|2|  curl replay template (own session confirmation)
A|3832|1|1) baseline with the legit token, from tester's own session
A|3841|1|2) variant matrix — change ONE thing per run, log status + body + side effect
A|3842|1|a) token omitted          → drop the csrf_token= field
A|3843|1|b) token blank            → --data 'csrf_token=<PLACEHOLDER_EMPTY>'
A|3844|1|c) token foreign          → --data 'csrf_token=<ATTACKER_SESSION_TOKEN>'
A|3845|1|d) Origin null            → -H 'Origin: null'
A|3846|1|e) Origin regex-buster    → -H 'Origin: https://<TARGET_HOST>.evil.tld'
A|3847|1|f) no Origin/Referer      → delete both header lines
A|3848|1|g) method mutation        → -X GET with params in the query string
A|3849|1|h) CT reshaping           → -H 'Content-Type: text/plain' / -F 'a=b' (multipart)
A|3851|1|3) raw response headers (Set-Cookie, CORS, CRLF splitting — V-10/V-14)
A|3857|1|4) WebSocket handshake probe (V-16, own session)
A|3864|1|5) clean-room cookie jar for V-06/V-07 (fresh session, no lazy-init surprises)
A|3874|2|  WAF evasion: encodings and obfuscations
A|3899|2|  Tool invocation templates
A|3902|1|V-11/V-14 header-rule mapping loop (one variable per request)
A|3909|1|V-14 preflight vs actual, side by side
A|3915|1|V-09 token harvest for entropy analysis (own accounts only)
A|3919|1|V-15 policy fetch
A|3930|2|  Chain it with
A|3961|2|  >> csrf-testing — variants-1.md (variant playbook)
A|3965|1|CSRF Variants 1-8 — core request-shape and token-lifecycle failures
A|3971|2|  Table of contents
A|3984|2|  V-01: POST-based CSRF with hidden form parameter tampering
A|4020|2|  V-02: GET-based CSRF via cross-origin embedded resource traversal
A|4054|2|  V-03: SameSite cookie restrictions and the Lax top-level navigation window
A|4089|2|  V-04: SameSite Strict subdomain takeover cross-context execution
A|4122|2|  V-05: Method-dependent token validation and POST to GET mutation
A|4156|2|  V-06: Token omission, deletion and stripping
A|4190|2|  V-07: Blank or null CSRF token acceptance
A|4224|2|  V-08: CSRF token not tied to the user session
A|4266|2|  >> csrf-testing — variants-2.md (variant playbook)
A|4270|1|CSRF Variants 9-18 — transport, header, parser and chain failures
A|4276|2|  Table of contents
A|4291|2|  V-09: Static or predictable CSRF tokens
A|4325|2|  V-10: Double submit cookie bypass with CRLF response splitting
A|4359|2|  V-11: Referer and Origin validation bypass via stripping and loose regex
A|4379|1|browser: <iframe sandbox="allow-forms allow-scripts" srcdoc="…auto-submit form…"> → Origin: null
A|4394|2|  V-12: Content-Type manipulation and multipart reshaping
A|4431|2|  V-13: JSON and form tunnelling with parser flexibility
A|4466|2|  V-14: SOP and CORS misconfiguration bypass with preflight mismatch
A|4502|2|  V-15: Flash based CSRF and crossdomain.xml policy hijacking
A|4521|1|legacy client leg, only if in scope: <embed src="https://<ATTACKER_HOST>/exploit.swf">
A|4537|2|  V-16: Cross Site WebSocket Hijacking
A|4573|2|  V-17: Pre auth CSRF token injection and authentication fixation
A|4591|1|fixate <T_FIX> (+SID) onto victim, victim logs in, then:
A|4608|2|  V-18: XSS assisted CSRF and DOM based token theft
A|4643|2|  >> info-disclosure-testing — SKILL.md
A|4647|1|info-disclosure-testing: Leaks & Disclosure Deep Playbook
A|4649|2|  1. Scope & authorization guardrail
A|4676|2|  2. Engagement workflow
A|4729|2|  3. Variant selection table
A|4750|2|  4. Verification standard
A|4778|2|  5. Report template
A|4781|1|<Class> exposed via <mechanism> at <location>
A|4789|2|  Steps to reproduce
A|4799|2|  Impact
A|4804|2|  Evidence
A|4808|2|  Remediation
A|4813|2|  References
A|4818|2|  6. Reference pointers
A|4837|2|  >> info-disclosure-testing — payloads.md (request templates, tool commands, evasion)
A|4841|1|info-disclosure-testing — Payloads, Templates & Tool Invocations (references/payloads.md)
A|4848|2|  Table of contents
A|4860|2|  1. Recon path catalog (wordlists with placeholders)
A|4907|2|  2. .git exposure validation: real HEAD/objects vs soft-404 and honeypots
A|4950|2|  3. curl capture templates: headers, banners, sourcemaps
A|4974|1|1) does the bundle advertise one?
A|4976|1|2) fetch and validate structure
A|4996|2|  4. S3/GCP bucket enumeration & verify (read-only procedure)
A|5005|1|from in-scope HTML/JS/pages you already fetched — no external scanning needed
A|5018|1|regional: https://<BUCKET>.s3.<REGION>.amazonaws.com/?list-type=2&max-keys=5
A|5029|1|200 + Content-Type + ETag → world-readable object even with listing denied
A|5030|1|403 AccessDenied → read blocked; 404 → key wrong
A|5040|1|website-style: https://<BUCKET>.storage.googleapis.com/
A|5060|2|  5. Tool invocation templates & path-probe evasion notes
A|5106|2|  6. Redaction checklist for discovered secrets
A|5144|2|  7. Chain it with (suite cross-references)
A|5180|2|  >> info-disclosure-testing — variants-1.md (variant playbook)
A|5184|1|info-disclosure-testing — Variants 1-8 (references/variants-1.md)
A|5192|2|  Table of contents
A|5205|2|  V-01: Exposed version control repositories and backup management leakage
A|5271|2|  V-02: Server banner response modification and micro-service infrastructure footprinting
A|5372|2|  V-03: Detailed debugging exception extraction via stack trace disclosures
A|5429|2|  V-04: Internal network schema mapping via server-leaked IP address points
A|5506|2|  V-05: Arbitrary resource harvesting via unprotected directory indexing filters
A|5559|2|  V-06: Hardcoded sensitive cryptographic keys, client secrets and token extraction
A|5657|2|  V-07: GraphQL introspection query data schema leakage exploitation
A|5717|2|  V-08: Heartbleed-style memory dump extraction via protocol heartbeat vulnerabilities
A|5742|1|expected vulnerable output (redacted):
A|5743|1|| ssl-heartbleed: VULNERABLE:
A|5744|1||   The TLS/DTLS Heartbeat extension returns raw memory
A|5745|1||   State: VULNERABLE
A|5771|2|  >> info-disclosure-testing — variants-2.md (variant playbook)
A|5775|1|info-disclosure-testing — Variants 9-15 (references/variants-2.md)
A|5784|2|  Table of contents
A|5796|2|  V-09: Client-side source map leakage for de-obfuscating frontend application logic
A|5823|1|→ {"version":3, "sources":87, "has_content":true}
A|5852|2|  V-10: Cloud storage bucket data leaks via open/public AWS S3 / GCP bucket permissions
A|5878|1|READ-ONLY enumeration — no PUT/POST/DELETE ever
A|5911|2|  V-11: Leaked infrastructure secrets via exposed environmental files (.env, config.json)
A|5968|2|  V-12: API documentation leaks via public Swagger / Postman collection endpoints
A|6028|2|  V-13: Verbose log file leaks via unsecured log rotation directories (/log/, /logs/)
A|6090|2|  V-14: Internal domain/hostname leakage via intranet SMTP/email header metadata
A|6153|2|  V-15: Metadata information extraction from publicly uploaded documents (EXIF data leakage)
A|6182|1|observed fields (values redacted):
A|6183|1|GPS Latitude  : <coordinates present — reported as rounded/omitted>
A|6184|1|Author        : <redacted — real name>
A|6185|1|Company       : <internal-company-name>
A|6186|1|Last Modified By : <redacted — employee name>
A|6219|2|  >> path-traversal-testing — SKILL.md
A|6223|1|Path Traversal / LFI & RFI Testing — Deep Playbook
A|6233|2|  1. Scope & authorization guardrail
A|6266|2|  2. Engagement workflow
A|6311|2|  3. Variant selection table
A|6331|2|  4. Verification standard
A|6352|2|  5. Report template
A|6355|3|    Title
A|6384|2|  6. Reference pointers
A|6397|2|  >> path-traversal-testing — payloads.md (request templates, tool commands, evasion)
A|6401|1|Payloads & Templates — Path Traversal / LFI / RFI
A|6407|2|  0. Safe-first proof ladder
A|6432|2|  1. Encoding & normalization matrix
A|6458|2|  2. PHP wrapper templates — read-only proof patterns
A|6465|1|READ-ONLY impact proof (production-appropriate)
A|6467|1|round-trip check — must decode to exact canary bytes:
A|6471|1|Read-only variants (still no execution)
A|6477|1|Wrapper-support probe (returns YOUR text — proves wrapper parsing, not file read)
A|6480|1|Relative anchors when the app prefixes a base dir
A|6485|1|Archive/pack wrappers (read-only; need an upload first → V-10/V-11)
A|6489|1|LAB ONLY — execution escalation (never against production):
A|6497|2|  3. Filter-bypass ladder
A|6549|2|  4. Safe canary files per OS
A|6566|2|  5. Tool invocation templates
A|6569|1|--- ffuf: value fuzzing with a traversal wordlist (in-scope target only) ---
A|6575|1|--- ffuf: depth sweep (../ x N) against a path param ---
A|6580|1|--- ffuf: URL-path traversal against static locations ---
A|6585|1|--- ffuf: wrapper fuzzing (rung 4) ---
A|6590|1|Seed wordlists inline (expand per engagement; keep pacing modest):
A|6591|1|traversal-encodings.txt  →  ../  ....//  %2e%2e%2f  %252e%252e%252f  ..%5c  ..;/
A|6592|1|dot-depths.txt           →  ../  ../../  ../../../  …  ../../../../../../../../
A|6593|1|php-wrappers.txt         →  php://filter/convert.base64-encode/resource=
A|6594|1|data://text/plain,  zip://  phar://  file://
A|6596|1|--- curl: canary read, evidence = first bytes only ---
A|6599|1|--- curl: wrapper proof with round-trip check ---
A|6603|1|--- payload encoding without shell mangling ---
A|6606|1|--- log/session poisoning sequence (read-back proof) ---
A|6611|1|--- Burp workflow: Decoder for stacked decodes, Repeater match/extract for the
A|6612|1|canary marker, Intruder with payload positions on the path param; compare
A|6613|1|block-page signatures (V-12) between plain and encoded variants. ---
A|6616|2|  6. Path catalogue (probe candidates)
A|6634|2|  7. Chain it with
A|6657|2|  >> path-traversal-testing — variants-1.md (variant playbook)
A|6661|1|Path Traversal / LFI & RFI Variants — Part 1 (V-01 … V-08)
A|6668|2|  Table of contents
A|6679|2|  V-01: Internal file resource inclusion via local file inclusion (LFI) filter breaks
A|6753|2|  V-02: External script execution traversal via remote file inclusion (RFI) wrapper pipelines
A|6826|2|  V-03: Directory separation invalidation via path traversal strings (../)
A|6889|2|  V-04: Core system profile access bypass (/etc/passwd or Windows/win.ini isolation mapping)
A|6965|2|  V-05: String parsing termination via null byte character injection (%00)
A|7032|2|  V-06: Directory matching evasion via double URL encoding string sequences (%252e%252e%252f)
A|7104|2|  V-07: Relative path overwrite (RPO) context confusions for script masquerading
A|7183|2|  V-08: LFI to RCE mutation via log file stalking (Apache/Nginx/SSH log injection)
A|7267|2|  >> path-traversal-testing — variants-2.md (variant playbook)
A|7271|1|Path Traversal / LFI & RFI Variants — Part 2 (V-09 … V-15)
A|7277|2|  Table of contents
A|7287|2|  V-09: LFI to RCE via PHP wrappers execution flow (php://filter, php://input, data://)
A|7335|1|lab only (execution):
A|7366|2|  V-10: Path traversal via nested archive unpacking flaws (Zip Slip)
A|7410|1|craft (template):
A|7452|2|  V-11: Local file access via symbolic link (symlink) file upload invalidation
A|7490|1|craft (template):
A|7526|2|  V-12: WAF bypass path traversal via Unicode/UTF-8 alternate slash character mappings
A|7602|2|  V-13: LFI resource hijacking via PHP session file poisoning (/var/lib/php/sessions/)
A|7681|2|  V-14: Path traversal via Nginx alias misconfiguration string splitting
A|7764|2|  V-15: Arbitrary root configuration file read via static asset mapping misconfigurations
A|7849|2|  >> rce-testing — SKILL.md
A|7853|1|RCE Testing — Deep Playbook
A|7862|2|  1. Scope & authorization guardrail
A|7890|2|  2. Engagement workflow
A|7934|2|  3. Variant selection table
A|7949|2|  4. Verification standard
A|7969|2|  5. Report template
A|7972|3|    Title
A|7997|2|  6. Reference pointers
A|8010|2|  >> rce-testing — payloads.md (request templates, tool commands, evasion)
A|8014|1|Payloads & Templates — RCE
A|8021|2|  0. Safe-first detection ladder
A|8042|1|interactsh — OOB DNS + HTTP with full request logging
A|8045|1|Burp: Collaborator tab → "Copy to file" then poll
A|8046|1|Simple HTTP callback logger (if you control a public box)
A|8048|1|DNS-only probe without HTTP:
A|8052|2|  1. Command-injection differential templates
A|8081|2|  2. SSTI fingerprinting ladder
A|8125|2|  3. Encoder / obfuscation tricks
A|8143|2|  4. Upload-testing checklist
A|8165|2|  5. Tool invocation templates
A|8168|1|Param discovery for command/code sinks
A|8171|1|OOB hit confirmation with attribution
A|8174|1|Callback listener during labs
A|8177|1|Deserialization gadget probing — LAB/authorized targets only, never prod
A|8181|1|Upload fuzzing
A|8185|2|  6. Chain it with
A|8205|2|  >> rce-testing — variants-1.md (variant playbook)
A|8209|1|RCE Variants — Part 1 (V-01 … V-05)
A|8215|2|  Table of contents
A|8223|2|  V-01: OS command string injection via unsanitized input concatenation
A|8286|2|  V-02: Language-specific code argument injection via dynamic code evaluators
A|8352|2|  V-03: Arbitrary object instantiation via insecure deserialization protocols
A|8420|2|  V-04: File upload and malicious web shell execution architectures
A|8489|2|  V-05: SSTI RCE via template engine fingerprinting
A|8559|2|  >> rce-testing — variants-2.md (variant playbook)
A|8563|1|RCE Variants — Part 2 (V-06 … V-09)
A|8568|2|  Table of contents
A|8575|2|  V-06: RCE via memory corruption and garbage collection vulnerability triggers
A|8617|1|file=@<PLACEHOLDER_MALFORMED_FILE>    # crafted against CVE-<ID>, lab-verified
A|8644|2|  V-07: Command injection via argument injection in Unix wrapper utilities
A|8713|2|  V-08: RCE via insecure configuration loading and variable override
A|8782|2|  V-09: Blind RCE via system environment variable injections and shell expansion
A|8861|2|  >> sandbox-escape-testing — SKILL.md
A|8865|1|Sandbox Escape Testing — Deep Playbook
A|8878|2|  1. Scope & authorization guardrail
A|8919|2|  2. Engagement workflow
A|8963|2|  3. Variant selection table
A|8983|2|  4. Verification standard
A|9008|2|  5. Report template
A|9011|3|    Title
A|9043|2|  6. Reference pointers
A|9057|2|  >> sandbox-escape-testing — payloads.md (request templates, tool commands, evasion)
A|9061|1|Payloads & Templates — Sandbox Escape Testing
A|9070|2|  0. Safe-first rule
A|9077|2|  1. Environment fingerprinting ladder
A|9120|2|  2. Benign probe library
A|9142|2|  3. Proof depth ladder
A|9174|2|  4. Per-ecosystem version & advisory context
A|9209|2|  5. Encoder / obfuscation & evasion notes
A|9229|2|  6. Tool invocation templates
A|9232|1|benign fingerprints (one-liners)
A|9236|1|container context
A|9238|1|k8s capability
A|9241|1|android statics
A|9243|1|windows
A|9246|1|eBPF surface
A|9248|1|advisory habit (no payloads, just matching)
A|9249|1|search: <product> <version> sandbox escape advisory   → GHSA / NVD / vendor notes
A|9250|1|then:   <advisory> affected range + fix version       → cite in report
A|9253|2|  7. Chain it with
A|9280|2|  >> sandbox-escape-testing — variants-1.md (variant playbook)
A|9284|1|Sandbox Escape Variants — Part 1 (V-01 … V-08)
A|9292|2|  Table of contents
A|9303|2|  V-01: Node.js context extraction via VM/VM2 sandbox evasion control breaks
A|9341|1|lab harness, version-matched:
A|9376|2|  V-02: Python scope re-alignment via exec/eval context isolation breaks
A|9448|2|  V-03: System restriction evasion via PHP disable_functions runtime bypass
A|9519|2|  V-04: Container privilege escalation via Docker daemon and kernel namespace breakouts
A|9558|1|lab-only benign escape proof (privileged misconfig): mount host disk
A|9559|1|read-only and read a marker file YOU placed there — never copy data out
A|9588|2|  V-05: Java SecurityManager execution bypass via reflection API interception
A|9661|2|  V-06: Chromium V8 sandbox evasion via type confusion optimization flaws
A|9734|2|  V-07: eBPF kernel sandbox escape via verifier logic flaw invalidation
A|9769|1|benign recon (target):
A|9772|1|lab-only (your version-matched kernel VM):
A|9801|2|  V-08: Ruby $SAFE sandbox circumvention via vulnerable core method clones
A|9839|1|lab only: <PUBLIC_BYPASS_FROM_RESEARCH> → benign proof: read marker file / puts `id`
A|9869|2|  >> sandbox-escape-testing — variants-2.md (variant playbook)
A|9873|1|Sandbox Escape Variants — Part 2 (V-09 … V-15)
A|9880|2|  Table of contents
A|9890|2|  V-09: Lua sandbox evasion via bytecode manipulation and arbitrary memory writes
A|9959|2|  V-10: Kubernetes pod escape via HostPath volume mount exploitations
A|9993|1|benign capability proof
A|9997|1|lab/staging: minimal read-only hostPath pod
A|10002|1|benign in-pod proof: diff /host/etc/hostname vs ./hostname, or read a
A|10003|1|marker file you placed on the node — nothing else
A|10033|2|  V-11: Windows sandbox escape via RPC interface exploitation and token impersonation
A|10073|1|lab only: <PUBLIC_POC_OR_TOOL_FOR_BUILD> → benign proof: `whoami` shows
A|10074|1|NT AUTHORITY\SYSTEM once, then stop — no persistence, no new accounts
A|10105|2|  V-12: Android app sandbox evasion via insecure content providers data leakage
A|10145|1|evidence = counts + column names; data rows stay redacted
A|10174|2|  V-13: WebAssembly linear memory escape via integer overflow sinks
A|10242|2|  V-14: Serverless FaaS environment persistence via writable /tmp code hijacking
A|10282|1|lab only: drop a benign module printing a marker on import into the
A|10283|1|first writable import path; observe the marker in a later invocation
A|10284|1|guardrail: delete the marker/module and disclose in the same session
A|10313|2|  V-15: Virtual machine hypervisor escape via vulnerable emulated hardware driver IOCTLs
A|10352|1|guest-side benign fingerprint
A|10356|1|lab only: <PUBLIC_POC_FOR_<HYPERVISOR>_<VER>> → benign proof: host marker
A|10357|1|file read displayed inside the guest — then stop
A|10389|2|  >> sqli-testing — SKILL.md
A|10393|1|sqli-testing: SQLi & NoSQLi Deep Playbook
A|10395|2|  1. Scope & authorization guardrail
A|10420|2|  2. Engagement workflow
A|10474|2|  3. Variant selection table
A|10499|2|  4. Verification standard
A|10523|2|  5. Report template
A|10526|1|<DBMS> SQL injection in <parameter> leaks <data class> via <variant>
A|10534|2|  Steps to reproduce
A|10548|2|  Impact
A|10554|2|  Evidence
A|10558|2|  Remediation
A|10564|2|  References
A|10569|2|  6. Reference pointers
A|10594|2|  >> sqli-testing — payloads.md (request templates, tool commands, evasion)
A|10598|1|sqli-testing — Payloads, Templates & Tool Invocations (references/payloads.md)
A|10605|2|  Table of contents
A|10618|2|  1. Detection ladder: safe probe → differential → confirmation
A|10660|2|  2. Payload templates per DBMS
A|10666|3|    MySQL / MariaDB
A|10681|3|    PostgreSQL
A|10695|3|    MSSQL
A|10709|3|    Oracle
A|10723|3|    SQLite
A|10733|3|    NoSQL (MongoDB-shaped) — see V-13
A|10739|2|  3. Tool invocation templates
A|10799|2|  4. WAF-evasion encoding / obfuscation table
A|10835|2|  5. Header-based vectors (User-Agent, Referer, Cookie)
A|10859|2|  6. Blind OOB HTTP/SMB variants (no DNS egress)
A|10879|2|  7. Time-based confirmation: differential timing, not fixed sleeps
A|10905|2|  8. Chain it with (suite cross-references)
A|10916|2|  >> sqli-testing — variants-1.md (variant playbook)
A|10920|1|sqli-testing — Variants 1-8 (references/variants-1.md)
A|10928|2|  Table of contents
A|10941|2|  V-01: Database schema extraction via error-based SQL injection engines
A|10992|2|  V-02: Cross-table arbitrary data retrieval via union-based SQL injection compilation
A|11045|2|  V-03: Inferential data exfiltration via boolean-based blind SQL inferences
A|11101|2|  V-04: Asynchronous database delay evaluation via time-based blind SQLi conditions
A|11156|2|  V-05: Out-of-band data exfiltration via DNS logging protocols (OOB SQLi / DNSlog frameworks)
A|11211|2|  V-06: Multi-stage query execution via stacked command separators and batch execution
A|11265|2|  V-07: Downstream persistence exploitation via second-order SQL injection pipelines
A|11325|2|  V-08: Transport-layer bypasses via JSON, XML and GraphQL embedded parametric SQLi
A|11384|2|  >> sqli-testing — variants-2.md (variant playbook)
A|11388|1|sqli-testing — Variants 9-15 (references/variants-2.md)
A|11397|2|  Table of contents
A|11410|2|  V-09: Structural query manipulation via ORDER BY, GROUP BY and LIMIT/OFFSET exploits
A|11468|2|  V-10: Database-specific command execution (MySQL INTO OUTFILE/LOAD_FILE, MSSQL xp_cmdshell, PostgreSQL COPY...
A|11529|2|  V-11: WAF impedance mismatch via inline comment obfuscation and whitespace bypass techniques
A|11596|2|  V-12: Automated time-delay evasion via polyglot SQLi execution blocks
A|11658|2|  V-13: NoSQL injection (NoSQLi) document extraction via operator substitution ($gt, $ne, $regex) including H...
A|11724|2|  V-14: Truncation-based SQL injection via database field length limits
A|11784|2|  V-15: Second-order blind inferential character-by-character verification extraction
A|11850|2|  Cross-cutting notes
A|11855|3|    Header-based vectors (User-Agent, Referer, Cookie)
A|11869|3|    Encoding bypasses (URL / hex / base64 / unicode, double encoding)
A|11878|3|    Case-sensitivity and alternative-logical-operator bypasses
A|11884|3|    String-concatenation obfuscation
A|11893|3|    Blind OOB HTTP/SMB variants (when DNS is blocked but HTTP/SMB isn't)
A|11908|2|  >> sqli-testing — core black-box scanning methods (book extract: Degerman & Dubrefjord, Chalmers 2021)
A|11919|1|Core black-box SQLi methods (book extract)
A|11921|2|  B-1. Attack taxonomy → coverage checklist (Doupé et al. [10]; OOB per Clarke [3])
A|11951|2|  B-2. The node method: inventory → dedup → per-node detection
A|11978|1|thesis appendix (full-crawl mode)
A|11983|1|per-node mode (their wrapper's construction):
A|11984|1|-u <url>  --cookie <cookies>  --data <body>   (when method==post)
A|11985|1|--forms                                          (when method==get)
A|11986|1|-p <parameters>                                  (explicit param list)
A|11989|2|  B-3. Scanner failure modes (proven by server-side coverage data) → what you must do by hand
A|12027|2|  B-4. Detection reliability → why the differential method exists
A|12045|2|  B-5. Defense recognition → which payloads are even possible
A|12059|2|  B-6. Coverage-first engagement loop (the thesis's headline result)
A|12078|2|  >> ssrf-testing — SKILL.md
A|12082|1|SSRF Testing — Deep Playbook
A|12093|2|  1. Scope & authorization guardrail
A|12123|2|  2. Engagement workflow
A|12164|2|  3. Variant selection table
A|12176|2|  4. Verification standard
A|12196|2|  5. Report template
A|12199|3|    Title
A|12228|2|  6. Reference pointers
A|12241|2|  >> ssrf-testing — payloads.md (request templates, tool commands, evasion)
A|12245|1|Payloads & Templates — SSRF
A|12252|2|  0. Safe-first detection ladder
A|12276|1|interactsh — OOB DNS + HTTP with full request logging
A|12279|1|Burp: Collaborator tab → "Copy to file" then poll
A|12280|1|HTTP callback logger with header/UA logging (fingerprint the fetcher)
A|12282|1|DNS-only probe when HTTP egress is filtered:
A|12286|2|  1. SSRF probing ladder
A|12351|2|  2. Filter-bypass & evasion tricks
A|12369|2|  3. Tool invocation templates
A|12372|1|Param discovery for URL-fetch sinks
A|12375|1|OOB hit confirmation with attribution
A|12378|1|Callback listener during labs (logs source IP + UA = fetcher fingerprint)
A|12381|1|DNS rebinding automation
A|12382|1|own authoritative NS with TTL-0 alternating A records, or a rebinding
A|12383|1|service; probe order: public→127.0.0.1, then public→169.254.169.254
A|12386|1|Timing-differential port mapping (in-scope only, slow pacing, 2 samples + control)
A|12390|2|  4. Chain it with
A|12413|2|  >> ssrf-testing — variants-1.md (variant playbook)
A|12417|1|SSRF Variants (V-01 … V-06)
A|12424|2|  Table of contents
A|12433|2|  V-01: Internal network mapping via basic SSRF scanning mechanisms
A|12502|2|  V-02: Infrastructure verification via asynchronous blind SSRF pipelines
A|12566|2|  V-03: Cloud infrastructure takeover via metadata API instance extraction
A|12611|1|IMDSv2 through a verb/header-controlling SSRF (V-05):
A|12644|2|  V-04: Network restriction bypass via automated TTL DNS rebinding
A|12683|1|then: 169.254.169.254 → identity proof only (V-03 rules apply)
A|12708|2|  V-05: SSRF via protocol smuggling (Gopher/DICT/FTP tunnelling)
A|12780|2|  V-06: SSRF via PDF/image rendering engines and cross-origin objects
A|12821|1|then:  src=http://127.0.0.1/ or http://169.254.169.254/... (identity only)
A|12822|1|exfil: src=http://<internal>/admin → marker appears in returned PDF
A|12850|2|  >> xss-testing — SKILL.md
A|12854|1|XSS Testing Playbook
A|12861|2|  1. Scope & authorization guardrail
A|12886|2|  2. Engagement workflow
A|12933|2|  3. Variant selection table
A|12960|2|  4. Verification standard
A|12979|2|  5. Report template
A|12982|1|<Title: e.g. Reflected XSS in /search via q parameter (HTML text context)>
A|12988|2|  Summary
A|12991|2|  Steps to reproduce
A|12997|2|  Impact
A|13002|2|  Evidence (redacted)
A|13008|2|  Remediation
A|13012|2|  References
A|13018|2|  6. Reference pointers
A|13027|2|  >> xss-testing — payloads.md (request templates, tool commands, evasion)
A|13031|1|Payloads, probes, encodings & tools — xss-testing
A|13053|2|  1. Context-disambiguation flow: where is the input? → which payload family
A|13108|2|  2. Representative payload templates per context
A|13110|3|    2.1 HTML text context
A|13122|3|    2.2 Attribute context
A|13133|3|    2.3 JavaScript context (inside a `<script>` or JS file)
A|13145|3|    2.4 Event-handler context
A|13157|3|    2.5 URL / URI context (href, src, action, formaction, xlink:href)
A|13169|3|    2.6 VBScript context (legacy IE only)
A|13176|3|    2.7 Framework expression context (CSTI — V-08)
A|13187|3|    2.8 Indirect-eval sink context (V-13)
A|13196|3|    2.9 Mutation / sanitizer context (V-07)
A|13207|3|    2.10 File/format vectors (V-14)
A|13219|2|  3. Detection / polyglot probe set (non-destructive)
A|13252|2|  4. WAF-evasion encoding table
A|13284|2|  5. Tool command templates
A|13289|1|Passive: collect URLs+params from a crawl, filter to XSS-shaped reflections
A|13292|1|dalfox — parameter scanning from a URL list (pipe mode)
A|13297|1|dalfox — one high-value URL with custom proof payload
A|13302|1|kxss — reflection pass (stdin URLs; look for its "reflection" lines per param)
A|13305|1|gf + dalfox combo — pattern-select XSS-prone params first
A|13308|1|Source→sink hunt in frontend bundles (V-03 / V-09)
A|13314|1|nuclei — XSS template suites (keep out-of-band templates pointed at YOUR OOB domain)
A|13319|1|Custom minimal nuclei-style template skeleton (write to xss-marker.yaml)
A|13337|1|Confirm execution in a real browser (headless chromium marker check)
A|13341|1|Playwright (python) full login+sweep harness — two self-interference traps that
A|13342|1|masquerade as app behavior (learned on Outlaw 2026-10-23):
A|13343|1|1) Program-mandated custom headers (e.g. X-Inspectiv-Tester) must be scoped to
A|13344|1|in-scope hosts via ctx.route — sending them on cross-origin subrequests
A|13345|1|(identitytoolkit.googleapis.com) adds them to the CORS preflight, the third
A|13346|1|party 403s the preflight, and Firebase login dies with
A|13347|1|auth/network-request-failed that looks like a network/app bug but is yours.
A|13353|1|2) Cached browser build may lag the playwright package (chromium-1234 vs 1248):
A|13354|1|point executable_path at the cached binary instead of reinstalling.
A|13355|1|Always assert login actually succeeded (page.url + a known post-login heading)
A|13356|1|before trusting sweep results — every protected SPA route silently redirects to
A|13357|1|the login page, so a failed login tests the login view, not your routes.
A|13359|1|Collaborator-style OOB watch (blind, V-05) — interactsh example
A|13368|2|  6. Chain it with (the suite)
A|13386|2|  >> xss-testing — variants-1.md (variant playbook)
A|13390|1|Variants 1-9 — xss-testing
A|13396|2|  Table of contents
A|13410|2|  V-01: Multi-transport parameter reflection (POST/GET XSS matrix)
A|13443|2|  V-02: Immediate context reflection boundary evasion (RXSS)
A|13469|1|full proof payloads per context: payloads.md §2 — swap in the marker the ladder selected
A|13484|2|  V-03: Client-side sink exploitation (DOM-based XSS source analysis)
A|13527|2|  V-04: Persistent storage script injection (stored XSS architecture)
A|13560|2|  V-05: Out-of-band testing (blind XSS tracking engines)
A|13593|2|  V-06: Browser SOP defiance (universal XSS / UXSS)
A|13626|2|  V-07: Parsing misalignment (mutation XSS / mXSS vs DOMPurify)
A|13645|1|Mutation = executable node present after round-trip, absent before.
A|13660|2|  V-08: Framework expression sandbox evasion (CSTI — AngularJS / Vue / Svelte)
A|13693|2|  V-09: DOM XSS-assisted prototype pollution exploitation
A|13725|2|  >> xss-testing — variants-2.md (variant playbook)
A|13729|1|Variants 10-18 — xss-testing
A|13734|2|  Table of contents
A|13748|2|  V-10: Cross-context resiliency (universal polyglot payloads)
A|13781|2|  V-11: Non-alphanumeric execution (JJEncode / AAEncode / JSFuck)
A|13814|2|  V-12: Double encoding obfuscation (WAF evasion: URL / HTML entity / Unicode)
A|13848|2|  V-13: Indirect string evaluation sinks (bypassing via evaluation functions)
A|13881|2|  V-14: Vector insertion via file formats (SVG / PDF / Markdown / XML)
A|13916|2|  V-15: Second-order reflected XSS via client-side cache injection
A|13949|2|  V-16: Relative path overwrite (RPO) context confusion
A|13986|2|  V-17: MIME-sniffing assisted XSS (Content-Type misconfigurations)
A|14019|2|  V-18: Breaking Trusted Types via unsanitized policy injection sinks
A|14052|2|  >> infra-fingerprinting — Website fundamentals: fingerprint the stack, route the bug class (client-side + s...
A|14059|1|Infra Fingerprinting — Website Fundamentals Playbook
A|14068|2|  1. Scope & authorization guardrail
A|14078|2|  2. Engagement workflow
A|14120|2|  3. Client-side fundamentals — signal → what it tells you → bugs it unlocks
A|14141|2|  4. Server-side fundamentals — signal → what it tells you → bugs it unlocks
A|14159|2|  5. Trust-boundary map — where "logic bypass" hypotheses come from
A|14180|2|  6. Signal → technique skill routing table
A|14199|2|  7. Verification standard
A|14221|2|  8. INGEST POINT — infrastructure recon map (pending data)
A|14244|2|  9. Report template (fingerprint-derived findings)
A|14247|2|  Title: <Component/version or stack detail> disclosed via <channel> (<misconfig class>)
A|14253|3|    Summary
A|14256|3|    Steps to reproduce
A|14261|3|    Impact
A|14265|3|    Evidence (redacted)
A|14268|3|    Remediation
A|14272|3|    References
A|14277|2|  10. Reference pointers
A|14288|1|3. HERMES-PROVIDED BUG BOUNTY SKILLS
A|14291|2|  >> bug-bounty-methodology — Continuous methodology extraction from reports
A|14295|1|Bug Bounty Methodology
A|14297|2|  Always-On Rules (User Preferences)
A|14305|2|  Workflow Steps
A|14307|3|    Step 1: Fetch Reports (When No Task Available)
A|14316|3|    Step 2: Extract Methodologies
A|14329|3|    Step 3: Analyze for Patterns
A|14338|3|    Step 4: Store and Apply
A|14343|2|  Methodology Database Format
A|14347|2|  Quick Reference — Methodology Templates
A|14349|3|    Recon
A|14355|3|    IDOR / BOLA
A|14363|3|    SSRF
A|14370|3|    XSS
A|14377|3|    Auth Bypass
A|14384|2|  Bug Chaining (Higher Payout)
A|14392|2|  Source Priority (Use in Order)
A|14401|2|  >> blackbox-writeups — core methods from 16 public black-box pentest/bug-bounty writeups (extraction 2026-1...
A|14410|3|    Source index
A|14431|3|    W-A. Engagement sequencing — the composite ladder
A|14461|3|    W-B. Recon tradecraft
A|14491|3|    W-C. Content discovery & inventory
A|14505|3|    W-D. Platform playbooks
A|14512|1|SSRF via xmlrpc: enumerate methods, then pingback.ping <attacker_url> <target_url>
A|14514|1|User enum: author-redirect loop (301 to slug), oembed leak, REST users
A|14517|1|Plugin/theme versions via readme.txt (NOT assumed from paths)
A|14519|1|Brute force with multicall throttle-bypass: one XML-RPC request wraps N wp.getUsersBlogs calls
A|14555|3|    W-E. Auth, session, rate-limit methods [W-7][W-13]
A|14571|3|    W-F. Chain & client-side methods
A|14597|3|    W-G. Verification & false-positive discipline
A|14616|3|    W-H. Reporting & triage methods
A|14639|3|    W-I. Operational rules (stealth, rate, restraint)
A|14656|2|  >> hacktivity-report — Daily report reading & methodology intake
A|14660|1|Hacktivity Report Workflow
A|14662|2|  Always-On Rules (User Preferences)
A|14668|2|  Workflow Steps
A|14670|3|    Step 1: Fetch Latest Reports
A|14672|1|Search for disclosed reports by vulnerability class
A|14677|3|    Step 2: Extract Methodologies
A|14689|3|    Step 3: Analyze for Patterns
A|14698|3|    Step 4: Store Knowledge
A|14708|3|    Step 5: Apply to Next Hunt
A|14715|2|  Methodology Templates
A|14717|3|    IDOR / BOLA Pattern
A|14727|3|    SSRF Pattern
A|14736|3|    XSS Pattern
A|14745|3|    Auth Bypass Pattern
A|14754|2|  Quick Reference - Endpoint Naming Patterns
A|14760|2|  Bug Chaining (Higher Payout)
A|14770|2|  AUTO-IMPROVEMENT (DAILY)
A|14779|2|  >> web-vulnerability-hunting — Full OWASP Top 10 hunting with control tests
A|14783|1|Web Vulnerability Hunting
A|14785|3|    When to Use
A|14809|2|  Procedures
A|14811|3|    Phase 1 — Subdomain Enumeration
A|14818|3|    Phase 2 — API Endpoint Discovery
A|14823|3|    Phase 3 — Vulnerability Testing (MANDATORY CONTROL TESTS)
A|14833|3|    Phase 4 — Authenticated Session Testing
A|14845|2|  Report Format (SUBZY-STYLE)
A|14850|1|Scanner: Subzy (or target tool)
A|14851|1|==============================
A|14853|1|subzy run --targets "$domain/subdomains_all_${domain}.txt" --hide_fails > "$domain/subzy_${domain}.txt"
A|14855|1|Summary output:
A|14865|2|  Prerequisites
A|14868|1|Recon tools
A|14874|1|Other tools (available in environment)
A|14875|1|dirsearch, ffuf, nmap, sqlmap, nuclei, amass, masscan
A|14877|1|Note: subzy installation failed (module fetch error). Use nuclei + manual crawling instead.
A|14878|1|nuclei binaries are available at:
A|14879|1|- /root/go/bin/nuclei (v3.11.1)
A|14880|1|- /root/nuclei-templates/ (template directory)
A|14883|2|  Report Format (SUBZY-STYLE)
A|14888|1|Scanner: Subzy (or target tool)
A|14889|1|==============================
A|14891|1|subzy run --targets "$domain/subdomains_all_${domain}.txt" --hide_fails > "$domain/subzy_${domain}.txt"
A|14893|1|Summary output:
A|14903|2|  Validation & False Positive Filtering (MANDATORY GATE)
A|14907|3|    The Control Test Pattern
A|14925|3|    Step-by-step Validation Process
A|14933|3|    Common False Positives to Filter Out
A|14947|2|  >> web-vulnerability-hunting — testing-payloads.md
A|14951|1|Testing Payloads Reference
A|14953|2|  Control & Validation Pattern (REQUIRED before reporting)
A|14956|3|    Example: SQLi on login form
A|14963|3|    Example: XSS on register form
A|14970|3|    Decision rules:
A|14975|2|  Server-Side Template Injection (SSTI)
A|14977|3|    Detection payloads
A|14987|2|  SQL Injection
A|14989|3|    Boolean-based
A|14996|3|    UNION-based
A|15003|3|    WAF bypass (test each, compare with control)
A|15012|2|  IDOR & Broken Access Control
A|15014|3|    Auth bypass headers
A|15023|3|    Mass assignment
A|15034|2|  SSRF
A|15036|3|    Internal targets
A|15046|2|  Path Traversal
A|15056|2|  Command Injection
A|15066|2|  Parameter names to test
A|15075|2|  Rate: Multiple payloads tested = Multiple control runs
A|15083|2|  >> blocked-page-recovery — 403/429/paywall/WAF recovery ladder
A|15087|1|Blocked-Page Recovery
A|15094|2|  The ladder
A|15113|2|  Provenance discipline (non-negotiable)
A|15126|2|  Manual routes
A|15128|3|    1. Wayback Machine (best provenance, try first)
A|15131|1|Discovery: returns closest snapshot URL + timestamp as JSON
A|15133|1|Then fetch archived_snapshots.closest.url
A|15148|3|    2. archive.today (paywalls, deleted content)
A|15163|3|    3. Jina Reader (requires JINA_API_KEY)
A|15176|3|    4. API-first pivot
A|15187|2|  Fake successes — routes that LIE
A|15205|2|  Proxy relays: don't
A|15213|1|4. MASTER PROMPTS / CORE IDENTITY
A|15216|2|  >> BUG_HUNTING_MASTER_PROMPT — Hermes master instructions for senior bug bounty research
A|15220|1|HERMES MASTER INSTRUCTIONS — SENIOR BUG BOUNTY RESEARCH AGENT
A|15222|2|  1. ROLE AND MISSION
A|15236|2|  2. PERSISTENT WORKSPACE
A|15295|2|  3. LEARN FROM PUBLIC SECURITY RESEARCH
A|15327|3|    Research rules
A|15341|3|    Extract useful knowledge from every selected write-up
A|15360|2|  4. VULNERABILITY TAXONOMY
A|15364|3|    A. Cross-Site Scripting
A|15381|3|    B. Cross-Site Request Forgery
A|15393|3|    C. SQL Injection
A|15406|3|    D. Command Injection, Code Injection, and RCE
A|15421|3|    E. SSTI, SSRF, XXE, and Deserialization
A|15432|3|    F. IDOR, BOLA, BAC, and RBAC
A|15467|3|    G. Authentication and Session Security
A|15482|3|    H. JavaScript and Frontend Source Analysis
A|15504|3|    I. Information Disclosure and Hidden Endpoints
A|15518|3|    J. Other Security Domains
A|15542|2|  5. RESEARCH WORKFLOW
A|15546|3|    Phase 1: Scope and constraints
A|15553|3|    Phase 2: Application understanding
A|15560|3|    Phase 3: Hypothesis generation
A|15574|3|    Phase 4: Validation
A|15584|3|    Phase 5: Reporting
A|15612|3|    Phase 6: Learning loop
A|15624|2|  6. RESEARCH AND EXECUTION SAFETY
A|15646|2|  7. WORKING STYLE
A|15664|2|  8. INITIAL TASKS
A|15684|2|  >> bug-hunter-main-prompt — Core bug bounty hunter identity & workflow
A|15688|1|🎯 Bug Bounty Hunter — Core Identity
A|15693|2|  Identity
A|15700|2|  🛠️ Language & Injection Expertise (Fully Qualified)
A|15760|2|  🌐 Networking Mastery (Network Core Protocols & the OSI Model)
A|15792|2|  ⚠️ SKILL-FIRST HUNTING (ALWAYS ACTIVE)
A|15802|2|  📋 RAW SCOPE HANDLING (ORGANIZE FIRST, THEN HUNT)
A|15832|2|  Core Rules
A|15845|2|  Target Prioritization
A|15854|2|  Attack Methodology
A|15865|2|  Skills (Installed — ALWAYS LOAD THE MATCHING ONE BEFORE HUNTING)
A|15888|3|    Skill → Vuln Class Quick Map
A|15907|2|  🧪 SKILL: Blind & Numeric IDOR Testing
A|15911|3|    1. Blind & Numeric IDOR Testing
A|15951|3|    2. Access Control & Authorization Bypasses
A|15959|1|Traversal in endpoint path
A|15963|1|Case sensitivity check
A|15989|3|    3. Information Disclosure & Asset Mapping
A|15997|1|Spring Boot Actuator endpoints
A|16001|1|OpenAPI / Swagger specs
A|16024|3|    4. Diagnostic Scripting with curl
A|16029|1|Silence output (-s), include response headers (-i), print HTTP status code (-w)
A|16039|2|  Agents (Installed — Delegate When Useful)
A|16053|2|  Tooling Quick Reference
A|16071|2|  🎯 Vulnerability → Tool to Use (Full Map)
A|16112|2|  CVSS Quick Reference
A|16121|2|  Common Attack Chains
A|16134|2|  Legal & Ethics
A|16143|1|5. LESSONS — LEARNING LOG
A|16146|2|  >> LESSONS.md — Report- and conversation-derived learning log (append-only)
A|16150|1|LESSONS — report- and conversation-derived learning log
A|16159|2|  YYYY-MM-DD — <source: own-report / triage-response / disclosed / third-party / conversation>
A|16183|2|  2026-10-21 — system initialized
A|16193|2|  2026-10-21 — own-engagement (vinted.com session 1)
A|16210|2|  2026-10-21 — own-engagement (vinted.com session 2, authenticated) + incident
A|16237|2|  2026-10-21 — suite restructure: rce-ssrf-testing split in two
A|16257|2|  2026-10-21 — SPA DOM-XSS hunting on a hashed-bundle PhantomBuster app
A|16292|2|  2026-10-21 — intake rule widened: conversations now mined like reports
A|16308|2|  2026-10-21 — unauthenticated info-disclosure sweep (PhantomBuster staging, continuation)
A|16344|2|  2026-10-21 — conversation
A|16362|2|  2026-10-21 — conversation
A|16375|2|  2026-10-21 — conversation
A|16391|2|  2026-10-21 — conversation
A|16405|2|  2026-10-23 — conversation
A|16421|2|  2026-10-24 — conversation
A|16444|2|  2026-10-24 — conversation (jardindacclimatation.fr first engagement)
A|16470|2|  2026-10-24 — conversation (casino-baden-baden.de first engagement, php2shell templates)
A|16511|2|  2026-10-25 — own-engagement (reready.co session 1, unauthenticated-only)
A|16557|1|6. DOMAIN PROFILES & FINDINGS
A|16563|2|  >> [bug-hunter/references/domain-template.md] domain-template.md
A|16567|1|Domain profile template
A|16578|1|<domain>
A|16583|2|  Scope
A|16588|2|  Stack (verified <date>)
A|16594|2|  Attack surface
A|16595|3|    Subdomains & hosts
A|16599|3|    Endpoints
A|16603|3|    API / GraphQL
A|16606|2|  Findings history
A|16610|2|  Ruled out (and why)
A|16613|2|  WAF / defense behavior
A|16616|2|  Next session (ranked)
A|16621|2|  Rules
A|16632|2|  >> [domains/aida.de/SKILL.md] SKILL.md
A|16636|1|aida.de
A|16646|2|  Scope
A|16656|2|  Identity (verified 2026-10-23, via web research — no packets to target)
A|16665|3|    False match to avoid
A|16669|2|  Stack (verified 2026-10-23)
A|16686|2|  Attack surface
A|16687|3|    Subdomains & hosts
A|16694|3|    Endpoints
A|16703|3|    API / GraphQL
A|16706|2|  Findings history
A|16711|2|  Ruled out (and why)
A|16722|2|  WAF / defense behavior
A|16731|2|  Next session (ranked)
A|16745|2|  >> [domains/bb.bigid.cloud/SKILL.md] SKILL.md
A|16749|1|bb.bigid.cloud
A|16754|2|  Scope
A|16759|2|  Stack (verified 2026-10-23)
A|16765|2|  Attack surface
A|16766|3|    Subdomains & hosts
A|16771|3|    Endpoints
A|16775|3|    API / GraphQL
A|16778|2|  Findings history
A|16782|2|  Ruled out (and why)
A|16785|2|  WAF / defense behavior
A|16788|2|  Next session (ranked)
A|16794|2|  >> [domains/casino-baden-baden.de/SKILL.md] SKILL.md
A|16798|1|casino-baden-baden.de
A|16808|2|  Scope
A|16818|3|    Program exclusions that shape this engagement (from the pasted policy)
A|16836|2|  Stack (verified 2026-10-24)
A|16852|2|  Attack surface
A|16853|3|    Subdomains & hosts
A|16864|3|    Endpoints
A|16875|2|  Findings history
A|16880|2|  Ruled out (and why)
A|16895|2|  WAF / defense behavior
A|16902|2|  Test mailbox / credentials
A|16907|2|  Next session (ranked)
A|16926|2|  >> [domains/frontier.com/SKILL.md] SKILL.md
A|16930|1|frontier.com — bgp/ipadmin scope
A|16938|2|  Scope
A|16948|2|  Stack (verified 2026-10-24)
A|16968|2|  Attack surface
A|16970|3|    Subdomains & hosts
A|16976|3|    Endpoints (complete BFS crawl 2026-10-24 — 16 HTML + 1 PHP)
A|16992|3|    API / GraphQL
A|16995|2|  Findings history
A|17002|2|  Ruled out (and why)
A|17016|2|  WAF / defense behavior
A|17022|2|  Test log (2026-10-24)
A|17042|2|  Open leads (ranked)
A|17059|2|  >> [domains/frontier.com/evidence/config-surface-2026-10-24.md] config-surface-2026-10-24.md
A|17063|1|Evidence — exposed config surface (finding 002) + parity — 2026-10-24
A|17065|2|  Discovery chain
A|17079|2|  Raw responses (bgp.frontier.com; ipadmin identical — parity spot-checked)
A|17111|2|  Conditional-output probes (all 200 / 0 bytes)
A|17115|2|  /themes/ content search
A|17119|2|  ipadmin parity spot-check (identical status+size)
A|17124|2|  >> [domains/frontier.com/evidence/xss-retest-2026-10-24.md] xss-retest-2026-10-24.md
A|17128|1|XSS retest — /bgp_procedures_new_form.php (asn + all fields) — 2026-10-24
A|17134|2|  1. Reflection matrix (all form fields, POST, marker `ZMQ9<>'"&ZMQ9`)
A|17146|2|  2. Bypass probes (all failed)
A|17163|2|  3. Browser execution proof (Playwright + Chromium 1234, file:// auto-submitting form)
A|17179|2|  4. Endpoint inventory tested for the same class
A|17194|2|  >> [domains/frontier.com/findings/001-gitignore-structure-disclosure.md] 001-gitignore-structure-disclosure.md
A|17198|1|Finding 001 — Public .gitignore discloses internal application structure
A|17204|2|  Summary
A|17210|2|  Steps to reproduce
A|17228|2|  Impact
A|17236|2|  Evidence (redacted)
A|17254|2|  Remediation
A|17259|2|  References
A|17265|2|  >> [domains/frontier.com/findings/002-exposed-internal-config-endpoints.md] 002-exposed-internal-config-end...
A|17269|1|Finding 002 — Internal config endpoints and directories web-accessible (silent)
A|17281|2|  Summary
A|17288|2|  Steps to reproduce
A|17302|2|  Impact
A|17311|2|  Evidence (redacted)
A|17332|2|  Remediation
A|17337|2|  References
A|17343|2|  >> [domains/getoutlaw.com/SKILL.md] SKILL.md
A|17347|1|getoutlaw.com
A|17352|2|  Scope
A|17367|2|  Stack (verified 2026-10-23)
A|17375|2|  Attack surface
A|17376|3|    Hosts
A|17384|3|    RPC functions (via fv.getoutlaw.com/api/*)
A|17398|3|    Other routes
A|17403|2|  Findings history
A|17409|2|  Ruled out (and why)
A|17422|2|  WAF / defense behavior
A|17429|2|  Next session (ranked)
A|17438|2|  >> [domains/getoutlaw.com/findings/F-01-getbundle-unauthenticated.md] F-01-getbundle-unauthenticated.md
A|17442|1|F-01 — Unauthenticated deal-bundle read via `POST /api/getBundle`
A|17449|2|  Summary
A|17455|2|  Evidence (all requests carry the mandatory `X-Inspectiv-Tester` header)
A|17464|2|  Data returned without auth (from own demo deal)
A|17472|2|  Impact
A|17476|2|  Reproduction
A|17486|2|  Recommended fix
A|17490|2|  Evidence files
A|17496|2|  >> [domains/getoutlaw.com/findings/F-02-checkaccount-enumeration.md] F-02-checkaccount-enumeration.md
A|17500|1|F-02 — Pre-auth account-existence + auth-method oracle via `POST /api/checkAccount`
A|17506|2|  Summary
A|17515|2|  Reproduction
A|17523|2|  Notes / adjacent observations (not separate findings)
A|17527|2|  Recommended fix
A|17531|2|  >> [domains/hub.devolutions.com/SKILL.md] SKILL.md
A|17535|1|hub.devolutions.com — Devolutions Cloud
A|17543|2|  Scope
A|17564|2|  Stack (verified 2026-10-25)
A|17588|2|  Attack surface
A|17589|3|    Subdomains & hosts
A|17597|3|    Endpoints
A|17604|3|    API / GraphQL
A|17619|2|  Findings history
A|17625|2|  Session-2 follow-up (2026-10-25): F-01 validated, RCE + SQLi investigated
A|17645|2|  Ruled out (and why)
A|17663|2|  WAF / defense behavior
A|17669|2|  Session-1 recon artifacts (evidence/recon/)
A|17676|2|  Next session (ranked)
A|17694|2|  Bounding rules carried from program scope
A|17702|2|  >> [domains/hub.devolutions.com/findings/F-01-opensearch-credential-disclosure.md] F-01-opensearch-credenti...
A|17706|1|F-01 — Unauthenticated OpenSearch/Elasticsearch credential disclosed via /api/server-configurations
A|17714|2|  Summary
A|17724|2|  Steps to reproduce
A|17730|2|  Impact
A|17744|2|  Evidence
A|17752|2|  Remediation
A|17763|2|  Live validation (2026-10-25) — credential is REAL but locked down
A|17790|2|  >> [domains/hub.devolutions.com/findings/F-02-sourcemap-exposure.md] F-02-sourcemap-exposure.md
A|17794|1|F-02 — Full client source code exposed via served sourcemaps (main.js.map, 62 MB)
A|17802|2|  Summary
A|17812|2|  Steps to reproduce
A|17819|2|  Impact
A|17826|2|  Evidence
A|17833|2|  Remediation
A|17839|2|  Bounding / triage note
A|17847|2|  >> [domains/hub.devolutions.com/findings/REPORT-F-01-server-configurations-credential-disclosure.md] REPORT...
A|17851|1|Production OpenSearch credential exposed via unauthenticated `/api/server-configurations`
A|17874|2|  Steps to reproduce
A|17904|2|  Impact
A|17923|2|  Evidence (redacted)
A|17936|2|  Remediation
A|17949|2|  Scope note
A|17956|2|  References
A|17963|2|  >> [domains/jardindacclimatation.fr/SKILL.md] SKILL.md
A|17967|1|jardindacclimatation.fr
A|17977|2|  Scope
A|18000|2|  Stack (verified 2026-10-24)
A|18026|2|  Attack surface
A|18028|3|    Subdomains & hosts
A|18040|3|    Pages (27 routes — from `_buildManifest.js`, fetched with validated `_abck`)
A|18052|3|    Endpoints (from JS bundle static analysis — `endpoints.json` in this dir)
A|18100|2|  Findings history
A|18106|3|    New routes found after the initial inventory (from `_app` chunk module `66679`)
A|18111|2|  Ruled out (and why)
A|18143|2|  WAF / defense behavior (Akamai Bot Manager) — **read before testing**
A|18165|2|  Next session (ranked)
A|18198|2|  >> [domains/jardindacclimatation.fr/evidence/technique-matrix.md] technique-matrix.md
A|18202|1|jardindacclimatation.fr — technique routing matrix (Phase 3)
A|18213|2|  XSS (`xss-testing`)
A|18229|2|  IDOR / broken access control (`bac-idor-testing`)
A|18250|2|  SQL / NoSQL injection (`sqli-testing`)
A|18266|2|  RCE (`rce-testing`)
A|18276|2|  LFI / path traversal (`path-traversal-testing`)
A|18285|2|  SSRF (`ssrf-testing`)
A|18295|2|  Business logic (`business-logic-testing`)
A|18307|2|  CSRF (`csrf-testing`)
A|18320|2|  Info disclosure (`info-disclosure-testing`)
A|18331|2|  Sandbox escape (`sandbox-escape-testing`)
A|18338|3|    Priority order for next session
A|18347|2|  >> [domains/jardindacclimatation.fr/findings/001-email-enumeration-oracle.md] 001-email-enumeration-oracle.md
A|18351|1|Account existence enumeration via unauthenticated `checkEmail` oracle
A|18362|2|  Endpoint
A|18374|2|  Summary
A|18386|2|  Steps to reproduce
A|18433|2|  Impact
A|18444|2|  Evidence
A|18449|2|  Remediation
A|18459|2|  Open (to confirm before submitting)
A|18466|2|  >> [domains/quizlet.com/SKILL.md] SKILL.md
A|18470|1|quizlet.com
A|18475|2|  Scope
A|18490|2|  Stack (verified 2026-10-21)
A|18502|3|    Auth model
A|18510|2|  Attack surface
A|18512|3|    Subdomains & hosts
A|18533|3|    Endpoints (from 8,000 archived URLs — Wayback CDX, IA was offline for live fetches)
A|18554|3|    API / GraphQL
A|18557|2|  Findings history
A|18564|2|  Ruled out (and why)
A|18579|2|  Open leads (not ruled out — blocked by the challenge)
A|18588|2|  WAF / defense behavior (characterized 2026-10-21)
A|18597|2|  Next session (ranked)
A|18610|2|  >> [domains/quizlet.com/findings/F-01-missing-security-headers-origin.md] F-01-missing-security-headers-ori...
A|18614|1|Missing security headers on origin-served responses
A|18623|2|  Summary
A|18636|2|  Steps to reproduce
A|18667|2|  Impact
A|18677|2|  False-positive check (what I ruled out)
A|18688|2|  Caveat / limitation
A|18696|2|  Remediation
A|18703|2|  References
A|18709|2|  >> [domains/quizlet.com/findings/F-02-envoy-k8s-service-disclosure.md] F-02-envoy-k8s-service-disclosure.md
A|18713|1|Internal Kubernetes service topology disclosed via `x-envoy-decorator-operation` (+ unauthenticated event i...
A|18722|2|  Summary
A|18744|2|  Steps to reproduce
A|18762|2|  Impact
A|18775|2|  False-positive check
A|18782|2|  Remediation
A|18788|2|  References
A|18794|2|  >> [domains/quizlet.com/findings/F-03-internal-routing-header-disclosure.md] F-03-internal-routing-header-d...
A|18798|1|Internal application routing metadata disclosed via `quizlet-action-name` / `quizlet-route-importance`
A|18806|2|  Summary
A|18827|2|  Steps to reproduce
A|18841|2|  Impact / how to use it
A|18852|2|  False-positive check
A|18857|2|  Remediation
A|18862|2|  References
A|18867|2|  >> [domains/reready.co/SKILL.md] SKILL.md
A|18871|1|reready.co
A|18878|2|  Scope
A|18903|2|  Stack (verified 2026-10-25, sandbox)
A|18937|2|  Attack surface
A|18939|3|    Subdomains & hosts
A|18946|3|    Endpoints
A|18956|3|    API / GraphQL
A|18959|2|  Findings history
A|18964|2|  Authentication testing (2026-10-25, sandbox only — no successful login yet)
A|18975|2|  Ruled out (and why)
A|18997|2|  WAF / defense behavior
A|19000|2|  Next session (ranked)
A|19023|2|  Recons done (don't redo)
A|19050|2|  >> [domains/reready.co/evidence/2026-10-25-unauth.md] 2026-10-25-unauth.md
A|19054|1|Evidence — 2026-10-25, session 1 (unauthenticated only)
A|19061|2|  0. Scope gate
A|19077|2|  1. Baseline headers (sandbox, GET /)
A|19093|2|  2. Reflection / RXSS sweep
A|19109|2|  3. SQLi on /help?search (boolean oracle exists: 20 vs 0 article links)
A|19131|2|  4. Path traversal
A|19145|2|  5. CSRF / Origin matrix (POST /users/sign_in, captcha-free flow)
A|19158|2|  6. CORS / method discovery (nonexistent UUID = zero collateral)
A|19171|2|  7. Host header / redirects
A|19180|2|  8. Info disclosure probes
A|19194|2|  9. Asset / JS findings (operational, not security)
A|19210|2|  10. Rate limits & auth-flow gating
A|19226|2|  11. Host ports (single pass, 2 s connect timeout, sandbox IP only)
A|19235|2|  >> [domains/verizon.com/SKILL.md] SKILL.md
A|19239|1|Verizon (Inspectiv)
A|19244|2|  Scope
A|19310|2|  Rules of Engagement (mandatory on EVERY request)
A|19320|2|  Stack (verified — pending first recon pass)
A|19329|2|  Attack surface
A|19330|3|    Subdomains & hosts
A|19333|3|    Endpoints
A|19337|3|    API / GraphQL
A|19340|2|  Findings history
A|19344|2|  Ruled out (and why)
A|19347|2|  WAF / defense behavior
A|19350|2|  Next session (ranked)
A|19362|2|  >> [domains/vinted.com/SKILL.md] SKILL.md
A|19366|1|vinted.com
A|19372|2|  Scope
A|19392|2|  Stack (verified 2026-10-21)
A|19406|2|  Security posture observed (session 1)
A|19417|2|  Attack surface
A|19418|3|    Hosts
A|19429|3|    Endpoints & params (pre-auth)
A|19439|2|  Findings history
A|19446|3|    Authenticated session notes (2026-10-21, sessions 2–3)
A|19469|2|  Ruled out (and why)
A|19511|2|  WAF / defense behavior
A|19515|2|  Next session (ranked)
A|19533|2|  >> [domains/vinted.com/findings/F-01-missing-security-headers.md] F-01-missing-security-headers.md
A|19537|1|F-01 — Missing browser security headers + weak HSTS on www.vinted.com
A|19549|2|  Summary
A|19553|2|  Evidence (2026-10-21)
A|19579|2|  Impact
A|19590|2|  Steps to reproduce
A|19594|2|  Remediation
A|19605|2|  Why this matters (one line)
A|19610|2|  >> [domains/vinted.com/findings/F-02-static-csrf-token-origin-unchecked.md] F-02-static-csrf-token-origin-u...
A|19614|1|F-02 — Globally static CSRF token + Origin/Referer not validated
A|19623|2|  Summary
A|19628|2|  Evidence (2026-10-21) — four independent sources, one value
A|19654|2|  Why severity is Low, not Critical
A|19664|2|  Escalation conditions (re-rate to High if any one appears)
A|19672|2|  Steps to reproduce
A|19679|2|  Remediation
A|19687|2|  Related
A|19692|1|7. LAB FILES — TOOLS & SCOPE
A|19695|2|  >> next-actions.md
A|19699|1|Next Actions
A|19701|2|  BLOCKED ON USER INPUT (Phase A gate)
A|19708|2|  Ready to run once scope is set (Phase B, passive)
A|19714|2|  Not started
A|19718|2|  >> tools-manifest.md
A|19722|1|Tools Manifest
A|19726|2|  Host
A|19732|2|  Pre-existing (system)
A|19741|2|  Installed this session (passive recon + crawling) — ~/go/bin
A|19756|2|  Deferred until active phases (not yet installed)
A|19759|2|  Not permitted without asking
A|19763|2|  >> scope/exclusions.md
A|19770|2|  >> scope/program-scope.md
A|19777|1|8. CREDENTIALS — Reference Only (No Secrets In This File)
A|19806|1|9. VALIDATION SCRIPT
A|19809|2|  >> validate_vulnerability.py — Control-test based validation
A|19840|1|Control test evidence table (from session 2026-10-29)
A|19957|2|  EXCLUDED FROM THIS FILE (by design)
A|19974|2|  17. Knowledge intake — appended methodology (research pass 2026-11-07)
A|19985|3|    17.1 SAML XML Signature Wrapping (XSW) — validated-signature/handled-node confusion → IdP-cert forgery → au...
A|19998|3|    17.2 MongoDB operator injection in the access_token query parameter — unauthenticated auth bypass → admin
A|20010|3|    17.3 GraphQL free-form `filter` JSON → JS-library `$where` → `new Function` → unauthenticated RCE in the No...
A|20024|3|    17.4 WordPress REST batch endpoint route-dispatch desync → unauthenticated blind SQLi (string where an arra...
A|20037|3|    17.5 SSRF filter bypass via the NAT64 local-use IPv6 prefix `64:ff9b:1::/48`
A|20050|3|    17.6 Unescaped dot in the redirect allowlist regex → open redirect → cross-domain auth-token theft → 1-clic...
A|20063|3|    17.7 Access-denied response body still leaks the protected object (HTTP 422 "not authorized" carries `conte...
A|20075|3|    17.8 Default/empty signing key → forged HMAC JWT → service "join" → full admin token (JFrog Artifactory)
A|20088|3|    17.9 Password-reset email param as a JSON ARRAY (scalar→array type confusion) → reset token mailed to attac...
A|20101|3|    17.10 Ruby Octokit/Sawyer method override → redis RESP size-desync → injected Redis command → Marshal.load ...
A|20116|3|    17.11 Shell-string sink: import/migration source path interpolated into Open3.popen3 -> command injection -...
A|20130|3|    17.12 Dependency confusion: unclaimed internal package name resolved from the public registry, install hook...
A|20142|3|    17.13 Archive symlinks not stripped on extract -> symlink followed at load -> arbitrary file read (GitLab b...
A|20156|3|    17.14 Internet-exposed unauthenticated Kubernetes API -> cluster-admin -> pod/job RCE + Secret/credential t...
A|20169|3|    17.15 Unsanitised value reflected into HTML rendered by a PDF/headless-browser generator -> iframe -> SSRF ...
A|20183|3|    17.16 Array-typed parameter (x[]) as a blind-SQLi sink on legacy report/export endpoints (Valve report_xml....
A|20195|3|    17.17 Server-side URL fetch: scheme-allowlist bypass (file://) -> arbitrary local repository read (GitLab R...
A|20208|3|    17.18 Delegated-admin object: field-level authorization not enforced -> vertical privilege escalation via r...
A|20221|3|    17.19 Perimeter appliance pre-auth file read -> runtime credential/session-store harvest -> 2FA bypass -> p...
A|20236|3|    17.20 HTTP desync / request smuggling (TE-header obfuscated) -> web-cache poisoning -> stored XSS on a logi...
A|20250|3|    17.21 Session tokens are portable: unbound session-cookie replay -> privileged account takeover (HackerOne ...
A|20262|3|    17.22 Upload-reference rewriter path traversal -> arbitrary file read -> secret_key_base cookie forgery -> ...
A|20401|3|    17.23 Loopback control service without an Origin check → desktop (Electron) RCE
A|20413|3|    17.24 Disk-image backing-file / external-data-file reference → arbitrary server file read
A|20426|3|    17.25 Trusted identity header (`X-Pid`) IDOR → cross-project role substitution → observer escalates to writ...
A|20438|3|    17.26 Selector/reader node mismatch → attribute injection into a string-concatenated tag → `data-*`-driven ...
A|20451|3|    17.27 Name field → secondary render path (slash-command / quick-action picker) → stored XSS for another use...
A|20463|3|    17.28 GraphQL write mutation resolves public handle → private email in the RESPONSE, before consent (Hacker...
A|20476|3|    17.29 Record-export path re-serves ACL-hidden content + guessable attachment ids -> internal file read (Hac...
A|20487|3|    17.30 Flag injection where the wrapped tool WRITES ITS OWN attacker-controlled stdout to a path -> arbitrar...
A|20497|3|    17.31 Unauthenticated Actuator `/heapdump` -> offline harvest of live session tokens/credentials from the h...
A|20508|3|    17.32 Length-field / signed-subtraction bounds-check bypass -> OOB read used as a remote oracle, and alloca...
A|20522|3|    17.33 Authz validator that EARLY-RETURNS by namespace/object shape → object-level check skipped → async exp...
A|20536|3|    17.34 Command/macro ("Quick Action") resolver serializes the WHOLE target model into the response → `runner...
A|20547|3|    17.35 Async job identity resolved at EXECUTION time from ownership → pipeline runs as another user → `CI_JO...
A|20562|3|    17.36 Path traversal carried in an uploaded artifact's OWN METADATA (not the URL path) → arbitrary file wri...
A|20575|3|    17.37 Project-export/import mass-assignment installs a server-side integration flagged as an instance TEMPL...
A|20589|3|    17.38 SSO identifier normalization mismatch: entityId validated TRIMMED but provisioning matches a trailing...
A|20604|3|    17.39 Signed-upload-envelope parser desync: a bracketed multipart field name makes the signed field map and...
A|20617|3|    17.40 Import/restore mass-assignment of an uploader's remote-fetch attribute the cleaner forgot → attacker-...
A|20629|3|    17.41 Two-object diff/compare: authorization is checked on the object you ADDRESS, but the COUNTERPART of t...
A|20644|3|    17.42 Program-enforced control (mandatory 2FA / reporter blacklist / rate limit) is enforced on the PRIMARY...
A|20658|3|    17.43 Machine credential carrying an identity CLAIM (SSH CA certificate `extension:login@github.com=<user>`...
A|20670|3|    17.44 Stored SSTI whose evaluation SINK is the OUTBOUND transactional EMAIL template → the computed payload...
A|20687|3|    17.45 SAML response validator verifies the signature only `if (a <ds:Signature/> element exists)` → strip t...
A|20700|3|    17.46 Password-reset INITIATE request returns the reset/session token IN ITS RESPONSE → the reset self-comp...
A|20712|3|    17.47 Headless-renderer export (PDF/report/screenshot) runs an EOL bundled Chromium with `--no-sandbox` → H...
A|20723|3|    17.48 Trusted INTERNAL identity claim reachable two ways: (i) internal signed token EXPOSED via a traversal...
A|20737|3|    17.49 Untrusted code sandbox: overwriting a BUILTIN EXCEPTION CLASS makes the engine's own error path recur...
A|20750|3|    17.50 Exposed OLD Swagger-UI honours a `configUrl` param → load a `data:text/html;base64,…` "config" → atta...
A|20761|3|    17.51 Untrusted INDEX from a network/binary message → unvalidated table lookup → virtual call on an attacke...
A|20773|3|    17.52 Untrusted interpreter sandbox: UNBOUNDED C-LEVEL recursion (no `eval`) bypasses the script-level stac...
A|20784|3|    17.53 CI build-cache poisoning: re-upload a modified remote-cache artifact under an existing key (the cache...
A|20796|3|    17.54 Purchase-flow parameter tampering that WRITES the target account: buy a subscription "for" the victim...
A|20808|3|    17.55 Untrusted interpreter sandbox: DELETING a core method the engine's own C helper calls (`NilClass.remo...
A|20821|3|    17.56 HTTP/2 → HTTP/1.1 frontend-downgrade request smuggling: a framing header the frontend never parses bu...
A|20833|3|    17.57 Untrusted interpreter sandbox: an ALLOCATED-BUT-NEVER-INITIALIZED object reaching `initialize_copy` →...
A|20845|3|    17.58 Webview/desktop chat XSS → CUSTOM URI-SCHEME HANDLER (`steam://openexternalforpid/<n>/<program>`) → a...
A|20859|3|    17.59 Delimiter-less signature canonicalization → signed-payment parameter smuggling (`Amount=2000` ≡ `Amou...
A|20872|3|    17.60 GraphQL invitation-object over-exposure → harvested invite token → token-consume endpoint returns the...
A|20887|3|    17.61 Exposed proxy/gateway on a non-standard port routes on an attacker-supplied `Host:` header → internal...
A|20899|3|    17.62 SSO login-token theft: over-permissive `referrer` allow-list + `#fragment` surviving 302/307 + attack...
A|20913|3|    17.63 Docs/help portal on a third-party SaaS renders user "suggest edits" as an AngularJS template → CSTI e...
A|20927|3|    17.64 Network-message index: LOWER-bound-only check + index scaled by a fixed stride (`shl eax,4`) wraps a ...
A|20940|3|    17.65 Length-prefixed decoder: bounds checks hoisted OUT of the `do/while` that advances both cursors; cont...
A|20955|3|    17.66 Two-parser header case-sensitivity mismatch: `Content-Length: N` + `content-length: 0` → allocated-bu...
A|20967|3|    17.67 A message-staged GLOBAL POINTER as the fake-object stage: unchecked `slot` into a static `.data` arra...
A|20978|3|    17.68 Delimiter-bounded copy into fixed STACK buffers in a client-parsed asset file (`<cmd:args>` tokenizer...
A|20989|3|    17.69 Free-form `sort_query: String` passed verbatim into the search engine's `sort` parameter → scripted-s...
A|21002|3|    17.70 Flag injection that switches the tool into its own filesystem-walk mode (`ref=--no-index` into `git g...
A|21014|3|    17.71 SSO migration that leaves a legacy auth entrypoint enabled + a STATIC placeholder password in the loc...
A|21030|3|    17.72 Mobile deep link: internal-URL allowlist checked on the OUTER host + a re-parsed `proceed_to` redirec...
A|21041|3|    17.73 URL-preview / unfurl endpoint returns the fetched page's `og:title` → a built-in blind-SSRF READ ORAC...
A|21053|3|    17.74 Localhost "inspector" WebSocket `live_reload` downloads an attacker file with a naive `dir + fileName...
A|21065|3|    17.75 Unauthenticated observability backend (`/config`) + exposed Go pprof (`/debug/pprof/cmdline?debug=1`,...
A|21078|3|    17.76 Job-submission REST endpoint runs a CLASSPATH class with attacker `entry-class`/`programArg` -> JDK `...
A|21089|3|    17.77 CRLF injection through an edge/WAF rule-engine string function accepting HEX ESCAPES (`\x0a\x0d` in `...
A|21100|3|    17.78 Cross-account config overwrite: writing a feature config on an UNVERIFIED ("pending") resource overwr...
A|21115|3|    17.79 Security-disabled feature attribute RE-ENABLED from document CONTENT via an inline counter/set macro ...
A|21127|3|    17.80 Parameter-pollution of an admin-only "trusted" flag on an OAuth client YOU create -> consent/CSRF byp...
A|21140|3|    17.81 `data:image/svg+xml` used as an IMAGE SOURCE: the SVG script is dormant inside `<img>` but RUNS when ...
A|21154|3|    17.82 Account-identifier (user_id) enumeration through a MOBILE onboarding/duplication-check flow that igno...
A|21166|3|    17.83 `javascript:` URI accepted by a POST-LOGIN redirect parameter (`dest=`/`next=`/`return_to=`/`redirect...
A|21177|3|    17.84 Inbound-EMAIL stored XSS: the mail client's CSS rewriter DECODES octal escapes (`\00003c`) inside `ur...
A|21193|3|    17.85 Draft/preview render path re-uses raw link values while scheme validation and sanitisation run only o...
A|21205|3|    17.86 Setuid-root binary executes a helper by a BARE name, trusting the caller's `$PATH` — local privilege ...
A|21217|3|    17.87 One-time-benefit CLAIM endpoint is not idempotent and does not burn the offer id — replay stacks the ...
A|21230|3|    17.88 A client tool materialises a local file whose NAME comes from page-controlled attributes — `Path.reso...
A|21241|3|    17.89 Server-owned approval/lifecycle STATE fields are writable through the object PATCH — self-approve and...
A|21253|3|    17.90 Peer-supplied BIT length copied into a fixed BYTE-sized stack buffer off a voice/network channel — st...
A|21264|3|    17.91 GraphQL field selection gated by a CLIENT-ASSERTED permission variable (`@include(if: $flag)`) — the ...
A|21276|3|    17.92 A GraphQL PERSISTED-OPERATION hash plus a NAME variable is an IDOR: the request carries no query text...
A|21287|3|    17.93 A document-IMPORT pipeline fetches a reference found inside the uploaded archive and returns the resp...
A|21300|3|    17.94 Registry SOURCE-PRIORITY INVERSION — a LEGITIMATE internal package is overridden by a same-named publ...
A|21312|3|    17.95 An internet-exposed analytics QUERY ENGINE (Presto coordinator) behind a misconfigured firewall is a ...
A|21326|3|    17.96 An XML DTD ENTITY inside an uploaded SVG switches OFF the SVG element/attribute whitelist -> `onload`...
A|21344|3|    17.97 A markdown REFERENCE-REDACTION pass reads a stored html-encoded attribute back out and re-emits it as...
A|21363|3|    17.98 An attacker-settable CONNECTOR CONFIG value names a JDK JAAS login module (`com.sun.security.auth.mod...
A|21378|3|    17.99 An INVITE-ACCEPTANCE endpoint trusts a client-supplied invite id with no ownership check — a failed r...
A|21393|3|    17.100 A WINDOWS-node kubelet in-tree storage plugin does not sanitize the volume's LOCAL PATH field — a us...
A|21409|3|    17.101 A server accepts an OBJECT where a STRING is expected, and the React client passes it as a `createEl...
A|21421|3|    17.102 A server-validated one-time SECRET is brute-forceable through a DIFFERENTIAL RESPONSE-LENGTH oracle ...
A|21434|3|    17.103 A protocol FEE/BOND DERIVED from a measured value can be inflated arbitrarily by an attacker who con...
A|21448|3|    17.104 A Node service's PROTOTYPE POLLUTION inside an internal-index pipeline reaches a `sourceURL`/code-ge...
A|21460|3|    17.105 A customer-created PROVISIONING object supplies the URL, and the provider's CONTROL-PLANE controller...
A|21475|3|    17.106 An admin-visible ACTIVITY/AUDIT LOG stores request metadata written by an UNAUTHENTICATED request ->...
A|21490|3|    17.107 Client-side MEMORY-CORRUPTION primitives reachable from untrusted script in a plugin/runtime — UAF v...
A|21503|3|    17.108 A Windows server's own PATH handling coerces NTLM over SMB from a UNC path -> capture/relay -> RCE, ...
A|21519|3|    17.109 Hostname validation/resolution DIFFERENTIAL — a fixed 256-byte truncation makes the string the valid...
A|21532|3|    17.110 Oversized chunked-TRAILER header drives a back-end parser into an `IOException` error path → the lef...
A|21545|3|    17.111 EMAIL-GATEWAY action endpoint trusts the `From:` header → any sender performs an account-bound actio...
A|21558|3|    17.112 Multi-CONNECTOR SSRF — a provider/source selector exposes independently-protected server-side fetch ...
A|21573|3|    17.113 Client-side desync (CSD) — an over-declared `Content-Length` on an INCOMPLETE POST desyncs the VICTI...
A|21586|3|    17.114 TRAILER-SECTION line-skipping — a trailer line WITHOUT a colon makes the parser swallow the next req...
A|21600|3|    17.115 ENV-FILE delimiter/newline injection into `$GITHUB_ENV` via `core.exportVariable` → attacker-defined...
A|21613|3|    17.116 WAF bypass by splitting a SQL FUNCTION NAME from its parenthesis with an inline comment, plus a VALU...
A|21626|3|    17.117 Unauthenticated `admin-ajax.php` PREVIEW action that expands WordPress shortcodes from a parameter, ...
A|21643|3|    17.118 Project IMPORT that TRUST-RESTORES a `cache_markdown_field` — an attacker `note_html` plus a matchin...
A|21651|3|    17.119 A cacheable per-user response carrying the session `Set-Cookie` + `Cache-Control: public` is stored ...
A|21659|3|    17.120 Partial PUT with an attacker-influenced temp-file name/path on a WRITABLE Default Servlet → reach th...
A|21667|3|    17.121 DNS rebinding via `0.0.0.0` + macOS `.local` DNS to read the Node inspector's `webSocketDebuggerUrl`...
A|21675|3|    17.122 Blind SQLi in a URL PATH SEGMENT via an `or 1=1--` / `or 1=2--` boolean predicate, reached from a pr...
A|21685|3|    17.123 An OAuth/token endpoint that builds its OUTBOUND url from the request `Host` (absolute route helper)...
A|21692|3|    17.124 An UNAUTHENTICATED federation/OCM `notifications` endpoint that trusts a `sharedSecret` the attacker...
A|21699|3|    17.125 A document→preview/PDF converter that FOLLOWS document-embedded external links (ODF OLE object / `te...
A|21706|3|    17.126 An OAuth login that MINTS A VALID SESSION on a FAILED exchange → authentication bypass into the auth...
A|21715|3|    17.127 A server's URL-normalization ORDER (decode AFTER the check) turns a percent-encoded dot-dot into arb...
A|21722|3|    17.128 A desync that needs NO malformed bytes at all — PAUSE-BASED desync, where a server-level responder t...
A|21729|3|    17.129 The injectable field is INSIDE a base64/hex-encoded blob in one opaque parameter — so no scanner and...
A|21736|3|    17.130 A PDF generator that EXECUTES the injected JavaScript — the breakout is `</script><script>` and the ...
A|21745|3|    17.131 An INCOMPLETE DENY-LIST of framework-RESERVED routing keys is URL-authority/scheme injection: `domai...
A|21752|3|    17.132 GRAPHQL GLOBAL-ID TYPE CONFUSION: a mutation resolves any global id with the generic resolver and de...
A|21759|3|    17.133 NON-HTTP SSRF through a MEDIA RELAY: TURN credentials handed to any user are a TCP-and-UDP proxy int...
A|21766|3|    17.134 When the injected `--output` path is written by TWO SEQUENTIAL invocations, the LAST writer decides ...
A|21775|3|    17.135 A third-party ERROR-MONITORING SDK is an SSRF gadget: the monitoring backend fetches a URL taken fro...
A|21782|3|    17.136 The ANTI-ABUSE ATTEMPT COUNTER is keyed on the RAW identifier while authentication normalizes it — m...
A|21789|3|    17.137 A stored-XSS SINK that renders ONLY for a viewer in a DIFFERENT permission/state than the author — V...
A|21798|3|    17.138 A policy VALIDATOR that normalizes only SOME of the input TYPES its sink accepts is bypassed by the ...
A|21805|3|    17.139 A two-step OTP CLAIM flow whose VERIFY step is not bound to the resource the code was ISSUED for — r...
A|21814|3|    17.140 A reflected POST parameter is a HEADER ORACLE after a desync, and the vendor's TRUSTED-GATEWAY ADMIN...
A|21821|3|    17.141 An OAuth provider's "verify your email" gate enforced only in the UI — POSTing `/oauth/authorize` di...
A|21828|3|    17.142 An integration/marketplace app's setup SERVLET mints the tenant-binding claim JWT for ANY user who o...
A|21835|3|    17.143 The SSRF sink is a QUERY ARGUMENT inside a GraphQL document — the URL is a field parameter, not an H...
A|21844|3|    17.144 A per-user COUNTER that ticks only on a valid reference is an EXISTENCE ORACLE — a write/link mutati...
A|21851|3|    17.145 A bundled headless browser's DevTools channel is the RCE path: JS-port-scan localhost → steal the br...
A|21858|3|    17.146 An access-control gate enforced on the PUBLIC render path but not on a SIBLING preview path — an una...
A|21868|3|    17.147 A postMessage listener's escape loop MUTATES the object it was handed and skips NON-OWN properties —...
A|21876|3|    17.148 One server-side HTML literal escapes some interpolations and not others — the unescaped SIBLING fiel...
A|21886|3|    17.149 External protocol handler bypasses the app's proxy/anonymity confinement → real-IP deanonymization +...
A|21900|3|    17.150 A markup renderer's OPTIONAL scripting extension is enabled by a successful `require` — and the esca...
A|21914|3|    17.151 A server-side JS engine given LIVE serializer objects: coerce its OVERLOAD RESOLUTION into construct...
A|21928|3|    17.152 A CONTENT-EMBEDDED diagram/chart config-init directive is DEEP-MERGED into the renderer's shared con...
A|21943|3|    17.153 A frontend sanitizing DIRECTIVE (`v-safe-html`) is bypassed by the app's OWN CUSTOM ELEMENT, whose t...
A|21959|3|    17.154 A user-supplied URL is interpolated INSIDE a CLI config argument (`-c http.<url>.extraHeader=…`) so ...
A|21973|3|    17.155 A renderer config value is concatenated into a CSS string that is assigned to `<style>.innerHTML`, s...
A|21988|3|    17.156 An opaque identifier you cannot enumerate becomes enumerable when the SAME endpoint accepts it under...
A|22000|3|    17.157 A MIRROR/REGISTRY renders metadata authored by a THIRD PARTY on the UPSTREAM, so whoever controls a ...
A|22013|3|    17.158 "You may only assign YOURSELF as the actor" is enforced by a validator built from a RELATIONSHIP tha...
A|22029|3|    17.159 An UNTHENTICATED landing page that word-differentiates a live identifier from a dead one is an exist...
A|22044|3|    17.160 An OAuth CONSENT SCREEN can under-state the grant for a NON-STANDARD flow: the permission dialog ren...
A|22059|3|    17.161 A SELF-SERVICE account mutation in ONE client silently CORRUPTS an UNRELATED security/privacy settin...
A|22072|3|    17.162 A LEGACY server-rendered admin FILE escapes a modern PATH-PREFIX auth gate: the middleware protects ...
A|22085|3|    17.163 A media DEMUXER resolves URLs and PATHS that are embedded as PLAYLIST DIRECTIVES inside an uploaded ...
A|22099|3|    17.164 The app's editor re-hydration on the EDIT route sanitizes LESS than the read-only route — deliver th...
A|22111|3|    17.165 A postMessage origin gate written as a SUBSTRING test (`indexOf`/`includes`) is reachable from a dom...
A|22137|3|    17.167 An identifier that was PUBLIC when the object was public remains a BEARER CREDENTIAL after the objec...
A|22150|3|    17.168 Two features that each MINT access grant unlimited access when composed: an automated onboarding pat...
A|22165|3|    17.169 A validator that NORMALIZES parameter keys (lowercases them) before checking a whitelist, while the ...
A|22178|3|    17.170 A sandbox that decides TRUST from a CANONICALIZED path while the LOADER resolves the RAW string gran...
A|22191|3|    17.171 A step-up/MFA factor NAMED by a client request field can be swapped for a factor that was never chal...
A|22203|3|    17.172 A config-injection fix that BLACKLISTS a directive NAME is bypassed by an ALTERNATE directive that r...
A|22216|3|    17.173 An ownership check whose "second factor" is a SHARED CONSTANT (the email DOMAIN) rather than a per-u...
A|22228|3|    17.174 Over HTTP/2, the ORDER in which two concurrent multiplexed responses arrive (not elapsed time) is a ...
A|22241|3|    17.175 A role assignment that silently SUBSCRIBES the new member to PRIVATE child objects discloses those o...
A|22256|3|    17.176 An assertion is trusted with NO signature verification while the ISSUER is chosen by the attacker — ...
A|22270|3|    17.177 The provisioning STATE STORE holds the cluster CA private key and the NODE's cloud identity can read...
A|22286|3|    17.178 A config-injection sanitizer is defeated through the LOGGING directives: attacker-controlled log PAT...
A|22300|3|    17.179 A config-injection fix lands per-ANNOTATION per-CVE — every OTHER annotation whose value renders int...
A|22314|3|    17.180 An export/render endpoint authorizes the request that CREATES the artifact but not the request that ...
A|22327|3|    17.181 A config-injection into a generated proxy config becomes an ARBITRARY INTERNAL FILE READ when the in...
A|22341|3|    17.182 A privileged desktop helper/installer is exploitable on two axes — a caller-supplied SOURCE PATH ins...
A|22355|3|    17.183 A "recently used / saved query" history persists user input and re-renders it to EVERY user of the t...
A|22367|3|    17.184 The CLIENT trusts a user-replaceable BACKEND (the RPC node the wallet talks to) and injects the node...
A|22379|3|    17.185 An internal cache service bound on a NON-STANDARD port with no authentication — scan ALL ports on ev...
A|22393|3|    17.186 A validator that shares a realm with the code it constrains is bypassable by monkey-patching the bui...
A|22402|3|    17.187 The HTML-sanitizer ALLOW-LIST configuration is itself the attack surface — (a) a tag that embeds a n...
A|22411|3|    17.188 A redirect-following client forwards its credentials across HOST and SCHEME — a 301 from an attacker...
A|22420|3|    17.189 A stored CONNECTION/config field becomes a raw CLI flag → attacker-controlled classpath/jar loads → ...
A|22431|3|    17.190 A connection-pool REUSE KEY that omits the IDENTITY-AFFECTING options hands the next transfer the pr...
A|22440|3|    17.191 Combined client SAFETY/STATE options act on the WRONG OBJECT — (a) cleanup-on-error deletes the file...
A|22449|3|    17.192 A security fix scoped to ONE parameter-SUPPLY PATH — the per-call argument was patched, the class-le...
A|22460|3|    17.193 TLS SESSION-TICKET RESUMPTION state is not isolated per virtual host — a ticket minted by the mTLS v...
A|22470|3|    17.194 An ATOMIC FILE REPLACE installs the TEMP file's permissions instead of the DESTINATION's — the objec...
A|22500|3|    17.199 A checkout accepts a CLIENT-SUPPLIED PAYMENT INSTRUMENT with no ownership binding — the selection en...
A|22510|3|    17.200 In a two-step money flow the capture endpoint re-reads the AMOUNT from the client instead of from th...
A|22520|3|    17.201 A SPLIT CREDENTIAL whose missing half parses to `nil` matches every record whose credential COLUMN I...
A|22737|2|  §17.276 (mirror) — Hasura anonymous-role introspection = permission map; 0-row write-grant probing (VERIFIE...
A|22812|3|    17.277 A MITIGATION's own bound check is off by one against the SCALED index it guards — the single admitte...
A|22827|3|    17.278 An object property the runtime RESOLVES THROUGH AN ACCESSOR YOU CONTROL is resolved INSIDE the runti...
A|22843|3|    17.279 The AUTHORIZATION LAYER is itself probeable — its PRESENCE is read from the KIND of error an operati...
A|22860|3|    17.280 A CLOUD-DRIVE CONNECTOR'S SERVER-SIDE FETCH IS A TOKEN DELIVERY SERVICE: the user's file id is CONCA...
A|22868|3|    17.281 A SERVICE WORKER ON YOUR OWN WILDCARD SUBDOMAIN READS THE AUTH CALLBACK, AND THE OAUTH `state` IS NO...
A|22876|3|    17.282 A CHATBOT'S SESSION-ECHOED "GREETING" IS A STORED-XSS SINK WITH A FREE PLANTING STEP (CSRF), THE MAR...
A|22884|3|    17.283 A MUTATED (UNICODE-NORMALISED) CRLF IN A URL PATH INJECTS `Set-Cookie`, AND THE POINT OF THE INJECTI...
A|22892|3|    17.284 A CSP THAT DOES NOT COVER `object-src` IS NO DEFENCE, AND A FIELD AN UNPRIVILEGED PARTY SUPPLIES IS ...
A|22901|3|    17.285 BOLA ON AN ACCOUNT-LINKING ENDPOINT PLUS A MISSING E-MAIL-VERIFICATION GATE = A BACKDOOR LOGIN METHO...
A|22910|3|    17.286 AN ORIGIN-UNCHECKED `postMessage` INTO A THIRD-PARTY SDK'S COMMAND QUEUE IS ARBITRARY SDK-API EXECUT...
A|22919|3|    17.287 A CLIENT-ASSIGNABLE IDENTIFIER IS AN UNFILTERED XSS SOURCE — the create-user endpoint lets the calle...
A|22928|3|    17.288 A BUILD CONFIG'S PACKAGE-INSTALL LIST ACCEPTS A LOCAL PATH, SO THE PACKAGE MANAGER'S OWN MAINTAINER ...
A|22937|3|    17.289 THE FRAMEWORK'S PASSWORD-RESET TOKEN IS A SEPARATE SIGNED ARTIFACT — a weak/default Flask `SECRET_KE...
A|22946|3|    17.290 A MALFORMED FILE NAME OVERFLOWS THE DIRECTORY-LISTING FORMATTER — the enumeration path (`maps *` → `...
A|22955|3|    17.291 A SHARED-MEMORY FIELD WRITTEN BY AN UNPRIVILEGED WORKER AND USED AS AN UNCHECKED INDEX BY A STILL-RO...
A|22964|3|    17.292 A DYNAMICALLY GENERATED JS FILE IS AN XSSI SOURCE — its per-cookie content is importable cross-origi...
A|22973|3|    17.293 REDACTION MASKS THE DISPLAY, NOT THE COMPARISON — a bot that scores your input against the pre-redac...
A|22982|3|    17.294 AN SVG URL-IRI ATTRIBUTE ON A SERVER-SIDE RASTERIZER IS AN SSRF SINK, AND THE FETCHED RESOURCE IS CO...
A|22991|3|    17.295 AN XML-CONVERTED IMAGE IS AN XML-ENTITY SINK — bypass the URL filter with the protocol-relative `//h...
A|23000|3|    17.296 A SELF-SERVICE CREATE FLOW DISABLED IN THE RESTRICTED PRODUCT'S UI IS STILL REACHABLE WHEN THE SIBLI...
A|23011|3|    17.297 An internal mutation whose input is a VALUE (not an object id) has nothing to authorize — a store SE...
A|23018|3|    17.298 A server-side HTML→PDF preview that EXECUTES JAVASCRIPT on an OUTDATED engine escalates to host RCE ...
A|23026|3|    17.299 Unauthenticated record DELETION via a REST delete-by-id endpoint — the per-ENTITY permission oracle ...
A|23082|3|    17.300 Appliance Management Console config field rendered as a NOMAD/Go template = command-injection sink r...
A|23095|3|    17.301 HTTP request headers (User-Agent / Referer / X-Forwarded-For) are SQLi injection points — find them ...
A|23107|3|    17.302 A server-side URL fetch gated by a Content-Type read from a HEAD while the payload is served from a ...
A|23131|3|    17.303 A GROUP-LEVEL DEFAULT setting is interpolated unescaped into a generated terminal-command sample on ...
A|23147|3|    17.304 An ENTITLEMENT JSON boolean computed client-side is rewriteable with a proxy Match-and-Replace — the...
A|23163|3|    17.305 A TIME-BASED BLIND SQLi in a numeric account-id query parameter of a legacy PHP install/settings scr...
A|23190|3|    17.306 A mail/message `message[content]` stored through a FORWARD multipart POST fires on OPEN in the recip...
A|23242|3|    17.307 A SANITIZER that rewrites an attribute string by regex and re-splices it injects its own delimiter —...
A|23287|3|    17.308 A legacy ColdFusion `.cfm` endpoint's numeric query parameter (`countID`) reaches SQL — confirm it w...
A|23295|3|    17.309 A workspace settings POST whose ACTION is in the PATH and whose VALUE is in the JSON body has no ser...
A|23312|3|    17.310 A static-hosting platform serves content for a custom domain BEFORE ownership is verified, for a 7-d...
A|23320|3|    17.311 A driver's OWN `driverrequest` response hands back the `tender.id` + `order_id`, and `getTenderStatu...
A|23355|3|    17.312 A DECORATION/EXPANSION PARAMETER THAT RESOLVES A VALUE YOU WROTE INTO A FREE-TEXT FIELD IS AN OBJECT...
A|23365|3|    17.313 THE UI'S ACL FILTER IS NOT THE OBJECT'S ACL — a low-privilege participant on a private record cannot...
A|23376|3|    17.314 PII EMBEDDED IN A SIGNED-BUT-NOT-ENCRYPTED URL TOKEN + THE URL ARCHIVED BY THE WAYBACK MACHINE → PUB...
A|23385|3|    17.315 A SENSITIVE VALUE SET VIA THE CLI IS MASKED ON THE OBJECT PAGE BUT RENDERED UNMASKED IN THE CLI/AUDI...
A|23396|3|    17.316 THE ORM PARAMETERIZES VALUES, NOT QUERY STRUCTURE — Django's `WhereNode.as_sql` interpolates the Q-o...
A|23407|3|    17.317 AN UNKEYED OR OVERRIDDEN REQUEST HEADER IS A CACHE BODY-AND-KEY ORACLE — BRUTEFORCE HEADERS (MERGE P...
A|23416|3|    17.318 A HEADLESS-BROWSER PRERENDERER THAT EXECUTES A REQUEST-SUPPLIED JAVASCRIPT PARAMETER IS AN SSRF SINK...
A|23425|3|    17.319 A CI BUILD VARIABLE THAT NAMES AN EXECUTABLE IS A COMMAND-INJECTION SINK — `DOCKER_AUTH_CONFIG` → `c...
A|23437|3|    17.320 A CUSTOM-DOMAIN CNAME TARGET SHARED BY TWO PRODUCT FEATURES IS CLAIMABLE IN THE WEAKER FEATURE EVEN ...
A|23446|3|    17.321 AN HTTP HEADER-COUNT OVERFLOW PAST THE EDGE'S PARSE CAP MAKES THE CDN STOP EVALUATING CACHE RULES / ...
A|23455|3|    17.322 A ROLE-BEARING INVITE IS AN AUTHORIZATION GRANT THAT MUST BE RE-CHECKED AGAINST THE INVITER'S MEMBER...
A|23466|3|    17.323 AN IDOR-ABLE CONFIG ENDPOINT THAT RETURNS THE AUTHORIZATION HASH FOR A STATE-CHANGING ACTION LETS YO...
A|23475|3|    17.324 AN ERROR RESPONSE FROM A VALIDATION ENDPOINT RENDERED VIA `innerHTML` IS AN HTML-INJECTION SINK — A ...
A|23486|3|    17.325 THE TOTP SEED (`gauth_secret`) IS RETURNED IN THE RESPONSE OF AN ORDINARY ACCOUNT "RENEW" REQUEST — ...
A|23495|3|    17.326 AN EMAIL-CHANGE CONFIRMATION TOKEN IS EXPOSED IN A UI "RESEND" LINK, AND THE BASE CONFIRMATION URL V...
A|23504|3|    17.327 A GRAPHQL MUTATION THAT AUTHORIZES THE PARENT ID BUT LOADS THE CHILD ID THROUGH A GLOBAL RESOLVER LE...
A|23513|3|    17.328 AN UNAUTHENTICATED `PUT` TO A GCS-BACKED CDN WITH `Content-Type: application/octet-stream` (OR BLANK...
A|23522|3|    17.329 A TOKEN-EXCHANGE ENDPOINT THAT ACCEPTS A SOCIAL ACCESS TOKEN WITHOUT VALIDATING THE ISSUING `app_id`...
A|23603|3|    17.355 AN ASP.NET HANDLER THAT REFLECTS A USER-SUPPLIED `__PARAMETERS` VALUE INTO `TemplateControl.ParseCon...
A|23612|3|    17.356 A PUBLIC CONTAINER IMAGE IS PART OF THE ATTACK SURFACE — PULL THE ORG'S IMAGES, EXTRACT EVERY LAYER,...
A|23623|3|    17.357 A MARKDOWN PIPELINE WHOSE SANITIZER ONLY ESCAPES USER-SUPPLIED ATTRIBUTE VALUES IS BYPASSED BY A DOW...
A|23632|3|    17.358 A WAF INSPECTS EACH REQUEST FIELD SEPARATELY, SO AN XSS PAYLOAD SPLIT ACROSS A REFLECTED URL PARAMET...
A|23643|3|    17.359 AN EXPOSED DEV/TEST MAIL CATCHER ON AN IN-SCOPE SUBDOMAIN RECEIVES THE APPLICATION'S TRANSACTIONAL M...
A|23654|3|    17.360 A CHECKOUT REQUEST WHOSE TOTAL IS COMPUTED FROM THE SUPPLIED PARAMETER SET IS RE-PRICED BY DELETING ...
A|23665|3|    17.361 AN OAUTH SUCCESS/CALLBACK PAGE THAT `postMessage`s ITS OWN URL (WHICH CARRIES THE AUTHORIZATION `cod...
A|23674|3|    17.362 A SUPPORT DESK THAT CREATES READABLE TICKETS FOR AN UNVERIFIED E-MAIL ADDRESS IS A MAILBOX-READ PRIM...
A|23685|3|    17.363 A MOBILE DEEPLINK QUERY PARAMETER THAT NAMES THE FILE THE APP WRITES IS A PATH-TRAVERSAL SINK — INJE...
A|23695|3|    17.364 A MODERATION / "REPORT THIS CONTENT" ENDPOINT VALIDATES THAT THE TARGET OBJECT EXISTS, NOT THAT IT I...
A|23703|3|    17.365 A DEEP LINK WHOSE QUERY STRING CARRIES A SEQUENTIAL INTEGER OBJECT ID IS AN UNAUTHENTICATED PII ORAC...
A|23711|3|    17.366 AN ADMIN-NAMED PROFILE-EDIT PATH IS NOT AN ADMIN GATE — WHEN AN ORDINARY ACCOUNT CAN POST TO IT, EVE...
A|23719|3|    17.367 AN EXPOSED WEBLOGIC `/console` WITH A VENDOR-DEFAULT CREDENTIAL PAIR IS UNAUTHENTICATED ADMIN ACCESS...
A|23727|3|    17.368 A USER-DIRECTORY API THAT RETURNS A SECURITY FIELD (RESET TOKEN / SESSION TOKEN) FOR AN ARBITRARY `u...
A|23737|3|    17.369 A SECURITY PRODUCT'S INTERSTITIAL PAGE IS PART OF THE ATTACK SURFACE OF EVERY SITE IT BLOCKS — IF TH...
A|23745|3|    17.370 A GRAPHQL MUTATION THAT RESOLVES ITS TARGET WITH A VISIBILITY SCOPE (`*_i_can_see`) AND HANDS IT TO ...
A|23753|3|    17.371 A SECURITY COMPONENT'S INJECTED UI IS ONLY AS TRUSTED AS THE PAGE THAT HOSTS IT — IF THE WIDGET IS S...
A|23761|3|    17.372 A COOKIE-CLEARING ROUTINE THAT COMPARES INCOMING COOKIE NAMES LOOSELY WILL ECHO THE APPLICATION'S EN...
A|23769|3|    17.373 A CHUNKED-UPLOAD ROUTE THAT VALIDATES THE SHARE TOKEN BUT NOT THE UPLOAD'S OWNERSHIP IS A CROSS-USER...
A|23779|3|    17.374 A USERNAME VALIDATOR THAT BLACKLISTS CONTROL CHARACTERS AND WHITESPACE BUT NEVER NORMALISES OR ALLOW...
A|23781|3|    17.375 A REALTIME FEED THAT PUSHES AN OBJECT IDENTIFIER BEFORE THE SUBSCRIBER IS ASSIGNED TO THAT OBJECT IS...
A|23783|3|    17.376 AN IN-APP BROWSER THAT DROPS THE SITE'S `Content-Security-Policy` HEADER CONVERTS EVERY CSP-DEFENDED...
A|23784|3|    17.377 A CNAME WHOSE TARGET IS A HOSTNAME UNDER AN UNREGISTERED DOMAIN IS A SUBDOMAIN TAKEOVER CLAIMABLE BY...
A|23786|3|    17.378 A CHILD-OBJECT ENDPOINT THAT EMBEDS THE PARENT OBJECT'S NAME AND AUTHORIZES ONLY THE CHILD'S ID LEAK...
A|23788|3|    17.379 A WORDPRESS SEARCH THAT ACCEPTS ITS TERM IN A POST BODY PARAMETER IS A TIME-BASED BLIND SQLI SINK — ...
A|23790|3|    17.380 A PROVIDER-SELECTOR PARAMETER THAT LETS YOU CHOOSE A HEADER-BASED / PASSWORDLESS AUTH BACKEND TURNS ...
A|23792|3|    17.381 A CONSENT PROMPT THAT RENDERS TOOL ARGUMENTS AS HTML WITHOUT ESCAPING IS A UI-REDRessing PRIMITIVE —...
A|23794|3|    17.382 A CDN/IMAGE ENDPOINT THAT REFLECTS ATTACKER CONTENT AND FORWARDS `Cache-Control` CAN BE TURNED INTO ...
A|23796|3|    17.383 AN OBJECT BUCKET WHOSE READS ARE GATED ONLY BY A FORGEABLE `Referer` HEADER AND WHOSE APP EXPOSES AN...
A|23798|3|    17.384 A SCOPED TOKEN WHOSE AUTHORIZATION FALLS BACK TO A BROADER CONTEXT WHEN ITS SCOPE OBJECT IS REVOKED/...
A|23800|3|    17.385 AN OBJECT-ID STATUS/LOOKUP ENDPOINT THAT RETURNS THE OWNER'S USER ID (AND THE OWNER'S INTEGRATION/EN...
A|23802|3|    17.386 A GRAPHQL FIELD WHOSE AUTHORIZATION IS WEAKER THAN THE EQUIVALENT REST ROUTE IS AN AUTHORIZATION BYP...
A|23803|3|    17.387 A BROWSER EXTENSION WHOSE CONTENT SCRIPT USES DOM EVENTS AS ITS OWN IPC LEAVES THAT CHANNEL OPEN TO ...
A|23805|3|    17.388 A FIRST-PARTY QUERY PARAMETER WHOSE VALUE IS A URL AND THAT IS PASSED THROUGH TO A THIRD-PARTY SCRIP...
A|23807|3|    17.389 A CSRF TOKEN THAT IS A DETERMINISTIC FUNCTION OF A WILDCARD-SCOPED COOKIE THE ATTACKER CAN FIXATE FR...
A|23809|3|    17.390 AN IMPORT ENDPOINT WHOSE FILE ARGUMENT IS A SERVER-SIDE PATH GUARDED ONLY BY `file_exists()` IS AN L...
A|23811|3|    17.391 WHEN A WALLET/BALANCE/TIER RESTRICTION BLOCKS AN ACTION, LOOK FOR THE ENDPOINT THAT RESETS THE GATIN...
A|23813|3|    17.392 AN LLM ASSISTANT THAT READS ATTACKER-CONTROLLED FILES AND RENDERS ITS REPLIES AS HTML IS A DATA-EXFI...
A|23815|3|    17.393 AN OBJECT ID IN A WRITE REQUEST WHOSE OWNERSHIP CHECK IS ENFORCED ON ONLY ONE BRANCH IS NOT AN AUTHO...
A|23817|3|    17.394 A REVOKE ENDPOINT THAT REQUIRES A PARAMETER THE SHIPPED CLIENT OMITS IS A NO-OP — REPLAY THE TOKEN A...
A|23819|3|    17.395 AN INVITATION-CONFIRMATION LINK THAT THE INVITER CAN READ FROM THEIR OWN DASHBOARD AND THAT IS NOT B...
A|23823|3|    17.396 A PROTOCOL WHOSE SAVINGS INTEREST IS CREDITED BY AN EXTERNAL `drip()` CALL RATHER THAN ATOMICALLY WI...
A|23825|3|    17.397 A "PRIVATE NETWORK" GUARD WHOSE CLASSIFIER CHECKS `.private?` BUT NOT `.link_local?` LETS 169.254.0....
A|23827|3|    17.398 A JSON-RPC / "invoke" ENDPOINT WHOSE PARAMETER VALUE IS DESERIALIZED IS A DIRECT UNAUTHENTICATED RCE...
A|23829|3|    17.399 A MEDIA DEMUXER'S OWN TEXT RENDERER IS AN OUTPUT-SIDE EXFIL CHANNEL — WHEN A PRODUCT TRANSCODES AN U...
A|23831|3|    17.400 AN OAUTH/OIDC CALLBACK THAT REFLECTS A QUERY PARAMETER INTO A `<script>` TAG BODY IS A REFLECTED-XSS...
A|23833|3|    17.401 A SANITISER THAT RUNS BEFORE A CHARSET CONVERSION IS NOT A SANITISER — `htmlspecialchars` ON RAW UTF...
A|23835|3|    17.402 AN `HttpOnly` SESSION COOKIE DOES NOT STOP AN XSS — CALL AN AUTHENTICATED SAME-ORIGIN API WITH `fetc...
A|23837|3|    17.403 A SANITISER THAT ENTITY-ENCODES CSS STRINGS BUT NOT CSS SELECTORS IS BYPASSED BY WRITING THE BREAKOU...
A|23841|3|    17.404 AN ARTIFACT-EXTRACT STEP THAT DEFAULTS TO THE WORKING DIRECTORY IS A FILE-OVERRIDE PRIMITIVE — A CI ...
A|23843|3|    17.405 A QUERY-LANGUAGE EXTERNAL-DATA OPERATOR THAT TAKES A URL AND AUTHENTICATES WITH THE SERVICE'S OWN TO...
A|23845|3|    17.406 A HOST-SIDE AGENT THAT INVOKES A CONTAINER-CONTROLLED BINARY BY NAME WITH ELEVATED PRIVILEGES IS A C...
A|23847|3|    17.407 A READ-ONLY CLOUD ROLE THAT CAN READ AN INTEGRATION KEY PLUS A SELF-REGISTRATION API IS A PRIVILEGE-...
A|23849|3|    17.408 A PRIVILEGED SERVICE THAT VALIDATES A CONFIG AND THEN EXECUTES IT IS A TOCTOU — RACE THE VALIDATE->E...
A|23853|3|    17.409 A PASSWORD-RESET TEMP TOKEN IS A BEARER CREDENTIAL — REPLAY IT AGAINST EVERY OTHER API ENDPOINT AND ...
A|23855|3|    17.410 A FIRST-PARTY APP CREDENTIAL EMBEDDED IN A CLIENT-SIDE BUNDLE IS A TOKEN-THEFT PRIMITIVE — BASE64-DE...
A|23857|3|    17.411 A GRAPHQL MUTATION THAT TAKES AN OBJECT ID AND MINTS A DERIVED OBJECT ID IS AN IDOR/BOLA CHAIN — SWA...
A|23859|3|    17.412 A RESET TOKEN CARRIED ALONGSIDE AN EDITABLE `userId` IS AN ATO PRIMITIVE — SWAP THE userId TO ANY AC...
A|23863|3|    17.413 A LOWER-PRIVILEGED ROLE CAN INVOKE AN ADMIN-ONLY GRAPHQL MUTATION WHEN THE ROLE CHECK TRUSTS A STATI...
A|23865|3|    17.414 A FORM PARAMETER NAMED FOR A DOCUMENT TYPE IS A PARSER SINK — CONFIRM BLIND XXE WITH AN OOB CALLBACK...
A|23867|3|    17.415 FIND THE INJECTION POINT BY BROWSING WITH A PROXY AND PICKING THE UNIQUE POST REQUEST OUT OF HTTP HI...
A|23871|3|    17.416 A BLANK ENDPOINT THAT SETS AUTHENTICATION COOKIES IS A COOKIE-MINTING ORACLE — HARVEST THE COOKIES, ...
A|23873|3|    17.417 A WORDPRESS HELPER THAT QUERIES `post_status='any'` WITHOUT A READ CHECK TURNS EVERY REFERENCE FIELD...
A|23875|3|    17.418 A WRAPPER ROUTE IS A SECOND AUTHORIZATION IMPLEMENTATION — DIFF ITS `permission_callback` AGAINST TH...
A|23877|3|    17.419 A ROLE PERSISTED AT INVITE TIME MUST BE RE-VALIDATED AT ACCEPTANCE — POST THE HIGHEST ROLE TO THE IN...
A|23879|3|    17.420 AN OAUTH LINKING FLOW WITH NO STATE IS A CSRF — CAPTURE YOUR OWN CALLBACK URL AND REPLAY IT AGAINST ...
A|23881|3|    17.421 A PDF LIBRARY THAT DOES NOT ESCAPE PARENTHESES IN ANNOTATION URIS IS AN XSS SINK — BREAK OUT OF THE ...
A|23885|3|    17.422 A PER-USER SESSION TOKEN DISCLOSED BY AN IDOR-ABLE USER-INFO API IS A BEARER CREDENTIAL — REPLAY IT ...
A|23887|3|    17.423 AUTHORIZATION IS PER-ENDPOINT, NOT PER-ACTION — ENUMERATE THE PARAMETERS OF A HIGHER-PRIVILEGE SIBLI...
A|23889|3|    17.424 A ROLE DOWNGRADE MUST REPLACE THE PERMISSION SET, NOT MERGE INTO IT — DOWNGRADE A TEST ACCOUNT AND R...
A|23893|3|    17.425 A THIRD-PARTY ANALYTICS BEACON ON A PAGE WHOSE URL CARRIES A SECRET IS A DISCLOSURE CHANNEL — PROXY ...
A|23897|3|    17.426 A CREDENTIAL IN A URL IS A CREDENTIAL IN THE WEB ARCHIVE — ENUMERATE THE WAYBACK CDX FOR THE TARGET'...
A|23901|3|    17.427 A WRITE ENDPOINT'S VALIDATION-ERROR PATH IS A SECOND SERIALIZER — STRIP THE PAYLOAD DOWN TO THE OBJE...
A|23906|3|    17.428 A URL VALIDATOR THAT CHECKS ONLY THE HOSTNAME OF A THIRD-PARTY DOMAIN IS NOT AN SSRF CONTROL — THE A...
A|23908|3|    17.429 A FILTER WHOSE SCAN RANGE STOPS AT 0x7F IS DEFEATED BY INSERTING A HIGH BYTE (%80-%FF) INTO THE PAYL...
A|23910|3|    17.430 A SECURE-TOKEN CALLBACK THAT ONLY FILLS A BLANK FIELD IS NOT A VALIDATOR, AND A STORAGE PATH BUILT B...
A|23912|3|    17.431 A CONSENT SCREEN OPENED IN A NEW TOP-LEVEL WINDOW IS NOT PROTECTED BY `X-FRAME-OPTIONS` — ALIGN A DE...
A|23914|3|    17.432 SESSION INVALIDATION MUST BE TESTED ON EVERY CREDENTIAL-CHANGE SURFACE — THE ADMIN CLI/API PATH IS T...
A|23918|3|    17.433 A SIGNED URL'S SIGNATURE MUST COVER EVERY PARAMETER THAT CHANGES HOW THE OBJECT IS SERVED — IF `resp...
A|23922|3|    17.434 A "SECRET TOKEN" THAT IS IMPLEMENTED AS A SEQUENTIAL INTEGER IS NOT A SECRET — THE ENDPOINT'S OWN TO...
A|23924|3|    17.435 WHEN A PARSER DERIVES AN OUTPUT PATH FROM A FIELD INSIDE THE INPUT ARTIFACT, THE TRAVERSAL PAYLOAD L...
A|23928|3|    17.436 ANY CODE EXECUTION IN A DEFAULT-BRANCH GITHUB ACTIONS WORKFLOW IS A CACHE-POISONING PRIMITIVE — STEA...
A|23930|3|    17.437 A SETUP/BOOTSTRAP ENDPOINT THAT AUTHENTICATES A LOW-PRIVILEGE CONSOLE ROLE BUT PERFORMS A CREDENTIAL...
A|23934|3|    17.438 A COOKIE THE PRODUCT DESERIALIZES WITH .NET BINARYFORMATTER IS AN RCE ENTRY POINT — AND THE GADGET C...
A|23936|3|    17.439 A SANITIZER THAT ESCAPES ONE QUOTE CHARACTER ALMOST NEVER ESCAPES THE OTHER — PROBE WITH DOUBLE QUOT...
A|23940|3|    17.440 THE AURA ENDPOINT IS A GENERIC METHOD DISPATCHER KEYED BY THE `descriptor` STRING — SWAP THE DESCRIP...
A|23942|3|    17.441 ON A JSON API ERROR PAGE THE REFLECTED TOKEN MAY BE A FIELD NAME RATHER THAN A VALUE — KEYCLOAK'S OI...
A|23944|3|    17.442 A SEARCH/COUNT ENDPOINT THAT MATCHES NON-PUBLIC CONTENT AND RETURNS A HIT COUNT IS A BOOLEAN ORACLE ...
A|23946|3|    17.443 A KUBERNETES `Service` OF TYPE `ExternalName` POINTED AT `kubernetes.default` TURNS ANY INGRESS INTO...
A|23948|3|    17.444 A CLIENT ACCOUNT-SWITCH THAT TREATS POSSESSION OF A LINKED THIRD-PARTY CREDENTIAL AS PROOF OF THE FI...
A|23950|3|    17.445 A SANITIZER THAT DELETES A SEPARATOR BLOCKLIST CAN ITSELF PRESERVE A SEPARATOR WHEN THE DELETION PRI...
A|23954|3|    17.446 THE GLOBAL GRAPHQL `node(id:)` INTERFACE IS A UUID-ORACLE WHEN ITS ID IS THE MODEL'S AUTO-INCREMENT ...
A|23956|3|    17.447 A TOKENIZED INCOMING-MAIL ALIAS AT THE CORPORATE DOMAIN IS AN IDENTITY PRIMITIVE — MINT AN ADDRESS T...
A|23960|3|    17.448 A DOCUMENTED RESTRICTED / VIEW-ONLY MODE THAT IS ENFORCED INSIDE INDIVIDUAL HANDLERS IS A DENY-LIST ...
A|23962|3|    17.449 AN IMPORT PATH THAT RESOLVES ATTACKER-SUPPLIED GLOBAL OBJECT REFERENCES WITHOUT A TENANT CHECK, WHIL...
A|23964|3|    17.450 A REMOTE-RESOURCE BLOCKLIST IS ONLY AS STRONG AS ITS ELEMENT/ATTRIBUTE COVERAGE: THE SANITIZER THAT ...
A|23968|3|    17.451 A FREE-TEXT BUSINESS FIELD IN AN UNAUTHENTICATED CHECKOUT/PAYMENT ACTION IS A SERVER-SIDE FETCH SINK...
A|23972|3|    17.453 A JS BUILT-IN OVERRIDE THAT CAPTURES A PRIVILEGED OBJECT THE APP'S OWN CODE INVOKES THROUGH `Functio...
A|23974|3|    17.454 A REALTIME PUSH-CHANNEL NAME THAT THE CALLER CONTROLS BUT THE SERVER DOES NOT BIND TO THE CALLER'S S...
A|23976|3|    17.455 A NETWORK PERMISSION THAT ONLY INSPECTS TCP HOSTS IS BYPASSED BY A UNIX DOMAIN SOCKET PATH (Node.js,...
A|23980|3|    17.456 A CHARACTER DENYLIST THAT BLOCKS QUOTES IS NOT A SANITISER ON POSTGRESQL — `$tag$…$tag$` DOLLAR-QUOT...
A|23982|3|    17.457 AN UNAUTHENTICATED INBOUND THIRD-PARTY WEBHOOK THAT FETCHES A CALLER-SUPPLIED MEDIA/ATTACHMENT URL A...
A|23986|3|    17.458 A NESTED REST ROUTE WHOSE PARENT OBJECT IS A PATH SEGMENT AND WHOSE ACL CHECKS ONLY THE CALLER IS A ...
A|23988|3|    17.459 A SELF-SERVICE URL FIELD THAT THE SERVER FETCHES AND ECHOES A CHALLENGE/RESPONSE FOR IS A FULL-READ ...
A|23990|3|    17.460 AN OPEN `/wp-json` ROUTE INDEX IS A MAP OF UNDOCUMENTED PLUGIN ENDPOINTS — PAIR THE ROUTE THAT DISCL...
A|23994|3|    17.461 A SETTINGS PERMISSION THAT CONTROLS THE OUTBOUND MAIL TRANSPORT IS A USER-MANAGEMENT PERMISSION IN D...
A|23998|3|    17.462 A CAPTCHA/LOCKOUT COUNTER KEYED ON A CLIENT-SUPPLIED IP HEADER IS NOT A THROTTLE — ROTATE `X-Forward...
A|24000|3|    17.463 AN OAUTH AUTHORIZATION CODE / REFRESH TOKEN MUST BE CONSUMED ATOMICALLY — FIRE THE TOKEN REQUEST CON...
A|24004|3|    17.464 A SELF-SERVICE OAUTH CLIENT-REGISTRATION `redirect_uris` FIELD WITH NO SCHEME ALLOWLIST IS A STORED-...
A|24006|3|    17.465 A SEAT LIMIT ENFORCED ONLY WHEN THE INVITATION IS CREATED IS NOT A LIMIT — A PENDING INVITATION IS A...
A|24008|3|    17.466 IN RAILS 7.0/7.1 THE CONTROLLER'S `translate` HELPER MARKS `_html`-SUFFIXED KEYS AND UNESCAPED `defa...
A|24012|3|    17.467 A PERMISSION MUTATION FIRED WHILE AN OBJECT IS IN A TRANSITIONAL STATE IS AUTHORIZED AGAINST THE PRE...
A|24014|3|    17.468 AN IMMUTABILITY WINDOW ENFORCED ONLY AGAINST THE AUTHOR IS NOT IMMUTABILITY — A PRIVILEGED ROLE'S "E...
A|24018|3|    17.469 A DESKTOP APP THAT PASSES A USER-CONFIGURABLE URL TO `ShellExecute` AFTER ONLY A "STARTS WITH http:/...
A|24022|3|    17.470 AN EXPORTED ANDROID ACTIVITY THAT LOADS AN INTENT-SUPPLIED `html` EXTRA INTO A WEBVIEW IS AN XSS-TO-...
A|24024|3|    17.471 A WHITESPACE BYTE AFTER A RECOGNISED HEADER TOKEN (NOT BEFORE IT) CAN DROP THE PARSER'S PENDING STAT...
A|24028|2|  §17 additions — reader pass 2026-11-11 batch 162 (1 entry appended, §17.472)
A|24030|3|    17.472 AN ITEM-LEVEL STATUS ENDPOINT THAT NEVER RE-VALIDATES THE BATCH CONTEXT LETS A CUSTOMER DRIVE A BATC...
A|24034|2|  §17 additions — reader pass 2026-11-11 batch 163 (2 entries appended, §17.473–§17.474)
A|24036|3|    17.473 A FIRST-RUN INITIALISATION THAT CREATES ITS PER-USER DATA DIRECTORY ONLY IF ABSENT, WITHOUT VERIFYIN...
A|24038|3|    17.474 AN ORIGIN CHECK THAT COMPARES THE HOST OF A USER-SUPPLIED URL AGAINST AN EXPECTED HOST IS BYPASSABLE...
A|24042|3|    17.475 AN INTEGRATION/"CONNECT <THIRD-PARTY>" INIT ENDPOINT IS ITSELF AN AUTHORIZATION SURFACE — WHEN THE R...
A|24044|3|    17.476 AN ANONYMITY TOGGLE THAT SUPPRESSES THE NAME BUT NOT THE AVATAR IS NOT ANONYMITY — THE BULK EXPORT I...
A|24048|3|    17.477 AN INVITE/ACCEPT TOKEN THAT IS NOT BOUND TO THE TENANT THAT ISSUED IT IS A CROSS-TENANT ACCOUNT-CREA...
A|24052|3|    17.478 A DELETE/CLEANUP GUARD THAT DERIVES ITS CONFINEMENT DIRECTORY FROM THE SAME ATTACKER-CONTROLLED FIEL...
A|24056|3|    17.479 AN AUTH GATE THAT APPEARS ON ONE VALUE OF A NUMERIC PATH/INSTANCE SEGMENT IS PER-VALUE, NOT PER-FUNC...
A|24060|3|    17.480 A QUOTE-ESCAPE HELPER DOES NOT PROTECT A VALUE INTERPOLATED INTO A COMMENT IN GENERATED CODE — THE P...
A|24062|3|    17.481 EXECUTION AFTER REDIRECT (EAR): THE 302 BODY ALREADY CONTAINS THE FULL PRIVILEGED PAGE — FLIP THE ST...
A|24064|3|    17.482 AN ACCOUNT-LIFECYCLE-STATE RULE (`deactivated`) ENFORCED ON THE REST API IS SILENTLY SKIPPED BY THE ...
A|24066|3|    17.483 A DESKTOP APP'S DOWNLOAD-AND-AUTO-OPEN PATH IS AN RCE SINK WHOSE GATE IS (a) AN UNANCHORED INTERNAL-...
A|24070|3|    17.484 A PRIVILEGED INSTALLER/HELPER THAT (RE)WRITES SHARED-PATH SYMLINKS AT A USER-SUPPLIED `--app-path` —...
A|24072|3|    17.485 ANY "CONNECT YOUR OWN DATABASE" FEATURE IS A CLIENT-SIDE FILE READ WHEN `local_infile` IS ON: POINT ...
A|24074|3|    17.486 ACL/EVALUATION ORDER: A FEATURE-TRIAL FLAG CHECK (`return_true_if { feature_enabled?(TRIAL) }`) PLAC...
A|24078|3|    17.487 A PRE-AUTH CONTACT/TICKET INTAKE API IS AN UNAUTHENTICATED STORED-XSS CHANNEL INTO THE STAFF BACK-OF...
A|24080|3|    17.488 USER-AUTHORED RULES COMPILED INTO STORED PHP (`compiledlimitations`, evaluated on every banner deliv...
A|24082|3|    17.489 A STYLE SANITIZER THAT FIXES STRING-TOKEN BOUNDARIES BEFORE DECODING CSS CHARACTER ESCAPES CAN BE TO...
A|24134|3|    17.508 THE PRICE MUST BE RECOMPUTED AGAINST THE FINAL INPUTS AT BOOKING TIME — IF THE CONFIRMATION STEP ACC...
A|24138|3|    17.509 A PASSWORD-RESET TOKEN BUILT FROM PUBLIC VALUES PLUS A TIMESTAMP THE RESPONSE HANDS YOU IS NOT A TOK...
A|24140|3|    17.510 A TYPE TAG IN A JSON BODY (`@class` / `@type`) IS A REQUEST TO CONSTRUCT AN OBJECT OF THE ATTACKER'S...
A|24144|3|    17.511 WHEN USER INPUT IS COMPILED INTO GENERATED SOURCE, THE COMMENT IT SITS IN IS THE BOUNDARY — AND IN A...
A|24146|3|    17.512 A USER-SUPPLIED JDBC URL REACHING `DriverManager.getConnection` IS AN RCE PRIMITIVE: THE DRIVER'S UR...
A|24148|3|    17.513 AN ATTACKER-CONTROLLED PROPERTY NAME IS AS DANGEROUS AS AN ATTACKER-CONTROLLED VALUE: `obj[key]=valu...
A|24152|3|    17.514 WHEN ONE VALUE IS INTERPOLATED INTO A GENERATED SCRIPT AT MORE THAN ONE PLACE, EVERY SYNTAX ERROR YO...
A|24154|3|    17.515 A FIXED-SIZE INTERNAL MESSAGE BUFFER PLUS A HANDLER THAT RESOLVES A REQUEST BEFORE ITS BODY IS CONSU...
A|24156|3|    17.516 AN AUTO-UPDATE / REPUTATION-DATABASE MANIFEST IS CODE INPUT: IF ANY OF ITS FIELDS (`filename`, `url`...
A|24160|3|    17.517 IN AN ELECTRON DESKTOP CLIENT THE `webPreferences` HARDENING EVERYONE CHECKS (`nodeIntegration:false...
A|24162|3|    17.518 A STORED XSS THAT FIRES IN AN ADMIN SESSION IS THE REQUEST-TRANSPORT FOR EXPLOITING A BLIND SQLI THA...
A|24164|3|    17.519 WHEN AN AUTHENTICATION REQUEST CARRIES A CLIENT-SUPPLIED USER ID NEXT TO THE CREDENTIALS, SWAPPING I...
A|24166|3|    17.520 THE URL FRAGMENT IS THE ONLY PART OF `window.location`/`document.URL` THAT IS NEVER PERCENT-ENCODED ...
A|24170|3|    17.521 AN XSS THAT FIRES ON A LOGIN OR ACCOUNT ORIGIN IS A CREDENTIAL-STEALING AND ACCOUNT-REBINDING POSITI...
A|24172|3|    17.522 A CRLF RESPONSE SPLIT THAT CAN SET A PARENT-DOMAIN COOKIE IS A CROSS-SUBDOMAIN INJECTION PRIMITIVE —...
A|24174|3|    17.523 WHEN A FIX TURNS A RAW PARAMETER INTO "MUST BE A BASE64 SERIALIZED OBJECT", SATISFY THE VALIDATOR WI...
A|24265|3|    17.564 A URL-VALUED FIELD THAT A PRIVILEGED USER'S BROWSER LATER FETCHES IS A FORCED-BROWSING GADGET — THE ...
A|24350|3|    17.596 THE RECIPIENT FIELD OF A NOTIFICATION-DISPATCH API IS AN OBJECT REFERENCE — tamper the body `email` ...
A|24358|3|    17.597 A FEATURE RESTRICTION IS A CANONICAL-ROUTE FILTER, NOT A DATA ACL — the project-scoped SEARCH API re...
A|24601|3|    17.683 A SIGNATURE CHECK WHOSE SIGNER NAME, SIGNER CERT AND REVOCATION DATA ALL RIDE THE CHANNEL BEING MITM...
A|24603|3|    17.684 A FIREWALL SCOPED TO ONE ADDRESS OF A MULTI-ADDRESS INTERNAL SERVICE IS NOT ACCESS CONTROL: WALK THE...
A|24605|3|    17.685 A FEATURE THAT FETCHES A TARGET AND COMPARES THE RESPONSE TO AN ATTACKER-SUPPLIED STRING IS A BLIND ...
A|24607|3|    17.686 THE PDF GENERATOR IS THE DEPENDENCY: FINGERPRINT IT (ERROR BANNER + VERSION EMBEDDED IN THE PDF META...
A|24609|3|    17.687 A DATA-URI/BASE64 ECHO OF A FETCHED URL IS A FULL-READ CHANNEL: ALWAYS DECODE THE BLOB BEFORE CALLIN...
A|24613|3|    17.688 DELTA: TWO `@` SIGNS IN ONE AUTHORITY MAKE TWO PARSERS SEE TWO DIFFERENT HOSTS — APACHE HTTPCLIENT'S...
A|24615|3|    17.689 WHEN VALIDATION AND FETCH PARSE THE SAME STRING DIFFERENTLY, THE HOST THE FILTER SEES IS NOT THE HOS...
A|24617|3|    17.690 THE ERROR TEXT OF A SERVER-SIDE FETCH IS THE FETCHED SERVICE'S REPLY: `wrong status line: "SSH-2.0-O...
A|24759|3|    17.734 CSP DOES NOT NEUTRALIZE HTML INJECTION IN A TRUSTED UI: STORED HTML IN A PASSWORD-MANAGER EXTENSION'...
A|24761|3|    17.735 AUTHORIZE AGAINST THE TIER THAT OWNS THE RESOURCE: A CLAIM/OWNERSHIP-TRANSFER MUTATION ON A SHARED P...
A|24763|3|    17.736 OPAQUE IDENTIFIERS ARE A SERIALIZATION CHOICE, NOT ACCESS CONTROL: A CALLER-SET RESPONSE-MODE PARAME...
A|24767|3|    17.737 A NAME-BASED SYMLINK KEEP-LIST IS DEFEATED BY A LINE BREAK: AN ARCHIVE ENTRY NAMED `.`+NEWLINE+`x` M...
A|24771|3|    17.738 THE SOCIAL-LOGIN ACCOUNT KEY MUST COME FROM THE SERVER-SIDE VERIFIED TOKEN RESPONSE, NEVER FROM A RE...
A|24773|3|    17.739 STATE SET BY A LOWER-PRIVILEGED ACTOR NEEDS AN OWNER OVERRIDE IN EVERY TYPE BRANCH, A TTL, AND LIFEC...
A|24775|3|    17.740 AUTHORIZE PER REFERENCED ID, NOT JUST THE ANCHOR: A RELATIONSHIP MUTATION THAT PASSES `ensure_can_*`...
A|24779|3|    17.741 THE SHARE/ACL LISTING IS ITS OWN AUTHORIZATION SURFACE: THE SHARE INDEX KEYED BY AN ENUMERABLE OBJEC...
A|24781|3|    17.742 AN ENTRY DEEP LINK THAT MINTS A SESSION BEFORE ANY CREDENTIAL STEP IS AN AUTHENTICATION BYPASS — REA...
A|24785|3|    17.743 THE NAVIGATION GRAPH IS AN API: AN EXPORTED ACTIVITY THAT ROUTES AN UNREGISTERED SCHEME TO EVERY NAV...
A|24787|3|    17.744 AN `exec()` ALLOWLISTED TO MONITORING PLUGINS IS NOT A COMMAND BOUNDARY: SSRF PAST A DENYLIST THAT I...
A|24879|1|============================================================================
A|24880|2|  >> BATCH 2026-11-14 — operator's paid-report corpus: new variants, routing rows, recon atoms
A|24881|1|============================================================================
A|24891|2|  V-19: Guard-layer bypass by path shape, judged by the error-code LAYER
A|24912|2|  V-20: `/public/` unauthenticated API surface + two-step identifier chaining
A|24926|2|  V-21: Unauthenticated server-computed quote manipulation (aberrant quantity / sign)
A|24941|2|  V-22: CSRF delivery shapes for state-changing GET and base64 SAML/OAuth parameters
A|24956|2|  V-23: XSS under a WAF — entity-encoding bypass + the retest-after-fix protocol
A|24972|2|  V-24: Data-store proxy read — URL segment as index + encoded-metachar edge bypass
A|24985|2|  V-25: Crypto/credential material in the bundle → mint the application's own credentials
A|25000|2|  V-26: UI-gate-only preconditions + the sibling-action status differential
A|25013|2|  V-27: External-dependency takeover frontier (script-src host / published-email domain / delegated NS)
A|25029|2|  V-28: Component finding proved from public source (version → tag source → changelog-after → live input)
A|25040|3|    Routing rows added (append to the technique routing table)
A|25054|3|    Binding habits this batch adds
A|25065|1|============================================================================
A|25066|2|  >> BATCH 2026-11-14 (batch 308) — server-rendered template platform: operator report corpus (Magentrix Clou...
A|25067|1|============================================================================
A|25076|2|  V-29: Server-rendered template platform — the create-time content filter is not the render path
A|25104|2|  V-30: Extract-before-validate — archive entry names write payloads into compiled/served paths
A|25122|2|  V-31: Template-substitution special tokens (`$'`, `` $` ``, `$&`) — config-section injection → the app's ow...
A|25142|2|  V-32: File-store containment is per parameter AND per verb
A|25162|2|  V-33: Blind-injection oracles on filter and sort parameters (size + type-error)
A|25181|2|  V-34: SSRF that STORES its response — the serving route is the exfiltration channel
A|25200|2|  V-35: Deserialization gadget chosen by the payload + `respond_to?` dispatch → argv injection
A|25218|3|    Routing rows added (append to the technique routing table)
A|25230|3|    Binding habits this batch adds

===== FILE B: /root/bugbountyhuntingskills.md =====
B|1|1|Bug Bounty Hunting Skills
B|35|2|  0. AGENT DECISION TREE — route by observation (READ THIS FIRST)
B|102|2|  1. Cross-Site Scripting (XSS)
B|104|3|    1.1 Write-time vs. read-time sanitization gap — WordPress plugin admin notice
B|131|3|    1.2 Sanitizer bypass at the HTML-generation layer + CSP bypass — GitLab comments
B|156|3|    1.3 Client-side sink discovery via hash parsing → prototype pollution → gadget
B|180|3|    1.4 Upload/parser-based stored XSS (media handling)
B|198|3|    1.5 Filter-logic bypass by shape, not by payload list
B|221|3|    1.6 Third-party / infrastructure inheritance (dangling CNAME)
B|238|2|  2. Server-Side Request Forgery (SSRF)
B|240|3|    2.1 User-controlled URL parameter on an unauthenticated endpoint
B|258|3|    2.2 SSRF used as a *response oracle* — internal fetch output echoed in an error message
B|280|3|    2.3 Feature that "tests" a user URL — webhook validation button
B|297|3|    2.4 Mitigation bypass: redirect chain + URL-decode smuggling
B|321|3|    2.5 Known-vulnerable component with a URL parameter
B|339|3|    2.6 Probing localhost services from inside a browser context
B|356|2|  3. IDOR / BOLA (Broken Object Level Authorization)
B|358|3|    3.1 Swap the identifier in a path parameter, then enumerate
B|380|3|    3.2 Identifier discovery from a public surface
B|400|3|    3.3 State-changing side effects beat data disclosure
B|422|3|    3.4 GraphQL mutation enumeration
B|439|3|    3.5 Zombie endpoints extracted from a mobile binary
B|458|2|  4. Cross-cutting methodology extracted from the set
B|482|2|  5. Reusable test checklist
B|500|2|  6. Source index
B|540|1|Part II — Injection, Disclosure, Auth Bypass, ATO, Command Execution
B|549|2|  7. SQL Injection
B|551|3|    7.1 Array parameter defeats scalar sanitization — ImpressCMS
B|597|3|    7.2 Unauthenticated SQLi in a plugin → insecure deserialization → RCE — Krisp
B|622|3|    7.3 Login-form SQLi (auth bypass) and the surrounding auth surface
B|652|3|    7.4 SQLi detection ladder (synthesis of the above)
B|667|3|    7.5 Django ORM `FilteredRelation` alias injection → RCE — CVE-2025-57833
B|695|3|    7.6 PostgreSQL `IN`-list array-key injection — Drupal CVE-2026-9082
B|738|3|    7.7 SQLi via the POST **parameter name** — NASA Space Place (Bugcrowd disclosure)
B|766|3|    7.8 Time-based blind SQLi in an `ORDER BY` / `sort` parameter — NASA JPL Photojournal
B|793|3|    7.9 Boolean-blind over Oracle with binary search — NASA REST API (Bugcrowd disclosure)
B|819|3|    7.10 BigQuery SQL injection — non-standard syntax and system-variable oracles
B|856|3|    7.11 mysqljs/mysql escape bypass via JavaScript object type coercion
B|897|2|  8. Path Traversal, LFI and the LFI→SSRF→RCE chain
B|899|3|    8.1 Non-recursive filter removal — `....//`
B|919|3|    8.2 Validate-then-decode ordering + hashed upload names
B|945|3|    8.3 `readfile()` is both LFI and SSRF — SaaS download endpoint
B|970|3|    8.4 Path traversal in the multipart *filename*
B|993|3|    8.5 When the app appends an extension: null byte, truncation, wrappers
B|1018|3|    8.6 LFI → RCE via log poisoning
B|1038|3|    8.7 Fragment + base64 to defeat extension whitelists — Evernote SSRF
B|1064|3|    8.8 Path traversal as a *cache* primitive — ChatGPT wildcard cache deception
B|1088|2|  9. Source code, `.git`, `.env` and GitHub exposure
B|1090|3|    9.1 Exposed `.git/` → full source → credentials → admin
B|1119|3|    9.2 `.env` reachable only through the origin/CNAME
B|1140|3|    9.3 Desktop app bundle → leftover `.env` → org-wide GitHub token — Shopify
B|1169|3|    9.4 Backup archives and `.bak` files
B|1194|3|    9.5 GitHub dorking with the API (not the web UI)
B|1227|3|    9.6 CI/CD as a credential store — anonymous Jenkins
B|1247|2|  10. Information disclosure and PII
B|1249|3|    10.1 A framework upgrade changed serialization semantics — HackerOne `.json`
B|1275|3|    10.2 GraphQL field-level authorization missing — HackerOne
B|1298|3|    10.3 REST user enumeration and PII endpoints
B|1317|3|    10.4 Parameter-driven PII on a third-party fulfilment link
B|1333|3|    10.5 Memory disclosure through an image library — Basecamp
B|1351|3|    10.6 Disclosure checklist (synthesis)
B|1366|2|  11. Authentication and header-based bypass
B|1368|3|    11.1 Underscore/dash header smuggling — mTLS header forgery
B|1417|3|    11.2 JWT: the five implementation bugs worth testing first
B|1453|3|    11.3 OAuth + "forgot password" → account takeover (UUID linking)
B|1477|3|    11.4 Host header injection → reset-link poisoning
B|1501|3|    11.5 TE.0 HTTP request smuggling — mass zero-click ATO
B|1541|3|    11.6 Miscellaneous bypass patterns worth a permanent slot
B|1557|2|  12. Account takeover and XSS chains
B|1559|3|    12.1 XSS → email change → ATO (the standard escalation)
B|1585|3|    12.2 Cookie theft is not the impact — replaying it is
B|1603|3|    12.3 HTML injection in a desktop app → Electron RCE (Slack)
B|1633|3|    12.4 Cache deception + client-side path traversal → ATO
B|1654|3|    12.5 Zero-click variants (what "zero-click" actually means here)
B|1668|2|  13. Command injection and code execution
B|1670|3|    13.1 Template value → shell string (Airflow example DAGs)
B|1702|3|    13.2 Chat-command arguments → `$()` substitution
B|1724|3|    13.3 JSON field → `execFile` without sanitization
B|1742|3|    13.4 Import pipeline: branch name → command execution (GitHub)
B|1760|3|    13.5 Arbitrary file write → `authorized_keys` → command execution
B|1786|3|    13.6 Driver-mediated RCE: upload + SSRF to a local JMX agent
B|1807|3|    13.7 Argument injection into `ProxyCommand`
B|1825|3|    13.8 Command-injection detection ladder
B|1840|2|  14. Dorking tradecraft (how to actually run the templates)
B|1856|1|SQLi / RCE
B|1860|1|Traversal / LFI / SSRF
B|1864|1|Source / git / env
B|1868|1|Information disclosure
B|1872|1|Auth / header
B|1876|1|ATO / XSS
B|1880|1|Command injection
B|1905|2|  15. Master checklist (Part II)
B|1954|2|  16. Source index — Part II
B|2013|2|  17. Knowledge intake — appended methodology (research pass 2026-11-07)
B|2024|3|    17.1 SAML XML Signature Wrapping (XSW) — validated-signature/handled-node confusion → IdP-cert forgery → au...
B|2037|3|    17.2 MongoDB operator injection in the access_token query parameter — unauthenticated auth bypass → admin
B|2049|3|    17.3 GraphQL free-form `filter` JSON → JS-library `$where` → `new Function` → unauthenticated RCE in the No...
B|2063|3|    17.4 WordPress REST batch endpoint route-dispatch desync → unauthenticated blind SQLi (string where an arra...
B|2076|3|    17.5 SSRF filter bypass via the NAT64 local-use IPv6 prefix `64:ff9b:1::/48`
B|2089|3|    17.6 Unescaped dot in the redirect allowlist regex → open redirect → cross-domain auth-token theft → 1-clic...
B|2102|3|    17.7 Access-denied response body still leaks the protected object (HTTP 422 "not authorized" carries `conte...
B|2114|3|    17.8 Default/empty signing key → forged HMAC JWT → service "join" → full admin token (JFrog Artifactory)
B|2127|3|    17.9 Password-reset email param as a JSON ARRAY (scalar→array type confusion) → reset token mailed to attac...
B|2140|3|    17.10 Ruby Octokit/Sawyer method override → redis RESP size-desync → injected Redis command → Marshal.load ...
B|2158|2|  Knowledge intake — reader pass 2026-11-07 (batch: 6 reports)
B|2391|2|  Knowledge intake — reader pass 2026-11-07 (batch 3: 6 reports — GitLab import/IDOR, PayPal smuggling, mruby...
B|2659|2|  Knowledge intake — reader pass 2026-11-07 (batch 4: 6 sources — GitLab project-template privilege escalatio...
B|2718|2|  Knowledge intake — reader pass 2026-11-07 (batch 5: 6 sources — GitLab Nuget package-registry metadata path...
B|2820|2|  Knowledge intake — reader pass 2026-11-07 (batch 7: 6 sources — HackerOne `/skills` cross-applicant proof l...
B|2878|2|  Knowledge intake — reader pass 2026-11-07 (batch 8: 6 sources — HackerOne embedded-submission authorization...
B|2924|2|  Knowledge intake — reader pass 2026-11-07 (batch 9: 6 sources — Uber password-reset token returned in the r...
B|3237|2|  Knowledge intake — report-reader pass 2026-11-07 (batch 14: 6 sources, all 6 readable, 6 new entries)
B|3730|2|  Knowledge intake — report-reader pass 2026-11-07 (batch 21: 6 sources — GraphQL persisted-operation IDOR on...
B|3791|2|  Knowledge intake — report-reader pass 2026-11-07 (batch 22: 6 sources — Shopify SVG XML-ENTITY whitelist by...
B|3994|2|  Knowledge intake — report-reader pass 2026-11-07 (batch 25: 6 sources — managed-control-plane SSRF from a c...
B|4065|2|  Knowledge intake — report-reader pass 2026-11-07 (batch 26: 6 sources — the Adobe Flash Player memory-corru...
B|4139|2|  Knowledge intake — report-reader pass 2026-11-07 (batch 27: 6 sources — Dropbox/HelloSign SSRF #923132, Dro...
B|4427|2|  Knowledge intake — reader pass 2026-11-07 (batch 32: 6 sources — GitLab Rails reserved-routing-key XSS (#94...
B|8087|2|  Knowledge intake — report-reader pass 2026-11-08 (batch 78: 6 assigned sources, read one by one in the give...
B|8175|2|  Knowledge intake — report-reader pass 2026-11-08 (batch 79: 6 assigned sources, read one by one in the give...
B|8219|2|  Knowledge intake — report-reader pass 2026-11-08 (batch 80: 6 assigned sources, read one by one in the give...
B|8280|2|  Knowledge intake — report-reader pass 2026-11-08 (batch 81: 6 assigned sources, read one by one in the give...
B|8295|2|  §17.276 — Hasura GraphQL: the per-role introspection dump IS the permission map (unauth read + write grants...
B|8372|2|  Knowledge intake — report-reader pass 2026-11-08 (batch 82: 6 assigned sources, read one by one in the give...
B|8398|2|  Knowledge intake — report-reader pass 2026-11-08 (batch 84: 6 assigned sources, read one by one in the give...
B|8441|2|  Knowledge intake — report-reader pass 2026-11-08 (batch 85: 6 assigned sources read one by one in the given...
B|8507|2|  Knowledge intake — report-reader pass 2026-11-08 (batch 86: 6 assigned sources read one by one in the given...
B|8944|2|  Knowledge intake — report-reader pass 2026-11-08 (batch 93: 6 assigned sources read ONE BY ONE in the given...
B|12354|2|  VALID BUT NOT APPENDED (nothing new, nothing invented)
B|12365|2|  Batch 145 — 6 sources, read ONE BY ONE in the assigned order (2026-11-11)
B|12369|3|    RESULT: 2 entries appended (2 new §17 slots); 6 sources read, 0 fabricated
B|12407|2|  VALID BUT NOT APPENDED (nothing new, nothing invented)
B|12473|2|  VALID BUT NOT APPENDED (nothing new, nothing invented)
B|12483|2|  PASS 2026-11-11 (batch 144) — NOTHING NEW, 0 APPENDED
B|12543|2|  PASS 2026-11-11 (batch 147) — NOTHING NEW, 0 APPENDED
B|14000|2|  Batch 159 — 6 sources, read ONE BY ONE in the assigned order (2026-11-11)
B|14006|3|    RESULT: 2 entries appended (2 new §17 slots); 6 sources read, 0 fabricated
B|14061|2|  Batch 160 — 6 sources, read ONE BY ONE in the assigned order (2026-11-11)
B|14067|3|    RESULT: 1 entry appended (1 new §17 slot); 6 sources read, 0 fabricated
B|14110|2|  Batch 161 — 6 sources, read ONE BY ONE in the assigned order (2026-11-11)
B|14116|3|    RESULT: 2 entries appended (2 new §17 slots); 6 sources read, 0 fabricated
B|14171|2|  Batch 162 — 6 sources, read ONE BY ONE in the assigned order (2026-11-11)
B|14177|3|    RESULT: 1 entry appended (1 new §17 slot, §17.472); 6 sources read, 0 fabricated, 0 invented
B|21975|2|  PASS 2026-11-14 (batch 308) — operator report corpus: a server-rendered template platform (Magentrix Cloud ...
B|21986|3|    §17.788 — A CREATE-TIME CONTENT DENYLIST IS NOT A CONTROL ON THE RENDER PATH: A TEXT FILTER IS DEFEATED BY ...
B|22006|3|    §17.789 — TEMPLATE POISONING BY AN ACCEPTED WRITE PRIMITIVE INTO THE COMPILED-TEMPLATE DIRECTORY: THE FILTE...
B|22027|3|    §17.790 — EXTRACT-BEFORE-VALIDATE: WHEN AN ARCHIVE IS UNPACKED BEFORE ITS ENTRY NAMES ARE VALIDATED, A `..\...
B|22046|3|    §17.791 — STRING-REPLACEMENT SUBSTITUTION TOKENS (`$'`, `` $` ``, `$&`, `$<n>`) ARE A NEWLINE+QUOTE SMUGGLI...
B|22065|3|    §17.792 — CONTAINMENT MUST BE ENFORCED PER PARAMETER AND PER VERB: A SANITIZED FILENAME DOES NOT PROTECT TH...
B|22085|3|    §17.793 — A FILTER-EXPRESSION MINI-LANGUAGE WITH A DATABASE ESCAPE HATCH IS A SQLi SURFACE: AN UNVALIDATED ...
B|22105|3|    §17.794 — A SORT CLAUSE HANDED VERBATIM TO THE ORM IS SQLi EVEN BEHIND A TOKEN BLACKLIST: WITH AN AGGREGATE...
B|22125|3|    §17.795 — AN SSRF THAT STORES WHAT IT FETCHED TURNS THE STORAGE ROUTE INTO THE EXFILTRATION CHANNEL (the fe...
B|22145|3|    §17.796 — DESERIALIZATION GADGET CHOSEN BY A KEY IN THE PAYLOAD GRAPH + `respond_to?` DISPATCH = RCE: WHEN ...
B|22165|3|    CARRIER-DELTA ENTRIES (no §17 slot; recorded so no later pass re-opens them)
B|22179|3|    METHODS HABIT ADDED BY THIS CORPUS (binds every future report)
