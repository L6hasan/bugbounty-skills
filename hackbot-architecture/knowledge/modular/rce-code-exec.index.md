# rce-code-exec INDEX — grep this, then read_file(<part>, offset=<line-1>)
# 94 segments / 17 part(s)

rce-code-exec-01.md|4|V-08: LFI to RCE mutation via log file stalking (Apache/Nginx/SSH log injection)
rce-code-exec-01.md|87|V-09: LFI to RCE via PHP wrappers execution flow (php://filter, php://input, data://)
rce-code-exec-01.md|135|>> rce-testing — SKILL.md
rce-code-exec-01.md|139|RCE Testing — Deep Playbook
rce-code-exec-01.md|148|>> rce-testing — payloads.md (request templates, tool commands, evasion)
rce-code-exec-01.md|152|Payloads & Templates — RCE
rce-code-exec-01.md|159|2. SSTI fingerprinting ladder
rce-code-exec-01.md|203|Deserialization gadget probing — LAB/authorized targets only, never prod
rce-code-exec-01.md|208|>> rce-testing — variants-1.md (variant playbook)
rce-code-exec-01.md|212|RCE Variants — Part 1 (V-01 … V-05)
rce-code-exec-01.md|218|V-02: Language-specific code argument injection via dynamic code evaluators
rce-code-exec-01.md|284|V-03: Arbitrary object instantiation via insecure deserialization protocols
rce-code-exec-01.md|352|V-05: SSTI RCE via template engine fingerprinting
rce-code-exec-01.md|421|>> rce-testing — variants-2.md (variant playbook)
rce-code-exec-01.md|425|RCE Variants — Part 2 (V-06 … V-09)
rce-code-exec-01.md|430|V-06: RCE via memory corruption and garbage collection vulnerability triggers
rce-code-exec-01.md|472|V-08: RCE via insecure configuration loading and variable override
rce-code-exec-01.md|541|V-09: Blind RCE via system environment variable injections and shell expansion
rce-code-exec-01.md|619|V-02: Python scope re-alignment via exec/eval context isolation breaks
rce-code-exec-01.md|691|2.8 Indirect-eval sink context (V-13)
rce-code-exec-01.md|700|V-13: Indirect string evaluation sinks (bypassing via evaluation functions)
rce-code-exec-01.md|733|Server-Side Template Injection (SSTI)
rce-code-exec-01.md|735|Command Injection
rce-code-exec-01.md|745|D. Command Injection, Code Injection, and RCE
rce-code-exec-01.md|760|E. SSTI, SSRF, XXE, and Deserialization
rce-code-exec-01.md|771|2026-10-21 — suite restructure: rce-ssrf-testing split in two
rce-code-exec-01.md|792|RCE (`rce-testing`)
rce-code-exec-01.md|802|17.3 GraphQL free-form `filter` JSON → JS-library `$where` → `new Function` → unauthenticated RCE in the Node process
rce-code-exec-01.md|819|17.10 Ruby Octokit/Sawyer method override → redis RESP size-desync → injected Redis command → Marshal.load session deserialization → RCE (Gi
rce-code-exec-01.md|835|17.11 Shell-string sink: import/migration source path interpolated into Open3.popen3 -> command injection -> RCE (GitLab bulk project import
rce-code-exec-01.md|850|17.12 Dependency confusion: unclaimed internal package name resolved from the public registry, install hook runs in CI -> supply-chain RCE (
rce-code-exec-01.md|863|17.14 Internet-exposed unauthenticated Kubernetes API -> cluster-admin -> pod/job RCE + Secret/credential theft (Snapchat)
rce-code-exec-01.md|877|17.19 Perimeter appliance pre-auth file read -> runtime credential/session-store harvest -> 2FA bypass -> post-auth RCE (Pulse Connect Secur
rce-code-exec-01.md|893|17.22 Upload-reference rewriter path traversal -> arbitrary file read -> secret_key_base cookie forgery -> RCE (GitLab UploadsRewriter #8270
rce-code-exec-01.md|977|17.23 Loopback control service without an Origin check → desktop (Electron) RCE
rce-code-exec-01.md|990|17.30 Flag injection where the wrapped tool WRITES ITS OWN attacker-controlled stdout to a path -> arbitrary file write -> authorized_keys -
rce-code-exec-01.md|1001|17.44 Stored SSTI whose evaluation SINK is the OUTBOUND transactional EMAIL template → the computed payload is visible only in the mail body
rce-code-exec-01.md|1016|17.47 Headless-renderer export (PDF/report/screenshot) runs an EOL bundled Chromium with `--no-sandbox` → HTML-injection / open redirect → p
rce-code-exec-01.md|1028|17.51 Untrusted INDEX from a network/binary message → unvalidated table lookup → virtual call on an attacker-shaped object → RCE (Valve CS:G
rce-code-exec-01.md|1041|17.52 Untrusted interpreter sandbox: UNBOUNDED C-LEVEL recursion (no `eval`) bypasses the script-level stack guard → process stack overflow 
rce-code-exec-01.md|1053|17.64 Network-message index: LOWER-bound-only check + index scaled by a fixed stride (`shl eax,4`) wraps a large positive value negative → O
rce-code-exec-01.md|1067|17.68 Delimiter-bounded copy into fixed STACK buffers in a client-parsed asset file (`<cmd:args>` tokenizer) → stack overflow → RCE (Valve C
rce-code-exec-01.md|1079|17.74 Localhost "inspector" WebSocket `live_reload` downloads an attacker file with a naive `dir + fileName()` concat → path traversal → arb
rce-code-exec-01.md|1092|17.76 Job-submission REST endpoint runs a CLASSPATH class with attacker `entry-class`/`programArg` -> JDK `jrunscript` -> RCE (Aiven Apache 
rce-code-exec-01.md|1104|17.88 A client tool materialises a local file whose NAME comes from page-controlled attributes — `Path.resolve` escapes the tool's temp dir 
rce-code-exec-01.md|1116|17.90 Peer-supplied BIT length copied into a fixed BYTE-sized stack buffer off a voice/network channel — stack overflow → RCE (Valve Portal 
rce-code-exec-01.md|1128|17.94 Registry SOURCE-PRIORITY INVERSION — a LEGITIMATE internal package is overridden by a same-named public copy (global sources / transit
rce-code-exec-01.md|1141|17.98 An attacker-settable CONNECTOR CONFIG value names a JDK JAAS login module (`com.sun.security.auth.module.JndiLoginModule`) -> the work
rce-code-exec-02.md|4|17.104 A Node service's PROTOTYPE POLLUTION inside an internal-index pipeline reaches a `sourceURL`/code-generation gadget, with `\u2028\u20
rce-code-exec-02.md|17|17.120 Partial PUT with an attacker-influenced temp-file name/path on a WRITABLE Default Servlet → reach the file-based SESSION store → DESE
rce-code-exec-02.md|26|17.121 DNS rebinding via `0.0.0.0` + macOS `.local` DNS to read the Node inspector's `webSocketDebuggerUrl` and drive it over the SOP-exempt
rce-code-exec-02.md|35|17.151 A server-side JS engine given LIVE serializer objects: coerce its OVERLOAD RESOLUTION into constructing a serializer with attacker `T
rce-code-exec-02.md|50|17.172 A config-injection fix that BLACKLISTS a directive NAME is bypassed by an ALTERNATE directive that reaches the same code-execution si
rce-code-exec-02.md|64|17.189 A stored CONNECTION/config field becomes a raw CLI flag → attacker-controlled classpath/jar loads → RCE on the worker (Apache Airflow
rce-code-exec-02.md|76|17.193 TLS SESSION-TICKET RESUMPTION state is not isolated per virtual host — a ticket minted by the mTLS vhost the attacker MAY use resumes
rce-code-exec-02.md|86|17.298 A server-side HTML→PDF preview that EXECUTES JAVASCRIPT on an OUTDATED engine escalates to host RCE via a public exploit — fingerprin
rce-code-exec-02.md|94|17.355 AN ASP.NET HANDLER THAT REFLECTS A USER-SUPPLIED `__PARAMETERS` VALUE INTO `TemplateControl.ParseControl` COMPILES ATTACKER XAML INTO
rce-code-exec-02.md|104|17.378 A CHILD-OBJECT ENDPOINT THAT EMBEDS THE PARENT OBJECT'S NAME AND AUTHORIZES ONLY THE CHILD'S ID LEAKS EVERY PARENT'S NAME TO ANY CALL
rce-code-exec-02.md|106|17.391 WHEN A WALLET/BALANCE/TIER RESTRICTION BLOCKS AN ACTION, LOOK FOR THE ENDPOINT THAT RESETS THE GATING STATE AND CHECK WHETHER IT ACCE
rce-code-exec-02.md|108|17.398 A JSON-RPC / "invoke" ENDPOINT WHOSE PARAMETER VALUE IS DESERIALIZED IS A DIRECT UNAUTHENTICATED RCE PRIMITIVE — FEED IT A c3p0 `Wrap
rce-code-exec-02.md|110|17.467 A PERMISSION MUTATION FIRED WHILE AN OBJECT IS IN A TRANSITIONAL STATE IS AUTHORIZED AGAINST THE PRE-TRANSITION STATE — RACE THE STAT
rce-code-exec-02.md|112|17.486 ACL/EVALUATION ORDER: A FEATURE-TRIAL FLAG CHECK (`return_true_if { feature_enabled?(TRIAL) }`) PLACED BEFORE THE ROLE CHECK SHORT-CI
rce-code-exec-02.md|116|17.510 A TYPE TAG IN A JSON BODY (`@class` / `@type`) IS A REQUEST TO CONSTRUCT AN OBJECT OF THE ATTACKER'S CHOOSING: WHEN POLYMORPHIC DESER
rce-code-exec-02.md|120|17.514 WHEN ONE VALUE IS INTERPOLATED INTO A GENERATED SCRIPT AT MORE THAN ONE PLACE, EVERY SYNTAX ERROR YOUR INPUT PROVOKES IS A TEMPLATE O
rce-code-exec-02.md|122|17.516 AN AUTO-UPDATE / REPUTATION-DATABASE MANIFEST IS CODE INPUT: IF ANY OF ITS FIELDS (`filename`, `url`, `version`) REACHES `sprintf` OR
rce-code-exec-02.md|126|17.735 AUTHORIZE AGAINST THE TIER THAT OWNS THE RESOURCE: A CLAIM/OWNERSHIP-TRANSFER MUTATION ON A SHARED POOL GATED AT THE TEAM/PUBLIC-PROG
rce-code-exec-02.md|128|17.743 THE NAVIGATION GRAPH IS AN API: AN EXPORTED ACTIVITY THAT ROUTES AN UNREGISTERED SCHEME TO EVERY NAV-GRAPH DESTINATION, PLUS A `deepL
rce-code-exec-03.md|4|17.744 AN `exec()` ALLOWLISTED TO MONITORING PLUGINS IS NOT A COMMAND BOUNDARY: SSRF PAST A DENYLIST THAT IS "APPLIED BEFORE FOLLOWING HTTP 
rce-code-exec-04.md|4|V-35: Deserialization gadget chosen by the payload + `respond_to?` dispatch → argv injection
rce-code-exec-04.md|23|7.5 Django ORM `FilteredRelation` alias injection → RCE — CVE-2025-57833
rce-code-exec-04.md|52|8. Path Traversal, LFI and the LFI→SSRF→RCE chain
rce-code-exec-04.md|54|8.6 LFI → RCE via log poisoning
rce-code-exec-04.md|75|13. Command injection and code execution
rce-code-exec-04.md|77|13.6 Driver-mediated RCE: upload + SSRF to a local JMX agent
rce-code-exec-04.md|99|Command injection
rce-code-exec-04.md|125|17.10 Ruby Octokit/Sawyer method override → redis RESP size-desync → injected Redis command → Marshal.load session deserialization → RCE (Gi
rce-code-exec-04.md|144|Knowledge intake — reader pass 2026-11-07 (batch 4: 6 sources — GitLab project-template privilege escalation, GitLab Runner-token leak via Q
rce-code-exec-04.md|202|Knowledge intake — reader pass 2026-11-07 (batch 7: 6 sources — HackerOne `/skills` cross-applicant proof leak; GitHub Enterprise cross-repo
rce-code-exec-04.md|260|Knowledge intake — reader pass 2026-11-07 (batch 8: 6 sources — HackerOne embedded-submission authorization bypass of program-enforced contr
rce-code-exec-05.md|4|Knowledge intake — reader pass 2026-11-07 (batch 9: 6 sources — Uber password-reset token returned in the reset-INITIATE HTTP response → ATO
rce-code-exec-06.md|4|Knowledge intake — report-reader pass 2026-11-08 (batch 93: 6 assigned sources read ONE BY ONE in the given order — 2 entries appended + 2 §
rce-code-exec-07.md|4|Knowledge intake — report-reader pass 2026-11-08 (batch 93: 6 assigned sources read ONE BY ONE in the given order — 2 entries appended + 2 §
rce-code-exec-08.md|4|Knowledge intake — report-reader pass 2026-11-08 (batch 93: 6 assigned sources read ONE BY ONE in the given order — 2 entries appended + 2 §
rce-code-exec-09.md|4|Knowledge intake — report-reader pass 2026-11-08 (batch 93: 6 assigned sources read ONE BY ONE in the given order — 2 entries appended + 2 §
rce-code-exec-10.md|4|Knowledge intake — report-reader pass 2026-11-08 (batch 93: 6 assigned sources read ONE BY ONE in the given order — 2 entries appended + 2 §
rce-code-exec-11.md|4|Knowledge intake — report-reader pass 2026-11-08 (batch 93: 6 assigned sources read ONE BY ONE in the given order — 2 entries appended + 2 §
rce-code-exec-12.md|4|Knowledge intake — report-reader pass 2026-11-08 (batch 93: 6 assigned sources read ONE BY ONE in the given order — 2 entries appended + 2 §
rce-code-exec-13.md|4|Knowledge intake — report-reader pass 2026-11-08 (batch 93: 6 assigned sources read ONE BY ONE in the given order — 2 entries appended + 2 §
rce-code-exec-14.md|4|Knowledge intake — report-reader pass 2026-11-08 (batch 93: 6 assigned sources read ONE BY ONE in the given order — 2 entries appended + 2 §
rce-code-exec-15.md|4|Knowledge intake — report-reader pass 2026-11-08 (batch 93: 6 assigned sources read ONE BY ONE in the given order — 2 entries appended + 2 §
rce-code-exec-16.md|4|Knowledge intake — report-reader pass 2026-11-08 (batch 93: 6 assigned sources read ONE BY ONE in the given order — 2 entries appended + 2 §
rce-code-exec-17.md|4|Knowledge intake — report-reader pass 2026-11-08 (batch 93: 6 assigned sources read ONE BY ONE in the given order — 2 entries appended + 2 §
rce-code-exec-17.md|72|§17.788 — A CREATE-TIME CONTENT DENYLIST IS NOT A CONTROL ON THE RENDER PATH: A TEXT FILTER IS DEFEATED BY ANY CONSTRUCT THAT ASSEMBLES THE 
rce-code-exec-17.md|92|§17.796 — DESERIALIZATION GADGET CHOSEN BY A KEY IN THE PAYLOAD GRAPH + `respond_to?` DISPATCH = RCE: WHEN `Oj.load(payload)` INSTANTIATES T
