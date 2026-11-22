# bac-idor-bola INDEX — grep this, then read_file(<part>, offset=<line-1>)
# 117 segments / 5 part(s)

bac-idor-bola-01.md|4|>> bac-idor-testing — SKILL.md
bac-idor-bola-01.md|8|BAC / IDOR Testing Playbook
bac-idor-bola-01.md|15|1. Scope & authorization guardrail
bac-idor-bola-01.md|27|Title: <Resource/action> accessible across accounts via <missing check> (IDOR/BOLA/<variant>)
bac-idor-bola-01.md|33|>> bac-idor-testing — payloads.md (request templates, tool commands, evasion)
bac-idor-bola-01.md|37|GraphQL introspection & authorization probes
bac-idor-bola-01.md|43|--- G8: error-shaping oracle (does "not found" vs "not authorized" leak existence?)
bac-idor-bola-01.md|57|>> bac-idor-testing — variants-1.md (variant playbook)
bac-idor-bola-01.md|61|Variants 1-8 — IDOR core, function-level, and ID-shape flaws
bac-idor-bola-01.md|69|V-01: Direct parameter manipulation via authenticated IDOR security evasion
bac-idor-bola-01.md|97|V-02: Unauthenticated endpoint identification via IDOR resource enumeration
bac-idor-bola-01.md|124|V-03: Scripted request validation and automation via custom cURL IDOR frameworks
bac-idor-bola-01.md|181|V-05: Horizontal privilege escalation via missing object-level access control (BOLA/BMAO)
bac-idor-bola-01.md|238|V-06: Vertical privilege escalation via function-level access control evasion (RBAC/ABAC bypass)
bac-idor-bola-01.md|294|V-07: Server-side array confusion via HTTP parameter pollution (HPP) IDOR mutations
bac-idor-bola-01.md|350|>> bac-idor-testing — variants-2.md (variant playbook)
bac-idor-bola-01.md|354|V-09: Second-order IDOR via dynamic session parameter substitution sinks
bac-idor-bola-01.md|382|V-12: GraphQL query object variable manipulation for unauthorized node access
bac-idor-bola-01.md|439|V-14: JWT algorithm laundering and signature nullification privilege escalation
bac-idor-bola-01.md|469|1. Scope & authorization guardrail
bac-idor-bola-01.md|485|redirect_uri variant at the authorize step
bac-idor-bola-01.md|519|Probe: one privileged field added
bac-idor-bola-01.md|524|Scope & authorization guardrail
bac-idor-bola-01.md|534|1. Scope & authorization guardrail
bac-idor-bola-01.md|561|1. Scope & authorization guardrail
bac-idor-bola-01.md|594|1. Scope & authorization guardrail
bac-idor-bola-01.md|622|1. Scope & authorization guardrail
bac-idor-bola-01.md|663|V-04: Container privilege escalation via Docker daemon and kernel namespace breakouts
bac-idor-bola-01.md|703|lab-only benign escape proof (privileged misconfig): mount host disk
bac-idor-bola-01.md|705|1. Scope & authorization guardrail
bac-idor-bola-01.md|730|1. Scope & authorization guardrail
bac-idor-bola-01.md|760|1. Scope & authorization guardrail
bac-idor-bola-01.md|785|1. Scope & authorization guardrail
bac-idor-bola-01.md|795|IDOR / BOLA
bac-idor-bola-01.md|804|IDOR / BOLA Pattern
bac-idor-bola-01.md|815|IDOR & Broken Access Control
bac-idor-bola-01.md|817|F. IDOR, BOLA, BAC, and RBAC
bac-idor-bola-01.md|852|🧪 SKILL: Blind & Numeric IDOR Testing
bac-idor-bola-01.md|856|1. Blind & Numeric IDOR Testing
bac-idor-bola-01.md|896|2. Access Control & Authorization Bypasses
bac-idor-bola-01.md|905|IDOR / broken access control (`bac-idor-testing`)
bac-idor-bola-01.md|926|17.7 Access-denied response body still leaks the protected object (HTTP 422 "not authorized" carries `context.subject`)
bac-idor-bola-01.md|941|17.18 Delegated-admin object: field-level authorization not enforced -> vertical privilege escalation via role grants (Teleport Access Lists
bac-idor-bola-01.md|955|17.25 Trusted identity header (`X-Pid`) IDOR → cross-project role substitution → observer escalates to write + credential mint (Mail.ru MCS 
bac-idor-bola-01.md|968|17.33 Authz validator that EARLY-RETURNS by namespace/object shape → object-level check skipped → async export job never re-authorized (GitL
bac-idor-bola-01.md|983|17.41 Two-object diff/compare: authorization is checked on the object you ADDRESS, but the COUNTERPART of the diff is resolved with no ACL c
bac-idor-bola-01.md|999|17.48 Trusted INTERNAL identity claim reachable two ways: (i) internal signed token EXPOSED via a traversal file-read, (ii) internal identit
bac-idor-bola-01.md|1014|17.69 Free-form `sort_query: String` passed verbatim into the search engine's `sort` parameter → scripted-sort (`_script`/Painless) compilat
bac-idor-bola-01.md|1028|17.81 `data:image/svg+xml` used as an IMAGE SOURCE: the SVG script is dormant inside `<img>` but RUNS when the stored asset is opened as a t
bac-idor-bola-01.md|1043|17.86 Setuid-root binary executes a helper by a BARE name, trusting the caller's `$PATH` — local privilege escalation (Keybase #426944)
bac-idor-bola-01.md|1056|17.91 GraphQL field selection gated by a CLIENT-ASSERTED permission variable (`@include(if: $flag)`) — the request claims its own privileges
bac-idor-bola-01.md|1069|17.92 A GraphQL PERSISTED-OPERATION hash plus a NAME variable is an IDOR: the request carries no query text and no membership check runs on 
bac-idor-bola-01.md|1081|17.111 EMAIL-GATEWAY action endpoint trusts the `From:` header → any sender performs an account-bound action as another user → broken access
bac-idor-bola-01.md|1095|17.132 GRAPHQL GLOBAL-ID TYPE CONFUSION: a mutation resolves any global id with the generic resolver and derives its ability from the RESOLV
bac-idor-bola-01.md|1103|17.141 An OAuth provider's "verify your email" gate enforced only in the UI — POSTing `/oauth/authorize` directly mints a grant code for an 
bac-idor-bola-01.md|1111|17.156 An opaque identifier you cannot enumerate becomes enumerable when the SAME endpoint accepts it under an ALIASED parameter KEY (`userU
bac-idor-bola-01.md|1124|17.170 A sandbox that decides TRUST from a CANONICALIZED path while the LOADER resolves the RAW string grants high privileges for a path it 
bac-idor-bola-01.md|1138|17.175 A role assignment that silently SUBSCRIBES the new member to PRIVATE child objects discloses those objects through the notification p
bac-idor-bola-01.md|1152|17.180 An export/render endpoint authorizes the request that CREATES the artifact but not the request that FETCHES it — a tenant id in the r
bac-idor-bola-01.md|1166|17.182 A privileged desktop helper/installer is exploitable on two axes — a caller-supplied SOURCE PATH installed with the CALLER's ownershi
bac-idor-bola-01.md|1180|17.183 A "recently used / saved query" history persists user input and re-renders it to EVERY user of the tenant — one low-privilege write, 
bac-idor-bola-02.md|4|17.280 A CLOUD-DRIVE CONNECTOR'S SERVER-SIDE FETCH IS A TOKEN DELIVERY SERVICE: the user's file id is CONCATENATED into the provider API pat
bac-idor-bola-02.md|13|17.284 A CSP THAT DOES NOT COVER `object-src` IS NO DEFENCE, AND A FIELD AN UNPRIVILEGED PARTY SUPPLIES IS RENDERED BY THE PRIVILEGED PARTY'
bac-idor-bola-02.md|23|17.285 BOLA ON AN ACCOUNT-LINKING ENDPOINT PLUS A MISSING E-MAIL-VERIFICATION GATE = A BACKDOOR LOGIN METHOD ON AN ACCOUNT YOU DO NOT OWN — 
bac-idor-bola-02.md|33|17.288 A BUILD CONFIG'S PACKAGE-INSTALL LIST ACCEPTS A LOCAL PATH, SO THE PACKAGE MANAGER'S OWN MAINTAINER SCRIPT RUNS AS ROOT IN THE JOB CO
bac-idor-bola-02.md|43|17.291 A SHARED-MEMORY FIELD WRITTEN BY AN UNPRIVILEGED WORKER AND USED AS AN UNCHECKED INDEX BY A STILL-ROOT SUPERVISOR IS AN ARBITRARY-FUN
bac-idor-bola-02.md|53|17.297 An internal mutation whose input is a VALUE (not an object id) has nothing to authorize — a store SETTING is written by a zero-permis
bac-idor-bola-02.md|61|17.300 Appliance Management Console config field rendered as a NOMAD/Go template = command-injection sink reachable by a low-privilege "edit
bac-idor-bola-02.md|75|17.313 THE UI'S ACL FILTER IS NOT THE OBJECT'S ACL — a low-privilege participant on a private record cannot see team-only activity in the HT
bac-idor-bola-02.md|87|17.322 A ROLE-BEARING INVITE IS AN AUTHORIZATION GRANT THAT MUST BE RE-CHECKED AGAINST THE INVITER'S MEMBERSHIP AT ACCEPT TIME — REMOVING TH
bac-idor-bola-02.md|99|17.323 AN IDOR-ABLE CONFIG ENDPOINT THAT RETURNS THE AUTHORIZATION HASH FOR A STATE-CHANGING ACTION LETS YOU FORGE THE ACTION AGAINST ANY OB
bac-idor-bola-02.md|109|17.327 A GRAPHQL MUTATION THAT AUTHORIZES THE PARENT ID BUT LOADS THE CHILD ID THROUGH A GLOBAL RESOLVER LETS YOU PASS YOUR OWN TEAM ID PLUS
bac-idor-bola-02.md|119|17.361 AN OAUTH SUCCESS/CALLBACK PAGE THAT `postMessage`s ITS OWN URL (WHICH CARRIES THE AUTHORIZATION `code`) TO `window.opener` WITH `targ
bac-idor-bola-02.md|129|17.364 A MODERATION / "REPORT THIS CONTENT" ENDPOINT VALIDATES THAT THE TARGET OBJECT EXISTS, NOT THAT IT IS VISIBLE TO THE REPORTER — SO A 
bac-idor-bola-02.md|138|17.369 A SECURITY PRODUCT'S INTERSTITIAL PAGE IS PART OF THE ATTACK SURFACE OF EVERY SITE IT BLOCKS — IF THE OVERRIDE PAGE IS FIRST-PARTY TO
bac-idor-bola-02.md|147|17.370 A GRAPHQL MUTATION THAT RESOLVES ITS TARGET WITH A VISIBILITY SCOPE (`*_i_can_see`) AND HANDS IT TO AN INTERACTOR MARKED `skip_author
bac-idor-bola-02.md|156|17.374 A USERNAME VALIDATOR THAT BLACKLISTS CONTROL CHARACTERS AND WHITESPACE BUT NEVER NORMALISES OR ALLOW-LISTS UNICODE IS BYPASSED BY ZER
bac-idor-bola-02.md|158|17.375 A REALTIME FEED THAT PUSHES AN OBJECT IDENTIFIER BEFORE THE SUBSCRIBER IS ASSIGNED TO THAT OBJECT IS A BAC PRIMITIVE — CAPTURE THE ID
bac-idor-bola-02.md|160|17.384 A SCOPED TOKEN WHOSE AUTHORIZATION FALLS BACK TO A BROADER CONTEXT WHEN ITS SCOPE OBJECT IS REVOKED/DELETED, OR WHOSE SCOPE CHECK VER
bac-idor-bola-02.md|162|17.385 AN OBJECT-ID STATUS/LOOKUP ENDPOINT THAT RETURNS THE OWNER'S USER ID (AND THE OWNER'S INTEGRATION/ENTITLEMENT STATE) WITHOUT CHECKING
bac-idor-bola-02.md|164|17.393 AN OBJECT ID IN A WRITE REQUEST WHOSE OWNERSHIP CHECK IS ENFORCED ON ONLY ONE BRANCH IS NOT AN AUTHORIZATION CONTROL — DIFF THE ADD A
bac-idor-bola-02.md|166|17.394 A REVOKE ENDPOINT THAT REQUIRES A PARAMETER THE SHIPPED CLIENT OMITS IS A NO-OP — REPLAY THE TOKEN AFTER LOGOUT AND READ THE ERROR FO
bac-idor-bola-02.md|168|17.404 AN ARTIFACT-EXTRACT STEP THAT DEFAULTS TO THE WORKING DIRECTORY IS A FILE-OVERRIDE PRIMITIVE — A CI JOB THAT EXECUTES A FILE FROM THA
bac-idor-bola-02.md|170|17.407 A READ-ONLY CLOUD ROLE THAT CAN READ AN INTEGRATION KEY PLUS A SELF-REGISTRATION API IS A PRIVILEGE-ESCALATION CHAIN — REGISTER YOUR 
bac-idor-bola-02.md|172|17.408 A PRIVILEGED SERVICE THAT VALIDATES A CONFIG AND THEN EXECUTES IT IS A TOCTOU — RACE THE VALIDATE->EXECUTE WINDOW TO INJECT A DIRECTI
bac-idor-bola-02.md|176|17.410 A FIRST-PARTY APP CREDENTIAL EMBEDDED IN A CLIENT-SIDE BUNDLE IS A TOKEN-THEFT PRIMITIVE — BASE64-DECODE THE BLOBS IN THE BLOKS/SSR S
bac-idor-bola-02.md|178|17.411 A GRAPHQL MUTATION THAT TAKES AN OBJECT ID AND MINTS A DERIVED OBJECT ID IS AN IDOR/BOLA CHAIN — SWAP THE VICTIM'S ID INTO THE MUTATI
bac-idor-bola-02.md|180|17.413 A LOWER-PRIVILEGED ROLE CAN INVOKE AN ADMIN-ONLY GRAPHQL MUTATION WHEN THE ROLE CHECK TRUSTS A STATIC, CLIENT-SUPPLIED ROLE ID — REPL
bac-idor-bola-02.md|182|17.416 A BLANK ENDPOINT THAT SETS AUTHENTICATION COOKIES IS A COOKIE-MINTING ORACLE — HARVEST THE COOKIES, REPLAY THEM AGAINST THE OBJECT-VI
bac-idor-bola-02.md|184|17.418 A WRAPPER ROUTE IS A SECOND AUTHORIZATION IMPLEMENTATION — DIFF ITS `permission_callback` AGAINST THE CANONICAL ROUTE'S, AND A WRAPPE
bac-idor-bola-02.md|186|17.422 A PER-USER SESSION TOKEN DISCLOSED BY AN IDOR-ABLE USER-INFO API IS A BEARER CREDENTIAL — REPLAY IT AS A URL QUERY PARAMETER AND YOU 
bac-idor-bola-03.md|4|17.424 A ROLE DOWNGRADE MUST REPLACE THE PERMISSION SET, NOT MERGE INTO IT — DOWNGRADE A TEST ACCOUNT AND RE-RUN EVERY HIGHER-ROLE ACTION; I
bac-idor-bola-03.md|8|17.431 A CONSENT SCREEN OPENED IN A NEW TOP-LEVEL WINDOW IS NOT PROTECTED BY `X-FRAME-OPTIONS` — ALIGN A DECOY BUTTON IN A SECOND WINDOW SO 
bac-idor-bola-03.md|10|17.434 A "SECRET TOKEN" THAT IS IMPLEMENTED AS A SEQUENTIAL INTEGER IS NOT A SECRET — THE ENDPOINT'S OWN TOKEN NAMING CONCEALS AN INT PRIMAR
bac-idor-bola-03.md|12|17.436 ANY CODE EXECUTION IN A DEFAULT-BRANCH GITHUB ACTIONS WORKFLOW IS A CACHE-POISONING PRIMITIVE — STEAL `ACTIONS_RUNTIME_TOKEN` + `Cach
bac-idor-bola-03.md|14|17.440 THE AURA ENDPOINT IS A GENERIC METHOD DISPATCHER KEYED BY THE `descriptor` STRING — SWAP THE DESCRIPTOR TO A CONTROLLER THAT READS AN
bac-idor-bola-03.md|16|17.443 A KUBERNETES `Service` OF TYPE `ExternalName` POINTED AT `kubernetes.default` TURNS ANY INGRESS INTO AN UNAUTHENTICATED KUBE-APISERVE
bac-idor-bola-03.md|18|17.448 A DOCUMENTED RESTRICTED / VIEW-ONLY MODE THAT IS ENFORCED INSIDE INDIVIDUAL HANDLERS IS A DENY-LIST WITH HOLES — ENUMERATE THE WHOLE 
bac-idor-bola-03.md|20|17.458 A NESTED REST ROUTE WHOSE PARENT OBJECT IS A PATH SEGMENT AND WHOSE ACL CHECKS ONLY THE CALLER IS A CROSS-TENANT WRITE/READ SURFACE —
bac-idor-bola-03.md|22|17.468 AN IMMUTABILITY WINDOW ENFORCED ONLY AGAINST THE AUTHOR IS NOT IMMUTABILITY — A PRIVILEGED ROLE'S "EDIT INFORMATION" PATH THAT SKIPS 
bac-idor-bola-03.md|26|17.472 AN ITEM-LEVEL STATUS ENDPOINT THAT NEVER RE-VALIDATES THE BATCH CONTEXT LETS A CUSTOMER DRIVE A BATCH INTO AN INCONSISTENT STATE — CA
bac-idor-bola-03.md|30|17.476 AN ANONYMITY TOGGLE THAT SUPPRESSES THE NAME BUT NOT THE AVATAR IS NOT ANONYMITY — THE BULK EXPORT IS THE SURFACE AND THE INDIRECT ID
bac-idor-bola-03.md|34|17.481 EXECUTION AFTER REDIRECT (EAR): THE 302 BODY ALREADY CONTAINS THE FULL PRIVILEGED PAGE — FLIP THE STATUS TO 200 (OR READ THE BODY) TO
bac-idor-bola-03.md|36|17.482 AN ACCOUNT-LIFECYCLE-STATE RULE (`deactivated`) ENFORCED ON THE REST API IS SILENTLY SKIPPED BY THE GRAPHQL LAYER, WHICH CHECKS ONLY 
bac-idor-bola-03.md|38|17.484 A PRIVILEGED INSTALLER/HELPER THAT (RE)WRITES SHARED-PATH SYMLINKS AT A USER-SUPPLIED `--app-path` — BEAT THE "MUST BE UNDER /Applica
bac-idor-bola-03.md|40|17.508 THE PRICE MUST BE RECOMPUTED AGAINST THE FINAL INPUTS AT BOOKING TIME — IF THE CONFIRMATION STEP ACCEPTS A MUTATED QUOTE-DETERMINING 
bac-idor-bola-04.md|4|17.564 A URL-VALUED FIELD THAT A PRIVILEGED USER'S BROWSER LATER FETCHES IS A FORCED-BROWSING GADGET — THE URL CHECK IS ALMOST ALWAYS A SUBS
bac-idor-bola-04.md|90|17.684 A FIREWALL SCOPED TO ONE ADDRESS OF A MULTI-ADDRESS INTERNAL SERVICE IS NOT ACCESS CONTROL: WALK THE SERVICE'S ALIASES AND PROCESS CO
bac-idor-bola-05.md|4|17.736 OPAQUE IDENTIFIERS ARE A SERIALIZATION CHOICE, NOT ACCESS CONTROL: A CALLER-SET RESPONSE-MODE PARAMETER SWITCHES THE SAME LIST ENDPOI
bac-idor-bola-05.md|8|17.738 THE SOCIAL-LOGIN ACCOUNT KEY MUST COME FROM THE SERVER-SIDE VERIFIED TOKEN RESPONSE, NEVER FROM A REQUEST FIELD: SWAP THE CLIENT-ASSE
bac-idor-bola-05.md|10|17.739 STATE SET BY A LOWER-PRIVILEGED ACTOR NEEDS AN OWNER OVERRIDE IN EVERY TYPE BRANCH, A TTL, AND LIFECYCLE COUPLING: A `TYPE_TOKEN` LOC
bac-idor-bola-05.md|12|17.740 AUTHORIZE PER REFERENCED ID, NOT JUST THE ANCHOR: A RELATIONSHIP MUTATION THAT PASSES `ensure_can_*` ON THE TARGET OBJECT AND FORWARD
bac-idor-bola-05.md|16|17.741 THE SHARE/ACL LISTING IS ITS OWN AUTHORIZATION SURFACE: THE SHARE INDEX KEYED BY AN ENUMERABLE OBJECT ID, GATED ONLY BY "ANY LOGGED-I
bac-idor-bola-05.md|18|3. IDOR / BOLA (Broken Object Level Authorization)
bac-idor-bola-05.md|20|10.2 GraphQL field-level authorization missing — HackerOne
bac-idor-bola-05.md|44|13.5 Arbitrary file write → `authorized_keys` → command execution
bac-idor-bola-05.md|71|Knowledge intake — reader pass 2026-11-07 (batch 5: 6 sources — GitLab Nuget package-registry metadata path traversal → arbitrary file read;
