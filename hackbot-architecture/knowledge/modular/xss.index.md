# xss INDEX — grep this, then read_file(<part>, offset=<line-1>)
# 246 segments / 29 part(s)

xss-01.md|4|1. Domain intake — new domain mentioned = new profile skill
xss-01.md|23|V-04: SameSite Strict subdomain takeover cross-context execution
xss-01.md|57|V-15: Flash based CSRF and crossdomain.xml policy hijacking
xss-01.md|78|V-18: XSS assisted CSRF and DOM based token theft
xss-01.md|113|V-14: Internal domain/hostname leakage via intranet SMTP/email header metadata
xss-01.md|176|V-01: OS command string injection via unsanitized input concatenation
xss-01.md|239|V-12: Automated time-delay evasion via polyglot SQLi execution blocks
xss-01.md|301|>> xss-testing — SKILL.md
xss-01.md|305|XSS Testing Playbook
xss-01.md|312|<Title: e.g. Reflected XSS in /search via q parameter (HTML text context)>
xss-01.md|318|>> xss-testing — payloads.md (request templates, tool commands, evasion)
xss-01.md|322|Payloads, probes, encodings & tools — xss-testing
xss-01.md|344|2.9 Mutation / sanitizer context (V-07)
xss-01.md|355|3. Detection / polyglot probe set (non-destructive)
xss-01.md|388|Passive: collect URLs+params from a crawl, filter to XSS-shaped reflections
xss-01.md|392|kxss — reflection pass (stdin URLs; look for its "reflection" lines per param)
xss-01.md|396|gf + dalfox combo — pattern-select XSS-prone params first
xss-01.md|400|nuclei — XSS template suites (keep out-of-band templates pointed at YOUR OOB domain)
xss-01.md|406|Custom minimal nuclei-style template skeleton (write to xss-marker.yaml)
xss-01.md|425|>> xss-testing — variants-1.md (variant playbook)
xss-01.md|429|Variants 1-9 — xss-testing
xss-01.md|435|V-01: Multi-transport parameter reflection (POST/GET XSS matrix)
xss-01.md|468|V-02: Immediate context reflection boundary evasion (RXSS)
xss-01.md|495|V-03: Client-side sink exploitation (DOM-based XSS source analysis)
xss-01.md|538|V-04: Persistent storage script injection (stored XSS architecture)
xss-01.md|571|V-05: Out-of-band testing (blind XSS tracking engines)
xss-01.md|604|V-06: Browser SOP defiance (universal XSS / UXSS)
xss-01.md|637|V-07: Parsing misalignment (mutation XSS / mXSS vs DOMPurify)
xss-01.md|657|V-09: DOM XSS-assisted prototype pollution exploitation
xss-01.md|688|>> xss-testing — variants-2.md (variant playbook)
xss-01.md|692|Variants 10-18 — xss-testing
xss-01.md|697|V-10: Cross-context resiliency (universal polyglot payloads)
xss-01.md|730|V-15: Second-order reflected XSS via client-side cache injection
xss-01.md|763|V-17: MIME-sniffing assisted XSS (Content-Type misconfigurations)
xss-01.md|796|V-18: Breaking Trusted Types via unsanitized policy injection sinks
xss-01.md|828|XSS
xss-01.md|836|XSS Pattern
xss-01.md|846|Phase 1 — Subdomain Enumeration
xss-01.md|854|subzy run --targets "$domain/subdomains_all_${domain}.txt" --hide_fails > "$domain/subzy_${domain}.txt"
xss-01.md|858|Example: XSS on register form
xss-01.md|866|A. Cross-Site Scripting
xss-01.md|883|J. Other Security Domains
xss-01.md|907|2026-10-21 — SPA DOM-XSS hunting on a hashed-bundle PhantomBuster app
xss-01.md|943|6. DOMAIN PROFILES & FINDINGS
xss-01.md|947|>> [bug-hunter/references/domain-template.md] domain-template.md
xss-01.md|951|Domain profile template
xss-01.md|962|<domain>
xss-01.md|967|Subdomains & hosts
xss-01.md|972|>> [domains/aida.de/SKILL.md] SKILL.md
xss-01.md|976|Subdomains & hosts
xss-01.md|984|>> [domains/bb.bigid.cloud/SKILL.md] SKILL.md
xss-01.md|988|Subdomains & hosts
xss-01.md|994|>> [domains/casino-baden-baden.de/SKILL.md] SKILL.md
xss-01.md|998|Subdomains & hosts
xss-01.md|1010|>> [domains/frontier.com/SKILL.md] SKILL.md
xss-01.md|1014|Subdomains & hosts
xss-01.md|1021|>> [domains/frontier.com/evidence/config-surface-2026-10-24.md] config-surface-2026-10-24.md
xss-01.md|1025|>> [domains/frontier.com/evidence/xss-retest-2026-10-24.md] xss-retest-2026-10-24.md
xss-01.md|1029|XSS retest — /bgp_procedures_new_form.php (asn + all fields) — 2026-10-24
xss-01.md|1035|>> [domains/frontier.com/findings/001-gitignore-structure-disclosure.md] 001-gitignore-structure-disclosure.md
xss-01.md|1039|>> [domains/frontier.com/findings/002-exposed-internal-config-endpoints.md] 002-exposed-internal-config-endpoints.md
xss-01.md|1043|>> [domains/getoutlaw.com/SKILL.md] SKILL.md
xss-01.md|1047|>> [domains/getoutlaw.com/findings/F-01-getbundle-unauthenticated.md] F-01-getbundle-unauthenticated.md
xss-01.md|1051|>> [domains/getoutlaw.com/findings/F-02-checkaccount-enumeration.md] F-02-checkaccount-enumeration.md
xss-01.md|1055|>> [domains/hub.devolutions.com/SKILL.md] SKILL.md
xss-01.md|1059|Subdomains & hosts
xss-01.md|1068|>> [domains/hub.devolutions.com/findings/F-01-opensearch-credential-disclosure.md] F-01-opensearch-credential-disclosure.md
xss-01.md|1072|>> [domains/hub.devolutions.com/findings/F-02-sourcemap-exposure.md] F-02-sourcemap-exposure.md
xss-01.md|1076|>> [domains/hub.devolutions.com/findings/REPORT-F-01-server-configurations-credential-disclosure.md] REPORT-F-01-server-configurations-crede
xss-01.md|1080|>> [domains/jardindacclimatation.fr/SKILL.md] SKILL.md
xss-01.md|1084|Subdomains & hosts
xss-01.md|1097|>> [domains/jardindacclimatation.fr/evidence/technique-matrix.md] technique-matrix.md
xss-01.md|1101|XSS (`xss-testing`)
xss-01.md|1117|>> [domains/jardindacclimatation.fr/findings/001-email-enumeration-oracle.md] 001-email-enumeration-oracle.md
xss-01.md|1121|>> [domains/quizlet.com/SKILL.md] SKILL.md
xss-01.md|1125|Subdomains & hosts
xss-01.md|1147|>> [domains/quizlet.com/findings/F-01-missing-security-headers-origin.md] F-01-missing-security-headers-origin.md
xss-01.md|1151|>> [domains/quizlet.com/findings/F-02-envoy-k8s-service-disclosure.md] F-02-envoy-k8s-service-disclosure.md
xss-01.md|1155|>> [domains/quizlet.com/findings/F-03-internal-routing-header-disclosure.md] F-03-internal-routing-header-disclosure.md
xss-01.md|1159|>> [domains/reready.co/SKILL.md] SKILL.md
xss-01.md|1163|Subdomains & hosts
xss-01.md|1171|>> [domains/reready.co/evidence/2026-10-25-unauth.md] 2026-10-25-unauth.md
xss-01.md|1175|2. Reflection / RXSS sweep
xss-01.md|1191|>> [domains/verizon.com/SKILL.md] SKILL.md
xss-01.md|1195|Subdomains & hosts
xss-01.md|1199|>> [domains/vinted.com/SKILL.md] SKILL.md
xss-01.md|1203|>> [domains/vinted.com/findings/F-01-missing-security-headers.md] F-01-missing-security-headers.md
xss-01.md|1207|>> [domains/vinted.com/findings/F-02-static-csrf-token-origin-unchecked.md] F-02-static-csrf-token-origin-unchecked.md
xss-01.md|1211|17.6 Unescaped dot in the redirect allowlist regex → open redirect → cross-domain auth-token theft → 1-click ATO
xss-01.md|1227|17.20 HTTP desync / request smuggling (TE-header obfuscated) -> web-cache poisoning -> stored XSS on a login page (PayPal #510152, bypass of
xss-01.md|1242|17.27 Name field → secondary render path (slash-command / quick-action picker) → stored XSS for another user (GitLab Customer Relations)
xss-01.md|1255|17.58 Webview/desktop chat XSS → CUSTOM URI-SCHEME HANDLER (`steam://openexternalforpid/<n>/<program>`) → arbitrary local program execution 
xss-01.md|1270|17.61 Exposed proxy/gateway on a non-standard port routes on an attacker-supplied `Host:` header → internal-only domains reachable (Reddit #
xss-01.md|1283|17.63 Docs/help portal on a third-party SaaS renders user "suggest edits" as an AngularJS template → CSTI executes in the admin dashboard → 
xss-01.md|1298|17.84 Inbound-EMAIL stored XSS: the mail client's CSS rewriter DECODES octal escapes (`\00003c`) inside `url()` and re-inserts the "filtered
xss-01.md|1314|17.96 An XML DTD ENTITY inside an uploaded SVG switches OFF the SVG element/attribute whitelist -> `onload` survives on the root element -> 
xss-01.md|1332|17.97 A markdown REFERENCE-REDACTION pass reads a stored html-encoded attribute back out and re-emits it as raw HTML (entity-ENCODE in, DECO
xss-02.md|4|17.99 An INVITE-ACCEPTANCE endpoint trusts a client-supplied invite id with no ownership check — a failed request ("Invite doesn't exist") s
xss-02.md|20|17.100 A WINDOWS-node kubelet in-tree storage plugin does not sanitize the volume's LOCAL PATH field — a user who can create pods + persiste
xss-02.md|37|17.101 A server accepts an OBJECT where a STRING is expected, and the React client passes it as a `createElement` child -> the framework's o
xss-02.md|50|17.106 An admin-visible ACTIVITY/AUDIT LOG stores request metadata written by an UNAUTHENTICATED request -> stored XSS in the admin panel ->
xss-02.md|66|17.118 Project IMPORT that TRUST-RESTORES a `cache_markdown_field` — an attacker `note_html` plus a matching `cached_markdown_version` stamp
xss-02.md|75|17.131 An INCOMPLETE DENY-LIST of framework-RESERVED routing keys is URL-authority/scheme injection: `domain` for open redirect, `script_nam
xss-02.md|83|17.137 A stored-XSS SINK that renders ONLY for a viewer in a DIFFERENT permission/state than the author — VCS ref names in GitLab's "rebase 
xss-02.md|93|17.145 A bundled headless browser's DevTools channel is the RCE path: JS-port-scan localhost → steal the browser-WS GUID via clickjack + a "
xss-02.md|101|17.148 One server-side HTML literal escapes some interpolations and not others — the unescaped SIBLING field (`src`, from `url`) is the XSS,
xss-02.md|112|17.152 A CONTENT-EMBEDDED diagram/chart config-init directive is DEEP-MERGED into the renderer's shared config; `__proto__` pollutes `Object
xss-02.md|128|17.153 A frontend sanitizing DIRECTIVE (`v-safe-html`) is bypassed by the app's OWN CUSTOM ELEMENT, whose tag-builder string-interpolates it
xss-02.md|145|17.155 A renderer config value is concatenated into a CSS string that is assigned to `<style>.innerHTML`, so `</style>` in the value BREAKS 
xss-02.md|161|17.157 A MIRROR/REGISTRY renders metadata authored by a THIRD PARTY on the UPSTREAM, so whoever controls a package's metadata controls marku
xss-02.md|176|17.159 An UNTHENTICATED landing page that word-differentiates a live identifier from a dead one is an existence ORACLE for the whole identif
xss-02.md|191|17.164 The app's editor re-hydration on the EDIT route sanitizes LESS than the read-only route — deliver the framework's own attachment ELEM
xss-02.md|204|17.165 A postMessage origin gate written as a SUBSTRING test (`indexOf`/`includes`) is reachable from a domain you control that merely CONTA
xss-02.md|231|17.173 An ownership check whose "second factor" is a SHARED CONSTANT (the email DOMAIN) rather than a per-user secret — the per-customer sec
xss-02.md|244|17.178 A config-injection sanitizer is defeated through the LOGGING directives: attacker-controlled log PATH + attacker-controlled log CONTE
xss-02.md|259|17.185 An internal cache service bound on a NON-STANDARD port with no authentication — scan ALL ports on every resolved subdomain IP, then s
xss-02.md|273|17.187 The HTML-sanitizer ALLOW-LIST configuration is itself the attack surface — (a) a tag that embeds a nested document and (b) `style` co
xss-02.md|283|17.279 The AUTHORIZATION LAYER is itself probeable — its PRESENCE is read from the KIND of error an operation returns (a domain error proves
xss-02.md|300|17.281 A SERVICE WORKER ON YOUR OWN WILDCARD SUBDOMAIN READS THE AUTH CALLBACK, AND THE OAUTH `state` IS NOT A CSRF DEFENCE WHEN THE ORIGIN 
xss-02.md|309|17.282 A CHATBOT'S SESSION-ECHOED "GREETING" IS A STORED-XSS SINK WITH A FREE PLANTING STEP (CSRF), THE MARKDOWN RENDERER'S OWN HTML IS THE 
xss-02.md|318|17.283 A MUTATED (UNICODE-NORMALISED) CRLF IN A URL PATH INJECTS `Set-Cookie`, AND THE POINT OF THE INJECTION IS SESSION ADOPTION: adopting 
xss-02.md|327|17.287 A CLIENT-ASSIGNABLE IDENTIFIER IS AN UNFILTERED XSS SOURCE — the create-user endpoint lets the caller SET ITS OWN `uuid`, validated b
xss-03.md|4|17.292 A DYNAMICALLY GENERATED JS FILE IS AN XSSI SOURCE — its per-cookie content is importable cross-origin via `<script src>`, so every gl
xss-03.md|14|17.302 A server-side URL fetch gated by a Content-Type read from a HEAD while the payload is served from a GET is a HEAD/GET TOCTOU — answer
xss-03.md|39|17.307 A SANITIZER that rewrites an attribute string by regex and re-splices it injects its own delimiter — put `rel=` inside a quoted attri
xss-03.md|84|17.310 A static-hosting platform serves content for a custom domain BEFORE ownership is verified, for a 7-day grace window, and disabling `F
xss-03.md|93|17.317 AN UNKEYED OR OVERRIDDEN REQUEST HEADER IS A CACHE BODY-AND-KEY ORACLE — BRUTEFORCE HEADERS (MERGE PARAM-MINER'S LIST WITH `Vary` VAL
xss-03.md|103|17.320 A CUSTOM-DOMAIN CNAME TARGET SHARED BY TWO PRODUCT FEATURES IS CLAIMABLE IN THE WEAKER FEATURE EVEN WHEN THE DOMAIN IS ALREADY CLAIME
xss-03.md|113|17.321 AN HTTP HEADER-COUNT OVERFLOW PAST THE EDGE'S PARSE CAP MAKES THE CDN STOP EVALUATING CACHE RULES / CUSTOM KEYS / DEFAULT CACHE KEYS 
xss-03.md|123|17.324 AN ERROR RESPONSE FROM A VALIDATION ENDPOINT RENDERED VIA `innerHTML` IS AN HTML-INJECTION SINK — A CSP IS NOT A DEAD END WHEN THE AP
xss-03.md|135|17.328 AN UNAUTHENTICATED `PUT` TO A GCS-BACKED CDN WITH `Content-Type: application/octet-stream` (OR BLANK) BYPASSES THE STORAGE AUTH GATE 
xss-03.md|145|17.357 A MARKDOWN PIPELINE WHOSE SANITIZER ONLY ESCAPES USER-SUPPLIED ATTRIBUTE VALUES IS BYPASSED BY A DOWNSTREAM FILTER THAT GENERATES AN 
xss-03.md|155|17.358 A WAF INSPECTS EACH REQUEST FIELD SEPARATELY, SO AN XSS PAYLOAD SPLIT ACROSS A REFLECTED URL PARAMETER AND A REFLECTED COOKIE/HEADER 
xss-03.md|167|17.359 AN EXPOSED DEV/TEST MAIL CATCHER ON AN IN-SCOPE SUBDOMAIN RECEIVES THE APPLICATION'S TRANSACTIONAL MAIL — A PASSWORD-RESET EMAIL IN I
xss-03.md|179|17.366 AN ADMIN-NAMED PROFILE-EDIT PATH IS NOT AN ADMIN GATE — WHEN AN ORDINARY ACCOUNT CAN POST TO IT, EVERY FREE-TEXT FIELD ON THAT FORM I
xss-03.md|188|17.371 A SECURITY COMPONENT'S INJECTED UI IS ONLY AS TRUSTED AS THE PAGE THAT HOSTS IT — IF THE WIDGET IS SERVED FROM THE HOST PAGE'S ORIGIN
xss-03.md|197|17.376 AN IN-APP BROWSER THAT DROPS THE SITE'S `Content-Security-Policy` HEADER CONVERTS EVERY CSP-DEFENDED XSS ON EVERY SITE IT RENDERS INT
xss-03.md|199|17.377 A CNAME WHOSE TARGET IS A HOSTNAME UNDER AN UNREGISTERED DOMAIN IS A SUBDOMAIN TAKEOVER CLAIMABLE BY REGISTERING THE DOMAIN — NO CLOU
xss-03.md|201|17.379 A WORDPRESS SEARCH THAT ACCEPTS ITS TERM IN A POST BODY PARAMETER IS A TIME-BASED BLIND SQLI SINK — CAPTURE THE RAW REQUEST, REPLAY I
xss-03.md|203|17.381 A CONSENT PROMPT THAT RENDERS TOOL ARGUMENTS AS HTML WITHOUT ESCAPING IS A UI-REDRessing PRIMITIVE — CONCEAL THE PAYLOAD IN MARKUP, G
xss-03.md|205|17.382 A CDN/IMAGE ENDPOINT THAT REFLECTS ATTACKER CONTENT AND FORWARDS `Cache-Control` CAN BE TURNED INTO A CSP-LESS CACHED COPY — SET `Cac
xss-03.md|207|17.383 AN OBJECT BUCKET WHOSE READS ARE GATED ONLY BY A FORGEABLE `Referer` HEADER AND WHOSE APP EXPOSES AN UNAUTHENTICATED SIGNER THAT ACCE
xss-03.md|209|17.386 A GRAPHQL FIELD WHOSE AUTHORIZATION IS WEAKER THAN THE EQUIVALENT REST ROUTE IS AN AUTHORIZATION BYPASS — QUERY `namespace(fullPath:)
xss-03.md|211|17.387 A BROWSER EXTENSION WHOSE CONTENT SCRIPT USES DOM EVENTS AS ITS OWN IPC LEAVES THAT CHANNEL OPEN TO EVERY WEBSITE IT RUNS ON — DISPAT
xss-03.md|213|17.388 A FIRST-PARTY QUERY PARAMETER WHOSE VALUE IS A URL AND THAT IS PASSED THROUGH TO A THIRD-PARTY SCRIPT/JSONP ENDPOINT IS AN XSS SINK —
xss-03.md|215|17.389 A CSRF TOKEN THAT IS A DETERMINISTIC FUNCTION OF A WILDCARD-SCOPED COOKIE THE ATTACKER CAN FIXATE FROM A SIBLING SUBDOMAIN IS NOT A C
xss-03.md|217|17.392 AN LLM ASSISTANT THAT READS ATTACKER-CONTROLLED FILES AND RENDERS ITS REPLIES AS HTML IS A DATA-EXFILTRATION CHANNEL — PLANT AN INSTR
xss-04.md|4|17.395 AN INVITATION-CONFIRMATION LINK THAT THE INVITER CAN READ FROM THEIR OWN DASHBOARD AND THAT IS NOT BOUND TO THE INVITEE'S E-MAIL IS A
xss-04.md|8|17.400 AN OAUTH/OIDC CALLBACK THAT REFLECTS A QUERY PARAMETER INTO A `<script>` TAG BODY IS A REFLECTED-XSS SINK — AND IN AN AI-AGENT APP TH
xss-04.md|10|17.401 A SANITISER THAT RUNS BEFORE A CHARSET CONVERSION IS NOT A SANITISER — `htmlspecialchars` ON RAW UTF-8 SEES NO `<`/`>`/`"`/`'`, AND A
xss-04.md|12|17.402 AN `HttpOnly` SESSION COOKIE DOES NOT STOP AN XSS — CALL AN AUTHENTICATED SAME-ORIGIN API WITH `fetch(..., {credentials:'include'})`,
xss-04.md|14|17.403 A SANITISER THAT ENTITY-ENCODES CSS STRINGS BUT NOT CSS SELECTORS IS BYPASSED BY WRITING THE BREAKOUT AS CSS HEX ESCAPES INSIDE A SEL
xss-04.md|18|17.405 A QUERY-LANGUAGE EXTERNAL-DATA OPERATOR THAT TAKES A URL AND AUTHENTICATES WITH THE SERVICE'S OWN TOKEN IS A TOKEN-THEFT PRIMITIVE — 
xss-04.md|20|17.414 A FORM PARAMETER NAMED FOR A DOCUMENT TYPE IS A PARSER SINK — CONFIRM BLIND XXE WITH AN OOB CALLBACK, THEN POINT THE ENTITY AT `http:
xss-04.md|22|17.420 AN OAUTH LINKING FLOW WITH NO STATE IS A CSRF — CAPTURE YOUR OWN CALLBACK URL AND REPLAY IT AGAINST A VICTIM'S LINKING SESSION TO BIN
xss-04.md|24|17.421 A PDF LIBRARY THAT DOES NOT ESCAPE PARENTHESES IN ANNOTATION URIS IS AN XSS SINK — BREAK OUT OF THE STRING, INJECT AN `/Action` DICTI
xss-04.md|28|17.423 AUTHORIZATION IS PER-ENDPOINT, NOT PER-ACTION — ENUMERATE THE PARAMETERS OF A HIGHER-PRIVILEGE SIBLING ENDPOINT AND ADD THEM TO A LOW
xss-04.md|30|17.425 A THIRD-PARTY ANALYTICS BEACON ON A PAGE WHOSE URL CARRIES A SECRET IS A DISCLOSURE CHANNEL — PROXY A CLICK, GREP THE BEACON'S QUERY 
xss-04.md|34|17.428 A URL VALIDATOR THAT CHECKS ONLY THE HOSTNAME OF A THIRD-PARTY DOMAIN IS NOT AN SSRF CONTROL — THE ALLOWLISTED HOST'S OWN RESPONSE SU
xss-04.md|36|17.429 A FILTER WHOSE SCAN RANGE STOPS AT 0x7F IS DEFEATED BY INSERTING A HIGH BYTE (%80-%FF) INTO THE PAYLOAD — THE BYTE RANGE, NOT THE DEC
xss-04.md|38|17.430 A SECURE-TOKEN CALLBACK THAT ONLY FILLS A BLANK FIELD IS NOT A VALIDATOR, AND A STORAGE PATH BUILT BY JOINING A USER-INFLUENCED KEY W
xss-04.md|40|17.433 A SIGNED URL'S SIGNATURE MUST COVER EVERY PARAMETER THAT CHANGES HOW THE OBJECT IS SERVED — IF `response-content-type` / `response-co
xss-04.md|44|17.435 WHEN A PARSER DERIVES AN OUTPUT PATH FROM A FIELD INSIDE THE INPUT ARTIFACT, THE TRAVERSAL PAYLOAD LIVES IN THE FILE'S OWN METADATA —
xss-04.md|48|17.438 A COOKIE THE PRODUCT DESERIALIZES WITH .NET BINARYFORMATTER IS AN RCE ENTRY POINT — AND THE GADGET CHAIN DOES NOT NEED A THIRD-PARTY 
xss-04.md|50|17.439 A SANITIZER THAT ESCAPES ONE QUOTE CHARACTER ALMOST NEVER ESCAPES THE OTHER — PROBE WITH DOUBLE QUOTES, READ THE BACKSLASH IN THE RES
xss-04.md|54|17.441 ON A JSON API ERROR PAGE THE REFLECTED TOKEN MAY BE A FIELD NAME RATHER THAN A VALUE — KEYCLOAK'S OIDC DYNAMIC CLIENT REGISTRATION EN
xss-04.md|56|17.445 A SANITIZER THAT DELETES A SEPARATOR BLOCKLIST CAN ITSELF PRESERVE A SEPARATOR WHEN THE DELETION PRIMITIVE TREATS `\` AS AN ESCAPE — 
xss-04.md|60|17.446 THE GLOBAL GRAPHQL `node(id:)` INTERFACE IS A UUID-ORACLE WHEN ITS ID IS THE MODEL'S AUTO-INCREMENT PRIMARY KEY — WALK THE INTEGER, R
xss-04.md|62|17.447 A TOKENIZED INCOMING-MAIL ALIAS AT THE CORPORATE DOMAIN IS AN IDENTITY PRIMITIVE — MINT AN ADDRESS THE COMPANY'S OWN DOMAIN TRUSTS, R
xss-04.md|66|17.449 AN IMPORT PATH THAT RESOLVES ATTACKER-SUPPLIED GLOBAL OBJECT REFERENCES WITHOUT A TENANT CHECK, WHILE THE EXPORT PATH IN THE SAME FIL
xss-04.md|68|17.450 A REMOTE-RESOURCE BLOCKLIST IS ONLY AS STRONG AS ITS ELEMENT/ATTRIBUTE COVERAGE: THE SANITIZER THAT BLOCKS `<img>`/`<image>`/`<use>` 
xss-04.md|72|17.453 A JS BUILT-IN OVERRIDE THAT CAPTURES A PRIVILEGED OBJECT THE APP'S OWN CODE INVOKES THROUGH `Function.prototype.apply`/`call` HANDS T
xss-05.md|4|17.454 A REALTIME PUSH-CHANNEL NAME THAT THE CALLER CONTROLS BUT THE SERVER DOES NOT BIND TO THE CALLER'S SESSION TURNS A SELF-XSS INTO A CR
xss-05.md|6|17.455 A NETWORK PERMISSION THAT ONLY INSPECTS TCP HOSTS IS BYPASSED BY A UNIX DOMAIN SOCKET PATH (Node.js, HackerOne #3465156, "Node.js per
xss-05.md|10|17.461 A SETTINGS PERMISSION THAT CONTROLS THE OUTBOUND MAIL TRANSPORT IS A USER-MANAGEMENT PERMISSION IN DISGUISE — HIJACK THE SMTP/EMAIL C
xss-05.md|14|17.462 A CAPTCHA/LOCKOUT COUNTER KEYED ON A CLIENT-SUPPLIED IP HEADER IS NOT A THROTTLE — ROTATE `X-Forwarded-For` PER ATTEMPT AND THE FAILU
xss-05.md|16|17.464 A SELF-SERVICE OAUTH CLIENT-REGISTRATION `redirect_uris` FIELD WITH NO SCHEME ALLOWLIST IS A STORED-XSS REGISTRATION PRIMITIVE — PAIR
xss-05.md|18|17.466 IN RAILS 7.0/7.1 THE CONTROLLER'S `translate` HELPER MARKS `_html`-SUFFIXED KEYS AND UNESCAPED `default:` VALUES AS HTML-SAFE — PASS 
xss-05.md|22|17.469 A DESKTOP APP THAT PASSES A USER-CONFIGURABLE URL TO `ShellExecute` AFTER ONLY A "STARTS WITH http://" PREFIX CHECK IS A COMMAND-INJE
xss-05.md|26|17.470 AN EXPORTED ANDROID ACTIVITY THAT LOADS AN INTENT-SUPPLIED `html` EXTRA INTO A WEBVIEW IS AN XSS-TO-JSBRIDGE ENTRY POINT — AND A BRID
xss-05.md|28|17.474 AN ORIGIN CHECK THAT COMPARES THE HOST OF A USER-SUPPLIED URL AGAINST AN EXPECTED HOST IS BYPASSABLE WITH `javascript://<expected-hos
xss-05.md|32|17.477 AN INVITE/ACCEPT TOKEN THAT IS NOT BOUND TO THE TENANT THAT ISSUED IT IS A CROSS-TENANT ACCOUNT-CREATION PRIMITIVE — THE CONSUMER TRU
xss-05.md|36|17.478 A DELETE/CLEANUP GUARD THAT DERIVES ITS CONFINEMENT DIRECTORY FROM THE SAME ATTACKER-CONTROLLED FIELD AS THE DELETION TARGET IS A NO-
xss-05.md|40|17.479 AN AUTH GATE THAT APPEARS ON ONE VALUE OF A NUMERIC PATH/INSTANCE SEGMENT IS PER-VALUE, NOT PER-FUNCTION — FLIP THE SEGMENT TO REACH 
xss-05.md|44|17.480 A QUOTE-ESCAPE HELPER DOES NOT PROTECT A VALUE INTERPOLATED INTO A COMMENT IN GENERATED CODE — THE PAYLOAD ONLY NEEDS THE COMMENT TER
xss-05.md|46|17.483 A DESKTOP APP'S DOWNLOAD-AND-AUTO-OPEN PATH IS AN RCE SINK WHOSE GATE IS (a) AN UNANCHORED INTERNAL-HOST REGEX — DEFEATED BY OWNING A
xss-05.md|50|17.487 A PRE-AUTH CONTACT/TICKET INTAKE API IS AN UNAUTHENTICATED STORED-XSS CHANNEL INTO THE STAFF BACK-OFFICE: THE SERVER ACCEPTS AN EMPTY
xss-05.md|52|17.488 USER-AUTHORED RULES COMPILED INTO STORED PHP (`compiledlimitations`, evaluated on every banner delivery) ARE AN EVAL SURFACE — AND A 
xss-06.md|4|17.489 A STYLE SANITIZER THAT FIXES STRING-TOKEN BOUNDARIES BEFORE DECODING CSS CHARACTER ESCAPES CAN BE TOLD WHERE THE STRING ENDS: `\0026`
xss-06.md|56|17.509 A PASSWORD-RESET TOKEN BUILT FROM PUBLIC VALUES PLUS A TIMESTAMP THE RESPONSE HANDS YOU IS NOT A TOKEN — IT IS A FUNCTION YOU CALL: T
xss-06.md|58|17.513 AN ATTACKER-CONTROLLED PROPERTY NAME IS AS DANGEROUS AS AN ATTACKER-CONTROLLED VALUE: `obj[key]=value` IS A WILDCARD WRITE TO EVERY P
xss-06.md|62|17.517 IN AN ELECTRON DESKTOP CLIENT THE `webPreferences` HARDENING EVERYONE CHECKS (`nodeIntegration:false`, `contextIsolation:true`) DOES 
xss-06.md|64|17.518 A STORED XSS THAT FIRES IN AN ADMIN SESSION IS THE REQUEST-TRANSPORT FOR EXPLOITING A BLIND SQLI THAT ONLY THAT SESSION CAN REACH — R
xss-06.md|66|17.519 WHEN AN AUTHENTICATION REQUEST CARRIES A CLIENT-SUPPLIED USER ID NEXT TO THE CREDENTIALS, SWAPPING IT REVEALS THE ADMIN SURFACE — AND
xss-06.md|68|17.520 THE URL FRAGMENT IS THE ONLY PART OF `window.location`/`document.URL` THAT IS NEVER PERCENT-ENCODED — WHEN CODE CONCATENATES THE FULL
xss-06.md|72|17.521 AN XSS THAT FIRES ON A LOGIN OR ACCOUNT ORIGIN IS A CREDENTIAL-STEALING AND ACCOUNT-REBINDING POSITION, NOT A SESSION-READING ONE — R
xss-06.md|74|17.522 A CRLF RESPONSE SPLIT THAT CAN SET A PARENT-DOMAIN COOKIE IS A CROSS-SUBDOMAIN INJECTION PRIMITIVE — THE FINDING IS NOT THE SPLIT, IT
xss-07.md|4|17.523 WHEN A FIX TURNS A RAW PARAMETER INTO "MUST BE A BASE64 SERIALIZED OBJECT", SATISFY THE VALIDATOR WITH A VALID OBJECT AND SMUGGLE THE
xss-08.md|4|17.596 THE RECIPIENT FIELD OF A NOTIFICATION-DISPATCH API IS AN OBJECT REFERENCE — tamper the body `email` to any victim and ride a URL in a
xss-08.md|13|17.683 A SIGNATURE CHECK WHOSE SIGNER NAME, SIGNER CERT AND REVOCATION DATA ALL RIDE THE CHANNEL BEING MITM'D VERIFIES NOTHING: FROM A HOSTN
xss-08.md|15|17.687 A DATA-URI/BASE64 ECHO OF A FETCHED URL IS A FULL-READ CHANNEL: ALWAYS DECODE THE BLOB BEFORE CALLING AN SSRF BLIND — THE SERVER BASE
xss-08.md|19|17.689 WHEN VALIDATION AND FETCH PARSE THE SAME STRING DIFFERENTLY, THE HOST THE FILTER SEES IS NOT THE HOST THE REQUEST HITS — FUZZ FOR THE
xss-09.md|4|17.690 THE ERROR TEXT OF A SERVER-SIDE FETCH IS THE FETCHED SERVICE'S REPLY: `wrong status line: "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u4"` S
xss-10.md|4|17.690 THE ERROR TEXT OF A SERVER-SIDE FETCH IS THE FETCHED SERVICE'S REPLY: `wrong status line: "SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u4"` S
xss-10.md|63|17.734 CSP DOES NOT NEUTRALIZE HTML INJECTION IN A TRUSTED UI: STORED HTML IN A PASSWORD-MANAGER EXTENSION'S OWN POPUP, PADDED AFTER SPACES 
xss-10.md|65|17.737 A NAME-BASED SYMLINK KEEP-LIST IS DEFEATED BY A LINE BREAK: AN ARCHIVE ENTRY NAMED `.`+NEWLINE+`x` MATCHES A LINE-ANCHORED `\.{1,2}$`
xss-10.md|69|V-23: XSS under a WAF — entity-encoding bypass + the retest-after-fix protocol
xss-10.md|86|V-27: External-dependency takeover frontier (script-src host / published-email domain / delegated NS)
xss-10.md|103|§17.797 — AN EDITOR'S RE-PARSE REVIVES DORMANT ATTRIBUTES: CLIENT-SUPPLIED ATTACHMENT CONTENT + `data-behavior` → `innerHTML` → A FRAME LIBR
xss-10.md|112|§17.801 — A SCANNER WITH A WINDOW IS A SCANNER WITH A HOLE: PAYLOAD BEYOND THE BYTE CAP + INLINE-SERVED SVG = STORED XSS, THEN THE VICTIM'S 
xss-10.md|120|1. Cross-Site Scripting (XSS)
xss-10.md|122|1.1 Write-time vs. read-time sanitization gap — WordPress plugin admin notice
xss-10.md|150|1.2 Sanitizer bypass at the HTML-generation layer + CSP bypass — GitLab comments
xss-10.md|176|1.4 Upload/parser-based stored XSS (media handling)
xss-10.md|195|7.1 Array parameter defeats scalar sanitization — ImpressCMS
xss-10.md|242|12. Account takeover and XSS chains
xss-10.md|244|12.1 XSS → email change → ATO (the standard escalation)
xss-10.md|271|13.3 JSON field → `execFile` without sanitization
xss-10.md|290|ATO / XSS
xss-11.md|4|Knowledge intake — reader pass 2026-11-07 (batch 3: 6 reports — GitLab import/IDOR, PayPal smuggling, mruby RCE, Dropbox SSRF, GitLab XSS, G
xss-11.md|272|Knowledge intake — report-reader pass 2026-11-07 (batch 21: 6 sources — GraphQL persisted-operation IDOR on `gql.reddit.com` mod logs; Lark 
xss-12.md|4|Knowledge intake — report-reader pass 2026-11-07 (batch 22: 6 sources — Shopify SVG XML-ENTITY whitelist bypass → stored admin-panel XSS; Ma
xss-12.md|207|Knowledge intake — report-reader pass 2026-11-07 (batch 25: 6 sources — managed-control-plane SSRF from a customer-created provisioning obje
xss-13.md|4|Knowledge intake — report-reader pass 2026-11-07 (batch 27: 6 sources — Dropbox/HelloSign SSRF #923132, Dropbox/HelloFax email-gateway BAC #
xss-14.md|4|Knowledge intake — reader pass 2026-11-07 (batch 32: 6 sources — GitLab Rails reserved-routing-key XSS (#946728), GitLab GraphQL global-id t
xss-15.md|4|Knowledge intake — reader pass 2026-11-07 (batch 32: 6 sources — GitLab Rails reserved-routing-key XSS (#946728), GitLab GraphQL global-id t
xss-16.md|4|Knowledge intake — reader pass 2026-11-07 (batch 32: 6 sources — GitLab Rails reserved-routing-key XSS (#946728), GitLab GraphQL global-id t
xss-17.md|4|Knowledge intake — reader pass 2026-11-07 (batch 32: 6 sources — GitLab Rails reserved-routing-key XSS (#946728), GitLab GraphQL global-id t
xss-18.md|4|Knowledge intake — reader pass 2026-11-07 (batch 32: 6 sources — GitLab Rails reserved-routing-key XSS (#946728), GitLab GraphQL global-id t
xss-19.md|4|Knowledge intake — reader pass 2026-11-07 (batch 32: 6 sources — GitLab Rails reserved-routing-key XSS (#946728), GitLab GraphQL global-id t
xss-20.md|4|Knowledge intake — reader pass 2026-11-07 (batch 32: 6 sources — GitLab Rails reserved-routing-key XSS (#946728), GitLab GraphQL global-id t
xss-21.md|4|Knowledge intake — reader pass 2026-11-07 (batch 32: 6 sources — GitLab Rails reserved-routing-key XSS (#946728), GitLab GraphQL global-id t
xss-22.md|4|Knowledge intake — reader pass 2026-11-07 (batch 32: 6 sources — GitLab Rails reserved-routing-key XSS (#946728), GitLab GraphQL global-id t
xss-23.md|4|Knowledge intake — reader pass 2026-11-07 (batch 32: 6 sources — GitLab Rails reserved-routing-key XSS (#946728), GitLab GraphQL global-id t
xss-24.md|4|Knowledge intake — reader pass 2026-11-07 (batch 32: 6 sources — GitLab Rails reserved-routing-key XSS (#946728), GitLab GraphQL global-id t
xss-25.md|4|Knowledge intake — reader pass 2026-11-07 (batch 32: 6 sources — GitLab Rails reserved-routing-key XSS (#946728), GitLab GraphQL global-id t
xss-26.md|4|Knowledge intake — reader pass 2026-11-07 (batch 32: 6 sources — GitLab Rails reserved-routing-key XSS (#946728), GitLab GraphQL global-id t
xss-26.md|191|Knowledge intake — report-reader pass 2026-11-08 (batch 78: 6 assigned sources, read one by one in the given order — 5 entries appended: Arg
xss-27.md|4|Knowledge intake — report-reader pass 2026-11-08 (batch 80: 6 assigned sources, read one by one in the given order — 3 entries appended: Wor
xss-27.md|65|Knowledge intake — report-reader pass 2026-11-08 (batch 84: 6 assigned sources, read one by one in the given order — 1 new general method + 
xss-27.md|108|Knowledge intake — report-reader pass 2026-11-08 (batch 85: 6 assigned sources read one by one in the given order — 4 entries appended. NEW 
xss-28.md|4|Knowledge intake — report-reader pass 2026-11-08 (batch 86: 6 assigned sources read one by one in the given order — 5 entries appended: 2 HT
xss-29.md|4|Knowledge intake — report-reader pass 2026-11-08 (batch 86: 6 assigned sources read one by one in the given order — 5 entries appended: 2 HT
xss-29.md|200|§17.792 — CONTAINMENT MUST BE ENFORCED PER PARAMETER AND PER VERB: A SANITIZED FILENAME DOES NOT PROTECT THE SIBLING FOLDER/PATH PARAMETER —
xss-29.md|220|§INTAKE-2026-11-17/1 — A DORMANT CLIENT BEHAVIOUR REVIVED ONLY BY THE EDITOR'S RE-PARSE: CLIENT-SUPPLIED ATTACHMENT `content` KEPT BECAUSE I
xss-29.md|242|§INTAKE-2026-11-17/5 — A CONTENT SCANNER WITH A BYTE CAP + INLINE-SERVED DOCUMENT-TYPE UPLOAD = STORED XSS: PUT THE PAYLOAD BEYOND THE SCANN
