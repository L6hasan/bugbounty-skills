# ssrf-xxe-lfi INDEX — grep this, then read_file(<part>, offset=<line-1>)
# 92 segments / 3 part(s)

ssrf-xxe-lfi-01.md|4|V-13: Nested API resource path traversal for internal object-level access bypass
ssrf-xxe-lfi-01.md|61|Path Traversal / LFI & RFI Testing — Deep Playbook
ssrf-xxe-lfi-01.md|71|Payloads & Templates — Path Traversal / LFI / RFI
ssrf-xxe-lfi-01.md|77|Wrapper-support probe (returns YOUR text — proves wrapper parsing, not file read)
ssrf-xxe-lfi-01.md|81|--- ffuf: URL-path traversal against static locations ---
ssrf-xxe-lfi-01.md|87|Path Traversal / LFI & RFI Variants — Part 1 (V-01 … V-08)
ssrf-xxe-lfi-01.md|94|V-01: Internal file resource inclusion via local file inclusion (LFI) filter breaks
ssrf-xxe-lfi-01.md|168|V-02: External script execution traversal via remote file inclusion (RFI) wrapper pipelines
ssrf-xxe-lfi-01.md|241|V-03: Directory separation invalidation via path traversal strings (../)
ssrf-xxe-lfi-01.md|304|Path Traversal / LFI & RFI Variants — Part 2 (V-09 … V-15)
ssrf-xxe-lfi-01.md|310|V-10: Path traversal via nested archive unpacking flaws (Zip Slip)
ssrf-xxe-lfi-01.md|355|V-12: WAF bypass path traversal via Unicode/UTF-8 alternate slash character mappings
ssrf-xxe-lfi-01.md|431|V-13: LFI resource hijacking via PHP session file poisoning (/var/lib/php/sessions/)
ssrf-xxe-lfi-01.md|510|V-14: Path traversal via Nginx alias misconfiguration string splitting
ssrf-xxe-lfi-01.md|593|V-15: Arbitrary root configuration file read via static asset mapping misconfigurations
ssrf-xxe-lfi-01.md|677|file read displayed inside the guest — then stop
ssrf-xxe-lfi-01.md|709|>> ssrf-testing — SKILL.md
ssrf-xxe-lfi-01.md|713|SSRF Testing — Deep Playbook
ssrf-xxe-lfi-01.md|724|>> ssrf-testing — payloads.md (request templates, tool commands, evasion)
ssrf-xxe-lfi-01.md|728|Payloads & Templates — SSRF
ssrf-xxe-lfi-01.md|735|1. SSRF probing ladder
ssrf-xxe-lfi-01.md|800|>> ssrf-testing — variants-1.md (variant playbook)
ssrf-xxe-lfi-01.md|804|SSRF Variants (V-01 … V-06)
ssrf-xxe-lfi-01.md|811|V-01: Internal network mapping via basic SSRF scanning mechanisms
ssrf-xxe-lfi-01.md|880|V-02: Infrastructure verification via asynchronous blind SSRF pipelines
ssrf-xxe-lfi-01.md|944|IMDSv2 through a verb/header-controlling SSRF (V-05):
ssrf-xxe-lfi-01.md|978|V-05: SSRF via protocol smuggling (Gopher/DICT/FTP tunnelling)
ssrf-xxe-lfi-01.md|1050|V-06: SSRF via PDF/image rendering engines and cross-origin objects
ssrf-xxe-lfi-01.md|1092|SSRF
ssrf-xxe-lfi-01.md|1100|SSRF via xmlrpc: enumerate methods, then pingback.ping <attacker_url> <target_url>
ssrf-xxe-lfi-01.md|1104|SSRF Pattern
ssrf-xxe-lfi-01.md|1114|SSRF
ssrf-xxe-lfi-01.md|1116|Path Traversal
ssrf-xxe-lfi-01.md|1126|LFI / path traversal (`path-traversal-testing`)
ssrf-xxe-lfi-01.md|1135|SSRF (`ssrf-testing`)
ssrf-xxe-lfi-01.md|1145|4. Path traversal
ssrf-xxe-lfi-01.md|1159|17.5 SSRF filter bypass via the NAT64 local-use IPv6 prefix `64:ff9b:1::/48`
ssrf-xxe-lfi-01.md|1175|17.13 Archive symlinks not stripped on extract -> symlink followed at load -> arbitrary file read (GitLab bulk-import UploadsPipeline)
ssrf-xxe-lfi-01.md|1190|17.15 Unsanitised value reflected into HTML rendered by a PDF/headless-browser generator -> iframe -> SSRF to cloud IMDS (HackerOne Analytic
ssrf-xxe-lfi-01.md|1205|17.24 Disk-image backing-file / external-data-file reference → arbitrary server file read
ssrf-xxe-lfi-01.md|1219|17.29 Record-export path re-serves ACL-hidden content + guessable attachment ids -> internal file read (HackerOne "Export as .zip" #186230)
ssrf-xxe-lfi-01.md|1231|17.36 Path traversal carried in an uploaded artifact's OWN METADATA (not the URL path) → arbitrary file write → engine copy-race → arbitrary
ssrf-xxe-lfi-01.md|1245|17.39 Signed-upload-envelope parser desync: a bracketed multipart field name makes the signed field map and the app's nested-query parse dis
ssrf-xxe-lfi-01.md|1259|17.40 Import/restore mass-assignment of an uploader's remote-fetch attribute the cleaner forgot → attacker-controlled server-side fetch WITH
ssrf-xxe-lfi-01.md|1272|17.56 HTTP/2 → HTTP/1.1 frontend-downgrade request smuggling: a framing header the frontend never parses but the backend does (Basecamp #121
ssrf-xxe-lfi-01.md|1285|17.59 Delimiter-less signature canonicalization → signed-payment parameter smuggling (`Amount=2000` ≡ `Amount2=000`) → attacker-set amount →
ssrf-xxe-lfi-01.md|1299|17.70 Flag injection that switches the tool into its own filesystem-walk mode (`ref=--no-index` into `git grep`) → internal file read → toke
ssrf-xxe-lfi-01.md|1312|17.73 URL-preview / unfurl endpoint returns the fetched page's `og:title` → a built-in blind-SSRF READ ORACLE + port scan (Reddit Matrix `pr
ssrf-xxe-lfi-01.md|1325|17.77 CRLF injection through an edge/WAF rule-engine string function accepting HEX ESCAPES (`\x0a\x0d` in `concat()`) -> header injection ->
ssrf-xxe-lfi-01.md|1337|17.79 Security-disabled feature attribute RE-ENABLED from document CONTENT via an inline counter/set macro -> arbitrary file read + arbitrar
ssrf-xxe-lfi-01.md|1350|17.93 A document-IMPORT pipeline fetches a reference found inside the uploaded archive and returns the response BODY as a downloadable artef
ssrf-xxe-lfi-01.md|1364|17.105 A customer-created PROVISIONING object supplies the URL, and the provider's CONTROL-PLANE controller fetches it from the provider's n
ssrf-xxe-lfi-01.md|1380|17.110 Oversized chunked-TRAILER header drives a back-end parser into an `IOException` error path → the leftover bytes are re-framed as a NE
ssrf-xxe-lfi-01.md|1394|17.112 Multi-CONNECTOR SSRF — a provider/source selector exposes independently-protected server-side fetch paths, and a 303 redirect from th
ssrf-xxe-lfi-01.md|1410|17.123 An OAuth/token endpoint that builds its OUTBOUND url from the request `Host` (absolute route helper) is an unauthenticated blind SSRF
ssrf-xxe-lfi-02.md|4|17.125 A document→preview/PDF converter that FOLLOWS document-embedded external links (ODF OLE object / `text:section-source xlink:href`, un
ssrf-xxe-lfi-02.md|12|17.127 A server's URL-normalization ORDER (decode AFTER the check) turns a percent-encoded dot-dot into arbitrary file read, and an existing
ssrf-xxe-lfi-02.md|20|17.133 NON-HTTP SSRF through a MEDIA RELAY: TURN credentials handed to any user are a TCP-and-UDP proxy into the internal network (`XOR-PEER
ssrf-xxe-lfi-02.md|28|17.135 A third-party ERROR-MONITORING SDK is an SSRF gadget: the monitoring backend fetches a URL taken from a stack-trace frame's `filename
ssrf-xxe-lfi-02.md|36|17.140 A reflected POST parameter is a HEADER ORACLE after a desync, and the vendor's TRUSTED-GATEWAY ADMIN headers replayed on the internal
ssrf-xxe-lfi-02.md|44|17.143 The SSRF sink is a QUERY ARGUMENT inside a GraphQL document — the URL is a field parameter, not an HTTP parameter, so param-keyed SSR
ssrf-xxe-lfi-02.md|54|17.154 A user-supplied URL is interpolated INSIDE a CLI config argument (`-c http.<url>.extraHeader=…`) so the URL becomes the CONFIG KEY — 
ssrf-xxe-lfi-02.md|69|17.163 A media DEMUXER resolves URLs and PATHS that are embedded as PLAYLIST DIRECTIVES inside an uploaded file — the upload passes the exte
ssrf-xxe-lfi-02.md|84|17.294 AN SVG URL-IRI ATTRIBUTE ON A SERVER-SIDE RASTERIZER IS AN SSRF SINK, AND THE FETCHED RESOURCE IS COMPOSED INTO THE OUTPUT — an absol
ssrf-xxe-lfi-02.md|94|17.318 A HEADLESS-BROWSER PRERENDERER THAT EXECUTES A REQUEST-SUPPLIED JAVASCRIPT PARAMETER IS AN SSRF SINK WITH THE RENDERER'S INTERNAL NET
ssrf-xxe-lfi-02.md|104|17.363 A MOBILE DEEPLINK QUERY PARAMETER THAT NAMES THE FILE THE APP WRITES IS A PATH-TRAVERSAL SINK — INJECT `../` AND AIM AT SHARED STORAG
ssrf-xxe-lfi-02.md|115|17.390 AN IMPORT ENDPOINT WHOSE FILE ARGUMENT IS A SERVER-SIDE PATH GUARDED ONLY BY `file_exists()` IS AN LFI — POINT IT AT `/etc/passwd` OR
ssrf-xxe-lfi-02.md|117|17.397 A "PRIVATE NETWORK" GUARD WHOSE CLASSIFIER CHECKS `.private?` BUT NOT `.link_local?` LETS 169.254.0.0/16 AND fe80::/10 THROUGH AS PUB
ssrf-xxe-lfi-02.md|119|17.399 A MEDIA DEMUXER'S OWN TEXT RENDERER IS AN OUTPUT-SIDE EXFIL CHANNEL — WHEN A PRODUCT TRANSCODES AN UPLOADED PLAYLIST AND SERVES THE R
ssrf-xxe-lfi-02.md|121|17.457 AN UNAUTHENTICATED INBOUND THIRD-PARTY WEBHOOK THAT FETCHES A CALLER-SUPPLIED MEDIA/ATTACHMENT URL AND STORES OR ECHOES THE RESPONSE 
ssrf-xxe-lfi-02.md|125|17.459 A SELF-SERVICE URL FIELD THAT THE SERVER FETCHES AND ECHOES A CHALLENGE/RESPONSE FOR IS A FULL-READ SSRF ORACLE, AND THE IPv6 UNSPECI
ssrf-xxe-lfi-02.md|127|17.471 A WHITESPACE BYTE AFTER A RECOGNISED HEADER TOKEN (NOT BEFORE IT) CAN DROP THE PARSER'S PENDING STATE — `Connection: close<TAB>` MAKE
ssrf-xxe-lfi-02.md|131|17.515 A FIXED-SIZE INTERNAL MESSAGE BUFFER PLUS A HANDLER THAT RESOLVES A REQUEST BEFORE ITS BODY IS CONSUMED TURNS REQUEST SIZE INTO A SMU
ssrf-xxe-lfi-02.md|133|17.685 A FEATURE THAT FETCHES A TARGET AND COMPARES THE RESPONSE TO AN ATTACKER-SUPPLIED STRING IS A BLIND BOOLEAN READ ORACLE: ANYTHING YOU
ssrf-xxe-lfi-02.md|135|17.686 THE PDF GENERATOR IS THE DEPENDENCY: FINGERPRINT IT (ERROR BANNER + VERSION EMBEDDED IN THE PDF METADATA) AND EXPLOIT ITS OWN CVE — T
ssrf-xxe-lfi-02.md|137|17.688 DELTA: TWO `@` SIGNS IN ONE AUTHORITY MAKE TWO PARSERS SEE TWO DIFFERENT HOSTS — APACHE HTTPCLIENT'S `URIUtils.extractHost()` FALLBAC
ssrf-xxe-lfi-02.md|139|V-34: SSRF that STORES its response — the serving route is the exfiltration channel
ssrf-xxe-lfi-02.md|159|2. Server-Side Request Forgery (SSRF)
ssrf-xxe-lfi-02.md|161|2.2 SSRF used as a *response oracle* — internal fetch output echoed in an error message
ssrf-xxe-lfi-02.md|184|2.4 Mitigation bypass: redirect chain + URL-decode smuggling
ssrf-xxe-lfi-02.md|209|8.3 `readfile()` is both LFI and SSRF — SaaS download endpoint
ssrf-xxe-lfi-02.md|235|8.4 Path traversal in the multipart *filename*
ssrf-xxe-lfi-02.md|259|8.7 Fragment + base64 to defeat extension whitelists — Evernote SSRF
ssrf-xxe-lfi-02.md|286|8.8 Path traversal as a *cache* primitive — ChatGPT wildcard cache deception
ssrf-xxe-lfi-02.md|311|10.4 Parameter-driven PII on a third-party fulfilment link
ssrf-xxe-lfi-02.md|328|11.1 Underscore/dash header smuggling — mTLS header forgery
ssrf-xxe-lfi-02.md|378|11.5 TE.0 HTTP request smuggling — mass zero-click ATO
ssrf-xxe-lfi-02.md|419|12.4 Cache deception + client-side path traversal → ATO
ssrf-xxe-lfi-02.md|441|Traversal / LFI / SSRF
ssrf-xxe-lfi-03.md|4|Knowledge intake — report-reader pass 2026-11-07 (batch 26: 6 sources — the Adobe Flash Player memory-corruption family, all reaching code e
ssrf-xxe-lfi-03.md|79|§17.791 — STRING-REPLACEMENT SUBSTITUTION TOKENS (`$'`, `` $` ``, `$&`, `$<n>`) ARE A NEWLINE+QUOTE SMUGGLING PRIMITIVE INTO ANY CONFIG/TEMP
ssrf-xxe-lfi-03.md|98|§17.795 — AN SSRF THAT STORES WHAT IT FETCHED TURNS THE STORAGE ROUTE INTO THE EXFILTRATION CHANNEL (the fetch feature never echoes the body
