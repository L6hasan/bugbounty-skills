# sqli-nosqli INDEX — grep this, then read_file(<part>, offset=<line-1>)
# 75 segments / 2 part(s)

sqli-nosqli-01.md|4|SQLi hand-off when V-14 step 5 shows a query-shaped kid lookup:
sqli-nosqli-01.md|14|V-07: Command injection via argument injection in Unix wrapper utilities
sqli-nosqli-01.md|83|>> sqli-testing — SKILL.md
sqli-nosqli-01.md|87|sqli-testing: SQLi & NoSQLi Deep Playbook
sqli-nosqli-01.md|89|<DBMS> SQL injection in <parameter> leaks <data class> via <variant>
sqli-nosqli-01.md|97|>> sqli-testing — payloads.md (request templates, tool commands, evasion)
sqli-nosqli-01.md|101|sqli-testing — Payloads, Templates & Tool Invocations (references/payloads.md)
sqli-nosqli-01.md|108|MySQL / MariaDB
sqli-nosqli-01.md|124|PostgreSQL
sqli-nosqli-01.md|139|MSSQL
sqli-nosqli-01.md|154|SQLite
sqli-nosqli-01.md|165|NoSQL (MongoDB-shaped) — see V-13
sqli-nosqli-01.md|172|7. Time-based confirmation: differential timing, not fixed sleeps
sqli-nosqli-01.md|198|>> sqli-testing — variants-1.md (variant playbook)
sqli-nosqli-01.md|202|sqli-testing — Variants 1-8 (references/variants-1.md)
sqli-nosqli-01.md|210|V-01: Database schema extraction via error-based SQL injection engines
sqli-nosqli-01.md|261|V-02: Cross-table arbitrary data retrieval via union-based SQL injection compilation
sqli-nosqli-01.md|314|V-03: Inferential data exfiltration via boolean-based blind SQL inferences
sqli-nosqli-01.md|370|V-04: Asynchronous database delay evaluation via time-based blind SQLi conditions
sqli-nosqli-01.md|425|V-05: Out-of-band data exfiltration via DNS logging protocols (OOB SQLi / DNSlog frameworks)
sqli-nosqli-01.md|480|V-07: Downstream persistence exploitation via second-order SQL injection pipelines
sqli-nosqli-01.md|540|V-08: Transport-layer bypasses via JSON, XML and GraphQL embedded parametric SQLi
sqli-nosqli-01.md|598|>> sqli-testing — variants-2.md (variant playbook)
sqli-nosqli-01.md|602|sqli-testing — Variants 9-15 (references/variants-2.md)
sqli-nosqli-01.md|611|V-09: Structural query manipulation via ORDER BY, GROUP BY and LIMIT/OFFSET exploits
sqli-nosqli-01.md|669|V-10: Database-specific command execution (MySQL INTO OUTFILE/LOAD_FILE, MSSQL xp_cmdshell, PostgreSQL COPY TO/FROM PROGRAM, Oracle UTL_HTTP
sqli-nosqli-01.md|730|V-13: NoSQL injection (NoSQLi) document extraction via operator substitution ($gt, $ne, $regex) including HTTP-parameter/JSON-operator injec
sqli-nosqli-01.md|796|V-14: Truncation-based SQL injection via database field length limits
sqli-nosqli-01.md|856|>> sqli-testing — core black-box scanning methods (book extract: Degerman & Dubrefjord, Chalmers 2021)
sqli-nosqli-01.md|867|Core black-box SQLi methods (book extract)
sqli-nosqli-01.md|869|dirsearch, ffuf, nmap, sqlmap, nuclei, amass, masscan
sqli-nosqli-01.md|871|Example: SQLi on login form
sqli-nosqli-01.md|879|SQL Injection
sqli-nosqli-01.md|883|C. SQL Injection
sqli-nosqli-01.md|896|Session-2 follow-up (2026-10-25): F-01 validated, RCE + SQLi investigated
sqli-nosqli-01.md|917|SQL / NoSQL injection (`sqli-testing`)
sqli-nosqli-01.md|933|3. SQLi on /help?search (boolean oracle exists: 20 vs 0 article links)
sqli-nosqli-01.md|955|17.2 MongoDB operator injection in the access_token query parameter — unauthenticated auth bypass → admin
sqli-nosqli-01.md|970|17.4 WordPress REST batch endpoint route-dispatch desync → unauthenticated blind SQLi (string where an array is expected)
sqli-nosqli-01.md|986|17.16 Array-typed parameter (x[]) as a blind-SQLi sink on legacy report/export endpoints (Valve report_xml.php)
sqli-nosqli-01.md|1000|17.26 Selector/reader node mismatch → attribute injection into a string-concatenated tag → `data-*`-driven CSP bypass (GitLab Kroki)
sqli-nosqli-01.md|1014|17.53 CI build-cache poisoning: re-upload a modified remote-cache artifact under an existing key (the cache "authorized link" is not immutab
sqli-nosqli-01.md|1027|17.95 An internet-exposed analytics QUERY ENGINE (Presto coordinator) behind a misconfigured firewall is a data-warehouse read: `POST /v1/st
sqli-nosqli-01.md|1041|17.108 A Windows server's own PATH handling coerces NTLM over SMB from a UNC path -> capture/relay -> RCE, with no database and no SQLi in t
sqli-nosqli-01.md|1057|17.115 ENV-FILE delimiter/newline injection into `$GITHUB_ENV` via `core.exportVariable` → attacker-defined environment variables in every l
sqli-nosqli-01.md|1071|17.116 WAF bypass by splitting a SQL FUNCTION NAME from its parenthesis with an inline comment, plus a VALUE-KEYED DB result cache defeated 
sqli-nosqli-01.md|1085|17.117 Unauthenticated `admin-ajax.php` PREVIEW action that expands WordPress shortcodes from a parameter, whose shortcode then interpolates
sqli-nosqli-01.md|1103|17.122 Blind SQLi in a URL PATH SEGMENT via an `or 1=1--` / `or 1=2--` boolean predicate, reached from a promo page's XHR (inDrive / id.indr
sqli-nosqli-01.md|1114|17.181 A config-injection into a generated proxy config becomes an ARBITRARY INTERNAL FILE READ when the injected directive is a FILE-SERVIN
sqli-nosqli-01.md|1129|17.301 HTTP request headers (User-Agent / Referer / X-Forwarded-For) are SQLi injection points — find them with sqlmap --level 5 --risk 3 an
sqli-nosqli-01.md|1142|17.305 A TIME-BASED BLIND SQLi in a numeric account-id query parameter of a legacy PHP install/settings script — prove it with a SLEEP whose
sqli-nosqli-01.md|1170|17.308 A legacy ColdFusion `.cfm` endpoint's numeric query parameter (`countID`) reaches SQL — confirm it with the DBMS banner returned in-b
sqli-nosqli-02.md|4|17.316 THE ORM PARAMETERIZES VALUES, NOT QUERY STRUCTURE — Django's `WhereNode.as_sql` interpolates the Q-object CONNECTOR into the WHERE cl
sqli-nosqli-02.md|16|17.415 FIND THE INJECTION POINT BY BROWSING WITH A PROXY AND PICKING THE UNIQUE POST REQUEST OUT OF HTTP HISTORY; WHEN A FIREWALL BLOCKS SQL
sqli-nosqli-02.md|20|17.437 A SETUP/BOOTSTRAP ENDPOINT THAT AUTHENTICATES A LOW-PRIVILEGE CONSOLE ROLE BUT PERFORMS A CREDENTIAL-SETTING OPERATION IS A DIRECT PR
sqli-nosqli-02.md|24|17.451 A FREE-TEXT BUSINESS FIELD IN AN UNAUTHENTICATED CHECKOUT/PAYMENT ACTION IS A SERVER-SIDE FETCH SINK: THE PAYMENT-GATEWAY INTEGRATION
sqli-nosqli-02.md|28|17.456 A CHARACTER DENYLIST THAT BLOCKS QUOTES IS NOT A SANITISER ON POSTGRESQL — `$tag$…$tag$` DOLLAR-QUOTING IS A QUOTE-FREE STRING LITERA
sqli-nosqli-02.md|30|17.460 AN OPEN `/wp-json` ROUTE INDEX IS A MAP OF UNDOCUMENTED PLUGIN ENDPOINTS — PAIR THE ROUTE THAT DISCLOSES AN IDENTIFIER WITH THE SIBLI
sqli-nosqli-02.md|34|17.485 ANY "CONNECT YOUR OWN DATABASE" FEATURE IS A CLIENT-SIDE FILE READ WHEN `local_infile` IS ON: POINT THE APP'S MYSQL CLIENT AT YOUR RO
sqli-nosqli-02.md|36|17.511 WHEN USER INPUT IS COMPILED INTO GENERATED SOURCE, THE COMMENT IT SITS IN IS THE BOUNDARY — AND IN A COMPILE-ONLY JVM CONTEXT, SHADOW
sqli-nosqli-02.md|38|17.512 A USER-SUPPLIED JDBC URL REACHING `DriverManager.getConnection` IS AN RCE PRIMITIVE: THE DRIVER'S URL PARAMETERS NAME CLASSES TO INST
sqli-nosqli-02.md|40|7.2 Unauthenticated SQLi in a plugin → insecure deserialization → RCE — Krisp
sqli-nosqli-02.md|66|7.3 Login-form SQLi (auth bypass) and the surrounding auth surface
sqli-nosqli-02.md|97|7.4 SQLi detection ladder (synthesis of the above)
sqli-nosqli-02.md|112|7.6 PostgreSQL `IN`-list array-key injection — Drupal CVE-2026-9082
sqli-nosqli-02.md|156|7.7 SQLi via the POST **parameter name** — NASA Space Place (Bugcrowd disclosure)
sqli-nosqli-02.md|185|7.8 Time-based blind SQLi in an `ORDER BY` / `sort` parameter — NASA JPL Photojournal
sqli-nosqli-02.md|213|7.9 Boolean-blind over Oracle with binary search — NASA REST API (Bugcrowd disclosure)
sqli-nosqli-02.md|240|7.10 BigQuery SQL injection — non-standard syntax and system-variable oracles
sqli-nosqli-02.md|278|7.11 mysqljs/mysql escape bypass via JavaScript object type coercion
sqli-nosqli-02.md|320|12.3 HTML injection in a desktop app → Electron RCE (Slack)
sqli-nosqli-02.md|351|13.7 Argument injection into `ProxyCommand`
sqli-nosqli-02.md|370|SQLi / RCE
sqli-nosqli-02.md|375|§17.793 — A FILTER-EXPRESSION MINI-LANGUAGE WITH A DATABASE ESCAPE HATCH IS A SQLi SURFACE: AN UNVALIDATED LIST PARAMETER INTERPOLATED INTO 
sqli-nosqli-02.md|395|§17.794 — A SORT CLAUSE HANDED VERBATIM TO THE ORM IS SQLi EVEN BEHIND A TOKEN BLACKLIST: WITH AN AGGREGATE QUERY AND A SORT KEY THAT IS NOT
