# SKILL CORE — always-inject routing card (KEEP SMALL; ledgers are 47k lines)

SEVERITY FLOOR: HIGH/CRITICAL only. P3/P4 primitive = chain material, never a report.
EVIDENCE BAR : source URL+date for every technique, reproduce twice, zero false positives.
RULE         : NEVER read the ledgers top-to-bottom. Route through SKILL-INDEX.md, then
               read_file(<ledger>, offset=<index line -5>, limit=200).

ROUTE (preferred): /root/hackbot-architecture/knowledge/modular/MANIFEST.md  -> pick the class
               file (each <200 KB) -> grep its <class>.index.md for the entry -> read_file at offset.
ROUTE (fallback): grep -n -i '<class>' /root/hackbot-architecture/knowledge/SKILL-INDEX.md

CLASS -> ANCHOR (A=Bugbountyskills.md  B=bugbountyhuntingskills.md)

- XSS                            -> A:14370 XSS ; B:102 1. Cross-Site Scripting (XSS)
- SQLi                           -> A:14987 SQL Injection ; B:549 7. SQL Injection
- RCE / code & command injection -> B:1880 Command injection ; A:15056 Command Injection
- SSTI                           -> A:14975 Server-Side Template Injection (SSTI) ; B:2878 Knowledge intake — reader pass 2026-11-07 (batch 8: 6 sources — HackerOne embe
- SSRF                           -> A:15034 SSRF ; A:14363 SSRF
- XXE                            -> A:15421 E. SSTI, SSRF, XXE, and Deserialization ; A:23865 17.414 A FORM PARAMETER NAMED FOR A DOCUMENT TYPE IS A PARSER SINK — CONFIRM B
- LFI / path traversal           -> A:15046 Path Traversal ; A:18276 LFI / path traversal (`path-traversal-testing`)
- IDOR / BOLA / BAC              -> A:15012 IDOR & Broken Access Control ; A:18229 IDOR / broken access control (`bac-idor-testing`)
- Auth bypass                    -> A:14377 Auth Bypass ; B:2024 17.1 SAML XML Signature Wrapping (XSW) — validated-signature/handled-node conf
- JWT / session forgery          -> A:978 JWT checklist driver (test-step execution, per section above) ; A:816 JWT testing checklist (test steps, not exploit code)
- CSRF                           -> A:3526 CSRF Testing ; A:3633 CSRF: <concise endpoint-specific title, e.g. "Change email accepts cross-site 
- Open redirect                  -> B:2089 17.6 Unescaped dot in the redirect allowlist regex → open redirect → cross-dom ; A:20050 17.6 Unescaped dot in the redirect allowlist regex → open redirect → cross-dom
- Host header injection          -> A:2318 Host header & password reset test templates ; A:2790 V-06: Insecure password reset logic via Host header injection or token leakage
- Prototype pollution            -> B:3994 Knowledge intake — report-reader pass 2026-11-07 (batch 25: 6 sources — manage ; A:13693 V-09: DOM XSS-assisted prototype pollution exploitation
- Information disclosure         -> B:1868 Information disclosure ; B:1247 10. Information disclosure and PII
- Business logic / race          -> A:1922 Business Logic Testing Playbook ; A:18295 Business logic (`business-logic-testing`)
- Supply chain / takeover        -> A:24156 17.516 AN AUTO-UPDATE / REPUTATION-DATABASE MANIFEST IS CODE INPUT: IF ANY OF  ; A:4089 V-04: SameSite Strict subdomain takeover cross-context execution
- GraphQL                        -> A:868 GraphQL introspection & authorization probes ; A:16603 API / GraphQL
- OAuth / OIDC / SSO             -> A:2274 OAuth 2.0 testing checklist (test steps) ; A:3005 Variants 9-15 — concurrency abuse, negative values, session races, form contex
- File upload                    -> A:7452 V-11: Local file access via symbolic link (symlink) file upload invalidation ; A:8420 V-04: File upload and malicious web shell execution architectures
- Deserialization                -> A:8177 Deserialization gadget probing — LAB/authorized targets only, never prod ; A:15421 E. SSTI, SSRF, XXE, and Deserialization
- Request smuggling              -> B:4139 Knowledge intake — report-reader pass 2026-11-07 (batch 27: 6 sources — Dropbo ; B:1501 11.5 TE.0 HTTP request smuggling — mass zero-click ATO

XSS SUB-TAXONOMY — test ALL ten, not just reflected:
  Reflected(RXSS) | Stored/Persistent | DOM-based | Blind(staff/log console) | UXSS | Self
  | POST-based | GET-based | Mutation(mXSS) | Polyglot
  Sinks to trace: .html() .append() .innerHTML document.write eval( popup( $.html(

INDEX   : /root/hackbot-architecture/knowledge/SKILL-INDEX.md
DOCTRINE: /root/hackbot-architecture/SEVERITY_DOCTRINE.md