# recon-methodology INDEX — grep this, then read_file(<part>, offset=<line-1>)
# 61 segments / 1 part(s)

recon-methodology.md|4|>> bug-hunter — Engagement orchestrator (scope → recon → hunt → validate → report)
recon-methodology.md|8|Enumeration throttle: rate-limit politely, never hammer
recon-methodology.md|32|Tool invocations (templates)
recon-methodology.md|36|Header/context flip fuzzing (V-11) — small curated list, not a wordlist dump
recon-methodology.md|43|Mass-assignment field enumeration (V-04): small candidate list, one field at a time
recon-methodology.md|48|>> business-logic-testing — payloads.md (request templates, tool commands, evasion)
recon-methodology.md|52|Workflow mapping procedure (map first, then skip/swap)
recon-methodology.md|95|V-04: Administrative interface discovery via URL obfuscation and Unicode path bruteforcing
recon-methodology.md|132|Tool invocation templates
recon-methodology.md|138|V-11/V-14 header-rule mapping loop (one variable per request)
recon-methodology.md|146|>> info-disclosure-testing — payloads.md (request templates, tool commands, evasion)
recon-methodology.md|150|info-disclosure-testing — Payloads, Templates & Tool Invocations (references/payloads.md)
recon-methodology.md|157|1. Recon path catalog (wordlists with placeholders)
recon-methodology.md|204|5. Tool invocation templates & path-probe evasion notes
recon-methodology.md|250|READ-ONLY enumeration — no PUT/POST/DELETE ever
recon-methodology.md|284|>> path-traversal-testing — payloads.md (request templates, tool commands, evasion)
recon-methodology.md|288|--- ffuf: value fuzzing with a traversal wordlist (in-scope target only) ---
recon-methodology.md|295|Seed wordlists inline (expand per engagement; keep pacing modest):
recon-methodology.md|297|V-04: Core system profile access bypass (/etc/passwd or Windows/win.ini isolation mapping)
recon-methodology.md|373|Param discovery for command/code sinks
recon-methodology.md|377|>> sandbox-escape-testing — payloads.md (request templates, tool commands, evasion)
recon-methodology.md|381|1. Environment fingerprinting ladder
recon-methodology.md|424|benign fingerprints (one-liners)
recon-methodology.md|430|benign recon (target):
recon-methodology.md|435|lab only: <PUBLIC_POC_OR_TOOL_FOR_BUILD> → benign proof: `whoami` shows
recon-methodology.md|437|guest-side benign fingerprint
recon-methodology.md|443|3. Tool invocation templates
recon-methodology.md|503|B-3. Scanner failure modes (proven by server-side coverage data) → what you must do by hand
recon-methodology.md|541|HTTP callback logger with header/UA logging (fingerprint the fetcher)
recon-methodology.md|545|Param discovery for URL-fetch sinks
recon-methodology.md|549|Callback listener during labs (logs source IP + UA = fetcher fingerprint)
recon-methodology.md|553|Timing-differential port mapping (in-scope only, slow pacing, 2 samples + control)
recon-methodology.md|558|5. Tool command templates
recon-methodology.md|564|>> infra-fingerprinting — Website fundamentals: fingerprint the stack, route the bug class (client-side + server-side)
recon-methodology.md|571|Infra Fingerprinting — Website Fundamentals Playbook
recon-methodology.md|580|8. INGEST POINT — infrastructure recon map (pending data)
recon-methodology.md|603|9. Report template (fingerprint-derived findings)
recon-methodology.md|607|Recon
recon-methodology.md|614|W-B. Recon tradecraft
recon-methodology.md|644|W-C. Content discovery & inventory
recon-methodology.md|658|Scanner: Subzy (or target tool)
recon-methodology.md|662|Recon tools
recon-methodology.md|669|Other tools (available in environment)
recon-methodology.md|671|Discovery: returns closest snapshot URL + timestamp as JSON
recon-methodology.md|675|3. Information Disclosure & Asset Mapping
recon-methodology.md|684|Tooling Quick Reference
recon-methodology.md|702|🎯 Vulnerability → Tool to Use (Full Map)
recon-methodology.md|743|Discovery chain
recon-methodology.md|758|Account existence enumeration via unauthenticated `checkEmail` oracle
recon-methodology.md|769|Recons done (don't redo)
recon-methodology.md|796|Stack (verified — pending first recon pass)
recon-methodology.md|806|7. LAB FILES — TOOLS & SCOPE
recon-methodology.md|808|>> tools-manifest.md
recon-methodology.md|812|Tools Manifest
recon-methodology.md|816|17.82 Account-identifier (user_id) enumeration through a MOBILE onboarding/duplication-check flow that ignores an account-level privacy togg
recon-methodology.md|829|17.129 The injectable field is INSIDE a base64/hex-encoded blob in one opaque parameter — so no scanner and no reviewer sees a parameter to 
recon-methodology.md|837|17.290 A MALFORMED FILE NAME OVERFLOWS THE DIRECTORY-LISTING FORMATTER — the enumeration path (`maps *` → `sprintf`) is the sink, NOT the fi
recon-methodology.md|847|>> BATCH 2026-11-14 — operator's paid-report corpus: new variants, routing rows, recon atoms
recon-methodology.md|849|V-26: UI-gate-only preconditions + the sibling-action status differential
recon-methodology.md|863|1.3 Client-side sink discovery via hash parsing → prototype pollution → gadget
recon-methodology.md|888|3.2 Identifier discovery from a public surface
