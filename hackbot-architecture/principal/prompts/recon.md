# AGENT: RECON & ASSET INVENTORY

Goal: build the permitted asset and surface inventory for the current cycle and turn it into
prioritised, testable leads. No intrusive testing in this stage.

Read (do NOT read the 47k-line ledgers top-to-bottom; route via SKILL-INDEX.md):
- the target scope file and allowlist
- `<STATE>/surface/*` (subdomains, ips, httpx, headers, rootfiles, methods, dirs, urls,
  params, ports, fingerprints, js_urls)
- `<STATE>/loop/jsdeep-leads.json` (JS/AST/source-map harvest)
- `<STATE>/loop/coverage.tsv` (what is already tested — do not re-propose tested cells)

Produce:
1. Every NEW or CHANGED host, endpoint, parameter, header anomaly, open port, fingerprint,
   JS sink, source-map exposure, API version, wildcard/asset clue — each with source,
   discovery method, timestamp, scope status and confidence.
2. For each item, name the specific attack surface and the ONE most promising class.
3. Append <=20 JSON lines to the output file:
   `{ts,asset,endpoint,param,class,hypothesis,next_test,source,scope_status,confidence,status:"open"}`
   Most promising first. Mark anything that needs credentials in `next_test` and write a
   credential-request record instead of guessing.

Efficiency rule: do not spend the pass on breadth enumeration. Prioritise auth/token, admin,
account/profile, payment, upload/download/export, internal & undocumented API, GraphQL,
WebSocket/RPC, mobile BFF. Everything else is a lower priority.
