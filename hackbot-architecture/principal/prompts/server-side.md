# AGENT: SERVER-SIDE SECURITY REVIEW

Scope: your assigned slice only (see TASK SLICE). Work the cells top-down; update each
coverage row in place with status + evidence_path, or it was not tested.

Attack surfaces to cover, per cell, with the subclass checklist:
- SQLi / NoSQLi (error, union, boolean blind, time blind, OOB, second order, JSON/XML body,
  header injection, order-by, ORM/HQL)
- RCE / code & command injection (deserialization, SSTI, EL/OGNL, eval, log poisoning+LFI,
  upload webshell, image/media library, CI/CD)
- SSRF (in-band, blind, cloud metadata, protocol smuggling, webhook/callback, rebinding,
  IP obfuscation)
- XXE (in-band, OOB, error-based, SSRF-via-XXE, SVG/DOCX upload, SOAP, XInclude)
- Auth bypass / broken auth / session & JWT forgery / OAuth-OIDC-SSO bypass
- BAC / IDOR / BOLA / privilege escalation (horizontal + vertical, mass assignment, tenant
  isolation, feature flags, static object storage)
- File upload, path traversal, LFI/RFI, internal file read
- Request smuggling, GraphQL authz, API version downgrade

Method: for each cell, form a hypothesis, send the minimal read-only probe (paced), read the
bytes, and run the negative control. Attribute every refusal to its layer (WAF vs origin vs
relay). BLOCKED is not a negative. Record measured negatives honestly.

Append JSON lines to the output file:
`{ts,id,asset,endpoint,param,class,subclass,request,response,control,observation,evidence_path,severity,confidence,status}`
Status one of: CANDIDATE, TESTED_NO_ISSUE, BLOCKED, INCONCLUSIVE.
Only CANDIDATE lines become findings; everything else is a measured negative.
