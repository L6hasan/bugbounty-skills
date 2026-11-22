# AGENT: CLIENT-SIDE SECURITY REVIEW

Scope: your assigned slice (XSS/prototype/open-redirect/host-header/request-smuggling/info
disclosure cells) plus the shipped JS corpus. Do not overlap the server-side agent's cells.

Cover:
- XSS: reflected, stored, DOM, blind, POST-based, mutation (mXSS), polyglot. Trace sinks in
  the JS bundles (innerHTML, .html(), document.write, eval, postMessage) back to sources.
- Prototype pollution: merge/setters gadgets in vendored libraries, then a DOM-XSS gadget.
- Open redirect: every redirect parameter, including protocol-relative, backslash, @, encoded,
  double-encoded, subdomain/prefix whitelist bypass.
- Host header injection: password-reset poisoning, cache poisoning via unkeyed header, routing.
- CORS: origin reflection with credentials, null origin, subdomain trust.
- Request smuggling: CL.TE / TE.CL / CL.CL, header anomalies, frontend/backend parser diff.
- Info disclosure: .git/.env/backups, source maps, verbose errors, GraphQL introspection,
  Swagger/OpenAPI, excessive data exposure in API responses.

Method: read the JS/HTML/API responses, then verify read-only. For XSS a payload must actually
execute in a real headless browser before CANDIDATE — a reflected string is a lead, not a bug.
Negative control required.

Append JSON lines to the output file (same schema as the server-side agent).
