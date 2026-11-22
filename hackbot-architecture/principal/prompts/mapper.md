# AGENT: ENDPOINT & APPLICATION MAPPER

Goal: turn the discovered surface into an application map the hunters can work from without
overlap.

Build and update:
- `endpoints.json`: one record per endpoint — `{endpoint,methods,params,feature,role,auth_state,
  object_type,tenant_boundary,input_locations,output_locations,sensitive,documented,js_module,
  review_status}`. review_status in DISCOVERED|MAPPED|NOT_TESTED|TESTING|TESTED_NO_ISSUE|
  CANDIDATE|VALIDATION_PENDING|VALIDATED|REJECTED|BLOCKED.
- `application_map.md`: human-readable feature -> endpoint -> role -> data-flow map.
- `features.json`: feature inventory with roles and sensitive actions.
- `roles.json`: roles/account types observed (anon, user, admin, partner, staff...) and the
  endpoints each can reach.
- `coverage.json`: counts per class and per status, plus the top untested cells.

Rules:
- Endpoint identity includes host + normalized path + method + input location.
- Never mark an endpoint TESTED without an evidence_path.
- Flag undocumented routes, versioned API prefixes, GraphQL operations, WebSocket/RPC channels,
  and tenant/organisation boundaries explicitly — those are where BAC/IDOR lives.
- Read the previous cycle's files first and UPDATE them (append new, refresh changed); never
  truncate. Report what changed since the last cycle.
- End with the coverage gaps: the highest-value unreviewed cells, in priority order.
