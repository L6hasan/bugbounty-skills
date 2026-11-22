---
name: bb.bigid.cloud
description: Recon notes, scope, attack surface, tested history and open leads for bb.bigid.cloud — use when hunting on this target, resuming a previous engagement, or when a conversation mentions bb.bigid.cloud / bigid.cloud.
---

# bb.bigid.cloud

**Program / authorization:** Own infrastructure (user-asserted, 2026-10-23) — self-hosted bug-bounty test lab. User granted full tooling/scanning permission; scope limited to **unauthenticated testing**.
**Last engagement:** 2026-10-23

## Scope
- In scope: `https://bb.bigid.cloud/` — all unauthenticated attack surface (RXSS, DOM XSS, stored XSS, GET-based XSS, CSRF, SQLi, info disclosure, path traversal, business logic, header/response injection).
- Out of scope / exclusions: authenticated abuse beyond unauth surface, destructive actions, DoS/rate-limit exhaustion, credential reuse.
- Rate limits & testing windows: unspecified — be conservative (small bursts, back off on 403/406/429).

## Stack (verified 2026-10-23)
- WAF: unknown — TBD in recon
- Server / framework / language: unknown — TBD in recon
- Auth model: unknown — TBD in recon
- Notable middleware: unknown — TBD in recon

## Attack surface
### Subdomains & hosts
| Host | Purpose | Stack | Notes |
|---|---|---|---|
| bb.bigid.cloud | test lab | unknown | primary target |

### Endpoints
| Endpoint | Params | Auth | Signal / sink | Tested? |
|---|---|---|---|---|

### API / GraphQL
unknown — check /swagger, /graphql introspection

## Findings history
| Date | Endpoint | Class | Status | Report |
|---|---|---|---|---|

## Ruled out (and why)
(none yet)

## WAF / defense behavior
(none yet)

## Next session (ranked)
1. robots.txt / security.txt / sitemap — free scope intel
2. Root page + JS bundle enumeration
3. Parameter discovery on discovered endpoints
