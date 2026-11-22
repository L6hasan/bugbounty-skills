# Domain profile template

Copy this skeleton to `domains/<domain>/SKILL.md` and fill it in. Keep the frontmatter
description — it is what makes the profile advertise itself as a skill.

```markdown
---
name: <domain>
description: Recon notes, scope, attack surface, tested history and open leads for <domain> — use when hunting on this target, resuming a previous engagement, or when a conversation mentions <domain>.
---

# <domain>

**Program / authorization:** <name + link, or "own infra", or "UNKNOWN — confirm before testing">
**Last engagement:** <date or "never">

## Scope
- In scope: <hosts, paths>
- Out of scope / exclusions: <paths, actions, DoS, payments, user data>
- Rate limits & testing windows: <numbers/windows, or "unspecified — be conservative">

## Stack (verified <date>)
- WAF: <none detected / name + what it blocks>
- Server / framework / language: <evidence-based, not guessed>
- Auth model: <cookie session / JWT / SSO — where tokens appear>
- Notable middleware: <CDN, reverse proxy, rate limiter quirks>

## Attack surface
### Subdomains & hosts
| Host | Purpose | Stack | Notes |
|---|---|---|---|

### Endpoints
| Endpoint | Params | Auth | Signal / sink | Tested? |
|---|---|---|---|---|

### API / GraphQL
<introspection state, schema notes, versioning>

## Findings history
| Date | Endpoint | Class | Status | Report |
|---|---|---|---|---|

## Ruled out (and why)
<endpoint → variant tested → result>. Prevents re-testing dead ends.

## WAF / defense behavior
<what returns 403/406, what passes, encoding that worked>

## Next session (ranked)
1. <highest-value untested surface>
2. ...
```

## Rules

- **Verified vs. guess:** mark anything inferred from a single header as `guess`.
  A wrong stack entry costs the next session an hour.
- **Append, don't overwrite.** Tested-history and ruled-out entries are the asset.
- **Findings live beside the profile:** `domains/<domain>/findings/<id>-<slug>.md`, with the
  raw request/response pair under `evidence/`.
- **One profile per registrable domain.** Subdomains go in the *Attack surface* table unless
  they are independently scoped targets with their own program rules.
