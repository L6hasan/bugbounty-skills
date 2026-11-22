# Variants 9-15 — second-order, version/context, GraphQL, JWT, and tenancy flaws

The second half of the playbook: flaws that hide behind a different request than the one
you tamper with, plus API-structure, token, and tenant-boundary failures. Same section
shape as `variants-1.md`; the two-account setup from `payloads.md` applies to every proof.

## Table of contents

- [V-09: Second-order IDOR via dynamic session parameter substitution sinks](#v-09-second-order-idor-via-dynamic-session-parameter-substitution-sinks)
- [V-10: API endpoint version bypassing for unprotected legacy resource fetching](#v-10-api-endpoint-version-bypassing-for-unprotected-legacy-resource-fetching)
- [V-11: Contextual role-based state flipping through client-side request mutation](#v-11-contextual-role-based-state-flipping-through-client-side-request-mutation)
- [V-12: GraphQL query object variable manipulation for unauthorized node access](#v-12-graphql-query-object-variable-manipulation-for-unauthorized-node-access)
- [V-13: Nested API resource path traversal for internal object-level access bypass](#v-13-nested-api-resource-path-traversal-for-internal-object-level-access-bypass)
- [V-14: JWT algorithm laundering and signature nullification privilege escalation](#v-14-jwt-algorithm-laundering-and-signature-nullification-privilege-escalation)
- [V-15: Cross-tenant data exposure via insecure multi-tenancy boundary isolation flaws](#v-15-cross-tenant-data-exposure-via-insecure-multi-tenancy-boundary-isolation-flaws)

---

## V-09: Second-order IDOR via dynamic session parameter substitution sinks

**Mechanism:** The attacker-controlled identifier is stored (profile field, callback
URL, "default document", saved filter) and used later by the server in a *different*
request context — export job, PDF renderer, scheduled task. Authorization is checked at
write time (or not at all), but the sink queries by the stored value directly: the
violated assumption is "data written under my session is safe to read under it later".

**Preconditions:**
- A field you can persist that references an object ID or owner (settings, exports,
  callbacks, shared templates, import mappings).
- A consuming action runs server-side, possibly async, under your session or none.

**Detect:**
1. Trace data flow: fields *written* in one request and *read* later — export targets,
   `default_*` settings, webhook `resource_id`, "share with user id", OAuth `state`.
2. Write `<OBJECT_ID_B>` (or B's user id) into the field using a normal update request —
   the write will often succeed silently because no check runs at storage time.
3. Trigger the consuming action (export, render, refresh, test-webhook button) and
   inspect the output for B's data — mark content with B's unique marker from setup.
4. Watch *substitution scope*: does the sink interpolate your value into a query, path,
   or template? Path/template interpolation may additionally enable traversal/SSRF
   (chain pointers in `payloads.md`).
5. Async results correlate by job id, not HTTP status.

**Proof of concept:**
```bash
# 1) Store B's object id in a trusted field (write-time check may pass)
curl -sS -i -X PUT '<TARGET_URL>/api/profile' -H 'Cookie: session=<SESSION_A>' \
  -H 'Content-Type: application/json' -d '{"default_document_id":"<OBJECT_ID_B>"}'
# 2) Trigger the sink
curl -sS -i -X POST '<TARGET_URL>/api/exports' -H 'Cookie: session=<SESSION_A>' \
  -H 'Content-Type: application/json' -d '{"type":"default_document"}'
```

**Confirm:** The export contains B's data (marker match) and B's session confirms
ownership — decisively, no trigger-time request carried B's ID: the substitution happened
server-side from stored state.

**False positives:** Value echoed but never used (send a garbage ID — if the sink
doesn't error, it isn't consumed); sink re-derives the owner from the session and returns
your own object anyway; sandbox copies generated per user; queue workers running with a
broad service account (still a finding — classify as over-privileged service context
rather than per-user IDOR); server overwrites your stored id before use.

**Impact:** "Values stored in `<field>` are trusted at use time; a user can cause
`<server-side action>` on another user's `<object>`, delivering `<data>` to the
attacker." Note the cause→effect delay for triage.

**Remediation:** Re-authorize at the point of use: every sink must resolve the stored
reference against the current principal's ownership before querying, not assume
storage-time validity.

**CWE / OWASP:** CWE-639; OWASP A01:2021; OWASP API1:2023 BOLA (second-order variant).

---

## V-10: API endpoint version bypassing for unprotected legacy resource fetching

**Mechanism:** Authorization middleware was added when v2 shipped, but v1 (or a
`legacy`/`beta` prefix, or content-negotiated variants) is still deployed without it for
backward compatibility. Old code paths carry old — absent — checks: the violated
assumption is "deprecating a version removes its risk".

**Preconditions:**
- Multiple versions/variants exist: `/api/v1`, `/api/v2`, `/legacy`, version headers
  (`X-API-Version`, `Accept: application/vnd.app.v1+json`), `?version=`, subdomains
  (`api-old.`).
- Same logical operation reachable on at least two of them.

**Detect:**
1. Inventory versions from JS bundles, OpenAPI files (`/v1/swagger.json`),
   `Deprecation`/`Sunset` headers, and error messages that name versions.
2. Replay the identical operation as low-priv A across versions; record status +
   response depth for each.
3. Read the differential: v2 `403` for `<OBJECT_ID_B>` while v1 returns `200` + data is
   the clean signal; also compare field exposure (v1 may return more fields than v2 even
   when both "work" — that's BOPLA on the legacy path).
4. Test the *auth* dimensions separately per version: session cookie vs. API key vs.
   legacy static token; old versions sometimes accept a revoked/weak credential type.
5. Try version selection via non-path channels (header, query, body `version` field) —
   the app may honor a downgraded version string inside an otherwise v2 request.

**Proof of concept:**
```bash
curl -sS -i -H 'Cookie: session=<SESSION_A>' '<TARGET_URL>/api/v2/<RESOURCE>/<OBJECT_ID_B>'   # expect 403
curl -sS -i -H 'Cookie: session=<SESSION_A>' '<TARGET_URL>/api/v1/<RESOURCE>/<OBJECT_ID_B>'   # observe response
curl -sS -i -H 'Cookie: session=<SESSION_A>' -H 'Accept: application/vnd.app.v1+json' \
  '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_B>'
```

**Confirm:** Same session, same object, different version → denied vs. returned. The
A/B differential proves the gap is version-scoped middleware, not a flaky check; back it
with B's session confirming object ownership.

**False positives:** v1 returns `200` but only *your own* or sanitized data (old
serialization may mask rows differently — check whose object it is); v1 is a documented
stub returning canned responses; v1 requires an API key with intentionally broader
scope (report as over-scoped credential, not version bypass); v1 routes actually
aliasing v2 middleware in the router (compare bodies byte-for-byte); cached v1 responses.

**Impact:** "The deprecated `/v1` path lacks the authorization enforcement added in `/v2`,
letting any authenticated user fetch other users' `<resource>`; v1 remains reachable
with `<credential type>`."

**Remediation:** Retire legacy versions (410 after a sunset window) and apply the same
authorization middleware/version-agnostic policy layer to every route regardless of
version.

**CWE / OWASP:** CWE-284 (Improper Access Control); OWASP A01:2021 — report as an
over-scoped legacy credential instead when the version's broader scope is documented by design.

---

## V-11: Contextual role-based state flipping through client-side request mutation

**Mechanism:** The server chooses an authorization context (role, tenant, agency,
impersonation, "view as") from a client-controlled channel — custom header, query param,
non-integrity-protected cookie, or body field — instead of deriving it from the
authenticated session. Flipping the value re-decides your permissions. The violated
assumption is "the client will only send the context it was issued".

**Preconditions:**
- A discoverable context input: `X-Role`, `X-User-Type`, `role`, `as`, `impersonate`,
  `tenant`, `X-Forwarded-Role`, `org` claims in client state, or an interceptable
  role-switcher request.
- Server behavior (data scope, actions, response shape) varies with the context.

**Detect:**
1. Mine context inputs from JS/HTML: role-switch dropdowns, `X-` headers in fetch code,
   `localStorage` keys like `activeRole`, `?org=` in deep links.
2. Capture a normal request, then flip one context value at a time (`role=user` →
   `role=admin`, `X-User-Type: customer` → `staff`, `tenant`/`org` ids swapped to B's).
3. Diff both dimensions: response *content* (new fields, other users' rows) and response
   *capability* (previously 403'd action now succeeds). Capability change = escalation;
   content change alone may be a filter difference.
4. Check persistence: does the flipped context survive refresh (was it written to your
   profile — that's V-04 territory) or is it per-request only?
5. Test the trust chain: if the context arrives in a JWT claim, fold this into V-14; if
   in a cookie without `HttpOnly`/signature, note cookie tampering as the vector.

**Proof of concept:**
```bash
curl -sS -i -H 'Cookie: session=<SESSION_A>' -H 'X-Role: admin' \
  '<TARGET_URL>/api/<FUNCTION_ONLY_ADMANS_HAVE>'
curl -sS -i -H 'Cookie: session=<SESSION_A>' -H 'X-Tenant: <TENANT_ID_B>' \
  '<TARGET_URL>/api/<RESOURCE>'
```

**Confirm:** A function/data set that is only reachable in the flipped role, verified
against an account that legitimately holds that role (or a lab admin account): same
outcome from the forged context and from the real role proves the server honored your
claim. Echoed headers or cosmetic changes don't count.

**False positives:** Header/param echoed into the response but ignored in policy; role
re-derived from the DB at check time (flip accepted, effect null); display-only
context (different UI theme, same data); CDN/bot-management headers with predictable
names that apps merely log; context affecting a sandbox/test mode flag.

**Impact:** "Authorization context is attacker-controlled: by setting `<input>` the user
gains `<role>`'s `<actions/data>` without any role assignment." If the flip reaches
other users' data, cross-reference the tenant/role data class for severity.

**Remediation:** Derive role, tenant, and impersonation state solely from the verified
session/token server-side; strip client-supplied context fields at the edge.

**CWE / OWASP:** CWE-602 (Client-Side Enforcement of Server-Side Security) / CWE-862;
OWASP A01:2021.

---

## V-12: GraphQL query object variable manipulation for unauthorized node access

**Mechanism:** GraphQL resolves typed objects from client-supplied variables — often
relay-style global IDs that are just `base64("TypeName:id")`. Resolvers check that *you
passed a valid ID*, not that *you own the node*, so swapping the decoded id (or the
type) inside the variable reaches another user's private fields. Null-safety quirks and
aliases can further leak which IDs exist.

**Preconditions:**
- A GraphQL endpoint (`/graphql`, `/gql`, WS subscription) accepting queries with
  `ID`/`String` variables (find them via introspection or the client's operation log).
- Some node type with per-user data (`User`, `Invoice`, `Message`, `Document`).

**Detect:**
1. Run introspection (template in `payloads.md`) — list query fields taking `$id: ID!`
   and object types with private fields; note the `node(id:)` field if relay-style.
2. Decode your own global ID: `echo -n 'User:<YOUR_ID>' | base64` →
   `VXNlcjoxMjM=`. Swap the inner id for `<USER_ID_B>` and re-encode — if the encoding
   is trivially reversible, ID opacity never protected this API.
3. Send the query with B's variable as session A; repeat as B (control) and with no
   token (auth control).
4. Probe field-level authorization: ask for sensitive fields (`email`, `phone`,
   `internalNotes`) even on *your own* node — sometimes the resolver leaks them to
   anyone, which is BOPLA on top of the IDOR.
5. Sweep types, not just ids: same id under different type names (`User:5` vs
   `Invoice:5`); resolver confusion across types is its own gap.
6. Note error-shaping: `Node not found` vs `Not authorized` tells you whether a check
   exists at all (differential is also an enumeration oracle).

**Proof of concept:**
```bash
curl -sS -i -X POST '<TARGET_URL>/graphql' -H 'Cookie: session=<SESSION_A>' \
  -H 'Content-Type: application/json' \
  -d '{"query":"query($id:ID!){ node(id:$id){ ... on User { email } } }","variables":{"id":"<BASE64_TYPE_B_ID>"}}'
```

**Confirm:** B's private field values returned to session A, matched against the same
query executed by session B's own session — plus the no-token control returning 401.
Three-way differential, done with two curl calls.

**False positives:** Resolver returns only public-profile fields (diff against B's full
view field by field); introspection result mistaken for data exposure (schema ≠ records);
caching/proxy serving one user's response to another (check `Set-Cookie`/`Age` — that's
a cache bug, report separately); aliases/batching changing nothing about authz; node
types intentionally public (docs, shared workspace objects).

**Impact:** "Any authenticated user can enumerate GraphQL nodes of type `<type>` by
swapping the id variable, exposing `<field list>`. Global IDs are reversible
(`base64`), so no entropy protects the API."

**Remediation:** Authorize inside each resolver against the session principal, treat
global ID encoding as formatting (never security), and redact fields per-viewer.

**CWE / OWASP:** CWE-639; OWASP A01:2021; OWASP API1:2023 BOLA (GraphQL profile).

---

## V-13: Nested API resource path traversal for internal object-level access bypass

**Mechanism:** Nested routes compose authorization from segments (`/users/<uid>/orders/<oid>`)
but the server validates only one segment — usually the parent, sometimes neither. Swapping
the inner segment under your own parent yields the victim's child, and normalization tricks
(`..`, `%2f`, `//`) bypass composition entirely: "the parent I passed is the object's parent" is false.

**Preconditions:**
- At least two-segment object routes (or nested GraphQL/REST paths like
  `/orgs/<org>/members/<user>`).
- Child IDs independently obtainable for B (from the two-account setup).

**Detect:**
1. Map nested routes from JS/OpenAPI; list which segments are object ids vs. slugs.
2. Vary segments *independently*: fix your parent, swap the child; fix B's child, swap
   the parent; all four A/B combinations — the matrix shows which segment is checked.
3. Normalization probes on the parent segment: `/users/<USER_A>/../<USER_B>/orders/<OID>`,
   `/users/%2e%2e%2f<USER_B>/orders/<OID>`, `//users/<USER_B>/orders/<OID>`, trailing
   `/./` — send raw (curl `--path-as-is`) so the client doesn't normalize for you.
4. Check intermediate layers: an API gateway may authorize the first segment only, then
   hand the full path to the service — the split is visible when gateway-level checks
   pass but the service answers with foreign data.
5. Also try nesting depth changes: `/orders/<OID>` directly vs.
   `/users/<uid>/orders/<OID>` — flatter route often lacks the parent check by design
   debt.

**Proof of concept:**
```bash
curl -sS -i --path-as-is -H 'Cookie: session=<SESSION_A>' \
  '<TARGET_URL>/api/users/<USER_ID_A>/orders/<ORDER_ID_B>'
curl -sS -i --path-as-is -H 'Cookie: session=<SESSION_A>' \
  '<TARGET_URL>/api/users/../users/<USER_ID_B>/orders/<ORDER_ID_B>'
```

**Confirm:** Response contains B's child object while the outer segment names *your*
user — verified by B's session fetching the same child (marker match). The parent/child
mismatch visible in the single request plus B's control = confirmed.

**False positives:** Router ignores the parent but authorizes the child correctly (you get
*your* order — safe; only a V-01 if child authz is missing elsewhere); `<ORDER_ID_B>` is
actually yours (namespace overlap); edge normalizes `..` before auth (replay with
`--path-as-is`); file-access `..` issues belong to `path-traversal-testing`; public/shared
children (shared invoices, team docs).

**Impact:** "Segment-level checks are incomplete: users can address any `<child>` by
altering `<segment>`, bypassing the parent-scoped permission model that the API design
implies."

**Remediation:** Authorize every path segment against its owner (parent *and* child)
using canonicalized paths — reject `..`, encoded separators, and duplicate slashes at
the edge before routing.

**CWE / OWASP:** CWE-639 with CWE-20 (path structure validation); OWASP A01:2021 — if
`..` reaches filesystem paths, hand off to `path-traversal-testing` (CWE-22).

---

## V-14: JWT algorithm laundering and signature nullification privilege escalation

**Mechanism:** The server trusts the token's own `alg` header (or a client-controlled key
reference) when deciding how to verify — or skips verification for `none`. An attacker
edits claims (`role`, `sub`, `tenant`) and re-signs under a weaker regime (unsigned
`alg:none`, or HS256 keyed with the public key from the app's JWK): "the token header is
a hint the client may choose".

**Preconditions:**
- A JWT is used for auth; you can modify your own token — its verification behavior is what the `payloads.md` checklist determines.
- Know a target claim to flip and its legitimate value (B's `sub`/`role` from your own test setup).

**Detect:**
1. Decode your token (it's just base64url); record `alg`, `kid`, `jku`/`jwk` and claims
   `sub`, `role`/`admin`, `tenant`/`org`, `exp`, `iat`, `nbf`, scopes — plus where the
   token lives (unsigned cookies can be swapped wholesale).
2. Walk the JWT checklist in `payloads.md`: `alg:none` → RS256→HS256 confusion →
   `kid`/key-reference injection → `exp`/`iat`/`nbf` tampering → claim tampering; record
   each response.
3. Classify responses: `401 invalid signature` = verified (healthy); `401 malformed` =
   parsed but rejected early; `200` = finding — now prove the claim *took effect*.
4. Effect test: take the accepted tampered token and hit a resource gated by the changed
   claim (role-gated function, B's `sub`-owned object). Accepted-but-ignored = token-
   integrity issue (lower severity); honored = escalation (high/critical).
5. Check the key source: fetch `/.well-known/jwks.json` — if the server HS256-verifies,
   the public key material is the HMAC secret; find how `kid` maps to a key (path/URL/DB).

**Proof of concept:** (forging done with a JWT tool per the checklist — never paste a forged real-target token into a report)
```bash
# Replay the tampered test token produced by the checklist against a gated resource
curl -sS -i -H 'Authorization: Bearer <TAMPERED_TEST_TOKEN>' \
  '<TARGET_URL>/api/<ROLE_GATED_FUNCTION>'
```

**Confirm:** Two-part: the tampered token is *accepted* (no 401) **and** the modified
claim *changes authorization outcome* (admin function executes, or B's object returned
for your `sub` swap — verified with B's session). Either half alone is a lesser finding.

**False positives:** Library rejects on parse regardless of `alg` (401 everywhere —
healthy); token accepted but claims re-loaded from DB per request (tamper ignored —
report only if something depends on signed claims); `exp` accepted beyond expiry but
session revoked elsewhere; endpoint public anyway; "expired token accepted" when the
request also carried a *second* valid auth mechanism (isolate the token in curl).

**Impact:** "JWT verification honors attacker-chosen parameters (`<vector>`), enabling
forged `<claim>` values — escalation to `<role>` / impersonation of `<sub>` / auth
bypass." Severity tracks what the honored claim controls.

**Remediation:** Pin an algorithm allow-list per key, verify the signature before reading
any claim, never HS256-key with public key or attacker-influenceable `kid`/`jku` values,
and enforce `exp`/`nbf` with bounded leeway.

**CWE / OWASP:** CWE-347 (Improper Verification of Cryptographic Signature); OWASP
A02:2021 + A01:2021; OWASP API2:2023 Broken Authentication (JWT profile).

---

## V-15: Cross-tenant data exposure via insecure multi-tenancy boundary isolation flaws

**Mechanism:** Tenancy scope should be enforced server-side from session context on every
query, cache key, and background job. When the tenant id comes from the client, is omitted
from a WHERE clause, or is missing from a cache key, records cross the org/workspace
boundary — "sharing the database is safe as long as the UI shows one tenant" is false.

**Preconditions:**
- You can hold sessions in two tenants (two organizations — self-serve signup is the
  normal path; both under your control for the proof).
- Resources exist that are unique to tenant B (marker field set by B).

**Detect:**
1. Establish two tenants (A and B) with uniquely marked objects; record both tenant ids
   (`org_id`, `workspace`, subdomain, `X-Tenant`, token claim).
2. Enumerate tenant carriers: subdomain, path prefix (`/orgs/<id>/`), header, query
   param, JWT claim. Try flipping each to B's value with session A — some apps will
   happily change your *view* even when they don't change your *permissions*.
3. Sweep the read surfaces: detail endpoints (V-01 style), list/search/export endpoints
   (filters are where tenant clauses go missing), autocomplete, and reports.
4. Cache axis: replay B's request under A's session and look for B's response with A's
   CDN headers (`Age`, `X-Cache`) — tenant-agnostic cache keys leak even correct apps.
5. Background surfaces: export jobs and webhooks often run with a tenant-spanning service account.
6. Test both matrices: within-tenant peer escalation and cross-tenant are separate findings.

**Proof of concept:**
```bash
# A's session asking for B's tenant scope
curl -sS -i -H 'Cookie: session=<SESSION_A>' -H 'X-Tenant: <TENANT_ID_B>' \
  '<TARGET_URL>/api/<RESOURCE>'
curl -sS -i -H 'Cookie: session=<SESSION_A>' '<TARGET_URL>/orgs/<TENANT_ID_B>/<RESOURCE>'
# List-surface sweep (server-side filter check)
curl -sS -i -H 'Cookie: session=<SESSION_A>' '<TARGET_URL>/api/search?q=<B_MARKER_STRING>'
```

**Confirm:** Data that exists *only* in tenant B (marker verified in B's own session)
returns under A's session or A's tenant context — and the no-flip control shows only
A's rows. That four-way differential (A plain / A flipped / B own / A-flipped-then-B-check)
excludes cache and fixture explanations.

**False positives:** Intentionally cross-tenant resources (public templates, marketplace
listings, platform announcements — check sharing mode); demo fixtures visible to all;
shared ID namespace but rows are still your own (verify marker); two accounts accidentally
in the *same* tenant (re-verify tenant ids — the most common self-inflicted waste here).

**Impact:** "A user of tenant `<X>` can read/modify data belonging to tenant `<Y>`
(`<record class>`), i.e., a cross-company data breach in a B2B product — regulatory
exposure (GDPR/CCPA)." State blast radius: one record shown, the record class implied.

**Remediation:** Derive tenant scope exclusively from the verified session and enforce it
at the query layer (repository policy or DB row-level security) plus in every cache key.

**CWE / OWASP:** CWE-639 / CWE-284 (tenant boundary as access-control root); OWASP
A01:2021; OWASP API1:2023 BOLA (tenant-wide manifestation).
