# bac-idor-bola — part 1/5 (61 segment(s))
# content-aware dedupe applied; every unique entry preserved.

## [Bugbountyskills.md] >> bac-idor-testing — SKILL.md

*Source: `/root/Myskill/bac-idor-testing/SKILL.md`*

## [Bugbountyskills.md] BAC / IDOR Testing Playbook

A methodical playbook for finding and proving broken access control: IDOR (BOLA/BMAO),
function-level (RBAC/ABAC) bypasses, mass assignment, HPP mutations, predictable IDs,
second-order substitution, version/role/context confusion, GraphQL node access, JWT
algorithm abuse, and multi-tenant boundary failures.

## [Bugbountyskills.md] 1. Scope & authorization guardrail

Only test targets the user is authorized to test: a published bug bounty program with
this asset in scope, an explicitly scoped pentest asset, or the user's own lab/CTF.
Refuse out-of-scope hosts, third-party targets, and anything the user cannot show
authorization for. Never run destructive or availability-harming payloads (bulk DELETE,
unbounded enumeration loops, request floods) — access control bugs are proven with a
handful of requests, not thousands. Keep every proof minimal: when a reachable object
belongs to a real user you do not control, take the smallest redacted sample that proves
the ownership boundary was crossed and nothing more. The skill exists to make authorized
testing methodical and to produce reports that hold up under triage.

## [Bugbountyskills.md] Title: <Resource/action> accessible across accounts via <missing check> (IDOR/BOLA/<variant>)

**Severity:** <Low/Medium/High/Critical — justify with data sensitivity + action + auth requirement>
**Endpoint:** `<METHOD> <path>` (parameters: `<param>`)
**Variant:** V-<NN> <name>

## [Bugbountyskills.md] >> bac-idor-testing — payloads.md (request templates, tool commands, evasion)

*Source: `/root/Myskill/bac-idor-testing/references/payloads.md`*

## [Bugbountyskills.md] GraphQL introspection & authorization probes

Fill `<TARGET_URL>` (usually `/graphql`), keep `-b jar_a.txt` / `-b jar_b.txt` separate.

```bash

## [Bugbountyskills.md] --- G8: error-shaping oracle (does "not found" vs "not authorized" leak existence?)

curl -sS -b jar_a.txt -X POST '<TARGET_URL>/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"query($id:ID!){ node(id:$id){ id } }","variables":{"id":"<BASE64_RANDOM_GUESS>"}}'
```

**Reading the results:** G5 returning B's private fields (matched against B's own G4
response) = **V-12**. G7 returning fields the UI never shows = BOPLA on top. G8's
differential is an enumeration oracle worth reporting alongside V-12 when IDs are
otherwise unpredictable. Aliases/batching (`{ a: user(id:1){...} b: user(id:2){...} }`)
are useful to compress probes — respect the throttle note below even over batching.

---

## [Bugbountyskills.md] >> bac-idor-testing — variants-1.md (variant playbook)

*Source: `/root/Myskill/bac-idor-testing/references/variants-1.md`*

## [Bugbountyskills.md] Variants 1-8 — IDOR core, function-level, and ID-shape flaws

Deep playbook for the first eight broken access control variants. Each section follows
the same shape: **Mechanism → Preconditions → Detect → Proof of concept → Confirm →
False positives → Impact → Remediation → CWE / OWASP**. Payloads, curl templates, and
the two-account setup live in `payloads.md` — every proof below assumes you completed
that setup first.

## [Bugbountyskills.md] V-01: Direct parameter manipulation via authenticated IDOR security evasion

**Mechanism:** The endpoint authenticates the session but never binds the object
identifier to that session's principal. The server trusts the client-supplied `id` as
the lookup key and returns/acts on whatever row comes back — the violated assumption is
"whoever knows the ID is allowed to use it".

**Preconditions:**
- Valid session (cookie/token) for Account A; the endpoint loads an object by ID.
- Object IDs for a second principal are obtainable (your Account B, sequential guessing,
  or an ID leaked elsewhere — see `payloads.md` ID catalog).
- Endpoint is read or write; both are in scope.

**Detect:**
1. While signed in as A, capture a request for one of *your own* objects (`GET`, `PUT`,
   `POST`, `DELETE`) and note every place the ID appears: path, query, body, header.
2. Create the same class of object as Account B and record `<OBJECT_ID_B>`.
3. Replay A's request with only the ID swapped to `<OBJECT_ID_B>` — change nothing else.
4. Watch the status *and* the body: `200` + B's fields = hit; `403/404` = checked;
   `200` + `{"error":...}` = soft-404 (see False positives).
5. Delta-probe: try `<OWN_ID>±1`, the same ID with different type prefixes
   (`order_123` → `invoice_123`), and light encoding variants (path case, `%2d`, param
   in query vs. body) only if a WAF blocks the plain swap — encode the value, not the
   structure.

**Proof of concept:**
```bash

## [Bugbountyskills.md] V-02: Unauthenticated endpoint identification via IDOR resource enumeration

**Mechanism:** An endpoint that should require authentication has no auth middleware at
all (or only client-side gating). The trust assumption "you must be logged in to reach
this route" is enforced in the UI, never on the server.

**Preconditions:**
- Route exists and returns object data; you can replay it without credentials.
- The app has some session model, so a protected sibling endpoint exists to use as a
  control.

**Detect:**
1. Capture the request with full credentials, then replay it with the `Cookie`/`Authorization`
   header removed entirely (fresh curl, no jar).
2. Compare three responses: (a) A authenticated on own object, (b) A on B's object, (c)
   no credentials at all.
3. Three-way read: `401/403` with no credentials + `403` for B's object = healthy;
   full object body with no credentials = missing authentication (V-02); body only for
   B's object while authenticated = missing ownership check (V-01/V-05).
4. Check response headers for cache artifacts (`Age`, `X-Cache: HIT`) — a cached
   personalized page can fake an unauthenticated leak (see False positives).
5. Repeat on the write methods too: a GET that is "public" may be fine while the
   matching `POST` is the real problem.

**Proof of concept:**
```bash

## [Bugbountyskills.md] V-03: Scripted request validation and automation via custom cURL IDOR frameworks

**Mechanism:** This is the *method* variant: instead of hand-testing one ID, you sweep a
small candidate set with both sessions and classify response pairs. It exploits nothing
by itself — it turns a hunch ("these IDs look sequential") into a statistically solid
finding fast, and it catches the cases where only *some* objects leak (mixed ownership
rows, stale cache entries, per-tenant gaps).

**Preconditions:**
- Two authenticated sessions (cookie jars `jar_a` / `jar_b` from the two-account setup).
- A small candidate ID list (10-50 entries, see the ID catalog in `payloads.md`).
- Program's rate-limit rules known; you will stay well under them.

**Detect:**
1. Fix the request shape once (method, path, headers) and vary only the ID.
2. Run the matrix: each candidate ID × each session; classify into `OWN`, `CROSS-LEAK`,
   `DENIED`, `SOFT-404`, `ERROR` by status + a body fingerprint (length, JSON path of a
   key field — not just status code).
3. Look for anomalies: any `CROSS-LEAK` row, any ID where A gets 200 but the body
   matches B's object rather than A's, any `DENIED` for one ID and `200` for its
   neighbor (inconsistent authorization = per-object gap).
4. Keep the sweep polite: one request per second, stop at the first 10 cross-principal
   hits — you need proof, not a database dump.

**Proof of concept:** Template (fill slots; throttle is deliberate):
```bash
jar_a=<JAR_A>; jar_b=<JAR_B>
for id in <ID_1> <ID_2> <ID_3>; do
  code=$(curl -sS -o /tmp/body_$id -w '%{http_code}' -b "$jar_a" \
    '<TARGET_URL>/api/<RESOURCE>/'"$id")
  echo "$id A-> $code $(wc -c </tmp/body_$id)"
  sleep 1
done
```
(Exact templates, including ffuf variants, are in `payloads.md`.)

**Confirm:** Re-run one anomalous row by hand with a clean curl and verify against B's
session that the object belongs to B. Script output is a lead until one row is
reproduced manually.

**False positives:** Rate-limit or WAF pages served with HTTP 200 (fingerprint the body
— `<!doctype html>` in a JSON API is a block page); cookie jars cross-contaminated so
both "sessions" are actually the same user; redirects normalizing every ID to your own
profile; soft-404s inflating the 200 count; session expiry mid-sweep producing uniform
`401` rows that look like "all denied".

**Impact:** Phrase as scale: "authorization is checked inconsistently across `<N>`
objects; `<K>` of `<N>` tested IDs returned cross-account data." Scale drives severity —
systemic vs. one-off.

**Remediation:** Centralize the authorization decision in one layer applied to every
object fetch (middleware/policy), and alert on cross-principal access attempts in logs.

**CWE / OWASP:** CWE-639; OWASP A01:2021.

---

## [Bugbountyskills.md] V-05: Horizontal privilege escalation via missing object-level access control (BOLA/BMAO)

**Mechanism:** The canonical OWASP API1 flaw, tested as a *family* rather than a single
parameter: reads, updates, deletes, and list filters on one resource all skip the "does
this object belong to the caller?" check. BMAO extends the gap field-by-field — you may
fetch the object but also receive/modify properties beyond your role's visibility
(e.g., other users' `internal_notes` on a shared record).

**Preconditions:**
- Two accounts with parallel objects (from the two-account setup).
- Resource exposes collection, detail, and ideally mutation routes.
- Tester controls the objects used for destructive tests (reads only on any third-party object).

**Detect:**
1. Build an ownership matrix for one resource: `GET detail`, `GET collection`,
   `PUT/PATCH`, `DELETE`, plus `?filter=user_id=` style query params — rows vs. accounts
   A and B.
2. For the collection endpoint, check filtering happens *server-side*: send
   `?user_id=<USER_ID_B>` as A and confirm rows change; if the app ignores it and still
   lists only your rows, the list path is safe while detail may not be.
3. Run the write verbs against `<OBJECT_ID_B>` using objects B created for this test —
   update a marker field, then delete as the final step (and only B's own test object).
4. Property-level pass: diff the JSON you get for B's object against what B's UI shows;
   extra fields (`email`, `ssn`, `internal_*`, `cost`) are BOPLA/BMAO even if the IDOR
   itself is accepted risk.
5. Method-spoofing pass: `X-HTTP-Method-Override` / `_method=DELETE` if only GET is guarded.

**Proof of concept:**
```bash
curl -sS -i -H 'Cookie: session=<SESSION_A>' '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_B>'
curl -sS -i -X PUT -H 'Cookie: session=<SESSION_A>' -H 'Content-Type: application/json' \
  -d '{"marker":"A-PROOF-1"}' '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_B>'
curl -sS -i -X DELETE -H 'Cookie: session=<SESSION_A>' '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_B>'
```

**Confirm:** The classic two-account confirmation: after A's write, sign in as B and see
the modified marker on B's own object (or its absence after delete). The change must be
*in B's session*, not just in A's response.

**False positives:** Write appears accepted but is silently dropped or scoped back to A
(check B's view!); CDN/proxy 200 stubs; soft-404 on DELETE (nothing was actually
deleted); objects in a shared/team workspace where cross-access is intended (verify the
object's sharing mode); test/sandbox data visible to all accounts by design.

**Impact:** "Any authenticated user can list/read/modify/delete any other user's
`<resource>` via `<route>`; demonstrated on one object (redacted), pattern is systemic."
Add data sensitivity and whether delete is irreversible.

**Remediation:** Enforce one policy decision — `(session principal, action, object)` —
in a shared authorization layer for every object-level route, including nested and list
filters, and apply property-level filtering to responses.

**CWE / OWASP:** CWE-639; OWASP A01:2021; OWASP API1:2023 BOLA (+ API3:2023 BOPLA for
the property-level pass).

---

## [Bugbountyskills.md] V-06: Vertical privilege escalation via function-level access control evasion (RBAC/ABAC bypass)

**Mechanism:** Function-level checks (admin panels, moderation actions, impersonation,
bulk ops) are gated by UI hiding or a client-side role check. The server route executes
for any valid session — the violated assumption is "the button only shows for admins".

**Preconditions:**
- You know or can guess privileged function routes (from JS bundles, mobile app,
  sitemap, role-separated test accounts).
- ABAC variant: policies reference attributes (department, tier, scope) you can influence
  or that default permissively.

**Detect:**
1. Enumerate function-level endpoints from client code and docs; note the exact verb
   each uses (`POST /api/admin/users/<id>/ban`).
2. Build a role × endpoint matrix: session as low-priv A vs. any elevated account you
   control (labs/CTFs often grant one; otherwise infer from error strings).
3. Probe as the low-priv session: `403/401` = gated; `200` + action executed = bypass;
   `200` + `{"error":"forbidden"}` = soft gate (log it, not a finding yet).
4. Try verb and path shapes the middleware may miss: `GET` vs `POST`, trailing slash,
   case variation, method-override headers, `/api/admin/...` vs `/api/v1/admin/...`
   (feeds V-10).
5. For ABAC, vary *your own* attributes (org, tier, scope claim) and see the policy
   decision change — a policy that says "allow if attribute matches request" is
   attacker-controlled policy input.

**Proof of concept:**
```bash
curl -sS -i -X POST -H 'Cookie: session=<SESSION_A>' \
  -H 'Content-Type: application/json' -d '{"action":"ban","target":"<USER_ID_B>"}' \
  '<TARGET_URL>/api/admin/<ACTION>'
```

**Confirm:** The privileged *action actually executes* — verified by an independent
observer (the affected account sees the state change, or an admin account confirms it in
its own session). A bare 200 is a lead; a completed action is the finding.

**False positives:** Universal 200 error pages; JSON `200 {"message":"forbidden"}`;
routes that exist but no-op for non-admins (nothing changed anywhere); cached
admin-page HTML; endpoints whose "admin" scope comes from an API key you were issued
deliberately (report as scope misconfig, not escalation); rate-limit redirects masking
the real status.

**Impact:** "A standard user can invoke `<admin function>` — `<concrete consequence:
ban users / read all records / change pricing / grant roles>` — because role checks
exist only in the UI."

**Remediation:** Perform a server-side role/attribute check at each function entry point
(default-deny, deny on role lookup failure), sharing one authorization library with the
object layer instead of sprinkling `if (user.isAdmin)` checks that new routes forget.

**CWE / OWASP:** CWE-285 (Improper Authorization) / CWE-862 (Missing Authorization);
OWASP A01:2021; OWASP API5:2023 Broken Function Level Authorization (BFLA).

---

## [Bugbountyskills.md] V-07: Server-side array confusion via HTTP parameter pollution (HPP) IDOR mutations

**Mechanism:** Repeated or array-encoded parameters are parsed differently by the layers
in front of the app (WAF/LB/proxy vs. framework). One layer's ownership filter reads the
first value (your own ID, passes) while the application's data access reads the second
(the victim's ID) — a split-brain between the check and the action.

**Preconditions:**
- Stack tolerant of duplicate params (PHP `id[]`, ASP.NET indexed, Node `qs`, JVM arrays)
  or a proxy that normalizes differently than the app.
- An endpoint where the ID appears in query string or form body (less common in JSON).

**Detect:**
1. Take a working V-01 probe and duplicate the parameter:
   `?id=<OWN_ID>&id=<OBJECT_ID_B>`, `?id[]=<OWN_ID>&id[]=<OBJECT_ID_B>`, and the
   mixed-position variants (victim first / own first).
2. Vary the *name* shape: `id`, `Id`, `ID`, `id%5B%5D`, `id[0]`, `id.` / `id_` (some
   parsers collapse these into one slot).
3. Move one copy across layers: one in the query string, one in the body (`application/x-www-form-urlencoded`
   alongside a JSON body), or one in a header the app also reads (`X-Id`).
4. Observe the split: response body references `<OBJECT_ID_B>`'s data while a logging/
   cache layer keyed on the first value suggests your own ID — the divergence *is* the
   bug.
5. Repeat with ownership filters: `?owner=<ME>&owner=<THEM>`, `?tenant_id=` pairs.

**Proof of concept:**
```bash
curl -sS -i -g -H 'Cookie: session=<SESSION_A>' \
  '<TARGET_URL>/api/<RESOURCE>?id=<OWN_ID>&id=<OBJECT_ID_B>'
curl -sS -i -H 'Cookie: session=<SESSION_A>' \
  '<TARGET_URL>/api/<RESOURCE>?id[]=<OWN_ID>&id[]=<OBJECT_ID_B>'
```

**Confirm:** Two-layer divergence: the returned object provably belongs to B (verified
in B's session) while your single-value request against the same object is denied. That
pair proves the duplicate value changed the outcome, not just the payload.

**False positives:** Framework simply takes first or last value and your second value is
never used (no divergence — outcome identical to a plain V-01 probe); the "victim" value
is a shared/public object; array syntax silently ignored; your own and the victim ID
happen to resolve to the same record (namespace collision); encoded brackets stripped by
the edge so only one value survives.

**Impact:** "Duplicate-parameter handling lets the attacker bypass the `<param>` ownership
filter, reaching other users' `<resource>` — filter and application disagree on which
value is authoritative."

**Remediation:** Reject duplicate parameter names at the edge (normalize to a single
value or 400) and parse parameters strictly once, so filter and data access always read
the same value.

**CWE / OWASP:** CWE-235 (Improper Handling of Extra Values) / CWE-88-adjacent argument
smuggling; OWASP A01:2021 (with A03:2021 as a secondary tag where input is query-driven).

---

## [Bugbountyskills.md] >> bac-idor-testing — variants-2.md (variant playbook)

*Source: `/root/Myskill/bac-idor-testing/references/variants-2.md`*

## [Bugbountyskills.md] V-09: Second-order IDOR via dynamic session parameter substitution sinks

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

## [Bugbountyskills.md] V-12: GraphQL query object variable manipulation for unauthorized node access

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

## [Bugbountyskills.md] V-14: JWT algorithm laundering and signature nullification privilege escalation

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

## [Bugbountyskills.md] 1. Scope & authorization guardrail

Only test targets the user is authorized to test: a published bug bounty program with
this asset in scope, an explicitly scoped pentest asset, or the user's own lab/CTF.
Refuse out-of-scope hosts, third-party targets, and anything the user cannot show
authorization for. Logic tests touch money and shared state, so extra rules on top of
the usual ones: never generate real money, credits, or discounts beyond the minimal
demonstrable amount (one cent-scale unit, one extra redemption on a code you created
yourself); never consume, burn, or invalidate coupons, balances, or records belonging to
other users; prefer the staging or sandbox tenant whenever the program offers one; and
never run availability-harming payloads — algorithmic-complexity probes stop at the
first clear latency curve, race bursts at 10-20 requests. Quantify impact conservatively
in reports: claim the multiplier or amount you actually demonstrated, and label the
theoretical scale as such. The skill exists to make authorized testing methodical and
to produce reports that hold up under triage.

## [Bugbountyskills.md] redirect_uri variant at the authorize step

curl -sS -i '<TARGET_URL>/oauth/authorize?client_id=<CLIENT_ID>&redirect_uri=<VARIANT>&response_type=code'
```

**Confirm:** Two tester-controlled accounts demonstrate the end state: victim's login
lands in the attacker's session (login CSRF), or an intercepted `code` is redeemed for
victim's token at an attacker-controlled `redirect_uri` — verified by signing in as the
victim and seeing the linkage/session. Both sides are your own accounts (guardrail);
one-account "worked for me" flows prove nothing about ATO.

**False positives:** `state` validated against your *own* completed flow (only a
cross-session replay proves login CSRF); loose `redirect_uri` matching that still
rejects off-domain hosts (path-only flexibility is a real but lower-severity finding —
say which); PKCE optional for *confidential* clients (spec-permitted; report per program
policy rather than as a bypass); callback returning `200` with an error body (read the
body before claiming acceptance); `state` checked but bypassed only with a token you
yourself minted (that's V-05 territory).

**Impact:** "`<flow>` permits `<login CSRF / code interception via redirect_uri or
dynamic registration / PKCE downgrade>` → account takeover of any user who can be made to
visit one URL (or click one link)." High/critical only with the two-account end-state
demo; otherwise report the individual control failure with its narrower reach.

**Remediation:** Exact-match `redirect_uri` against pre-registered values, random
per-session `state` validated once and invalidated, PKCE (`S256`) required for public
clients, single-use short-TTL codes, and registration-endpoint hardening (no arbitrary
redirects, authenticated developers).

**CWE / OWASP:** CWE-345 (Insufficient Verification of Data Authenticity) / CWE-352
(CSRF, for login CSRF) / CWE-862; OWASP A07:2021; RFC 9700 (OAuth 2.0 Security BCP).

---

## [Bugbountyskills.md] Probe: one privileged field added

curl -sS -i -c jar_probe.txt -X POST '<TARGET_URL>/api/register' \
  -d 'email=<EMAIL_PROBE>&password=<PASSWORD>&role=admin'

## [Bugbountyskills.md] Scope & authorization guardrail

Only test targets the user is authorized to test: a published bug bounty program with
this asset in scope, a signed assessment engagement, or the user's own lab/CTF. Refuse
out-of-scope hosts, third-party victims, and any request the program rules exclude.
CSRF tests mutate state by design, so NEVER run destructive or DoS payloads (password
changes, fund transfers, deletions of real data, bulk operations) as probes — prove the
bug with the least-impact state change that still demonstrates the cross-site condition.
If intent is unclear, ask for the program/scope before producing payloads.

## [Bugbountyskills.md] 1. Scope & authorization guardrail

Only test targets you are authorized to test: a published bug bounty program with the
asset in scope, a client-engagement target, or your own lab/CTF. Refuse out-of-scope
hosts, third-party assets (including third-party buckets and CDNs you stumble onto),
and any request to enumerate or exfiltrate data from a system you do not have
permission for. When in doubt, ask for the program URL or scope statement before
touching a target. Note that many programs scope *buckets and file storage* by name —
a bucket that resolves from a domain you found is not automatically in scope.

Two rules that are not negotiable:

- **Read-only means read-only.** Never modify, upload to, delete from, or "clean up"
  anything you find — no `PUT`/`DELETE` against buckets, no writing into exposed
  `.git` or log directories, no renaming objects to prove access. For bucket work,
  listing and reading are the proof; changing state is both a scope violation and a
  crime on someone else's infrastructure. Never run memory-extraction loops (V-08)
  against production at volume — Heartbleed probes can crash the service (DoS guardrail).
- **Never paste live secrets into reports, chat logs, or screenshots.** Redact to the
  pattern + location (see `payloads.md` §6). A report that leaks the very credential it
  reports becomes the leak. Capture hashes, truncated values (`AKIA…7Q`), or masked
  samples instead.

This skill exists to make authorized testing methodical and to produce reports that
hold up under triage review. The hard part of this category is not discovery — it is
**triage**: most things you find are not bugs, and the skill teaches where the line is.

## [Bugbountyskills.md] 1. Scope & authorization guardrail

Only test targets you are authorized to test: a published bug bounty program
with this asset in scope, a client engagement with written scope, or your own
lab/CTF. If the target is out of scope, belongs to a third party, or you cannot
verify authorization, refuse and stop. Never run destructive payloads, never
mass-scan third-party infrastructure (wordlist runs stay in-scope and
rate-limited), and never exfiltrate data beyond the minimum needed to prove
impact.

Skill-specific hard rules:

- **Canary-first, entitlement-first proof.** Prove impact by reading a harmless
  canary (a file you planted, `/etc/hostname`, a known public asset) or a file
  you are already entitled to (your own account's export, avatar, session data).
  Do not open the evidence phase with system or user files.
- **Minimal redacted evidence when traversal reaches sensitive system files.**
  Capture only what proves the read: one signature line of `/etc/passwd`
  (`root:x:0:0:…` with usernames intact is fine; hashes do not exist there), the
  `[fonts]` header of `win.ini`, a key *name* from a config with its value
  redacted. Never request or dump `/etc/shadow`, private keys, cloud
  credentials, session stores wholesale, other users' data, or `/proc/*/environ`
  contents — if the traversal implies they are reachable, say "reachable" and
  stop.
- **Write-class proof creates new files only.** For Zip Slip and symlink
  variants, plant a *new* benign canary file; never overwrite or delete
  existing files on a production target. Overwrite/execution demonstrations
  belong in a lab clone.
- **Execution proofs are lab-only.** Log poisoning, session poisoning, and
  `php://input`/`data://` code execution get read-back proof in production
  (your injected marker returns through the include) and full execution proof
  only against an in-scope container or your own lab.

## [Bugbountyskills.md] 1. Scope & authorization guardrail

Only test targets you are authorized to test: a published bug bounty program
with this asset in scope, a client engagement with written scope, or your own
lab/CTF. If the target is out of scope, belongs to a third party, or you cannot
verify authorization, refuse and stop. Never run destructive payloads (mass
scanning of third-party infrastructure, fork bombs, resource exhaustion),
never establish persistence or backdoors, and never exfiltrate data beyond the
minimum needed to prove impact.

Skill-specific hard rules:

- **No shells as a first step.** The first signal for any injection is an
  out-of-band callback to a domain or collaborator you control (DNS or HTTP),
  an arithmetic marker, or a short time differential. Code execution proofs
  come last, and only a single benign command (`whoami`, `id`) at the
  impact-proof stage.
- **No persistence, no web shells left behind.** If an upload executes, prove
  it with one benign marker request, then delete it or disclose it to the
  program immediately.
- **Exploitation depth belongs in a container or lab.** Deserialization gadget
  chains, sandbox escapes, memory-corruption exploits, and config-override
  RCE chains get developed against in-scope docker/k8s targets or your own
  lab clone — not against production.
- Cloud metadata is **not** this skill's territory — SSRF that reaches
  `169.254.169.254` routes to `ssrf-testing` (identity-only evidence rules
  apply there).

## [Bugbountyskills.md] 1. Scope & authorization guardrail

Only test targets you are authorized to test: a published bug bounty program
with this asset in scope, a client engagement with written scope, or your own
lab/CTF. If the target is out of scope, belongs to a third party, or you
cannot verify authorization, refuse and stop.

This skill lives in 0-day / CVE-adjacent territory, so its destructive-payload
rule is wider than in other skills: kernel-module bugs, V8/eBPF/hypervisor
PoCs, and device fuzzing can panic hosts, corrupt disks, and DoS shared
infrastructure. The playbook is deliberately scoped to four moves:

- **(a) Recognize the escape surface** — what the sandbox still lets you reach.
- **(b) Fingerprint versions and match them to public advisories** — the exact
  runtime, library, kernel, engine, or build number, checked against
  NVD/GHSA/vendor advisories.
- **(c) Reproduce a public PoC in your own lab/container/VM** — a
  version-matched clone you own, never third-party production.
- **(d) Write the report** — evidence, version+advisory citation, impact.

Hard rules for this skill:

- **Do not invent or fabricate novel kernel, V8, eBPF, or hypervisor
  exploits.** Improvising memory corruption does not work, and a claim you
  cannot reproduce is worse than no finding at all. Where an advisory exists,
  cite it instead of shipping exploit code — reports in this class get
  accepted on version evidence + advisory + config proof more often than on
  crash output.
- **Benign proof ceiling:** `id`, `whoami`, `uid`, hostname, or reading a
  marker file you created — inside a lab context. Config-evidence proofs
  (decoded capabilities, `kubectl auth can-i` results, `whoami /priv` lists)
  require no execution at all and are preferred where they suffice.
- **Memory-corruption depth stays in your lab.** Kernel/V8/eBPF/hypervisor
  public PoCs run only against your own version-matched VMs. On a live
  target, the finding is "vulnerable version + reachable surface + advisory".
- **No persistence, no backdoors.** The one exception is variant 14's benign
  marker file proving `/tmp` reuse — disclose it and delete it in the same
  session.
- Never run destructive payloads (kernel fuzzing, crash loops, fork bombs,
  disk writes) against any target you do not own outright.

## [Bugbountyskills.md] V-04: Container privilege escalation via Docker daemon and kernel namespace breakouts

**Mechanism:** A container shares the host kernel; isolation is only as good
as namespaces + capabilities + seccomp + device access. Breakouts come from
config (`--privileged`, `CAP_SYS_ADMIN`, host docker.sock mounted, host
binds, hostPID) and from kernel/runtime bugs in the shared kernel (cgroup
release_agent-class escapes, runc binary-overwrite-class runtime CVEs,
overlayfs/capability kernel CVEs). The violated assumption: "container
boundary ≈ VM boundary."

**Preconditions:**
- Code execution inside a container (or ability to create/modify containers)
- A breakout rung present: privileged/SYS_ADMIN, docker.sock, host mounts,
  host PID/user namespace sharing, or a vulnerable kernel/runc version
- Kernel version visible via `uname -r` (plus distro backport status)

**Detect:**
1. Benign in-container recon: `id`, `cat /proc/self/status | grep CapEff`,
   `ls -la /.dockerenv 2>/dev/null; cat /proc/1/cgroup`, `uname -r`,
   `cat /proc/1/comm`.
2. Decode capabilities: `capsh --decode=<PLACEHOLDER_CAPEFF>` — `sys_admin`
   or near-full caps change this from "hygiene note" to "breakout likely".
3. Surface checks: `ls -la /var/run/docker.sock /run/containerd/containerd.sock`,
   `mount | grep -Ev 'proc|sysfs|cgroup|overlay|tmpfs'` (host binds),
   `ls /dev/sd* /dev/vg* /dev/mapper 2>/dev/null` (block devices visible =
   privileged-class config).
4. Version match: kernel `uname -r` and `runc --version` (where visible)
   against *distro* advisories — vanilla upstream ranges mislead because
   distros backport fixes (check the distro's advisory, not just NVD).
5. Public PoCs (cgroup release_agent class, runc overwrite class, kernel
   CVEs) reproduce only in **your** lab VM with a version-matched kernel —
   a failed or crashing attempt on a shared host is a DoS, not a finding.

**Proof of concept:**
```
$ id && cat /proc/self/status | grep CapEff          # inside container → <PLACEHOLDER_CAPEFF>
$ capsh --decode=<PLACEHOLDER_CAPEFF>                # decodes to capability list
$ ls -la /var/run/docker.sock 2>/dev/null            # socket present?
$ mount | grep -E 'kubelet|/dev/sda|host'            # host binds?

## [Bugbountyskills.md] lab-only benign escape proof (privileged misconfig): mount host disk

## [Bugbountyskills.md] 1. Scope & authorization guardrail

Only test targets you are authorized to test: a published bug bounty program with the
asset in scope, a client-engagement target, or your own lab/CTF. Refuse out-of-scope
hosts, third-party assets you have no permission for, and any request to run payloads
against someone else's production system. When in doubt, ask for the program URL or
scope statement before touching a target.

Two rules that are not negotiable:

- **Never run destructive queries** — no `DROP`, `DELETE`, `UPDATE`, `INSERT`,
  `TRUNCATE`, `ALTER`, or schema-mutating statements — against third-party targets.
  Never run DoS-style payloads (heavy cartesian joins, `REPEAT('a',100000000)`,
  recursive CTE bombs, thousands of stacked statements, `pg_sleep` in a loop). These
  break things, burn the target's resources, and turn a valid finding into a ban.
- **Prove impact with read-only extraction on your own account** or with a boolean /
  timing oracle. A single boolean oracle that flips on `AND 1=1` vs `AND 1=2`, or a
  measured time delta on `AND SLEEP(3)`, is enough to prove the vulnerability; schema
  dumps and file reads are demonstrated against data you are entitled to read (your
  own user's row, test records you created), not the platform's crown jewels.

This skill exists to make authorized testing methodical and to produce reports that
hold up under triage review. Speed comes from picking the right variant early, not
from blasting payloads.

## [Bugbountyskills.md] 1. Scope & authorization guardrail

Only test targets you are authorized to test: a published bug bounty program
with this asset in scope, a client engagement with written scope, or your own
lab/CTF. If the target is out of scope, belongs to a third party, or you cannot
verify authorization, refuse and stop. Never mass-scan third-party or
out-of-scope internal infrastructure, never run destructive payloads against
internal services, and never exfiltrate data beyond the minimum needed to
prove impact.

Skill-specific hard rules:

- **Cloud metadata findings are proven by identifying the role/instance — not
  by dumping credentials.** If you can reach `169.254.169.254`, fetch the IAM
  role name or the instance identity document, then stop. Do not retrieve,
  copy, screenshot, or retain temporary credentials; redact anything
  token-like from evidence.
- **The first signal is an out-of-band callback to a domain or collaborator
  you control.** A hit from the app's egress IP with a non-browser UA proves
  server-side fetch; anything less is a lead. Client-side fetches (link
  previews rendered in the victim's browser) are not SSRF.
- **Protocol-smuggling write primitives stay in the lab.** Gopher'd writes to
  Redis/Memcached/SMTP get demonstrated against your own listener first;
  internal-state-changing chains are lab-depth, described in prod reports.
- **No job floods, no scan loops against production.** Pacing (two samples
  per probe plus a control) is part of the no-destructive rule.
- Code execution reached *through* an SSRF (gopher → internal RCE, metadata
  → privilege pivot) reports as the chain it is; the execution-side framing
  lives in `rce-testing`.

## [Bugbountyskills.md] 1. Scope & authorization guardrail

Only test targets you are authorized to test: a published bug bounty program with the asset
in scope, a client engagement with written rules of engagement, or your own lab/CTF. If the
user names a third-party domain, ask for the program link or scope statement before doing
anything else; refuse out-of-scope assets and never argue someone into "probably fine".

Hard limits inside authorized scope:

- No destructive or availability-impacting payloads: no self-replicating scripts, no
  mass-mailing loops, no resource-exhaustion payloads, no payloads that delete or modify
  other users' data.
- Prove execution with inert markers (`alert(document.domain)`, a DOM element you inserted,
  an out-of-band ping to your own collaborator domain). Never exfiltrate real users' cookies,
  tokens, or content — if you need a "look, I got data" proof, exfiltrate your own test
  account's marker string.
- Blind XSS (V-05) fires in someone else's browser, often an admin's. Collect the minimum
  context needed to prove the point (origin, path, role label), redact it in the report, and
  state clearly in the report what was and was not accessed.
- UXSS (V-06) is a browser-vendor bug. If you find one while testing a web app, it is
  context for the app report at most — the finding belongs to the browser program.

The skill exists to make authorized testing methodical and to produce reports that hold up
under triage. Follow it and your findings will be reproducible, minimal, and unambiguous.

## [Bugbountyskills.md] 1. Scope & authorization guardrail

Only test targets the user is authorized to test: a published program covering the asset,
a scoped pentest in writing, or the user's own lab/CTF. Refuse out-of-scope hosts and
third-party targets outright. Passive fingerprinting still counts as testing on some
programs — check the brief before you send anything. No destructive probes, no version
exploitation without a safe confirmation step, no bulk banner-grabbing against rate-limited
edges; fingerprints are collected from the traffic you would send anyway, plus a handful of
targeted probes.

### [Bugbountyskills.md] IDOR / BOLA

1. Find API endpoint with numeric/object ID param
2. Authenticate as user A
3. Change ID to user B
4. Check if data returned (with authorization)
5. Test mass assignment (extra fields in request body)
6. Test with different role headers

### [Bugbountyskills.md] IDOR / BOLA Pattern

```
1. Find API endpoint with numeric/object ID parameter
2. Authenticate as user A
3. Change ID to user B
4. Check if data is returned (with authorization)
5. Test mass assignment (extra fields in request body)
6. Test with different role headers
```

## [Bugbountyskills.md] IDOR & Broken Access Control

### [Bugbountyskills.md] F. IDOR, BOLA, BAC, and RBAC

This is a top-priority research category.

Study:

- Insecure direct object references (IDOR).
- Broken object-level authorization (BOLA).
- Broken function-level authorization.
- Broken access control (BAC).
- Role-based access control (RBAC) failures.
- Horizontal and vertical privilege escalation.
- Same-tenant and cross-tenant isolation failures.
- Organization, workspace, project, team, and account boundary violations.
- Owner, administrator, supervisor, member, editor, and viewer permission inconsistencies.
- Unauthorized access to invoices, payment history, documents, financial records, exports, and private resources.
- Missing authorization checks on REST, GraphQL, RPC, and internal application APIs.
- Unauthorized object creation, modification, deletion, and ownership reassignment.
- Invitation acceptance, account linking, organization switching, and role-transition flaws.
- Race conditions affecting invitations, roles, access checks, and business workflows.

Use an explicit comparison methodology:

1. Establish the permissions of Account A and Account B.
2. Identify the resource owner and expected authorization policy.
3. Capture the normal request and response for each account.
4. Compare identifiers, roles, tenant context, tokens, and server-side behavior.
5. Test only authorized, controlled accounts and resources.
6. Determine whether the server enforces ownership and permissions independently of client-side controls.
7. Demonstrate the smallest meaningful unauthorized action or data exposure.
8. Record expected behavior, observed behavior, impact, and evidence.
9. Rule out intended sharing, delegated permissions, public resources, and stale sessions.

Do not classify a response difference, identifier predictability, or HTTP 200 status as a vulnerability without evidence of an authorization failure.

## [Bugbountyskills.md] 🧪 SKILL: Blind & Numeric IDOR Testing

When testing for Insecure Direct Object References (IDOR), manipulating resource identifiers, HTTP methods, or adding parameter overrides can expose unauthorized data.

### [Bugbountyskills.md] 1. Blind & Numeric IDOR Testing

**Testing Alternative HTTP Methods**
If `GET /api/v1/users/1002` returns 403 Forbidden, test whether alternative methods bypass the access check:

```bash
curl -i -X PUT "https://target.com/api/v1/users/1002" \
     -H "Authorization: Bearer <LOW_PRIV_TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"email":"test@example.com"}'
```

**Parameter Pollution & HPP (HTTP Parameter Pollution)**
Send duplicate parameters to see if the backend authorization logic evaluates the first ID while the database fetches the second:

```bash
curl -i -s "https://target.com/api/v1/account?id=1001&id=1002" \
     -H "Authorization: Bearer <TOKEN_USER_1001>"
```

**JSON Array Wrapping / Type Juggling**
Replace a single integer ID with an array or JSON object to bypass strict string/integer validation:

```bash
curl -i -X POST "https://target.com/api/v1/order/details" \
     -H "Authorization: Bearer <LOW_PRIV_TOKEN>" \
     -H "Content-Type: application/json" \
     -d '{"order_id": [1001, 1002]}'
```

**Header-Based ID Override**
Test if custom routing headers override the session context:

```bash
curl -i -s "https://target.com/api/v1/me" \
     -H "Authorization: Bearer <USER_A_TOKEN>" \
     -H "X-Mode-Api-User: 1002" \
     -H "X-User-Id: 1002"
```

### [Bugbountyskills.md] 2. Access Control & Authorization Bypasses

These patterns test for broken object-level authorization (BOLA) and broken function-level authorization (BFLA).

**Path Traversal & Middleware Bypasses**
Reverse proxies (like NGINX or HAProxy) and backend application servers often parse URIs differently. Use path normalization tricks to bypass `/admin` path blocks:

```bash

## [Bugbountyskills.md] IDOR / broken access control (`bac-idor-testing`)

| Endpoint | Param | Class | Status |
|---|---|---|---|
| `GET /api/proxy/orders` | — | horizontal list | 401 |
| `GET /api/proxy/orders/{id}` | `{id}` | **BOLA object read** | 401 (sent non-existent id — safe) |
| `GET /api/proxy/orders/{id}/{itemId}` | `{id},{itemId}` | **BOLA file download** (tickets) | Untested |
| `DELETE /api/proxy/payment/methods` | `id` | **delete another user's stored card** | Untested — destructive |
| `PATCH /api/proxy/auth/me` | body | **mass assignment** (role/flags?) | Untested |
| `POST /api/proxy/business/associateTicketsToCustomers` (+Express) | body + `token` header | **link tickets to arbitrary customer** | Untested |
| `POST /api/proxy/business/desassociateTicket` | body + `token` header | unlink | Untested |
| `GET /api/proxy/admin/orders` | `search,columnToFilter,orderBy,token` | **vertical escalation → cross-account PII** | 401 w/ invalid token |
| `PATCH /api/proxy/admin/orders/{tx}/email` | `newEmail,isGuest,token` | **order-email takeover chain** | Untested — destructive |
| `PATCH /api/proxy/admin/business/users/authorize` | `userId,token` | privilege grant | Untested |
| `PATCH /api/proxy/admin/business/users/modify` | `userId,gtsVisionId,token` | — | Untested |
| `GET /api/proxy/admin/orders/{id}/tickets` | `token` | ticket → PII download | Untested |

Safe-first for all of the above: probe a **guaranteed-nonexistent ID** first for
`401 vs 403 vs 404 vs 200`, then only self-owned objects. Never call refund/relaunch/email-change
during discovery.

### [Bugbountyskills.md] 17.7 Access-denied response body still leaks the protected object (HTTP 422 "not authorized" carries `context.subject`)

SOURCE: HackerOne #3862641 — HackerOne, "IDOR allows user to access report details via `reference.json` endpoint" (Critical, $15,000, disclosed 2026-10-01)  read 2026-11-07
CLASS: IDOR / sensitive info disclosure via error response (CWE-639 / CWE-209)
CORE METHOD:
  1. Map authenticated endpoints that return a serialized object: `/{id}.json`, `/api/…/{id}`, `/reference.json`, error-shaped `{error, context}` responses.
  2. Request an object you are NOT entitled to (`/{other_id}/reference.json`) — the point is that the endpoint returns an access-denied status yet still serialises the resource.
  3. Send the minimal body to trigger the error path: `POST /reports/{id}/reference.json` with `{}` + the CSRF token. On HackerOne this returned **HTTP 422 "You do not have the appropriate access"** while the JSON body still contained private report fields in `context.subject`.
  4. Walk the ID space (and any `?format=`, `.json`, `.xml` siblings) collecting leaked fields from 4xx bodies — the data is in the error envelope, not a success response.
DETECTION SIGNAL: a resource endpoint whose 4xx body includes `context`, `subject`, `data`, `resource`, `object` or any of the target's own fields; status says "denied" but the payload says otherwise; `.json`-suffixed siblings of HTML routes.
CHAIN: low-priv "not authorized" 4xx → body still serialises the protected object → private report/PII read at scale across the ID space → sensitive info disclosure with PoC (rated Critical/$15k because the leaked objects were private program reports).
TRANSFERABLE TEST: Take any endpoint you ARE allowed to call, then call it for an object you are not — (a) valid-shaped foreign ID, (b) empty/absent body, (c) malformed body — and diff the 4xx body for fields that shouldn't be there. Never trust "not authorized"; read the payload.

<!-- exact-duplicate entries folded in: 1 -->

### [Bugbountyskills.md] 17.18 Delegated-admin object: field-level authorization not enforced -> vertical privilege escalation via role grants (Teleport Access Lists #2281075)

SOURCE: https://hackerone.com/reports/2281075  2026-11-07
NOTE (fetch honesty): the HackerOne page would NOT render from this egress — web_extract returned HTTP 403 "Upstream forbidden"; the browser tool and https://r.jina.ai/ both hit the Cloudflare "Just a moment…" challenge and were redirected to /users/sign_in; the Wayback Machine capture (2025-04-19) is only a 302 → sign_in and archive.ph had no copy. Technique reconstructed from the CREDITED vendor advisory for this same report — GHSA-76cc-p55w-63g3 (github.com/gravitational/teleport/security/advisories/GHSA-76cc-p55w-63g3, Critical, published 2023-12-29) — plus the public Teleport Access-List docs. Nothing invented. ROUTE THAT WORKED: vendor advisory + product docs.
CLASS: broken function/FIELD-level authorization on a delegated-admin object → vertical privilege escalation (CWE-20 improper input validation / CWE-274 improper handling of insufficient privileges) — Teleport Access Lists
CORE METHOD:
  1. Identify the delegated-admin object and its documented limits. Teleport Access-List OWNERS are documented as able to only "control membership requirements / list members / provision and revoke membership / audit Access Lists" and explicitly NOT to "add or remove owners … or control what roles and traits are granted by the Access List".
  2. The defect (vendor wording): "an Access List Owner [can] assign arbitrary permissions, including permissions to themselves which could result in privilege escalation". The write path enforces "you must be an owner", but the FIELD-level restriction (which fields an owner may set — `grants` / `owner_grants` = roles+traits) is not enforced.
  3. Exploit: as the owner, call the object's write API (Web UI "manage Access List", `tctl`, or the Auth `AccessListService` upsert) and set the list's `grants` (and/or `owner_grants`) to the preset highest roles — `editor` (manage all cluster resources) and/or `access` — then add yourself (or an account you control) as a member that meets the membership requirements.
  4. Log out / re-evaluate membership: Access-List grants are applied at login → the preset highest roles are now held.
DETECTION SIGNAL: any product where a "delegated admin / list owner / team owner / project admin" can WRITE the very object they administer (upsert/PATCH/PUT) even though the vendor docs state only certain fields are owner-editable; the object's `grants`/`roles`/`traits`/`scopes`/`permissions`/`owners`/`members` fields are accepted from the owner's request body; role changes take effect at next login with no second reviewer.
CHAIN: low-privilege user who merely OWNS one Access List → owner-only (not field-level) write authorization → set the list's `grants`/`owner_grants` to preset `editor`/`access` → Access-List grants applied on login → cluster-admin-equivalent privilege (rated Critical; fixed in Teleport 14.2.4 / 13.4.13).
TRANSFERABLE TEST: For every "owner/manager/admin-of-object" role in an RBAC/IGA/IAM system, take the object you own and replay its write API (PUT/PATCH/upsert, JSON body) with the RESTRICTED fields populated — `grants`, `owner_grants`, `roles`, `traits`, `scopes`, `permissions`, `members`, `owners` — including a preset highest-privilege role; also try adding yourself as a member/owner of your own object. If the change persists and is applied at re-auth, it is vertical privilege escalation.

### [Bugbountyskills.md] 17.25 Trusted identity header (`X-Pid`) IDOR → cross-project role substitution → observer escalates to write + credential mint (Mail.ru MCS SQS)

SOURCE: https://hackerone.com/reports/1177451 — Mail.ru Cloud Solutions `sqs.mcs.mail.ru` (Critical, $15,000)  read 2026-11-07
ROUTE: body not public (`.json` 404; HTML/jina → bot gate; Wayback 2022 = SPA shell). Method = the program's own summary, taken from the Wayback snapshot's `og:description` ("IDOR for X-Pid header allowed user with observer role to elevate privileges for SQS service of MCS (sqs.mcs.mail.ru) by using role from the different project").
CLASS: BAC/IDOR on a custom identity header → vertical privilege escalation across projects
CORE METHOD:
  1. Per-project role model (observer/viewer — read-only) and the acting project/principal id travels in a CUSTOM HEADER (`X-Pid`) instead of being derived from the session token.
  2. Replay your own allowed request with `X-Pid` set to a role/project id from a DIFFERENT project → the backend authorizes the observer as a writer of that project.
  3. Aim the escalation at an action that MINTS A CREDENTIAL (create SQS access keys) — the durable key is the real impact, not the write.
DETECTION SIGNAL: `X-Pid`/`X-Project-Id`/`X-Tenant`/`X-Account-Id`/`X-Org`/`X-Role` headers on a multi-tenant API; UI that only ever sends your own tenant id; ids harvestable from other responses/URLs/console.
CHAIN: observer primitive → header swap → writer authorization on a foreign project → access keys minted → cross-project queue read/write ($15,000).
TRANSFERABLE TEST: Take a write you are forbidden (`create*Key`, `put-policy`, `add-member`) and replay it with the identity header set to a project/role id you do not own; 2xx + object created, then the credential-minting variant, is the finding.

### [Bugbountyskills.md] 17.33 Authz validator that EARLY-RETURNS by namespace/object shape → object-level check skipped → async export job never re-authorized (GitLab project templates #689314)

SOURCE: https://hackerone.com/reports/689314 — GitLab EE, "Project Template functionality can be used to copy private project data, such as repository, confidential issues, snippets, and merge requests" (Critical, reporter jobert)  read 2026-11-07 (body via the HackerOne `.json` endpoint, 12,378 bytes)
CLASS: broken access control / object-level authorization · CWE-284 · CWE-639
CORE METHOD:
  1. `POST /projects` with normal multipart fields PLUS `project[use_custom_template]=true`, `project[template_name]=<victim project name>`, `project[group_with_project_templates_id]=<group id you do not belong to>` and `project[namespace_id]=<your OWN USER namespace id>`.
  2. The EE validator is `validate_namespace_used_with_template` and starts with `return unless project.group` — a project created in a USER namespace has no group, so the "template owner must be an ancestor of the namespace" check is skipped entirely and both EE params survive into `Projects::CreateService`.
  3. `template_name` present ⇒ `CreateFromTemplateService` → EE `GitlabProjectsImportService` → `current_user.available_custom_project_templates(search:, subgroup_id:)` = `::Project.where(namespace_id: group_id)` + `ProjectsFinder` with NO per-project access-level check (a public project whose repo/issues/snippets/MRs are "Only Project Members" is returned anyway); the first hit becomes `params[:custom_template]`.
  4. That project is then handed to `custom_template.add_export_job(current_user:, after_export_strategy: CustomTemplateExportImportStrategy.new(export_into_project_id: project.id))` — a FULL export of the victim's restricted project, auto-imported into the attacker's project.
  5. The export job runs asynchronously with no re-authorization (explicit TOCTOU: leave the group, or clog Sidekiq, after scheduling — the export still lands).
  6. Read the import: repository+wiki, uploads, services/config, issues with comments, MRs with diffs, confidential issues, snippets, LFS, issue boards.
DETECTION SIGNAL: an authorization check whose control flow depends on object SHAPE (`return unless obj.parent`, `if (org)`, "team accounts only") so a sibling namespace type skips it; "create/import/fork from <template|project|app>" flows where the source id is a request parameter resolved by a visibility-filtered `where(namespace_id: …)` rather than a membership-scoped finder; public objects with members-only FEATURES (these are the exploitable objects); any EXPORT/IMPORT/MIRROR background job keyed by a user-supplied id with no requester re-check at execution.
CHAIN: registered user with no memberships → crafted `POST /projects` in own user namespace + victim group id/template name → validator early-return → unrestricted template finder → export job on a restricted project → auto-import → full read of private repo, confidential issues, private snippets, MRs (Critical).
TRANSFERABLE TEST: On every "new object from template/import/fork" endpoint, create the object in the scope where the guard is weakest (personal namespace / team-less workspace) and pass the source id raw; diff the created object's content against your ACL on the source. Then test the second-order half: schedule the export/import, DROP your own access (leave group / downgrade role / delete membership) before the worker runs, and confirm the job still returns the data.

### [Bugbountyskills.md] 17.41 Two-object diff/compare: authorization is checked on the object you ADDRESS, but the COUNTERPART of the diff is resolved with no ACL check → cross-repository / cross-tenant content read (GitHub Enterprise #3124517, CVE-2025-8447)

SOURCE: https://hackerone.com/reports/3124517 — GitHub Enterprise Server < 3.18, "Arbitrary Read of Another Users private repository without Authorization" (High, CWE-639, CVSS 4.0 7.0, $10,000, reporter furbreeze)  read 2026-11-07 (report body is restricted; the method was read from GitHub's own summary on the report page plus the CVE-2025-8447 record and GHSA-rw5q-23mh-r4c3)
CLASS: IDOR / BOLA on a two-object operation → unauthorized content read through a diff · CWE-639
CORE METHOD:
  1. Precondition: any authenticated user with access to at least ONE repository (no access to the target needed) and knowledge of the private repository's NAME plus one of its refs (branch, tag or commit SHA). GHES `<3.18`; fixed 3.14.17 / 3.15.12 / 3.16.8 / 3.17.5.
  2. GitHub's wording for the primitive: users "with access to any repository" could "retrieve limited code content from another repository by creating a diff between the repositories … needed to know the name of a private repository along with its branches, tags, or commit SHAs … trigger compare/diff functionality and retrieve limited code without proper authorization".
  3. Request shape: the compare/diff endpoint takes the counterpart reference as part of the range — `/<owner>/<repo>/compare/<base>...<head>` with the other side naming the private repo (`/my-org/my-repo/compare/main...victim-org:private-repo:branch`). The handler authorizes the repository in the path and then resolves the OTHER side's commit/tree/blob objects by name.
  4. Impact shape: a diff renders BOTH sides, so the returned unified diff carries the private repository's file CONTENT for the paths touched by the range. Iterate ref pairs (branches/tags/SHAs) and the sibling renderings (`.diff`, `.patch`, `?format=json`, `Accept:` media types, older API versions) to widen the read.
  5. Same root cause, second I/O: the sibling CVE-2026-75101 scopes raw PR diff/patch tokens to the repository NAME + PR NUMBER instead of a globally unique repository id, so an attacker creating a repo/PR matching the victim's name and number reuses THEIR OWN token to fetch the private PR's diff.
DETECTION SIGNAL: any operation that takes a SECOND object reference — base/head, source/target, from/to, left/right, parent/child, original/copy, before/after — and RETURNS CONTENT (diff, patch, merge preview, comparison, changelog, fork/sync diff, document-revision diff, schema-migration diff, version restore preview); the primary object is authorized while the counterpart is looked up by name/id without a check; format/media-type variants and legacy API versions that skip the UI's check; tokens or cache keys scoped to a mutable NAME rather than an immutable id.
CHAIN: any authenticated user (access to any one repository) → compare/diff whose other side names a private repository or ref → the diff resolves and returns the private repository's file content for the changed paths → unauthorized read of proprietary source and of any secrets committed to it → repeated across ref pairs/formats to widen the map (High, CWE-639, $10,000).
TRANSFERABLE TEST: create your own object A (a repo with one commit, one document revision); then request a diff/compare/merge-preview whose OTHER side is an object you may not read (another tenant's repo/ref, another user's document revision, an internal package's earlier version). If the returned diff body contains the counterpart's bytes, that second reference is unauthorized. Sweep the siblings (`compare/<own>...<victim>:<ref>`, `/<id>.diff`, `/<id>.patch`, `?format=json`, `/api/v1` vs `/api/v2`), then enumerate refs (branches, tags, SHAs) to turn one leaked range into a map. General rule: for every two-object operation, ask which of the two the server actually authorizes — then make that one yours.

NOTE — read pass 2026-11-07 (batch 7, no other §17 entry added): https://hackerone.com/reports/188719 (HackerOne `/skills` cross-applicant proof leak, Medium 6.5, $10,000) was read (body = one URL + one sentence, plus the vendor's root-cause summary) and recorded in the harvest ledger and the dated knowledge file, but NO §17 entry was created for it — the technique is a plain un-scoped listing query in a workflow (BOLA on a GROUP-scoped join), i.e. the archetype already covered by the §3 / §11 BOLA methodology, so it is not a new general method. https://hackerone.com/reports/542180 (Valve L4D2 NAV parser buffer overflow → EIP control → RCE) and https://hackerone.com/reports/2900606 (PlayStation 5 `sys_fsc2h_ctrl` kernel stack free → UAF → LPE) were likewise read and recorded in the harvest ledger and the dated knowledge file, but no §17 entry was created: both are memory-corruption classes and the sandbox-escape playbook in this file forbids teaching novel client/kernel exploitation here (same precedent as #826026). https://hackerone.com/reports/307239 (Coinbase "Double Payout via PayPal") and https://hackerone.com/reports/1312641 (Pornhub/redtube `/media/hls?s=` deserialization) are NOT publicly readable on any route and no credited writeup exists → INVALID, nothing invented.

### [Bugbountyskills.md] 17.48 Trusted INTERNAL identity claim reachable two ways: (i) internal signed token EXPOSED via a traversal file-read, (ii) internal identity header trusted to name any principal → unauthorized write (GitLab Workhorse JWT + `Geo-GL-Id`, #1040786) — extends 17.25

SOURCE: https://hackerone.com/reports/1040786 — GitLab, "Exposure of a valid Gitlab-Workhorse JWT leading to various bad things" (Improper Authentication; High; reporter ledz1996)  read 2026-11-07 (full body via the HackerOne `.json` endpoint, 11,280 bytes)
CLASS: authentication/authorization bypass — a valid internal API-request JWT leaked through a path traversal, plus an internal identity header trusted to name ANY ssh key · CWE-22 + CWE-287/CWE-863
CORE METHOD:
  1. EXPOSE the JWT: `POST /api/v4/projects/<id>/terraform/state/%2e%2e%2f%2e%2e%2fwikis%2fattachments?serial=1` with a `multipart/form-data` body (`import_url`,`mirror`,…) and `Private-Token: <PAT>`; the State API does `data = request.body.read` and appends it as a FILE, so the traversal escapes the state directory.
  2. READ it back: `GET /api/v4/projects/<id>/terraform/state/%2e%2e%2f%2e%2e` → the response multipart field `mirror.gitlab-workhorse-upload` carries a signed JWT (`eyJhbG...`) that satisfies `Gitlab::Workhorse.verify_api_request!`.
  3. On EE the git-http controller picks the acting user from a header: `user → geo_push_user&.user`, `::Geo::PushUser.new_from_headers(headers)['Geo-GL-Id']`, `identify_using_ssh_key` → `User.find_by_ssh_key_id(key_id.gsub("key-",""))`. So `Geo-GL-Id: key-<n>` authenticates you as the owner of ssh-key `<n>` — a small incremental integer.
  4. Turn read into write: fork the readable repo, clone over HTTP, intercept the push, and rewrite the path using both the traversal and the internal push route: `/-/push_from_secondary/2/<victim-project>.git/git-upload-pack.t%2f%2e%2e%2fgit-receive-pack`.
  5. Headers: `Gitlab-Workhorse-Api-Request: <the JWT>` + `Geo-GL-Id: key-<id>` (id of any key whose owner can push to the project). Body = normal `git-receive-pack` pack.
  6. The push is accepted into a repository you were only authorized to read.
DETECTION SIGNAL: an upload/import/state endpoint whose stored filename/name comes from `request.body`/a user path and is written AFTER URL normalization; a signed INTERNAL token in a RESPONSE you can read (grep for `eyJ` / `*-upload`); a service resolving the ACTING USER from an internal header (`Geo-GL-Id`, `X-User-Id`, `X-Pid`, `X-Gitlab-*`) especially a `find_by_<key>_id(<int>)`; an alternate write route (`/-/push_from_secondary/`, an "internal"/`/-/` route, a mobile BFF) that honours the internal header while skipping the primary authorization gate.
CHAIN: any account + PAT → expose the Workhorse JWT via a traversal file-read → forge an internal API-request and add `Geo-GL-Id: key-<victim-id>` → authenticate as any ssh-key owner → bypass the pre-receive push check via `push_from_secondary` + `%2f%2e%2e%2f` → unauthorized push to any readable repo (High).
TRANSFERABLE TEST: (1) hunt "read a file into a response" where a user-controlled name is written to a path after normalization, and grep the response for a signed token (`eyJ`). (2) If you get an internal signed token, replay it in its native header AND pair it with each internal identity header the stack consumes (`Geo-GL-Id`, `X-User-Id`, `X-Pid`, `X-Gitlab-*`), cycling small sequential ids. (3) Look for a second route that performs the same write without the primary authorization gate.

### [Bugbountyskills.md] 17.69 Free-form `sort_query: String` passed verbatim into the search engine's `sort` parameter → scripted-sort (`_script`/Painless) compilation and per-document EXECUTION before the authorization layer (HackerOne #3694007)

SOURCE: https://hackerone.com/reports/3694007 — HackerOne, "Authenticated Elasticsearch Painless script execution via Query.search.sort_query on hackerone.com/graphql" (High; $7,000; reporter brumbelow)  read 2026-11-07 (full body, 14,853 bytes, via the HackerOne `.json` endpoint)
CLASS: pass-through string argument → backend query-language / script injection · CWE-94 (+ CWE-200 authorization bypass)
CORE METHOD:
  1. Locate a resolver whose argument is a plain STRING fed to the search backend: `Query.search(index: IndexEnum, query_string: String, sort_query: String, size: Int)`.
  2. Prove raw DSL reaches the engine: `sort_query:"[{\"id\":\"asc\"}]"` → returned ids strictly ascending; nested object sorts (`{"order":"desc","missing":"_last"}`) accepted too.
  3. COMPILE ORACLE: only `_script.script.source` changes — `""` → 500 `STANDARD_ERROR`, `"unterminated` → 500, `"1"` → 200, `"1+1"` → 200. Identical JSON shapes, so a schema validator cannot separate them: a compiler is reachable with attacker source.
  4. EXECUTION ORACLE: `source:"1"` vs `source:"doc[\"_seq_no\"].value"` → the first five documents share ZERO overlap and B's order matches the ascending-`_seq_no` baseline = per-document execution.
  5. Impact: `_script` sort runs in the ES query phase BEFORE resolver-layer authorization, so `doc['<field>'].value` reaches fields of documents the caller cannot read; expensive scripts also degrade the shared cluster.
DETECTION SIGNAL: fields named `sort`/`sort_query`/`query`/`filter`/`where`/`script`/`dsl`/`agg`/`expression` typed as STRING and described as "raw"/"advanced"; an ES/OpenSearch/Solr/Mongo/JS-eval backend behind the graph; malformed DSL → 500 vs valid DSL → 200.
CHAIN: any authenticated low-privilege user → one request with a scripted sort → script compiled and run per document inside the search JVM, before authorization → pre-authorization field reads (cross-tenant disclosure if the index is not partitioned) → code execution on the search infrastructure where the script sandbox is weak (High).
TRANSFERABLE TEST: for every string parameter reaching a search/sort layer compare three probes — (a) `[{"<field>":"asc"}]` (does order change?), (b) engine scripted form vs a broken source (200/500 = compiler reachable), (c) per-document field read vs constant (different order = execution); on non-ES stacks use `$where`, `$expr`, `eval`, `$function`, `<script>` and the same oracle.

### [Bugbountyskills.md] 17.81 `data:image/svg+xml` used as an IMAGE SOURCE: the SVG script is dormant inside `<img>` but RUNS when the stored asset is opened as a top-level document -> execution in the authenticated origin -> same-origin privileged read (Shopify #1276742)

SOURCE: https://hackerone.com/reports/1276742 — Shopify, "Stored XSS in SVG file as data: url" (XSS - Stored; Medium 5.4; $5,300; reporter irisrumtub; disclosed 2023-01-31; fix = stop converting the `data:` URL into a `blob:` URL)  read 2026-11-07 (full body, 5,452 bytes + public Shopify summary, via `r.jina.ai`)
CLASS: stored XSS via a `data:` URL SVG image source whose execution context is TOP-LEVEL NAVIGATION, not the `<img>` element · CWE-79
CORE METHOD:
  1. Any rich-text/HTML field accepting an image source (product description, gift, page) accepts `data:` URLs as `src`.
  2. Store `<img src="data:image/svg+xml;base64,<b64 of an SVG carrying onload=…>" alt="">`.
  3. Payload: a SYNCHRONOUS same-origin read — `req.open('GET','https://<shop>.myshopify.com/admin', false); req.setRequestHeader('Upgrade-Insecure-Requests','1'); req.send(null);` then read `req.response`.
  4. Trigger: `<img>` does NOT execute the SVG script; the victim opens the image in a NEW TAB, so the `data:` URL becomes a top-level document where `onload` fires in the ADMIN ORIGIN and CORS lets the read through.
DETECTION SIGNAL: rich-text/image-URL fields that store `data:` URLs; SVG served/reflected as `image/svg+xml`; any "open image"/"view"/"preview in new tab" affordance that navigates DIRECTLY to the stored asset (that navigation is what arms the payload); a stored `data:` image NOT rewritten to a `blob:`/proxied URL (the rewrite is the fix, so its absence is the bug).
CHAIN: stored `data:image/svg+xml` in a description field -> dormant in `<img>`, executes when the asset is opened top-level -> execution in the victim's authenticated origin -> same-origin XHR reads `/admin` and can drive privileged actions -> admin-session compromise.
TRANSFERABLE TEST: save `<img src="data:image/svg+xml;base64,<b64 of <svg onload="alert(document.domain)">>">` in any image-source field, then open the asset in a NEW TAB (or via "view image") — execution proves the vector; escalate to `fetch('/<privileged-path>',{credentials:'include'})` / synchronous XHR and check whether the privileged page content returns, upgrading script execution to an admin-context read.

NOTE — read pass 2026-11-07 (batch 17; §17.79–17.81 appended from 6 sources read; 2 sources `no-content` with no readable method — NOT invented). Bodies: #1098793 via the public disclosed-reports dataset + `r.jina.ai`; #1148364, #1276742, #1147433 via `r.jina.ai`; #518641 (Mail.ru markdown LRF) and #1145428 (Uber U4B Vouchers chain) are `visibility: no-content` (`vulnerability_information` 0 bytes; the GraphQL node answers "Report does not exist"; Uber's public summary states impact but names no endpoint/parameter/bypass) -> no entry, NOT invented. §17.79 is a NEW general method (a security-disabled feature attribute re-enabled from document CONTENT — distinct from §17.20 TE-header obfuscation and from the disabled-endpoint material around §13.5). §17.80 is a NEW general method (self-escalated OAuth client trust via parameter pollution -> consent bypass -> token mint); nothing in §17 or the OAuth sections covers mutating your own client's admin-only flag. §17.81 is a NEW sink (a `data:` URL SVG that only executes on top-level navigation, not in `<img>`, plus the blob:-rewrite fix signature). #1147433 (Shopify rich-text-editor attribute break-out `">]` payload) is recorded in the harvest ledger `/root/bugbountyhuntingskills.md` and the dated knowledge file but got NO §17 entry: the general method (sanitizer/parser-differential break-out in a rich-text HTML mode) is already covered by the mXSS/DOMPurify-differential playbook in §1, and it is admin-context self-XSS unless a second viewer exists. Full per-source route/honesty records are in the harvest ledger and `/root/hackbot-architecture/knowledge/methodologies-2026-11-07.md`.

### [Bugbountyskills.md] 17.86 Setuid-root binary executes a helper by a BARE name, trusting the caller's `$PATH` — local privilege escalation (Keybase #426944)

SOURCE: https://hackerone.com/reports/426944 — Keybase, "Linux privilege escalation via trusted $PATH in keybase-redirector" (Privilege Escalation; reporter mirchr; disclosed 2018-12-18; 245 votes; bounty yes)  read 2026-11-07 (full body 2,437 B from the local disclosed-reports dataset)
CLASS: local privilege escalation via an untrusted program-search path in a setuid-root binary · CWE-426 / CWE-427
CORE METHOD:
  1. `/usr/bin/keybase-redirector` is setuid root and execs `fusermount` by a BARE name (no absolute path), so the caller's `$PATH` decides which binary runs.
  2. Compile a malicious helper: `int main(){ setreuid(0,0); system("/usr/bin/touch /w00t"); return 0; }` -> `gcc -Wall fusermount.c -o fusermount`.
  3. Put it in the current directory and prepend `.` to `$PATH`, then run the setuid binary: `env PATH=.:$PATH /usr/bin/keybase-redirector /keybase` (Ctrl-C to exit).
  4. The setuid process execs the attacker's `fusermount` as root (a root-owned `/w00t` is created) -> arbitrary root command execution.
DETECTION SIGNAL: `find / -perm -4000 -type f` (setuid binaries) whose child exec is a bare command name — confirm with `strings` / `ltrace -f -e execvp` / `strace -f -e trace=execve`; the same for root-owned cron/systemd/helper units, relative `dlopen`, `--`-prefixed argument injection, and `system()/popen()` calls with unqualified program names.
CHAIN: unprivileged local user -> setuid-root binary resolves its helper via `$PATH` -> attacker drops a trojanized helper on a `$PATH`-controlled dir -> it runs as root -> full host compromise (confidentiality/integrity/availability).
TRANSFERABLE TEST: list `find / -perm -4000 -type f`, trace each setuid binary's children for a bare-name exec; if found, drop a same-named script/ELF in a directory you control and run the binary with `PATH=<yourdir>:$PATH` (also `PATH=.:$PATH`); if your helper executed with euid 0 (`id`), it is local privesc.

### [Bugbountyskills.md] 17.91 GraphQL field selection gated by a CLIENT-ASSERTED permission variable (`@include(if: $flag)`) — the request claims its own privileges (Shopify #2207248)

SOURCE: https://hackerone.com/reports/2207248 — Shopify, "IDOR on GraphQL queries BillingDocumentDownload and BillDetails" (IDOR; reporter blaklis; disclosed 2024-02-08; 100 votes; bounty yes)  read 2026-11-07 (full body 9,347 B from the local disclosed-reports dataset)
CLASS: authorization decision taken from a request parameter — the client declares whether the caller holds a permission · CWE-863 (the report's demonstrated impact was the accompanying BOLA; this is the reusable primitive captured in the same request)
CORE METHOD:
  1. The captured operation declares the flag in its variables: `{"operationName":"BillDetails","variables":{"id":"<BillingInvoice id>","hasBillingSubscriptionsPermission":false},"query":"query BillDetails($id: ID!, $hasBillingSubscriptionsPermission: Boolean!){ billingAccount{ subscription @include(if: $hasBillingSubscriptionsPermission){ id billingPeriod } } node(id:$id){ ... } }"}`.
  2. The server uses that CLIENT-supplied boolean to decide whether the gated sub-tree (`subscription`) is included in the response — provided without any server-side check that the caller actually holds that permission.
DETECTION SIGNAL: GraphQL variables named after a permission/capability (`hasXPermission`, `canViewY`, `isAdmin`) wired into `@include(if:)`/`@skip(if:)`; mutation/query bodies where the caller asserts a capability the UI normally derives from the server; any boolean that removes a field rather than being validated.
CHAIN: any authenticated session → set the permission variable to `true` in the operation variables → server returns fields it otherwise withholds (capability assertion trusted client-side) → read the gated sub-tree of another or your own object.
TRANSFERABLE TEST: in every GraphQL request you capture, flip each `has*/can*/is*` boolean variable to `true` (and `false`) and diff the returned field set; a larger response is an authorization decision taken from the request. Pair it with the V-12 `node(id:)` id swap to test the same operation for BOLA.

NOTE — §17 additions 2026-11-07 batch 20 (§17.88–17.91 from 5 readable sources; #2352968 is `no-content`+unreachable — NOT invented). NEW GENERAL METHODS: §17.88 (a client tool deriving a local filename from page-controlled attributes → traversal write to an autostart path → RCE — the read/receive-side sibling of the upload→shell-job and flag/PATH material, but the sink is the TOOL's own temp file, not the server's upload dir); §17.89 (a server-owned workflow STATE field writable through the object PATCH → self-approval + payment bypass — V-04 covers identity/privilege fields, not lifecycle gates); §17.90 (peer-supplied BIT length into a fixed BYTE stack buffer over a voice/network channel → stack overflow → RCE — distinct from the asset-file overflow §17.68/#463286 and from the network OOB-READ index bugs §17.64/#807772); §17.91 (a client-asserted permission boolean driving `@include(if: $flag)` → the request decides what it is allowed to see — no prior `@include`/permission-variable material exists). NOT given §17 slots: #2207248's IDOR half (GraphQL `node(id:)` global-id swapping is already V-12) and #299728 (markdown autolinker attribute break-out — the general sanitizer/parser-differential method is already the §1 mXSS/DOMPurify playbook, same call as #1147433 in batch 17); both are recorded in the harvest ledger `/root/bugbountyhuntingskills.md` and `/root/hackbot-architecture/knowledge/methodologies-2026-11-07.md`. #1543159's sibling `email` mass-assignment (#1551176) stays at V-04. Full per-source route/honesty records are in those two files.

### [Bugbountyskills.md] 17.92 A GraphQL PERSISTED-OPERATION hash plus a NAME variable is an IDOR: the request carries no query text and no membership check runs on the object the name resolves to (Reddit `gql.reddit.com` mod logs #1658418)

SOURCE: https://hackerone.com/reports/1658418 — Reddit, "Getting access of mod logs from any public or restricted subreddit with IDOR vulnerability" (Insecure Direct Object Reference (IDOR); reporter high_ping_ninja; High 7~8.9; $5,000; asset `gql.reddit.com`; disclosed 2022-08-04)  read 2026-11-07 (full body 2,077 B from the local disclosed-reports dataset mirror `/tmp/h1_train.parquet`, `visibility: full`, read with `/usr/bin/python3.12`)
CLASS: IDOR/BOLA on a GraphQL persisted-operation endpoint
CORE METHOD:
  1. Capture the moderator-modlog request: `POST / HTTP/2` on `Host: gql.reddit.com`, `Authorization: Bearer <token>`, `Content-Type: application/json`, `Origin: https://www.reddit.com`, body `{"id":"6243efcbc61d","variables":{"subredditName":"any-subreddit"}}` — NOTE: no `query` text, only a persisted-operation hash `id` + variables.
  2. Swap `subredditName` to a public or restricted subreddit you do NOT moderate; the server returns its moderator log (the reporter: "There's no check if the user is moderator of the particular subreddit").
  3. If the response's `hasNextPage` is `true`, resend with `"after":"<endCursor>"` and loop while `hasNextPage` is `true` to walk the entire log (`mod_logs.sh` automated this).
DETECTION SIGNAL: requests carrying a persisted-operation hash (`{"id":"<hex>","variables":{…}}`) instead of `query`/`operationName`; a variable that names an object by NAME/SLUG/ID (`subredditName`, `orgSlug`, `projectId`, `tenantId`, `userId`) with no companion membership field; cursor pagination (`hasNextPage`/`endCursor`/`after`).
CHAIN: any authenticated user -> persisted-op hash with `subredditName` = a subreddit they don't moderate -> missing moderator check -> full mod log of any public/restricted subreddit (private moderation actions, bans, removal reasons) -> cross-tenant disclosure.
TRANSFERABLE TEST: capture any GraphQL request carrying a persisted-operation hash and a NAME/ID variable; resend it pointed at a resource of a second account you control (or an org you are not in) and diff vs an authorized baseline; if data returns it is BOLA — then walk the cursor to size the leak. The op-id is not the secret; the missing authorization check is. Pair with V-12 (`node(id:)` global-id swap) for the raw-id variant.

### [Bugbountyskills.md] 17.111 EMAIL-GATEWAY action endpoint trusts the `From:` header → any sender performs an account-bound action as another user → broken access control (HelloFax / HackerOne #1428385)

SOURCE: https://hackerone.com/reports/1428385 — Dropbox, "Send Fax from Anyone's HelloFax Account Due to Misconfigured Email Validation", Broken Access Control, High, $4,913, reporter ehsayaan, reported 2021-12-16, fixed 2022-03-17; read from the reporter's public writeup `https://infosecwriteups.com/mail-server-misconfiguration-leads-to-sending-a-fax-from-anyones-account-on-hellofax-dropbox-bbp-aab3d97ab4e7` (Sayaan Alam, 2022-07-25) because the report page/`.json`/Wayback were unreadable  read 2026-11-07
CLASS: Broken access control / authorization bypass via an inbound-EMAIL action endpoint that authenticates the actor from the `From:` header alone (no SPF/DKIM/DMARC, no per-account token)
CORE METHOD:
  1. The app performs an action when a user emails `<target>@<domain>` (email-to-fax: `<FAXNUMBER>@hellofax.com` sends the body/attachment as a fax, billed to the sender's account).
  2. The inbound handler resolves the acting account from `From:` and never validates SPF/DKIM/DMARC → the sender is forgeable.
  3. PoC: email `+12345678900@hellofax.com` with the VICTIM's address in `From:` (via a spoofing relay such as `anonymailer.net`) → the fax is sent from and billed to the victim's account ("fax sent successfully").
  4. Reproduced on a bug-reporting portal: emailing `bugs@<target>` created a ticket as the victim / as internal staff.
DETECTION SIGNAL: any "email X to perform Y" feature (email-to-fax, email-to-ticket `support@`/`bugs@`, email-to-post/publish, email-to-upload); help text "send from the email address registered to your account"; an inbound-mail handler binding the action to an account with no SPF/DKIM/DMARC check and no signed per-account token.
CHAIN: forgeable `From:` (primitive) → inbound email bound to the victim's account → unauthorized action as that user (send faxes / open tickets), billed to them (BAC with monetary/account impact). DOCTRINE: "missing SPF/DKIM/DMARC" is itself ineligible hardening (§2c) — report the cross-account ACTION, and only when it actually lands on the victim's account.
TRANSFERABLE TEST: find every "email us at X to do Y" feature; send ONE email from a spoofable relay with the VICTIM's address in `From:` (vary `Return-Path`/`Reply-To`/`Sender`) and check whether the action is attributed to the victim's account and the victim is billed/notified; a signed per-account token or DKIM-validated domain that rejects the spoof closes the class.
WHY IT IS A NEW GENERAL METHOD: the file's access-control and ATO entries are HTTP-request driven (IDOR/BOLA, CSRF, OAuth/SAML); this is a distinct ENTRY SURFACE — an inbound-EMAIL gateway — where the identity is the forgeable `From:` header, spanning fax/ticket/post/upload-by-email features that no HTTP-request playbook reaches.

### [Bugbountyskills.md] 17.132 GRAPHQL GLOBAL-ID TYPE CONFUSION: a mutation resolves any global id with the generic resolver and derives its ability from the RESOLVED object's class, so a lower role can drive a higher-privileged service with the wrong object (GitLab `destroySnippet` + `DiffNote#repository` → repository deletion, HackerOne #858671)

CLASS/METHOD: `destroySnippet` calls `authorized_find!(id:)` → `GitlabSchema.object_from_id(id)` with NO type assertion, and builds the permission as `"#{ability_name}_#{snippet.to_ability_name}"` from the resolved object; a Maintainer holds `admin_note` (and passes `admin_snippet` on a `DiffNote`) while being denied repository deletion by design, so `gid://gitlab/DiffNote/<id>` is authorized; the service then runs on the wrong class — `Snippets::DestroyService` → `snippet.repository`, and `DiffNote#repository = noteable.repository || project.repository` → `Repositories::DestroyService` deletes the PROJECT repository. Repro: create a diff note on a MR (its id leaks when you delete a previous one), then `mutation test{ destroySnippet(input: {id: "gid://gitlab/DiffNote/118"}){ errors } }` from `/-/graphiql-explorer`.
DETECTION SIGNAL: an id-taking mutation/REST object route casting with `object_from_id`/`node(id:)`/`from_global_id`/`find_object` plus an ability or ownership check derived from the resolved object rather than a type assertion; sibling `destroy<X>` mutations across classes; a role holding `admin_*` on a RELATED object (note/diff-note/comment) while denied the destructive action on its container (project/repository) — that asymmetry is what the confusion launders; a method on the wrong class returning a higher-privileged container (`noteable.repository`, `parent.project`, `board.project`, `namespace`).
CHAIN: low/medium role → mutation fed an id of a DIFFERENT global type → generic resolver + class-derived ability authorizes it → the wrong class's method returns the container (`project.repository`) → the mutation performs a destructive action the role is forbidden to perform (repository deletion; vertical privilege escalation).
TRANSFERABLE TEST: for every id-taking mutation, enumerate the global-id types you can mint (note, diff-note, issue, snippet, attachment, file, label, milestone, member) and send each where the expected type belongs — SUCCESS on a foreign type is the bug (the resolver is generic and the ability came from the object). Then read the wrong class for a method RETURNING a container and call the destructive mutation through it.
WHY IT IS A NEW GENERAL METHOD: the playbook's GraphQL entries cover authorization logic, persisted-operation hashes, client-asserted permission variables and field-level gating — not the ID NAMESPACE itself being polymorphic. The reusable rule: a global-id decoder that does not assert the type means every mutation in the schema can be pointed at every object you can already read.

### [Bugbountyskills.md] 17.141 An OAuth provider's "verify your email" gate enforced only in the UI — POSTing `/oauth/authorize` directly mints a grant code for an UNVERIFIED address, and a relying party that keys accounts on EMAIL folds it into the victim's existing account → cross-site ATO (GitLab / gitlab.com, HackerOne #922456)

CLASS/METHOD: create a provider (GitLab) account with an email you do not control and never confirm it; then request the grant as a RAW request instead of through the UI: `POST /oauth/authorize HTTP/1.1  Host: gitlab.com  Content-Type: application/x-www-form-urlencoded  Cookie: [COOKIES]` with body `utf8=%E2%9C%93&authenticity_token=[CSRF]&client_id=<app>&redirect_uri=<rp callback>&state=[STATE]&response_type=code&scope=&nonce=`. The UI refuses ("Verify the email address in your account profile before you sign in.") but the raw POST returns `302` with a `code` for the UNVERIFIED email. Because the relying party assumes the provider only vouches for validated emails and merges OAuth identities into existing accounts BY EMAIL, redeeming that code logs you into the victim's account (seeded earlier by registering the same email elsewhere). The same trick reaches internal pages that merely check for an `@domain.com` suffix.
DETECTION SIGNAL: an OAuth/OIDC provider whose verification gate is a page-level check (grant obtainable by POSTing the authorization endpoint with your own CSRF token + `client_id` + `redirect_uri` + `state` + `response_type=code`); a relying party that keys accounts on EMAIL rather than the provider's immutable subject id (`sub`) and merges social login into existing accounts; an `email_verified`/verified-email claim asserted without a hard server-side gate; access gates based solely on an email domain suffix.
CHAIN: attacker's provider account with the victim's (unverified) email → raw `POST /oauth/authorize` bypasses the UI-only gate → authorization `code` minted for the victim's email → relying party trusts the provider and merges the identity into the victim's account → full ATO on that RP, at scale on every RP that keys on email, plus internal-only pages gated by email domain.
TRANSFERABLE TEST: for the target's social login — register a provider account with an email you do not control and do not verify; note the UI refusal; replay the authorization endpoint as a raw POST with your session's `authenticity_token`/`state`, `client_id`, `redirect_uri`, `response_type=code`; if a `code` comes back, redeem it at the RP callback and check whether you land in an account created by a different registration with the same email. Test the CLAIM (`email` vs `sub`), never the UI text.
WHY IT IS A NEW GENERAL METHOD: §17.38/§17.80/§17.126 cover identifier-normalization, client-flag pollution and a session minted on a FAILED exchange, but none where the PROVIDER itself asserts an unverified identity. Reusable rule: "verified email" from a provider is a CLAIM — test it by requesting the grant through the raw endpoint, and check whether the RP identifies users by email (mergeable) or by `sub`.

### [Bugbountyskills.md] 17.156 An opaque identifier you cannot enumerate becomes enumerable when the SAME endpoint accepts it under an ALIASED parameter KEY (`userUuid` → `email`) — BOLA/IDOR on an internal server-side path (Uber for Business `POST /server/employees`)

SOURCE: https://hackerone.com/reports/151465 — Uber, *"Get organization info base on uuid"* (Improper Authentication - Generic; no rating; $3,000; 23 votes; reporter **severus**; created 2016-07-15, disclosed 2016-09-02; resolved)  read 2026-11-07 (full 300-B public body from the LOCAL disclosed-reports mirror `/tmp/h1_train.parquet`; the live page via `web_extract` additionally surfaced the reporter's `email`-alias follow-up comment)
CLASS: BOLA/IDOR where the object identifier's KEY is interchangeable — a UUID-keyed parameter is not the only way the handler hydrates the object, and one of the alternative keys is a directory-enumerable identifier.
CORE METHOD (reporter's text, typos his):
  1. Entry point: `https://business.uber.com/server/employees` — the console's own server-side path, not the documented API.
  2. "Send post request to https://business.uber.com/server/employees" … "Change `userUuid` of other user and then see organization info if they has valid organization and their persinol info".
  3. Reporter's follow-up on the same report: "my attack can get full name of employees, payment name for org, useruuid ( if they have profile in Uber) and org's id. In addition, I found that turned `userUuid` into `email` made this attack easier."
DETECTION SIGNAL: a request body carrying an identifier KEY whose value you never supplied (`userUuid`, `org_id`, `uuid`) — resend with the key RENAMED to `email`, `user_id`, `id`, `username`, `phone`, `orgId`, `organization` and the victim's identifier as the value; a handler hydrating from whichever key it finds converts an unguessable UUID into an enumerable identifier. Secondary tell: console pages that load employee/org data through `/server/…` (or `/internal/…`, `/bff/…`) paths the public API never documents — read the bundle's XHR names.
CHAIN: any authenticated business account (primitive: one POST with an identifier the caller is not entitled to) → `userUuid`/`email` of another user → response leaks organization info, the full names of employees, the org's payment name and org id → cross-tenant enumeration of an employee directory merely by substituting `email` for the UUID key → BAC/IDOR on PII + billing metadata.
TRANSFERABLE TEST: capture the org/team/employee request, then (a) swap the identifier for a second account you control and diff; (b) RENAME the key (`userUuid` → `email`) and resend with a victim's address; (c) repeat against the sibling `/server/…` list, detail and export routes. A response naming employees, a payment name or an org id you should not see = reportable BAC/IDOR; size the leak by enumerating the alias key across the domain's public mail pattern.
WHY IT IS A NEW GENERAL METHOD: the recorded BOLA material (V-05/BMAO playbook, GraphQL BOLA, IDOR-DELETE, mass-assignment entries) covers swapping an ID VALUE, extra body fields, method override and cursor walking — none covers swapping the parameter KEY for an alias the backend also accepts, which is the step that turns an unguessable UUID into an enumerable identifier. The one adjacent ledger note (a payment-integrity "field-rename primitive", `Amount`/`Amount2` hashing) is a signature-validation trick in a different context.

### [Bugbountyskills.md] 17.170 A sandbox that decides TRUST from a CANONICALIZED path while the LOADER resolves the RAW string grants high privileges for a path it never loads — `..`/nested-archive interpretation split (PS4 BD-J `BdjPolicyImpl` vs `JarZipFile`, HackerOne #3452696)

SOURCE: https://hackerone.com/reports/3452696 — PlayStation, "PS4 BD-J privilege escalation using nested JAR" (Privilege Escalation; Medium; $2,500; reporter gezine)  read 2026-11-07 via the `.json` `summaries[]` team writeup (10,563 B) + `r.jina.ai` cross-check
CLASS: sandbox / privileged-context escape by path-interpretation split (TOCTOU) · CWE-436 / CWE-367 → CWE-269
CORE METHOD:
  1. Pick a path that means two different files: `file:/dsm/00000.jar/../../app0/bdjstack/lib/ext/00000.jar` (`javaHome=/app0/bdjstack`, `vfsRoot=/VP`=disc root).
  2. The TRUST check canonicalizes: `BdjPolicyImpl.getPermissions()` → `new File(url.getFile()).getCanonicalPath()` → `/app0/bdjstack/lib/ext/00000.jar` → `startsWith(javaHome+"lib/ext")` TRUE → `AllPermission` granted.
  3. The LOADER is literal: `needProxy("/dsm/…")` → `getAbsPath()` prefixes `vfsRoot+"BDMV/JAR/"` → `/VP/BDMV/JAR/00000.jar/../../app0/bdjstack/lib/ext/00000.jar`; `JarZipFile` splits at the FIRST `.jar/`, opens the OUTER JAR on the disc, and looks up the ZIP ENTRY named literally `../../app0/bdjstack/lib/ext/00000.jar` (a nested JAR you packed) → classes load from YOUR JAR.
  4. Skip signature verification: nested-JAR classes go through `JarInputStream`, and `defineClass1()` nulls the certs when `!isBDJVerified()`; additionally set the BDJO `applicationId` OUTSIDE `0x4000..0x7FFFF` so `CoreAppId.isSigned()` is false → `needsToVerify()` false → the `"cannot load unsigned class."` throw is skipped.
DETECTION SIGNAL: a sandbox deciding trust from a NORMALIZED path/URL (`getCanonicalPath()`, `realpath()`, `normpath()`, `Path.resolve()`, `.normalize()`) while the loader uses the RAW string (or vice versa); a nested container (`x.jar/…`, image layer, archive-in-archive) or symlink table where `..`/a separator is DATA; a trust/signature decision gated on an attacker-controlled flag (here the "am I signed?" `applicationId` boolean) that when false skips the whole check.
CHAIN: unauthenticated author of a disc image → crafted Xlet/BDJO path (primitive) → policy canonicalizes → `AllPermission` on a path it never loads (primitive) → loader treats `..` literally → loads attacker class from a nested JAR (primitive: split interpretation) → unsigned code with all privileges → full system access (Medium in the console's model; RCE/Critical for the same split in a server-side/CI sandbox).
TRANSFERABLE TEST: wherever a sandbox allowlists a PATH, compute both normalizations yourself and diff them — build a value whose canonical form sits inside the allowlisted prefix while its literal form points at your file (`<allowed>/../../<allowed>/x` where the consumer splits on the first separator/`.jar/` and treats the rest literally). Then look for an attacker-settable flag that short-circuits the trust check and set it.
WHY IT IS A NEW GENERAL METHOD: this file's sandbox-escape and path-traversal material records traversal decoding ladders (single/double URL-encode) and the recorded BD-J chain (#1379975: deserialization→class-instantiation→reflective bypass→JIT write-what-where→UDF overflow); neither records the "checker canonicalizes / consumer treats the string literally" trust split, where the path resolves to a trusted location for the permission decision and to an attacker object for the load. Reusable rule: **if two components interpret the same path differently, the one that grants trust and the one that loads the bytes are the bug — always diff the canonicalizer against the opener.** Slot 17.170.

### [Bugbountyskills.md] 17.175 A role assignment that silently SUBSCRIBES the new member to PRIVATE child objects discloses those objects through the notification payload — implicit authorization attached to a subscription, not to a read (HackerOne program-viewer draft-report exposure, #2552205)

SOURCE: https://hackerone.com/reports/2552205 — HackerOne, "Private draft report exposure in a program a user is added as a viewer to" (Information Disclosure; Medium 6.5; no bounty; reporter jay; created 2024-06-14, disclosed 2024-09-17)  read 2026-11-07 via the `.json` endpoint — `visibility: no-content`, `vulnerability_information` 0 B; the method is the program's own `summaries[]` team entry (585 B), cross-checked with `r.jina.ai` (same page). No researcher body / no request shapes exist — the entry is flagged accordingly.
CLASS: broken access control by implicit authorization-on-subscription · CWE-285 / CWE-639
CORE METHOD (from the program summary — nothing invented):
  1. You are added to a program as a VIEWER — the lowest role.
  2. The role assignment AUTO-SUBSCRIBES the viewer to that program's DRAFT reports (private, unpublished objects).
  3. Every subsequent comment on ANY draft emits a notification to the viewer carrying the private content: "the exposure of sensitive information, including the comment content, report title, and the creation time of the draft (viewable via the GraphQL response)".
  4. Read the notification stream / its backing GraphQL query for the draft title and comment bodies.
DETECTION SIGNAL: a role-assignment action (add-member / add-viewer / invite) that silently attaches the member to child objects' NOTIFICATION/SUBSCRIPTION streams; a notification payload (email, push, in-app feed, or the GraphQL query the feed calls) carrying the private object's TITLE/BODY/COMMENT text rather than an id; a role denied READ that still RECEIVES notifications. Tell: you cannot OPEN the object yet you RECEIVE its contents.
CHAIN: added under the LOWEST role (primitive: membership) → platform implicit-subscribes you to private draft reports (primitive: authorization attached to a subscription, not a read) → draft titles + comment bodies delivered via the notification/GraphQL payload → mass disclosure of a program's private drafts and comments (Medium; "mass disclosure" in large programs).
TRANSFERABLE TEST: get added under the MINIMUM role, have another user comment/update a PRIVATE child object (or wait for one), then inspect EVERY notification channel — email, push, in-app feed, and the GraphQL/REST query the feed itself issues. If the private object's title/body/comment text arrives, the role granted an implicit READ via subscription: report the SUBSCRIPTION, not the role.
WHY IT IS A NEW GENERAL METHOD: this file's authorization material records missing ownership checks, role/claim tampering and mass-assignment; nothing records an authorization implicitly created by a ROLE ASSIGNMENT that ATTACHES A SUBSCRIPTION to a private object, where the READ is never granted but the notification stream becomes the exfiltration path. Reusable rule: **after any "add member / lower role" action, treat the notification/subscription stream as an access path — diff what the feed delivers against what the role may read.** Slot 17.175.

### [Bugbountyskills.md] 17.180 An export/render endpoint authorizes the request that CREATES the artifact but not the request that FETCHES it — a tenant id in the request BODY plus a format-switchable artifact URL is a two-request cross-tenant extraction chain (New Relic "Get as image" NRQL, HackerOne #397137)

SOURCE: https://hackerone.com/reports/397137 — New Relic, "[NR Insights] Pull any Insights/NRQL data from any NR account" (Insecure Direct Object Reference; $2,500; 2018-10)  read 2026-11-07 via the CREDITED public writeup of the same researcher, `https://www.jonbottarini.com/2018/10/09/get-as-image-function-pulls-any-insights-nrql-data-from-any-new-relic-account-idor/` — the H1 page itself is gone (page → HTTP 302, `.json` → HTTP 404, all archives show only H1's JS shell; nothing invented, every request shape below is quoted from the writeup).
CLASS: IDOR/BOLA on a tenant identifier inside a render/export REQUEST BODY, escalated by a FORMAT SWITCH on the artifact URL the response advertises (CWE-639).
CORE METHOD (credited writeup, verbatim structure):
  1. Entry surface: Infrastructure → GCP integration dashboards' per-chart "Get as image" action — present in no other dashboard area (a one-area feature usually missed the shared authorization helper).
  2. The action POSTs the chart definition: `{"query":{"account_id":1523936,"nrql":"SELECT count(*) FROM IntegrationError FACET dataSourceName SINCE 1 DAY AGO"},"account_id":1523936,"endpoint":"/v2/nrql","title":"Authentication Errors"}` — `account_id` appears twice and is never checked against the caller.
  3. Swap both ids for a foreign account (ids are incremental → Burp Intruder), and swap `nrql` too: `{"query":{"account_id":any_account_number_here,"nrql":"SELECT * FROM SystemSample"},"account_id":any_account_number_here,"endpoint":"/v2/nrql","title":"Uh oh!"}` — the query, not the chart, defines the data exposed.
  4. ESCALATION: the response carries `X-Image-Url: http://gorgon.nr-assets.net/image/{UNIQUE_ID}`; append `?type=json` (or `?type=json&height=2000`) and the "image" returns the tenant's data as a JSON dump; an invalid `?type=` answers with the permitted list (`apdex area bar … traffic-light vertical-bar`, incl. `json`, `csv`-like `table`, `markdown`).
DETECTION SIGNAL: an export/render/chart/PDF feature whose request BODY carries the tenant identifier (`account_id`, `org_id`, `tenant_id`, `team_id`) instead of deriving it from the session; a RESPONSE HEADER advertising the generated artifact (`X-Image-Url`, `X-Asset-Url`, `Location`, `Content-Location`) with an opaque id and a format switchable by query parameter (`?type=`, `?format=`, `?raw=`); sequential/guessable tenant ids; the same action missing from sibling product areas.
CHAIN: normal account, no privilege (primitive: authenticated user) → POST the render request with a foreign `account_id` in the body (primitive: IDOR — no ownership check on the render path) → server executes the attacker's `nrql` for that tenant (primitive: cross-tenant arbitrary query) → fetch `X-Image-Url … ?type=json` (primitive: format switch = machine-readable exfil) → every account's telemetry/dashboards (High; $2,500). Three requests: the check covers request one, the impact lives in request two/three.
TRANSFERABLE TEST: capture any export/render request and list EVERY identifier in the BODY, not just the path; replay with a second account you own and with id±1; then take the artifact URL from the response HEADERS and append `?type=json`, `?format=csv`, `?raw=1`, `?type=bogus` (bogus often lists the permitted formats). Foreign tenant data in a machine-readable format = the IDOR + exfil chain. Rule: **audit the SECOND request — the one that fetches the artifact the first request produced.**
WHY IT IS A NEW GENERAL METHOD: this file's IDOR material is object-id substitution in paths/params/GraphQL args where a single request both triggers and returns the data; the renderer/export material records SSRF, injection and XSS through renderers, not authorization across a two-step artifact flow. Nothing records the pattern "authorization missing on a BODY tenant id + the produced artifact is retrievable by an id and re-serializable into another FORMAT", which is what turns an empty chart into a full dump. Reusable rule: **for any export/render, test the artifact-fetch leg separately from the create leg, and always try to switch the artifact's output format.** Slot 17.180.

### [Bugbountyskills.md] 17.182 A privileged desktop helper/installer is exploitable on two axes — a caller-supplied SOURCE PATH installed with the CALLER's ownership, and a signature-check-then-launch TOCTOU (symlink swap); either yields unprivileged local user → root (Keybase macOS Helper/Installer, KB004 group, HackerOne #473252 / #471739 / #470398)

SOURCE: https://hackerone.com/reports/473252 — Keybase, "Privilege Escalation through Keybase Installer via Helper" (Privilege Escalation; $2,500; 17 upvotes)  read 2026-11-07. The report's own body is NOT public (`.json` → HTTP 404; page → HTTP 302; `web_extract` → Cloudflare 403; `r.jina.ai` → Cloudflare "Just a moment…" → `/users/sign_in`; every Wayback capture is H1's JS-disabled shell; the id is absent from the mirror and from all three Hugging Face splits). Technique read via (a) the CREDITED VENDOR ADVISORY `https://keybase.io/docs/secadv/kb004` (13,025 B, fetched whole, whose External Links name this report by its exact title) and (b) the SAME advisory group's publicly disclosed sibling bodies, read in full this pass: H1 #471739 "macOS privilege escalation via keybase install" (8,584 B) and H1 #470398 "Local privilege escalation bug using Keybase redirector on macOS" (4,227 B). HONESTY NOTE: KB004 collected five reports / three bugs and does not attribute a specific bug to a report id — this entry records the advisory-GROUP technique with every step quoted from those bodies. Affected: Keybase for macOS < 2.12.6 (fixed 2019-01-01).
CLASS: local privilege escalation to root via a privileged desktop helper/installer — (a) privileged install from a CALLER-SUPPLIED SOURCE PATH with the caller's ownership preserved; (b) check-then-use TOCTOU (signature verify at path P → launch by path P) with a symlink swap (CWE-269 / CWE-367). Distinct from §17.86, which is a $PATH resolution bug in a setuid binary.
CORE METHOD (verbatim structure from the group's public bodies):
  1. Preconditions: an unprivileged local user (uid=508), app installed by an admin; Keybase 2.12.2 (< 2.12.6). No admin rights.
  2. INSTALLER axis (#471739): call the app's installer CLI with an ATTACKER-CONTROLLED bundle as source, abusing DUPLICATE options so the attacker's value wins — `keybase -d install -f --source-path=/does/not/exist -c app --source-path=$PWD/Keybase.app`; the log shows `keybase.Helper (privileged=1)` → `Install: Privileged Helper` → `Checking security requirements` → `Copying app bundle /Users/test2/update/Keybase.app to /Applications/Keybase.app` → `Checking destination`.
  3. RESULT: `ls -ld` afterwards shows `/Applications/Keybase.app` and its binaries owned by the UNPRIVILEGED user (`test2 staff`) — the root helper moved attacker content into the privileged location carrying the caller's ownership, so the low-priv user can trojan the app others launch (reporter also flags a probable root path).
  4. REDIRECTOR axis (#470398): the Helper copies `keybase-redirector` to a root-only location, CHECKS ITS SIGNATURE, then LAUNCHES it referencing "just its path" (reporter's code ref `osx/Helper/KBHelper.m#L213-L236`) — replace the binary with a SYMLINK that points at the real binary for the check and at an evil script for the launch.
  5. Widening the race, verbatim: patch `bindfs` so `bindfs_read` counts reads and prints the counter, mount it over `~/switcher`, create the two symlinks, restart the redirector via the app's MessagePack/RPC path, and flip `switch` → `evil.sh` when the count hits the marker; `evil.sh` = `touch /pwned.txt`, which appears ROOT-owned.
DETECTION SIGNAL: a desktop app with a privileged helper/installer — macOS SMJobBless/Helper + Installer (`XPC`/`MPXPCClient`/MessagePack RPC reachable by ANY local user), a Windows SYSTEM service, a Linux setuid/setgid helper — where (i) an install/update/move RPC takes a CALLER-SUPPLIED source or destination path, (ii) the privileged process CHECK-THEN-USE's a path (signature/type check, then launch/copy/move by the same path), or (iii) files in a privileged location keep or acquire the CALLER's ownership. Tells: a CLI option that can be repeated with the attacker's occurrence winning (`--source-path=… --source-path=…`); log strings `Copying app bundle … to /Applications/…`, `Install: Privileged Helper`, `Checking security requirements`, `Checking destination`; helper launched by bare path after a signature check; `move`/`install`/`update` RPC verbs naming paths.
CHAIN: unprivileged local user (primitive: ordinary account) → invoke the install/update path with an attacker-controlled source bundle (primitive: privileged helper honours a caller-supplied source path) → the root Helper copies it into a privileged location keeping the caller's ownership (primitive: privileged write of attacker content, attacker-owned) → trojan the binaries/config of an app launched by other users or root at startup, OR win the check→use window with a symlink swap (primitive: TOCTOU) → code executes as root / as any user running the app = full local privilege escalation. The vendor's fix names both halves: the `move` RPC was RETIRED, installs run unprivileged, and file TYPES are checked when moving into privileged locations.
TRANSFERABLE TEST: on any desktop app with a privileged helper, ask three questions in order. (1) Can my unprivileged user invoke its install/update/move RPC at all? (2) Does any option name a SOURCE or DESTINATION path — pass my own (try the duplicate-option trick, then the bare form `--source-path=$PWD/evil.app`), then `ls -ld` the privileged destination and check WHOSE ownership the files carry. (3) For any check-then-use path (signature/type verify → launch/copy/move), race a symlink swap — widen the window with a slow FUSE layer or a tight loop, watch with `fs_usage`/`opensnoop`, and flip `link → real` to `link → payload` after the check. My ownership on files in a privileged location, or a payload of mine executed from there, is the escalation. Rule: **a privileged helper is only as safe as its authorization on the IPC verb AND its ownership/type handling at the destination — test the verb, then race the check-then-use.** Slot 17.182.

### [Bugbountyskills.md] 17.183 A "recently used / saved query" history persists user input and re-renders it to EVERY user of the tenant — one low-privilege write, all users as victims (New Relic NRQL chart builder & "my recent queries", HackerOne #634692 + #626082)

SOURCE: https://hackerone.com/reports/634692 — New Relic, "Stored XSS Via NRQL chartbuilder JSON view" (XSS; $2,500; 9 upvotes) and the sibling https://hackerone.com/reports/626082 — "Stored XSS via \"my recent queries\" selector in NRQL dashboard builder" (XSS; $2,500; 15 upvotes)  read 2026-11-07. Neither body is public (page -> HTTP 302 to `/users/sign_in`; `.json` -> HTTP 404; `web_extract` -> Cloudflare 403; `r.jina.ai` -> Cloudflare interstitial; the browser tool -> Cloudflare Ray ID `a56ff700fd2e1116`; every Wayback capture is H1's JS shell). Technique read from TWO independent public indexes that quote the report verbatim — `maverickNerd/BugForaging/Bugs_on_NewRelic.md` ("Bug 10") and `pwnpanda/Bug_Bounty_Reports/reports.md` (row 332) — plus #626082's own `og:description` (Wayback raw capture) for its entry point. Nothing invented.
CLASS: stored XSS through an account-wide SAVED-INPUT feature (query history).
CORE METHOD:
  1. Chart builder -> query editor -> NRQL mode; submit a query whose text carries the payload (published by both indexes): ``SELECT `"><img src=x onerror=alert(document.domain)> "' Style=position` FROM SyntheticCheck`` — the backtick and `">` close out of the string/attribute context the query is later rendered in, and `Style=position` absorbs the trailing syntax so the query still stores.
  2. The query text is persisted for the WHOLE account ("all the recent queries are saved and showed to all the users of acount").
  3. Any user who opens the chart builder / the account's "recent queries" list runs the script in THEIR session; #626082 delivers it by link ("having them navigate to the link") from the dashboard builder's "my recent queries" selector, #634692 is the chartbuilder JSON view.
DETECTION SIGNAL: any "recent / saved / last used / history" store of user input inside a tenant-scoped product, rendered back as HTML or attribute content and visible to OTHER users of the same account; a query language (NRQL or any `SELECT ... FROM ...`) that allows arbitrary string literals.
CHAIN: low-privilege user of the tenant (or an attacker who plants a query others will open) -> unsanitized persistence of the query text in the account-wide history (primitive: stored XSS) -> execution in EVERY user's session, admins included ($2,500 each) -> the usual stored-XSS escalation: session/token theft or privileged action inside that account.
TRANSFERABLE TEST: find every feature that REMEMBERS input and shows it to a wider audience (recent queries/searches, saved views, history dropdowns, shared dashboards); plant x"><img src=x onerror=alert(document.domain)> (or a script tag / template expression), then open that history UI as a DIFFERENT user of the same account and watch for execution.
WHY IT IS A NEW GENERAL METHOD: this file's stored-XSS material covers profile/name fields, chart/JSON fields (#520630 — a role name inside a JSON chart), notes and embedded charts, all places where the ATTACKER's own object is rendered to somebody else. Nothing records this carrier: a HISTORY store that is the account's shared memory of input, so one low-privilege write lands in front of every user, and the payload has to defeat the RENDER OF A QUERY LANGUAGE rather than an HTML attribute. Reusable rule: **treat "recently used / saved" lists as account-wide sinks — the victim set is everyone who opens them, not just the author.** Slot 17.183.

