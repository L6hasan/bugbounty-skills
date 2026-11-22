# Variants 1-8 — IDOR core, function-level, and ID-shape flaws

Deep playbook for the first eight broken access control variants. Each section follows
the same shape: **Mechanism → Preconditions → Detect → Proof of concept → Confirm →
False positives → Impact → Remediation → CWE / OWASP**. Payloads, curl templates, and
the two-account setup live in `payloads.md` — every proof below assumes you completed
that setup first.

## Table of contents

- [V-01: Direct parameter manipulation via authenticated IDOR security evasion](#v-01-direct-parameter-manipulation-via-authenticated-idor-security-evasion)
- [V-02: Unauthenticated endpoint identification via IDOR resource enumeration](#v-02-unauthenticated-endpoint-identification-via-idor-resource-enumeration)
- [V-03: Scripted request validation and automation via custom cURL IDOR frameworks](#v-03-scripted-request-validation-and-automation-via-custom-curl-idor-frameworks)
- [V-04: Internal variable overwriting via mass assignment object property injection](#v-04-internal-variable-overwriting-via-mass-assignment-object-property-injection)
- [V-05: Horizontal privilege escalation via missing object-level access control (BOLA/BMAO)](#v-05-horizontal-privilege-escalation-via-missing-object-level-access-control-bolabmao)
- [V-06: Vertical privilege escalation via function-level access control evasion (RBAC/ABAC bypass)](#v-06-vertical-privilege-escalation-via-function-level-access-control-evasion-rbacabac-bypass)
- [V-07: Server-side array confusion via HTTP parameter pollution (HPP) IDOR mutations](#v-07-server-side-array-confusion-via-http-parameter-pollution-hpp-idor-mutations)
- [V-08: Cryptographic entity guessing via cryptographically weak UUID/GUID generation routines](#v-08-cryptographic-entity-guessing-via-cryptographically-weak-uuidguid-generation-routines)

---

## V-01: Direct parameter manipulation via authenticated IDOR security evasion

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
# Control (A's own object) vs. probe (B's object)
curl -sS -i -H 'Cookie: session=<SESSION_A>' '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_A>'
curl -sS -i -H 'Cookie: session=<SESSION_A>' '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_B>'
```

**Confirm:** Log in as B and fetch the same object; the data A received must match B's
own view (unique marker field, timestamps). One request proves nothing — the same 200
could be dummy data.

**False positives:** Endpoints that echo any ID with a default/dummy object; soft-404s
(HTTP 200 + empty body or `null`); ID namespaces colliding across types (ID `451` is a
different object family than you think); CDN caching a response keyed without the ID;
redirects landing you back on your own object (check the final body, not the 302).

**Impact:** "Any authenticated user can read (or modify) any other user's `<records>` by
changing `<param>` — no enumeration needed beyond possessing an ID." Name the data class
(PII, financial, private content) and the number of objects reachable if you sampled it.

**Remediation:** Enforce a server-side ownership check binding the object to the
session principal on every read/write, deny by default when the binding fails — the ID
must be a lookup key, never an authorization credential.

**CWE / OWASP:** CWE-639 (Authorization Bypass Through User-Controlled Key); OWASP
Top 10 A01:2021 Broken Access Control; OWASP API API1:2023 BOLA.

---

## V-02: Unauthenticated endpoint identification via IDOR resource enumeration

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
# Strip every credential; use a clean cookie jar so nothing leaks in
curl -sS -i -c /dev/null '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_B>'
# Control: a known-protected sibling
curl -sS -i -c /dev/null '<TARGET_URL>/api/profile'
```

**Confirm:** The same resource ID is *denied* to an unauthenticated caller on a sibling
route but returned in full here — proving this specific route skipped auth rather than
the whole API being public by design.

**False positives:** Genuinely public resources (marketing, shared links with secret
tokens — a long random path is "capability URL", classify differently); browser
extension or proxy auto-injecting an auth header (verify with curl, not Repeater that
still has a rule); shared CDN cache serving a logged-in user's page (check for `Age` and
replay with `Cache-Control: no-cache`); "public profile" pages that are intentional —
compare field depth with the authenticated view.

**Impact:** "The `<resource>` API requires no authentication; anyone on the internet can
read `<data>` for any ID." Unauthenticated findings are typically one severity step above
the authenticated equivalent.

**Remediation:** Put the route behind default-deny authentication middleware shared with
the rest of the API — public access must be an explicit allow-list entry, not an
omission.

**CWE / OWASP:** CWE-306 (Missing Authentication for Critical Function); OWASP A01:2021.

---

## V-03: Scripted request validation and automation via custom cURL IDOR frameworks

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

## V-04: Internal variable overwriting via mass assignment object property injection

**Mechanism:** The framework binds the request body wholesale onto a model/DTO
(`req.body` → `user.save()`), including fields no client should set: `role`, `is_admin`,
`owner_id`, `verified`, `tenant_id`, `credits`, `price`. The violated assumption is
"input only contains the fields the form showed".

**Preconditions:**
- Body maps to a persistent object (ORM/Active Record/Eloquent, or a Rails
  `params.require(...).permit` misconfig) and a candidate privileged/ownership field
  exists in the model (guess from UI, API docs, client JS, or error messages).

**Detect:**
1. Capture a legitimate state-changing request (profile update, settings save, order
   create) as Account A.
2. Add one extra property at a time to the body: `role`, `admin`, `is_admin`,
   `owner_id`, `user_id`, `verified`, `status`, `credits`, `tenant_id`, `password_hash`
   (read-only probes first).
3. Diff response *and* follow-up behavior: re-fetch the object, then hit a function only
   available at the new privilege/ownership level.
4. Enumerate bindable fields with a canary key: unknown-key errors, a `422` naming
   allowed fields, or silent drop reveals the allow/deny-list shape.
5. Overwrite ownership on *someone else's* object (`owner_id` → A's id on
   `<OBJECT_ID_B>`) — that converts a vertical probe into a takeover.

**Proof of concept:**
```bash
curl -sS -i -X POST '<TARGET_URL>/api/<RESOURCE>' \
  -H 'Cookie: session=<SESSION_A>' -H 'Content-Type: application/json' \
  -d '{"name":"probe","role":"admin"}'          # privileged-field probe

curl -sS -i -X PUT '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_B>' \
  -H 'Cookie: session=<SESSION_A>' -H 'Content-Type: application/json' \
  -d '{"owner_id":"<USER_ID_A>"}'               # ownership-transfer probe
```

**Confirm:** The injected value takes effect through an *independent* path: as A you now
pass a role-gated check, or as B the object is foreign-owned while A can still manage it.
A field echoed back in the response body is not confirmation.

**False positives:** Field accepted and silently discarded (return payload reflects
request, DB does not); role field written but the app re-derives role from a separate
relations table at check time; harmless display preferences behaving as designed;
`null` hydration where absent fields are nulled rather than set (check before/after);
admin flag on a demo tenant where everyone is admin.

**Impact:** "A user can set `<privileged_field>` on their own (or another user's) record,
gaining `<role/action>` or taking ownership of `<resource>`." State whether it persists.

**Remediation:** Bind each endpoint to an explicit per-endpoint allow-list DTO —
never assign request payloads onto the persistence model directly, and set
ownership/role columns only from server-side session context.

**CWE / OWASP:** CWE-915 (Improperly Controlled Modification of Dynamically-Determined
Object Attributes); OWASP A01:2021 + A04:2021 Insecure Design.

---

## V-05: Horizontal privilege escalation via missing object-level access control (BOLA/BMAO)

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

## V-06: Vertical privilege escalation via function-level access control evasion (RBAC/ABAC bypass)

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

## V-07: Server-side array confusion via HTTP parameter pollution (HPP) IDOR mutations

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

## V-08: Cryptographic entity guessing via cryptographically weak UUID/GUID generation routines

**Mechanism:** Object identifiers look unguessable but are structurally predictable:
UUIDv1/v2 embed a timestamp (and MAC), DB auto-increment counters leak volume, snowflake
IDs embed a millisecond timestamp with a fixed epoch, and weak PRNGs seed from time.
Knowledge of *your own* IDs reveals *other users'* IDs — turning a "secret URL" into a
list. (Predictability alone is not a vulnerability: it becomes one when combined with a
missing authz check, i.e., it upgrades V-01 from hard to trivial.)

**Preconditions:**
- You can collect 3-5 IDs you legitimately own (or public IDs from listing pages).
- IDs follow one of the cataloged shapes — run the catalog in `payloads.md` first.

**Detect:**
1. Collect several IDs (your objects + any public ones) and lay them side by side.
2. Check UUID version: third group starts with `1` → v1/v2 (timestamp-bearing); with `4`
   → v4 (random — stop here for pure guessing). Decode v1 time fields: does the
   timestamp equal the object's creation time you know? That's a leak by itself.
3. Check the node/MAC field (last 12 hex): a constant value across IDs means a real MAC
   or fixed node — more structure to correlate; random node per ID weakens the attack.
4. Integers: measure deltas (+1, +7, time-bucketed?). Snowflake-shaped 18-19 digit IDs:
   shift right 22 bits, subtract the vendor epoch — does it decode to a plausible
   creation time? Then neighbors in time are neighbors in ID space.
5. Prediction test with two accounts: create a new object as B *after* observing A's
   sequence, generate the candidate ID locally, and fetch it as A. Success = confirmed
   predictability against a real other-principal object.

**Proof of concept:** (structure, not a brute force — see payload catalog for decoders)
```bash
# Candidate derived from your own ID(s); fetch as A
curl -sS -i -H 'Cookie: session=<SESSION_A>' \
  '<TARGET_URL>/api/<RESOURCE>/<PREDICTED_ID_FOR_B_OBJECT>'
```

**Confirm:** You fetch an object belonging to B that you never observed in any response
(predicted from your own IDs), and B's session confirms that object is B's. Optionally,
decoded v1 timestamp equals B's real creation time — an independent structural signal.

**False positives:** RFC 9562 v1/v2 with a random node field (no MAC leak); hashids or
slugged IDs that merely *look* sequential (same input → same output reveals a salt —
check determinism); ID count too small to distinguish pattern from chance; IDs shared
across environments (staging IDs replayed in prod); timestamps present but IDs still
122-bit random for v4.

**Impact:** "Object identifiers are predictable (`<shape>`), so any user can enumerate
other users' `<resource>` — combined with `<existing authz gap>` this yields bulk
enumeration." If the IDs alone leak creation-time metadata, note that as a secondary
information disclosure.

**Remediation:** Issue random (UUIDv4/128-bit) or HMAC-derived opaque IDs server-side,
and never let authorization depend on ID secrecy — predictability must not widen access.

**CWE / OWASP:** CWE-330 (Use of Insufficiently Random Values) / CWE-340
(Predictability); paired with CWE-639 when exploited; OWASP A01:2021 (+ A02:2021 where
crypto primitives are the root cause).
