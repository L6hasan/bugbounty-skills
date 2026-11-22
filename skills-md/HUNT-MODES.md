# HUNT-MODES — blackbox / graybox / whitebox, case by case

Companion to `/root/HUNT-WORKFLOW.md`. This file answers one question: **given what I already
have, what is the correct first move and what do I do when it stalls?**

---

## §B — BLACKBOX (no credentials, no code)

**You may assume:** only what the wire shows. Anything else is a guess and guesses cost passes.

### B1. Fingerprint (5 min, do not skip)
```
U=https://target
curl -sS -D - -o page.html "$U" | grep -iE '^(server|content-type|x-powered|set-cookie|strict-transport|x-frame)'
whatweb -a 3 "$U"
httpx -u "$U" -td -title -status-code -tech-detect -web-server
```
Write down: server + version, frontend framework, auth product (SSO/OIDC/SAML), WAF/CDN,
session cookie names, and every security header. **The cookie set is the auth model** — multiple
cookies means multiple layered sessions and you must find which one the API honors (remove them
one at a time until the response changes).

### B2. Surface map
```
curl -sS "$U" | grep -oE '(src|href)="[^"]+"' | sort -u
curl -sS "$U/main.<hash>.js" -o main.js
grep -oE '"/[A-Za-z0-9_.:/-]{3,60}"' main.js | sort -u
grep -oiE '(rest|api|graphql|rpc|internal|v[0-9])[-_a-z0-9/]*' main.js | sort -u
katana -u "$U" -jc -d 3 | sort -u > urls.txt
```
Micro-frontend / Angular / React apps hide the entire route table behind a hashed bundle plus
`remoteEntry.js`. Fetch `remoteEntry.js` — it names every module and every chunk hash, so you can
pull the *entire* client even without a browser.

### B3. Unauthenticated triage, in this order
1. **Auth itself** — login endpoint, password reset, registration, SSO `redirect_uri`/`state`.
2. **Public APIs** — anything ending `/api`, `/rest`, `/graphql`, `/v1`, `/rpc`.
3. **Object ids in public responses** — then test them without auth (missing check vs. public).
4. **Static leakage** — source maps, `.git`, `.env`, buckets, backups, `swagger.json`.
5. **Open redirect / SSRF sinks** — callback, webhook, image proxy, PDF render, import URL.

### B4. When blackbox stalls
- Sign up (self-signup allowed is still blackbox, and it unlocks graybox).
- Get a second identity (two browsers, two tenants if free tiers allow).
- Go read the public docs/help centre to learn the product's own vocabulary — then request the
  endpoints the UI *would* call but the page does not render.
- Take the app's own mobile/legacy route: `/m/`, `/mobile/`, `/v1/`, `/internal/`, `.json` suffix.

**Blackbox budget:** 60/40 recon-to-hunt early, flipping to 20/80 once the surface map exists.
Do not keep enumerating after the sensitive surface is identified — that is procrastination.

---

## §G — GRAYBOX (credentials, any role)

**You may assume:** you are a real, authorized user. This is where most bounty money is.

### G1. Set up two principals before testing anything
```
creds/<slug>-<userA>.cookies     # lower role  (viewer)
creds/<slug>-<userB>.cookies     # higher role (tester/admin)
```
Verify each actually authenticates — a login that silently redirects to a landing page is a
broken session. Then build the request helper once and reuse it so every test has identical
headers except the one variable under test.

### G2. The two-account loop (the backbone of BAC/IDOR)
For each object-bearing endpoint:
1. `A` requests `A`'s object → **baseline** (status, size, body hash).
2. `A` requests `B`'s object → **probe**.
3. `B` requests `B`'s object → **confirms the object exists and B can read it**.
4. `A` requests `B`'s object with **no credentials** → negative control.

Verdict table:

| baseline | probe | B-baseline | noauth | verdict |
|---|---|---|---|---|
| 200 | 200, identical body | 200 | 401 | **IDOR — confirmed** |
| 200 | 200, different body | 200 | 401 | field-scoped leak — dig |
| 200 | 403 | 200 | 401 | check exists — try bypass ladder |
| 404 | 404 | 200 | 401 | wrong id format — not a finding |
| 200 | 404 | 200 | 401 | object-scoped 404 = **check exists**, try sibling route |
| 200 | 500 | 200 | 500 | server crash ≠ authz decision — inspect error class |

**Step 3 is the step people skip.** Without it you cannot distinguish a real IDOR from a
mysterious id that returns empty for everyone.

### G3. Role/tenant matrix
Take one endpoint, vary: role (viewer vs tester vs admin), tenant/org GUID, and verb
(GET→POST/PUT/DELETE). A lower role that can *read* an admin-only object is Low/Medium; one that
can *write* is High. Same for cross-tenant.

### G4. The session/CSRF model — determine it empirically
This is not theoretical: on real SSO products the CSRF header may be present, absent, or bogus
and the result may not change. Test:
```
with token      -> ?
without token   -> ?
with bogus token-> ?
```
If all three behave the same, the token is **decorative** for that route → note it as chain
material (CSRF), do not report it alone. If removing it changes the response, you found the real
gate and can now attack it deliberately.

Cookie-flag findings (`SameSite`, `HttpOnly`) are program-disqualified in most modern programs.
Only care about them when they enable an actual theft path.

### G5. When graybox stalls
- Enumerate the *product's own* API from the JS bundle, not from your imagination.
- Ask "what does the admin role see that I do not?" and request exactly that with the low role.
- Move from object → action: can I *approve*, *export*, *share*, *invite*, *reset* beyond my role?
- Business logic: quantity, price, quota, step order, replay, race.

---

## §W — WHITEBOX (source, binary, repo, APK)

**You may assume:** the code is the map. Runtime only confirms. Do NOT read the repo top-to-bottom.

### W1. Find the sinks, not the files
```
# dangerous sinks first — these are your candidate entry points
grep -rnE '(exec|system|popen|subprocess|shell_exec|Runtime\.getRuntime|child_process)' .
grep -rnE '(eval|Function\(|setTimeout\("|innerHTML|document\.write|dangerouslySetInnerHTML)' .
grep -rnE '(query\(|execute\(|rawQuery|find\(|\$where|sequelize\.query)' .
grep -rnE '(include|require|readFile|sendFile|resolve\(|join\()' .
grep -rnE '(deserialize|pickle|yaml\.load|unserialize|ObjectInputStream|readObject)' .
grep -rnE '(redirect\(|Location\(|next=|returnUrl|redirect_uri)' .
grep -rnE '(http\.get|requests\.get|fetch\(|axios|urllib|RestTemplate)' .   # SSRF candidates
```
Then **trace each sink backwards to a route** and note the auth/role guard (or its absence).

### W2. Build the route → guard → sink table
| Route | Method | Auth guard | Role guard | Input | Reaches | Notes |
|---|---|---|---|---|---|---|
Anyone can generate this from a framework's route file plus one pass of `grep`. This single table
is the highest-value whitebox artifact: it tells you exactly where the gaps are.

### W3. Read for *authorization*, not for bugs
The productive whitebox question is never "is there a bug here" — it is:
- Which routes have an authentication guard but **no object-level ownership check**?
- Which routes trust a client-supplied `tenant`/`org`/`owner` field?
- Which internal/admin routes are registered but not in the UI?
- Which deserializer/serializer allows type confusion?
- Which secret is committed and where does it grant access?

### W4. Confirm at runtime
For each code-level gap: build the *exact* request the code expects (watch required headers,
content-type, body shape — the framework's serializer is the spec), send it, and prove impact.
A code gap with no runtime proof is a **lead**, not a finding.

### W5. When whitebox stalls
- Look at the CI/deploy config: `.github/workflows`, Dockerfile, IaC → env vars, secrets, ports.
- Look at tests — they document intended authorization behaviour and the edge cases devs skipped.
- Look at migrations — new columns/tables often shipped before their permission model.
- Look at the mobile app (`.apk`/`.ipa`): different routes, different auth, often older and weaker.

---

## §C — Combined (creds + code) and the hand-off rules

1. GRAYBOX first to find the *live* gap. WHITEBOX second to explain *why* it exists and to find
   the **siblings** (the same missing guard on other routes) — siblings are new reports, and they
   are usually the highest-value ones.
2. If blackbox only: get in (signup, SSO, invite) — blackbox without an account is capped at
   unauth surfaces, which are the most heavily tested.
3. Hand-off between agents/modes must carry: slug, mode, credentials location, surface.md path,
   leads.jsonl path, and the exact next hypothesis. Never hand off "have a look around".
