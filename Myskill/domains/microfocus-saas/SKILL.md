---
name: microfocus-saas
description: Recon notes, scope, attack surface, verified session mechanics, tested history, closed-report intel and open leads for the MicroFocus / OpenText SaaS bug bounty program (lreorg9994.stg.saas.microfocus.com LoadTest PCX and net-auto.systemteam-nom.com Network Automation) — use when hunting this target, resuming the engagement, or when a conversation mentions MicroFocus, OpenText, LoadTest/PCX, Performance Engineering, Network Automation, lreorg9994, or systemteam-nom.
---

# MicroFocus / OpenText SaaS — LoadTest PCX + Network Automation

**Program:** private bug bounty. Two in-scope web applications.
**Engagement started:** 2026-11-18. **Mode:** GRAYBOX (two roles per app provided).

## Scope

| In-scope asset | Notes | Status |
|---|---|---|
| `https://lreorg9994.stg.saas.microfocus.com/Loadtest/pcx/login?tenant=b639df63-9f8e-4e7c-99d4-0ca507d7bb84` | LoadTest PCX, Angular SPA + .NET/ASMX backend, tenant GUID in URL | live, session works |
| `https://net-auto.systemteam-nom.com` | OpenText Network Automation 26.4, JSP/JSESSIONID | live, view021 works |

**Out of scope:** every other domain/subdomain — explicitly stated by the program.

**Bounty:** Low $50 · Medium $300 · High $800 · Critical $1,300.

**Duplicate ratio (program rule):** 1st report 100% · 2nd 100% · 3rd 75% · 4th 50% · 5th 25% ·
6th+ 0%. Consequence: do **not** spend early slots on textbook singletons; hunt the variant.

### Qualifying classes
SQLi · XSS · RCE · IDOR · horizontal/vertical privesc · auth bypass & broken auth · business
logic with real impact · LFI/RFI/XXE/SSRF/XSPA · CORS with real impact · CSRF with real impact ·
open redirect · exposed secrets/credentials on an in-scope asset.

### Non-qualifying (do not report, chain only)
broken link/social hijack · tabnabbing · missing cookie flags · content/text injection ·
clickjacking · DoS · CVEs <30 days · CVE without PoC · open port without exploitable PoC ·
social engineering · autocomplete · outdated-browser bugs · **self-XSS or XSS that cannot impact
another user** · any hypothetical flaw without PoC · SSL/TLS issues · unexploitable through
headers · MITM/physical-access scenarios · missing headers without exploitable PoC · low-sev CSRF
(unauth/logout/login/cart) · SPF/DKIM/DMARC · **session management issues** (no expiry, no logout
on password change, concurrent sessions) · **info disclosure without exploitable PoC** (stack
traces, path disclosure, directory listings, versions, IP disclosure, 3rd-party secrets, EXIF,
origin IP) · CSV injection · malicious file upload (EICAR/.EXE) · HSTS · subdomain takeover
without PoC · **blind SSRF without exploitable PoC** (DNS/HTTP pingback) · rate-limit/brute-force/
captcha · **user enumeration** (email/alias/GUID/CMS endpoints) · weak password policy · user
spam · **disclosed public API keys** · password-reset token in Referer to analytics · stolen
secrets from a third-party asset · secrets not applicable to scope · pre-account-takeover via
OAuth · **GraphQL introspection enabled**.

### Closed-report intel (seen on the program, 2026-11-06 → 11-09)
11 closed reports, and the distribution is the strategy:

| Class | Count | Hunters |
|---|---|---|
| Improper Access Control – Generic (CWE-284) | 7 | morsec0x, b0oda |
| IDOR (CWE-639) | 1 | morsec0x |
| Code Injection (CWE-94) | 1 | morsec0x |
| Business Logic Errors (CWE-840) | 2 | b0oda |

**Reading:** access control is the proven-valid class here (8 of 11). It also means BAC
singletons are saturated — a plain missing-authz read may pay 25–50%. The Code Injection report
proves the backend accepts input that reaches code — look for the *server-side* sink, not another
reflected param. Class to prioritise: **cross-tenant BAC on a legacy/undocumented route** and
**second-order injection through a stored field**, not another plain IDOR.

## Credentials (program-provided, role pairs)

`/root/state/recon/microfocus/creds/` — chmod 600, never commit, never paste into a report.

**PCX — LoadTest** (`/loadtest/PCX/`), two levels *Performance Tester* / *Viewer*:
- `test021` / `gUc4NKIr?@pf!oi3` → **works** (session in `creds/pcx-test021.cookies`)
- `view021` / `nWv02l5ekYy%esp4` → viewer role

**Network Automation** (`https://net-auto.systemteam-nom.com`):
- `test021` / `@pG_vLZVf#-n9` → **rejected: "invalid or account is disabled"** (2026-11-18)
- `view021` / `jn1-+N_3*pcWU` → **works**, lands on `/index.jsp` (session in `creds/na-view021.cookies`)

Only one role per app is actually usable → for PCX the second account is `view021`; for Network
Automation the tester account is dead and **must be re-requested** (viewer-only caps most IDOR
tests, but still allows read-side BAC testing).

## Verified session & request mechanics (tested, not assumed)

### PCX (`lreorg9994.stg.saas.microfocus.com`)

Layered SSO cookies: `LWSSO_COOKIE_KEY`, `ASP.NET_SessionId`, `PcWeb-Login`, `Login`,
`User_Reports`. The REST API `rest-pcweb` honors the **`PcWeb-Login`/`Login` pair**, not `LWSSO`.

`X-Xsrf-Header: <token>` — **observed behaviour differs per route; test it, do not assume**:

| Route | With session | No cookie | Notes |
|---|---|---|---|
| `POST /loadtest/rest-pcweb/runs/collate?id=N` | `204` empty | `401` `Failed to retrieve data. Authentication is needed` | success = 204 empty body |
| same, **without** `X-Xsrf-Header` | `204` | — | token accepted as **decorative** on this route |
| same, **bogus** `X-Xsrf-Header` | `204` | — | confirms decorative |
| `GET` on the same route | — | `500` `<Exception><ErrorCode>1001` | wrong verb → 500 |
| `POST` with `id` 50–55 | `204` | — | id 56+ → `500 ErrorCode 5000` |

**Authorization oracle (use this everywhere on this stack):**
- `{"Message":"An internal server error occurred."}` (500) → routing/serialization/DI died
  **before** business logic. The request *shape* is wrong. **Not a finding.**
- `<CommonApiException><ExceptionMessage>Operation failed.</ExceptionMessage><ErrorCode>5000</ErrorCode>`
  → the handler ran and rejected the object. **This is an authorization decision — dig here.**
- `<Exception><ErrorCode>1001</ErrorCode>` → wrong verb/shape, not authz.
- `204` + empty body → success with no payload. Establish this baseline before judging a probe.

Tenant GUID `b639df63-9f8e-4e7c-99d4-0ca507d7bb84` appears in the login URL and in the app's
Referer. **Tenant swap is the primary BAC hypothesis** (see leads).

### Network Automation (`net-auto.systemteam-nom.com`)

- `POST /login.jsp` form fields: `LoginForm=LoginForm`, `j_username`, `j_password`.
  Success → `302 /index.jsp` (62 KB). Failure → `200` with `invalid or account is disabled.`
- Cookies: `JSESSIONID`, `NMSOBTURATE` (note: `NMSOBTURATE` is a **base32-ish opaque token**,
  `path=/; secure; HttpOnly; SameSite=Strict` — a candidate forgery/enumeration target).
- Version banner `Network Automation 26.4` on the login page.
- `/robots.txt` exists (26 B). Everything else probed (`/login`, `/api/login`, `/nmc/`, `/admin/`,
  `/portal/`, `/nmc/`) → `404 183 B` (custom 404 page).
- Some routes return `500` rather than `404` — treat 500-vs-404 as a route-existence oracle.

## Attack surface map (recon 2026-11-18)

### PCX — client bundle graph (fully enumerated)
Frontend is Angular micro-frontend, `main.6b784bfb0b4ab583.js` → lazy module
`/Loadtest/Run-Dashboard/remoteEntry.js` → **386 chunk files** (all fetched,
`state/recon/microfocus/surface/pcx-chunks/`). Chunk→module map in `surface/pcx-chunks.txt`.
Extracted handler routes (the high-value ones):

```
/loadtest/rest-pcweb/runs/collate                (POST, id in query AND body)
/loadtest/Services/OnlineGraphsService.asmx/{GetRunId,GetRunStatus,GetOnlineSummaryData,
     GetOnlineGroupsData,GetSettingsForOnline,IsRunOffline,GetRunTransactionsData,
     GetAggregatedRunMessagesData,GetRunMessagesData,GetRunMessagesTotalCount,
     ClearOutputMessages,ChangeVusersState,GetOnlineScriptId,SetRunDashboardFilter,
     GetRunDashboardFilter,OnlineRunStopNow,HasRunTestPermission,KillOldPresenters}
/loadtest/Services/TestService.asmx/{CheckTestPermissions,LoadTestDataPcx}
/loadtest/Services/RunsService.asmx/{GetHTMLResults,GetNVReport,StopOperation,RecoverResults}
/loadtest/Services/DashboardService.asmx/{SetSelectedRun,OpenRunDashboard,GetHelpUrl,GetSummaryData}
/loadtest/Services/NotificationsService.asmx/SetPcSystemLocale
/loadtest/SLA/{CalculateSLA,SLAReport}.aspx?runId=
/loadtest/PCWeb/Dialogs/DownloadResult.aspx?resultID=
/loadtest/Online/Dashboard/Dialogs/VuserActivityLog.aspx?RunID=
/loadtest/PcWeb/Attachments/{AttachmentsPage,AddUrlAttachment}.aspx?testID=
/loadtest/ManageLoadTest/NetworkVirtualizationSettings.aspx?testID=
/loadtest/Scripts/UploadScripts.aspx?LoginClient=iPC&folderId=
/loadtest/PCWEB/Default.aspx?fileUpload=Yes
/loadtest/Online/Dashboard/Dialogs/{GroupDialogs/EditGroupDialog,SchedulerDialog/Scheduler,
     LoadGeneratorsDialog}.aspx?runID=&testID=&GroupName=
/loadtest/RuntimeOperations/RunStart.aspx?FromPc=true&qcRunID=&pcRunID=
/loadtest/HTML/EditScriptParameters/templates
/loadtest/Files/
/rest-pcweb            (base path seen in bundle)
/loadtest/Run-Dashboard/rest/v2/{Dashboard,OnlineGraphs,RoadMessages,RunMessages}/*
     Authentication/TempAuthenticate, Dashboard/{CreateMergeGraph,DeleteGraph,
     EditMergeGraph,DuplicateGraph,RenameGraph,ReOrderGraphs,UpdateGraphsSettings,
     UpdateMeasurements,UpdateTimeDisplay,PersistTimerangeSettings,SetSelectedGraph,
     GetDashboardLayout,AddGroupsToMergeGraph,DeleteGroupsFromMergeGraph,
     ToggleAnomalySleeve}, OnlineGraphs/{GetData,GetMeasurementsGroupDetails}
../SAML/RedirectToSSO.aspx?<param>   ../SAML/RedirectToSLO.aspx?tenant=
```

Notable: **`UploadScripts.aspx` + `HTML/EditScriptParameters/templates` + `Code Injection` was
already reported** → script/template editing is a real, accepted class on this product.
`DownloadResult.aspx?resultID=` and `VuserActivityLog.aspx?RunID=` are textbook IDOR shapes.

### Network Automation
Unfamiliar JSP app; surface not yet enumerated. `/lib/bower_components/` static tree is
reachable and version-datable (bower = old OpenText/MicroFocus build). Next: enumerate
`/lib/bower_components/` + JS, then `/rest/`, `/api/`, `/nmc/` families.


## Pass 3 — endpoint sweep results (2026-11-18)

### net-auto: 22-route sweep (session working; see harness note)
| Route | Outcome |
|---|---|
| `/index.jsp` | 200 62 KB authenticated |
| `device.adhocquery.enter.do` | 200 **220 KB** — device search, internal IPs `10.2.1.1`, `10.2.1.100`, `10.0.129.200` |
| `devicelist.query.execute.do?deviceGroupID=1` / `=2` | 17 / 7 devices: `R2 192.168.1.3`, `R3 192.168.1.4`, `R4 192.168.1.5`, `10.99.99.99` (Cisco 7206VXR etc.) |
| `query.execute.do?filterType=User` | 200 91 KB — **147 users with email**. **User enumeration = non-qualifying on this program.** |
| `query.execute.do?filterType={UserGroup,Task,Policy,Acl,Configuration}` | Error Page — **correctly gated** |
| `query.execute.do?filterType={Session,Event,Diagnostic}` | 200 — allowed |
| `/user.groups.htm` | 200 63 KB, 6 groups + role matrix, actions are `<acronym class="LinkDisabled" title="You do not have permission…">` |
| `/partition.list.do` `/roles.htm` `/login.user.list.htm` `/service.management.htm` `/gateway.list.do` `/customdata.do` `/saml.spmetadata.do` | Error Page — gated |
| `/drivers.htm` | 200 442 KB driver catalog (not sensitive) |
| `/permission.summary.htm?userID=1151` | 200 — **1151 is our own id**; other ids Error Page ⇒ correctly scoped |

**`query.execute.do` is the authorization boundary on this product**: `filterType` is the object
selector and it correctly gates 5 of 8 object types. This is the single most useful fact for any
future net-auto pass.

### PCX: the real REST API (mined from chunk `5033.*.js`) — use this, not the aspx dialog
`baseApiUrl = /loadtest/rest-pcweb` · `baseLoadtestXApiUrl = /loadtest/platform/rest/v1`

```
POST /test/addUrlAttachment     -> 204 empty = accepted
GET  /test/getAttachments?id=   -> 401 ErrorCode 2009 "User unauthorized. Please check your permissions."
POST /test/updateAttachment   POST /test/deleteAttachments
GET  /test/getVersions?id=    GET  /test/DownloadAttachmentFile?attachmentId=&entityId=
/Trend/* (20+ ops), /designLoadtest/*, /runs/analyze, /test/bulkDelete/,
/test/bulkcheckin, /monitors/BulkDelete*, /onlineDashboard/*, /initRun/*
```

#### URL-fetch allowlist oracle (reproducible, both on REST and on `AddUrlAttachment.aspx?testID=55`)
| URL | Code | Meaning |
|---|---|---|
| `http://example.com/` | 204 | accepted |
| `http://127.0.0.1/` | **403** | blocked |
| `http://[::1]/` `http://10.0.0.1:8080/` `http://169.254.169.254/…` `gopher://127.0.0.1:6379/_INFO` | **403** | blocked |
| **`http://example.com@127.0.0.1/`** | **204** | **BYPASS — userinfo defeats the blocklist** |
| **`file:///etc/passwd`** | **204** | **BYPASS — non-HTTP scheme not filtered** |
| `http://metadata.google.internal/` | 204 | (not AWS metadata) |

**Status: LEAD, not a finding.** It is blind: `getAttachments` refuses even our own entity with
`2009 User unauthorized`, so the fetched body cannot be read back. Program explicitly excludes
blind SSRF without exploitable PoC, and local-file read needs a demonstrated read. Escalation
requires a route that returns the fetched content (try `getVersions`, `DownloadAttachmentFile`,
a report/export renderer) or a proven state change caused by the internal request.

### ASMX — structurally dead (closed, do not retry)
All 5 `*.asmx?WSDL` return `Method <Svc>.<firstMethod> can not be reflected`; **every** invocation
returns that same first-method fault regardless of `SOAPAction` (server-side contract break:
`Dictionary`, `IRun`, `IList` serialization). Leaked namespaces `HP.PC.Web.Model.Api.IRun`,
`LT.LTOM.Model.DockerHost`, `HP.PC.Online.PresentationModel.Model.*` are descriptive-error
disclosure ⇒ non-qualifying.

### Directory brute force — closed
`/loadtest/{Downloads,Certificates,Templates,Users,UserControls,Platform,General}/*` = uniform
`403 118 B` for every guess (blanket deny, not an index). `/loadtest/Files/` flips 500/403 but the
500 is the generic `customErrors` page with no stack trace.

### Harness bugs found and fixed (important)
1. **Never `tr '\n' ';'` a Netscape cookie jar** — it breaks the 7-field format and every request
   silently serves the login page, making healthy endpoints look 200-but-empty. Use `-b <jar>`.
2. **200 + smaller body can mean "accepted and cleared"** — diff the response body against the form;
   a 204/200 with the fields emptied is a success signal.
3. **Chunk-mined REST constants > URL guessing.** `rest-pcweb/test/addUrlAttachment` came from one
   grep of `5033.*.js`; the aspx dialog had been the wrong surface for three passes.


## Pass 4 — payload work, case by case (2026-11-18)

### Stored XSS: sink CONFIRMED, write primitive NOT available
`device.view.do?deviceID=1001` renders hostname **unescaped inside an anchor**:
`<a href="device.view.do?deviceID=1001" class="LinkRegular">zqxSIX7f3a<img src=x onerror="..."></a>`
while the same value in `<title>` **is** escaped (`&lt;img src&#x3d;x`). List views
(`devicelist.query.execute.do`, `query.execute.do?filterType=Device`) escape it too (raw=0,
escaped=2). So the defect is **per-sink inconsistent output encoding**, detail-view only.
Every marked row is a `zqx…` artifact from a previous session; `device.edit.do` renders only the
15 nav inputs for a viewer (no hostname field) and a forged POST did not change the record.
⇒ **Lead for a tester/admin account; not reportable from viewer.**

### Global pre-DB character filter (closes SQLi AND XSS)
A single quote on **any param of any route** → distinct 500
(`NA server has encountered an abnormal condition` + UUID, 2790 B). Proven with a param the page
ignores (`/index.jsp?x='`), on `favorites.htm?x='`, and on `POST /login.jsp j_username=view021'`
(no session needed). Backslash, `;`, `(`, `AND 1=1`, `AND 1=2`, numeric coercion, long strings all
behave normally. `<script>` → ABNORMAL; `"` and `>` → 200. **Character-specific global blocklist,
not SQLi.** Zero reflection across 22 routes × 8 params.

### Every POST kills the session (blocks all write testing headless)
Any POST returns the 2292-byte "You've successfully signed out" page — reproduced on
`left_navi.jsp` (the app's own call), `task.snapshot.save.do`, with correct `Origin`/`Referer`/
content-type and the `nmsObturate` token. **`NMSOBTURATE` rotates on every login**, so it cannot be
replayed. ⇒ mass assignment, task creation, device edit and import **require a real browser**;
do not burn another curl pass on them.

### Authz verdicts (viewer)
Allowed: `Device Event Session Diagnostic Interface`. **Denied: `UserGroup Task Policy Acl
Configuration Vlan Mac`** — correct. `User` → 147 users (enumeration ⇒ non-qualifying).
`changeplan.list.view.do` → 36 **stock vendor templates** (`Cisco IOS Initial Setup`,
`ios_generic_reboot`, `[Shared]`) = product defaults, not customer data.
`diagnostic` results contain only our own devices.

### Device IDs are dense and enumerable
Group 1: `211 221 231 241 321 501 511 801 821 831 841 851 891 941 951 1001 1011`
Group 2: `1001 1011 211 221 231 241 501 941` · templates outside inventory: `871 881 901`.
`device.view.do?deviceID=N` is the per-object entry point — a 1..1100 sweep found no foreign devices,
which is itself evidence the object-level check works.

### PCX session unrecoverable headless
Cookie alone → 401; `POST /login/LoginToProject` → 401; `/authentication-point/*` → 404. Auth is
LWSSO-layer behind an SSO redirect. **Needs a fresh session string from the operator.**


## Pass 5 — full GET surface + payload matrix (2026-11-18)

### CORRECTION: the running-config is real
`device.config.detail.htm?deviceID=211&meuseful` returns the full `show running-config` as **125
numbered `<tt id="t_N">` rows** (I had mis-read an earlier save). Contents: `version 15.2`,
`hostname R2`, `enable secret 5 xxx`, `username admin privilege 15 password xxx`,
`aaa new-model`, `ip domain name aws.net`, `interface FastEthernet0/0 ip address 192.168.1.3`,
`ip route 0.0.0.0 0.0.0.0 192.168.1.1`, `snmp-server community xxx` ×2, `snmp-server location
BTP-AWS`, `line vty 0 4 / password xxx / transport input telnet ssh`.
**All secrets are the literal placeholder `xxx`** — scrubbed lab device, and "View Config" is
offered to viewers in the UI. ⇒ inventory/demo data, **not** a credential leak.
Only device **211** has a body; 221/231 show only `hostname R3`/`R4`.

### ONE unescaped stored-XSS sink (corrected — raw-byte measurement)
| Renderer | raw `<img` | escaped | verdict |
|---|---|---|---|
| **`device.view.do?deviceID=N`** (Hostname anchor) | **1** | 4 (title) | **UNESCAPED** |
| `devicelist.query.execute.do` | 0 | 3 | escaped |
| `query.execute.do?filterType=Device` | 0 | 3 | escaped |
| `recenttask.query.execute.do` | **0** | **4** | **escaped** |
⚠ `recenttask` was a **false alarm**: I had run `html.unescape()` before checking, which manufactured
a raw sink. **Always count `<img` in the response bytes before any unescape.** Only `device.view.do`
is unescaped, and it is genuinely so (`<a …>zqxSIX7f3a<img src=x onerror="…"></a>` while `<title>`
escapes the same value). Write primitive unavailable at viewer level ⇒ lead, not finding.

### Task surfaces are correctly scoped
`recenttask` = 146 tasks, all `Scheduled By: infra_q9p31` (system account). Task IDs **rotate
between passes** (90001 → 88921), so not enumerable. `task.view.htm?taskID=N`: real ids → 66 KB
"Task Information"; `1/2/80000/99999/100000` → 55.8 KB empty shell. Object check works.
`task.result.do?taskID=N&owningUser=M` → 302 to `task.view.htm`; mutating `owningUser` (1/2/0/1151)
changes nothing.

### Denied / empty for a viewer (do not retry)
`/admin.do` + `?page=*` · `config_policy.{compliance_report,test,util}.htm` ·
`config_policy.event.list.htm` · `device.status.report.htm` · `network.status.report.htm` ·
`best.practices.report.htm` · `policy.list.view.do` · `device.config.editor.do?state=*` ·
`device.activate.do?operation=*`. `statistics.dashboard.htm` / `single_view.htm` render but contain
only our own devices.

### CSV export — the one bulk path left
`search_results.csv` → `200 text/plain "Error: No query results found."` Needs a server-side result
set created by a POST (session-killing). Implementation in `scripts/na-csp-handlers.js`
(`viewAsCsv()` → `search_results.csv?historyNoAdd=true&filterID=<data-filter-id>`).
**Requires a browser session.**

### Device sub-resource endpoint map (all GET, all resolve for a viewer)
```
device.view.do?deviceID=N                            device.view.do?tab=device.view.{configs,relationship,
device.config.detail.htm?deviceID=N&meuseful              specifics,search}.htm&deviceID=N
device.acl.view.do?queryName=Acl&deviceID=N          device.devicetasks.view.do?queryName=DeviceTasks&deviceID=N
device.interface.view.do?queryName=DeviceInterfaces&deviceID=N
device.ipaddress.view.do?queryName=IpAddress&deviceID=N
device.macaddress.view.do?queryName=MacAddress&deviceID=N
device.module.view.do?queryName=DeviceModule&sortBy=Slot&deviceID=N
device.policies.view.do?queryName=DevicePolicies&deviceID=N&deviceFamily=Cisco+IOS
device.vlan.view.do?queryName=Vlan&deviceID=N
diagnostics.list.htm?deviceID=N&showall        network.diagagent.view.do?deviceID=N
single_view.htm?filterName=SingleView[Device]&deviceID=N
pendingtask|runningtask|recenttask|templatetask.query.execute.do?pageTitle=...
script.query.execute.do?filterName=RN_TC_Diagnostics
task.view.htm?taskID=N        task.result.do?taskID=N&owningUser=M
enhanced.vlan.edit.do?isEdit=false&deviceID=N   partition.list.do?deviceViewID=N
```


## Pass 6 — server-side surfaces (2026-11-18)

### `/soap/` — unauthenticated NAS SOAP API (new surface)
`GET /soap/` → `200 47 "NAS SOAP API: Only handles HTTP POST requests."` Any subpath
(`/soap/wsdl`, `/soap/nas`, `/soap/NAS-2.0`) returns the same string.
`POST /soap/` with `<soap:Envelope><soap:Body/></soap:Envelope>` → `200 0`; with any child element
→ `200 632` SOAP fault:
`Error building response: NAMESPACE_ERR …` (shape-invariant across 14 tried operation names —
the correct namespace belongs to the NAS desktop client, not the web app).
**Auth: none.** Identical responses authenticated vs not.

**XXE: CLOSED, decisively.** Any `<!DOCTYPE …>` (empty DTD, entity, parameter-entity OOB, entity
as text node / element name) → `529 "Unable to create envelope from given source:"`, i.e. the DTD is
rejected **before** entity expansion. 200 KB junk body → 529, no crash. Do not retry.
⇒ surface, not a finding. Escalation needs the `vugen`/NAS client SOAP namespace (whitebox task).

### `/FrontEnd` — paramui WebSocket backend
`401 34 "401 - Cookie is invalid or missing"` (GET/OPTIONS), `411` (POST). This is the endpoint the
`/loadtest/HTML/EditScriptParameters/templates/` Vue app opens via
`new WebSocket('wss://'+host+':'+port+'/FrontEnd')`. All 4 PCX cookies (individually and combined)
plus 5 guessed cookie names → **all 401**. The cookie is issued by the LoadRunner agent, not the web
tier. No other WS path exists (`/ws`, `/socket`, `/websocket`, `/vugen` → 404). Needs an agent session.

### Open redirect / CRLF — none
No endpoint redirects (`200`, no `Location:`) among `login.jsp`, `index.jsp`, `logout.jsp`,
`task.result.do`, `device.view.do`, `admin.do`, `left_navi.jsp`. CRLF payloads
(`%0d%0aSet-Cookie:`, `%0d%0aX-Injected:`) injected **0** headers.
SAML `RedirectToSSO.aspx` / `RedirectToSLO.aspx` → `500 "Error: The provided tenant id, x, is not
valid."` — a tenant validator, not a redirector.

### LFI / traversal — closed (three distinct 404 handlers, all correct)
| Path | Response |
|---|---|
| `/WEB-INF/`, `/META-INF/` | **404 74 b** `<title>Error</title> 404 - Not …` (protected-path handler) |
| `/lib/`, `/scripts/`, `/style/`, `/na-dojo/`, `/images/`, `/includes/` | **403 2508** (directory deny) |
| `/js/`, `/css/`, `/pages/`, `/servlet/`, `/api/`, `/rest/` | 404 183 b (app page) |
| `/localizer.jsp?file=../../../etc/passwd` | 500 ABNORMAL (character filter) |
No file read. The 74-byte handler is a container deny, not an exposure.

### `localizer.jsp` — static, not parameterised
`200 29523 text/javascript` of `_msg['js/…']` strings. **16 param names fuzzed** (`lang`, `locale`,
`language`, `file`, `bundle`, `module`, `path`, `key`, `name`, `id`, `type`, `res`, …) → output
md5 **unchanged for every one**. No traversal/SSRF/injection possible.

### Java appserver admin paths — all 404
`/actuator`, `/actuator/env`, `/actuator/health`, `/actuator/heapdump`, `/jolokia`, `/jmx-console`,
`/web-console`, `/invoker/JMXInvokerServlet`, `/h2-console`, `/manager/html`, `/struts/`, `/ws/`,
`/api/v1`, `/v1`, `/xmlrpc`, `/wsdl` → 404 183.

### Forms that render but expose nothing at viewer level
`task.import.add.do` (Import Devices), `task.importresourceids.add.do`, `task.load.do`,
`task.multi.add.do`, `saml.spmetadata.do`, `diagramming.view.do` (115 KB), `nai.view.do`,
`task.importuser.add.do` — all contain **only the 16 nav inputs**. The real upload/import form is not
rendered for a viewer ⇒ **XXE-via-upload and CSV-import cannot be tested from this role.**

## Tested history

| Date | Endpoint | Test | Result |
|---|---|---|---|
| 11-18 | `POST /loadtest/rest-pcweb/runs/collate?id=N` | session, verb, xsrf presence/bogus, tenant blank/foreign/body, id sweep 40–60 | **clean** — auth required (401 no cookie); xsrf decorative but harmless (no state change reachable unauth); ids 50–55 → 204, 56+ → 500; no data returned in any case |
| 11-18 | `/loadtest/SLA/SLAReport.aspx?runId=N` | auth vs noauth, id sweep 1/55/56/500/999999 | **clean and correctly scoped** — noauth 302→login; only own run (55) renders data (`zqxMX-t013-test-7f3a91`), foreign ids render an empty report. Correctly authorized. |
| 11-18 | `/loadtest/Services/*.asmx/*` | GET, POST JSON, POST form | 500 empty / 302 ErrorPage — needs correct SOAP/`__VIEWSTATE` shape or is disabled; do not conclude "vulnerable" from a 500 |
| 11-18 | `/loadtest/PCWeb/Dialogs/DownloadResult.aspx?resultID=1` | GET | `404 0` — path variant may be `/PCWeb/` vs `/PcWeb/`; retry both cases |
| 11-18 | `/loadtest/Online/Dashboard/Dialogs/VuserActivityLog.aspx?RunID=1` | GET | `404 0` — retry under `/loadtest/online/` (bundle uses lowercase in some routes) |
| 11-18 | `/loadtest/rest-pcweb/*` roots (`/runs`, `/users`, `/projects`, `/session`, `/config`, `/`) | GET | `404 0` — only `/runs/collate` is registered |
| 11-18 | net-auto `/login`, `/api/login`, `/rest/login`, `/nmc/`, `/admin/`, `/portal/`, `/login.action` | GET | `404 183 B` custom page |
| 11-18 | net-auto `POST /login.jsp` with `test021` | login | **rejected — account disabled**; `view021` works |

## Open leads (ranked, next pass)

1. **PCX tenant isolation (highest value, matches the proven class).** Tenant GUID appears in the
   URL and Referer. Hypothesis: a REST/ASMX route resolves the tenant from the *session* while a
   second route resolves it from the *request*, so one leaks into the other. Test: authenticate as
   `test021` (tenant `b639df63-…`) and replay every `rest-pcweb` and `Run-Dashboard/rest/v2`
   route with (a) a foreign tenant GUID in the query, (b) a foreign tenant in the body, (c) a
   foreign tenant in `Referer`/`Origin`. Because BAC is 8/11 of the closed reports, a *different*
   BAC primitive (tenant-scoped rather than object-scoped) is the non-duplicate play.
2. **`UploadScripts.aspx?folderId=` + `HTML/EditScriptParameters/templates`.** Code Injection is
   already an accepted class here. Hypothesis: `folderId` reaches a path or a command; the
   template editor accepts a server-side script parameter file. Test traversal in `folderId`, and
   whether a saved script parameter file is executed by `RunStart`.
3. **`DownloadResult.aspx?resultID=` / `VuserActivityLog.aspx?RunID=`.** Both returned 404 on the
   bundle's literal case; retry case variants and `/PcWeb/`↔`/PCWeb/`, `/Online/`↔`/online/`
   since other routes in the same bundle differ in case (the app is case-sensitive in routing,
   which itself is worth one pass).
4. **`NMSOBTURATE` cookie (net-auto).** Opaque, `SameSite=Strict`, set pre-auth on the login page.
   Determine whether it is the real session carrier, whether it is predictable/enumerable, and
   whether the app honors it without `JSESSIONID`. If it is a bearer-like token in a cookie, that
   is a forgery-class lead.
5. **`SAML/RedirectToSSO.aspx?<param>`** — the bundle builds the query from a token map
   (`${xe.$3}`, `${this.PUBLIC_TOKEN}`) and there is also `RedirectToSLO.aspx?tenant=`. SSO param
   injection / open redirect / tenant-confusion. Open redirect is in-scope for this program
   (unlike most), so even a redirect is reportable *if* the program accepts it as open-redirect
   proper — verify against the qualifying list.
6. **`GetNVReport` / `GetHTMLResults` (`RunsService.asmx`)** — report generation from a run id.
   Report/export endpoints are the classic second-order sink. If `GetHTMLResults` renders stored
   run content, test stored XSS at the *stored field* (test name, run name — we already observed
   a stored `Test Name`/`Run Name` rendered into `SLAReport`).

## Environment notes

- `state/recon/microfocus/surface/pcx-chunks/` — 385 chunk files, 26 MB. Reusable; do not refetch.
- Both hosts are behind AWS ALB (`AWSALB*` cookies). Rate-limit politely; no burst scanning.
- Executed recon strictly against the two in-scope hosts only.
