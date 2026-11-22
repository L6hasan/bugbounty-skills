# Sandbox Escape Variants — Part 2 (V-09 … V-15)

Deep playbook sections for variants 9-15. Same discipline as part 1:
fingerprint with benign probes, match versions to public advisories,
reproduce public PoCs only in your own lab against version-matched clones,
and check **False positives** before writing anything up.

## Table of contents

- [V-09: Lua sandbox evasion via bytecode manipulation and arbitrary memory writes](#v-09-lua-sandbox-evasion-via-bytecode-manipulation-and-arbitrary-memory-writes)
- [V-10: Kubernetes pod escape via HostPath volume mount exploitations](#v-10-kubernetes-pod-escape-via-hostpath-volume-mount-exploitations)
- [V-11: Windows sandbox escape via RPC interface exploitation and token impersonation](#v-11-windows-sandbox-escape-via-rpc-interface-exploitation-and-token-impersonation)
- [V-12: Android app sandbox evasion via insecure content providers data leakage](#v-12-android-app-sandbox-evasion-via-insecure-content-providers-data-leakage)
- [V-13: WebAssembly linear memory escape via integer overflow sinks](#v-13-webassembly-linear-memory-escape-via-integer-overflow-sinks)
- [V-14: Serverless FaaS environment persistence via writable /tmp code hijacking](#v-14-serverless-faas-environment-persistence-via-writable-tmp-code-hijacking)
- [V-15: Virtual machine hypervisor escape via vulnerable emulated hardware driver IOCTLs](#v-15-virtual-machine-hypervisor-escape-via-vulnerable-emulated-hardware-driver-ioctls)

## V-09: Lua sandbox evasion via bytecode manipulation and arbitrary memory writes

**Mechanism:** Lua's loader trusts precompiled bytecode — the official docs
say undumps are for *trusted* files. Malformed bytecode (inconsistent
constants, prototype counts, upvalue descriptors) corrupts interpreter
internals while staying "valid enough" to pass light checks, giving
arbitrary address r/w from pure Lua — enough to overwrite a function pointer
or forge objects and escape sandboxes that removed `io`/`os`/C access but
still load attacker bytecode. The violated assumption: "an interpreter-level
sandbox (no OS libraries) contains untrusted code" while `load`,
`string.dump`, the `debug` library, or LuaJIT `ffi` remain reachable.

**Preconditions:**
- Attacker supplies Lua code *or bytecode* (game mods, config scripts, wire
  protocol, embedded automation)
- `load`/`loadstring` reachable and the loader accepts bytecode; or
  `debug`/`ffi` present (those are near-instant escape classes, report first)
- Exact Lua/LuaJIT version known (`_VERSION`, `jit.version`)

**Detect:**
1. Benign fingerprints: `print(_VERSION)` (`Lua 5.x`), and for LuaJIT
   `print(jit and jit.version)`. Version mismatch between the dumper and
   loader runtimes is itself a fingerprint (5.3 dumps fail on 5.4 — the error
   text leaks versions).
2. Surface inventory (all benign): `type(load)`, `type(string.dump)`,
   `type(debug)`, `type(ffi)`. `ffi` present = the sandbox is decorative;
   `debug` present often is too. Report what exists before digging deeper.
3. Bytecode acceptance test: `assert(load(string.dump(function() return 42
   end)))() == 42` — a `42` means untrusted bytecode is loadable (the whole
   variant's precondition confirmed); an error means the door is shut.
4. Match `_VERSION`/`jit.version` to public bytecode-corruption research and
   write-ups (prevalent for 5.1/LuaJIT eras); reproduce public PoCs only in
   **lab** on a version-matched interpreter — these crash or corrupt memory.

**Proof of concept:**
```
benign probes:
  print(_VERSION)                                     → <PLACEHOLDER_LUA_VERSION>
  print(jit and jit.version)                          → <PLACEHOLDER_LUAJIT_V>
  print(type(load), type(string.dump), type(debug), type(ffi))
  assert(load(string.dump(function() return 42 end)))()   → 42 = bytecode accepted
lab only: <PUBLIC_BYTECODE_POC> → benign proof: contents of a marker file you created
```

**Confirm:** Bytecode roundtrip returning `42` (loader trusts dumps) plus,
in lab, a public-PoC benign marker read on a version-matched interpreter.
On the live target the honest tier is: bytecode accepted + version-to-
research mapping + no OS layer beneath.

**False positives:** Attacker-supplied *source text* executing inside the
sandbox is not an escape — that's the sandbox working as designed; only
leaving the intended capability set counts. `luac` version mismatch errors
are fingerprints, not findings. Memory-corruption claims without a lab repro
on the exact version are theory — do not report them as confirmed. `ffi`
present but `ffi.cdef`/`ffi.load` restricted via `__index` metatable tricks —
test the actual denial before claiming either side.

**Impact:** Sandboxed script → arbitrary process memory r/w → RCE in the
host app (games, firmware, CDN/WAF Lua platforms, serverless Lua).
Phrase as "untrusted bytecode accepted on Lua <ver> → memory corruption
class per `<research>` → process RCE; OS layer: `<container/no>`".

**Remediation:** Never load untrusted bytecode — accept text source only,
strip `string.dump`, remove `load`, and delete `debug`/`ffi` from the
sandbox; run untrusted Lua in a separate process with OS limits.

**CWE / OWASP:** CWE-502-adjacent untrusted deserialization of bytecode
(CWE-502), CWE-125/787 (OOB read/write); OWASP A03:2021 Injection.

## V-10: Kubernetes pod escape via HostPath volume mount exploitations

**Mechanism:** `hostPath` volumes pierce pod isolation by mounting host
filesystem paths inside the container. Whoever can create or edit pods —
over-broad RBAC, a compromised CI service account, a permissive dashboard,
missing admission policy — can mount `/`, `/var/lib/kubelet`, `/etc`, or
container-socket paths and thereby read/write host files: other tenants'
secrets, pod specs, service account tokens, host cron/`rc.local`-class
persistence. The violated assumption: "Kubernetes namespaces isolate
tenants" when volumes cross the node boundary.

**Preconditions:**
- Either: ability to create/edit pods (or `podsecurity`-bypassing workloads),
  or: already running in a pod that mounts a hostPath (recon from inside)
- No PSA "restricted" enforcement / OPA-Kyverno deny for hostPath
- Node-level consequence path (writeable host path or token-readable path)

**Detect:**
1. In-pod recon (benign): `cat /proc/mounts | grep -Ev 'proc|sysfs|cgroup|
   overlay|tmpfs'`, `ls /var/lib/kubelet/pods 2>/dev/null`,
   `ls /var/run/secrets/kubernetes.io/serviceaccount`, `id`, `hostname`.
2. API-side capability (benign): `kubectl auth can-i create pods -n <NS>`,
   `kubectl auth can-i list pods --all-namespaces`,
   `kubectl get ns -o jsonpath='{.items[*].metadata.annotations.pod-security\.kubernetes\.io/enforce}'`
   — the enforce label tells you whether policy would block your PoC.
3. If pod creation is possible: send a **read-only** hostPath pod spec (see
   PoC) in lab or an authorized staging cluster; on production, capability
   evidence + any existing dangerous mount is the honest evidence tier.
4. Version check: `kubectl version` / API `/version` (benign) against kubelet
   /node advisories too — but note most HostPath findings are *misconfig*,
   not CVEs.

**Proof of concept:**
```
# benign capability proof
kubectl auth can-i create pods -n <PLACEHOLDER_NAMESPACE>          → yes/no
kubectl auth can-i list secrets --all-namespaces                   → yes/no

# lab/staging: minimal read-only hostPath pod
spec:
  volumes: [{ name: h, hostPath: { path: /, type: Directory } }]
  containers: [{ name: c, image: <PLACEHOLDER_IMAGE>,
                 volumeMounts: [{ name: h, mountPath: /host, readOnly: true }] }]
# benign in-pod proof: diff /host/etc/hostname vs ./hostname, or read a
# marker file you placed on the node — nothing else
```

**Confirm:** Two signals: RBAC/policy evidence (`can-i` result + enforce
label) *and* host-scope data (host-only file content read in lab, hostname
differential) — reproduced twice. On production, `can-i create pods` + an
already-mounted dangerous path also qualifies.

**False positives:** HostPath of `/var/log` or `/etc/hosts` for telemetry is
often intentional — report as over-broad hygiene unless it enables host
writes or token reads (scope honestly). Overlay on `/` in `/proc/mounts` is
the normal container filesystem, not the host. PSA enforcing `restricted`
blocks hostPath — check the enforce label before claiming exploitability.
Reading *pod-namespace* secrets via the mounted service account is normal
RBAC behavior, not an escape — the finding is the volume or the RBAC grant,
whichever is the actual flaw. One compromised node ≠ whole cluster — say so.

**Impact:** "Pod with `<SA>` can mount the node filesystem → node root,
cross-namespace secret read on node `<name>`, cluster-takeover path via
scheduling/token abuse." Severity: High/Critical depending on whether
cluster-admin tokens or other tenants sit behind it.

**Remediation:** Enforce PSA `restricted` (or admission-deny hostPath and
escalation verbs), scope RBAC so untrusted SAs cannot create/edit pods, and
isolate tenant workloads per node/pool.

**CWE / OWASP:** CWE-250 (Execution with Unnecessary Privileges), CWE-269
(Improper Privilege Management), CWE-284; OWASP A05:2021 Security
Misconfiguration.

## V-11: Windows sandbox escape via RPC interface exploitation and token impersonation

**Mechanism:** Windows privilege boundaries ride on access tokens. A service
holding `SeImpersonatePrivilege`/`SeAssignPrimaryTokenPrivilege` can be
coerced into authenticating to an attacker-controlled named pipe/RPC
endpoint, after which the attacker impersonates that token — the potato
class of techniques: local service → SYSTEM. Separately, exposed RPC
interfaces (DCERPC over ncacn/ALPC, printer spooler RPC, other historical
RPC services) with missing authentication have produced remote/local
privilege flaws (PrintNightmare-class, Netlogon-class). The violated
assumption: "a service running as SYSTEM won't act on my behalf."

**Preconditions:**
- A Windows foothold (web shell, deserialization — chain with
  `rce-testing`) as a user with a service privilege, *or* an
  unauthenticated RPC interface reachable
- Exact OS build known (`systeminfo`), matching a public technique/tool or
  RPC advisory for that build
- The relevant service running (spooler etc.) — check, don't assume

**Detect:**
1. Benign recon (all read-only): `whoami /priv`, `whoami /groups`,
   `hostname`, `systeminfo | findstr /B /C:"OS Name" /C:"OS Build"`,
   `sc query type= service state= all | findstr /i "spooler"`.
2. Classify: `SeImpersonatePrivilege` *enabled* → potato-class precondition
   (precondition ≠ vulnerability — see False positives). No such privilege →
   that technique class is closed; look at RPC-surface advisories instead.
3. Match the OS build against public RPC/tooling advisories — e.g. the 2021
   printer-driver RPC class (check the *patch* level, not just build name)
   — "check the build, then check the advisory."
4. Lab-only: potato-class tools and public RPC PoCs run against **your** own
   Windows VM. Against the target, production evidence stops at privileges +
   build + service state; a SYSTEM banner from your own lab is not target
   evidence.

**Proof of concept:**
```
whoami /priv | findstr /i "SeImpersonate SeAssignPrimaryToken"    # benign
systeminfo | findstr /B /C:"OS Name" /C:"OS Build"                # benign fingerprint
sc query spooler | findstr STATE                                  # service-state check
# lab only: <PUBLIC_POC_OR_TOOL_FOR_BUILD> → benign proof: `whoami` shows
# NT AUTHORITY\SYSTEM once, then stop — no persistence, no new accounts
```

**Confirm:** Privilege list + build fingerprint + service state (channel one)
and, in lab, the public technique producing a single benign `whoami`
elevation on a version-matched build (channel two). For RPC-specific CVEs,
also show the patched/unpatched differential by build/KB.

**False positives:** `SeImpersonatePrivilege` on a service account is
*normal configuration* — it is the precondition, not the bug; reports that
equate the two get rejected. TCP 135 open is default exposure, not a
vulnerability — an *abusable* interface needs missing auth on a specific
service. Technique failing on target does not prove safety elsewhere (and
do not keep pushing — destructive boundary). 32-bit vs 64-bit tooling
mismatches produce fake "non-vulnerable" results. A SYSTEM `whoami` from
*your lab VM* pasted as target evidence is fraud, not proof — label lab
results as lab.

**Impact:** Local privilege escalation to SYSTEM / service-account
takeover; RPC-class issues may be network-local or remote. Phrase as
"`<user>` + `<privilege>` → SYSTEM on build `<N>` (technique class per
`<advisory/tool>`); lab-reproduced on matching build" — with the starting
privilege stated.

**Remediation:** Strip unneeded privileges from service accounts, apply the
build's KB patch for RPC-class CVEs, firewall RPC surfaces to needed
transports only, disable unused services (e.g. spooler where not needed).

**CWE / OWASP:** CWE-269 (Improper Privilege Management), CWE-306 (Missing
Authentication for Critical Function); OWASP A01:2021 Broken Access Control.

## V-12: Android app sandbox evasion via insecure content providers data leakage

**Mechanism:** `ContentProvider`s pierce the app sandbox by design. A
provider declared `android:exported="true"` without a (signature-level)
permission — or with `grantUriPermissions`/`path-permission` gaps, or SQL
`selection` built by string concatenation — lets any installed app (or adb
shell) read or write the app's private database/files. The violated
assumption: "app-private storage stays private" once the provider boundary
is mis-gated.

**Preconditions:**
- APK obtainable (store, MDM, leaked build) for static analysis
- A provider exported (or exportable via intent filter) without an enforced
  signature permission; `normal`/`dangerous` protection-level custom
  permissions are bypassable by *any* app that requests them — the classic
  junior miss
- Device/lab access for dynamic probes (unprivileged third-party app or adb)

**Detect:**
1. Static: `apkanalyzer manifest print <PLACEHOLDER_APK>` or
   `aapt dump xmltree <PLACEHOLDER_APK> AndroidManifest.xml`; enumerate every
   `<provider>`: `android:exported`, `android:permission`,
   `readPermission`/`writePermission`, `grantUriPermissions`,
   `android:authorities`, `<path-permission>` entries.
2. Judge the permission model: missing permission, or a custom permission
   with `protectionLevel` below `signature` → bypassable. `signature` →
   likely fine (verify enforcement dynamically).
3. Dynamic, benign: `adb shell content query --uri
   content://<PLACEHOLDER_AUTHORITY>/<PLACEHOLDER_PATH> --projection <BENIGN_COL>`
   — record **row counts and column schema only**, never data rows.
4. SQL injection in `selection`: row-count differential
   `--where "1=1"` vs `--where "1=2"` — count-only evidence.
5. FileProvider paths: probe `content://<AUTHORITY>/../../...` style paths
   for traversal — benign: attempt to list a *mapped root*, don't exfiltrate.

**Proof of concept:**
```
adb shell content query --uri content://<PLACEHOLDER_AUTHORITY> \
  --projection <PLACEHOLDER_BENIGN_COLUMN> | wc -l            # count only
row-count differential: --where "1=1" vs --where "1=2"        # injection signal
# evidence = counts + column names; data rows stay redacted
```

**Confirm:** Two channels: the `1=1`/`1=2` count differential (injection) or
unpermissioned read (authz gap) *plus* a control showing the same data is
private by comparison (file read of app-private path fails from the same
context). Reproduce twice.

**False positives:** `exported="false"` provider readable only by the same
UID — not a finding. SecurityException on access = permission *enforced*
(record as protected). `FileProvider` with `readPermission` +
`grantUriPermissions` correctly scoped is the secure pattern — don't report
it for existing. adb's shell user has broader power than a normal app —
confirm from an unprivileged third-party app before claiming "any app".
Leaked provider *authority names* are metadata, not data leakage.

**Impact:** "Unprotected exported provider `<AUTHORITY>` exposes
`<DATA CLASS>` (PII/tokens/messages) to any installed app; selection
injection allows row-set control." Evidence: schema + counts, rows redacted.

**Remediation:** `android:exported="false"` unless integration requires
otherwise; enforce `signature`-level permissions (or explicit
`readPermission`/`writePermission`), parameterize selection queries, and
tighten FileProvider path grants.

**CWE / OWASP:** CWE-926 (Improper Export of Android Application
Components), CWE-89 (SQL Injection where selection is injectable), CWE-200;
OWASP MASVS / MASTG — platform interaction & data storage testing.

## V-13: WebAssembly linear memory escape via integer overflow sinks

**Mechanism:** WASM linear memory is bounds-checked *by the engine* — OOB
inside it traps and stays sandboxed. "Escaping" therefore means the buggy
layer is somewhere else: host glue (JS/Go/Rust wrappers) computing
`ptr + len` in wrapping 32-bit arithmetic and slicing `TypedArray`s out of
bounds, missing checks on `memory.copy`/`memory.fill`/`memory.init`
operands, or a historical engine validator bug. The violated assumption:
"every length the guest supplies is re-checked with overflow-safe math at
the host boundary" — the wrapper, not the guest, is usually where the
integer overflow lives.

**Preconditions:**
- Attacker influences WASM input sizes/offsets (document/image/media
  decoders compiled to WASM are the classic hosts)
- A wrapper doing manual `ptr+len` math, or an engine version with a public
  validator/runtime advisory (wasmtime/wasmer/wasm-micro-runtime publish
  GHSAs — check version)

**Detect:**
1. Fingerprint benignly: WASM present (`\0asm` module magic, `WebAssembly`
   global in JS hosts, `wasmtime --version`/`wasmer --version` on hosts
   where visible); engine + version feeds the advisory check.
2. Differential probes (benign, from the public API): invoke with
   `(ptr=0, len=<LARGE>)` — expect a clean trap ("out of bounds"); then
   `(ptr=<N>, len=2**32 - N + 1)` — the wrapping case. Record the *differential*:
   trap (correct) vs host-side exception vs silent accept (lead).
3. If source is available (open-source host glue, leaked source): grep for
   `ptr + len`, `offset + size` slicing without checked-add — a lead to
   prioritize, not a finding by itself.
4. Match engine version to GHSA/NVD; public PoCs reproduce in **lab** only.

**Proof of concept:**
```
invoke <PLACEHOLDER_FUNC>(ptr=0, len=<PLACEHOLDER_LARGE>)        →  trap (expected)
invoke <PLACEHOLDER_FUNC>(ptr=<N>, len=2**32 - N + 1)            →  observe differential:
     trap   = correct behavior (no finding)
     silent accept / host TypeError / neighboring data returned  = lead → lab
lab only: <PUBLIC_ENGINE_POC> → benign proof: marker bytes read from an
     adjacent allocation — never host-process data
```

**Confirm:** Data from a *different* object's allocation returned through
the wrapped length (proves real OOB, not a wrap-to-zero no-op), reproduced
twice; or, for engine-CVE findings: version ≤ vulnerable range + advisory +
surface reachable.

**False positives:** `i32.wrap` semantics are *defined* — wrapping is only a
bug if the wrapped value is then trusted as a length (check the code path
before claiming). Engine traps on OOB are correct behavior, not findings.
The biggest junior mistake: "WASM memory corruption" claimed from linear-
memory OOB alone — that stays inside the sandbox by design; the finding
requires the *host/validator* to be the buggy layer, and the report must say
which layer. OOM/allocation-failure ≠ OOB.

**Impact:** Host wrapper or engine bug → OOB r/w in the host process → RCE
in apps using the WASM component (document processors are pre-auth-shaped
attack surface). Phrase by layer: "integer overflow in host wrapper
(`<file:line>`) → OOB read of adjacent allocations" vs "engine CVE-<X>
class on `<engine> <ver>`".

**Remediation:** Overflow-safe bounds (checked add) on every `ptr+len`
before slicing; validate guest lengths at the boundary; upgrade the engine
per its advisory.

**CWE / OWASP:** CWE-190 (Integer Overflow), CWE-125/787 (OOB read/write);
OWASP A03:2021 Injection / A06:2021 Vulnerable and Outdated Components.

## V-14: Serverless FaaS environment persistence via writable /tmp code hijacking

**Mechanism:** FaaS platforms reuse warm execution environments across
invocations. Anything writable inside the instance — `/tmp` (Lambda,
Cloud Functions tmpfs), and worse: env-var mutations made in-process —
survives into the *next* invocation of the same instance. An attacker with
one-shot code execution (upload handler, injection sink) who can write to a
path later consulted at import/startup (Python `.pth`/`sitecustomize` on
`sys.path`, Node `require` resolution into writable dirs, modified
dependency caches) turns a transient injection into persistent, cross-
invocation code execution. The violated assumption: "each invocation is a
fresh isolate."

**Preconditions:**
- One write primitive during an invocation (even file-write-only helps)
- The platform reuses instances (Lambda does per function+account; check the
  provider's documented reuse behavior)
- A load path consulting writable dirs (`sys.path` includes `/tmp`,
  `NODE_PATH`, cwd-based imports) — *detect*, don't assume

**Detect:**
1. Persistence probe (benign, the core test): invocation A writes
   `/tmp/<MARKER>` containing a unique token + timestamp; invocation B
   (separate request, unique token) reads it back. Present across two
   requests = warm reuse confirmed.
2. Surface read (benign): Python `print(sys.path, os.getcwd())`, Node
   `console.log(require.main.paths, process.cwd(), process.env.NODE_PATH)`,
   env listing with `os.environ`/`process.env` — find what imports consult
   and whether `/tmp` or cwd is on it.
3. Warm-pool evidence: identical marker contents + timing gaps show same
   instance; require at least two successful round-trips before claiming
   reuse (the platform may interleave cold starts).
4. Hijack candidates: identify (read-only) the first import that resolves
   after `/tmp` on the path — the *lab* proof rung is a benign module that
   only prints a marker when imported.

**Proof of concept:**
```
invocation A:  write /tmp/<MARKER> = <TOKEN_A + timestamp>     # benign
invocation B:  read  /tmp/<MARKER> → <TOKEN_A>                  # persistence proof
# lab only: drop a benign module printing a marker on import into the
# first writable import path; observe the marker in a later invocation
# guardrail: delete the marker/module and disclose in the same session
```

**Confirm:** Marker round-trip across two separate invocations (channel one:
timestamps/token match) *and* — lab only — the benign import hijack printing
its marker on a subsequent invocation (channel two). Then remove everything.

**False positives:** Providers/configs with per-invocation fresh containers —
marker absent on B is a *non-finding*, report "not reproducible under this
configuration", not a vuln. Two "separate" requests landing in the same
invocation batch (unique tokens + timestamps fix this). Lambda clears
`/tmp` on cold start — flakiness is expected; one hit is a lead, two hits
are evidence. Your own test harness writing the marker locally (verify the
read comes from the server side — echo the marker's timestamp back).

**Impact:** "One-shot code execution → persistent RCE across warm
invocations of function `<NAME>` (attacker-planted module loads on later
invocations — including other users' requests hitting the same instance)."
Phrase the multi-tenant angle carefully per provider model; the persistence
alone is High.

**Remediation:** Immutable, read-only deployment packages; keep writable
dirs off every import path; destroy or recycle instances after anomalous
writes; monitor `/tmp` writes against a baseline.

**CWE / OWASP:** CWE-732 (Incorrect Permission Assignment for Critical
Resource), CWE-427 (Uncontrolled Search Path Element); OWASP A05:2021
Security Misconfiguration.

## V-15: Virtual machine hypervisor escape via vulnerable emulated hardware driver IOCTLs

**Mechanism:** Guests reach host-side emulation through device interfaces:
virtio devices (ring buffers, config space), VirtualBox guest-driver IOCTLs
(`DeviceIoControl` on `\\.\VBoxDrv`-class devices, shared folders/clipboard
providers), VMware backdoor I/O, guest-AGT channels. Bugs in the *host's*
device emulation — unchecked descriptor lengths, config-space OOB, integer
overflows in packet handling — turn a guest-side ioctl into host-process
code execution. The violated assumption: "the guest↔host device interface
is data-only" when the host parser is C/C++ code handling guest-controlled
structures.

**Preconditions:**
- Code execution inside a guest VM (malicious tenant, compromised guest,
  CTF/lab — most real bug bounty paths require you to *be* the guest, which
  means the surface is the *product's* hypervisor layer)
- An exposed emulated device with known-vulnerable version (guest additions/
  tools, VBox guest drivers, QEMU device models)
- Hypervisor/device version known (guest-side fingerprint or infra disclosure)

**Detect:**
1. Guest-side benign recon: `dmidecode -s system-manufacturer` /
   `system-product-name` (`VMware, Inc.`, `innotek GmbH`/Oracle, `QEMU`),
   `lspci | grep -i -E 'virtio|vmware|vbox'`, `ls /sys/bus/virtio/devices`,
   `VBoxControl --version 2>/dev/null`, `vmware-toolbox-cmd -v 2>/dev/null`
   — presence of guest additions/tools is itself the exposed surface.
2. Surface inventory: which channels exist? Shared folders/clipboard mounted?
   3D/virgl? USB passthrough emulation? Fewer devices = smaller attack
   surface; report what is *on*.
3. Version match: guest-reported additions/driver version, or host-side
   QEMU/VBox/VMware version from the program's disclosed infra (chain
   `info-disclosure-testing` for version banners) → check vendor advisories
   and distro backports.
4. Lab-only: public guest→host PoCs run against **your** version-matched
   hypervisor VMs. Fuzzing a production hypervisor is a DoS risk and off-
   limits (guardrail).

**Proof of concept:**
```
# guest-side benign fingerprint
dmidecode -s system-manufacturer            # → <PLACEHOLDER_HYPERVISOR>
VBoxControl --version 2>/dev/null || vmware-toolbox-cmd -v 2>/dev/null
ls /sys/bus/virtio/devices | head           # exposed emulated devices
# lab only: <PUBLIC_POC_FOR_<HYPERVISOR>_<VER>> → benign proof: host marker
# file read displayed inside the guest — then stop
```

**Confirm:** Two channels: version evidence mapping the *host* hypervisor or
guest-additions to a public advisory's affected range, plus the exposed
device surface (guest additions present/enabled). In lab: the public PoC's
benign host-marker read on a version-matched build.

**False positives:** "VM detected" ≠ escape surface — a hypervisor with no
shared/emulated channels (no additions, virtio-net only) offers almost no
guest→host surface; say what exists before claiming risk. Device present
but host patched via *distro backport* — check the changelog, not the
vanilla version string. Guest crash ≠ host compromise (a crash is a lead —
verify whether the host service actually died, and never induce crashes on
production). Shared-folder write access is a configured feature, not a vuln
(unless permissions allow writing outside the share root — that's a config
finding of its own). Nested-virt sandboxes (microVMs, Firecracker-class)
have different surfaces — don't mislabel them.

**Impact:** Guest → host RCE, i.e. cross-tenant VM compromise on shared
hypervisors. Phrase as "guest-to-host via `<device>` on `<hypervisor>
<ver>` per `<advisory>`; benign lab proof: host-marker read; tenant blast
radius: `<other guests on host>`". Severity: Critical on multi-tenant hosts.

**Remediation:** Patch the hypervisor/guest-additions per vendor advisory,
remove unused emulated devices and guest channels, disable shared
folders/clipboard where unneeded, isolate tenants per host.

**CWE / OWASP:** CWE-20 (Improper Input Validation), CWE-787 (Out-of-bounds
Write), CWE-119; OWASP A06:2021 Vulnerable and Outdated Components.
