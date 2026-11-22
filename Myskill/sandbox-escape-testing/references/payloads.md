# Payloads & Templates — Sandbox Escape Testing

All payloads are templates with `<PLACEHOLDER>` slots. Fill them for the
specific engagement; never paste live third-party targets. Every template in
this file is benign by design: version reads, configuration reads, marker
arithmetic, identity prints (`id`/`whoami`/`uid`/hostname), and marker files
*you* create. Memory-corruption exploits are not shipped here — those are
public advisories you match to versions and reproduce in your own lab.

## 0. Safe-first rule

**The first signals are always read-only: a fingerprint or a capability
check. No PoCs, no memory-corruption inputs, no crashes — ever — before the
version is pinned and matched to an advisory.** Stop climbing as soon as you
have two independent signals. See §3 for exactly when to stop.

## 1. Environment fingerprinting ladder

**First determine what sandbox you are actually in** — language, version,
then confinement mechanism. Wrong model → wrong variant → wasted work.

**Layer 0 — runtime + version (benign probes, all read-only):**

| Ecosystem | Benign probe | Expected tell |
|---|---|---|
| Node.js | `process.version`, `process.versions.v8` | `v18.x`, V8 `10.x` |
| vm2 (in lab clone) | `require('vm2/package.json').version` | exact vm2 version for advisories |
| Python | `sys.version` / `platform.python_version()` | `3.x.y` + build tag |
| PHP | `phpversion()`, `PHP_VERSION` | `8.x.y` / `7.x.y` |
| Java | `System.getProperty("java.version")`, `Runtime.version()` | JDK `1.8` / `11` / `17+` |
| Ruby | `RUBY_VERSION`, `RUBY_ENGINE` | `2.7` = $SAFE era; `3.x` = removed |
| Lua | `_VERSION`, `jit and jit.version` | `Lua 5.4`, `LuaJIT 2.1` |
| Go/WASM host | `wasmtime --version` / `wasmer --version` | engine + version |
| Chromium/Electron | `navigator.userAgent`, `process.versions.v8`, `process.versions.electron` | build ↔ bundled V8 mapping |
| Android | `apkanalyzer manifest print <APK>` | min/target SDK, providers |
| Windows | `systeminfo`, `ver` | OS build for RPC/tooling advisories |
| Hypervisor (guest side) | `dmidecode -s system-manufacturer`, `VBoxControl --version` | hypervisor + additions |

**Layer 1 — confinement mechanism (what restricts you):**

| Confinement | Benign probe | Tell |
|---|---|---|
| Node `vm`/vm2 | `typeof process` inside context | `undefined` = confined; visible = misconfig, not escape |
| Python jail | `len(().__class__.__base__.__subclasses__())` | count > 0 = object graph intact |
| PHP restrictions | `ini_get('disable_functions')`, `ini_get('open_basedir')` | the actual denylist |
| Java SecurityManager | `System.getSecurityManager() != null`; denied `File.exists` → `SecurityException` | SM engaged vs absent |
| Ruby `$SAFE` | `$SAFE` value; gated op → `SecurityError` | engaged on <3.0; `NameError` on 3.x |
| Lua sandbox | `type(load)`, `type(string.dump)`, `type(debug)`, `type(ffi)` | `ffi` present = decorative sandbox |
| Container | `id`, `/.dockerenv`, `/proc/self/status` → `CapEff`, `uname -r` | capability + kernel context |
| Kubernetes | `kubectl auth can-i ...`, serviceaccount namespace | RBAC reach |
| eBPF surface | `cat /proc/sys/kernel/unprivileged_bpf_disabled` | `0` = open to unprivileged |
| Windows token | `whoami /priv` | `SeImpersonatePrivilege` etc. |
| WASM | module magic `\0asm`; host API errors | engine vs wrapper layer |
| FaaS reuse | marker write→read across two invocations | warm instance confirmed |
| Hypervisor | virtio/VMware/VBox devices via `lspci`, `/sys/bus/virtio` | exposed guest↔host channels |

All probes return version/config/identity strings — never another user's
data. Record every value: each one feeds §4's advisory match.

## 2. Benign probe library

Building blocks for **Detect** steps across variants — safe to send early:

- **Marker arithmetic** (evaluation proof): `7*7` → `49`; `{{7*7}}` for
  template-shaped sinks. Read-only, in-band.
- **Capability existence** (surface mapping, no effect):
  `function_exists('pcntl_exec')` (PHP), `type(ffi)` (Lua),
  `kubectl auth can-i create pods` (k8s), `ls /var/run/docker.sock`.
- **Engagement checks** (prove the gate is *on* — expected denials are
  evidence): Java `new File("/etc/passwd").exists()` → expect
  `SecurityException`; Ruby gated op → expect `SecurityError`; WASM
  `(ptr=0, len=<LARGE>)` → expect trap. Always pair with the bypass
  attempt: denied-control vs succeeded-through-bypass is the differential.
- **Reflection guards** (kill the "it just echoed my input" false positive):
  after any fingerprint-style read, compare against a host-side control in
  the same process/request. The escaped value must equal the *host's*, not
  your input's, surroundings.
- **Round-trip markers** (persistence class): unique token + timestamp per
  invocation (`/tmp/<MARKER>` in V-14). One hit is a lead; two hits are
  evidence.

## 3. Proof depth ladder

Prove the escape with the **lowest rung that shows the boundary fell**, then
stop:

- **Rung 0 — fingerprint only.** Version + surface evidence. Establishes
  *eligibility* for a finding, never the finding itself.
- **Rung 1 — config/capability evidence.** Decoded `CapEff`,
  `kubectl auth can-i` = yes, `whoami /priv` list, `disable_functions`
  content, `typeof process === 'undefined'` alongside a host-reach probe.
  Proves the precondition — zero execution.
- **Rung 2 — benign boundary-crossing proof (production ceiling).** Read a
  marker file *you* created, or print `uid`/hostname/`id`/`whoami` once.
  This is the standard for live targets: one benign command, one marker,
  then stop.
- **Rung 3 — lab-only repro.** A public PoC run against *your* version-
  matched clone/VM, proving the advisory maps to this version. Cite it as
  lab evidence; never paste exploit source into the report.

**Never:** credential dumps, other users' data, persistence/backdoors,
crash-as-proof, disk or kernel writes beyond your own lab.

**Why the lowest rung is enough for the report:** triage needs three
things, none of which require deeper exploitation — (1) a *differential*
proving the boundary crossed (denied control vs succeeded probe, context
`typeof process` vs host value, host marker vs pod marker), (2) the exact
version + advisory ID + fix version so a reviewer can verify without you
re-running anything dangerous, and (3) blast radius *described* in prose.
Minimal proof means fewer moving parts to dispute, zero collateral damage,
no scope/ToS gray zone — programs pay for the crossed boundary, not for the
body count of the evidence.

## 4. Per-ecosystem version & advisory context

Method for every variant — **check the version, then check the advisory**;
never invent the exploit:

1. Pin the exact version (§1 probes, lockfiles, banners, leaked source).
2. Search `<product> <version> sandbox escape advisory` → GHSA/NVD/vendor
   release notes.
3. Read the affected range and the **fix version**; for kernels/QEMU-class
   components, check the *distro backport*, not just the vanilla string.
4. Cite the advisory ID + fix version in the report; reproduce the public
   PoC in lab only. If no advisory matches, report the reachable surface
   with the evidence you have and say it is unvalidated — do not fabricate.

Context per ecosystem (history, not payloads):

| Ecosystem | What the history says | Where to check |
|---|---|---|
| Node vm2 | Accumulated multiple sandbox escapes (handler/Proxy/object-reach classes) through 2021-2023; project subsequently **discontinued** — any remaining use is itself a finding | GHSA/NVD for the exact version; vendor EOL notice |
| Node `vm` | Officially documented as *not* a security mechanism — "escape" of stock vm is a design-reliance finding, not a CVE hunt | Node docs; app's security claims |
| Python jails | Docs state restricted eval is not a security boundary; subclass/MRO walk research is a mature public corpus; framework bugs (RestrictedPython et al.) do get advisories | Python docs; framework GHSA; version-pinned research |
| PHP disable_functions | Per-version bypasses recur via FFI/imap/imagick/`mail`-child/LD_PRELOAD-class sinks; bypass collections and Metasploit modules track them | `phpversion()` + loaded modules → public research/Metasploit module notes |
| Java SecurityManager | Deprecated (JEP 411), removed for app use on modern JDKs; bypass literature mostly pre-JPMS — check whether the SM even exists on the deployed JDK | `java.version`; JEP notes; JDK-era research |
| Chromium/V8 | In-the-wild type-confusion era is well documented (Map-side-effect class onward); engine bugs are tracked per build | Chrome release blog, NVD, Project Zero; Electron↔Chromium mapping tables |
| eBPF verifier | 2020-2021 in-the-walk LPEs via ALU32/bounds-tracking flaws; several *more* since; distro backports decide real exposure | `uname -r` + distro changelogs; kernel CVE trackers |
| Ruby `$SAFE` | Core devs long said `$SAFE` is not a security feature; bypass research exists for 1.8/1.9-era; `$SAFE` removed in Ruby 3.0, taint in 3.2 | `RUBY_VERSION` decides whether the class even applies |
| Lua bytecode | Official docs: only load **trusted** bytecode; memory-corruption write-ups cluster on 5.1/LuaJIT; `ffi`/`debug` presence short-circuits the question | `_VERSION`/`jit.version` → public write-ups |
| Kubernetes HostPath | Mostly misconfiguration class (baseline: PSA restricted / Kyverno / OPA policies); kubelet/node CVEs are the CVE-adjacent edge | pod spec, enforce labels; kubelet release notes |
| Windows | Potato-class is a *technique* tied to privilege presence; RPC-specific issues are build/KB-specific (2021 spooler and Netlogon RPC classes are the canonical examples) | `systeminfo` build + patch level → vendor advisories |
| Android providers | Exported-provider issues are a *misconfiguration* class unless a platform CVE is involved | manifest flags + protectionLevel; MASVS/MASTG |
| WASM engines | wasmtime/wasmer/WAMR publish GHSAs for runtime bugs; the common production issue is wrapper `ptr+len` integer overflow in app code | engine version → GHSA; wrapper source review |
| FaaS /tmp reuse | Documented platform *behavior* (warm reuse, tmpfs semantics), not a CVE class — findings are misconfiguration-shaped | provider docs; your marker round-trip test |
| runc/kernel container | Recurring CVE classes (runtime binary-overwrite era, cgroup release_agent era, overlayfs/capability era) | `uname -r` + `runc --version` + distro advisories |
| Hypervisors | Guest→host issues surface periodically in VBox/QEMU/VMware device emulation; guest additions carry their own version/CVE trail | vendor advisories + distro backports; additions version |

## 5. Encoder / obfuscation & evasion notes

Use only when a WAF/filter mangles your *benign* probes; sandbox probes
often sail under WAFs tuned for XSS/SQLi until dunder patterns trigger:

| Trick | Example | Bypasses |
|---|---|---|
| Split dunder names (Python) | `'__cla' + 'ss__'`, `'__cla%s%s__' % ('','')` | WAF dunder-name rules |
| JSON unicode escapes | `"\u005f\u005fclass\u005f\u005f"` | signature scanning of raw bodies |
| Split JS properties (Node) | `this['constru' + 'ctor']` | `constructor`-pattern rules |
| PHP case mixing | `POSIX_getuid()` (function names are case-insensitive) | *string*-based denylist layers |
| Layered URL-encoding | `%25255f` for nested decoders | double/triple-decode sinks |
| Whitespace swaps | `%0a`, `%09` in expression payloads | naive space/keyword filters |
| Base64 wrapping | `echo <B64> \| base64 -d` for lab probes | content-pattern filters |

Honesty note: encodings matter only if you observe mangling — test with a
benign marker first (does `7*7` survive?) and match the encoding depth to
the decoder you actually observed. Overlong UTF-8 and null-byte tricks are
dead on modern stacks.

## 6. Tool invocation templates

```bash
# benign fingerprints (one-liners)
node -e 'console.log(process.version)'
python3 -c 'import sys; print(sys.version)'
php -r 'echo phpversion()," | ",ini_get("disable_functions");'
# container context
grep CapEff /proc/self/status && capsh --decode=<PLACEHOLDER_CAPEFF>
# k8s capability
kubectl auth can-i create pods -n <PLACEHOLDER_NAMESPACE>
kubectl get ns -o jsonpath='{.items[*].metadata.annotations.pod-security\.kubernetes\.io/enforce}'
# android statics
apkanalyzer manifest print <PLACEHOLDER_APK> | grep -A4 '<provider'
# windows
whoami /priv
systeminfo | findstr /B /C:"OS Name" /C:"OS Build"
# eBPF surface
cat /proc/sys/kernel/unprivileged_bpf_disabled
# advisory habit (no payloads, just matching)
# search: <product> <version> sandbox escape advisory   → GHSA / NVD / vendor notes
# then:   <advisory> affected range + fix version       → cite in report
```

## 7. Chain it with

- **`rce-testing`** — every sandbox escape needs a *code-execution sink
  inside the sandbox* first: `eval`/`assert` sinks, SSTI, deserialization,
  template/workflow engines, and upload-to-exec are that skill's variants.
  Land the execution there, then come here to break the confinement. SSRF
  also returns after infra escapes (reaching the scheduler API, cloud
  metadata, or internal control planes from an escaped container/host).
- **`path-traversal-testing`** — file read *in the escaped context* is the
  canonical rung-2 proof: marker-file reads, `/etc/hostname` differentials
  between guest/pod and host, and wrapper-style reads
  (`file://`, `php://`) after a jail break. LFI→jail-entry combinations
  (log poisoning delivering code into a `disable_functions`-restricted PHP,
  include-driven eval into a Python jail) live in that skill — chain
  traversal *into* the sandbox, then escape *out* of it.
- **`info-disclosure-testing`** — the version fingerprint that §4 depends on
  usually comes from there: leaked `package.json`/lockfiles, sourcemaps
  revealing the sandbox library and version, stack traces naming the runtime,
  `.git` history showing which vm2/jail framework was pinned. Report the
  leak class, redact anything secret-shaped — recon material feeds the
  advisory match, it is not the finding.

Also: escapes chain *upward* — Python/PHP/Node jail (V-01/V-02/V-03) →
container (V-04) → node/k8s (V-10) → hypervisor (V-15); stop at the first
boundary your authorization actually covers.
