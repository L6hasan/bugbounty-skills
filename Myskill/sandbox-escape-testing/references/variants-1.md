# Sandbox Escape Variants — Part 1 (V-01 … V-08)

Deep playbook sections for the first eight variants. Work the **Detect**
steps in order: fingerprint first (benign probes only), match the exact
version to public advisories, reproduce public PoCs in *your own* lab
against a version-matched clone, and check **False positives** before writing
anything up. Payload slots are `<PLACEHOLDER>` — fill them per engagement.

## Table of contents

- [V-01: Node.js context extraction via VM/VM2 sandbox evasion control breaks](#v-01-nodejs-context-extraction-via-vmvm2-sandbox-evasion-control-breaks)
- [V-02: Python scope re-alignment via exec/eval context isolation breaks](#v-02-python-scope-re-alignment-via-execeval-context-isolation-breaks)
- [V-03: System restriction evasion via PHP disable_functions runtime bypass](#v-03-system-restriction-evasion-via-php-disable_functions-runtime-bypass)
- [V-04: Container privilege escalation via Docker daemon and kernel namespace breakouts](#v-04-container-privilege-escalation-via-docker-daemon-and-kernel-namespace-breakouts)
- [V-05: Java SecurityManager execution bypass via reflection API interception](#v-05-java-securitymanager-execution-bypass-via-reflection-api-interception)
- [V-06: Chromium V8 sandbox evasion via type confusion optimization flaws](#v-06-chromium-v8-sandbox-evasion-via-type-confusion-optimization-flaws)
- [V-07: eBPF kernel sandbox escape via verifier logic flaw invalidation](#v-07-ebpf-kernel-sandbox-escape-via-verifier-logic-flaw-invalidation)
- [V-08: Ruby $SAFE sandbox circumvention via vulnerable core method clones](#v-08-ruby-safe-sandbox-circumvention-via-vulnerable-core-method-clones)

## V-01: Node.js context extraction via VM/VM2 sandbox evasion control breaks

**Mechanism:** Attacker-influenced code runs in a `vm.createContext`/`vm2`
context that the app treats as isolated. The context shares the same heap and
prototype machinery as the host, so constructor walks
(`this.constructor.constructor('return process')()`), realm-crossing objects
(promises, error stacks, bound functions), and — in vm2's history — handler-
boundary/Proxy flaws let the sandboxed code reach the *host* realm. The
violated assumption: "a separate JS context is a security boundary." Node's
own docs say `vm` is not one; vm2 claimed to be one and accumulated multiple
sandbox escapes before being discontinued (2024).

**Preconditions:**
- Attacker code or expressions execute in `vm`/vm2 (template editor,
  serverless plugin, workflow automation, "safe eval" feature)
- Exact vm2 version matches a public advisory, *or* stock `vm` is relied on
  as a security boundary by the app's design/claims
- Host realm has useful reach (`process`, `require`) — always true for servers

**Detect:**
1. Identify the mechanism from stack traces (`runInNewContext`, `VM`), error
   names (`VMError`), leaked `package.json`/lockfiles, or the app's docs.
2. Fingerprint versions with benign probes: `process.version` and
   `process.versions.v8` from the host side; `require('vm2/package.json').version`
   in your own lab clone of the same app (never against the target).
3. Verify the sandbox is actually engaged: run `typeof process` inside the
   context — `"undefined"` proves confinement is active (if `process` is
   already visible, the sandbox is misconfigured, not escaped — different
   finding).
4. Match the pinned vm2/Node version against GHSA/NVD ("vm2 sandbox escape"
   advisories are numerous and version-specific; stock `vm` has no advisories
   because it was never a boundary).
5. Reproduce the *public* advisory PoC in your lab container against the
   version-matched install; production probing stops at steps 1–4 plus the
   benign constructor-walk probe below.

**Proof of concept:**
```
# lab harness, version-matched:
node -e "const {VM}=require('vm2'); console.log(new VM().run('<PLACEHOLDER_PROBE>'))"

benign probes:
  typeof process                                  → "undefined" (confined, expected)
  this.constructor.constructor('return process.version')()
                                                  → HOST version string = escape signal
```

**Confirm:** The constructor-walk result equals the *host* `process.version`
measured outside the sandbox in the same process (rules out reflection), and
`typeof process === 'undefined'` still holds inside — two orthogonal signals:
version differential + confinement-engaged evidence. Reproduce twice.

**False positives:** Reporting "vm escapes" against vanilla Node `vm` when
the program never claimed it was a boundary (docs say it isn't — check the
program's security claim first; without one this is usually informative, not
a vuln). The "escaped" value is your input echoed back (always diff against a
host-side control). `process` deliberately injected into the sandbox context
(misconfig, not escape). vm2 version *newer* than the advisory (backport or
fixed release — read the advisory's fixed version, not just the CVE list).

**Impact:** Arbitrary host JS execution — same blast radius as RCE in the
server process: env vars, app secrets, network pivot. Phrase as "sandbox
escape from vm2 <ver> → code execution as `<user>` in app process"; cite the
advisory instead of pasting exploit code.

**Remediation:** Treat neither `vm` nor vm2 as isolation — run untrusted code
in a separate process or container with OS-level limits (non-root user,
seccomp, cgroups, no network), or drop dynamic evaluation entirely.

**CWE / OWASP:** CWE-693 (Protection Mechanism Failure), CWE-269 (Improper
Privilege Management); OWASP A05:2021 Security Misconfiguration / A06:2021
Vulnerable and Outdated Components.

## V-02: Python scope re-alignment via exec/eval context isolation breaks

**Mechanism:** Untrusted code runs in a "jailed" namespace (restricted
`__builtins__`, RestrictedPython, custom eval wrappers). Names are hidden,
but the object graph is shared: every object links back to `object`, so
`().__class__.__base__.__subclasses__()` enumerates every loaded class, and
MRO walks reach classes whose module globals hold `os`, `subprocess`, or
`warnings.catch_warnings.__init__.__globals__` — re-aligning scope to the
host interpreter. The violated assumption: "hiding dangerous names removes
dangerous capabilities."

**Preconditions:**
- A code sink: `eval`/`exec`/`compile`/RestrictedPython on attacker input
  (calculator, formula field, SSTI-adjacent features)
- Useful classes already imported (`os`, `subprocess`, `warnings` — true of
  any long-running web app)
- No OS-level confinement under the interpreter (Python's own docs: eval
  restrictions are not a security boundary)

**Detect:**
1. Confirm evaluation with a benign arithmetic marker (e.g. `7*7` → `49`).
2. Benign reach check: `len(().__class__.__base__.__subclasses__())` — a
   count, not a gadget walk. A large count (>20) means the class graph is
   intact (confined-but-connected); `0`/error means deeper restriction.
3. Fingerprint the interpreter benignly: `__import__('sys').version` if
   `__import__` survived, else from leaked source/lockfiles/stack traces
   (`type(sys.last_value)` names the runtime).
4. Check what lies *under* the jail (is the process in a container? seccomp?
   non-root?) — this decides severity, and it is what juniors forget to ask.
5. In **lab** only: walk the subclass list against known jail-escape chain
   shapes (public research: `os._wrap_close`, `catch_warnings` globals) and
   land the benign proof rung.

**Proof of concept:**
```
POST /api/calc HTTP/1.1
Content-Type: application/json

{"expr": "<PLACEHOLDER_EXPR>"}

rung 1 (benign): 7*7                                              → 49
rung 2 (benign): len(().__class__.__base__.__subclasses__())       → count
rung 3 (benign): __import__('sys').version                        → "3.x.y"
rung 4 (lab only): subclass/globals chain → open('/tmp/<MARKER>').read()
```

**Confirm:** Interpreter version string (env-unique, reflection can't fake
it) *plus* the subclass-count differential showing a connected object graph
— and, in lab, the benign marker read from the public chain shape.
Reproduce twice.

**False positives:** "name 'os' is not defined" after your probe — that is
*expected* under the jail and proves nothing about safety (the whole point of
this variant is that names ≠ capability). Subclass list exists but no
dangerous classes loaded (fresh/lean interpreter — chain not available;
report as hardening gap). RestrictedPython or a similar library is in use
*and the program documents itself as non-security* (it isn't one — but scope
the finding as "eval sink = RCE", route to `rce-testing`). Client-side
math evaluating `49` in the browser.

**Impact:** Arbitrary Python in the app process → OS command execution as
the service user; report as "sandboxed eval escape (restricted builtins) →
RCE as `<user>`", noting the OS layer below (containerized? root?).

**Remediation:** Do not eval untrusted code inside the app process at all —
run it in a separate, non-root, seccomp-confined container with no network
and a read-only filesystem; if evaluation must stay, replace it with a
grammar-restricted expression parser.

**CWE / OWASP:** CWE-94 (Eval Injection) / CWE-693 (Protection Mechanism
Failure); OWASP A03:2021 Injection; WSTG — Testing for Code Injection.

## V-03: System restriction evasion via PHP disable_functions runtime bypass

**Mechanism:** `disable_functions` deletes symbols from the runtime's
function table; it is a denylist, not a security boundary. Execution
capability is recovered through surfaces the denylist doesn't cover: `FFI`
(PHP 7.4+), `imap_open`, `Imagick`, `pcntl_*`, `mail()`/`error_log` child
processes combined with `putenv` LD_PRELOAD, CGI argv quirks, and
version-specific module sinks. The violated assumption: "listing dangerous
function names equals removing dangerous capability."

**Preconditions:**
- A PHP code-execution sink already reached (LFI→RCE, upload→exec, legacy
  `assert`/`preg_replace /e`, template eval)
- `disable_functions` set in php.ini (the constraint being claimed bypassable)
- A loaded module or alternative sink not on the list; exact PHP version

**Detect:**
1. Confirm PHP execution benignly: `echo phpversion();` — if this doesn't
   run, you don't have code execution, fix that first (route to
   `rce-testing`).
2. Read the denylist itself: `echo ini_get('disable_functions');` — benign,
   and now you know exactly what you must recover.
3. Enumerate bypass surface benignly: `extension_loaded('ffi')`,
   `ini_get('ffi.enable')`, `function_exists('imap_open')`,
   `class_exists('Imagick')`, `function_exists('pcntl_exec')`,
   `function_exists('putenv')`. Each `true` is a rung.
4. Match `phpversion()` + module set against public bypass collections and
   Metasploit-class modules — these are per-version; the correct move is
   "check the version, then check the advisory/research", not improvising.
5. Prove recovery with the *lowest* rung: a read-only function the denylist
   thought it removed (e.g. `posix_getuid()`, `getcwd()`) — uid/identity
   evidence before any shell.

**Proof of concept:**
```
POST /api/diag  (or wherever your code sink lands)
<?php
echo phpversion();                          // benign fingerprint
echo ini_get('disable_functions');          // the denylist
var_dump(extension_loaded('ffi'));          // bypass surface probes
var_dump(function_exists('imap_open'));
echo posix_getuid();                        // benign capability proof (if reachable)
?>
```

**Confirm:** Function/capability data obtained *through a path the denylist
was supposed to remove* (uid output from a blocked-family function, or FFI
reach demonstrated by a read-only call), reproducible on a second request —
plus the denylist content itself showing the function family was listed.

**False positives:** `disable_functions` is empty — then this is plain PHP
RCE (route to `rce-testing`; claiming a "bypass" of nothing gets
rejected). `function_exists` returns `true` but the call fails at
`open_basedir`/seccomp level (existence ≠ usability — attempt one benign
call). The sink only runs `php -r` on the *tester's* machine (lab confusion).
PHP-FPM `security.limit_extensions` blocking `.php` execution of your upload
(a different, protective control).

**Impact:** Denylist bypass → OS command execution as the web user — most
severe on shared hosting where `disable_functions` was the *only* hardening.
Phrase as "disable_functions bypass on PHP <ver> via `<module/sink>` → code
execution as `<user>`; `<list>` neutralized".

**Remediation:** Never treat `disable_functions` as isolation — run PHP-FPM
workers as a dedicated non-root user under seccomp/container confinement,
remove dangerous extensions (FFI unless required), and patch to a supported
PHP version.

**CWE / OWASP:** CWE-693 / CWE-284 (Improper Access Control); OWASP A05:2021
Security Misconfiguration; OWASP A03:2021 where an injection sink feeds it.

## V-04: Container privilege escalation via Docker daemon and kernel namespace breakouts

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
# lab-only benign escape proof (privileged misconfig): mount host disk
# read-only and read a marker file YOU placed there — never copy data out
```

**Confirm:** Two signals: decoded capability/config evidence (what makes the
breakout possible) *plus* a host-scope behavior (host-only artifact read in
lab, or socket API answering with host `docker version`) — reproduced twice.

**False positives:** `.dockerenv` also appears in systemd-nspawn/lxc-style
sandboxing (presence alone proves little). Full `CapEff` inside a *user
namespace* where the mapping is unprivileged — decode the map, don't assume
host root. A docker.sock mounted **read-only** is unusable (socket I/O
needs write — juniors report this as critical; test before claiming).
cgroup v2 without release_agent semantics ≠ the release_agent escape. A
mounted host *log* directory is often intentional (hygiene note, not
breakout) unless it enables writes to host-executed paths.

**Impact:** Container → host root, cross-container compromise on the node,
cluster node takeover (pair with V-10). Phrase as "container with
`<caps/mounts>` on kernel `<ver>` → host compromise path; benign proof:
host-marker read". Severity follows the lowest common denominator of config.

**Remediation:** No `--privileged`, drop all then add only needed caps, never
mount docker.sock, default-deny seccomp + AppArmor, patch kernel and runc
per distro advisory, run workloads rootless/with user namespaces.

**CWE / OWASP:** CWE-250 (Execution with Unnecessary Privileges), CWE-269
(Improper Privilege Management), CWE-1326 (Missing Immutable Root File
System); OWASP A05:2021 Security Misconfiguration.

## V-05: Java SecurityManager execution bypass via reflection API interception

**Mechanism:** A SecurityManager + policy denies untrusted code file/network/
exec permissions via checks on sensitive API entry points. Historical
bypasses re-enter through surfaces the policy doesn't gate: pre-JPMS
`setAccessible(true)` unwrapping private internals, `doPrivileged` frames in
classpath classes (gadget-style "confused deputy"), `MethodHandles`/
`Unsafe` in older JVMs, or custom class loaders. The violated assumption:
"deny-by-default checks at API boundaries cannot be re-entered from a
privileged frame." Crucial context: the SecurityManager is deprecated and
removed for application use on modern JDKs — many "bypasses" are now just
"the feature is gone."

**Preconditions:**
- Untrusted code executes under an active SecurityManager (plugin/extension
  server, script engine, old app server) — `System.getSecurityManager()`
  non-null
- Old enough JVM (pre-module or with `--add-opens`) for reflection to reach
  JDK internals; a privileged frame or AllPermission class reachable
- Exact JVM version known (`java.version`)

**Detect:**
1. Benign fingerprints: `System.getProperty("java.version")`,
   `Runtime.version()` (9+), and
   `System.getSecurityManager() == null ? "NO-SM" : "SM-ACTIVE"`.
2. Prove the mechanism is engaged: attempt a benign denied operation
   (`new java.io.File("/etc/passwd").exists()`) — a `SecurityException`
   (whose text often leaks the policy source) is the engagement signal; a
   `true/false` result means the SM isn't gating what you assumed.
3. Check reflection surface: whether `setAccessible` works on a JDK-internal
   member from your context — on JDK 17+ modules usually block it; that is a
   dead end and a result, not a failure.
4. Match `java.version` to public SecurityManager-bypass literature (largely
   pre-JDK 9 research) — reproduce public techniques in **lab** only.
5. If the app *claims* sandboxing on JDK 17+ with no SM (Nashorn gone,
   GraalVM sandbox separate): the reportable issue may be "claimed sandbox
   not implemented" — scope accordingly.

**Proof of concept:**
```
lab (version-matched JVM):
System.getProperty("java.version");                 // benign fingerprint
System.getSecurityManager() != null                 // SM engaged?
new java.io.File("/etc/hostname").exists();          // control: expect SecurityException
// benign bypass proof (public technique, lab only): read the marker file
// the policy denies — file CONTENT of a marker you created, nothing else
```

**Confirm:** SM reported active (control op throws `SecurityException`) *and*
a policy-denied but benign operation (marker file read) succeeds reproducibly
— denied-by-policy and performed-anyway are the two orthogonal signals.

**False positives:** SM active but the policy grants the permission anyway
(read the policy before claiming a "bypass"). JDK 17+ where the SM was
removed entirely — a "bypass" claim there is mis-scoped (report the missing
sandbox only if the product claims one). `doPrivileged` used by the
application's own code is not attacker-reachable (prove reach from the
untrusted context). Reflection silently blocked by JPMS (attempt it — don't
assume either way; `InaccessibleObjectException` is the deny signal).

**Impact:** Escaping the intended plugin/script sandbox → file read/write
and command execution inside the JVM process. Phrase as "SecurityManager
bypass on JDK <ver> via `<technique>` → policy-denied operations performed
as the JVM user"; cite the research rather than pasting exploit code.

**Remediation:** Do not build sandboxes on the SecurityManager (deprecated,
JDK JEP 411) — isolate untrusted code in a separate process/container; where
an old JVM must stay, minimal policy, no `--add-opens`, and block
class-loader/method-handle escalation paths.

**CWE / OWASP:** CWE-863 (Incorrect Authorization), CWE-693 (Protection
Mechanism Failure); OWASP A05:2021 Security Misconfiguration.

## V-06: Chromium V8 sandbox evasion via type confusion optimization flaws

**Mechanism:** V8's JIT tiers (Sparkplug/Maglev/TurboFan) speculate on
object maps and eliminate checks; a mis-speculation class (stale map after
transitions, wrong range after bounds narrowing) yields type confusion →
out-of-bounds r/w in the JS heap → renderer RCE — and, historically, a further
step out of the renderer sandbox. The violated assumption: "optimized code
preserves the semantics the interpreter enforced." Note the layering: a JS
engine escape lands in the renderer, which is *itself* sandboxed by Chromium;
host compromise needs the additional renderer-sandbox step — say which layer
your evidence actually proves.

**Preconditions:**
- Attacker JS executes somewhere useful (embedded Chromium, Electron app,
  kiosk browser, headless renderer service — *not* your own local browser)
- Exact Chrome/Electron/V8 version ≤ a range with a public in-the-wild or
  advisory-documented type confusion
- Renderer sandbox still on (its absence is a separate, easier finding)

**Detect:**
1. Fingerprint benignly: `navigator.userAgent` / Client Hints (web-exposed),
   `chrome://version` via the product itself, and for Electron/Node-embedded:
   `process.versions.v8`, `process.versions.electron`. V8 version alone can
   map to a Chrome build; record both.
2. Map the build to advisories: Chrome release blog + NVD + Project Zero
   write-ups for that era. "Check the version, then check the advisory" —
   this variant is almost entirely fingerprinting work; exploitation is lab
   work you inherit from the advisory, never invented.
3. If the product bundles an old Chromium and serves *other users*, outdated-
   engine evidence (version string + advisory + shipped-by-default) is the
   finding; do not need a live crash.
4. Lab-only: run the *public* crash PoC against a version-matched build to
   sanity-check the advisory mapping. A crash is a lead; a confirmed mapping
   needs the advisory's bug class matching your fingerprint.

**Proof of concept:**
```
fingerprint (benign):
  navigator.userAgent / process.versions.v8  → <PLACEHOLDER_V8_VERSION>
  product build                             → <PLACEHOLDER_BUILD>
advisory lookup:
  chrome release notes + NVD for <era> → <CVE_ID> fixed in <FIXED_BUILD>
lab sanity check (your own VM, public PoC): crash/behavior matches advisory class
```

**Confirm:** Version evidence showing the engine is inside the vulnerable
range *and* the advisory's bug class fits (type confusion in the relevant
tier), with the fix build identified. Two channels: UA/version string +
advisory mapping. Lab crash repro is a bonus, not a requirement for a
version-based finding.

**False positives:** UA strings altered by enterprise proxies or UA-reduction
policy (corroborate with Client Hints or an independent endpoint). Electron
version ≠ Chrome version mapping done sloppily (map via Electron's bundled
Chromium table). A generic renderer crash is OOM/other — not type confusion
without the advisory's signature. Exploiting *your own* browser against
yourself is not a finding against the program. Renderer RCE ≠ host escape —
don't claim host compromise from JS-engine evidence alone.

**Impact:** For products shipping embedded Chromium/Electron: outdated
in-the-wild-exploited engine reachable by untrusted content → report as
"renderer RCE chain precondition (CVE-<X> class) via outdated bundled
Chromium <ver>"; severity from content exposure model, not from hypothetical
full-chain drama.

**Remediation:** Upgrade the bundled Chromium/Electron to the fixed build;
keep the renderer sandbox and site isolation enabled (never ship
`--no-sandbox`).

**CWE / OWASP:** CWE-843 (Access of Resource Using Incompatible Type /
type confusion), CWE-1104 (Use of Unmaintained Third-Party Components);
OWASP A06:2021 Vulnerable and Outdated Components.

## V-07: eBPF kernel sandbox escape via verifier logic flaw invalidation

**Mechanism:** The kernel verifier statically proves each eBPF program
memory-safe (pointer types, bounds). Public flaw classes — ALU32 bound
tracking, signed/unsigned confusion, narrowing after `OR`/`AND`, map-value
pointer arithmetic — let a program pass verification yet, at runtime, read
and write kernel memory arbitrarily → LPE. The violated assumption: "accepted
by the verifier = memory-safe at runtime." These flaws were exploited in the
wild (2020–2021 era), which is why version matching matters more than
payload cleverness here.

**Preconditions:**
- Ability to load eBPF programs: `kernel.unprivileged_bpf_disabled=0`
  (mass-exploitable) *or* CAP_BPF/CAP_SYS_ADMIN (container-LPE class)
- Kernel version in a vulnerable range *without distro backport* (backports
  are the #1 trap — see Detect)
- `bpf()` syscall not blocked by seccomp/apparmor

**Detect:**
1. Benign probes: `uname -r`, `cat /proc/sys/kernel/unprivileged_bpf_disabled`,
   `ls /sys/fs/bpf 2>/dev/null`, `id` (do you hold CAP_BPF/CAP_SYS_ADMIN?).
   `2` means disabled-unless-CAP_BPF, `1`/`-1` means closed for unprivileged.
2. Classify reach: unprivileged → anyone-on-host LPE; CAP_BPF-only →
   container→host class (still serious; pair with V-04).
3. **Backport check:** map `uname -r` through the *distro's* advisory pages
   (Ubuntu/Debian/RHEL kernel changelogs) — a 5.11-based RHEL kernel may
   already carry the fix. Vanilla upstream ranges are a lead until the
   changelog confirms.
4. Lab-only validation: load the *public* PoC against a version-matched
   vanilla kernel VM; the benign proof rung is a uid differential
   (`id` before/after) on your own VM. Never fuzz or PoC against a shared
   production kernel — verifier bugs crash the host.

**Proof of concept:**
```
# benign recon (target):
$ uname -r && cat /proc/sys/kernel/unprivileged_bpf_disabled   # → <PLACEHOLDER_KERNEL> / <0|1|2>
$ id                                                            # capability check
# lab-only (your version-matched kernel VM):
$ <PUBLIC_POC_FROM_ADVISORY> && id                              # uid differential = benign proof
```

**Confirm:** Kernel fingerprint inside the vulnerable range *plus* the load
surface actually open (`unprivileged_bpf_disabled=0` or CAP_BPF held) — and
in lab, the public PoC's benign uid proof on a version-matched kernel.
Two channels: version+changelog evidence, surface evidence.

**False positives:** `unprivileged_bpf_disabled=1` and no CAP_BPF — surface
closed, not a finding (the CVE existing elsewhere doesn't matter). Distro
backport makes the vanilla range wrong (the most common mis-triage in this
class). Container holding CAP_BPF on a *patched* kernel is a config hygiene
issue, not an LPE. Classic BPF socket filters (cBPF) are a different
mechanism — verifier flaw research is eBPF-specific. `bpf()` returning
EPERM means seccomp/blocked, not vulnerable.

**Impact:** Unprivileged local user → kernel memory R/W → root LPE; in
containers: breakout to host kernel. Phrase as "kernel <ver> + unprivileged
bpf enabled → LPE per <advisory>, surface confirmed by `<sysctl>`"; severity
Critical when unprivileged.

**Remediation:** Set `kernel.unprivileged_bpf_disabled=1` (or 2 with strict
caps), drop CAP_BPF/SYS_ADMIN from workloads, patch to the distro-fixed
kernel, seccomp-deny `bpf()` where unused.

**CWE / OWASP:** CWE-190 (Integer Overflow / bounds tracking) / CWE-787
(Out-of-bounds Write), CWE-250; OWASP A05:2021 Security Misconfiguration.

## V-08: Ruby $SAFE sandbox circumvention via vulnerable core method clones

**Mechanism:** `$SAFE` levels plus taint/trust tried to confine untrusted
code by gating dangerous operations on tainted/trusted objects. Historical
bypasses lived in core methods that mishandled taint propagation — objects
created, cloned, or replaced without carrying the taint bit or safe-level
check (IO/`Kernel` paths, `Marshal`-adjacent reconstructions, default-proc
and struct tricks across 1.8/1.9-era research). The violated assumption:
"marking data unsafe and checking it at call sites contains code." Ruby's
own maintainers stated `$SAFE` is not a security mechanism — and modern
Rubies removed `$SAFE` (3.0) and taint entirely (3.2), so this variant
exists almost entirely on legacy stacks.

**Preconditions:**
- Legacy app evals untrusted code with `$SAFE` raised (DRb-era apps, old
  template systems, "safe eval" wrappers)
- `RUBY_VERSION` < 3.0 (else the mechanism doesn't exist — see False
  positives) and a core-method bypass matching that version is public
- Underlying OS confinement absent (no container/limits below the interpreter)

**Detect:**
1. Benign fingerprint: `RUBY_VERSION`, `RUBY_ENGINE`, and mechanism presence:
   `$SAFE` (on 3.x this raises `NameError` — itself a useful result: the
   legacy sandbox code is dead but may still *believe* it is protecting).
2. Prove the mechanism engages: at the raised level, attempt a benign op the
   level gates — expect `SecurityError`. Engagement evidence is half your
   confirmation; without it there is nothing to "escape".
3. Map `RUBY_VERSION` to published `$SAFE`-bypass research/CVEs for that
   era; reproduce public techniques only in **lab** on a version-matched
   Ruby.
4. Check below the interpreter (container? rlimit? user?) — severity
   depends on the OS layer, same as V-02.

**Proof of concept:**
```
RUBY_VERSION                       # benign fingerprint → <PLACEHOLDER_RUBY_VERSION>
$SAFE rescue 'removed'             # mechanism presence (3.x: "removed")
File.exist?('/tmp/<MARKER>') rescue $!   # control: SecurityError proves gating active
# lab only: <PUBLIC_BYPASS_FROM_RESEARCH> → benign proof: read marker file / puts `id`
```

**Confirm:** Control operation raising `SecurityError` (mechanism active) +
a policy-denied-but-benign operation succeeding through the bypass class,
reproduced twice in lab; on the live target, engagement evidence +
version-to-research mapping is the honest evidence tier.

**False positives:** On Ruby ≥ 3.0 there is no `$SAFE` — "escaping" it is
meaningless; the reportable issue, if any, is obsolete sandbox *reliance* in
dead code or a plain eval RCE (route to `rce-testing`). The app never
raised `$SAFE` at all (again: plain RCE, not this variant). Taint behavior
differed between 1.8 and 1.9+ (match research to the exact series).
`SecurityError` for an operation that is denied *by the bypass target too*
proves nothing — the differential must be denied-control vs succeeded-
through-bypass.

**Impact:** Untrusted script → arbitrary Ruby → OS execution as the app
user; typical of long-lived legacy services that can't be upgraded
casually. Phrase as "$SAFE level <N> circumvention on Ruby <ver> via
`<method-class>` → code execution as `<user>`; OS layer: `<container/no>`".

**Remediation:** Remove reliance on `$SAFE` (gone in 3.x) — run untrusted
code in a separate non-root process/container; upgrade the interpreter.

**CWE / OWASP:** CWE-693 (Protection Mechanism Failure), CWE-94 (Eval
Injection); OWASP A03:2021 Injection / A06:2021 Vulnerable and Outdated
Components.
