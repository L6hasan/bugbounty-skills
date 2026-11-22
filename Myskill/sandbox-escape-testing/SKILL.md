---
name: sandbox-escape-testing
description: Deep playbook for sandbox escape bug bounty testing: 15 variants covering Node vm/vm2 context extraction, Python exec/eval jail breaks (__subclasses__/MRO), PHP disable_functions bypasses, Docker daemon and Linux namespace breakouts, Java SecurityManager reflection bypass, Chromium V8 type confusion, eBPF verifier flaws, Ruby $SAFE circumvention, Lua bytecode manipulation, Kubernetes HostPath pod escapes, Windows RPC and token impersonation, Android content provider leakage, WASM integer overflows, FaaS /tmp persistence, and hypervisor IOCTL escapes. Use this skill whenever the user is doing authorized security testing and mentions sandbox escape, vm2, Node vm, Python jail, disable_functions, SecurityManager, container escape, docker breakout, pod escape, hostPath, eBPF verifier, V8 type confusion, $SAFE, Lua bytecode, token impersonation, content provider, WASM memory, FaaS /tmp persistence, or hypervisor escape; asks how to test whether a sandbox or isolation boundary can be broken, wants version fingerprinting matched to public advisories for a sandboxed runtime, needs to confirm or triage a sandbox-escape finding, or is writing a report for a sandbox escape bug. Also use when analyzing a sandbox implementation, container/pod spec, or code snippet for isolation weaknesses.
---

# Sandbox Escape Testing — Deep Playbook

Sandbox escapes are the class triage teams both love and distrust: enormous
impact claims, easy to over-state, nearly impossible to reproduce safely if
you do it sloppily. This skill makes the work methodical — identify which
confinement you are actually in, map the remaining escape surface,
fingerprint the exact runtime/library/kernel version against public
advisories, prove the boundary crossing with the lowest-impact evidence that
still holds up, and write the report. Fifteen variants span language jails
(Node/Python/PHP/Java/Ruby/Lua), infrastructure layers (Docker, Kubernetes,
Windows, Android, serverless), and memory-safety layers (V8, eBPF, WASM,
hypervisors).

## 1. Scope & authorization guardrail

Only test targets you are authorized to test: a published bug bounty program
with this asset in scope, a client engagement with written scope, or your own
lab/CTF. If the target is out of scope, belongs to a third party, or you
cannot verify authorization, refuse and stop.

This skill lives in 0-day / CVE-adjacent territory, so its destructive-payload
rule is wider than in other skills: kernel-module bugs, V8/eBPF/hypervisor
PoCs, and device fuzzing can panic hosts, corrupt disks, and DoS shared
infrastructure. The playbook is deliberately scoped to four moves:

- **(a) Recognize the escape surface** — what the sandbox still lets you reach.
- **(b) Fingerprint versions and match them to public advisories** — the exact
  runtime, library, kernel, engine, or build number, checked against
  NVD/GHSA/vendor advisories.
- **(c) Reproduce a public PoC in your own lab/container/VM** — a
  version-matched clone you own, never third-party production.
- **(d) Write the report** — evidence, version+advisory citation, impact.

Hard rules for this skill:

- **Do not invent or fabricate novel kernel, V8, eBPF, or hypervisor
  exploits.** Improvising memory corruption does not work, and a claim you
  cannot reproduce is worse than no finding at all. Where an advisory exists,
  cite it instead of shipping exploit code — reports in this class get
  accepted on version evidence + advisory + config proof more often than on
  crash output.
- **Benign proof ceiling:** `id`, `whoami`, `uid`, hostname, or reading a
  marker file you created — inside a lab context. Config-evidence proofs
  (decoded capabilities, `kubectl auth can-i` results, `whoami /priv` lists)
  require no execution at all and are preferred where they suffice.
- **Memory-corruption depth stays in your lab.** Kernel/V8/eBPF/hypervisor
  public PoCs run only against your own version-matched VMs. On a live
  target, the finding is "vulnerable version + reachable surface + advisory".
- **No persistence, no backdoors.** The one exception is variant 14's benign
  marker file proving `/tmp` reuse — disclose it and delete it in the same
  session.
- Never run destructive payloads (kernel fuzzing, crash loops, fork bombs,
  disk writes) against any target you do not own outright.

## 2. Engagement workflow

1. **Recon & confinement inventory.** Determine what sandbox you are actually
   in before anything else: language, exact version, and confinement
   mechanism (Node `vm`/vm2, restricted Python builtins, `disable_functions`,
   container, Java SecurityManager, Ruby `$SAFE`, k8s policy, hypervisor).
   Wrong mental model → wrong variant → wasted work, because escape surfaces
   differ completely per runtime. Use the fingerprinting ladder in
   `references/payloads.md` §1 — all probes there are benign.
2. **Surface mapping.** List what the sandboxed code *can* still reach (code
   evaluation, bytecode loading, reflection, file write, network, import
   path). An escape is one hop from a remaining primitive to a capability the
   sandbox claimed to block; you cannot find the hop without the inventory.
   Record the controls in place (allowlists, seccomp profile, admission
   policy, capability set) — they determine severity.
3. **Variant selection.** Route the observed signal through the table in §3
   and open the matching section in `references/variants-1.md` or
   `references/variants-2.md`. One signal often maps to several variants (a
   file read outside a jail could be a Python escape *or* a PHP
   `disable_functions` bypass); test the cheapest discriminators first.
4. **Version fingerprint & advisory match.** Pin the exact version from a
   package manifest, error banner, `phpversion()`, `uname -r`, UA string, or
   leaked source, then check NVD/GHSA/vendor advisories for *that* version
   and its fix. This is the core method of this skill: the exploit usually
   already exists publicly — your job is matching, not inventing.
5. **Safe probe.** Send the benign rung from `payloads.md` §2: version read,
   marker arithmetic, capability existence checks (`function_exists`,
   `kubectl auth can-i`, `type(LIST)`). No memory-corruption payloads and no
   PoCs at this stage — you are still confirming which sandbox you are in.
6. **Confirmation test.** Reproduce with a second, *independent* signal:
   version string plus behavior differential, config evidence plus benign
   marker read, RBAC result plus a host-path read in your lab. Two orthogonal
   signals are required because "sandbox reported vulnerable version" has
   plausible alternative explanations (backports, feature disabled) — this is
   the step juniors skip and the reason reports die in triage.
7. **Impact proof.** Climb the proof depth ladder in `payloads.md` §3 only to
   the lowest rung that proves the boundary was crossed — a marker file read,
   `uid`/hostname, one `id` — then stop. The report needs proof the boundary
   fell, not a demonstration of everything behind it.
8. **False-positive filter & report.** Work each variant's **False
   positives** section (document what you ruled out), then write the report
   with the template in §5. Redact anything token-like; attach the exact
   commands/requests with `<PLACEHOLDER>` slots.

## 3. Variant selection table

| Signal you observed | Likely variant | Reference |
|---|---|---|
| Code runs in `vm`/`runInNewContext`/vm2; stacks name `vm2` or context objects; constructor-chain walks in review | V-01 Node.js context extraction | `references/variants-1.md` |
| Python `eval`/`exec`/RestrictedPython sink; `__subclasses__`/MRO reachable; "name not defined" but object graph intact | V-02 Python scope re-alignment | `references/variants-1.md` |
| PHP target sets `disable_functions`; FFI/imap/imagick/pcntl still loaded; code sink already reached | V-03 PHP disable_functions bypass | `references/variants-1.md` |
| Inside a container: `/.dockerenv`, high `CapEff`, docker.sock mounted, `--privileged`, old `uname -r` | V-04 Docker/kernel breakout | `references/variants-1.md` |
| Java app runs a SecurityManager or plugin/script sandbox; `getSecurityManager()` non-null; reflection research applies | V-05 Java SecurityManager bypass | `references/variants-1.md` |
| Chrome/Electron/V8 build behind known in-the-wild type confusion; renderer exploit research; outdated embedded Chromium | V-06 V8 type confusion | `references/variants-1.md` |
| `uname -r` in a vulnerable kernel range *and* `unprivileged_bpf_disabled=0` or CAP_BPF present | V-07 eBPF verifier flaw | `references/variants-1.md` |
| Legacy Ruby app sets `$SAFE` around `eval`; `RUBY_VERSION` < 3.0; core-method taint bypass research | V-08 Ruby $SAFE circumvention | `references/variants-1.md` |
| Attacker supplies Lua bytecode; `load(string.dump(...))` roundtrip accepted; LuaJIT `ffi` visible | V-09 Lua bytecode/memory writes | `references/variants-2.md` |
| Pod has `hostPath` mounts (or SA can create pods); `mount` shows kubelet/host paths; no PSA restricted | V-10 Kubernetes HostPath escape | `references/variants-2.md` |
| Windows foothold with `SeImpersonatePrivilege`; RPC/135 reachable; potato-class or RPC advisory matches build | V-11 Windows RPC/token impersonation | `references/variants-2.md` |
| APK shows `exported` providers with no/enforced-weak permission; `content query` returns rows; `1=1`/`1=2` differs | V-12 Android content provider leakage | `references/variants-2.md` |
| WASM parser/decoder feature; host glue computes `ptr + len` in 32-bit math; engine version behind advisory | V-13 WASM integer overflow | `references/variants-2.md` |
| FaaS with warm instance reuse; `/tmp` writable and on the import path; marker file persists across invocations | V-14 FaaS /tmp persistence | `references/variants-2.md` |
| Guest VM shows shared folders/guest additions/hypercall surface; hypervisor fingerprint + version known | V-15 hypervisor IOCTL escape | `references/variants-2.md` |

## 4. Verification standard

A confirmed sandbox escape requires all of the following; anything less is a
lead and gets labeled as a lead:

1. **Reproducible pair.** The exact commands/requests (with `<PLACEHOLDER>`
   slots filled) and their output, produced at least twice with the same
   result — paste-ready for triage.
2. **A second, independent signal.** Two orthogonal channels: e.g. exact
   version fingerprint *and* a behavior differential (benign op that should
   be denied, succeeding); capability/config evidence *and* a benign marker
   read. One signal has alternative explanations; two do not co-occur by
   accident.
3. **Minimal-impact proof.** The lowest proof-depth rung that shows the
   boundary fell: marker file, `uid`/hostname, one `id`, or pure config
   evidence (decoded `CapEff`, `can-i` result, privilege list). Never data
   dumps, never persistence, never crashes as "proof".
4. **Version + advisory citation.** Exact version, advisory ID, and fixed
   version. In this class the fingerprint *is* evidence — but a version in a
   vulnerable range without a reachable surface (feature off, backport
   applied, sandbox not actually engaged) is a lead, not a finding.
5. **False-positive audit documented.** Name the alternative explanations
   you ruled out (sandbox never active, reflection echo, feature disabled,
   distro backport, per-invocation container) in the report's evidence.

## 5. Report template

```markdown
### Title
`<Sandbox escape> via <mechanism> at <endpoint/asset> (V-XX)`

**Severity:** <Critical/High/...> — one-line justification (which boundary
fell, what sits behind it)
**Endpoint:** <`POST /api/<path>` / container `<name>` / pod `<ns/name>` /
host `<alias>` — mechanism and auth state required>
**Summary:** 2-3 sentences: the confinement mechanism, the violated trust
assumption, the proven effect.

**Steps to reproduce:**
1. <Fingerprint: command/probe → observed version/build>
2. Send/run: `<commands or request with <PLACEHOLDER> slots>`
3. Observe: <benign proof: uid/hostname/marker content/config evidence>
4. Advisory match: <CVE/GHSA-XXXX → affected <range>, fixed in <ver>>

**Impact:** What an attacker crosses (jail → process, container → host,
guest → host, warm invocation → persistent code) and the realistic worst
case. Describe blast radius; show only the minimal proof.

**Evidence:** Redacted command/output or request/response pairs, timestamps,
version strings, advisory links. No exploit source, no credentials, no
payloads beyond the benign proof.

**Remediation:** One specific fix for this boundary (patch to <ver>, run the
eval in a separate process with OS isolation, PSA restricted, drop
capability X, remove writable dirs from the import path).

**References:** CWE-<XX>; OWASP Top 10 <A0X:2021>; <advisory ID>; variant
V-XX in sandbox-escape-testing skill.
```

## 6. Reference pointers

Read `references/variants-1.md` for variants 1-8 and `references/variants-2.md`
for variants 9-15; read `references/payloads.md` when you need request
templates, tool commands, or WAF-evasion encodings.

Each variant section is self-contained: mechanism, preconditions, numbered
detect steps, a proof-of-concept template with `<PLACEHOLDER>` slots, the
independent confirmation signal, false positives, impact phrasing, a
boundary-specific remediation, and the CWE/OWASP mapping. Match your observed
signal to §3, open that variant, and work top to bottom — and climb the
ladders in `payloads.md` only as far as impact proof requires.
