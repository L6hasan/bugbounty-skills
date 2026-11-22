# AGENTS.md — universal entry point

Any agent (OpenCode, Claude Code, Codex, Cursor, Hermes, custom) that reads this file can operate
this skill. **Read `SKILL.md` next; it is the contract.** `WORKFLOW.md` is the detailed state
machine, `references/` the depth. All are plain Markdown with no tool-specific requirements.

## What this is

An authorized bug bounty hunting loop that only reports P1/P2/P3 impact and improves itself from
disclosed research.

## Non-negotiables

1. Confirm the host is in scope before any request; write `targets/<program>/scope.md` first.
2. Check the program's excluded findings and the auto-reject list in `SKILL.md` §1. P4/P5 items
   are chain primitives — never deliverables.
3. Test only accounts you own; never touch real user data.
4. Non-destructive: no DoS, no mass scanning, no persistence, no real payments.
5. Ambiguous scope or safety → stop and ask.
6. Telegram is finding-only: `scripts/notify_telegram.py` after VERIFY, with title, description,
   steps, PoC, and impact. No status pings, no candidates, no progress messages.

## The loop

`RESEARCH → UPGRADE → RECON → HUNT → DIG → BLOCKED? → BYPASS → ESCALATE → CHAIN → VERIFY → REPORT → LEARN`

- RESEARCH: 3 extraction cards from **current (6–12 month)** disclosed reports. Record URL +
  accessed date; never cite a writeup you have not opened. Unverified techniques stay out of the
  playbooks.
- UPGRADE: promote verified methods into `references/playbooks.md`; record failures.
- HUNT/DIG: HUNT produces leads, never reports; DIG goes deep on one endpoint for 20 minutes.
- BYPASS: 5 attempts / 20 min per block. If it fails, escalate the impact axis, then chain.
- VERIFY: reproduce twice with two accounts; no proof, no finding.
- REPORT: check the program's core-ineligible list, then confirm the chain reaches ATO, sensitive
  data, RCE, or admin functionality before drafting.
- LEARN: append `learnings.md`, update `targets/<program>/state.md`, bump the version if the
  skill changed.

## Low findings are chain material

Info disclosure, reflected parameters, open redirects, verbose errors, and weak headers are
recorded with evidence and tested for combination — never reported alone. If no in-scope chain
reaches concrete impact, they go to `findings/rejected.md`.

## Severity honesty

"Think critical" means finding the worst realistic outcome and the shortest in-scope path to it.
It does not mean labeling a finding higher than the evidence. Before rating High/Critical, state
the attacker's exact preconditions and the exact data or action gained.

## Minimum proof by class

IDOR/BAC = account B reads/writes A's object · auth bypass = protected action without a valid
session or as the wrong role · SSRF = server hits your collaborator · RCE = read-only command
output · SQLi = a value you control extracted · XSS = execution in another/privileged context ·
LFI = server file contents · logic = real gain reproduced twice.

## Session close (always print)

```
Targets covered:
Verified findings (severity + one-line impact):
Blocked paths + bypass attempts:
Chains attempted:
Rejected candidates (reason):
Research cards added:
Skill changes (version):
Next steps:
```

## Drop-in prompt (for agents without skill support)

```
Operate under /root/Myskill/bugbounty-hunter. Read AGENTS.md and SKILL.md first.
Follow the loop. Report only P1/P2/P3 with reproduced impact. Never test out of scope.
Update learnings.md and the playbooks before you finish.
```
