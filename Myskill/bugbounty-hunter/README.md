# bugbounty-hunter

A portable, self-improving bug bounty hunting skill. Markdown only — no runtime, no tool
dependencies. Any agent that can read files and send HTTP requests can use it.

## Layout

| File | Role | Read when |
|---|---|---|
| `AGENTS.md` | Universal entry point + drop-in prompt | Always, if your agent reads AGENTS.md |
| `SKILL.md` | The contract: rules, impact gate, the loop | Always |
| `WORKFLOW.md` | State machine: entry/exit, timeboxes, resume | Running or resuming a hunt |
| `references/research-loop.md` | Source rotation, card schema, promotion rules | Before a new target |
| `references/playbooks.md` | Per-class probes, proof, false-positive traps | During HUNT/DIG |
| `references/escalation-ladder.md` | Block taxonomy, bypass menu, chain patterns | When blocked |
| `references/writeup-sources.md` | Sources, queries, extraction card | Research |
| `references/report-template.md` | Report format + severity reasoning | Writing up |
| `learnings.md` | Compounding memory + research queue | Start and end of session |
| `targets/_template/` | `scope.md` + `state.md` templates | New target |
| `scripts/notify_telegram.py` | The only approved Telegram sender (validates a verified finding) | After VERIFY |

## Notifications

Telegram is **finding-only**. There is exactly one sender:

```bash
python3 scripts/notify_telegram.py findings/<finding>.json
```

It refuses unless the JSON is confirmed/verified and carries title, description, at least three
reproduction steps, a PoC, an impact statement, and a P1–P3 severity. Use `--dry-run` to validate
without sending. Background-session pings in the Telegram bot are disabled
(`TRACK_BACKGROUND_SESSIONS=false`); status, candidates, and progress are never sent.

## Install

**OpenCode / Claude Code (global):**

```bash
mkdir -p ~/.config/opencode/skills
ln -sfn /root/Myskill/bugbounty-hunter ~/.config/opencode/skills/bugbounty-hunter
# Claude Code compatibility:
ln -sfn /root/Myskill/bugbounty-hunter ~/.claude/skills/bugbounty-hunter
```

**Project-local:** copy or symlink to `.opencode/skills/bugbounty-hunter/`.

**Any other agent:** point it at `AGENTS.md`, or paste the drop-in prompt at the bottom of that
file. Nothing else is required.

## First run on a target

```bash
mkdir -p targets/<program>
cp targets/_template/scope.md targets/<program>/scope.md   # fill before any request
cp targets/_template/state.md targets/<program>/state.md
```

Then: RESEARCH (3 cards) → RECON → pick top 5 hypotheses → HUNT → DIG → verify.

## Maintenance

- After every session: append `learnings.md`, update `targets/<program>/state.md`, and promote
  anything confirmed into `references/playbooks.md`.
- Bump the version and add a changelog line when the skill changes.
- Monthly: prune stale techniques and dead source links (`references/research-loop.md` §5).

## Design principles

1. **Impact floor** — P3 minimum, Medium needs data or action. P4/P5 have an explicit reject list.
2. **Chain material, not reports** — low findings are recorded and combined; only the chain is
   reported.
3. **Evidence over volume** — one reproduced auth bypass beats twenty speculative findings.
4. **Depth over breadth** — 20 minutes digging one endpoint, then move.
5. **Escalate, don't grind** — bypass fails → change the impact axis → chain.
6. **Fresh research only** — 6–12 month sources, opened URLs, verified before promotion.
7. **Compound** — every session must leave the skill better, or say why it could not.
