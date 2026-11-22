# WORKFLOW — the hunt state machine

This is the detailed operating procedure behind `SKILL.md`. Any agent can resume from
`targets/<program>/state.md` without reading the whole history.

## ASCII flow

```
 [R] RESEARCH ──► [U] UPGRADE ──► [C] RECON ──► [H] HUNT ──► [D] DIG
                                                        │        │
                                                        │        ├─ lead ──► [V] VERIFY ──► [P] REPORT
                                                        │        │
                                                        └────────┴─ blocked ──► [B] BYPASS
                                                                                   │
                                                                        pass ──────┤
                                                                        fail ──► [E] ESCALATE ──► [CH] CHAIN
                                                                                                     │
                                                                                         lead ──► [V] VERIFY
                                                                                                     │
 [R] ◄──────── [L] LEARN ◄──────── [P] REPORT ◄──────────────────────────────────────────────────────┘
```

## State contract

Every state has: **entry condition, timebox, actions, exit condition, artifact**. If a state
exits by timeout without a result, record that and move to the next state — do not silently loop.

| # | State | Entry | Timebox | Exit | Artifact |
|---|---|---|---|---|---|
| R | Research | new target, or >3 days since last read | 45 min | 3 mapped cards (URL + date recorded) | `learnings.md` |
| U | Upgrade | end of session, or new confirmed/failed technique | 15 min | skill diff + version | `references/playbooks.md`, `learnings.md` |
| C | Recon | scope verified | 60–90 min | inventory with params/roles | `targets/<p>/state.md` |
| H | Hunt | ≥1 prioritized endpoint | 45 min per hypothesis | lead / negative / blocked | state file |
| D | Dig | promising endpoint | 20 min | siblings exhausted or new lead | state file |
| B | Bypass | block classified | 5 attempts / 20 min | bypass or "hard block" | state file |
| E | Escalate | hard block, or low impact | 30 min | higher-impact lead or dead end | state file |
| CH | Chain | ≥2 demonstrated leads | 30 min | end-to-end impact | finding file |
| V | Verify | lead with impact | 20 min | reproduced twice / rejected | finding file |
| P | Report | verified finding | 30 min | report complete | `reports/` |
| L | Learn | end of session | 15 min | changelog + learnings | `learnings.md` |

## Per-state procedure

### R — Research
1. Pick 3 sources from the rotation in `references/research-loop.md`.
2. Open 3–5 disclosed reports from the last 6–12 months with a bounty and raw requests. Record
   the exact URL and accessed date — never cite something you did not open.
3. Write 3 cards into `learnings.md` using the schema; mark `Verified: unverified` until the
   technique reproduces on a lab or your own setup.
4. Map each card to a concrete endpoint class on this target ("applies to").
5. Exit only when all 3 have an applies-to. Otherwise research more.

### U — Upgrade
1. Promote **verified** methods into `references/playbooks.md` (request shape + source URL).
   Unverified techniques stay in `learnings.md` marked UNVERIFIED.
2. Move disproven methods to the failed list with the disproof.
3. Add triage patterns (accepted/rejected shape, severity call, program quirk).
4. Record low findings as chain material with evidence — never as standalone reports.
5. Bump version and add a changelog line.
6. If nothing changed, write why in one line.

### C — Recon
1. Write/refresh `targets/<program>/scope.md`; verify every host before requesting.
2. Enumerate subdomains, live hosts, endpoints, JS, API specs, auth flows.
3. Build the endpoint inventory with columns: host, path, method, params, auth, role, object,
   tenant, notes, status.
4. Rank by expected impact using §1 of `SKILL.md`; pick the top 5.
5. Exit when the top 5 each have a named hypothesis.

### H — Hunt
1. Pick one endpoint + one class.
2. Write the hypothesis and expected impact in the state file.
3. Send the minimum probe; capture raw request/response.
4. Classify: lead / negative / blocked.
5. Lead → D or V. Negative → next hypothesis. Blocked → B.
6. Every five candidates, run the drift audit: ≥3 at P4/P5 means change asset or class.

### D — Dig
Run the 8-item depth checklist in `SKILL.md` §6. Record every attempt. Stop at 20 minutes even
if interesting — write the next step and move on. Deep on one endpoint, not wide on ten.

### B — Bypass
1. Classify the control that blocked you (taxonomy in `references/escalation-ladder.md`).
2. Work the ladder in order; log each attempt with payload shape and response delta.
3. Max 5 attempts / 20 minutes. A WAF block is not a finding.
4. Pass → V or continue D. Fail → E.

### E — Escalate
Move along the impact axes, cheapest first:
- same object, sibling endpoint
- same endpoint, other role
- same endpoint, other tenant
- same data, other verb (read → write)
- same bug, bulk/export/report variant
- combine with an existing lead

### CH — Chain
1. List links; mark each demonstrated or assumed.
2. Never report a chain with an assumed link — go demonstrate it or downgrade to the last
   demonstrated link.
3. Assign severity at the final impact.
4. Keep one evidence artifact per link.

### V — Verify
Two accounts, clean rerun, minimal sequence, one-sentence impact. Reject on any inconsistency.

### P — Report
Use `references/report-template.md`. Under 10 minutes to reproduce. Include CVSS and the
program's severity label. Add "why this is not <likely rejection>". Pre-report gate: check the
program's core-ineligible list, and state the exact preconditions plus the exact data or action
gained. No concrete impact → not a report.

### L — Learn
Append learnings, update state file, output the session close block from `SKILL.md` §10.
Telegram: only a verified finding goes out, via `scripts/notify_telegram.py`. If the session has
no verified finding, send nothing.

## Resume protocol

When picking up an existing target:

1. Read `targets/<program>/state.md` — current state, open leads, blockers, next step.
2. Read `learnings.md` — failed list first (do not repeat dead ends).
3. Re-verify scope if the file is older than 7 days.
4. Continue from the recorded state; do not restart recon.

## Stop conditions (abort the whole session and report to the human)

- Scope or authorization is ambiguous.
- A test would touch real user data, real money, or production availability.
- The only path to impact needs destructive action.
- Evidence suggests you are not the first researcher and the issue is being actively exploited.
