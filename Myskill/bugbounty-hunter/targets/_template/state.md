# targets/<program>/state.md template

Copy to `targets/<program>/state.md`. This is the resume file: any agent must be able to read it
and continue without the chat history.

```
# <Program> — hunt state

Updated: YYYY-MM-DD HH:MM
Current state: R | U | C | H | D | B | E | CH | V | P | L
Current focus: <host + endpoint + class>
Time spent this session: <h>

## Scope snapshot
- In-scope hosts: <n>
- Excluded: <classes/hosts>
- Scope file verified: YYYY-MM-DD

## Top hypotheses
| # | Endpoint | Class | Expected impact | Status |
|---|----------|-------|-----------------|--------|
| 1 |          |       |                 | open   |

## Open leads
| Lead | Evidence | Next step | Age |
|------|----------|-----------|-----|

## Blocked paths
| Endpoint | Block type | Attempts (max 5) | Result | Escalated to |
|----------|-----------|------------------|--------|--------------|

## Chain candidates
| Link 1 | Link 2 | Final impact | Valid? |
|--------|--------|--------------|--------|

## Dead ends (do not retest)
- <endpoint> — <why>

## Confirmed findings
| Finding | Severity | Report |
|---------|----------|--------|

## Next action (one line)
<the single next request or decision>
```
