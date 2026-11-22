# Research loop — how the skill keeps upgrading itself

The skill is only as good as the last techniques added to it. This file defines the reading
rotation, the extraction format, and the promotion rules that turn a writeup into a reusable
method.

## 1. Source rotation

Read 3 sources per session. Rotate so no single feed dominates.

| Slot | Sources |
|---|---|
| A | HackerOne Hacktivity (disclosed, bounty, high/critical, last 12 months) |
| B | Bugcrowd Crowdstream + Bugcrowd research blog |
| C | PortSwigger research + Web Security Academy lab solutions |
| D | Intigriti blog/writeups + YesWeHack learn |
| E | PentesterLand weekly list |
| F | Medium `tag/bug-bounty` + InfoSec Writeups |
| G | GitHub indexes: `reddelexc/hackerone-reports`, nuclei-templates |

Default rotation: A → C → E → B → F → D → G → repeat. Skip a slot only if it produced nothing
usable last time; record the skip.

## 2. Freshness and quality filter

**Freshness**
- Prefer the **last 6–12 months**. Fetch the page now; do not rely on memory, a search snippet,
  or a summarizer's paraphrase.
- Record `Source URL` and `Accessed` date on every card. No URL → not a card.
- **Never cite a writeup you have not opened.** If it will not load, drop it rather than cite it.
- A technique older than 24 months is allowed only if it is foundational (e.g. a parser quirk or
  a protocol flaw), and must say why it still applies.

**Keep a report only if it has:**
- a disclosed report or a reproducible lab, **and**
- a raw request/response or exact payload shape, **and**
- a stated root cause (not just "I found an IDOR"), **and**
- relevance to web/API/mobile classes on in-scope-style targets.

Discard: news, tool releases, "top 10" listicles, reports without requests, content that only
describes an outcome with no method.

## 3. Extraction card

Append to `learnings.md`:

```
### YYYY-MM-DD — <short technique name>
Source URL: <exact url you opened>
Accessed: YYYY-MM-DD
Class: IDOR | auth | OAuth | SQLi | XSS | SSRF | RCE | LFI | XXE | logic | misconfig
Precondition: <auth level, feature, stack, tenant model>
Signal: <what you observe that says "try this here">
Request shape: <METHOD path — params/body/headers, redacted>
Root cause: <why the server trusts the wrong thing>
Bypass: <filter/WAF/encoding nuance that made it work>
Chain potential: <what it becomes at P1/P2>
Applies to: <endpoint class on the current target>
Verified: unverified | lab:<date> | target:<name>:<date>
Status: untested | tested:<target>:<result>
```

A card without `Signal`, `Applies to`, and a real `Source URL` is not usable. Rewrite or drop it.

**Verification gate.** Try the technique on a lab you control or on your own test setup. If it
does not reproduce, either mark it `Verified: unverified` and keep it as a hypothesis, or discard
it. An unverified technique is never promoted into `references/playbooks.md` or `SKILL.md`.

## 4. Promotion rules (this is the "upgrade" step)

| Event | Action |
|---|---|
| Technique verified on a lab, or confirmed on target | Promote into `references/playbooks.md` with request shape + source URL; bump MINOR |
| Technique reproduced but not yet confirmed on a target | Keep in `learnings.md`, `Verified: lab:<date>`; do not promote yet |
| Technique does not reproduce | Mark UNVERIFIED or move to Failed with the disproof |
| Card fails on a target | Move to Failed with the disproof; keep the card for other targets |
| Technique is contradicted by evidence | Edit the playbook, note date, bump PATCH |
| Structural change to the loop | Bump MAJOR |
| Duplicate of an existing method | Merge, keep the better request shape |

Promotion is not "copy the writeup". It is: strip the target-specific details, keep the
precondition → signal → request → root cause → bypass → chain, and keep the citation.

## 5. Killing stale knowledge

Monthly:
- Delete or mark deprecated techniques that no longer work (framework patched, program dead).
- Re-test one promoted technique on a current target; if it fails, annotate why.
- Check that every playbook entry has a request shape and a false-positive trap.
- Verify source links still resolve; replace dead ones.

Stale playbooks are worse than none: they send the next agent down a dead path with confidence.

## 6. Research queue

Maintain a short queue at the top of `learnings.md`:

```
## Research queue
- [ ] <technique> — <url> — applies to <class> — priority H/M/L
- [x] <done technique> — promoted on YYYY-MM-DD
```

Keep 5–10 items. Do not let it grow into a reading list; it is a work queue.

## 7. Definition of "skill upgraded"

A session upgraded the skill if at least one of these is true:
- a **verified** method exists in `references/playbooks.md`;
- a failed method is recorded with a disproof;
- a triage pattern is recorded;
- a contradiction is fixed and the changelog notes it.

Research cards that are still UNVERIFIED are inventory, not an upgrade. They may be added to the
queue and to `learnings.md`, but they do not change the playbook or the version.

If none of the above happened, write one line explaining why (e.g. "no new technique encountered;
two dead ends recorded"). "Nothing to add" is acceptable once; three sessions in a row means the
research loop is not running.
