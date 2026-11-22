# Writeup sources, queries, and the extraction card

Read methods, not war stories. Before a new target: produce **3 cards** mapped to endpoints on
that target. After every session: add what you used and what failed.

## Sources (in priority order)

1. **HackerOne Hacktivity** — https://hackerone.com/hacktivity (filter: disclosed, severity
   high/critical, bounty awarded, last 12 months). Best source for accepted-report shape.
2. **Bugcrowd** — https://bugcrowd.com/crowdstream and https://bugcrowd.com/resources
   (Crowdstream = disclosed submissions; research blog = technique deep dives).
3. **Intigriti** — https://www.intigriti.com/researchers/blog and their writeup challenges.
4. **PortSwigger** — https://portswigger.net/research and the Web Security Academy lab
   solutions; the labs are the cleanest reproducible technique source.
5. **PentesterLand** — https://pentester.land/writeups/ (weekly aggregated list; searchable).
6. **Medium / InfoSec Writeups** — https://medium.com/tag/bug-bounty,
   https://infosecwriteups.com (quality varies; prefer posts with raw requests).
7. **YesWeHack** — https://www.yeswehack.com/learn-bug-bounty and disclosed reports.
8. **GitHub indexes** — `reddelexc/hackerone-reports`, `nahamsec/Resources-for-Beginner-Bug-
   Bounty-Hunters`, nuclei-templates for detection patterns.

## Search queries that surface method, not fluff

```
site:hackerone.com/reports "IDOR" "bounty" -inurl:reports/xxxx
site:medium.com "bug bounty" "auth bypass" "steps to reproduce"
site:pentester.land "OAuth" "redirect_uri"
site:portswigger.net/research "request smuggling" OR "cache poisoning"
site:infosecwriteups.com "GraphQL" "IDOR"
"writeup" "P1" "account takeover" "reset token"
```

## Extraction card (append to learnings.md)

```
### YYYY-MM-DD — <short technique name>
Source: <url>
Class: IDOR | auth | OAuth | SQLi | XSS | SSRF | RCE | LFI | XXE | logic | misconfig
Precondition: <auth level, feature, stack, tenant model>
Signal: <what you observe that says "try this here">
Request shape: <METHOD path — params/body/headers, redacted>
Root cause: <why the server trusts the wrong thing>
Bypass: <filter/WAF/encoding nuance that made it work>
Chain potential: <what it becomes at P1/P2>
Applies to: <endpoint class on the current target>
Status: untested | tested:<target>:<result>
```

## Rules

- A card without a "Signal" and "Applies to" is not usable — rewrite or drop it.
- Prefer 3 cards you will actually test over 30 you skimmed.
- When a card leads to a confirmed finding, promote the method into `references/playbooks.md`.
- When it fails, record why in the failed list so the next session does not repeat it.
