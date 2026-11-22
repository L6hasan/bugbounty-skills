# targets/<program>/scope.md template

Copy to `targets/<program>/scope.md` and fill before the first request. Unknown is a valid
value; a guess is not.

```
# <Program> — scope

Program / platform: <HackerOne | Bugcrowd | Intigriti | YesWeHack | self-hosted>
Policy URL:
Last verified: YYYY-MM-DD
Authorization: <published program | written engagement | own asset | lab>

## In scope (exact)
- https://...        <type> <value> <notes>

## Wildcards
- *.example.com — covers <what>; excludes <what>

## Out of scope / excluded
- hosts:
- paths:
- vuln classes (copy the program's excluded-findings list verbatim):
- testing constraints (rate limit, no DoS, no real payments, no email sending, windows):

## Required headers / researcher identity
- User-Agent suffix:
- Custom header:
- Registered account/email:

## Bounty table
| Severity | Web | API | Mobile |

## Auth and accounts
- Mechanism: session | JWT | OAuth | SAML
- Roles I control: <role A>, <role B>
- Tenants I control:
- Credentials location: <secret store, never in this file>

## Stack notes (verified, not guessed)
- Framework / server / CDN / WAF:
- API base(s):
- Identifier types:

## Program quirks
- Duplicate policy:
- Severity vocabulary:
- What they have rejected before:
```
