#!/usr/bin/env python3
"""coverage-review.py — reconcile inventory, find coverage gaps, emit >=5 tasks.

This is the step that must run at the END of every cycle so the loop cannot idle.
It reads the coverage matrix + endpoint inventory, computes what has NOT been reviewed,
and *materialises* the gaps as new UNTESTED rows in coverage.tsv (which is what the
slicer dispatches on) plus a human/task-queue-readable gap report.

usage:
  coverage-review.py --slug <slug> --state <state_dir> --pst <principal_state_dir>
                     [--hosts <allowlist file>] [--min-tasks 5]

exit codes: 0 ok, 2 nothing to do (should be impossible while classes are missing)

Design notes
- Gaps are computed per (host, class) pair against a canonical class list; a class with
  ZERO rows on a host that carries sensitive surface is a gap, not an absence of bug.
- Only classes the doctrine accepts are proposed (no headers/CORS/TLS noise classes).
- Every proposed row carries a reason so a worker knows WHY it was assigned.
- Idempotent: a (host, endpoint, method, class) key is never duplicated.
"""
import argparse
import collections
import json
import os
import re
import sys
import time

# canonical reportable classes, in dispatch order (highest expected yield first)
CLASSES = [
    "authz_idor", "auth_bypass", "sqli", "ssrf", "rce", "xss", "xss_stored",
    "lfi_file_read", "path_traversal", "ssti", "deserialization", "xxe",
    "oauth_bypass", "jwt_session_forgery", "api_broken_auth", "graphql_authz",
    "file_upload", "business_logic", "csrf", "request_smuggling", "cache_poisoning",
    "data_exposure",
]

# classes that must exist on any host that serves an authenticated app
HIGH_VALUE = ["authz_idor", "api_broken_auth", "data_exposure", "business_logic"]
PRIMS = {"auth_bypass", "sqli", "ssrf", "rce", "xss", "xss_stored", "lfi_file_read",
         "ssti", "deserialization", "xxe", "oauth_bypass", "jwt_session_forgery",
         "graphql_authz", "request_smuggling", "cache_poisoning", "csrf", "file_upload"}

# Synthetic probe paths, used ONLY when a host has no inventoried carrier of the needed
# shape. They are honest test targets (a route to confirm), never a claim that the route
# exists — the task reason says so explicitly.
PROBE_FOR = {
    "authz_idor": "/api/users", "api_broken_auth": "/api/", "data_exposure": "/api/",
    "business_logic": "/api/cart", "sqli": "/search?q=", "ssrf": "/api/fetch?url=",
    "rce": "/api/convert", "xss": "/search?q=", "xss_stored": "/api/comments",
    "lfi_file_read": "/download?file=", "path_traversal": "/files/",
    "ssti": "/render", "deserialization": "/api/import", "xxe": "/api/import",
    "oauth_bypass": "/oauth/authorize?redirect_uri=", "jwt_session_forgery": "/api/me",
    "graphql_authz": "/graphql", "file_upload": "/api/upload", "csrf": "/api/settings",
    "request_smuggling": "/", "cache_poisoning": "/",
}

HDR = ["host", "endpoint", "method", "vuln_class", "status", "evidence_path", "reason",
       "auth_state", "role", "updated"]


def load_rows(path):
    rows = {}
    order = []
    try:
        lines = open(path, errors="replace").read().splitlines()
    except FileNotFoundError:
        return rows, order
    for i, line in enumerate(lines):
        if i == 0 or not line.strip():
            continue
        p = line.split("\t")
        if len(p) < 5:
            continue
        p += [""] * (len(HDR) - len(p))
        key = (p[0], p[1], p[2], p[3])
        if key not in rows:
            order.append(key)
        rows[key] = p
    return rows, order


def write_rows(path, rows, order):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\t".join(HDR) + "\n")
        for k in order:
            f.write("\t".join(rows[k][:len(HDR)]) + "\n")
    os.replace(tmp, path)


def host_profile(rows):
    """Per host: which classes have any row, how many are untested, what endpoints exist."""
    prof = collections.defaultdict(lambda: {"classes": set(), "untested": 0,
                                            "total": 0, "endpoints": set(),
                                            "auth_endpoints": set()})
    for (h, ep, m, cls), p in rows.items():
        d = prof[h]
        d["classes"].add(cls)
        d["total"] += 1
        if p[4] in ("UNTESTED", "DISCOVERED", "NOT_TESTED", "", "LEAD_UNTESTED"):
            d["untested"] += 1
        if ep and ep != "* (catch-all baseline)":
            d["endpoints"].add(ep)
            low = ep.lower()
            if any(t in low for t in ("api", "account", "user", "profile", "admin",
                                      "login", "auth", "token", "order", "payment",
                                      "upload", "export", "graphql")):
                d["auth_endpoints"].add(ep)
    return prof


def endpoint_kind(ep):
    """Classify an endpoint so a class is only paired with a carrier that can carry it."""
    low = ep.lower()
    if "/graphql" in low:
        return "graphql"
    if any(t in low for t in ("upload", "attach", "file", "media", "import", "avatar")):
        return "upload"
    if any(t in low for t in ("export", "download", "report", "invoice", "pdf", "print")):
        return "export"
    if any(t in low for t in ("admin", "manage", "console", "internal")):
        return "admin"
    if any(t in low for t in ("search", "filter", "query", "lookup")) or "?q=" in low:
        return "search"
    if any(t in low for t in ("login", "signin", "auth", "token", "oauth", "sso",
                              "reset", "forgot", "register", "signup", "mfa", "otp")):
        return "auth"
    if any(t in low for t in ("api", "rest", "bff", "svc", "v1", "v2", "rpc")):
        return "api"
    if any(t in low for t in (".js", ".css", ".map", ".json", ".xml", ".txt", "/static/")):
        return "static"
    return "page"


# which endpoint kinds can carry which class (no pairing a class with a page that cannot host it)
CARRIER = {
    "authz_idor": {"api", "admin", "page", "upload", "export", "graphql"},
    "api_broken_auth": {"api", "admin", "graphql", "export"},
    "data_exposure": {"api", "admin", "export", "static", "page", "graphql"},
    "business_logic": {"api", "page", "export"},
    "auth_bypass": {"auth", "api", "admin"},
    "oauth_bypass": {"auth", "api"},
    "jwt_session_forgery": {"auth", "api"},
    "sqli": {"search", "api", "page", "export"},
    "ssrf": {"api", "upload", "export", "page"},
    "rce": {"api", "upload", "export", "admin"},
    "xss": {"search", "page", "api", "upload"},
    "xss_stored": {"api", "page", "upload", "admin"},
    "lfi_file_read": {"export", "upload", "page", "api"},
    "path_traversal": {"export", "upload", "page", "static", "api"},
    "ssti": {"page", "export", "api"},
    "deserialization": {"api", "auth", "page"},
    "xxe": {"upload", "api", "auth"},
    "graphql_authz": {"graphql"},
    "file_upload": {"upload"},
    "csrf": {"api", "page", "admin"},
    "request_smuggling": {"page", "api"},
    "cache_poisoning": {"page", "static", "api"},
}


def is_probeable(ep):
    """Reject wildcard/placeholder/aggregate endpoint strings — they cannot be probed.

    Two classes of junk live in long-lived ledgers and must be filtered by NAME, not just by
    shape, or the carrier lookup treats them as real endpoints and refills the queue forever
    (measured on FIBA p93: 5 new rows per run, never converging):

    1. coverage-review's own former synthetic placeholders: `/api_host`, a bare `/`.
    2. ad-hoc INVENTORY LABELS written by earlier passes: `/app_routes_web`,
       `/server_routes_web_hosts`, `/api_host`. These describe a body of work, not a path.
    """
    if not ep or len(ep) > 160:
        return False
    if any(c in ep for c in ("*", "<", "{", "}", ",", " ")):
        return False
    e = ep.strip()
    if e in ("/", "api_host", "/api_host"):
        return False
    # inventory labels: a path-shaped token containing an underscore-suffix, e.g. _web/_hosts
    if re.search(r"_(web|hosts|routes)$", e, re.I):
        return False
    return True


def gap_tasks(rows, prof, allowlist, min_tasks):
    """Return ordered gap proposals: (host, endpoint, method, class, reason)."""
    cand = []
    noc = collections.defaultdict(list)   # host -> classes with no carrier (reported, not queued)
    for host, d in prof.items():
        if allowlist and host not in allowlist:
            continue
        if " " in host or "/" in host:
            continue  # malformed aggregate host row
        kinds = collections.defaultdict(list)
        for ep in d["endpoints"]:
            if is_probeable(ep):
                kinds[endpoint_kind(ep)].append(ep)
        if not kinds:
            continue
        untested_weight = min(d["untested"], 200) // 20   # 0..10, rewards unexplored surface
        for rank, cls in enumerate(CLASSES):
            if cls in d["classes"]:
                continue
            carriers = CARRIER.get(cls, {"api", "page"})
            pool = [ep for k in carriers for ep in kinds.get(k, [])]
            synthetic = False
            if not pool:
                # NO inventoried carrier of the right shape on this host.
                #
                # Do NOT invent a probe path here. Measured failure mode (FIBA, p93): the first
                # version fell back to PROBE_FOR and produced /api_host cells for every class on
                # every host; each time a worker closed one, the next class in the list appeared,
                # so the queue refilled forever and "untested" never reached zero. A synthetic
                # row is the tool inventing work, and it buries the real gaps.
                #
                # Correct behaviour: record the absence in the report so a human sees which
                # classes have no testable carrier, and emit no row. The class is not a gap on
                # this host — there is nothing on this host to carry it.
                noc[host].append(cls)
                continue
            # prefer the endpoint most likely to be sensitive for this class
            def score(ep):
                s = 0
                low = ep.lower()
                if cls in ("authz_idor", "api_broken_auth") and any(
                        t in low for t in ("api", "admin", "user", "account", "order")):
                    s -= 5
                if cls in ("sqli", "xss") and ("?" in low or "search" in low):
                    s -= 4
                if cls == "data_exposure" and any(t in low for t in ("api", "export")):
                    s -= 3
                s += len(ep) / 200.0          # prefer short, concrete paths on a tie
                return (s, ep)
            ep = sorted(pool, key=score)[0]
            pri = 0
            if cls in HIGH_VALUE:
                pri += 40
            if cls in PRIMS:
                pri += 20
            pri += untested_weight
            if kinds.get("api"):
                pri += 8
            if kinds.get("admin"):
                pri += 6
            reason = (f"COVERAGE GAP: class `{cls}` has ZERO rows on this host "
                      f"({d['total']} rows, {d['untested']} untested, "
                      f"{len(d['endpoints'])} endpoints, carriers: "
                      f"{','.join(sorted({endpoint_kind(e) for e in pool}))}). "
                      + ("SYNTHETIC probe path — confirm the route exists (diff to the host's "
                         "soft-404 control) before testing the class. " if synthetic else "")
                      + "Assigned by coverage-review.")
            cand.append((-pri, rank, host, ep, "GET", cls, reason))
    cand.sort()
    # Distribute the task floor across the hosts we actually have: with one host, the cap
    # must rise to the floor, otherwise a single-host target can never produce 5 tasks.
    live = {h for h in prof if (not allowlist or h in allowlist) and " " not in h}
    cap = max(2, -(-max(min_tasks, 5) // max(len(live), 1)))
    out, seen, per_host = [], set(), collections.Counter()
    for _, _, h, ep, m, cls, why in cand:
        if (h, cls) in seen or per_host[h] >= cap:
            continue
        seen.add((h, cls))
        per_host[h] += 1
        out.append((h, ep, m, cls, why))
        if len(out) >= max(min_tasks, 5):
            break
    return out, noc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--slug", required=True)
    ap.add_argument("--state", required=True)
    ap.add_argument("--pst", required=True)
    ap.add_argument("--hosts")
    ap.add_argument("--min-tasks", type=int, default=5)
    a = ap.parse_args()

    cov = os.path.join(a.state, "loop", "coverage.tsv")
    rows, order = load_rows(cov)
    allow = None
    if a.hosts and os.path.exists(a.hosts):
        allow = {l.strip() for l in open(a.hosts, errors="replace")
                 if l.strip() and not l.startswith("#")}

    prof = host_profile(rows)
    tasks, noc = gap_tasks(rows, prof, allow, a.min_tasks)
    ts = time.strftime("%Y-%m-%dT%H:%MZ", time.gmtime())

    added = 0
    for host, ep, m, cls, why in tasks:
        key = (host, ep, m, cls)
        if key in rows:
            continue
        rows[key] = [host, ep, m, cls, "UNTESTED", "", why, "unknown", "none", ts]
        order.append(key)
        added += 1

    if added:
        write_rows(cov, rows, order)

    # task queue (what the principal shows / workers pull) + gap report
    tq = os.path.join(a.pst, "task_queue.json")
    payload = {"target": a.slug, "updated": ts,
               "source": "coverage-review", "tasks": [
                   {"id": f"GAP-{i+1:03d}", "host": h, "endpoint": ep, "method": m,
                    "class": c, "reason": w, "status": "queued", "created": ts}
                   for i, (h, ep, m, c, w) in enumerate(tasks)]}
    os.makedirs(a.pst, exist_ok=True)
    json.dump(payload, open(tq, "w"), indent=1)

    rep = os.path.join(a.pst, "coverage_review.md")
    with open(rep, "w") as f:
        f.write(f"# Coverage review — {a.slug} — {ts}\n\n")
        f.write(f"rows={len(rows)} hosts={len(prof)} gaps_queued={len(tasks)} "
                f"new_rows_added={added}\n\n## Per-host coverage\n\n")
        f.write("| host | rows | untested | endpoints | classes present | missing high-value |\n")
        f.write("|---|---|---|---|---|---|\n")
        for h in sorted(prof):
            d = prof[h]
            miss = [c for c in CLASSES if c not in d["classes"]]
            f.write(f"| {h} | {d['total']} | {d['untested']} | {len(d['endpoints'])} | "
                    f"{len(d['classes'])} | {', '.join(miss[:6])}"
                    f"{' …' if len(miss) > 6 else ''} |\n")
        f.write("\n## Queued tasks\n\n")
        if not payload["tasks"]:
            f.write("_None. Every reportable class has a carrier on this host and either a row "
                    "or no carrier at all — see the no-carrier table below._\n")
        for t in payload["tasks"]:
            f.write(f"- **{t['id']}** `{t['method']} {t['endpoint']}` on `{t['host']}` "
                    f"— class `{t['class']}`\n  - {t['reason']}\n")
        f.write("\n## Classes with NO carrier on a host (not queued, by design)\n\n")
        f.write("A class is not a gap where there is nothing that could carry it. These are "
                "recorded so the absence is visible, not converted into invented work.\n\n")
        for h in sorted(noc):
            f.write(f"- `{h}`: {', '.join(noc[h])}\n")

    print(json.dumps({"rows": len(rows), "hosts": len(prof), "queued": len(tasks),
                      "new_rows": added, "queue": tq, "report": rep}))
    # Exit 0 whenever the review COMPLETED. Zero gaps is a valid, healthy result: it means every
    # class with a carrier already has a row. Only signal exhaustion when there is genuinely
    # untested surface left that could not be turned into a task.
    untested_left = sum(1 for p in rows.values()
                        if len(p) > 4 and p[4] in ("UNTESTED", "DISCOVERED", "NOT_TESTED", ""))
    return 0 if (tasks or untested_left == 0) else 2


if __name__ == "__main__":
    sys.exit(main())
