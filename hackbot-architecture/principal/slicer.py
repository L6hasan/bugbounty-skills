#!/usr/bin/env python3
"""slicer.py — cut the coverage matrix into disjoint discipline slices.

usage: slicer.py <coverage.tsv> <out_dir> [max_cells_per_slice]

Writes <out_dir>/<discipline>.txt for each non-empty bucket and prints a JSON summary.
Row identity = host|endpoint|method|class. Only UNTESTED/DISCOVERED rows are sliced;
a cell already TESTED/CANDIDATE/VALIDATED is never re-assigned.
"""
import collections, json, os, sys, time

BUCKETS = {
    "injection": {"sqli", "rce", "command_injection", "ssti", "xxe", "deserialization",
                  "path_traversal", "lfi_file_read"},
    "serverside": {"auth_bypass", "authz_idor", "api_broken_auth", "session_privesc",
                   "jwt_session_forgery", "oauth_bypass", "graphql_authz", "request_smuggling",
                   "file_upload", "data_exposure", "ssrf"},
    "clientside": {"xss", "prototype_pollution", "open_redirect", "host_header_injection",
                   "csrf", "info_disclosure_poc"},
    "business": {"business_logic", "cloud_infra", "supply_chain", "tenant_isolation"},
}
WANT = {"UNTESTED", "DISCOVERED", "NOT_TESTED", ""}


def main():
    tsv, out = sys.argv[1], sys.argv[2]
    cap = int(sys.argv[3]) if len(sys.argv) > 3 else 25
    os.makedirs(out, exist_ok=True)
    slices = collections.defaultdict(list)
    seen = set()
    total = 0
    try:
        lines = open(tsv, errors="replace").read().splitlines()
    except FileNotFoundError:
        lines = []
    for i, line in enumerate(lines):
        if i == 0 or not line.strip():
            continue
        p = line.split("\t")
        if len(p) < 5:
            continue
        host, ep, method, cls, status = p[0], p[1], p[2], p[3], p[4]
        total += 1
        if status not in WANT:
            continue
        k = (host, ep, method, cls)
        if k in seen:
            continue
        seen.add(k)
        for name, classes in BUCKETS.items():
            if cls in classes:
                if len(slices[name]) < cap:
                    slices[name].append({"host": host, "endpoint": ep, "method": method,
                                         "class": cls, "reason": p[6] if len(p) > 6 else ""})
                break
    summary = {}
    for name, rows in slices.items():
        path = os.path.join(out, name + ".txt")
        with open(path, "w") as f:
            for r in rows:
                f.write("%-40s %-6s %-28s %s\n" % (r["host"][:40], r["method"][:6],
                                                    r["endpoint"][:60], r["class"]))
        summary[name] = len(rows)
    print(json.dumps({"total_rows": total, "slices": summary,
                      "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}))


if __name__ == "__main__":
    main()
