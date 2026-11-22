#!/usr/bin/env python3
"""phelp.py — state helpers for the principal supervisor.

Subcommands:
  merge   <findings_dir> <wave_glob> <slug> <cycle>
          Append new CANDIDATE JSON lines from wave files into candidates.jsonl,
          deduped on host|endpoint|class against candidates/confirmed/rejected.
          Prints JSON {new, dupes, bad}.
  verdict <findings_dir> <verdict_file>
          Apply validation verdicts: VERIFIED -> confirmed.jsonl (status VALIDATED),
          everything else -> rejected.jsonl. Prints JSON counts.
  cov     <coverage_tsv> <out_json>
          Write a coverage summary {total, by_status, by_class, untested_top}.
  assets  <state_dir> <out_json>
          Summarise the deterministic discovery artefacts into assets.json.

Every ledger is append-only. Nothing here truncates.
"""
import collections, glob, json, os, re, sys, time

STATUSES = ["NEW", "RESEARCHING", "NEEDS_APPROVAL", "VALIDATING", "VERIFIED",
            "REPORT_READY", "REPORTED", "DUPLICATE", "REJECTED", "INCONCLUSIVE",
            "OUT_OF_SCOPE"]


def jline(p):
    try:
        with open(p, errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except Exception:
                    continue
    except FileNotFoundError:
        return


def key_of(d):
    return "|".join(str(d.get(k, "") or "").lower() for k in
                    ("host", "asset", "endpoint", "class", "vuln_class"))


# ── deterministic P4/P5 floor (doctrine §2 / HackerOne Core Ineligible Findings) ─────────────
# The LLM validator can be lenient or lazy. This gate is MECHANICAL: an ineligible-class candidate is
# tagged at merge time and can NEVER be promoted to a deliverable, whatever the judge concluded.
# It is retained with its evidence as a CHAIN PRIMITIVE (doctrine: hold it, keep digging, chain it).
INELIGIBLE_CLASS = re.compile(
    r"(security[\s_-]*header|x xss|content.security.policy|\bcsp\b|x.frame|\bhsts\b|"
    r"cookie[\s_-]*flag|httponly|samesite|secure[\s_-]*flag|"
    r"\btls\b|\bssl\b|cipher|weak[\s_-]*(protocol|cipher)|certificate|padding[\s_-]*oracle|"
    r"\bspf\b|\bdkim\b|\bdmarc\b|"
    r"version[\s_-]*disclosure|software[\s_-]*version|\bbanner\b|"
    r"stack[\s_-]*trace|path[\s_-]*disclosure|directory[\s_-]*listing|descriptive[\s_-]*error|"
    r"clickjack|ui[\s_-]*redress|"
    r"self[\s_-]*xss|csv[\s_-]*injection|autocomplete|mixed[\s_-]*content|"
    r"rate[\s_-]*limit|brute[\s_-]*force|"
    r"account[\s_-]*oracle|user[\s_-]*enumeration|email[\s_-]*enumeration|enumeration|"
    r"content[\s_-]*spoof|text[\s_-]*injection|tabnabb|broken[\s_-]*link|"
    r"outdated[\s_-]*browser|eol[\s_-]*browser|"
    r"best[\s_-]*practice|missing[\s_-]*security|"
    r"open[\s_-]*redirect|logout[\s_-]*csrf|informational|hardening)",
    re.I)


def ineligible_reason(rec):
    """Return the matched ineligible-class token, or '' when the record is potentially reportable.
    Matched against the CLASS fields only (never free-text hypothesis prose) so a hypothesis that
    merely MENTIONS a bypass is not falsely rejected.
    NOTE the normalisation: class strings are snake/kebab-cased in practice (`tls_best_practice`,
    `security-headers`), and `_` is a WORD character, so `\\btls\\b` never matches inside
    `tls_best_practice`. Separators are flattened to spaces FIRST so word-boundary anchors work."""
    cls = " ".join(str(rec.get(k, "") or "") for k in ("class", "vuln_class", "title"))
    cls = re.sub(r"[\s_.\-/]+", " ", cls).strip()
    m = INELIGIBLE_CLASS.search(cls)
    return m.group(0) if m else ""


def append(path, rec):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def cmd_merge(fd, wave_glob, slug, cycle):
    seen = set()
    for f in ("candidates.jsonl", "confirmed.jsonl", "rejected.jsonl"):
        for d in jline(os.path.join(fd, f)):
            seen.add(key_of(d))
    new = dupe = bad = prim = 0
    for wf in sorted(glob.glob(wave_glob)) + sorted(glob.glob(wave_glob + ".transcript")):
        for d in jline(wf):
            if not isinstance(d, dict):
                bad += 1
                continue
            if d.get("status") not in (None, "CANDIDATE"):
                continue
            # PHANTOM-CANDIDATE GUARD. An agent's per-wave SUMMARY record
            # ({"agent":"clientside","wave":1,"records":44,"candidates":0,"note":...}) carries no status,
            # so it passed the check above and became a candidate — measured as PR-internationalsos-1-0,
            # a record that is not a finding at all and wasted a validation pass. A real candidate names
            # a vulnerability CLASS and a target (endpoint/host/asset); a summary names none.
            if not (d.get("class") or d.get("vuln_class")) or not (d.get("endpoint") or d.get("host") or d.get("asset")):
                bad += 1
                continue
            k = key_of(d)
            if k in seen:
                dupe += 1
                continue
            seen.add(k)
            rec = dict(d)
            rec.setdefault("id", "PR-%s-%s-%s" % (slug, cycle, new))
            rec["slug"] = slug
            rec["cycle"] = int(cycle)
            rec["status"] = "NEW"
            rec["ts"] = rec.get("ts") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            why = ineligible_reason(rec)
            if why:
                # Doctrine §2: retained WITH evidence as a chain primitive, explicitly marked so the
                # validate stage cannot promote it to a deliverable.
                rec["doctrine"] = "chain-primitive"
                rec["ineligible_reason"] = why
                prim += 1
            append(os.path.join(fd, "candidates.jsonl"), rec)
            new += 1
    print(json.dumps({"new": new, "dupes": dupe, "bad": bad, "chain_primitives": prim}))


def cmd_verdict(fd, vf):
    cands = {}
    for d in jline(os.path.join(fd, "candidates.jsonl")):
        cands[str(d.get("id"))] = d
    applied = collections.Counter()
    for v in jline(vf):
        vid = str(v.get("id", ""))
        cand = cands.get(vid)
        if cand is None:
            # match on host|endpoint|class if id missing
            for d in cands.values():
                if key_of(d) == key_of(v):
                    cand = d
                    vid = str(d.get("id"))
                    break
        if cand is None:
            applied["unknown_candidate"] += 1
            continue
        verdict = str(v.get("verdict", "")).upper()
        rec = dict(cand)
        rec["verdict"] = verdict
        rec["judge_reason"] = v.get("reason", "")
        rec["severity"] = v.get("severity") or rec.get("severity")
        rec["cvss"] = v.get("cvss") or rec.get("cvss")
        rec["validated_ts"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        why = rec.get("ineligible_reason") or ineligible_reason(rec)
        if verdict == "VERIFIED" and why:
            # DETERMINISTIC FLOOR (doctrine §2): an ineligible-class candidate is a CHAIN PRIMITIVE.
            # It is retained with its evidence, but it can NEVER be promoted to a deliverable, no matter
            # what the LLM validator concluded. Mechanical counterpart of the prompt rule.
            rec["status"] = "REJECTED"
            rec["verdict"] = "REJECTED"
            rec["doctrine"] = "chain-primitive"
            rec["judge_reason"] = "chain-primitive-only (doctrine §2 deterministic gate: '%s')" % why
            append(os.path.join(fd, "rejected.jsonl"), rec)
            applied["chain_primitive_blocked"] += 1
        elif verdict == "VERIFIED":
            rec["status"] = "VALIDATED"
            append(os.path.join(fd, "confirmed.jsonl"), rec)
            applied["verified"] += 1
        elif verdict == "DUPLICATE":
            rec["status"] = "DUPLICATE"
            append(os.path.join(fd, "rejected.jsonl"), rec)
            applied["duplicate"] += 1
        else:
            rec["status"] = {"NOT_REPRODUCED": "REJECTED", "FALSE_POSITIVE": "REJECTED",
                             "OUT_OF_SCOPE": "OUT_OF_SCOPE"}.get(verdict, "INCONCLUSIVE")
            append(os.path.join(fd, "rejected.jsonl"), rec)
            applied[rec["status"].lower()] += 1
    print(json.dumps(dict(applied)))


def cmd_cov(tsv, out):
    by_status = collections.Counter()
    by_class = collections.Counter()
    total = 0
    untested = []
    try:
        lines = open(tsv, errors="replace").read().splitlines()
    except FileNotFoundError:
        lines = []
    for i, line in enumerate(lines):
        if i == 0 or not line.strip():
            continue
        p = line.split("\t")
        if len(p) < 4:
            continue
        total += 1
        st = p[4] if len(p) > 4 else ""
        cl = p[3]
        by_status[st] += 1
        by_class[cl] += 1
        if st in ("UNTESTED", "DISCOVERED", "NOT_TESTED", ""):
            untested.append({"host": p[0], "endpoint": p[1], "method": p[2], "class": cl})
    summary = {"total": total, "by_status": dict(by_status),
               "by_class": dict(by_class), "untested": len(untested),
               "untested_top": untested[:50],
               "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    os.makedirs(os.path.dirname(out), exist_ok=True)
    tmp = out + ".tmp"
    with open(tmp, "w") as f:
        json.dump(summary, f, indent=2)
    os.replace(tmp, out)
    print(json.dumps({"total": total, "untested": len(untested)}))


def cmd_assets(state_dir, out):
    surf = os.path.join(state_dir, "surface")
    counts = {}
    files = {}
    if os.path.isdir(surf):
        for name in sorted(os.listdir(surf)):
            p = os.path.join(surf, name)
            if os.path.isfile(p):
                files[name] = os.path.getsize(p)
                try:
                    counts[name] = sum(1 for _ in open(p, errors="replace"))
                except Exception:
                    counts[name] = 0
    doc = {"state_dir": state_dir, "surface_files": files, "line_counts": counts,
           "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    os.makedirs(os.path.dirname(out), exist_ok=True)
    tmp = out + ".tmp"
    with open(tmp, "w") as f:
        json.dump(doc, f, indent=2)
    os.replace(tmp, out)
    print(json.dumps({"files": len(files)}))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    c = sys.argv[1]
    if c == "merge":
        cmd_merge(*sys.argv[2:6])
    elif c == "verdict":
        cmd_verdict(*sys.argv[2:4])
    elif c == "cov":
        cmd_cov(*sys.argv[2:4])
    elif c == "assets":
        cmd_assets(*sys.argv[2:4])
    else:
        print("unknown subcommand", c)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
