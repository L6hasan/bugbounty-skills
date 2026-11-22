#!/usr/bin/env python3
"""The only approved Telegram send path for bug-bounty findings.

It refuses to send unless the finding is confirmed/verified AND carries every field the
operator requires: title, description, steps to reproduce, PoC, impact.

Usage:
    notify_telegram.py FINDING.json [--dry-run]

Exit codes:
    0  sent (or validated in --dry-run)
    2  refused: missing/invalid fields, unverified, or non-reportable severity
    3  configuration or transport error

Never call this with a candidate, a status update, or a progress ping. VERIFY first.
"""

import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

ENV_FILES = [
    "/root/.hermes/.env",
    "/root/.config/opencode-telegram-bot/.env",
]
SEVERITIES = {"critical", "high", "medium", "p1", "p2", "p3",
              "critical/p1", "high/p2", "medium/p3"}
VERIFIED_STATES = {"confirmed", "verified", "validated", "reproduced"}
LOG_PATH = "/root/Myskill/bugbounty-hunter/findings/telegram-sent.log"


def load_env_file(path):
    out = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return out


def config_value(name):
    if os.environ.get(name):
        return os.environ[name]
    for path in ENV_FILES:
        val = load_env_file(path).get(name)
        if val:
            return val
    return ""


def as_text(value):
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (list, tuple)):
        return "\n".join(as_text(v) for v in value if as_text(v))
    if isinstance(value, dict):
        return "\n".join(f"{k}: {as_text(v)}" for k, v in value.items() if as_text(v))
    return ""


def count_steps(value):
    if isinstance(value, (list, tuple)):
        return len([v for v in value if as_text(v)])
    text = as_text(value)
    lines = [l for l in text.splitlines() if l.strip()]
    numbered = len(re.findall(r"(?m)^\s*(?:\d+[.)]|[-*])\s+", text))
    return max(len(lines) if len(lines) > 1 else 0, numbered)


def severity_ok(value):
    return as_text(value).lower() in SEVERITIES


def verified_ok(doc):
    for key in ("verified", "confirmed", "validated", "reproduced_twice", "reproduced"):
        if doc.get(key) is True:
            return True
    state = as_text(doc.get("status") or doc.get("state")).lower()
    return state in VERIFIED_STATES


def validate(doc):
    errors = []
    if not isinstance(doc, dict):
        return ["finding must be a JSON object"]

    placeholder = re.compile(r"^\s*(tbd|todo|n/?a|none|placeholder|test|unknown)\s*$", re.I)

    title = as_text(doc.get("title"))
    desc = as_text(doc.get("description") or doc.get("summary"))
    steps = doc.get("steps") or doc.get("steps_to_reproduce") or doc.get("reproduction")
    poc = as_text(doc.get("poc") or doc.get("proof") or doc.get("proof_of_concept"))
    impact = as_text(doc.get("impact"))
    sev = as_text(doc.get("severity"))

    if len(title) < 8:
        errors.append("title: missing or shorter than 8 characters")
    if len(desc) < 40:
        errors.append("description: missing or shorter than 40 characters")
    if count_steps(steps) < 3:
        errors.append("steps: need at least 3 numbered steps (list or numbered text)")
    if len(poc) < 20:
        errors.append("poc: missing or shorter than 20 characters")
    if len(impact) < 20:
        errors.append("impact: missing or shorter than 20 characters")
    if not sev:
        errors.append("severity: missing")
    elif not severity_ok(sev):
        errors.append("severity: must be critical/high/medium or P1/P2/P3, got %r" % sev)
    if not verified_ok(doc):
        errors.append("status: not confirmed/verified (set verified=true or status=confirmed)")

    for label, value in (("title", title), ("description", desc), ("poc", poc),
                         ("impact", impact)):
        if value and placeholder.match(value):
            errors.append("%s: placeholder value %r is not evidence" % (label, value))

    return errors


def message_for(doc):
    title = as_text(doc.get("title"))
    sev = as_text(doc.get("severity")).upper()
    asset = as_text(doc.get("asset") or doc.get("host") or doc.get("url"))
    desc = as_text(doc.get("description") or doc.get("summary"))
    steps = doc.get("steps") or doc.get("steps_to_reproduce") or doc.get("reproduction")
    poc = as_text(doc.get("poc") or doc.get("proof") or doc.get("proof_of_concept"))
    impact = as_text(doc.get("impact"))
    fix = as_text(doc.get("remediation") or doc.get("fix"))

    if isinstance(steps, (list, tuple)):
        steps = "\n".join(f"{i}. {as_text(s)}" for i, s in enumerate(steps, 1))

    parts = [
        f"VERIFIED FINDING — {sev}",
        f"Title: {title}",
    ]
    if asset:
        parts.append(f"Asset: {asset}")
    parts += [
        "",
        "Description",
        desc,
        "",
        "Steps to reproduce",
        as_text(steps),
        "",
        "PoC",
        poc,
        "",
        "Impact",
        impact,
    ]
    if fix:
        parts += ["", "Remediation", fix]
    parts += ["", "Status: confirmed and reproduced."]
    return "\n".join(parts)


def chunk(text, limit=3800):
    chunks, current = [], ""
    for line in text.splitlines():
        if len(current) + len(line) + 1 > limit and current:
            chunks.append(current)
            current = line
        else:
            current = f"{current}\n{line}" if current else line
    if current:
        chunks.append(current)
    return chunks


def split_target(target):
    target = target.strip()
    if target.lstrip("-").isdigit():
        return None, int(target)
    if target.startswith("@"):
        return target, None
    return target, None


def send(token, target, text):
    chat_id, thread_id = split_target(target)
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    for i, part in enumerate(chunk(text), 1):
        payload = {
            "chat_id": chat_id,
            "text": part,
            "disable_web_page_preview": True,
        }
        if thread_id is not None:
            payload["message_thread_id"] = thread_id
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json",
                     "User-Agent": "bugbounty-hunter/2.x"},
        )
        try:
            with urllib.request.urlopen(req, timeout=25) as resp:
                body = json.loads(resp.read().decode() or "{}")
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"telegram HTTP {exc.code}: {exc.read()[:300]!r}")
        except Exception as exc:
            raise RuntimeError(f"telegram transport: {exc}")
        if not body.get("ok"):
            raise RuntimeError(f"telegram rejected: {body}")
    return len(chunk(text))


def log_send(doc, chunks):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    title = as_text(doc.get("title"))
    sev = as_text(doc.get("severity"))
    digest = hashlib.sha256(title.encode()).hexdigest()[:12]
    with open(LOG_PATH, "a", encoding="utf-8") as fh:
        fh.write(f"{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\t"
                 f"{sev}\t{chunks}\t{digest}\t{title}\n")


def main(argv):
    args = [a for a in argv[1:] if a != "--dry-run"]
    dry_run = "--dry-run" in argv
    if len(args) != 1:
        print(__doc__.strip())
        return 3

    try:
        with open(args[0], "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"REFUSED: cannot read finding JSON: {exc}")
        return 2

    errors = validate(doc)
    if errors:
        print("REFUSED — not a verified, complete finding:")
        for err in errors:
            print(f"  - {err}")
        return 2

    text = message_for(doc)
    if dry_run:
        print("VALID — would send:")
        print(text)
        return 0

    token = config_value("TELEGRAM_BOT_TOKEN")
    target = (config_value("TELEGRAM_HOME_CHANNEL")
              or config_value("TELEGRAM_ALLOWED_USER_ID"))
    if not token or not target:
        print("ERROR: TELEGRAM_BOT_TOKEN or TELEGRAM_HOME_CHANNEL is not configured")
        return 3

    try:
        sent = send(token, target, text)
    except RuntimeError as exc:
        print(f"ERROR: {exc}")
        return 3

    log_send(doc, sent)
    print(f"SENT: {sent} message part(s) for {as_text(doc.get('title'))!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
