#!/usr/bin/env bash
# send_report_pdf.sh <pdf-path> ["message"]
# Uploads a report PDF as a real Discord attachment to the hackbot home channel,
# so the user can download it from Discord.
# Reads DISCORD_BOT_TOKEN + DISCORD_HOME_CHANNEL from /root/.hermes/.env.
# Prints the HTTP status and the resulting attachment CDN URL (verify from that, not from silence).
set -u
pdf="${1:-}"
msg="${2:-}"
if [ -z "$pdf" ]; then echo "usage: $0 <pdf-path> [\"message\"]"; exit 2; fi
if [ ! -f "$pdf" ]; then echo "no such file: $pdf"; exit 2; fi

# ── DELIVERY GATE (operator directive 2026-11-19) ───────────────────────────
# Discord carries ONE category: "Exploited & Ready to Submit". This uploader is reachable only from
# report-pdf.sh (which runs the Exploited&Ready gate and then exports HACKBOT_ALLOW_SEND=1), or from
# an explicit operator override. Any other caller is refused — leads are never uploaded.
if [ "${HACKBOT_ALLOW_SEND:-0}" != "1" ] && [ "${HACKBOT_NOTIFY_FORCE:-0}" != "1" ]; then
  echo "REFUSED: PDF uploads are gated. Discord delivery only for Exploited&Ready findings."
  echo "         Use:  notify-policy.sh finding <id|finding.json> \"message\""
  echo "         (operator override: HACKBOT_NOTIFY_FORCE=1)"
  exit 3
fi
sz=$(stat -c%s "$pdf")
if [ "$sz" -gt 8000000 ]; then echo "WARN: $sz bytes may exceed Discord's 8-10MB default limit; will still try"; fi

token="$(grep -E '^DISCORD_BOT_TOKEN=' /root/.hermes/.env 2>/dev/null | sed 's/^[^=]*=//' | tr -d '\r\n')"
channel="${DISCORD_HOME_CHANNEL:-$(grep -E '^DISCORD_HOME_CHANNEL=' /root/.hermes/.env 2>/dev/null | sed 's/^[^=]*=//' | tr -d '\r\n')}"
channel="${channel:-1567763899808354387}"
[ -z "$token" ] && { echo "no DISCORD_BOT_TOKEN"; exit 1; }

python3 - "$token" "$channel" "$pdf" "$msg" <<'PY'
import sys, os, json, uuid, mimetypes, urllib.request, urllib.error
token, channel, path, msg = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
fname = os.path.basename(path)
boundary = "----hackbot" + uuid.uuid4().hex
ctype = mimetypes.guess_type(fname)[0] or "application/pdf"
payload = {"content": msg[:1900] if msg else ""}
parts = []
parts.append(("--" + boundary).encode())
parts.append(b'Content-Disposition: form-data; name="payload_json"')
parts.append(b"Content-Type: application/json")
parts.append(b"")
parts.append(json.dumps(payload).encode())
parts.append(("--" + boundary).encode())
parts.append(('Content-Disposition: form-data; name="files[0]"; filename="%s"' % fname).encode())
parts.append(("Content-Type: %s" % ctype).encode())
parts.append(b"")
body = b"\r\n".join(parts) + b"\r\n"
with open(path, "rb") as fh:
    body += fh.read()
body += b"\r\n" + ("--" + boundary + "--").encode() + b"\r\n"

req = urllib.request.Request(
    "https://discord.com/api/v10/channels/%s/messages" % channel,
    data=body, method="POST",
    headers={"Authorization": "Bot %s" % token,
             "Content-Type": "multipart/form-data; boundary=%s" % boundary,
             "User-Agent": "hackbot/1.0"})
try:
    r = urllib.request.urlopen(req, timeout=120)
    d = json.loads(r.read().decode())
    print("http", r.status, "| message id", d.get("id"))
    for a in d.get("attachments", []):
        print("attachment:", a.get("filename"), a.get("size"), "bytes")
        print("url:", a.get("url"))
except urllib.error.HTTPError as e:
    print("http", e.code, e.read()[:500].decode("utf-8", "replace"))
    sys.exit(1)
except Exception as e:
    print("ERR", e)
    sys.exit(1)
PY
