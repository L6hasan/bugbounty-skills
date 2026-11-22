#!/bin/bash
# notch.sh "message"  — post a plain message to the hackbot Discord home channel
msg="$1"
token="$(grep -E '^DISCORD_BOT_TOKEN=' /root/.hermes/.env 2>/dev/null | sed 's/^[^=]*=//' | tr -d '\r\n')"
channel="${DISCORD_HOME_CHANNEL:-1567763899808354387}"
[ -z "$token" ] && { echo "no token"; exit 1; }
python3 - "$token" "$channel" "$msg" <<'PY'
import sys,json,urllib.request
token,channel,msg=sys.argv[1],sys.argv[2],sys.argv[3]
data=json.dumps({"content":msg[:1900]}).encode()
req=urllib.request.Request(f"https://discord.com/api/v10/channels/{channel}/messages",data=data,
    headers={"Authorization":f"Bot {token}","Content-Type":"application/json","User-Agent":"hackbot/1.0"})
try:
    r=urllib.request.urlopen(req,timeout=20)
    print("http",r.status)
except urllib.error.HTTPError as e:
    print("http",e.code,e.read()[:300].decode('utf-8','replace'))
except Exception as e:
    print("ERR",e)
PY
