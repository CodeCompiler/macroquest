#!/usr/bin/env python3
"""
sentinel_notify.py -- tiny Discord-webhook poster for Sentinel. Pure stdlib.

Used by sentinel.py; also runnable standalone for testing:
    set SENTINEL_WEBHOOK=https://discord.com/api/webhooks/...
    python sentinel_notify.py "hello from the VPS"

Messages longer than Discord's 2000-char limit are split on line boundaries.
The webhook URL is NEVER stored in the repo -- env var or gitignored file only.
"""
import os, sys, json, time, urllib.request

LIMIT = 1900          # headroom under Discord's 2000-char hard cap


def _chunks(msg):
    if len(msg) <= LIMIT:
        return [msg]
    out, cur = [], ""
    for line in msg.split("\n"):
        while len(line) > LIMIT:                 # a single monster line
            out.append(line[:LIMIT]); line = line[LIMIT:]
        if len(cur) + len(line) + 1 > LIMIT:
            out.append(cur); cur = line
        else:
            cur = (cur + "\n" + line) if cur else line
    if cur:
        out.append(cur)
    return out


def post(url, msg, retries=2):
    """POST `msg` to the Discord webhook `url`. Returns True on success."""
    ok = True
    for part in _chunks(msg):
        body = json.dumps({"content": part}).encode("utf-8")
        sent = False
        for attempt in range(retries + 1):
            try:
                req = urllib.request.Request(
                    url, data=body, method="POST",
                    headers={"Content-Type": "application/json",
                             "User-Agent": "eqmq-sentinel/1.0"})
                with urllib.request.urlopen(req, timeout=20) as r:
                    if 200 <= r.status < 300:
                        sent = True
                        break
            except urllib.error.HTTPError as e:
                if e.code == 429:                # rate limited: honor retry-after
                    try:
                        wait = float(json.loads(e.read()).get("retry_after", 2))
                    except Exception:
                        wait = 2.0
                    time.sleep(min(wait, 10))
                    continue
                break                             # other HTTP errors: don't hammer
            except Exception:
                time.sleep(1 + attempt)
        ok = ok and sent
    return ok


if __name__ == "__main__":
    url = os.environ.get("SENTINEL_WEBHOOK", "").strip()
    if not url:
        print("set SENTINEL_WEBHOOK first"); sys.exit(1)
    msg = " ".join(sys.argv[1:]) or "sentinel_notify test"
    sys.exit(0 if post(url, msg) else 1)
