"""Desktop notifications and webhooks (Discord, Slack, ntfy, or plain JSON)."""

from __future__ import annotations

import json
import shutil
import subprocess
import urllib.request

from . import __version__


def desktop(title: str, body: str, critical: bool) -> None:
    if shutil.which("notify-send"):
        subprocess.run(
            ["notify-send", "--app-name=aurguard", f"--urgency={'critical' if critical else 'normal'}", title, body],
            check=False,
        )


def webhook(url: str, title: str, body: str, payload: dict) -> None:
    """ntfy gets plain text; everything else gets JSON that Discord and Slack both accept,
    plus the full report under "aurguard" for tools like n8n."""
    headers = {"User-Agent": f"aurguard/{__version__}"}
    if "ntfy" in url:
        data = body.encode()
        headers |= {"Title": title, "Tags": "warning"}
    else:
        text = f"**{title}**\n{body}"
        data = json.dumps({"content": text[:1900], "text": text, "aurguard": payload}).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=20):
        pass
