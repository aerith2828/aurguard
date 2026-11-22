"""Detection rules applied to lines added to an AUR package.

Rules are deliberately simple regular expressions: each one is readable,
explains itself in the report and can be tested on a one-line example. They
look at *added* lines only, so a long-standing `npm install` in an Electron
package is not reported on every upgrade - only when it appears.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from urllib.parse import urlsplit

SEVERITIES = ("info", "medium", "high")


def rank(severity: str) -> int:
    return SEVERITIES.index(severity)


@dataclass
class Finding:
    severity: str
    rule: str
    message: str
    file: str = ""
    line: int = 0
    text: str = ""

    def as_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class Rule:
    id: str
    severity: str
    pattern: re.Pattern[str]
    message: str
    # "script": PKGBUILD, *.install, *.sh, *.hook ... ; "install": only *.install; "any": every text file
    scope: str = "script"
    exclude: re.Pattern[str] | None = field(default=None)


def _re(p: str) -> re.Pattern[str]:
    return re.compile(p, re.IGNORECASE)


# Strings published for the June 2026 AUR campaign (atomic-lockfile / js-digest).
KNOWN_IOCS = (
    "atomic-lockfile",
    "js-digest",
    "herbsobering",
    "olrh4mibs62l6kkuvvjyc5lrercqg5tz543r4lsw3o6mh5qb7g7sneid",
    "6144d433f8a0316869877b5f834c801251bbb936e5f1577c5680878c7443c98b",
    "7883bda1ff15425f2dbe622c45a3ae105ddfa6175009bbf0b0cad9bf5c79b316",
    "47893d9badc38c54b71321263ce8178c1abb10396e0aadf9793e61ec8829e204",
)

# Hosts where nothing a package needs should live.
SUSPICIOUS_HOSTS = (
    "temp.sh", "transfer.sh", "0x0.st", "file.io", "bashupload.com", "termbin.com",
    "pastebin.com", "paste.ee", "hastebin.com", "ghostbin.com", "rentry.co",
    "cdn.discordapp.com", "media.discordapp.net", "bit.ly", "tinyurl.com", "is.gd",
    "ngrok.io", "ngrok-free.app", "trycloudflare.com",
)

RULES: list[Rule] = [
    Rule("known-ioc", "high", _re("|".join(map(re.escape, KNOWN_IOCS))),
         "Matches a published indicator of the June 2026 AUR malware campaign.", scope="any"),
    Rule("pipe-to-shell", "high", _re(r"\b(curl|wget|fetch)\b[^|#\n]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b"),
         "Downloads something and runs it straight away - the content is never checked against a checksum."),
    Rule("decode-and-run", "high",
         _re(r"(base64\s+(-d|--decode)[^|\n]*\|\s*(ba)?sh|eval\s+[\"']?\$\((echo|printf|base64|curl|wget|xxd)|\bpython3?\s+-c\s+[\"'].*(exec|eval)\s*\()"),
         "Decodes or builds code at runtime and executes it - a common way to hide what a script really does."),
    Rule("network-in-install-hook", "high",
         _re(r"\b(curl|wget|nc|ncat|socat|npm|npx|bun|bunx|pnpm|yarn|pip3?|gem|cargo)\s"),
         "The .install file runs as root during pacman -S; it should never download anything.", scope="install"),
    Rule("persistence", "high",
         _re(r"(/etc/ld\.so\.preload|crontab\s+-|/etc/cron\.|\.config/autostart|systemctl\s+(--user\s+)?enable\s+--now|/etc/systemd/system/[^\s\"']+\.service|\.config/systemd/user/)"),
         "Sets something up to run automatically (preload, cron, autostart or a systemd unit).",
         # a message telling the user what to run is not running it (unless it is redirected somewhere)
         exclude=_re(r"^\s*(echo|printf)\b[^>|]*$")),
    Rule("js-package-manager", "medium",
         _re(r"\b(npm|bun|pnpm|yarn)\s+(i|install|add|ci)\b|\b(npx|bunx)\s+\S"),
         "Newly fetches packages from the npm registry at build time - this is how the atomic-lockfile campaign got in. "
         "Normal for Electron/JS apps, odd for anything else.",
         exclude=_re(r"--frozen-lockfile|--offline|\bnpm\s+ci\b.*--ignore-scripts")),
    Rule("pip-install", "medium", _re(r"\bpip3?\s+install\b"),
         "Installs Python packages with pip during the build instead of declaring dependencies."),
    Rule("sudo-in-build", "medium", _re(r"(^|[;&|]\s*|\s)sudo\s"),
         "PKGBUILDs are built as a normal user and must not need sudo."),
    Rule("setuid", "medium", _re(r"chmod\s+([ugoa]*\+s|[0-7]?[4-7][0-7]{3}\b)"),
         "Makes a file run with its owner's (often root's) privileges."),
    Rule("obfuscation", "medium", _re(r"[A-Za-z0-9+/]{160,}={0,2}|(\\x[0-9a-f]{2}){8,}"),
         "Long encoded blob in a script - packages rarely need one.", scope="any",
         exclude=_re(r"^\s*(b2|sha\d+|md5|ck)sums")),
]

SCRIPT_FILE = re.compile(r"(^|/)(PKGBUILD|[^/]*\.(install|sh|bash|hook|desktop|service|timer))$")
INSTALL_FILE = re.compile(r"\.install$")
URL = re.compile(r"\b(?:https?|ftp)://[^\s\"'()<>]+", re.IGNORECASE)
IP_HOST = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _in_scope(rule: Rule, path: str) -> bool:
    if rule.scope == "any":
        return True
    if rule.scope == "install":
        return bool(INSTALL_FILE.search(path))
    return bool(SCRIPT_FILE.search(path))


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def check_lines(path: str, added: list[tuple[int, str]], removed: Sequence[str] = ()) -> list[Finding]:
    """Run all rules over the added lines of one file.

    `removed` lines are used only to tell which download hosts are new.
    """
    findings: list[Finding] = []
    known_hosts = {_host(u) for line in removed for u in URL.findall(line)}

    for lineno, text in added:
        stripped = text.strip()
        if not stripped:
            continue
        # Comments don't run, so only the IOC rule applies to them.
        is_comment = stripped.startswith("#")
        for rule in RULES:
            if not _in_scope(rule, path) or (is_comment and rule.id != "known-ioc"):
                continue
            if rule.pattern.search(text) and not (rule.exclude and rule.exclude.search(text)):
                findings.append(Finding(rule.severity, rule.id, rule.message, path, lineno, stripped[:200]))

        for url in [] if is_comment else URL.findall(text):
            host = _host(url)
            if not host:
                continue
            if host.endswith(".onion") or IP_HOST.match(host) or any(host == h or host.endswith("." + h) for h in SUSPICIOUS_HOSTS):
                findings.append(Finding("high", "suspicious-host", f"Downloads from {host}, a host no real package should depend on.",
                                        path, lineno, stripped[:200]))
            elif removed and host not in known_hosts:
                findings.append(Finding("info", "new-host", f"New download host: {host}.", path, lineno, stripped[:200]))
                known_hosts.add(host)
    return _dedupe(findings)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen = set()
    out = []
    for f in findings:
        key = (f.rule, f.file, f.line)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def maintainer_change(old: str | None, new: str | None) -> Finding | None:
    if old == new:
        return None
    if old is None:
        return Finding("medium", "adopted", f"Orphaned package was adopted by {new}. New maintainers are worth a closer look at their first changes.")
    if new is None:
        return Finding("info", "orphaned", f"Package was orphaned (was {old}).")
    return Finding("medium", "maintainer-changed", f"Maintainer changed from {old} to {new}.")
