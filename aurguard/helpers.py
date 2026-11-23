"""paru and yay: picking one, and what both of them would skip anyway.

Both helpers take the same pacman-style flags for an AUR upgrade (-Sua,
--ignore pkg1,pkg2), so `aurguard upgrade` treats them the same way.
"""

from __future__ import annotations

import re
import shlex
import shutil
from pathlib import Path

SUPPORTED = ("paru", "yay")


def detect(preferred: str = "") -> str | None:
    """The configured helper if it is installed, else paru, else yay."""
    for name in ((preferred,) if preferred else ()) + SUPPORTED:
        if name and shutil.which(name):
            return name
    return None


def ignored_in_args(args: list[str]) -> set[str]:
    """Packages from `--ignore a,b` / `--ignore=a` in helper arguments."""
    names: set[str] = set()
    for i, arg in enumerate(args):
        value = None
        if arg == "--ignore" and i + 1 < len(args):
            value = args[i + 1]
        elif arg.startswith("--ignore="):
            value = arg.split("=", 1)[1]
        if value:
            names |= {n for n in value.split(",") if n}
    return names


def ignored_in_pacman_conf(path: Path = Path("/etc/pacman.conf")) -> set[str]:
    """IgnorePkg from pacman.conf - pacman, paru and yay all honour it.

    Glob patterns are kept as-is and matched with fnmatch by the caller.
    """
    names: set[str] = set()
    try:
        text = path.read_text()
    except OSError:
        return names
    section = ""
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if m := re.fullmatch(r"\[(.+)\]", line):
            section = m.group(1)
        elif section == "options" and (m := re.fullmatch(r"IgnorePkg\s*=\s*(.*)", line)):
            names |= set(m.group(1).split())
    return names


def split_args(text: str) -> list[str]:
    return shlex.split(text)
