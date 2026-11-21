"""Talking to the AUR: the RPC for metadata, git for the package files.

Package repositories are kept as bare clones in the cache directory. Nothing
from them is ever executed or checked out; files are only read with
`git show`.
"""

from __future__ import annotations

import json
import os
import subprocess
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from . import __version__

AUR = "https://aur.archlinux.org"
USER_AGENT = f"aurguard/{__version__}"
MAX_FILE_BYTES = 512 * 1024


@dataclass
class AurPackage:
    name: str
    base: str
    version: str
    maintainer: str | None
    last_modified: int


def installed_foreign() -> dict[str, str]:
    """Packages not found in the sync repos (`pacman -Qm`): name -> version."""
    out = subprocess.run(["pacman", "-Qm"], capture_output=True, text=True, check=True).stdout
    pkgs = {}
    for line in out.splitlines():
        name, _, version = line.partition(" ")
        if name:
            pkgs[name] = version.strip()
    return pkgs


def rpc_info(names: list[str], batch: int = 150) -> dict[str, AurPackage]:
    """Look up packages in the AUR RPC (v5). Missing names are simply absent."""
    found: dict[str, AurPackage] = {}
    for i in range(0, len(names), batch):
        query = urllib.parse.urlencode([("arg[]", n) for n in names[i : i + batch]])
        req = urllib.request.Request(f"{AUR}/rpc/v5/info?{query}", headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.load(resp)
        if data.get("type") == "error":
            raise RuntimeError(f"AUR RPC error: {data.get('error')}")
        for r in data["results"]:
            found[r["Name"]] = AurPackage(
                name=r["Name"],
                base=r["PackageBase"],
                version=r["Version"],
                maintainer=r.get("Maintainer"),
                last_modified=r.get("LastModified", 0),
            )
    return found


class Repo:
    """A bare clone of one AUR package base."""

    def __init__(self, cache_dir: Path, base: str):
        self.base = base
        self.path = cache_dir / "repos" / f"{base}.git"

    def _git(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1"}
        return subprocess.run(["git", "-C", str(self.path), *args], capture_output=True, env=env, check=check, timeout=120)

    def sync(self) -> None:
        if self.path.exists():
            self._git("fetch", "--quiet", "--force", "origin", "+refs/heads/*:refs/heads/*")
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
        subprocess.run(
            ["git", "clone", "--quiet", "--bare", f"{AUR}/{self.base}.git", str(self.path)],
            capture_output=True, env=env, check=True, timeout=120,
        )

    def head(self) -> str:
        return self._git("rev-parse", "HEAD").stdout.decode().strip()

    def has_commit(self, rev: str) -> bool:
        return self._git("cat-file", "-e", f"{rev}^{{commit}}", check=False).returncode == 0

    def commits(self, path: str | None = None, limit: int = 300) -> list[str]:
        args = ["log", f"--max-count={limit}", "--format=%H", "HEAD"]
        if path:
            args += ["--", path]
        return self._git(*args).stdout.decode().split()

    def count_between(self, old: str, new: str) -> int:
        return int(self._git("rev-list", "--count", f"{old}..{new}").stdout.decode().strip() or 0)

    def show(self, rev: str, path: str) -> str | None:
        """Text content of a file at a revision, or None for binary/huge/missing files."""
        res = self._git("show", f"{rev}:{path}", check=False)
        if res.returncode != 0 or len(res.stdout) > MAX_FILE_BYTES or b"\0" in res.stdout:
            return None
        return res.stdout.decode("utf-8", errors="replace")

    def files(self, rev: str) -> list[str]:
        return self._git("ls-tree", "-r", "--name-only", rev).stdout.decode().splitlines()

    def diff(self, old: str, new: str) -> str:
        res = self._git("diff", "--no-color", "--no-ext-diff", "-U3", old, new)
        return res.stdout.decode("utf-8", errors="replace")


def srcinfo_version(text: str) -> str | None:
    """`[epoch:]pkgver-pkgrel` from the pkgbase section of a .SRCINFO."""
    fields: dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith("pkgname ="):
            break  # first split package section starts; pkgbase section is done
        key, sep, value = line.strip().partition(" = ")
        if sep and key in ("pkgver", "pkgrel", "epoch"):
            fields[key] = value.strip()
    if "pkgver" not in fields or "pkgrel" not in fields:
        return None
    epoch = f"{fields['epoch']}:" if fields.get("epoch", "0") not in ("", "0") else ""
    return f"{epoch}{fields['pkgver']}-{fields['pkgrel']}"


def commit_for_version(repo: Repo, version: str) -> str | None:
    """Oldest commit of the newest run of commits whose .SRCINFO says `version`.

    Several commits can carry the same version (fixes pushed without a pkgrel
    bump - which is also exactly what an attacker would do). Taking the oldest
    one means the diff to HEAD includes all of them.

    VCS packages (-git) bump pkgver at build time, so they often have no match.
    """
    match = None
    for rev in repo.commits(".SRCINFO"):
        text = repo.show(rev, ".SRCINFO")
        if text and srcinfo_version(text) == version:
            match = rev
        elif match:
            break
    return match
