"""Deciding what to compare for each package and collecting findings."""

from __future__ import annotations

import re
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from .aur import AurPackage, Repo, commit_for_version
from .rules import Finding, check_lines, maintainer_change, rank

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


@dataclass
class FileChange:
    path: str
    added: list[tuple[int, str]] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)


def parse_diff(diff: str) -> list[FileChange]:
    """Added lines (with their new line numbers) and removed lines per file."""
    files: list[FileChange] = []
    current: FileChange | None = None
    lineno = 0
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            current = None
        elif line.startswith("+++ "):
            path = line[4:]
            if path == "/dev/null":
                current = None  # deleted file
                continue
            current = FileChange(path[2:] if path.startswith("b/") else path)
            files.append(current)
        elif line.startswith("--- "):
            continue
        elif m := HUNK.match(line):
            lineno = int(m.group(1))
        elif current is None:
            continue
        elif line.startswith("+"):
            current.added.append((lineno, line[1:]))
            lineno += 1
        elif line.startswith("-"):
            current.removed.append(line[1:])
        elif line.startswith(" "):
            lineno += 1
    return files


@dataclass
class Report:
    base: str
    installed: str
    aur_version: str | None
    maintainer: str | None
    last_modified: int = 0
    old_rev: str | None = None
    new_rev: str | None = None
    compared: str = ""  # human description of what was compared
    commits: int = 0
    diff: str = ""
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    explanation: dict | None = None

    @property
    def worst(self) -> str | None:
        return max((f.severity for f in self.findings), key=rank, default=None)

    def as_dict(self) -> dict:
        d = {k: v for k, v in self.__dict__.items() if k not in ("findings", "diff")}
        d["findings"] = [f.as_dict() for f in self.findings]
        d["worst"] = self.worst
        return d


def analyse(repo: Repo, old: str | None, new: str) -> tuple[str, list[Finding]]:
    """Diff old..new (or every file at `new` when old is None) and run the rules."""
    if old:
        diff = repo.diff(old, new)
        changes = parse_diff(diff)
    else:
        diff = ""
        changes = []
        for path in repo.files(new):
            text = repo.show(new, path)
            if text is not None:
                changes.append(FileChange(path, list(enumerate(text.splitlines(), 1))))
    findings = [f for c in changes for f in check_lines(c.path, c.added, c.removed)]
    return diff, findings


def build_report(
    cache_dir: Path,
    base: str,
    installed: str,
    pkg: AurPackage | None,
    mode: str,
    state: dict,
) -> Report:
    """mode: "check" (installed -> AUR), "watch" (last seen -> AUR), "audit" (all files at AUR HEAD)."""
    if pkg is None:
        return Report(base, installed, None, None, error="not found in the AUR (installed from another repo, or deleted from the AUR)")
    report = Report(base, installed, pkg.version, pkg.maintainer, pkg.last_modified)

    seen = state.get(base, {})
    if "maintainer" in seen and (f := maintainer_change(seen["maintainer"], pkg.maintainer)):
        report.findings.append(f)

    if mode == "check" and pkg.version == installed:
        report.compared = "up to date"
        return report
    if mode == "watch" and seen.get("aur_version") == pkg.version and seen.get("last_modified") == pkg.last_modified:
        report.compared = "no change since last run"
        return report

    repo = Repo(cache_dir, base)
    try:
        repo.sync()
        head = repo.head()
    except (subprocess.SubprocessError, OSError) as e:
        stderr = getattr(e, "stderr", b"") or b""
        report.error = f"git failed: {stderr.decode(errors='replace').strip() or e}"
        return report
    report.new_rev = head

    last = seen.get("rev") if seen.get("rev") and repo.has_commit(seen["rev"]) else None
    old = None
    if mode == "watch" and last:
        old, report.compared = last, "since last run"
    elif mode in ("check", "watch"):
        old = commit_for_version(repo, installed)
        if old:
            report.compared = f"installed {installed} -> AUR {pkg.version}"
        elif last:
            # typical for -git packages: the installed pkgver is computed at build time
            old, report.compared = last, "since last run (installed version not found in package history)"
    if old is None:
        report.compared = "all files" if mode == "audit" else "all files (installed version not found in package history)"
    if old == head:
        report.compared = report.compared or "no change"
        return report

    report.old_rev = old
    if old:
        report.commits = repo.count_between(old, head)
    report.diff, findings = analyse(repo, old, head)
    report.findings += findings
    return report


def run(cache_dir: Path, packages: dict[str, str], aur: dict[str, AurPackage], mode: str, state: dict, jobs: int = 4) -> list[Report]:
    """One report per package base; installed packages from the same base are merged."""
    bases: dict[str, tuple[str, AurPackage | None]] = {}
    for name, version in sorted(packages.items()):
        pkg = aur.get(name)
        bases.setdefault(pkg.base if pkg else name, (version, pkg))

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = [pool.submit(build_report, cache_dir, base, version, pkg, mode, state) for base, (version, pkg) in bases.items()]
        return [f.result() for f in futures]
