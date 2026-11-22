"""aurguard command line."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, aur, notify, scan, state
from .rules import rank

HELP = """\
commands:
  check   before upgrading: what changed between your installed version and the AUR
  watch   for a timer: what changed since the last run (notifies, remembers state)
  audit   one-off: scan every file of every installed AUR package as it is now

exit status: 0 nothing above --fail-on, 1 findings at or above it, 2 error
"""

COLORS = {"high": "\033[1;31m", "medium": "\033[33m", "info": "\033[36m", "dim": "\033[2m", "bold": "\033[1m", "off": "\033[0m"}


def parse_args(argv):
    p = argparse.ArgumentParser(prog="aurguard", description=__doc__, epilog=HELP, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"aurguard {__version__}")
    p.add_argument("command", choices=("check", "watch", "audit"))
    p.add_argument("packages", nargs="*", help="limit to these installed packages (default: all from pacman -Qm)")
    p.add_argument("--json", action="store_true", help="print the report as JSON")
    p.add_argument("--diff", action="store_true", help="also print the diff for packages with findings")
    p.add_argument("--explain", action="store_true", help="ask Claude to explain diffs with findings (needs aurguard[llm] + ANTHROPIC_API_KEY)")
    p.add_argument("--notify", action="store_true", help="desktop notification when something is found")
    p.add_argument("--webhook", default=os.environ.get("AURGUARD_WEBHOOK"), help="POST findings here (Discord/Slack/ntfy/JSON; env AURGUARD_WEBHOOK)")
    p.add_argument("--min-severity", default="medium", choices=("info", "medium", "high"), help="hide findings below this (default: %(default)s)")
    p.add_argument("--fail-on", default="high", choices=("info", "medium", "high"), help="exit 1 at this severity (default: %(default)s)")
    p.add_argument("--jobs", type=int, default=4, help="parallel git fetches (default: %(default)s)")
    p.add_argument("--cache-dir", type=Path, default=state.CACHE_DIR, help="bare clones of AUR repos (default: %(default)s)")
    p.add_argument("--state", type=Path, default=state.STATE_DIR / "state.json", help="state file (default: %(default)s)")
    p.add_argument("--no-color", action="store_true")
    return p.parse_args(argv)


def render(reports, args) -> str:
    use_color = sys.stdout.isatty() and not args.no_color and "NO_COLOR" not in os.environ

    def c(key, text):
        return f"{COLORS[key]}{text}{COLORS['off']}" if use_color else text

    out = []
    quiet = 0
    for r in sorted(reports, key=lambda r: (-rank(r.worst or "info") if r.findings else 1, r.base)):
        shown = [f for f in r.findings if rank(f.severity) >= rank(args.min_severity)]
        if not shown and not r.error and not (r.commits or r.old_rev is None and r.new_rev):
            quiet += 1
            continue
        version = f"{r.installed} -> {r.aur_version}" if r.aur_version and r.aur_version != r.installed else r.installed
        head = f"{c('bold', r.base)} {version}"
        meta = ", ".join(x for x in (r.compared, f"{r.commits} commits" if r.commits else "", f"maintainer {r.maintainer}" if r.maintainer else "") if x)
        out.append(f"{head}  {c('dim', meta)}")
        if r.error:
            out.append(f"  {c('medium', 'skipped')}  {r.error}")
        for f in shown:
            where = f"{f.file}:{f.line}" if f.file else ""
            out.append(f"  {c(f.severity, f.severity.upper().ljust(6))}  {f.rule}  {c('dim', where)}")
            if f.text:
                out.append(f"          {f.text}")
            out.append(f"          {c('dim', f.message)}")
        if r.explanation:
            e = r.explanation
            if "error" in e:
                out.append(f"  {c('dim', 'explain failed: ' + e['error'])}")
            else:
                out.append(f"  {c('bold', 'Claude:')} {e['verdict']} - {e['summary']}")
                for line in e["lines_of_concern"]:
                    out.append(f"          {c('dim', line)}")
        if not shown and not r.error:
            out.append(f"  {c('dim', 'no findings')}")
        if args.diff and shown and r.diff:
            out.append(c("dim", r.diff.rstrip()))
        out.append("")
    total = len(reports)
    flagged = sum(1 for r in reports if any(rank(f.severity) >= rank(args.min_severity) for f in r.findings))
    out.append(c("dim", f"{total} package bases, {flagged} with findings, {quiet} quiet"))
    return "\n".join(out)


def summary_text(reports, min_sev: str) -> tuple[str, str, bool]:
    flagged = [r for r in reports if any(rank(f.severity) >= rank(min_sev) for f in r.findings)]
    critical = any(r.worst == "high" for r in flagged)
    title = f"aurguard: {len(flagged)} AUR package(s) need a look"
    lines = []
    for r in flagged:
        worst = [f for f in r.findings if f.severity == r.worst]
        lines.append(f"{r.base} {r.aur_version}: {r.worst.upper()} {', '.join(sorted({f.rule for f in worst}))}")
    return title, "\n".join(lines), critical


def main(argv=None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    try:
        installed = aur.installed_foreign()
        if args.packages:
            missing = [p for p in args.packages if p not in installed]
            if missing:
                print(f"aurguard: not installed from the AUR: {', '.join(missing)}", file=sys.stderr)
                return 2
            installed = {p: installed[p] for p in args.packages}
        info = aur.rpc_info(sorted(installed))
    except Exception as e:  # noqa: BLE001 - one line for the user, not a traceback
        print(f"aurguard: {e}", file=sys.stderr)
        return 2

    st = state.load(args.state)
    reports = scan.run(args.cache_dir, installed, info, args.command, st, jobs=args.jobs)

    if args.explain:
        from . import llm

        for r in reports:
            if r.findings and r.worst != "info":
                try:
                    r.explanation = llm.explain(r.base, r.compared, r.diff or "(full file scan, no diff)", [f.as_dict() for f in r.findings])
                except Exception as e:  # noqa: BLE001
                    msg = str(e)
                    if "authentication" in msg.lower():
                        msg = "no Claude API credentials - set ANTHROPIC_API_KEY"
                    r.explanation = {"error": msg}

    print(json.dumps([r.as_dict() for r in reports], indent=2) if args.json else render(reports, args))

    title, body, critical = summary_text(reports, args.min_severity)
    if body:
        if args.notify:
            notify.desktop(title, body, critical)
        if args.webhook:
            try:
                notify.webhook(args.webhook, title, body, {"reports": [r.as_dict() for r in reports if r.findings]})
            except OSError as e:
                print(f"aurguard: webhook failed: {e}", file=sys.stderr)

    state.remember(st, reports)
    state.save(args.state, st)

    failing = any(rank(f.severity) >= rank(args.fail_on) for r in reports for f in r.findings)
    return 1 if failing else 0
