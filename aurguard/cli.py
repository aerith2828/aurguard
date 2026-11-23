"""aurguard command line."""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import sys
from pathlib import Path

from . import __version__, aur, config, helpers, notify, scan, state
from .rules import rank

DESCRIPTION = "Review what changed in the AUR packages you have installed before you upgrade them."

HELP = """\
commands:
  check     before upgrading: what changed between your installed version and the AUR
  upgrade   check, then run paru or yay (aurguard upgrade -- -Sua --ignore foo)
  watch     for a timer: what changed since the last run (notifies, remembers state)
  audit     one-off: scan every file of every installed AUR package as it is now
  setup     configure the AUR helper, AI provider, API key and notifications

exit status: 0 nothing at or above --fail-on, 1 findings at or above it, 2 error
"""

COLORS = {"high": "\033[1;31m", "medium": "\033[33m", "info": "\033[36m", "dim": "\033[2m", "bold": "\033[1m", "off": "\033[0m"}


def parse_args(argv: list[str]):
    # everything after "--" goes to paru/yay untouched
    helper_args = None
    if "--" in argv:
        i = argv.index("--")
        argv, helper_args = argv[:i], argv[i + 1 :]

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", type=Path, default=config.CONFIG_PATH, help="config file (default: %(default)s)")

    scan_opts = argparse.ArgumentParser(add_help=False)
    scan_opts.add_argument("--json", action="store_true", help="print the report as JSON")
    scan_opts.add_argument("--diff", action="store_true", help="also print the diff for packages with findings")
    scan_opts.add_argument("--explain", action=argparse.BooleanOptionalAction, default=None,
                           help="ask the configured AI to explain diffs with findings (default: ai.auto_explain from setup)")
    scan_opts.add_argument("--notify", action=argparse.BooleanOptionalAction, default=None, help="desktop notification when something is found")
    scan_opts.add_argument("--webhook", default=None, help="POST findings here (Discord/Slack/ntfy/JSON; env AURGUARD_WEBHOOK)")
    scan_opts.add_argument("--min-severity", default="medium", choices=("info", "medium", "high"), help="hide findings below this (default: %(default)s)")
    scan_opts.add_argument("--fail-on", default="high", choices=("info", "medium", "high"), help="exit 1 at this severity (default: %(default)s)")
    scan_opts.add_argument("--jobs", type=int, default=4, help="parallel git fetches (default: %(default)s)")
    scan_opts.add_argument("--cache-dir", type=Path, default=state.CACHE_DIR, help="bare clones of AUR repos (default: %(default)s)")
    scan_opts.add_argument("--state", type=Path, default=state.STATE_DIR / "state.json", help="state file (default: %(default)s)")
    scan_opts.add_argument("--no-color", action="store_true")

    p = argparse.ArgumentParser(prog="aurguard", description=DESCRIPTION, epilog=HELP, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version", version=f"aurguard {__version__}")
    sub = p.add_subparsers(dest="command", required=True, metavar="command")

    for name, text in (("check", "compare installed versions with the AUR"), ("watch", "changes since the last run"), ("audit", "scan all files as they are now")):
        c = sub.add_parser(name, parents=[common, scan_opts], help=text)
        c.add_argument("packages", nargs="*", help="limit to these installed packages (default: all from pacman -Qm)")
        if name == "check":
            c.add_argument("--include-ignored", action="store_true", help="also check packages in IgnorePkg (pacman.conf)")

    u = sub.add_parser("upgrade", parents=[common, scan_opts], help="check, then upgrade with paru or yay",
                       description="Run `check`, then the AUR helper. Arguments after -- go to the helper "
                                   "(default: aur.helper_args from setup, normally -Sua).")
    u.add_argument("--helper", choices=helpers.SUPPORTED, help="paru or yay (default: from setup, else whichever is installed)")
    u.add_argument("--yes", action="store_true", help="upgrade even if something was found (no question)")
    u.add_argument("--include-ignored", action="store_true", help=argparse.SUPPRESS)

    s = sub.add_parser("setup", parents=[common], help="interactive configuration")
    s.add_argument("--show", action="store_true", help="print the current configuration (API key masked)")
    s.add_argument("--set", action="append", default=[], metavar="KEY=VALUE", help="change one setting without questions, e.g. ai.provider=gemini")

    args = p.parse_args(argv)
    if helper_args is not None and args.command != "upgrade":
        p.error("arguments after -- are only used by `aurguard upgrade`")
    args.helper_args = helper_args
    return args


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
                out.append(f"  {c('dim', 'AI explanation failed: ' + e['error'])}")
            else:
                out.append(f"  {c('bold', e['model'] + ':')} {e['verdict']} - {e['summary']}")
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


def skip_ignored(installed: dict[str, str], patterns: set[str]) -> dict[str, str]:
    return {n: v for n, v in installed.items() if not any(fnmatch.fnmatch(n, p) for p in patterns)}


def run_scan(args, cfg: config.Config, mode: str, ignored: set[str] = frozenset()) -> int:
    """Scan, print, notify. Returns the exit status (0/1/2)."""
    try:
        installed = aur.installed_foreign()
        packages = getattr(args, "packages", [])
        if packages:
            missing = [p for p in packages if p not in installed]
            if missing:
                print(f"aurguard: not installed from the AUR: {', '.join(missing)}", file=sys.stderr)
                return 2
            installed = {p: installed[p] for p in packages}
        elif ignored:
            installed = skip_ignored(installed, ignored)
        info = aur.rpc_info(sorted(installed))
    except Exception as e:  # noqa: BLE001 - one line for the user, not a traceback
        print(f"aurguard: {e}", file=sys.stderr)
        return 2

    st = state.load(args.state)
    reports = scan.run(args.cache_dir, installed, info, mode, st, jobs=args.jobs)

    explain = args.explain if args.explain is not None else (cfg.ai.auto_explain and mode != "audit")
    if explain:
        from . import llm

        for r in reports:
            if r.findings and r.worst != "info":
                try:
                    r.explanation = llm.explain(cfg.ai, r.base, r.compared, r.diff or "(full file scan, no diff)", [f.as_dict() for f in r.findings])
                except llm.AiError as e:
                    r.explanation = {"error": str(e)}

    print(json.dumps([r.as_dict() for r in reports], indent=2) if args.json else render(reports, args))

    title, body, critical = summary_text(reports, args.min_severity)
    desktop = args.notify if args.notify is not None else (mode == "watch" and cfg.notify.desktop)
    webhook = args.webhook or os.environ.get("AURGUARD_WEBHOOK") or cfg.notify.webhook
    if body:
        if desktop:
            notify.desktop(title, body, critical)
        if webhook:
            try:
                notify.webhook(webhook, title, body, {"reports": [r.as_dict() for r in reports if r.findings]})
            except OSError as e:
                print(f"aurguard: webhook failed: {e}", file=sys.stderr)

    state.remember(st, reports)
    state.save(args.state, st)

    failing = any(rank(f.severity) >= rank(args.fail_on) for r in reports for f in r.findings)
    return 1 if failing else 0


def upgrade(args, cfg: config.Config) -> int:
    helper = args.helper or helpers.detect(cfg.aur.helper)
    if not helper or not helpers.detect(helper):
        print("aurguard: neither paru nor yay is installed", file=sys.stderr)
        return 2
    helper_args = args.helper_args if args.helper_args is not None else helpers.split_args(cfg.aur.helper_args or "-Sua")
    ignored = helpers.ignored_in_args(helper_args) | helpers.ignored_in_pacman_conf()

    status = run_scan(args, cfg, "check", ignored)
    command = [helper, *helper_args]
    if status == 2:
        print("aurguard: the check failed, not upgrading. Fix the error or run the helper yourself.", file=sys.stderr)
        return 2
    if status == 1 and not args.yes:
        if not sys.stdin.isatty():
            print("aurguard: findings above - not upgrading (use --yes to override).", file=sys.stderr)
            return 1
        answer = input(f"\nSomething was found. Run `{' '.join(command)}` anyway? [y/N]: ").strip().lower()
        if answer not in ("y", "yes", "t", "tak"):
            print("Not upgrading.")
            return 1
    print(f"\n-> {' '.join(command)}", flush=True)
    os.execvp(helper, command)
    return 0  # not reached


def main(argv=None) -> int:
    args = parse_args(list(argv) if argv is not None else sys.argv[1:])
    try:
        cfg = config.load(args.config)
    except RuntimeError as e:
        print(f"aurguard: {e}", file=sys.stderr)
        return 2

    if args.command == "setup":
        if args.set:
            try:
                # provider first: changing it resets model, base_url and key
                for item in sorted(args.set, key=lambda i: not i.startswith("ai.provider=")):
                    key, sep, value = item.partition("=")
                    if not sep:
                        raise ValueError(f"expected KEY=VALUE, got {item!r}")
                    config.set_value(cfg, key.strip(), value.strip())
            except ValueError as e:
                print(f"aurguard: {e}", file=sys.stderr)
                return 2
            config.save(cfg, args.config)
        if args.show or args.set:
            print(config.masked(cfg), end="")
            key, source = cfg.ai.resolved_key()
            if cfg.ai.enabled:
                print(f"# API key in use: {'from ' + source if key else 'none found'}; model: {cfg.ai.resolved_model() or '-'}")
            return 0
        from .setup import run

        return run(cfg, args.config)

    if args.command == "upgrade":
        return upgrade(args, cfg)

    ignored = set()
    if args.command == "check" and not args.include_ignored and not args.packages:
        ignored = helpers.ignored_in_pacman_conf()
    return run_scan(args, cfg, args.command, ignored)
