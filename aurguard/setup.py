"""`aurguard setup`: interactive configuration from the terminal."""

from __future__ import annotations

import getpass
import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import config, helpers

SYSTEMD_USER = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "systemd" / "user"

SERVICE = """[Unit]
Description=aurguard: check installed AUR packages for suspicious changes
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={exe} watch
# a finding makes aurguard exit 1; that is a result, not a failed unit
SuccessExitStatus=1
Nice=10
"""

TIMER = """[Unit]
Description=Run aurguard watch every 6 hours

[Timer]
OnBootSec=10min
OnUnitActiveSec=6h
RandomizedDelaySec=15min
Persistent=true

[Install]
WantedBy=timers.target
"""


def install_hint(extra: str) -> str:
    source = Path(__file__).resolve().parent.parent
    if (source / "pyproject.toml").exists():
        return f"uv tool install --force --editable '{source}[{extra}]'   (or pip install '{source}[{extra}]' in its venv)"
    return f"pip install '{'anthropic' if extra == 'claude' else 'openai'}' into the environment aurguard runs from"


def ask(question: str, default: str = "") -> str:
    hint = f" [{default}]" if default else ""
    answer = input(f"{question}{hint}: ").strip()
    return answer or default


def ask_yes(question: str, default: bool) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        answer = input(f"{question} [{hint}]: ").strip().lower()
        if not answer:
            return default
        if answer in ("y", "yes", "t", "tak"):
            return True
        if answer in ("n", "no", "nie"):
            return False


def choose(question: str, options: list[tuple[str, str]], default: str) -> str:
    print(question)
    for i, (_, label) in enumerate(options, 1):
        mark = " (current)" if options[i - 1][0] == default else ""
        print(f"  {i}) {label}{mark}")
    default_index = next((str(i) for i, (k, _) in enumerate(options, 1) if k == default), "1")
    while True:
        answer = ask("Choose", default_index)
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return options[int(answer) - 1][0]


def section(title: str) -> None:
    print(f"\n== {title} ==")


def setup_helper(cfg: config.Config) -> None:
    section("AUR helper")
    installed = [h for h in helpers.SUPPORTED if shutil.which(h)]
    if not installed:
        print("Neither paru nor yay is installed. `aurguard upgrade` needs one of them; check/watch/audit work without.")
        return
    current = cfg.aur.helper if cfg.aur.helper in installed else installed[0]
    if len(installed) > 1:
        cfg.aur.helper = choose("Which helper should `aurguard upgrade` run?", [(h, h) for h in installed], current)
    else:
        cfg.aur.helper = installed[0]
        print(f"Using {cfg.aur.helper}.")
    print("Arguments for the upgrade, e.g. `-Sua --ignore somepkg`. Packages passed with --ignore are skipped by the check too.")
    cfg.aur.helper_args = ask("Helper arguments", cfg.aur.helper_args or "-Sua")


def setup_ai(cfg: config.Config, path: Path) -> None:
    section("AI explanations (optional)")
    print("For packages with findings, an AI model can explain in plain words what the change does.")
    print("Only diffs that the rules flagged are sent, together with the rule findings.")
    options = [("none", "No AI - rules only")] + [(k, p.label) for k, p in config.PROVIDERS.items()]
    provider = choose("Provider:", options, cfg.ai.provider)
    changed = provider != cfg.ai.provider
    if changed:
        # a key for one provider must never be sent to another
        cfg.ai.model = cfg.ai.base_url = cfg.ai.api_key = ""
    cfg.ai.provider = provider
    if provider == "none":
        cfg.ai.api_key = ""
        cfg.ai.auto_explain = False
        return

    p = config.PROVIDERS[provider]
    module = "anthropic" if p.sdk == "anthropic" else "openai"
    if importlib.util.find_spec(module) is None:
        extra = "claude" if p.sdk == "anthropic" else "openai"
        print(f"\n! The `{module}` Python package is missing. Install it next to aurguard:")
        print(f"    {install_hint(extra)}")

    if provider == "custom":
        print("Examples: https://openrouter.ai/api/v1, http://localhost:11434/v1 (Ollama), http://localhost:1234/v1 (LM Studio)")
        cfg.ai.base_url = ask("Base URL", cfg.ai.base_url)
    model = ask("Model", cfg.ai.model or p.default_model)
    # keep the default implicit, so a newer default in a later aurguard version applies
    cfg.ai.model = "" if model == p.default_model else model

    env_var = next((v for v in p.env if os.environ.get(v)), None)
    if env_var:
        print(f"Found ${env_var} in your environment - it will be used (it wins over a stored key).")
        if cfg.ai.api_key and ask_yes("Remove the key stored in the config file?", True):
            cfg.ai.api_key = ""
    else:
        if p.key_url:
            print(f"Get a key at {p.key_url}")
        print(f"Either export {' or '.join('$' + v for v in p.env)} in your shell profile, or store the key in")
        print(f"{path} (plain text, readable only by you).")
        hint = " (Enter keeps the stored one)" if cfg.ai.api_key else " (Enter to skip)"
        key = getpass.getpass(f"API key{hint}: ").strip()
        if key:
            cfg.ai.api_key = key

    cfg.ai.auto_explain = ask_yes("Explain findings automatically in check/upgrade (without --explain)?", True if changed else cfg.ai.auto_explain)

    if ask_yes("Send a small test request now?", True):
        from .llm import AiError, test_connection

        try:
            result = test_connection(cfg.ai)
            print(f"OK - {result['model']} answered: {result['verdict']}, \"{result['summary'][:120]}\"")
        except AiError as e:
            print(f"! Test failed: {e}")


def setup_notifications(cfg: config.Config) -> None:
    section("Notifications")
    if shutil.which("notify-send"):
        cfg.notify.desktop = ask_yes("Desktop notification when `watch` finds something?", cfg.notify.desktop)
    else:
        print("notify-send not found (package libnotify) - desktop notifications are off.")
        cfg.notify.desktop = False
    print("Optional webhook: Discord/Slack incoming webhook, an ntfy topic URL, or any URL that takes JSON (n8n...).")
    cfg.notify.webhook = ask("Webhook URL (empty: none)", cfg.notify.webhook)


def setup_timer() -> None:
    section("Background checks")
    if not shutil.which("systemctl"):
        print("systemctl not found - skipping.")
        return
    timer = SYSTEMD_USER / "aurguard-watch.timer"
    if not ask_yes("Run `aurguard watch` every 6 hours with a systemd user timer?", not timer.exists()):
        return
    exe = shutil.which("aurguard") or f"{sys.executable} -m aurguard"
    SYSTEMD_USER.mkdir(parents=True, exist_ok=True)
    (SYSTEMD_USER / "aurguard-watch.service").write_text(SERVICE.format(exe=exe))
    timer.write_text(TIMER)
    for cmd in (["systemctl", "--user", "daemon-reload"], ["systemctl", "--user", "enable", "--now", "aurguard-watch.timer"]):
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            print(f"! {' '.join(cmd)} failed: {res.stderr.strip()}")
            return
    print(f"Timer enabled ({timer}). Logs: journalctl --user -u aurguard-watch")


def run(cfg: config.Config, path: Path) -> int:
    if not sys.stdin.isatty():
        print("aurguard setup is interactive; use `aurguard setup --set key=value` in scripts.", file=sys.stderr)
        return 2
    print(f"aurguard setup - writes {path}. Enter keeps the value in [brackets]; Ctrl-C quits without saving.")
    try:
        setup_helper(cfg)
        setup_ai(cfg, path)
        setup_notifications(cfg)
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled, nothing saved.")
        return 1
    config.save(cfg, path)
    print(f"\nSaved {path}")
    try:
        setup_timer()
    except (KeyboardInterrupt, EOFError):
        print("\nSkipped the timer.")
    print("\nDone. Try: aurguard check")
    return 0
