import importlib.util
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from aurguard import cli, config, helpers, llm


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "aurguard" / "config.toml"

    def tearDown(self):
        self.tmp.cleanup()

    def test_roundtrip_and_permissions(self):
        cfg = config.Config()
        cfg.ai.provider, cfg.ai.api_key, cfg.ai.auto_explain = "gemini", 'k"ey\\with-quotes', True
        cfg.aur.helper_args = "-Sua --ignore opentabletdriver"
        config.save(cfg, self.path)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        loaded = config.load(self.path)
        self.assertEqual(loaded, cfg)

    def test_missing_file_gives_defaults(self):
        self.assertEqual(config.load(self.path), config.Config())

    def test_set_value_validates(self):
        cfg = config.Config()
        config.set_value(cfg, "ai.provider", "deepseek")
        config.set_value(cfg, "ai.auto_explain", "yes")
        self.assertEqual((cfg.ai.provider, cfg.ai.auto_explain), ("deepseek", True))
        for bad in (("ai.provider", "skynet"), ("ai.nope", "1"), ("aur.helper", "pikaur"), ("ai.auto_explain", "maybe")):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                config.set_value(cfg, *bad)

    def test_provider_change_drops_key_and_model(self):
        cfg = config.Config()
        cfg.ai = config.AiConfig(provider="deepseek", model="deepseek-v4-pro", api_key="sk-deepseek")
        config.set_value(cfg, "ai.provider", "gemini")
        self.assertEqual((cfg.ai.model, cfg.ai.api_key), ("", ""))
        cfg.ai.api_key = "g"
        config.set_value(cfg, "ai.provider", "gemini")  # same provider: kept
        self.assertEqual(cfg.ai.api_key, "g")

    def test_key_resolution_prefers_environment(self):
        ai = config.AiConfig(provider="openai", api_key="stored")
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(ai.resolved_key(), ("stored", "config file"))
        with mock.patch.dict(os.environ, {"OPENAI_API_KEY": "env"}, clear=True):
            self.assertEqual(ai.resolved_key(), ("env", "$OPENAI_API_KEY"))

    def test_defaults_per_provider(self):
        self.assertEqual(config.AiConfig(provider="claude").resolved_model(), "claude-opus-5-5")
        self.assertEqual(config.AiConfig(provider="deepseek").resolved_base_url(), "https://api.deepseek.com")
        self.assertIsNone(config.AiConfig(provider="openai").resolved_base_url())
        self.assertEqual(config.AiConfig(provider="custom", base_url="http://localhost:11434/v1").resolved_base_url(), "http://localhost:11434/v1")

    def test_masked(self):
        cfg = config.Config()
        cfg.ai.api_key = "sk-1234567890abcdef"
        self.assertNotIn("1234567890", config.masked(cfg))


class HelperTests(unittest.TestCase):
    def test_ignored_in_args(self):
        args = ["-Sua", "--ignore", "opentabletdriver,java17-openjfx-bin", "--ignore=foo"]
        self.assertEqual(helpers.ignored_in_args(args), {"opentabletdriver", "java17-openjfx-bin", "foo"})

    def test_pacman_conf(self):
        with tempfile.NamedTemporaryFile("w", suffix=".conf") as f:
            f.write("[options]\nIgnorePkg = linux  nvidia-*  # pinned\n#IgnorePkg = commented\n[core]\nIgnorePkg = not-options\n")
            f.flush()
            self.assertEqual(helpers.ignored_in_pacman_conf(Path(f.name)), {"linux", "nvidia-*"})

    def test_detect_order(self):
        installed = {"yay"}
        with mock.patch("shutil.which", side_effect=lambda n: f"/usr/bin/{n}" if n in installed else None):
            self.assertEqual(helpers.detect(), "yay")
            installed.add("paru")
            self.assertEqual(helpers.detect(), "paru")
            self.assertEqual(helpers.detect("yay"), "yay")

    def test_skip_ignored_globs(self):
        self.assertEqual(cli.skip_ignored({"nvidia-dkms": "1", "paru": "2"}, {"nvidia-*"}), {"paru": "2"})


VERDICT = {"verdict": "needs_attention", "summary": "Adds npm install.", "lines_of_concern": ["npm install x"]}


@unittest.skipUnless(importlib.util.find_spec("openai") and importlib.util.find_spec("anthropic"), "needs the [ai] extra")
class AiProviderTests(unittest.TestCase):
    """The SDK clients are replaced by fakes; no network."""

    def test_no_key(self):
        with mock.patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(llm.AiError, "GEMINI_API_KEY"):
            llm.explain(config.AiConfig(provider="gemini"), "p", "c", "diff", [])

    def test_no_provider(self):
        with self.assertRaisesRegex(llm.AiError, "setup"):
            llm.explain(config.AiConfig(), "p", "c", "diff", [])

    def test_openai_schema_path(self):
        import openai

        def parse(**kw):
            parsed = kw["response_format"].model_validate(VERDICT)
            msg = SimpleNamespace(parsed=parsed, refusal=None)
            return SimpleNamespace(choices=[SimpleNamespace(message=msg)], model=kw["model"])

        client = mock.MagicMock()
        client.chat.completions.parse.side_effect = parse
        with mock.patch.object(openai, "OpenAI", return_value=client) as ctor:
            out = llm.explain(config.AiConfig(provider="gemini", api_key="k"), "p", "c", "+npm install x", [])
        self.assertEqual(ctor.call_args.kwargs["base_url"], "https://generativelanguage.googleapis.com/v1beta/openai/")
        self.assertEqual((out["verdict"], out["model"], out["provider"]), ("needs_attention", "gemini-4-hydrogen", "gemini"))

    def test_json_mode_retries_blank_answer(self):
        import openai

        answers = iter(["   ", json.dumps(VERDICT)])
        client = mock.MagicMock()
        client.chat.completions.create.side_effect = lambda **kw: SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=next(answers)))], model=kw["model"])
        with mock.patch.object(openai, "OpenAI", return_value=client):
            out = llm.explain(config.AiConfig(provider="deepseek", api_key="k"), "p", "c", "diff", [])
        self.assertEqual(out["summary"], "Adds npm install.")
        kwargs = client.chat.completions.create.call_args.kwargs
        self.assertEqual(kwargs["response_format"], {"type": "json_object"})
        self.assertIn("JSON", kwargs["messages"][0]["content"])

    def test_json_mode_bad_shape(self):
        import openai

        client = mock.MagicMock()
        client.chat.completions.create.return_value = SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"verdict": "fine"}'))], model="m")
        with mock.patch.object(openai, "OpenAI", return_value=client), self.assertRaisesRegex(llm.AiError, "expected format"):
            llm.explain(config.AiConfig(provider="custom", model="llama", base_url="http://localhost:11434/v1"), "p", "c", "d", [])

    def test_claude_path(self):
        import anthropic

        client = mock.MagicMock()
        client.beta.messages.parse.side_effect = lambda **kw: SimpleNamespace(
            stop_reason="end_turn", parsed_output=kw["output_format"].model_validate(VERDICT), model=kw["model"])
        with mock.patch.object(anthropic, "Anthropic", return_value=client):
            out = llm.explain(config.AiConfig(provider="claude", api_key="k"), "p", "c", "d", [])
        self.assertEqual(out["model"], "claude-opus-5-5")
        self.assertEqual(client.beta.messages.parse.call_args.kwargs["fallbacks"], "default")


class UpgradeTests(unittest.TestCase):
    def run_upgrade(self, argv, scan_status, cfg=None, tty=False, answer="n"):
        cfg = cfg or config.Config()
        with mock.patch.object(cli.config, "load", return_value=cfg), \
             mock.patch.object(cli, "run_scan", return_value=scan_status) as scan, \
             mock.patch.object(cli.helpers, "detect", side_effect=lambda p="": p or "yay"), \
             mock.patch.object(cli.helpers, "ignored_in_pacman_conf", return_value={"linux"}), \
             mock.patch("sys.stdin.isatty", return_value=tty), \
             mock.patch("builtins.input", return_value=answer), \
             mock.patch("os.execvp") as execvp:
            status = cli.main(argv)
        return status, scan, execvp

    def test_clean_check_runs_helper_with_args(self):
        status, scan, execvp = self.run_upgrade(["upgrade", "--", "-Sua", "--ignore", "opentabletdriver"], 0)
        execvp.assert_called_once_with("yay", ["yay", "-Sua", "--ignore", "opentabletdriver"])
        self.assertEqual(scan.call_args.args[3], {"opentabletdriver", "linux"})

    def test_configured_helper_and_args(self):
        cfg = config.Config()
        cfg.aur.helper, cfg.aur.helper_args = "paru", "-Sua --devel"
        _, _, execvp = self.run_upgrade(["upgrade"], 0, cfg)
        execvp.assert_called_once_with("paru", ["paru", "-Sua", "--devel"])

    def test_findings_stop_without_tty(self):
        status, _, execvp = self.run_upgrade(["upgrade"], 1)
        self.assertEqual(status, 1)
        execvp.assert_not_called()

    def test_findings_ask_on_tty(self):
        _, _, execvp = self.run_upgrade(["upgrade"], 1, tty=True, answer="y")
        execvp.assert_called_once()
        _, _, execvp = self.run_upgrade(["upgrade"], 1, tty=True, answer="")
        execvp.assert_not_called()

    def test_check_error_never_upgrades(self):
        status, _, execvp = self.run_upgrade(["upgrade", "--yes"], 2)
        self.assertEqual(status, 2)
        execvp.assert_not_called()

    def test_dashdash_only_for_upgrade(self):
        with self.assertRaises(SystemExit):
            cli.parse_args(["check", "--", "-Sua"])


if __name__ == "__main__":
    unittest.main()
