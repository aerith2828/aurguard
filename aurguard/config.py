"""User configuration: ~/.config/aurguard/config.toml, written by `aurguard setup`.

Command line flags win over environment variables, which win over this file.
"""

from __future__ import annotations

import json
import os
import tomllib
from dataclasses import asdict, dataclass, field
from pathlib import Path

CONFIG_PATH = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "aurguard" / "config.toml"


@dataclass(frozen=True)
class Provider:
    label: str
    default_model: str
    env: tuple[str, ...]  # environment variables checked for the API key, in order
    base_url: str | None = None  # None: the SDK default
    sdk: str = "openai"  # python package that talks to it
    structured: str = "schema"  # "schema": response_format=<model>, "json": json_object mode
    key_url: str = ""


PROVIDERS: dict[str, Provider] = {
    "claude": Provider("Claude (Anthropic)", "claude-opus-5-5", ("ANTHROPIC_API_KEY",), sdk="anthropic",
                       key_url="https://platform.claude.com/settings/keys"),
    "openai": Provider("ChatGPT (OpenAI)", "gpt-6.2-astra", ("OPENAI_API_KEY",),
                       key_url="https://platform.openai.com/api-keys"),
    "gemini": Provider("Gemini (Google)", "gemini-4-hydrogen", ("GEMINI_API_KEY", "GOOGLE_API_KEY"),
                       base_url="https://generativelanguage.googleapis.com/v1beta/openai/",
                       key_url="https://aistudio.google.com/apikey"),
    "deepseek": Provider("DeepSeek", "deepseek-flash", ("DEEPSEEK_API_KEY",), base_url="https://api.deepseek.com",
                         structured="json", key_url="https://platform.deepseek.com/api_keys"),
    "custom": Provider("Other OpenAI-compatible API (OpenRouter, Ollama, LM Studio, ...)", "", ("AURGUARD_API_KEY",),
                       structured="json"),
}


@dataclass
class AiConfig:
    provider: str = "none"  # "none" or a key of PROVIDERS
    model: str = ""
    api_key: str = ""  # empty: read from the provider's environment variable
    base_url: str = ""  # only for "custom"
    auto_explain: bool = False  # explain findings in check/upgrade without --explain

    @property
    def enabled(self) -> bool:
        return self.provider in PROVIDERS

    def resolved_model(self) -> str:
        return self.model or (PROVIDERS[self.provider].default_model if self.enabled else "")

    def resolved_key(self) -> tuple[str, str]:
        """(key, where it came from). Environment variables win over the stored key."""
        if not self.enabled:
            return "", ""
        for var in ("AURGUARD_API_KEY", *PROVIDERS[self.provider].env):
            if os.environ.get(var):
                return os.environ[var], f"${var}"
        if self.api_key:
            return self.api_key, "config file"
        return "", ""

    def resolved_base_url(self) -> str | None:
        if self.provider == "custom":
            return self.base_url or None
        return PROVIDERS[self.provider].base_url if self.enabled else None


@dataclass
class AurConfig:
    helper: str = ""  # "paru" or "yay"; empty: whichever is installed (paru first)
    helper_args: str = "-Sua"  # what `aurguard upgrade` runs the helper with


@dataclass
class NotifyConfig:
    desktop: bool = True  # notify-send from `watch`
    webhook: str = ""


@dataclass
class Config:
    ai: AiConfig = field(default_factory=AiConfig)
    aur: AurConfig = field(default_factory=AurConfig)
    notify: NotifyConfig = field(default_factory=NotifyConfig)


SECTIONS = {"ai": AiConfig, "aur": AurConfig, "notify": NotifyConfig}


def load(path: Path = CONFIG_PATH) -> Config:
    try:
        data = tomllib.loads(path.read_text())
    except FileNotFoundError:
        return Config()
    except tomllib.TOMLDecodeError as e:
        raise RuntimeError(f"{path}: {e}") from e
    cfg = Config()
    for name, cls in SECTIONS.items():
        known = set(cls.__dataclass_fields__)
        values = {k: v for k, v in data.get(name, {}).items() if k in known}
        setattr(cfg, name, cls(**values))
    return cfg


def dumps(cfg: Config) -> str:
    lines = ["# aurguard configuration - written by `aurguard setup`, safe to edit by hand", ""]
    for name, section in asdict(cfg).items():
        lines.append(f"[{name}]")
        for key, value in section.items():
            # JSON string escapes are valid TOML basic strings
            lines.append(f"{key} = {json.dumps(value) if isinstance(value, str) else str(value).lower()}")
        lines.append("")
    return "\n".join(lines)


def save(cfg: Config, path: Path = CONFIG_PATH) -> None:
    """Written with mode 600: the file may hold an API key."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(dumps(cfg))
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def set_value(cfg: Config, dotted: str, raw: str) -> None:
    """`aurguard setup --set ai.provider=gemini`"""
    section, _, key = dotted.partition(".")
    obj = getattr(cfg, section, None)
    if obj is None or key not in getattr(type(obj), "__dataclass_fields__", {}):
        raise ValueError(f"unknown setting: {dotted}")
    current = getattr(obj, key)
    if isinstance(current, bool):
        if raw.lower() not in ("true", "false", "yes", "no", "1", "0"):
            raise ValueError(f"{dotted} takes true or false")
        value = raw.lower() in ("true", "yes", "1")
    else:
        value = raw
    if dotted == "ai.provider":
        if value not in ("none", *PROVIDERS):
            raise ValueError(f"ai.provider must be one of: none, {', '.join(PROVIDERS)}")
        if value != cfg.ai.provider:
            # a key for one provider must never be sent to another
            cfg.ai.model = cfg.ai.base_url = cfg.ai.api_key = ""
    if dotted == "aur.helper" and value not in ("", "paru", "yay"):
        raise ValueError("aur.helper must be paru, yay or empty (auto)")
    setattr(obj, key, value)


def masked(cfg: Config) -> str:
    text = dumps(cfg)
    if cfg.ai.api_key:
        k = cfg.ai.api_key
        text = text.replace(json.dumps(k), json.dumps(f"{k[:4]}...{k[-4:]}" if len(k) > 12 else "***"))
    return text
