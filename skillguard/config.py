"""SkillGuard configuration: every setting is a SKILLGUARD_* environment variable.

Precedence (highest first): CLI flag > environment variable > .env file > default.
The .env file is `SKILLGUARD_ENV_FILE` (or `--env-file`), else `./.env` if it exists. It never overrides
variables already set in the environment. With the LiteLLM backend it may also hold provider keys
(e.g. ANTHROPIC_API_KEY), which LiteLLM reads itself.

Run `python3 -m skillguard config` to see the effective settings.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, fields
from pathlib import Path

BACKENDS = ("openrouter", "litellm")
OPENROUTER_URL = "https://openrouter.ai/api/v1"


class ConfigError(ValueError):
    """A setting has an invalid value."""


@dataclass
class Setting:
    env: str
    kind: type
    default: object
    help: str
    secret: bool = False


# field name -> definition. Order is the order of .env.example and `skillguard config`.
SETTINGS: dict[str, Setting] = {
    # --- LLM backend ---------------------------------------------------------------------------------
    "backend": Setting("SKILLGUARD_BACKEND", str, "openrouter",
                       "LLM backend: 'openrouter' (built-in HTTP client, no dependencies) or 'litellm' "
                       "(any LiteLLM provider; needs `pip install litellm`)"),
    "model": Setting("SKILLGUARD_MODEL", str, "openai/gpt-6-luna",
                     "Model for the LLM review. OpenRouter id, or a LiteLLM model string such as "
                     "anthropic/claude-sonnet-5.5, bedrock/..., ollama/llama3.1, openrouter/openai/gpt-6-luna"),
    "triage_model": Setting("SKILLGUARD_TRIAGE_MODEL", str, "",
                            "Model for triage of static findings. Empty = same as SKILLGUARD_MODEL. "
                            "'typesafe/jev-1.13' uses TypeSafe Jev (OpenRouter only)"),
    "fallback_model": Setting("SKILLGUARD_FALLBACK_MODEL", str, "openai/gpt-6-luna",
                              "Re-review model when the review model's content filter refuses a skill. "
                              "'none' disables. Use a model id valid for the chosen backend"),
    "api_key": Setting("SKILLGUARD_API_KEY", str, "",
                       "API key. OpenRouter backend: required. LiteLLM backend: optional (passed as api_key); "
                       "otherwise LiteLLM uses the provider's own variable, e.g. ANTHROPIC_API_KEY", secret=True),
    "base_url": Setting("SKILLGUARD_BASE_URL", str, "",
                        f"API base URL. OpenRouter backend: default {OPENROUTER_URL} (any OpenAI-compatible "
                        "endpoint works). LiteLLM backend: optional api_base, e.g. a LiteLLM proxy or Ollama URL"),
    "temperature": Setting("SKILLGUARD_TEMPERATURE", str, "0",
                           "Sampling temperature for review and triage; 'none' = provider default "
                           "(some reasoning models reject a temperature)"),
    "llm_timeout": Setting("SKILLGUARD_LLM_TIMEOUT", float, 300.0, "Seconds per LLM request"),
    "llm_retries": Setting("SKILLGUARD_LLM_RETRIES", int, 3, "Attempts per LLM request on transient errors"),
    "review_max_tokens": Setting("SKILLGUARD_REVIEW_MAX_TOKENS", int, 8000, "Max output tokens per review call"),
    "max_prompt_chars": Setting("SKILLGUARD_MAX_PROMPT_CHARS", int, 400_000,
                                "Max characters per review prompt; larger skills are split into several calls"),
    # --- Jev (optional triage model) ----------------------------------------------------------------
    "jev_base_url": Setting("SKILLGUARD_JEV_BASE_URL", str, OPENROUTER_URL, "Endpoint for TypeSafe Jev"),
    "jev_api_key": Setting("SKILLGUARD_JEV_API_KEY", str, "",
                           "Key for Jev; empty = SKILLGUARD_API_KEY", secret=True),
    # --- Layers ---------------------------------------------------------------------------------------
    "use_llm": Setting("SKILLGUARD_LLM", bool, True, "Run the LLM review (false = partial scan, never SAFE)"),
    "use_triage": Setting("SKILLGUARD_TRIAGE", bool, True, "Run triage of static findings"),
    "use_cisco": Setting("SKILLGUARD_CISCO", bool, True, "Run the Cisco scanner (false = partial scan, never SAFE)"),
    "cisco_package": Setting("SKILLGUARD_CISCO_PACKAGE", str, "cisco-ai-skill-scanner==2.1.0",
                             "Cisco scanner package spec for uvx (pin the version)"),
    "cisco_timeout": Setting("SKILLGUARD_CISCO_TIMEOUT", float, 300.0, "Seconds for the Cisco scanner"),
    # --- Triage policy -------------------------------------------------------------------------------
    "keep_threshold": Setting("SKILLGUARD_KEEP_THRESHOLD", float, 0.2,
                              "P(true_positive) at or above this always keeps a finding"),
    "drop_threshold": Setting("SKILLGUARD_DROP_THRESHOLD", float, 0.6,
                              "P(false_positive) at or above this removes a finding"),
    # --- Limits ----------------------------------------------------------------------------------------
    "max_file_bytes": Setting("SKILLGUARD_MAX_FILE_BYTES", int, 2_000_000,
                              "Text files larger than this are not inspected (reported as a coverage gap)"),
    "workers": Setting("SKILLGUARD_WORKERS", int, 4, "Skills scanned in parallel by `eval`"),
}


@dataclass
class Settings:
    backend: str
    model: str
    triage_model: str
    fallback_model: str
    api_key: str
    base_url: str
    temperature: str
    llm_timeout: float
    llm_retries: int
    review_max_tokens: int
    max_prompt_chars: int
    jev_base_url: str
    jev_api_key: str
    use_llm: bool
    use_triage: bool
    use_cisco: bool
    cisco_package: str
    cisco_timeout: float
    keep_threshold: float
    drop_threshold: float
    max_file_bytes: int
    workers: int

    # Derived values ------------------------------------------------------------------------------------
    @property
    def effective_triage_model(self) -> str:
        return self.triage_model or self.model

    @property
    def effective_fallback_model(self) -> str:
        return "" if self.fallback_model.lower() in ("", "none", "off") else self.fallback_model

    @property
    def effective_base_url(self) -> str:
        if self.base_url:
            return self.base_url.rstrip("/")
        return OPENROUTER_URL if self.backend == "openrouter" else ""

    @property
    def effective_jev_api_key(self) -> str:
        return self.jev_api_key or self.api_key

    @property
    def temperature_value(self) -> float | None:
        if self.temperature.strip().lower() in ("", "none", "default"):
            return None
        return _parse(float, self.temperature, "SKILLGUARD_TEMPERATURE")

    def describe(self) -> list[tuple[str, str, str]]:
        """(env var, effective value, help) with secrets masked, for `skillguard config`."""
        rows = []
        for name, spec in SETTINGS.items():
            value = getattr(self, name)
            if spec.secret and value:
                value = f"{str(value)[:6]}…(set)"
            rows.append((spec.env, str(value), spec.help))
        return rows


def _parse(kind: type, raw: str, env: str):
    raw = raw.strip()
    try:
        if kind is bool:
            if raw.lower() in ("1", "true", "yes", "on"):
                return True
            if raw.lower() in ("0", "false", "no", "off"):
                return False
            raise ValueError
        return kind(raw)
    except ValueError:
        raise ConfigError(f"{env}={raw!r} is not a valid {kind.__name__}") from None


def load_env_file(path: Path | None = None) -> Path | None:
    """Load KEY=VALUE lines into os.environ without overriding existing variables. Returns the file used."""
    if path is None:
        named = os.environ.get("SKILLGUARD_ENV_FILE")
        path = Path(named) if named else Path(".env")
        if not named and not path.is_file():
            return None
    if not path.is_file():
        raise ConfigError(f"env file {path} not found")
    for number, line in enumerate(path.read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line = line.removeprefix("export ").strip()
        if "=" not in line:
            raise ConfigError(f"{path}:{number}: expected KEY=VALUE")
        key, value = (part.strip() for part in line.split("=", 1))
        if value[:1] in ("'", '"') and value[-1:] == value[:1] and len(value) >= 2:
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        os.environ.setdefault(key, value)
    return path


def load(overrides: dict | None = None) -> Settings:
    """Build settings from defaults, environment and explicit overrides (None values are ignored)."""
    values = {}
    for name, spec in SETTINGS.items():
        raw = (os.environ.get(spec.env) or "").strip()
        if not raw:
            values[name] = spec.default  # unset or empty: built-in default
        elif spec.kind is str:
            values[name] = raw
        else:
            values[name] = _parse(spec.kind, raw, spec.env)
    for name, value in (overrides or {}).items():
        if value is not None:
            values[name] = value
    settings = Settings(**values)
    validate(settings)
    return settings


def validate(settings: Settings) -> None:
    if settings.backend not in BACKENDS:
        raise ConfigError(f"SKILLGUARD_BACKEND must be one of {', '.join(BACKENDS)}, not {settings.backend!r}")
    for name in ("keep_threshold", "drop_threshold"):
        if not 0 <= getattr(settings, name) <= 1:
            raise ConfigError(f"{SETTINGS[name].env} must be between 0 and 1")
    for name in ("llm_retries", "review_max_tokens", "max_prompt_chars", "max_file_bytes", "workers"):
        if getattr(settings, name) < 1:
            raise ConfigError(f"{SETTINGS[name].env} must be at least 1")
    if settings.max_prompt_chars < 50_000:
        raise ConfigError("SKILLGUARD_MAX_PROMPT_CHARS must be at least 50000")
    settings.temperature_value  # noqa: B018 - validates the value


def env_example() -> str:
    lines = ["# SkillGuard configuration. Copy to .env and adjust; all settings are optional except the API key.",
             "# Precedence: CLI flag > environment variable > this file > default.", ""]
    for spec in SETTINGS.values():
        lines.append(f"# {spec.help}")
        default = "" if spec.secret else ("true" if spec.default is True else "false" if spec.default is False else spec.default)
        lines.append(f"{spec.env}={default}")
        lines.append("")
    return "\n".join(lines)


# The active settings. The CLI replaces this via configure(); library users may do the same.
settings: Settings = Settings(**{name: spec.default for name, spec in SETTINGS.items()})


def configure(overrides: dict | None = None, env_file: Path | None = None) -> Settings:
    global settings
    load_env_file(env_file)
    settings = load(overrides)
    return settings


assert [f.name for f in fields(Settings)] == list(SETTINGS), "Settings fields and SETTINGS table must match"
