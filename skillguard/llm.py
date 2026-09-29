"""LLM access: JSON-mode chat completions via OpenRouter (stdlib HTTP) or LiteLLM, plus TypeSafe Jev.

All settings come from `skillguard.config` (SKILLGUARD_* environment variables).
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

from . import config

RETRY_CODES = {408, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524}  # 52x: transient upstream/CDN errors
COMPLETE_FINISH_REASONS = {"stop", "end_turn", "stop_sequence"}


class LLMError(RuntimeError):
    def __init__(self, message: str, usage: dict | None = None):
        super().__init__(message)
        self.usage = usage or {}  # tokens are billed even when the answer is unusable


# $ per million tokens (input, output), used only when neither the provider nor LiteLLM reports a cost.
PRICES = {
    "openai/gpt-6-luna": (0.10, 0.50),
    "openai/gpt-6-luna-pro": (0.10, 0.50),
    "anthropic/claude-sonnet-5.5": (2.0, 10.0),
    "anthropic/claude-sonnet-5": (2.0, 10.0),
}


def cost_of(model: str, usage: dict) -> float:
    """Provider-reported cost when present, else estimated from the token counts."""
    if usage.get("cost") is not None:
        return float(usage["cost"])
    price_in, price_out = PRICES.get(model.removeprefix("openrouter/"), (0.0, 0.0))
    return usage.get("prompt_tokens", 0) * price_in / 1e6 + usage.get("completion_tokens", 0) * price_out / 1e6


def add_usage(total: dict, usage: dict) -> dict:
    """Accumulate chat usage (prompt/completion tokens, cost) into `total`."""
    for key in ("prompt_tokens", "completion_tokens"):
        total[key] = total.get(key, 0) + int(usage.get(key) or 0)
    if usage.get("cost") is not None:
        total["cost"] = total.get("cost", 0.0) + float(usage["cost"])
    return total


def api_key() -> str:
    key = config.settings.api_key
    if not key:
        raise LLMError("No API key: set SKILLGUARD_API_KEY (environment or .env file).")
    return key


# --- HTTP (OpenRouter or any OpenAI-compatible endpoint, and Jev) -------------------------------------------

def http_post(base_url: str, key: str, path: str, payload: dict, *, timeout: float, retries: int) -> dict:
    request = urllib.request.Request(
        f"{base_url}{path}",
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    )
    last = ""
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = json.load(response)
            if isinstance(body, dict) and body.get("error"):
                last = json.dumps(body["error"])[:400]
            else:
                return body
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}: {exc.read()[:400].decode(errors='replace')}"
            # 402 "in_flight_budget_exhausted" (OpenRouter) clears once concurrent requests finish.
            if exc.code not in RETRY_CODES and not (exc.code == 402 and "in_flight" in last):
                break
            if exc.code == 402:
                time.sleep(15 * (attempt + 1))
                continue
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last = str(exc)
        time.sleep(2 * (attempt + 1))
    raise LLMError(last or "request failed")


def post(path: str, payload: dict) -> dict:
    s = config.settings
    return http_post(s.effective_base_url, api_key(), path, payload, timeout=s.llm_timeout, retries=s.llm_retries)


def _chat_http(model: str, messages: list[dict], max_tokens: int) -> tuple[str, str, object, dict]:
    s = config.settings
    payload = {"model": model, "messages": messages, "response_format": {"type": "json_object"},
               "max_tokens": max_tokens}
    if s.temperature_value is not None:
        payload["temperature"] = s.temperature_value
    if "openrouter.ai" in s.effective_base_url:
        payload["usage"] = {"include": True}  # OpenRouter-specific: return the billed cost
    body = post("/chat/completions", payload)
    usage = (body.get("usage") or {}) if isinstance(body, dict) else {}
    try:
        choice = body["choices"][0]
        message = choice["message"]
        return message.get("content") or "", choice.get("finish_reason"), message.get("refusal"), usage
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMError(f"unexpected response: {str(body)[:300]}", usage) from exc


# --- LiteLLM --------------------------------------------------------------------------------------------------

def _chat_litellm(model: str, messages: list[dict], max_tokens: int) -> tuple[str, str, object, dict]:
    try:
        import litellm
    except ImportError as exc:
        raise LLMError("SKILLGUARD_BACKEND=litellm needs the litellm package: pip install litellm "
                       "(or run with `uv run --with litellm python3 -m skillguard ...`)") from exc
    s = config.settings
    litellm.drop_params = True           # drop parameters a provider does not support instead of failing
    litellm.suppress_debug_info = True
    kwargs = {"model": model, "messages": messages, "response_format": {"type": "json_object"},
              "max_tokens": max_tokens, "timeout": s.llm_timeout, "num_retries": s.llm_retries}
    if s.temperature_value is not None:
        kwargs["temperature"] = s.temperature_value
    if s.api_key:
        kwargs["api_key"] = s.api_key
    if s.base_url:
        kwargs["api_base"] = s.base_url
    try:
        response = litellm.completion(**kwargs)
    except Exception as exc:  # noqa: BLE001 - LiteLLM raises provider-specific exception types
        name = type(exc).__name__
        reason = "content_filter" if "ContentPolicy" in name else name
        raise LLMError(f"litellm {reason}: {str(exc)[:300]}") from exc
    usage_obj = getattr(response, "usage", None)
    usage = {
        "prompt_tokens": int(getattr(usage_obj, "prompt_tokens", 0) or 0),
        "completion_tokens": int(getattr(usage_obj, "completion_tokens", 0) or 0),
    }
    cost = (getattr(response, "_hidden_params", None) or {}).get("response_cost")
    if cost is None:
        try:
            cost = litellm.completion_cost(completion_response=response)
        except Exception:  # noqa: BLE001 - unknown model price: fall back to the local table
            cost = None
    if cost is not None:
        usage["cost"] = float(cost)
    try:
        choice = response.choices[0]
        message = choice.message
        return (getattr(message, "content", None) or "", choice.finish_reason,
                getattr(message, "refusal", None), usage)
    except (AttributeError, IndexError, TypeError) as exc:
        raise LLMError(f"unexpected litellm response: {str(response)[:300]}", usage) from exc


# --- Shared ------------------------------------------------------------------------------------------------------

def parse_json_answer(content: str, finish: object, refusal: object, usage: dict) -> dict:
    """Validate completion metadata and extract the JSON object; raise LLMError (with usage) otherwise."""
    if not content.strip():
        raise LLMError(f"empty answer (finish_reason={finish}, refusal={str(refusal)[:100]})", usage)
    # A truncated or filtered answer may still parse as JSON but be incomplete; never accept it.
    if finish not in COMPLETE_FINISH_REASONS:
        raise LLMError(f"incomplete answer (finish_reason={finish})", usage)
    start = content.find("{")  # tolerate code fences or prose around the object
    try:
        data, _ = json.JSONDecoder().raw_decode(content[start:]) if start >= 0 else (None, 0)
    except json.JSONDecodeError as exc:
        raise LLMError(f"model returned invalid JSON ({exc.msg} at {exc.pos}, finish_reason={finish}): "
                       f"{content[:120]!r}", usage) from exc
    if not isinstance(data, dict):
        raise LLMError(f"model did not return a JSON object: {content[:120]!r}", usage)
    return data


def chat_json(model: str, system: str, user: str, *, max_tokens: int = 8000) -> tuple[dict, dict]:
    """Return (parsed JSON object, usage) from a JSON-mode chat completion on the configured backend."""
    messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    chat = _chat_litellm if config.settings.backend == "litellm" else _chat_http
    content, finish, refusal, usage = chat(model, messages, max_tokens)
    return parse_json_answer(content, finish, refusal, usage), usage


def jev(state: str, questions: dict, *, model: str = "typesafe/jev-1.13") -> dict:
    """TypeSafe Jev typed decision (OpenRouter /systemone endpoint, independent of the chat backend)."""
    s = config.settings
    key = s.effective_jev_api_key
    if not key:
        raise LLMError("No key for Jev: set SKILLGUARD_JEV_API_KEY or SKILLGUARD_API_KEY.")
    return http_post(s.jev_base_url.rstrip("/"), key, "/systemone",
                     {"model": model, "state": state, "questions": questions},
                     timeout=min(60.0, s.llm_timeout), retries=s.llm_retries)
