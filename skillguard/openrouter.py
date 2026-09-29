"""Minimal OpenRouter HTTP client (stdlib only) for chat completions and Jev."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

BASE_URL = os.environ.get("SKILLGUARD_BASE_URL", "https://openrouter.ai/api/v1")
RETRY_CODES = {408, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524}  # 52x: transient upstream/CDN errors
COMPLETE_FINISH_REASONS = {"stop", "end_turn", "stop_sequence"}


class LLMError(RuntimeError):
    pass


def api_key() -> str:
    key = (
        os.environ.get("SKILLGUARD_API_KEY")
        or os.environ.get("OPENROUTER_API_KEY")
        or os.environ.get("SKILLSPECTOR_COMPAT_API_KEY")
    )
    if not key:
        raise LLMError("No API key: set OPENROUTER_API_KEY (or source skills/.env).")
    return key


def post(path: str, payload: dict, *, timeout: float = 300, retries: int = 3) -> dict:
    request = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {api_key()}", "Content-Type": "application/json"},
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
            # 402 "in_flight_budget_exhausted" clears once concurrent requests finish.
            if exc.code not in RETRY_CODES and not (exc.code == 402 and "in_flight" in last):
                break
            if exc.code == 402:
                time.sleep(15 * (attempt + 1))
                continue
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last = str(exc)
        time.sleep(2 * (attempt + 1))
    raise LLMError(last or "request failed")


def chat_json(model: str, system: str, user: str, *, max_tokens: int = 8000) -> tuple[dict, dict]:
    """Return (parsed JSON content, usage) from a chat completion in JSON mode."""
    body = post(
        "/chat/completions",
        {
            "model": model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "response_format": {"type": "json_object"},
            "temperature": 0,
            "max_tokens": max_tokens,
            "usage": {"include": True},
        },
    )
    try:
        choice = body["choices"][0]
        content = choice["message"].get("content") or ""
    except (KeyError, IndexError, TypeError) as exc:
        raise LLMError(f"unexpected response: {str(body)[:300]}") from exc
    finish = choice.get("finish_reason")
    if not content.strip():
        refusal = choice["message"].get("refusal")
        raise LLMError(f"empty answer (finish_reason={finish}, refusal={str(refusal)[:100]})")
    # A truncated or filtered answer may still parse as JSON but be incomplete; never accept it.
    if finish not in COMPLETE_FINISH_REASONS:
        raise LLMError(f"incomplete answer (finish_reason={finish})")
    # Tolerate code fences or prose around the object: decode the first complete JSON object.
    start = content.find("{")
    try:
        data, _ = json.JSONDecoder().raw_decode(content[start:]) if start >= 0 else (None, 0)
    except json.JSONDecodeError as exc:
        raise LLMError(f"model returned invalid JSON ({exc.msg} at {exc.pos}, finish_reason="
                       f"{choice.get('finish_reason')}): {content[:120]!r}") from exc
    if not isinstance(data, dict):
        raise LLMError(f"model did not return a JSON object: {content[:120]!r}")
    return data, body.get("usage", {})


def jev(state: str, questions: dict, *, model: str = "typesafe/jev-1.13") -> dict:
    return post("/systemone", {"model": model, "state": state, "questions": questions}, timeout=60)
