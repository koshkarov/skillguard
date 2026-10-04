"""Result cache: an unchanged skill scanned with unchanged settings is not paid for twice.

The key covers the skill's full content hash (every file, including uninspected ones), the SkillGuard
version and every setting that can change a result. Only complete scans (no failed layer) are stored,
and the cache holds results before policy, so policy changes apply without a re-scan.
The cache directory is trusted like the SkillGuard installation itself: keep it private to the user or CI job.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path

from . import __version__, config

SCHEMA = 1


def fingerprint(**scan_options) -> dict:
    s = config.settings
    return {
        "schema": SCHEMA, "version": __version__, **scan_options,
        "backend": s.backend, "base_url": s.effective_base_url, "fallback_model": s.effective_fallback_model,
        "temperature": s.temperature, "cisco_package": s.cisco_package, "keep_threshold": s.keep_threshold,
        "drop_threshold": s.drop_threshold, "max_file_bytes": s.max_file_bytes,
        "max_prompt_chars": s.max_prompt_chars, "max_review_calls": s.max_review_calls,
        "review_max_tokens": s.review_max_tokens,
    }


def key(content_sha256: str, options: dict) -> str:
    return hashlib.sha256(json.dumps([content_sha256, options], sort_keys=True).encode()).hexdigest()


def _path(cache_key: str) -> Path | None:
    root = config.settings.effective_cache_dir
    return root / cache_key[:2] / f"{cache_key}.json" if root else None


def get(cache_key: str) -> dict | None:
    path = _path(cache_key)
    if not path or not path.is_file():
        return None
    try:
        entry = json.loads(path.read_text())
    except (OSError, ValueError):
        return None  # unreadable entries are simply re-scanned
    if not isinstance(entry, dict) or entry.get("key") != cache_key or not isinstance(entry.get("result"), dict):
        return None
    if time.time() - float(entry.get("stored_at", 0)) > config.settings.cache_ttl_days * 86400:
        return None
    return entry["result"]


def put(cache_key: str, result: dict) -> None:
    """Store atomically; a cache that cannot be written never fails a scan."""
    path = _path(cache_key)
    if not path:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
        with os.fdopen(fd, "w") as handle:
            json.dump({"key": cache_key, "stored_at": time.time(), "result": result}, handle)
        os.replace(tmp, path)
    except OSError:
        pass
