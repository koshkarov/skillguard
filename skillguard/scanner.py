"""Orchestrates the layers and computes the verdict."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import __version__, cache, config, layer1, policy as policy_mod, semantic, triage
from .model import Finding, LayerStatus, severity_rank
from .skill import Skill, open_skill

BLOCK_CATEGORIES = {"AST01", "AST03"}


def _confirmed(finding: Finding) -> bool:
    """A static finding confirmed independently of the LLM review (precise check or triage P(real) >= 0.5).

    LLM review findings alone never BLOCK: the review blocks through its overall `intent`, so one
    over-rated finding in an otherwise benign review leads to REVIEW, not BLOCK.
    """
    if finding.status != "active" or finding.source == "semantic":
        return False
    if finding.precise:
        return True
    return finding.triage.get("probabilities", {}).get("true_positive", 0.0) >= 0.5


def verdict(findings: list[Finding], review: dict, layers: list[LayerStatus]) -> tuple[str, str]:
    """BLOCK and REVIEW conditions first; SAFE only for a complete scan with nothing high left."""
    active = [f for f in findings if f.status not in ("removed", "suppressed")]
    high = [f for f in active if severity_rank(f.severity) >= severity_rank("HIGH")]
    blocking = [f for f in high if _confirmed(f) and f.ast in BLOCK_CATEGORIES]
    gaps = [f for f in active if f.rule == "COVERAGE_GAP"]
    intent = review.get("intent")
    ran = {layer.name for layer in layers if not layer.skipped}
    failed = [layer.name for layer in layers if not layer.skipped and not layer.ok]
    missing = sorted(COVERAGE_LAYERS - ran)
    if intent == "malicious":
        return "BLOCK", "The instruction/code review judged this skill malicious."
    if blocking:
        return "BLOCK", f"{len(blocking)} confirmed high-severity finding(s): " + "; ".join(f.title for f in blocking[:3])
    if failed:
        return "REVIEW", f"Not every check completed ({', '.join(failed)}), so the skill cannot be cleared automatically."
    if missing:
        return "REVIEW", f"Partial scan: {', '.join(missing)} did not run, so the skill cannot be cleared automatically."
    if gaps:
        return "REVIEW", f"{len(gaps)} part(s) of the skill could not be inspected, so it cannot be cleared automatically."
    if intent == "suspicious":
        return "REVIEW", "The instruction/code review found suspicious behavior."
    if high:
        return "REVIEW", f"{len(high)} high-severity finding(s) need a human look: " + "; ".join(f.title for f in high[:3])
    return "SAFE", "No high-severity issues remained after all checks."


# Layers without which the skill is not fully inspected. Triage only removes noise, so skipping it is safe.
COVERAGE_LAYERS = {"checks", "cisco", "semantic"}


def _guarded(name: str, fn, *args):
    """Run a layer; an unexpected exception marks it failed instead of crashing or passing silently."""
    try:
        return fn(*args)
    except Exception as exc:  # noqa: BLE001 - any failure must surface in the verdict
        return None, LayerStatus(name, False, f"{name} crashed: {type(exc).__name__}: {str(exc)[:200]}")


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen, unique = set(), []
    for finding in findings:
        key = (finding.rule, finding.file, finding.line)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def analyze(skill: Skill, *, model: str, triage_model: str, use_llm: bool, use_triage: bool,
            use_cisco: bool) -> tuple[list[Finding], list[LayerStatus], dict]:
    """Run the layers on a loaded skill. Returns (findings, layer statuses, LLM review)."""
    layers: list[LayerStatus] = []
    findings: list[Finding] = []

    with ThreadPoolExecutor(max_workers=2) as pool:
        cisco_future = pool.submit(_guarded, "cisco", layer1.run_cisco, skill) if use_cisco else None
        own, own_status = _guarded("checks", layer1.run_own_checks, skill)
        findings.extend(own or [])
        layers.append(own_status)
        if cisco_future:
            cisco_findings, cisco_status = cisco_future.result()
            findings.extend(cisco_findings or [])
            layers.append(cisco_status)
        else:
            layers.append(LayerStatus("cisco", True, "disabled (SKILLGUARD_CISCO=false / --no-cisco)", skipped=True))
    findings = _dedupe(findings)

    if use_triage:
        try:
            layers.append(triage.run(skill, findings, model=triage_model))
        except Exception as exc:  # noqa: BLE001
            layers.append(LayerStatus("triage", False, f"triage crashed: {type(exc).__name__}: {str(exc)[:200]}"))
    else:
        layers.append(LayerStatus("triage", True, "disabled (SKILLGUARD_TRIAGE=false / --no-triage)", skipped=True))

    review: dict = {}
    if use_llm:
        hints = [f for f in findings if f.status == "active"]
        try:
            review, semantic_findings, semantic_status = semantic.run(skill, hints, model)
            findings.extend(semantic_findings)
        except Exception as exc:  # noqa: BLE001
            semantic_status = LayerStatus("semantic", False, f"LLM review crashed: {type(exc).__name__}: {str(exc)[:200]}")
        layers.append(semantic_status)
    else:
        layers.append(LayerStatus("semantic", True, "disabled (SKILLGUARD_LLM=false / --no-llm)", skipped=True))
    return findings, layers, review


def scan(path: Path, *, model: str | None = None, use_llm: bool | None = None, use_triage: bool | None = None,
         use_cisco: bool | None = None, triage_model: str | None = None, use_cache: bool = True,
         policy: policy_mod.Policy | None = None) -> dict:
    """Scan one skill directory or .zip/.skill package. Arguments left as None come from the active settings
    (SKILLGUARD_* variables). The triage model defaults to the review model, so a single model is enough.

    Results of complete scans are cached by content hash (SKILLGUARD_CACHE_DIR); the policy (suppressions,
    approvals) is applied afterwards, so it is never baked into the cache."""
    started = time.monotonic()
    s = config.settings
    options = {
        "model": model or s.model,
        "triage_model": triage_model or s.triage_model or model or s.model,
        "use_llm": s.use_llm if use_llm is None else use_llm,
        "use_triage": s.use_triage if use_triage is None else use_triage,
        "use_cisco": s.use_cisco if use_cisco is None else use_cisco,
    }
    policy = policy if policy is not None else policy_mod.load(s.policy)
    with open_skill(Path(path)) as skill:
        content_sha256 = skill.content_sha256
        cache_key = cache.key(content_sha256, cache.fingerprint(**options))
        cached = cache.get(cache_key) if use_cache else None
        if cached:
            findings = [Finding(**f) for f in cached["findings"]]
            layers = [LayerStatus(**layer) for layer in cached["layers"]]
            review = cached["review"]
        else:
            findings, layers, review = analyze(skill, **options)
            if use_cache and all(layer.ok or layer.skipped for layer in layers):
                cache.put(cache_key, {"findings": [f.to_dict() for f in findings], "layers": [vars(l) for l in layers],
                                      "review": review, "scanned_at": _now()})
        applied = policy_mod.apply(policy, skill.name, content_sha256, skill.hashes, findings)
        summary = {"name": skill.name, "path": skill.display, "description": skill.description,
                   "files": len(skill.files) + len(skill.binary_files), "coverage_gaps": skill.coverage_gaps,
                   "content_sha256": content_sha256}

    findings.sort(key=lambda f: (f.status != "active", -severity_rank(f.severity), f.ast, f.location))
    label, reason = verdict(findings, review, layers)
    unapproved = label
    if label == "REVIEW" and applied["approval"]:
        label, reason = "SAFE", f"Approved by policy after human review ({applied['approval']['reason']}); was: {reason}"
    spent = not cached
    return {
        "skillguard_version": __version__,
        "skill": summary,
        "verdict": label,
        "reason": reason,
        "verdict_before_policy": unapproved,
        "review": review,
        "findings": [f.to_dict() for f in findings],
        "layers": [vars(layer) for layer in layers],
        "cost": round(sum(layer.cost for layer in layers), 6) if spent else 0.0,
        "tokens_in": sum(layer.tokens_in for layer in layers) if spent else 0,
        "tokens_out": sum(layer.tokens_out for layer in layers) if spent else 0,
        "cache": {"hit": True, "scanned_at": cached["scanned_at"]} if cached else {"hit": False},
        "policy": applied,
        "config": {"backend": s.backend, **options},
        "seconds": round(time.monotonic() - started, 2),
        "scanned_at": _now(),
    }


def _now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
