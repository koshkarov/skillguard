"""Orchestrates the layers and computes the verdict."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import layer1, semantic, triage
from .model import Finding, LayerStatus, severity_rank
from .skill import load_skill

DEFAULT_MODEL = "openai/gpt-6-luna"
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
    active = [f for f in findings if f.status != "removed"]
    high = [f for f in active if severity_rank(f.severity) >= severity_rank("HIGH")]
    blocking = [f for f in high if _confirmed(f) and f.ast in BLOCK_CATEGORIES]
    intent = review.get("intent")
    failed = [layer.name for layer in layers if not layer.ok]
    if intent == "malicious":
        return "BLOCK", "The instruction/code review judged this skill malicious."
    if blocking:
        return "BLOCK", f"{len(blocking)} confirmed high-severity finding(s): " + "; ".join(f.title for f in blocking[:3])
    if failed:
        return "REVIEW", f"Not every check completed ({', '.join(failed)}), so the skill cannot be cleared automatically."
    if intent == "suspicious":
        return "REVIEW", "The instruction/code review found suspicious behavior."
    if high:
        return "REVIEW", f"{len(high)} high-severity finding(s) need a human look: " + "; ".join(f.title for f in high[:3])
    return "SAFE", "No high-severity issues remained after all checks."


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen, unique = set(), []
    for finding in findings:
        key = (finding.rule, finding.file, finding.line)
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def scan(path: Path, *, model: str = DEFAULT_MODEL, use_llm: bool = True, use_triage: bool = True,
         use_cisco: bool = True) -> dict:
    started = time.monotonic()
    skill = load_skill(path)
    layers: list[LayerStatus] = []
    findings: list[Finding] = []

    with ThreadPoolExecutor(max_workers=2) as pool:
        cisco_future = pool.submit(layer1.run_cisco, skill) if use_cisco else None
        own, own_status = layer1.run_own_checks(skill)
        findings.extend(own)
        layers.append(own_status)
        if cisco_future:
            cisco_findings, cisco_status = cisco_future.result()
            findings.extend(cisco_findings)
            layers.append(cisco_status)
    findings = _dedupe(findings)

    if use_triage:
        layers.append(triage.run(skill, findings))

    review: dict = {}
    if use_llm:
        hints = [f for f in findings if f.status == "active"]
        review, semantic_findings, semantic_status = semantic.run(skill, hints, model)
        findings.extend(semantic_findings)
        layers.append(semantic_status)

    findings.sort(key=lambda f: (f.status != "active", -severity_rank(f.severity), f.ast, f.location))
    label, reason = verdict(findings, review, layers)
    return {
        "skill": {"name": skill.name, "path": str(skill.root), "description": skill.description,
                  "files": len(skill.files) + len(skill.binary_files)},
        "verdict": label,
        "reason": reason,
        "review": review,
        "findings": [f.to_dict() for f in findings],
        "layers": [vars(layer) for layer in layers],
        "cost": round(sum(layer.cost for layer in layers), 6),
        "seconds": round(time.monotonic() - started, 2),
        "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
    }
