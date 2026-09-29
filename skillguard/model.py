"""Shared data types: findings, severities, OWASP AST categories."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

AST_NAMES = {
    "AST01": "Malicious Skills",
    "AST02": "Supply Chain Compromise",
    "AST03": "Over-Privileged Skills",
    "AST04": "Insecure Metadata",
    "AST05": "Untrusted External Instructions",
    "AST06": "Weak Isolation",
    "AST07": "Update Drift",
    "AST08": "Poor Scanning",
    "AST09": "No Governance",
    "AST10": "Cross-Platform Reuse",
}

# Risks that depend on the runtime environment or organisation, not the package.
NOT_ASSESSABLE = {
    "AST06": "Check that skills run sandboxed (container, no host mode) with network egress controls.",
    "AST09": "Record the skill in an inventory with an approval record, owner and review cadence.",
    "AST10": "If the skill is used on several agent platforms, validate it separately for each one.",
}


def severity_rank(severity: str) -> int:
    return SEVERITIES.index(severity) if severity in SEVERITIES else 0


@dataclass
class Finding:
    source: str                 # "cisco", "check", "semantic"
    rule: str
    ast: str
    severity: str
    title: str
    file: str | None = None
    line: int | None = None
    evidence: str = ""
    why: str = ""
    fix: str = ""
    precise: bool = False       # high-precision check: skip triage
    triage: dict = field(default_factory=dict)
    original_severity: str | None = None
    status: str = "active"      # "active", "downgraded", "removed"

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def location(self) -> str:
        if not self.file:
            return "(skill)"
        return f"{self.file}:{self.line}" if self.line else self.file


@dataclass
class LayerStatus:
    name: str
    ok: bool
    detail: str = ""
    seconds: float = 0.0
    cost: float = 0.0
    skipped: bool = False   # disabled by the user; counts as "did not run" for the verdict
    tokens_in: int = 0      # all LLM calls of this layer, including retries and failed calls
    tokens_out: int = 0
