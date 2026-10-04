"""Organisation policy: reviewed suppressions and approvals, kept in a TOML file under version control.

    [[suppress]]                       # hide one reviewed finding
    rule = "COVERAGE_GAP"              # rule id (glob allowed), required
    path = "assets/template.tar.gz*"   # file glob; omit to match findings anywhere in the skill
    skill = "web-artifacts-builder"    # skill name glob; default "*"
    sha256 = "…"                       # only while the file at `path` has exactly this hash
    reason = "Reviewed by J. Doe, ticket SEC-123"   # required
    expires = 2027-01-31               # optional; expired entries are ignored and reported

    [[approve]]                        # accept a REVIEW verdict after a human review
    skill = "canvas-design"
    sha256 = "…"                       # content_sha256 from the report, required: any change voids it
    reason = "…"
    expires = 2027-01-31

Suppressed findings stay in every report (marked as suppressed) and never count towards the verdict.
An approval turns REVIEW into SAFE for exactly the reviewed content; it never overrides BLOCK. Policies
are loaded only from an explicit path (SKILLGUARD_POLICY / --policy), never discovered next to a skill,
so a skill cannot ship its own exemptions.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .config import ConfigError
from .model import Finding

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass
class Suppression:
    rule: str
    reason: str
    skill: str = "*"
    path: str | None = None
    sha256: str | None = None
    expires: dt.date | None = None


@dataclass
class Approval:
    skill: str
    sha256: str
    reason: str
    expires: dt.date | None = None


@dataclass
class Policy:
    source: str = ""
    suppressions: list[Suppression] = field(default_factory=list)
    approvals: list[Approval] = field(default_factory=list)


def _entry(kind: type, raw: object, where: str, required: tuple[str, ...]) -> object:
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: expected a table")
    known = set(kind.__dataclass_fields__)
    unknown = set(raw) - known
    if unknown:
        raise ConfigError(f"{where}: unknown key(s) {', '.join(sorted(unknown))}")
    for key in required:
        if not isinstance(raw.get(key), str) or not raw[key].strip():
            raise ConfigError(f"{where}: '{key}' is required")
    for key, value in raw.items():
        if key == "expires":
            if isinstance(value, dt.datetime):
                raw[key] = value.date()
            elif not isinstance(value, dt.date):
                raise ConfigError(f"{where}: 'expires' must be a date such as 2027-01-31")
        elif not isinstance(value, str):
            raise ConfigError(f"{where}: '{key}' must be a string")
    sha = raw.get("sha256")
    if sha is not None and not SHA256_RE.match(sha):
        raise ConfigError(f"{where}: 'sha256' must be 64 lowercase hex characters")
    return kind(**raw)


def load(path: Path | str | None) -> Policy:
    """Load and strictly validate a policy file; an invalid policy is a configuration error."""
    if not path:
        return Policy()
    path = Path(path)
    try:
        data = tomllib.loads(path.read_text())
    except OSError as exc:
        raise ConfigError(f"policy file {path} cannot be read: {exc}") from None
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"policy file {path}: {exc}") from None
    unknown = set(data) - {"suppress", "approve"}
    if unknown:
        raise ConfigError(f"policy file {path}: unknown section(s) {', '.join(sorted(unknown))}")
    return Policy(
        source=str(path),
        suppressions=[_entry(Suppression, raw, f"{path} [[suppress]] #{i + 1}", ("rule", "reason"))
                      for i, raw in enumerate(data.get("suppress", []))],
        approvals=[_entry(Approval, raw, f"{path} [[approve]] #{i + 1}", ("skill", "sha256", "reason"))
                   for i, raw in enumerate(data.get("approve", []))],
    )


def _hash_of(path: str | None, hashes: dict[str, str]) -> str | None:
    """Hash of a finding's file; for an archive member (`a.tar.gz!/x`) the archive's hash."""
    return hashes.get(path.split("!/", 1)[0]) if path else None


def _matches(rule: Suppression, skill_name: str, finding: Finding) -> bool:
    if not fnmatch.fnmatchcase(skill_name, rule.skill) or not fnmatch.fnmatchcase(finding.rule, rule.rule):
        return False
    if rule.path is None:
        return True
    return finding.file is not None and fnmatch.fnmatchcase(finding.file, rule.path)


def apply(policy: Policy, skill_name: str, content_sha256: str, hashes: dict[str, str],
          findings: list[Finding], today: dt.date | None = None) -> dict:
    """Mark matching findings as suppressed and look up an approval. Returns a summary for the report."""
    today = today or dt.date.today()
    notes: list[str] = []
    live = []
    for rule in policy.suppressions:
        if rule.expires and rule.expires < today:
            notes.append(f"Expired suppression ignored: {rule.rule} {rule.path or ''} (expired {rule.expires})".strip())
        else:
            live.append(rule)
    suppressed = 0
    for finding in findings:
        if finding.status == "removed":
            continue
        for rule in live:
            if not _matches(rule, skill_name, finding):
                continue
            if rule.sha256 and rule.sha256 != _hash_of(finding.file, hashes):
                notes.append(f"Suppression for {finding.rule} at {finding.location} not applied: the file changed "
                             "since it was reviewed (sha256 differs)")
                continue
            finding.suppression = {"reason": rule.reason, "expires": str(rule.expires or "")}
            finding.status = "suppressed"
            suppressed += 1
            break
    approval = None
    for entry in policy.approvals:
        if not fnmatch.fnmatchcase(skill_name, entry.skill):
            continue
        if entry.sha256 != content_sha256:
            notes.append(f"Approval for {entry.skill} not applied: the skill's content changed since it was approved")
        elif entry.expires and entry.expires < today:
            notes.append(f"Approval for {entry.skill} expired on {entry.expires}")
        else:
            approval = {"reason": entry.reason, "expires": str(entry.expires or "")}
            break
    return {"file": policy.source, "suppressed": suppressed, "approval": approval, "notes": notes}
