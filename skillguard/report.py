"""Render scan results as Markdown (for people) and SARIF (for CI).

Everything shown from a skill, the Cisco scanner or the LLM is untrusted: Markdown output escapes it, so
a skill cannot inject links, images, HTML or fake report sections when a report is posted as a PR comment.
"""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

from . import __version__
from .model import AST_NAMES, NOT_ASSESSABLE

VERDICT_ICON = {"SAFE": "✅ SAFE", "REVIEW": "⚠️ REVIEW", "BLOCK": "⛔ BLOCK"}
SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}
SOURCE_LABEL = {"cisco": "Cisco scanner", "check": "SkillGuard check", "semantic": "LLM review"}
MD_SPECIAL_RE = re.compile(r"([\\`*_\[\]<>|!#~])")


def _inline(text: object, limit: int = 1000) -> str:
    """Untrusted text as one line of inert Markdown."""
    return MD_SPECIAL_RE.sub(r"\\\1", " ".join(str(text or "").split())[:limit])


def _code(text: object) -> str:
    """Untrusted text as inline code; the delimiter is longer than any backtick run inside."""
    text = " ".join(str(text or "").split())
    ticks = "`" * (max((len(r) for r in re.findall(r"`+", text)), default=0) + 1)
    return f"{ticks} {text} {ticks}"


def _fence(text: str) -> list[str]:
    """Untrusted text as a fenced code block that it cannot close."""
    ticks = "`" * max(3, max((len(r) for r in re.findall(r"`+", text)), default=0) + 1)
    return [ticks, text, ticks]


def _location(finding: dict) -> str:
    loc = finding["file"] or "(skill)"
    return f"{loc}:{finding['line']}" if finding.get("line") else loc


def _triage_note(finding: dict) -> str:
    triage = finding.get("triage") or {}
    verdict = triage.get("verdict")
    if not verdict:
        return ""
    if verdict == "unverified":
        return "LLM finding whose quote was not found in the file"
    if verdict == "error":
        return "triage failed; kept as reported"
    probs = triage.get("probabilities") or {}
    return f"triage: {verdict} (P real={probs.get('true_positive', 0):.2f}, P false={probs.get('false_positive', 0):.2f})"


def _finding_block(finding: dict) -> list[str]:
    severity = finding["severity"]
    head = f"#### {SEVERITY_ICON.get(severity, '')} {_inline(severity)}: {_inline(finding['title'], 200)}"
    lines = [head, "", f"{_code(_location(finding))} · {SOURCE_LABEL.get(finding['source'], finding['source'])} "
                       f"{_code(finding['rule'])}"]
    if finding.get("original_severity"):
        lines[-1] += f" · downgraded from {_inline(finding['original_severity'])}"
    note = _triage_note(finding)
    if note:
        lines[-1] += f" · {note}"
    if finding.get("suppression"):
        lines[-1] += f" · suppressed by policy: {_inline(finding['suppression'].get('reason'), 300)}"
    if finding.get("evidence"):
        lines += [""] + _fence(finding["evidence"].strip()[:400])
    if finding.get("why"):
        lines += ["", f"**Why it matters:** {_inline(finding['why'])}"]
    if finding.get("fix"):
        lines += ["", f"**How to fix:** {_inline(finding['fix'])}"]
    return lines + [""]


def to_markdown(result: dict) -> str:
    skill = result["skill"]
    findings = result["findings"]
    active = [f for f in findings if f["status"] == "active"]
    downgraded = [f for f in findings if f["status"] == "downgraded"]
    removed = [f for f in findings if f["status"] == "removed"]
    suppressed = [f for f in findings if f["status"] == "suppressed"]
    review = result.get("review") or {}
    cached = (result.get("cache") or {}).get("hit")
    policy = result.get("policy") or {}

    out = [
        f"# SkillGuard report: {_inline(skill['name'], 200)}",
        "",
        f"## {VERDICT_ICON.get(result.get('verdict'), '❓ UNKNOWN VERDICT: ' + _inline(result.get('verdict')))}",
        "",
        f"**{_inline(result['reason'])}**",
        "",
        f"{_code(skill['path'])} · {skill['files']} files · scanned {result['scanned_at']} · "
        f"{result['seconds']}s · ${result['cost']:.4f} · "
        f"{result.get('tokens_in', 0):,} in / {result.get('tokens_out', 0):,} out tokens"
        + (f" · cached result from {result['cache']['scanned_at']} (no new LLM cost)" if cached else ""),
    ]
    if skill.get("content_sha256"):
        out += ["", f"Content sha256: `{skill['content_sha256']}` · SkillGuard {result.get('skillguard_version', '?')}"]
    if policy.get("approval"):
        out += ["", f"**Approved by policy:** {_inline(policy['approval']['reason'], 300)} "
                    f"(automatic verdict: {result.get('verdict_before_policy')})"]
    for note in policy.get("notes", []):
        out += ["", f"⚠️ Policy: {_inline(note, 300)}"]
    out += [
        "",
        "| Check | Status | Details | Tokens in | Tokens out | Cost |",
        "|---|---|---|---:|---:|---:|",
    ]
    names = {"checks": "SkillGuard checks", "cisco": "Cisco scanner (code)", "triage": "Triage",
             "semantic": "LLM review (instructions + code)"}
    for layer in result["layers"]:
        state = "⏭️ skipped" if layer.get("skipped") else ("✅ ran" if layer["ok"] else "❌ FAILED / incomplete")
        out.append(f"| {names.get(layer['name'], layer['name'])} | {state} | {_inline(layer['detail'], 400)} ({layer['seconds']:.1f}s) | "
                   f"{layer.get('tokens_in', 0):,} | {layer.get('tokens_out', 0):,} | ${layer.get('cost', 0):.4f} |")

    if review:
        out += ["", "## Summary", "", _inline(review.get("summary"), 2000), "",
                f"- **Declared purpose:** {_inline(review.get('declared_purpose'))}",
                f"- **What it actually does:** {_inline(review.get('actual_behavior'))}",
                f"- **Assessed intent:** {_inline(review.get('intent'))}"]

    out += ["", f"## Findings ({len(active)})", ""]
    if not active:
        out += ["No active findings.", ""]
    for ast in sorted({f["ast"] for f in active}):
        out += [f"### {ast}: {AST_NAMES.get(ast, '')}", ""]
        for finding in (f for f in active if f["ast"] == ast):
            out += _finding_block(finding)

    if downgraded:
        out += ["<details>", f"<summary>Downgraded to LOW by triage ({len(downgraded)})</summary>", ""]
        for finding in downgraded:
            out += _finding_block(finding)
        out += ["</details>", ""]
    if removed:
        out += ["<details>", f"<summary>Removed as false positives ({len(removed)})</summary>", "",
                "| Rule | Location | Title | Triage |", "|---|---|---|---|"]
        for f in removed:
            out.append(f"| {_inline(f['rule'])} | {_code(_location(f))} | {_inline(f['title'], 200)} | {_triage_note(f)} |")
        out += ["", "</details>", ""]
    if suppressed:
        out += ["<details>", f"<summary>Suppressed by policy ({len(suppressed)})</summary>", ""]
        for finding in suppressed:
            out += _finding_block(finding)
        out += ["</details>", ""]

    out += ["## Not assessed by scanning", "",
            "These OWASP risks depend on how and where the skill runs, not on its files:", ""]
    for ast, advice in NOT_ASSESSABLE.items():
        out.append(f"- **{ast} {AST_NAMES[ast]}:** {advice}")
    out += ["", "*SkillGuard never executes skill code. No findings does not prove a skill is safe.*", ""]
    return "\n".join(out)


def summary_markdown(results: list[dict]) -> str:
    """One table for a multi-skill scan, worst verdict first."""
    order = {"BLOCK": 0, "REVIEW": 1, "SAFE": 2}
    rows = sorted(results, key=lambda r: (order.get(r["verdict"], -1), r["skill"]["name"]))
    counts = {v: sum(r["verdict"] == v for r in results) for v in ("BLOCK", "REVIEW", "SAFE")}
    out = ["# SkillGuard summary", "",
           f"{len(results)} skill(s): ⛔ {counts['BLOCK']} BLOCK · ⚠️ {counts['REVIEW']} REVIEW · ✅ {counts['SAFE']} SAFE · "
           f"${sum(r['cost'] for r in results):.4f} · {sum(r.get('cache', {}).get('hit', False) for r in results)} cached",
           "", "| Skill | Verdict | Reason | Active findings | Cost |", "|---|---|---|---:|---:|"]
    for r in rows:
        active = sum(f["status"] == "active" for f in r["findings"])
        out.append(f"| {_inline(r['skill']['name'], 100)} ({_code(r['skill']['path'])}) | "
                   f"{VERDICT_ICON.get(r['verdict'], _inline(r['verdict']))} | {_inline(r['reason'], 300)} | "
                   f"{active} | ${r['cost']:.4f} |")
    return "\n".join(out) + "\n"


SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
# GitHub code scanning shows security alerts as Critical/High/Medium/Low from this score.
SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "2.0", "INFO": "0.0"}


def _artifact_uri(skill_path: str, file: str | None, base: Path) -> str:
    """Path of the file relative to `base` (the repository root in CI), POSIX style."""
    root = Path(skill_path)
    if root.is_file():  # a .zip/.skill package: point at the package
        target = root
    else:
        target = root / (file or "SKILL.md").split("!/", 1)[0]  # archive members: the archive
    try:
        return Path(os.path.relpath(target.resolve(), base.resolve())).as_posix()
    except ValueError:  # another drive on Windows
        return target.as_posix()


def to_sarif(results: dict | list[dict], base: Path | None = None) -> dict:
    """SARIF 2.1.0 for one or more scan results; URIs are relative to `base` (default: current directory)."""
    results = [results] if isinstance(results, dict) else results
    base = base or Path.cwd()
    entries, rules = [], {}
    for result in results:
        for f in result["findings"]:
            if f["status"] == "removed":
                continue
            rule_id = f"{f['ast']}/{f['rule']}"
            rule = rules.setdefault(rule_id, {
                "id": rule_id, "name": f["rule"],
                "shortDescription": {"text": f"{f['ast']} {AST_NAMES.get(f['ast'], '')}: {f['rule']}"},
                "helpUri": "https://github.com/OWASP/www-project-agentic-skills-top-10",
                "properties": {"tags": ["security", f["ast"]], "security-severity": "0.0"},
            })
            score = SECURITY_SEVERITY.get(f["severity"], "5.5")
            if float(score) > float(rule["properties"]["security-severity"]):
                rule["properties"]["security-severity"] = score
            uri = _artifact_uri(result["skill"]["path"], f.get("file"), base)
            region = {"startLine": f["line"]} if f.get("line") and "!/" not in (f.get("file") or "") else {}
            location = {"artifactLocation": {"uri": uri}}
            if region:
                location["region"] = region
            identity = f"{result['skill']['name']}|{f['rule']}|{f.get('file')}|{f.get('evidence', '')[:200]}"
            entry = {
                "ruleId": rule_id,
                "level": SARIF_LEVEL.get(f["severity"], "warning"),
                "message": {"text": f"[{result['skill']['name']}] {f['title']}"
                                    + (f" ({f['file']})" if "!/" in (f.get("file") or "") else "")
                                    + f". {f['why']} Fix: {f['fix']}".rstrip()},
                "locations": [{"physicalLocation": location}],
                "partialFingerprints": {"skillguard/v1": hashlib.sha256(identity.encode()).hexdigest()},
                "properties": {"severity": f["severity"], "source": f["source"], "status": f["status"],
                               "skill": result["skill"]["name"], "verdict": result["verdict"]},
            }
            if f["status"] == "suppressed":
                entry["suppressions"] = [{"kind": "external", "justification": f["suppression"].get("reason", "")}]
            entries.append(entry)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "SkillGuard", "version": __version__, "semanticVersion": __version__,
                                "informationUri": "https://github.com/OWASP/www-project-agentic-skills-top-10",
                                "rules": list(rules.values())}},
            "results": entries,
            "properties": {"skills": [{"name": r["skill"]["name"], "path": r["skill"]["path"], "verdict": r["verdict"],
                                       "reason": r["reason"], "content_sha256": r["skill"].get("content_sha256")}
                                      for r in results]},
        }],
    }
