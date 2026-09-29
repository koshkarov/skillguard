"""Render scan results as Markdown (for people) and SARIF (for CI)."""

from __future__ import annotations

from .model import AST_NAMES, NOT_ASSESSABLE

VERDICT_ICON = {"SAFE": "✅ SAFE", "REVIEW": "⚠️ REVIEW", "BLOCK": "⛔ BLOCK"}
SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}
SOURCE_LABEL = {"cisco": "Cisco scanner", "check": "SkillGuard check", "semantic": "LLM review"}


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
    head = f"#### {SEVERITY_ICON.get(severity, '')} {severity}: {finding['title']}"
    loc = finding["file"] or "(skill)"
    if finding.get("line"):
        loc += f":{finding['line']}"
    lines = [head, "", f"`{loc}` · {SOURCE_LABEL.get(finding['source'], finding['source'])} `{finding['rule']}`"]
    if finding.get("original_severity"):
        lines[-1] += f" · downgraded from {finding['original_severity']}"
    note = _triage_note(finding)
    if note:
        lines[-1] += f" · {note}"
    if finding.get("evidence"):
        lines += ["", "```", finding["evidence"].strip()[:400], "```"]
    if finding.get("why"):
        lines += ["", f"**Why it matters:** {finding['why']}"]
    if finding.get("fix"):
        lines += ["", f"**How to fix:** {finding['fix']}"]
    return lines + [""]


def to_markdown(result: dict) -> str:
    skill = result["skill"]
    findings = result["findings"]
    active = [f for f in findings if f["status"] == "active"]
    downgraded = [f for f in findings if f["status"] == "downgraded"]
    removed = [f for f in findings if f["status"] == "removed"]
    review = result.get("review") or {}

    out = [
        f"# SkillGuard report: {skill['name']}",
        "",
        f"## {VERDICT_ICON.get(result.get('verdict'), '❓ UNKNOWN VERDICT: ' + str(result.get('verdict')))}",
        "",
        f"**{result['reason']}**",
        "",
        f"`{skill['path']}` · {skill['files']} files · scanned {result['scanned_at']} · "
        f"{result['seconds']}s · ${result['cost']:.4f} · "
        f"{result.get('tokens_in', 0):,} in / {result.get('tokens_out', 0):,} out tokens",
        "",
        "| Check | Status | Details | Tokens in | Tokens out | Cost |",
        "|---|---|---|---:|---:|---:|",
    ]
    names = {"checks": "SkillGuard checks", "cisco": "Cisco scanner (code)", "triage": "Triage",
             "semantic": "LLM review (instructions + code)"}
    for layer in result["layers"]:
        state = "⏭️ skipped" if layer.get("skipped") else ("✅ ran" if layer["ok"] else "❌ FAILED / incomplete")
        out.append(f"| {names.get(layer['name'], layer['name'])} | {state} | {layer['detail']} ({layer['seconds']:.1f}s) | "
                   f"{layer.get('tokens_in', 0):,} | {layer.get('tokens_out', 0):,} | ${layer.get('cost', 0):.4f} |")

    if review:
        out += ["", "## Summary", "", review.get("summary", ""), "",
                f"- **Declared purpose:** {review.get('declared_purpose', '')}",
                f"- **What it actually does:** {review.get('actual_behavior', '')}",
                f"- **Assessed intent:** {review.get('intent', '')}"]

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
            loc = f"{f['file']}:{f['line']}" if f.get("line") else (f["file"] or "(skill)")
            out.append(f"| {f['rule']} | `{loc}` | {f['title']} | {_triage_note(f)} |")
        out += ["", "</details>", ""]

    out += ["## Not assessed by scanning", "",
            "These OWASP risks depend on how and where the skill runs, not on its files:", ""]
    for ast, advice in NOT_ASSESSABLE.items():
        out.append(f"- **{ast} {AST_NAMES[ast]}:** {advice}")
    out += ["", "*SkillGuard never executes skill code. No findings does not prove a skill is safe.*", ""]
    return "\n".join(out)


def to_sarif(result: dict) -> dict:
    level = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
    results = []
    for f in result["findings"]:
        if f["status"] == "removed":
            continue
        entry = {
            "ruleId": f"{f['ast']}/{f['rule']}",
            "level": level.get(f["severity"], "warning"),
            "message": {"text": f"{f['title']}. {f['why']} Fix: {f['fix']}".strip()},
        }
        if f.get("file"):
            region = {"startLine": f["line"]} if f.get("line") else {}
            entry["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": f["file"]}, "region": region}}]
        results.append(entry)
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "SkillGuard", "informationUri": "https://github.com/OWASP/www-project-agentic-skills-top-10"}},
                  "results": results}],
    }
