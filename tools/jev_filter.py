#!/usr/bin/env python3
"""Filter false positives out of a SkillSpector or Cisco skill-scanner JSON report using TypeSafe Jev.

Each finding is sent to Jev (via OpenRouter's /v1/systemone endpoint) together
with the source code around it and the skill's declared description. Jev
returns calibrated probabilities for three verdicts:

    true_positive   real malicious or dangerous behavior      -> kept
    benign_risk     real behavior, low risk, fits the purpose -> kept, downgraded to LOW
    false_positive  pattern match with no real risk           -> removed

Decision per finding:
    P(true_positive) >= --keep-threshold   -> kept as is
    else P(false_positive) >= --drop-threshold -> removed
    else                                   -> downgraded to LOW (if above LOW)
Coverage findings (AE*, "analysis-evasion") describe scanner limitations, not
code behavior, so they are passed through unjudged.

Usage:
    skillspector scan <skill> -f json -o report.json
    python jev_filter.py report.json -o filtered.json --md filtered.md

    skill-scanner scan <skill> --use-behavioral --format json --output cisco.json
    python jev_filter.py cisco.json -o filtered.json --md filtered.md

Auth: OPENROUTER_API_KEY, or SKILLSPECTOR_COMPAT_API_KEY from skills/.env.
Stdlib only; no pip installs needed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

API_URL = "https://openrouter.ai/api/v1/systemone"
DEFAULT_MODEL = "typesafe/jev-1.13"
CONTEXT_LINES = 25          # source lines shown before/after the finding
MAX_STATE_CHARS = 60_000    # Jev limit is ~64k tokens total; stay well under

VERDICT_CRITERIA = {
    "true_positive": (
        "Real malicious or dangerous behavior: exfiltration, credential theft, "
        "prompt injection, hidden or undisclosed destructive actions, "
        "remote code download/execution, or clear abuse of the agent."
    ),
    "benign_risk": (
        "The flagged behavior really exists but is low-risk, visible, and "
        "consistent with the skill's stated purpose (e.g. running a local CLI, "
        "starting a local server, reading its own files)."
    ),
    "false_positive": (
        "The pattern matched but the code does not do what the rule claims "
        "(e.g. no shell involved, value is not user-controlled, data never "
        "leaves the machine), or it is documentation/comments only."
    ),
}


def rule_id(issue: dict) -> str:
    return str(issue.get("rule_id") or issue.get("id") or "?")


def location(issue: dict) -> tuple[str | None, int | None, int | None]:
    loc = issue.get("location") or {}
    return loc.get("file"), loc.get("start_line"), loc.get("end_line")


COVERAGE_RULES = {"LLM_ANALYSIS_FAILED", "LLM_CONTEXT_BUDGET_EXCEEDED"}


def is_coverage_finding(issue: dict) -> bool:
    rule = rule_id(issue)
    return rule.startswith("AE") or rule in COVERAGE_RULES or issue.get("category") == "analysis-evasion"


def from_cisco(finding: dict) -> dict:
    """Map a Cisco skill-scanner finding onto the SkillSpector issue shape."""
    return {
        "id": finding.get("rule_id"),
        "severity": finding.get("severity"),
        "category": finding.get("category"),
        "pattern": finding.get("title"),
        "finding": finding.get("snippet"),
        "explanation": finding.get("description"),
        "location": {"file": finding.get("file_path"), "start_line": finding.get("line_number")},
    }


def load_report(report: dict) -> tuple[str, str, str, list[dict], list[dict]]:
    """Return (list key, skill source, skill name, normalized issues, original items)."""
    if "issues" in report:  # SkillSpector
        skill = report.get("skill", {})
        items = report["issues"]
        return "issues", skill.get("source", "."), skill.get("name", ""), items, items
    if "findings" in report:  # Cisco skill-scanner
        items = report["findings"]
        normalized = [from_cisco(f) for f in items]
        return "findings", report.get("skill_path", "."), report.get("skill_name", ""), normalized, items
    raise SystemExit("Unrecognized report: expected SkillSpector 'issues' or Cisco 'findings'.")


def skill_description(skill_dir: Path) -> str:
    skill_md = skill_dir / "SKILL.md"
    try:
        text = skill_md.read_text(errors="replace")
    except OSError:
        return "(SKILL.md not readable)"
    match = re.match(r"^---\n(.*?)\n---", text, re.S)
    return match.group(1).strip() if match else text[:2000]


def source_excerpt(skill_dir: Path, file: str | None, start: int | None, end: int | None) -> str:
    if not file:
        return "(no file location)"
    path = (skill_dir / file).resolve()
    if skill_dir.resolve() not in path.parents or not path.is_file():
        return f"(source file {file} not available)"
    lines = path.read_text(errors="replace").splitlines()
    if not start:
        body = lines[: CONTEXT_LINES * 2]
        first = 1
    else:
        first = max(1, start - CONTEXT_LINES)
        last = min(len(lines), (end or start) + CONTEXT_LINES)
        body = lines[first - 1 : last]
    return "\n".join(f"{first + i:5d}: {line}" for i, line in enumerate(body))


def build_state(issue: dict, skill_name: str, description: str, excerpt: str) -> str:
    file, start, end = location(issue)
    finding = {
        "rule": rule_id(issue),
        "severity": issue.get("severity"),
        "category": issue.get("category"),
        "pattern": issue.get("pattern"),
        "matched_text": issue.get("finding"),
        "scanner_explanation": issue.get("explanation"),
        "location": f"{file}:{start}" + (f"-{end}" if end and end != start else ""),
    }
    state = (
        "A static security scanner flagged the finding below in an AI agent skill. "
        "Judge it using the actual source code, not the rule name.\n\n"
        f"## Skill: {skill_name}\nDeclared frontmatter:\n{description}\n\n"
        f"## Finding\n{json.dumps(finding, indent=2)}\n\n"
        f"## Source around the finding\n{excerpt}\n"
    )
    return state[:MAX_STATE_CHARS]


def ask_jev(api_key: str, model: str, state: str, retries: int = 3) -> dict:
    payload = json.dumps(
        {
            "model": model,
            "state": state,
            "questions": {
                "verdict": {
                    "type": "choice",
                    "instructions": "Classify this scanner finding.",
                    "criteria": VERDICT_CRITERIA,
                }
            },
        }
    ).encode()
    request = urllib.request.Request(
        API_URL,
        data=payload,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
    )
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code not in (429, 500, 502, 503, 504) or attempt == retries - 1:
                raise RuntimeError(f"HTTP {exc.code}: {exc.read()[:300]!r}") from exc
        except urllib.error.URLError as exc:
            if attempt == retries - 1:
                raise RuntimeError(str(exc)) from exc
        time.sleep(2**attempt)
    raise RuntimeError("unreachable")


def judge(issue, *, api_key, model, skill_dir, skill_name, description, drop_threshold, keep_threshold):
    if is_coverage_finding(issue):
        return {"action": "keep", "verdict": "not_judged", "reason": "coverage finding (scanner limitation)"}
    file, start, end = location(issue)
    state = build_state(issue, skill_name, description, source_excerpt(skill_dir, file, start, end))
    try:
        response = ask_jev(api_key, model, state)
    except RuntimeError as exc:
        # Fail closed: an unjudged finding stays in the report.
        return {"action": "keep", "verdict": "error", "reason": str(exc)}
    answer = response["answers"]["verdict"]
    probs = answer.get("probabilities", {})
    p_fp = probs.get("false_positive", 0.0)
    p_tp = probs.get("true_positive", 0.0)
    severity = str(issue.get("severity", "")).upper()
    if p_tp >= keep_threshold:
        action = "keep"
    elif p_fp >= drop_threshold:
        action = "drop"
    elif severity in SEVERITY_ORDER and SEVERITY_ORDER.index(severity) > SEVERITY_ORDER.index("LOW"):
        # Unlikely to be a real threat but not clearly a false positive either.
        action = "downgrade"
    else:
        action = "keep"
    return {
        "action": action,
        "verdict": answer["choice"],
        "probabilities": probs,
        "confidence": answer.get("confidence"),
        "cost": response.get("usage", {}).get("cost", 0.0),
    }


def to_markdown(report: dict, results: list[tuple[dict, dict]], stats: dict) -> str:
    icon = {"keep": "✅ kept", "downgrade": "⬇️ → LOW", "drop": "🗑️ removed"}
    scanner = "SkillSpector" if "issues" in report else "Cisco skill-scanner"
    name = report.get("skill", {}).get("name") or report.get("skill_name", "?")
    out = [
        f"# Jev-filtered {scanner} report: {name}",
        "",
        f"Model `{stats['model']}` · {stats['total']} findings judged in {stats['seconds']:.1f}s · "
        f"cost ${stats['cost']:.5f}",
        "",
        f"**Kept:** {stats['keep']} · **Downgraded to LOW:** {stats['downgrade']} · "
        f"**Removed as false positive:** {stats['drop']} · **Errors (kept):** {stats['errors']}",
        "",
        f"**Max severity after filtering:** {stats['max_severity']}",
        "",
        "| Action | Severity | Rule | Location | Verdict | P(TP) / P(benign) / P(FP) |",
        "|---|---|---|---|---|---|",
    ]
    for issue, result in results:
        file, start, _ = location(issue)
        probs = result.get("probabilities") or {}
        p = (
            f"{probs.get('true_positive', 0):.2f} / {probs.get('benign_risk', 0):.2f} / "
            f"{probs.get('false_positive', 0):.2f}"
            if probs
            else "—"
        )
        out.append(
            f"| {icon[result['action']]} | {issue.get('severity')} | {rule_id(issue)} | "
            f"`{file}:{start}` | {result['verdict']} | {p} |"
        )
    out += ["", "## Remaining findings", ""]
    for issue, result in results:
        if result["action"] == "drop":
            continue
        file, start, _ = location(issue)
        text = issue.get("explanation") or issue.get("pattern") or ""
        severity = "LOW (was %s)" % issue.get("severity") if result["action"] == "downgrade" else issue.get("severity")
        out.append(f"- **{severity} {rule_id(issue)}** `{file}:{start}`: {text}")
    return "\n".join(out) + "\n"


SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("report", type=Path, help="SkillSpector JSON report")
    parser.add_argument("-o", "--output", type=Path, help="filtered JSON output")
    parser.add_argument("--md", type=Path, help="markdown summary output")
    parser.add_argument("--skill-dir", type=Path, help="skill source dir (default: skill.source in report)")
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--drop-threshold", type=float, default=0.6, help="min P(false_positive) to remove")
    parser.add_argument("--keep-threshold", type=float, default=0.2, help="P(true_positive) that always keeps")
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()

    api_key = os.environ.get("OPENROUTER_API_KEY") or os.environ.get("SKILLSPECTOR_COMPAT_API_KEY")
    if not api_key:
        sys.exit("Set OPENROUTER_API_KEY (or source skills/.env for SKILLSPECTOR_COMPAT_API_KEY).")

    report = json.loads(args.report.read_text())
    list_key, source, skill_name, issues, originals = load_report(report)
    skill_dir = args.skill_dir or Path(source)
    skill_name = skill_name or skill_dir.name
    description = skill_description(skill_dir)

    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        verdicts = list(
            pool.map(
                lambda issue: judge(
                    issue,
                    api_key=api_key,
                    model=args.model,
                    skill_dir=skill_dir,
                    skill_name=skill_name,
                    description=description,
                    drop_threshold=args.drop_threshold,
                    keep_threshold=args.keep_threshold,
                ),
                issues,
            )
        )
    results = list(zip(issues, verdicts))

    kept, dropped = [], []
    for original, (_, result) in zip(originals, results):
        issue = {**original, "jev": result}
        if result["action"] == "drop":
            dropped.append(issue)
            continue
        if result["action"] == "downgrade":
            issue["original_severity"] = issue.get("severity")
            issue["severity"] = "LOW"
        kept.append(issue)

    severities = [i.get("severity") for i in kept if i.get("severity") in SEVERITY_ORDER]
    stats = {
        "model": args.model,
        "total": len(issues),
        "seconds": time.monotonic() - started,
        "cost": sum(r.get("cost", 0.0) for _, r in results),
        "keep": sum(r["action"] == "keep" for _, r in results),
        "downgrade": sum(r["action"] == "downgrade" for _, r in results),
        "drop": len(dropped),
        "errors": sum(r["verdict"] == "error" for _, r in results),
        "max_severity": max(severities, key=SEVERITY_ORDER.index) if severities else "NONE",
    }

    filtered = {**report, list_key: kept, "jev_removed": dropped, "jev_stats": stats}
    if args.output:
        args.output.write_text(json.dumps(filtered, indent=2))
    markdown = to_markdown(report, results, stats)
    if args.md:
        args.md.write_text(markdown)
    if not args.output and not args.md:
        print(markdown)
    else:
        print(
            f"{stats['total']} findings: {stats['keep']} kept, {stats['downgrade']} downgraded, "
            f"{stats['drop']} removed, {stats['errors']} errors · max severity {stats['max_severity']} · "
            f"${stats['cost']:.5f} · {stats['seconds']:.1f}s"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
