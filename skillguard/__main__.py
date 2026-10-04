"""SkillGuard CLI.

    skillguard scan <path>... [--md report.md] [--json report.json] [--sarif out.sarif] [--out reports/]
    skillguard eval --benign <dir> --malicious <dir> [...] [--out results/]
    skillguard approve <path> --reason "..." [--expires 2027-01-31]
    skillguard config [--example]

A path is a skill folder, a .zip/.skill package, or a folder searched for skills (any depth).

Every option can also be set with a SKILLGUARD_* environment variable or in a .env file
(`python3 -m skillguard config --example` prints them all). CLI flags override the environment.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import __version__, config, policy, report
from .config import ConfigError
from .scanner import scan
from .skill import IGNORED_DIRS, UNSCANNED_DIRS, SkillLoadError, is_package, open_skill

EXIT = {"SAFE": 0, "REVIEW": 1, "BLOCK": 2}
EXIT_ERROR = 3  # nothing could be scanned, or invalid configuration; no verdict issued


def _tokens(tokens_in: int, tokens_out: int) -> str:
    return f"{tokens_in:,} in / {tokens_out:,} out tokens"


def _has_manifest(path: Path) -> bool:
    return path.is_dir() and any(p.name.lower() == "skill.md" for p in path.iterdir())


def discover(root: Path) -> list[Path]:
    """Skills under root: root itself if it is a skill or package, else every skill folder at any depth.
    A skill's own subfolders are part of it and are not searched for further skills."""
    if is_package(root) or _has_manifest(root):
        return [root]
    if not root.is_dir():
        return []
    found = []
    for dirpath, dirnames, _ in os.walk(root, followlinks=False):
        here = Path(dirpath)
        if here != root and _has_manifest(here):
            found.append(here)
            dirnames.clear()
            continue
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORED_DIRS | UNSCANNED_DIRS)
    return sorted(found)


def _stem(path: Path) -> str:
    return "__".join(part.strip(".") for part in path.parts[-3:]) or "skill"


def _error_result(path: Path, message: str) -> dict:
    return {"verdict": "ERROR", "reason": message, "skill": {"name": path.name, "path": str(path)},
            "cost": 0, "seconds": 0, "layers": [], "findings": [], "tokens_in": 0, "tokens_out": 0}


def cmd_scan(args) -> int:
    started = time.time()
    paths = [Path(p) for p in args.path]
    missing = [p for p in paths if not p.exists()]
    if missing:
        print(f"ERROR: {', '.join(map(str, missing))} does not exist; no verdict issued.", file=sys.stderr)
        return EXIT_ERROR
    skills = [skill for p in paths for skill in discover(p)]
    single = len(paths) == 1 and len(skills) <= 1
    if not skills and single:
        skills = paths  # not a skill: scanned anyway, so the missing SKILL.md is reported as a coverage gap
    if not skills:
        print("ERROR: no skills (folders with SKILL.md, or .zip/.skill packages) found; no verdict issued.", file=sys.stderr)
        return EXIT_ERROR
    try:
        active_policy = policy.load(config.settings.policy)
    except ConfigError as exc:
        print(f"CONFIG ERROR: {exc}", file=sys.stderr)
        return EXIT_ERROR

    def run(path: Path) -> dict:
        try:
            return scan(path, policy=active_policy, use_cache=not args.no_cache)
        except SkillLoadError as exc:
            return _error_result(path, f"{exc}; no verdict issued")
        except Exception as exc:  # noqa: BLE001 - one broken skill must not hide the others' verdicts
            return _error_result(path, f"scan crashed: {type(exc).__name__}: {str(exc)[:200]}")

    with ThreadPoolExecutor(max_workers=config.settings.workers) as pool:
        results = list(pool.map(run, skills))
    scanned = [r for r in results if r["verdict"] != "ERROR"]
    errors = [r for r in results if r["verdict"] == "ERROR"]
    for r in errors:
        print(f"ERROR: {r['skill']['path']}: {r['reason']}", file=sys.stderr)

    if single and scanned:
        result = scanned[0]
        markdown, document = report.to_markdown(result), result
    else:
        markdown = report.summary_markdown(scanned) + "".join("\n---\n\n" + report.to_markdown(r) for r in scanned)
        worst = max((EXIT.get(r["verdict"], EXIT_ERROR) for r in results), default=EXIT_ERROR)
        document = {"skillguard_version": __version__,
                    "verdict": next(v for v, code in {**EXIT, "ERROR": EXIT_ERROR}.items() if code == worst),
                    "skills": results}
    if args.md:
        Path(args.md).write_text(markdown)
    if args.json:
        Path(args.json).write_text(json.dumps(document, indent=2))
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(report.to_sarif(scanned), indent=2))
    if args.codequality:
        Path(args.codequality).write_text(json.dumps(report.to_codequality(scanned), indent=2))
    if args.gitlab_sast:
        Path(args.gitlab_sast).write_text(json.dumps(report.to_gitlab_sast(scanned, started=started), indent=2))
    if args.out:
        out = Path(args.out)
        out.mkdir(parents=True, exist_ok=True)
        for path, r in zip(skills, results):
            if r["verdict"] != "ERROR":
                (out / f"{_stem(path)}.md").write_text(report.to_markdown(r))
                (out / f"{_stem(path)}.json").write_text(json.dumps(r, indent=2))
        (out / "SUMMARY.md").write_text(report.summary_markdown(scanned))
    if not (args.md or args.json or args.sarif or args.codequality or args.gitlab_sast or args.out):
        print(markdown)
    else:
        for r in scanned:
            print(f"{r['verdict']}: {r['skill']['name']}: {r['reason']}  "
                  f"(${r['cost']:.4f}, {_tokens(r['tokens_in'], r['tokens_out'])}, {r['seconds']}s"
                  + (", cached" if r.get("cache", {}).get("hit") else "") + ")")
    return max(EXIT_ERROR if r["verdict"] == "ERROR" else EXIT[r["verdict"]] for r in results)


def cmd_approve(args) -> int:
    """Print a policy entry that approves exactly the current content of one skill."""
    try:
        with open_skill(Path(args.path)) as skill:
            name, digest = skill.name, skill.content_sha256
    except SkillLoadError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return EXIT_ERROR
    lines = ["[[approve]]", f"skill = {json.dumps(name)}", f'sha256 = "{digest}"', f"reason = {json.dumps(args.reason)}"]
    if args.expires:
        lines.append(f"expires = {args.expires}")
    print("\n".join(lines))
    return 0


def cmd_eval(args) -> int:
    s = config.settings
    cases = [(p, "benign") for root in args.benign for p in discover(Path(root))]
    cases += [(p, "malicious") for root in args.malicious for p in discover(Path(root))]
    cases += [(p, "unlabeled") for root in args.unlabeled for p in discover(Path(root))]
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    def run(case):
        path, label = case
        try:
            # Evaluations measure the scanner itself: no cache, no policy.
            result = scan(path, use_cache=False, policy=policy.Policy())
        except Exception as exc:  # keep evaluating the rest
            return path, label, _error_result(path, str(exc))
        (out / f"{_stem(path)}.md").write_text(report.to_markdown(result))
        (out / f"{_stem(path)}.json").write_text(json.dumps(result, indent=2))
        return path, label, result

    with ThreadPoolExecutor(max_workers=s.workers) as pool:
        rows = list(pool.map(run, cases))

    lines = ["| Skill | Label | Verdict | Active findings | Failed layers | Tokens in | Tokens out | Cost | Time |",
             "|---|---|---|---|---|---:|---:|---:|---:|"]
    for path, label, r in rows:
        ok = label == "unlabeled" or ((r["verdict"] in ("BLOCK", "REVIEW")) if label == "malicious" else (r["verdict"] != "BLOCK"))
        failed = ", ".join(l["name"] for l in r["layers"] if not l["ok"] and not l.get("skipped")) or "—"
        active = sum(f["status"] == "active" for f in r["findings"])
        name = "/".join(path.parts[-3:])
        lines.append(f"| {'' if ok else '❌ '}{name} | {label} | {r['verdict']} | {active} | {failed} | "
                     f"{r['tokens_in']:,} | {r['tokens_out']:,} | ${r['cost']:.4f} | {r['seconds']}s |")
    total_in, total_out = sum(r["tokens_in"] for _, _, r in rows), sum(r["tokens_out"] for _, _, r in rows)
    total_cost = sum(r["cost"] for _, _, r in rows)
    lines.append(f"| **Total ({len(rows)} skills)** | | | | | **{total_in:,}** | **{total_out:,}** | **${total_cost:.4f}** | |")
    benign = [r for _, l, r in rows if l == "benign"]
    malicious = [r for _, l, r in rows if l == "malicious"]

    def share(items, verdicts):
        return f"{sum(r['verdict'] in verdicts for r in items)}/{len(items)}" if items else "n/a"

    summary = [
        "", f"Backend: `{s.backend}` · review model: `{s.model}` · triage model: `{s.effective_triage_model}` · "
            f"LLM: {s.use_llm} · triage: {s.use_triage} · Cisco: {s.use_cisco}",
        "",
        f"- Malicious caught (BLOCK or REVIEW): **{share(malicious, {'BLOCK', 'REVIEW'})}**, BLOCK: {share(malicious, {'BLOCK'})}",
        f"- Benign false BLOCK: **{share(benign, {'BLOCK'})}**, REVIEW: {share(benign, {'REVIEW'})}, SAFE: {share(benign, {'SAFE'})}",
        f"- Scans with a failed layer: {sum(any(not l['ok'] and not l.get('skipped') for l in r['layers']) for _, _, r in rows)}/{len(rows)}",
        f"- Total: {_tokens(total_in, total_out)} · ${total_cost:.4f} · mean time "
        f"{sum(r['seconds'] for _, _, r in rows) / max(1, len(rows)):.1f}s per skill",
    ]
    text = "\n".join(lines + summary) + "\n"
    (out / "SUMMARY.md").write_text(text)
    print(text)
    return 0


def cmd_config(args) -> int:
    if args.example:
        print(config.env_example())
        return 0
    width = max(len(env) for env, _, _ in config.settings.describe())
    for env, value, help_text in config.settings.describe():
        print(f"{env:<{width}}  {value}")
    print(f"\nEffective: base URL {config.settings.effective_base_url or '(provider default)'} · "
          f"triage model {config.settings.effective_triage_model} · "
          f"fallback {config.settings.effective_fallback_model or '(disabled)'}")
    return 0


def _overrides(args) -> dict:
    """CLI flags that were given; everything else comes from the environment."""
    flags = {
        "backend": getattr(args, "backend", None),
        "model": getattr(args, "model", None),
        "triage_model": getattr(args, "triage_model", None),
        "fallback_model": getattr(args, "fallback_model", None),
        "workers": getattr(args, "workers", None),
        "policy": getattr(args, "policy", None),
    }
    for flag, name in (("no_llm", "use_llm"), ("no_triage", "use_triage"), ("no_cisco", "use_cisco")):
        if getattr(args, flag, False):
            flags[name] = False
    return flags


def main() -> int:
    parser = argparse.ArgumentParser(prog="skillguard", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version", version=f"skillguard {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    approve = sub.add_parser("approve", help="print a [[approve]] policy entry pinned to a skill's current content")
    approve.add_argument("path")
    approve.add_argument("--reason", required=True, help="who reviewed it and why it is acceptable")
    approve.add_argument("--expires", help="date after which the approval lapses, e.g. 2027-01-31")
    for name in ("scan", "eval", "config"):
        p = sub.add_parser(name)
        p.add_argument("--env-file", type=Path, help="load settings from this file (default: $SKILLGUARD_ENV_FILE or ./.env)")
        p.add_argument("--backend", choices=config.BACKENDS, help="LLM backend (SKILLGUARD_BACKEND)")
        p.add_argument("--model", help="review model (SKILLGUARD_MODEL)")
        p.add_argument("--triage-model", help="triage model; default same as --model; typesafe/jev-1.13 for Jev "
                                              "(SKILLGUARD_TRIAGE_MODEL)")
        p.add_argument("--fallback-model", help="model used when the review model's content filter refuses; "
                                                "'none' disables (SKILLGUARD_FALLBACK_MODEL)")
        if name == "config":
            p.add_argument("--example", action="store_true", help="print a .env template with every setting")
            continue
        p.add_argument("--no-llm", action="store_true", help="skip the LLM review (SKILLGUARD_LLM=false)")
        p.add_argument("--no-triage", action="store_true", help="skip triage (SKILLGUARD_TRIAGE=false)")
        p.add_argument("--no-cisco", action="store_true", help="skip the Cisco scanner (SKILLGUARD_CISCO=false)")
        if name == "scan":
            p.add_argument("path", nargs="+", help="skill folder, .zip/.skill package, or folder of skills")
            p.add_argument("--md", help="Markdown report (a summary plus every skill's report)")
            p.add_argument("--json", help="JSON result (one skill: its result; several: {verdict, skills})")
            p.add_argument("--sarif", help="SARIF 2.1.0 for GitHub code scanning; paths relative to the current dir")
            p.add_argument("--codequality", help="GitLab Code Quality report (merge request widget, all tiers)")
            p.add_argument("--gitlab-sast", help="GitLab SAST report (security widget, GitLab Ultimate)")
            p.add_argument("--out", help="directory for one Markdown + JSON report per skill and SUMMARY.md")
            p.add_argument("--policy", help="policy file with suppressions and approvals (SKILLGUARD_POLICY)")
            p.add_argument("--no-cache", action="store_true", help="ignore and do not update the result cache")
            p.add_argument("--workers", type=int, help="skills scanned in parallel (SKILLGUARD_WORKERS)")
        else:
            p.add_argument("--benign", nargs="*", default=[])
            p.add_argument("--malicious", nargs="*", default=[])
            p.add_argument("--unlabeled", nargs="*", default=[], help="scanned and reported, not scored")
            p.add_argument("--out", default="skillguard-eval")
            p.add_argument("--workers", type=int, help="skills scanned in parallel (SKILLGUARD_WORKERS)")
    args = parser.parse_args()
    if args.command == "approve":
        return cmd_approve(args)
    if args.command == "config" and args.example:
        return cmd_config(args)  # template only; no need for a valid environment
    try:
        config.configure(_overrides(args), env_file=args.env_file)
    except ConfigError as exc:
        print(f"CONFIG ERROR: {exc}", file=sys.stderr)
        return EXIT_ERROR
    return {"scan": cmd_scan, "eval": cmd_eval, "config": cmd_config}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
