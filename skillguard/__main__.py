"""SkillGuard CLI.

    python3 -m skillguard scan <skill-dir> [--md report.md] [--json report.json] [--sarif out.sarif]
    python3 -m skillguard eval --benign <dir> --malicious <dir> [...] [--out results/]
    python3 -m skillguard config [--example]

Every option can also be set with a SKILLGUARD_* environment variable or in a .env file
(`python3 -m skillguard config --example` prints them all). CLI flags override the environment.
"""

from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import config, report
from .config import ConfigError
from .scanner import scan
from .skill import SkillLoadError

EXIT = {"SAFE": 0, "REVIEW": 1, "BLOCK": 2}
EXIT_ERROR = 3  # nothing could be scanned, or invalid configuration; no verdict issued


def _tokens(tokens_in: int, tokens_out: int) -> str:
    return f"{tokens_in:,} in / {tokens_out:,} out tokens"


def cmd_scan(args) -> int:
    try:
        result = scan(Path(args.path))
    except SkillLoadError as exc:
        print(f"ERROR: {exc}; no verdict issued.", file=sys.stderr)
        return EXIT_ERROR
    markdown = report.to_markdown(result)
    if args.md:
        Path(args.md).write_text(markdown)
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2))
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(report.to_sarif(result), indent=2))
    if not (args.md or args.json or args.sarif):
        print(markdown)
    else:
        print(f"{result['verdict']}: {result['reason']}  "
              f"(${result['cost']:.4f}, {_tokens(result['tokens_in'], result['tokens_out'])}, {result['seconds']}s)")
    return EXIT[result["verdict"]]


def _has_manifest(path: Path) -> bool:
    return path.is_dir() and any(p.name.lower() == "skill.md" for p in path.iterdir())


def _skill_dirs(root: Path) -> list[Path]:
    if _has_manifest(root):
        return [root]
    return sorted(p for p in root.iterdir() if _has_manifest(p))


def cmd_eval(args) -> int:
    s = config.settings
    cases = [(p, "benign") for root in args.benign for p in _skill_dirs(Path(root))]
    cases += [(p, "malicious") for root in args.malicious for p in _skill_dirs(Path(root))]
    cases += [(p, "unlabeled") for root in args.unlabeled for p in _skill_dirs(Path(root))]
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    def run(case):
        path, label = case
        try:
            result = scan(path)
        except Exception as exc:  # keep evaluating the rest
            return path, label, {"verdict": "ERROR", "reason": str(exc), "cost": 0, "seconds": 0, "layers": [],
                                 "findings": [], "tokens_in": 0, "tokens_out": 0}
        stem = "__".join(part.strip(".") for part in path.parts[-3:])
        (out / f"{stem}.md").write_text(report.to_markdown(result))
        (out / f"{stem}.json").write_text(json.dumps(result, indent=2))
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
    }
    for flag, name in (("no_llm", "use_llm"), ("no_triage", "use_triage"), ("no_cisco", "use_cisco")):
        if getattr(args, flag, False):
            flags[name] = False
    return flags


def main() -> int:
    parser = argparse.ArgumentParser(prog="skillguard", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
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
            p.add_argument("path")
            p.add_argument("--md"), p.add_argument("--json"), p.add_argument("--sarif")
        else:
            p.add_argument("--benign", nargs="*", default=[])
            p.add_argument("--malicious", nargs="*", default=[])
            p.add_argument("--unlabeled", nargs="*", default=[], help="scanned and reported, not scored")
            p.add_argument("--out", default="skillguard-eval")
            p.add_argument("--workers", type=int, help="skills scanned in parallel (SKILLGUARD_WORKERS)")
    args = parser.parse_args()
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
