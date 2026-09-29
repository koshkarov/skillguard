# SkillGuard

A low-cost security scanner for AI agent skills (Claude Code, Codex, Cursor and others). It checks a skill before you install it, gives a clear verdict (✅ SAFE, ⚠️ REVIEW or ⛔ BLOCK), and explains every finding. Findings are mapped to the [OWASP Agentic Skills Top 10](https://github.com/OWASP/www-project-agentic-skills-top-10).

SkillGuard never executes skill code.

## How it works

| Layer | What it does | Cost |
|---|---|---|
| 1. Code checks | [Cisco skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) (offline), plus our own rules: hidden Unicode, encoded payloads, credential access, fake-prerequisite installers, instructions that upload local data, auto-run config, unpinned dependencies, secrets | free, ~1–5 s |
| 2. LLM review | One review of the skill's instructions **and** code against an OWASP-based questionnaire, with verified `file:line` evidence | ~$0.001–0.06 per skill (GPT-6 Luna) |
| 3. Triage | Classifies each Layer 1 finding as real, low-risk or false positive. By default the same model as layer 2 does this; [TypeSafe Jev](https://typesafe.ai/blog/introducing-system-one-models-and-jev) is optional | ~$0.0001–0.001 |
| 4. Report | Verdict, plain-language summary, findings grouped by OWASP category, Markdown / JSON / SARIF | — |

If any layer fails, the verdict becomes at least REVIEW, never a silent SAFE. See [DESIGN.md](DESIGN.md) for the reasoning, the decisions and the evaluation results.

## Requirements

- Python 3.10+
- [`uv`](https://docs.astral.sh/uv/). The Cisco scanner is run with `uvx`, so there's no separate install.
- An [OpenRouter](https://openrouter.ai) API key for layers 2 and 3

## Usage

```bash
export OPENROUTER_API_KEY=sk-or-...

# Scan one skill
python3 -m skillguard scan path/to/skill --md report.md --json report.json --sarif report.sarif

# Static checks only (free, no API key). A partial scan: it can BLOCK or REVIEW, never SAFE
python3 -m skillguard scan path/to/skill --no-llm --no-triage

# Evaluate against labeled sets
python3 -m skillguard eval --benign path/to/benign-skills --malicious path/to/malicious-skills --out eval/

# Tests (no network)
python3 -m unittest discover -s tests
```

Exit codes: `0` SAFE, `1` REVIEW, `2` BLOCK, `3` error (path not scannable, no verdict), so the scanner can gate CI.

Options: `--model` (any OpenRouter model; default `openai/gpt-6-luna`), `--triage-model` (default: same as `--model`; e.g. `typesafe/jev-1.13` for Jev), `--no-llm`, `--no-triage`, `--no-cisco`.

Every scan reports input/output tokens and cost per layer and in total, and `eval` adds a per-skill token table with totals. Costs are the amounts OpenRouter bills. They run slightly above list price because OpenAI charges prompt-cache writes at 1.25× the input price.

Anything SkillGuard cannot inspect (symlinks, unknown binaries or archives, files over 2 MB, missing `SKILL.md`) is reported as a coverage gap and forces at least REVIEW.

`tools/jev_filter.py` filters false positives out of a SkillSpector or Cisco JSON report using Jev, with the same decision policy as SkillGuard.

## Results so far

| Test set | Result |
|---|---|
| 19 real, harmless skills | 0 BLOCK, 3 REVIEW, 16 SAFE (the REVIEWs: an uninspected bundled `.tar.gz`, a real minor script-injection issue, and an invented user quote in `canvas-design`'s instructions) |
| Cost and tokens, all 27 skills (Luna only) | 879K in / 49K out tokens, $0.134 total, ~23 s per skill |
| 8 malicious samples ([snyk-labs/toxicskills-goof](https://github.com/snyk-labs/toxicskills-goof) + one test skill) | 8/8 BLOCK (Cisco offline alone: 2/7; SkillSpector static alone: 2/7) |

This is a small evaluation, and two rules were written after seeing these samples. A larger labeled test set is the next step (see DESIGN.md §11–13).

## Privacy

Layers 2 and 3 send skill content to OpenRouter and the model providers. Use `--no-llm --no-triage` for private skills.
