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

Built for use across an organisation:

- **Cheap at scale.** Results are cached by content hash, so an unchanged skill is never paid for twice (CI re-runs cost $0). A per-skill cap on LLM calls stops one huge skill from running up the bill.
- **CI gate.** A GitLab CI template with Code Quality and SAST reports for merge requests. Also a GitHub Action with SARIF, a summary across many skills, and exit codes for the worst verdict.
- **Governance.** A policy file with reviewed suppressions and approvals. Each entry has a reason and an expiry, and can be pinned to a hash, so it lapses when the content changes. Every report records the skill's content hash.
- **Air-gapped / private.** A Docker image with the pinned Cisco scanner pre-fetched; a local model via LiteLLM + Ollama; or static checks only.

## Install

```bash
pip install "git+https://github.com/koshkarov/skillguard"            # adds the `skillguard` command
pip install "skillguard[litellm] @ git+https://github.com/koshkarov/skillguard"   # with the LiteLLM backend
uvx --from "git+https://github.com/koshkarov/skillguard" skillguard scan path/to/skill   # no install
docker build -t skillguard .                                         # image; see "Docker" below
```

`python3 -m skillguard` works from a checkout as well.

## Requirements

- Python 3.11+ (standard library only)
- [`uv`](https://docs.astral.sh/uv/). The Cisco scanner is run with `uvx`, so there's no separate install.
- For layers 2 and 3, one of:
  - an [OpenRouter](https://openrouter.ai) API key (default backend, no extra packages), or
  - [LiteLLM](https://docs.litellm.ai/) (`pip install litellm`) for any other provider: Anthropic, OpenAI, Bedrock, Vertex, Azure, local Ollama, a LiteLLM proxy, …

## Configuration

Every setting is a `SKILLGUARD_*` environment variable. You can also put them in a `.env` file, which is read from the current directory, or from `SKILLGUARD_ENV_FILE`/`--env-file`. CLI flags override the environment, which overrides the file. [`.env.example`](.env.example) lists all of them.

```bash
cp .env.example .env          # then edit
python3 -m skillguard config  # show the effective settings (keys masked)
```

The main ones:

| Variable | Default | Meaning |
|---|---|---|
| `SKILLGUARD_API_KEY` | — | API key (required for the OpenRouter backend) |
| `SKILLGUARD_BACKEND` | `openrouter` | `openrouter` or `litellm` |
| `SKILLGUARD_MODEL` | `openai/gpt-6-luna` | review model |
| `SKILLGUARD_TRIAGE_MODEL` | same as model | triage model; `typesafe/jev-1.13` for Jev |
| `SKILLGUARD_BASE_URL` | OpenRouter | any OpenAI-compatible endpoint, or LiteLLM `api_base` |
| `SKILLGUARD_LLM` / `_TRIAGE` / `_CISCO` | `true` | turn layers on or off |
| `SKILLGUARD_CACHE_DIR` | `~/.cache/skillguard` | result cache; `none` disables |
| `SKILLGUARD_CACHE_TTL_DAYS` | `30` | re-scan cached results older than this |
| `SKILLGUARD_MAX_REVIEW_CALLS` | `8` | cost cap: larger skills are not sent to the LLM (verdict at least REVIEW) |
| `SKILLGUARD_POLICY` | — | policy file with suppressions and approvals |

Examples:

```bash
# OpenRouter (default)
SKILLGUARD_API_KEY=sk-or-...

# Anthropic directly, through LiteLLM (LiteLLM reads ANTHROPIC_API_KEY itself)
SKILLGUARD_BACKEND=litellm
SKILLGUARD_MODEL=anthropic/claude-sonnet-5.5
SKILLGUARD_FALLBACK_MODEL=none      # or another model when Anthropic's filter refuses a malicious skill
ANTHROPIC_API_KEY=sk-ant-...

# Local model through Ollama (no data leaves the machine)
SKILLGUARD_BACKEND=litellm
SKILLGUARD_MODEL=ollama/llama3.1
SKILLGUARD_BASE_URL=http://localhost:11434
SKILLGUARD_FALLBACK_MODEL=none

# A LiteLLM proxy server (OpenAI-compatible), no litellm package needed
SKILLGUARD_BASE_URL=http://localhost:4000
SKILLGUARD_API_KEY=sk-litellm-...
SKILLGUARD_MODEL=my-proxy-model-alias
```

Without installing `litellm`, run the LiteLLM backend with `uv run --no-project --with litellm python3 -m skillguard ...`.

## Usage

```bash
# Scan one skill (a folder, or a .zip/.skill package)
skillguard scan path/to/skill --md report.md --json report.json --sarif report.sarif

# Scan every skill in a repository (folders with SKILL.md at any depth), one report per skill plus a summary
skillguard scan . --out skillguard-reports/ --sarif skillguard.sarif

# Static checks only (free, no API key). A partial scan: it can BLOCK or REVIEW, never SAFE
skillguard scan path/to/skill --no-llm --no-triage

# Evaluate against labeled sets (no cache, no policy)
skillguard eval --benign path/to/benign-skills --malicious path/to/malicious-skills --out eval/

# Tests (no network)
python3 -m unittest discover -s tests
```

Exit codes: `0` SAFE, `1` REVIEW, `2` BLOCK, `3` error (path not scannable, invalid configuration or policy; no verdict). With several skills, the exit code is the worst one, so the scanner can gate CI.

CLI flags, each overriding its `SKILLGUARD_*` variable: `--env-file`, `--backend`, `--model`, `--triage-model`, `--fallback-model`, `--no-llm`, `--no-triage`, `--no-cisco`, `--policy`, `--workers`; for `scan` also `--no-cache`, `--out`.

Every scan reports input/output tokens and cost per layer and in total, and `eval` adds a per-skill token table with totals. Costs are what the provider reports: OpenRouter's billed amount, or LiteLLM's cost calculation. With OpenAI models they run slightly above list price because prompt-cache writes cost 1.25× the input price.

Bundled zip and tar archives are opened in memory, and their text files are reviewed like any other file (shown as `archive.tar.gz!/path`). Anything SkillGuard cannot inspect is reported as a coverage gap and forces at least REVIEW: symlinks, unknown binaries, other archive types, encrypted or nested archives, files over 2 MB, unsafe or duplicate paths in a package, and a missing `SKILL.md`.

`tools/jev_filter.py` filters false positives out of a SkillSpector or Cisco JSON report using Jev, with the same decision policy as SkillGuard.

## CI: GitLab

Include the template in `.gitlab-ci.yml` and set `SKILLGUARD_API_KEY` as a masked CI/CD variable:

```yaml
include:
  - remote: https://raw.githubusercontent.com/koshkarov/skillguard/main/ci/skillguard.gitlab-ci.yml
  # from a GitLab mirror instead:  - project: my-group/skillguard
  #                                  file: ci/skillguard.gitlab-ci.yml
variables:
  SKILLGUARD_PATHS: "skills .claude/skills"   # folders searched for skills, or packages
  SKILLGUARD_POLICY: "skillguard-policy.toml"
```

| Verdict | Job | Where findings show |
|---|---|---|
| ✅ SAFE | passed | Code Quality widget in the merge request (all tiers) |
| ⚠️ REVIEW | passed with warning (allowed failure, exit code 1) | Security widget and Vulnerability Report (Ultimate) |
| ⛔ BLOCK / error | failed | Markdown report linked from the merge request ("SkillGuard report") |

- **Strict gate:** to make REVIEW block merges too, override the job with `allow_failure: false`.
- **Cost:** results are kept in the GitLab cache between pipelines, so a merge request pays only for the skills it changes.
- **Pinning:** set `SKILLGUARD_PACKAGE` to a tag or commit tarball, or `SKILLGUARD_IMAGE` to an image built from the Dockerfile (no install step).
- **Protected variables:** if `SKILLGUARD_API_KEY` is *protected*, merge request pipelines from unprotected branches don't receive it. The LLM review can't run there, and every skill is at most REVIEW.

The reports can also be written directly, for any CI: `--codequality gl-code-quality-report.json --gitlab-sast gl-sast-report.json`. The SAST report is validated against GitLab's schema 15.2.1.

## CI: GitHub Action

```yaml
- uses: koshkarov/skillguard@main        # pin a tag or commit SHA in production
  with:
    paths: skills .claude/skills         # folders searched for skills, or packages
    api-key: ${{ secrets.SKILLGUARD_API_KEY }}
    policy: skillguard-policy.toml
    fail-on: block                       # or 'review', or 'never'
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: skillguard.sarif, category: skillguard }
```

The Action writes the report to the job summary, sets the `verdict` output, and caches results between runs, so a pull request that changes one skill pays only for that skill. A complete workflow is in [`examples/github-workflow.yml`](examples/github-workflow.yml). In SARIF, file paths are relative to the working directory, so GitHub links findings to the right files. Findings suppressed by policy are uploaded as suppressed.

Other CI systems: run `skillguard scan ... --sarif out.sarif` (or the GitLab report flags) and gate on the exit code.

## Policy: suppressions and approvals

After a person reviews a finding, record the decision in a TOML policy file instead of switching checks off. See [`examples/skillguard-policy.toml`](examples/skillguard-policy.toml):

```toml
[[suppress]]                     # one reviewed finding
rule = "COVERAGE_GAP"
path = "scripts/tool.bin"
sha256 = "…"                     # only while the file is unchanged
reason = "Vendor binary verified, SEC-1234"
expires = 2027-03-31

[[approve]]                      # accept a REVIEW verdict for exactly this content
skill = "canvas-design"
sha256 = "…"                     # from `skillguard approve <path> --reason ...`
reason = "Reviewed by security, SEC-1250"
```

- Suppressed findings stay in the report, marked as suppressed, and don't count towards the verdict.
- An approval turns REVIEW into SAFE only while the skill's content hash matches. It never overrides BLOCK.
- Expired, unmatched or outdated entries are reported in the output.
- SkillGuard loads a policy only from an explicit path (`--policy` / `SKILLGUARD_POLICY`), never from inside a scanned skill. Require security-team approval for changes to the file (CODEOWNERS on GitHub or GitLab Premium, or a protected branch), so a merge request can't exempt its own skill.

## Cost controls

- **Cache.** A complete scan is stored under the skill's content hash plus every setting that affects the result. A cache hit costs nothing and takes milliseconds. Failed or partial-failure scans are never cached. The policy is applied after the cache, so editing it needs no re-scan. Treat the cache directory like the installation itself: a writable cache is trusted.
- **Cap.** `SKILLGUARD_MAX_REVIEW_CALLS` (default 8) limits LLM review calls per skill. A larger skill is reported as not reviewed (REVIEW) instead of being sent anyway.
- **Free tier.** `--no-llm --no-triage` runs only the deterministic layers.

## Docker (air-gapped)

```bash
docker build -t skillguard .
docker run --rm --network none -v "$PWD:/work" -v skillguard-cache:/home/skillguard/.cache/skillguard \
  skillguard scan skills/ --no-llm --no-triage --sarif skillguard.sarif
```

The image runs as a non-root user and contains the pinned Cisco scanner, so the static layers work with no network access. For the LLM layers, build with `--build-arg EXTRAS=litellm` and point `SKILLGUARD_BASE_URL` at an internal model endpoint.

## Results so far

| Test set | Result |
|---|---|
| 19 real, harmless skills | 0 BLOCK, 3 REVIEW, 16 SAFE (the REVIEWs: an uninspected bundled `.tar.gz`, a real minor script-injection issue, and an invented user quote in `canvas-design`'s instructions) |
| Cost and tokens, all 27 skills (Luna only) | 879K in / 49K out tokens, $0.134 total, ~23 s per skill |
| 8 malicious samples ([snyk-labs/toxicskills-goof](https://github.com/snyk-labs/toxicskills-goof) + one test skill) | 8/8 BLOCK (Cisco offline alone: 2/7; SkillSpector static alone: 2/7) |

This is a small evaluation, and two rules were written after seeing these samples. A larger labeled test set is the next step (see DESIGN.md §11–13).

## Privacy

Layers 2 and 3 send skill content to the configured model provider. For private skills, use a local model (LiteLLM + Ollama, above) or `--no-llm --no-triage`. Reports escape all text taken from skills and model answers, so a report posted as a PR comment cannot carry injected links, images or HTML.
