# SkillGuard: design

A low-cost, pre-install security scanner for agent skills (Claude Code, Codex, Cursor and similar). It should catch most real security problems and explain each one clearly to the person deciding whether to install the skill.

Status: v1.2: v1.1 plus token accounting and single-model operation (D20); v1.1 = v1 plus fixes from an external code review (section 14). Evaluated on 19 benign skills + 8 malicious samples (section 13). Last updated 2026-09-29.

Usage:
```bash
export OPENROUTER_API_KEY=sk-or-...      # OpenRouter key
python3 -m skillguard scan <skill-dir> --md report.md --json report.json [--sarif out.sarif]
python3 -m skillguard eval --benign skills/skills --malicious <dir> --out skillguard-eval/run
```
Exit codes: 0 SAFE, 1 REVIEW, 2 BLOCK, 3 error (nothing scannable, no verdict). Flags: `--model`, `--no-llm`, `--no-triage`, `--no-cisco`. A scan with `--no-llm` or `--no-cisco` is partial and can return BLOCK or REVIEW, never SAFE.
Tests: `python3 -m unittest discover -s tests` (no network).

---

## 1. Goals and non-goals

**Goals**
- Catch most security issues that can be seen in a skill package before it is installed.
- Keep false positives low enough that people read the report instead of ignoring it.
- Give feedback a person can act on: a clear verdict, then for each finding what it is, where it is (`file:line`), why it matters and how to fix it.
- Keep the cost to cents or less per skill, so thousands of skills can be scanned.
- Map every finding to the [OWASP Agentic Skills Top 10](https://github.com/OWASP/www-project-agentic-skills-top-10) (AST01–AST10).

**Non-goals**
- Runtime or dynamic analysis. We never execute skill code.
- Checking things that depend on the environment rather than the package, such as sandboxing, governance or inventory (AST06, AST09 and most of AST10). The report lists these as *not assessed* instead of claiming coverage.
- Replacing human review of skills that are still flagged high-risk after all layers.

---

## 2. Background: what we evaluated

All numbers were measured on two skills:
- `skill-creator`: benign, 18 files, Python scripts plus HTML
- a small fake malicious skill: it claims to be a markdown formatter, collects environment variables and credential files, POSTs them to `collector.example.invalid`, and its `SKILL.md` tells the agent to hide this from the user.

| Tool / setup | Time | Cost / skill | Result on benign | Result on malicious | Notes |
|---|---|---|---|---|---|
| NVIDIA SkillSpector `--no-llm` | ~12 s | $0 | 9 findings, 4 HIGH, score 100 "DO NOT INSTALL" | 6 findings | **Missed the hidden instruction in SKILL.md.** Very noisy. |
| SkillSpector + free Nemotron | 4–8 min | $0 (free tier) | 26–45 findings | — | Results changed between runs; the LLM meta step **failed silently**. |
| SkillSpector + Sonnet 5.5 | 64 s | ~$1.11 | 10 findings, still 100/100 | — | The LLM marked static findings "unconfirmed", but they still drove the score. |
| Cisco skill-scanner (offline) | ~1 s | $0 | 2 findings, incl. 1 false CRITICAL | 4 findings | **Caught the prompt injection** and the credential→network flow. |
| Cisco + Sonnet 5.5 | 27 s | ~$0.25 | SAFE, 1 real LOW issue | — | Good verdict. The adjudicator's LLM call failed, but the failure was not visible. |
| Cisco + GPT-6 Luna | 20–50 s | ~$0.002–0.01 | LLM steps failed | LLM steps failed | Luna rejects Cisco's strict schema, and with plain JSON it returns fields Cisco does not expect. |
| Claude Code `/security-review` | — | higher | — | — | Reviews diffs and targets app-security bugs; not designed for skill threats. |
| Snyk agent-scan | — | — | — | — | Needs a Snyk account and sends skill content to Snyk's cloud. Not tested. |
| Scanner output + **Jev** filter | +0.3 s | ~$0.0001–0.0005 | 7 findings downgraded, 1 dropped | all threats kept (P(TP) 0.71–1.00) | Clean separation of real threats from noise. |

Lessons that shaped the design:
1. **Code patterns and instructions are separate problems.** A static scanner that only matches code patterns missed an attack written in plain language. OWASP AST08 (check 8.2) says the same: scan the code layer and the instruction layer independently.
2. **Existing tools are expensive mainly because of how they use the LLM.** SkillSpector made 72 calls and sent 516K tokens for one skill. One well-structured call per skill should be enough.
3. **Silent LLM failures are the biggest reliability risk.** Every tool we tried, in some configuration, reported a clean result after its LLM step had failed.
4. **Classifying existing findings is a different job from discovering new ones.** Jev (a typed-decision model) classifies scanner findings very cheaply, but it does not look for new issues.
5. **A cheap model works only if we control the answer format.** Luna failed because of Cisco's schema, not necessarily because of the model itself.

---

## 3. Architecture

```
skill folder / zip / git URL
  │
  ├─ Layer 1: Code layer (deterministic, free, ~1–2 s)
  │     a) Cisco skill-scanner, offline core + behavioral analyzers
  │     b) SkillGuard's own checks for the gaps (section 5)
  │
  ├─ Layer 2: Instruction layer (1 LLM call per skill)
  │     SKILL.md + referenced .md files + scripts, reviewed against an
  │     OWASP-derived questionnaire with our own JSON schema (section 6)
  │
  ├─ Layer 3: Triage (Jev, ~$0.0001)
  │     Each Layer 1 finding + source context → true_positive / benign_risk / false_positive
  │
  └─ Layer 4: Verdict + report
        ✅ SAFE / ⚠️ REVIEW / ⛔ BLOCK, findings grouped by AST category,
        "not assessed" section, Markdown + JSON (+ SARIF for CI)
```

### Why each layer exists

| Layer | Catches | Why not skip it |
|---|---|---|
| 1 Code | Known dangerous code: exfiltration, shell injection, credential reads, obfuscation, YARA signatures | Free, deterministic and fast, and it provides evidence with line numbers. |
| 2 Instructions | Hidden instructions, hiding actions from the user, description/behavior mismatch, runtime instruction fetching, new attacks | Pattern matching misses these (proven in our test). |
| 3 Triage | Nothing new; it removes noise | Without it, benign skills look critical and people stop reading reports. |
| 4 Report | — | The user asked for good feedback, so the report is part of the product, not an afterthought. |

---

## 4. Decisions and reasoning

| # | Decision | Reasoning | Alternatives considered |
|---|---|---|---|
| D1 | **Build our own orchestrator** and reuse Cisco for code detection | No single tool was both accurate and cheap. Cisco's offline engine is the best part of what exists; its LLM part isn't portable to cheap models. | Use SkillSpector or Cisco as-is (too noisy or too expensive); write all detection ourselves (reinventing YARA/dataflow). |
| D2 | **Cisco offline over SkillSpector for Layer 1** | Faster (~1 s vs ~12 s), far quieter, and it caught the prompt injection that SkillSpector missed. | SkillSpector `--no-llm` can be added later as an optional second engine if the evaluation shows recall gaps. |
| D3 | **One LLM call per skill, with our own schema** | Controls cost (~70× fewer calls than SkillSpector) and lets cheap models work. | Many calls per file or per analyzer (SkillSpector's approach, 516K tokens per skill). |
| D4 | **Model for Layer 2 chosen by evaluation**: GPT-6 Luna ($0.10/$0.50 per MTok) is the candidate, Sonnet 5.5 ($2/$10) the quality reference | Luna is 20× cheaper; its failure with Cisco was a format problem we avoid. | Free models: unreliable (5xx errors, 429s, wrong-format output). |
| D5 | **Jev for triage only** | Very cheap, fast, calibrated probabilities, and it passed the malicious-skill test. It classifies findings; it does not discover them. | LLM adjudication (Cisco's `--adjudicate`): costs more, and its LLM call failed in our runs. |
| D6 | **Fail closed, loudly** | Silent LLM failures were the most common problem. Any failed layer must show in the verdict (at least REVIEW) and in the report header. It must never quietly yield SAFE. | Treating a failure as "no findings" (what the evaluated tools effectively did). |
| D7 | **Verdict = three levels, not a 0–100 score** | SkillSpector's score saturated at 100 for a benign skill and carried no information. People need a decision: install, look closer, or don't install. | Numeric risk score. |
| D8 | **Map everything to OWASP AST01–AST10** | A shared vocabulary, and OWASP recommends mapping scanner output to it. It also shows which risks were checked and which were not. | Tool-specific rule IDs only. |
| D9 | **Report the risks we can't assess** (AST06, AST09, most of AST10) | Honest about the limits of scanning a package; avoids false confidence. | Omitting them. |
| D10 | **Never execute skill code** | Safety, so malicious samples can be scanned. OWASP's dynamic testing (1.5, 8.5) is left for a later sandboxed stage. | Dynamic analysis now: too costly and risky for v1. |
| D11 | **Build a test set before the scanner, and tune against it** | Without test data we cannot claim "catches most issues". OWASP ships no fixture corpus. | Tuning by inspection: that is how we'd end up with a noisy tool. |
| D12 | **Python, standard library + `uvx` for Cisco** | Matches the rest of the tooling and needs no heavy dependencies. `tools/jev_filter.py` is already stdlib-only. | — |
| D13 | *(added after evaluation)* **A single LLM finding can't BLOCK; the LLM blocks only through its overall `intent`** | In the first run, one over-rated finding (API fallback documentation in `claude-api`) caused a false BLOCK, even though the same review rated the intent "risky but legitimate". | Letting any verified HIGH LLM finding block. |
| D14 | *(added)* **Large skills are split into several LLM calls, with SKILL.md in each; pure data files (`.xsd`, `.xml`, `.css`, `.svg`, `.csv`, JSON > 100 KB) are checked by Layer 1 only** | 4 of 19 real skills were too large for one call. The Office skills are mostly XML schemas, which are data, not instructions. The files skipped are listed in the report. | Raising the budget (cost), or dropping files (silent gaps). |
| D15 | *(added)* **If the reviewer model's content filter refuses, re-review with a fallback model (GPT-6 Luna)** | Sonnet 5.5 via OpenRouter refused to review the malicious test skill (`finish_reason=content_filter`), because the request contains malicious code. The filter blocks exactly the skills that most need review. | Treating the refusal as a failure only (still safe through fail-closed, but it loses the explanation). |
| D16 | *(added)* **Default reviewer model = GPT-6 Luna** | Same results as Sonnet on this test set at ~1/18 of the cost, and no content-filter refusals. | Sonnet 5.5 as the default. |
| D17 | *(v1.1)* **Anything not inspected is a coverage gap → at least REVIEW**: symlinks (never followed), unknown binaries, bundled archives, text files > 2 MB, bundled `node_modules`/venv folders, missing `SKILL.md`. Known media (fonts, images, PDFs) are notes only. | The review found that such files were skipped while the scan reported success. A symlink could also pull files from outside the skill into the LLM prompt. | Silently skipping them (v1). |
| D18 | *(v1.1)* **A partial scan never returns SAFE; a missing path is an error (exit 3), not a verdict** | `--no-llm --no-cisco` used to return SAFE with only the regex checks run, and a nonexistent path was SAFE too. | Qualified SAFE. |
| D20 | *(v1.2)* **Triage uses the review model by default; Jev is optional** (`--triage-model`) | Jev is not available to everyone. A chat model gets the same question and answer shape (verdict + three probabilities), batched per skill, and goes through the same validation and decision code. On 54 static findings judged by both, Luna and Jev took the same action on 48; all 6 differences were "remove" vs "downgrade", never keep vs discard. Detection results were identical (8/8 BLOCK, 0/19 benign BLOCK). Triage cost for 27 skills: Luna $0.010, Jev $0.0035. | Jev only (v1); a separate cheap model per layer. |
| D19 | *(v1.1)* **Validate every external output strictly**: Cisco (exit code, report shape, severities), Jev (choice, all three probabilities finite and summing to ~1), LLM (finish reason, all required fields, the full evidence quote at the cited line) | Malformed or truncated answers were accepted and could downgrade real findings or produce SAFE. | Best-effort parsing (v1). |

---

## 5. Layer 1: own checks (gaps not covered by Cisco)

Derived from the OWASP checklist (numbers refer to `checklist.md` items).

| Check | AST | Checklist ref | Method |
|---|---|---|---|
| Hidden Unicode (zero-width, bidi overrides, tag characters / ASCII smuggling) | AST04 | 4.2 | Scan every text file for code points in the relevant Unicode ranges; show the decoded hidden text. |
| Encoded payloads (long base64/hex blobs, especially near exec/eval/decode) | AST01/04 | 1.4, 4.2 | Regex + decode attempt + entropy check. |
| Credential store access (`~/.ssh`, `~/.aws`, `.env`, `*credentials*`, wallets, browser data) in code **or instructions** | AST03 | 3.8 | Path patterns in all files, including markdown. |
| Writes to agent identity/memory files (`MEMORY.md`, `AGENTS.md`, `CLAUDE.md`, `SOUL.md`, `.claude/`) | AST01/03 | 1.6, 3.6 | Path + write-verb patterns in code and instructions. |
| Runtime external instruction sources (URLs fetched and followed at runtime) | AST05 | 5.1–5.4 | URL inventory, classified as documentation link vs runtime fetch-and-follow. Layer 2 confirms intent. |
| Unpinned dependencies, install-time scripts (`postinstall`, `setup.py` hooks), version ranges | AST02/07 | 2.2, 2.3, 7.1 | Parse `requirements*.txt`, `package.json`, `pyproject.toml`. |
| Repo config that runs code automatically (hooks, `.claude/settings.json`, `.mcp.json`, env overrides) | AST02 | 2.5 | File presence + content check. |
| Unsafe deserialization (`yaml.load` without SafeLoader, `!!python/` tags, `pickle`) | AST04 | 4.7 | Regex/AST. |
| Hardcoded secrets | AST08 | 8.3 | Key-format regexes; optionally gitleaks if installed. |
| Brand impersonation in name/description | AST04 | 4.6 | Small list of well-known brands; Layer 2 confirms. |
| *(added)* Fake-prerequisite installers: password-protected archive downloads, commands from paste sites, "download and run this binary" | AST01/02 | 1.4 | Line patterns in `.md`/`.txt`. A password-protected download is a precise check (CRITICAL), since it is the ClawHavoc delivery method. |
| *(added)* Instructions that send local data out: `curl`/`wget`/`iwr` with `-d`/`-F`/`--upload-file` whose payload is command output `$(…)`, a file `@…`, or an env var | AST01 | 1.4 | Precise (CRITICAL) when the target is a paste/webhook site, otherwise HIGH and triaged. Legit API docs send static JSON and don't match. |
| Frontmatter sanity (name/description present, no undeclared fields, `allowed-tools` declared vs used) | AST03/04 | 3.1, 4.4 | YAML safe parse. |

---

## 6. Layer 2: instruction-layer review

**Input** (within the model's context budget; a size limit must never silently drop `SKILL.md`, which was a Cisco default we found):
- `SKILL.md` in full, plus referenced `.md`/prompt files
- scripts in full, or trimmed to the lines around Layer 1 hits if too large
- the list of Layer 1 findings, as hints, never as conclusions

**Questions** (each answer must cite `file:line` evidence, or say "none"):
1. Declared purpose (from frontmatter) vs actual capabilities: list any mismatch. (AST04 4.1)
2. Hidden or deceptive instructions: hiding actions from the user, overriding prior instructions or safety rules, acting without consent. (AST01)
3. Data leaving the machine: what data, to where, and whether it is disclosed. (AST01/03)
4. Access beyond the stated purpose: credentials, agent config, memory files, broad filesystem, shell. (AST03)
5. External instruction sources fetched and followed at runtime. (AST05)
6. Persistence or self-modification: memory/identity files, startup, cron, hooks. (AST01/02)
7. Overall intent: `benign` / `risky-but-legitimate` / `suspicious` / `malicious`, with a one-paragraph rationale written for the user.

**Output**: strict JSON with our own schema, validated on receipt. On invalid JSON: retry once, then mark the layer *failed* (D6).

---

## 7. Verdict rules

| Verdict | When |
|---|---|
| ⛔ BLOCK | Layer 2 intent = `malicious` **or** a Layer 1 HIGH/CRITICAL in AST01/03 confirmed independently of the LLM review (precise check, or Jev P(TP) ≥ 0.5). A Layer 2 finding on its own never blocks (D13). |
| ⚠️ REVIEW | Any remaining HIGH, or Layer 2 intent = `suspicious`, **or any layer failed**, **or a coverage layer (checks, Cisco, LLM review) was skipped**, **or any coverage gap** (see D17) |
| ✅ SAFE | Only for a complete scan with none of the above. LOW/INFO findings are still listed as notes. Skipping triage alone does not prevent SAFE, since triage only removes noise. |

The thresholds are starting values, to be tuned on the test set (section 9).

---

## 8. Report format (what the user sees)

1. **Header**: verdict, one-sentence reason, skill name, scan date, layers run and their status (✅ ran / ❌ failed), cost and time.
2. **Summary written for a person**: the Layer 2 rationale.
3. **Findings grouped by AST category**, most severe first. For each: title, severity, `file:line`, evidence snippet, *why it matters* (in plain words), *how to fix*, and the triage verdict with its probability.
4. **Downgraded / removed findings**: collapsed, so nothing is hidden.
5. **Not assessed**: AST06, AST09 and AST10, with a note on what a person should check instead.
6. Machine outputs: JSON, and SARIF for GitHub Code Scanning.

---

## 9. Evaluation plan

**Test set**:
- benign: the 19 real skills in `skills/skills/`
- malicious: a public labeled test set chosen and downloaded by the user (e.g. Snyk `toxicskills-goof` samples, or Cisco's benchmark corpus), read-only and never executed. We decided not to write our own malicious test skills; v1 was checked with a single malicious test skill created earlier.

**Metrics**: recall on malicious (target ≥ 90% for BLOCK/REVIEW), false-BLOCK rate on benign (target 0%), REVIEW rate on benign (as low as possible), cost and time per skill, and the number of layer failures.

**Model comparison**: run Layer 2 with Luna and with Sonnet on the same test set. Choose Luna if its recall matches Sonnet's.

---

## 10. Cost estimate

| Component | Per skill | 1,000 skills |
|---|---|---|
| Layer 1 (Cisco offline + own checks) | $0, ~1–2 s | $0 |
| Layer 2, GPT-6 Luna (est. 20–110K tokens in) | ~$0.003–0.012 | ~$3–12 |
| Layer 2, Sonnet 5.5 (reference) | ~$0.05–0.25 | ~$50–250 |
| Layer 3, Jev | ~$0.0001–0.0005 | ~$0.1–0.5 |

For comparison: SkillSpector + Sonnet ~$1.11 per skill, and Cisco + Sonnet ~$0.25 per skill.

---

## 11. Risks and open questions

- **Jev is early-access** from a small vendor, and we have run it on only two skills. Its probabilities shifted slightly between runs (0.77 → 0.71). Mitigation: fail-closed thresholds, and a Sonnet fallback if it underperforms.
- **Privacy**: Layers 2 and 3 send skill content to OpenRouter, OpenAI and TypeSafe. Private skills may need a "local only" mode (Layer 1 only, or a local model).
- **Prompt injection against the scanner itself**: a malicious skill can try to talk the Layer 2 model into saying "benign". Mitigation: skill content is clearly delimited as untrusted data, Layer 1 evidence is independent of the LLM, and a Layer 2 "benign" verdict never overrides a confirmed Layer 1 HIGH finding.
- **Cisco dependency**: its output format could change. Pin the version and keep a thin adapter (as in `tools/jev_filter.py`).
- **Large skills**: may exceed a single LLM call; this needs a chunking rule that never silently drops files.
- **Known scanner bug**: SkillSpector's `static_parse_limit` treats JavaScript template literals in HTML as shell code (AE1 false positive). This is only relevant if SkillSpector is added as a second engine.

---

## 12. Build order

1. Test set (`fixtures/`) + evaluation harness
2. Layer 1: Cisco adapter + own checks
3. Layer 3: move `tools/jev_filter.py` in as a module
4. Layer 2: prompt, schema, validation, retry and fail-closed handling
5. Layer 4: verdict + Markdown/JSON/SARIF report
6. Tuning pass against the test set; Luna vs Sonnet comparison

## 13. Evaluation results (v1, 2026-09-29)

### Benign set: 19 real skills (`skills/skills/`) + 1 malicious test skill

Still small: 8 real malicious samples (below) are not enough for a reliable recall figure. Cisco's larger benchmark corpus is the next step.

| Run | Malicious caught | Benign BLOCK | Benign REVIEW | Failed layers | Cost (20 skills) | Mean time |
|---|---|---|---|---|---|---|
| Luna, first version | 1/1 (BLOCK) | **1/19** | 5/19 | 4 | $0.11 | 16.9 s |
| Luna, after D13–D14 + prompt calibration | 1/1 (BLOCK) | **0/19** | 1/19 | 0 | $0.12 | 16.6 s |
| Sonnet 5.5, same version | 1/1 (BLOCK) | 0/19 | 0/19* | 1** | $2.47 | 9–100 s |

\* After re-running the 2 skills that failed on OpenRouter's in-flight credit limit (HTTP 402, now retried automatically).
\** The malicious skill: Sonnet's content filter refused the review (led to D15). The verdict was still BLOCK, through the confirmed Layer 1 findings.

### ToxicSkills (snyk-labs/toxicskills-goof, real malicious samples)

Malicious (8): 2× fake Vercel skills (send host info or `.env` data to a paste site via instructions), `testing-guidelines` (ASCII-smuggled hidden instructions), 4 ClawHavoc samples (`google`, 2× `clawhub`, `refs/clawhub1-1.0.5`: a fake "prerequisite" password-protected download or paste-site command), + our own malicious test skill.

| Scanner | Caught (BLOCK or REVIEW) | Notes |
|---|---|---|
| Cisco skill-scanner offline | 2/7 | Other 5 reported only INFO. |
| SkillSpector `--no-llm` | 2/7 at HIGH | `google` scored 0/100 LOW; both Vercel exfil samples LOW. |
| SkillGuard v1 (as first built) | 8/8 (BLOCK 4, then 7) | ClawHavoc samples reached only REVIEW: the LLM called them "suspicious", and no static rule fired. |
| **SkillGuard + installer and data-sending checks** | **8/8, all BLOCK** | $0.033 for 13 skills. The two new rules fire on 0 of 19 benign skills. |

Unlabeled samples in the repo: `skill-defender` ×2 and `demos/skill-with-commands` → SAFE. `snyk-skill` → BLOCK: a prompt hook saves all env variables to a file, plus a `curl | bash` line. `skillguard-1.0.1` → BLOCK: it ships malicious test fixtures, and the LLM found a real command injection in its `clawhub.js`. Whether shipping inert attack fixtures should BLOCK or only REVIEW is an open policy question.

Main lesson: **real attacks here live in the instructions, not the code.** Static code scanners missed 5 of 7. The LLM review found all of them, but it can under-rate severity ("suspicious" rather than "malicious"), so cheap deterministic rules for known delivery patterns are what turn REVIEW into BLOCK.

### What the LLM review found in benign skills that static tools did not
- `docx`/`xlsx`/`pptx` `scripts/office/soffice.py`: reuses a shared library from a predictable `/tmp` path if the file already exists, so another local user could plant code there. Real, local-only; reported as MEDIUM/LOW.
- `skill-creator` eval viewer: evaluation output is embedded into a `<script>` tag with `json.dumps`, so `</script>` in the output can inject HTML/JS into the local review page. Real, minor.
- `canvas-design`: the instructions invent a prior user quote (*"The user ALREADY said…"*). It's a manipulation pattern used for quality rather than harm; it is the one remaining benign REVIEW.

Other observations:
- The same issue can get a different severity between runs (soffice: MEDIUM in `docx`, LOW in `xlsx`). Borderline severities should not be relied on alone.
- Jev triage lowered the Cisco CRITICAL false positive (`lsof` list arguments) correctly on every run.
- Size: `claude-api` (1.4 MB) cost $0.06 with Luna and $1.32 with Sonnet. Luna costs $0.0003–0.06 per skill, typically ~$0.005.

## 14. Code review fixes (v1.1)

An external review found 14 bugs. All are fixed and covered by regression tests (`tests/test_skillguard.py`, 39 tests, no network):

| # | Issue | Fix |
|---|---|---|
| 1 | Loader followed symlinks outside the skill, leaking files into the LLM prompt | `os.walk` without following links; symlinks and out-of-root files become coverage gaps |
| 2 | Missing path or missing `SKILL.md` could be SAFE | Missing path → error, exit 3; missing manifest → coverage gap |
| 3 | Oversized/binary files were skipped while the scan reported success | Coverage gaps (D17) |
| 4 | Disabled layers disappeared and still allowed SAFE | Recorded as skipped; partial scans can't be SAFE (D18) |
| 5 | Cisco adapter accepted failed or malformed reports | Exit code, shape and severity validation (D19) |
| 6 | Jev answer without probabilities downgraded HIGH findings | `validate_answer`; invalid answers keep the severity and fail the layer |
| 7 | Any ZIP + "password" on a line was a precise CRITICAL | Also requires download context (a URL or "download") |
| 8 | Caps silently stopped checks (5/3/5 per file) and triage (80) | Caps removed; triage limit 1000 with overflow reported as a failure |
| 9 | Upload rule missed `-T file`, `--upload-file`, `--json @file` | Rewritten: file-upload flags always count; data flags count when the payload is local |
| 10 | Oversized SKILL.md bypassed the prompt budget | Files (SKILL.md included) are split into line-range parts; budget includes the system message |
| 11 | Truncated but valid JSON answers were accepted | Finish reason must be a normal stop; all review fields validated |
| 12 | Evidence checked only by its first 120 characters, anywhere in the file | Full quote within ±3 lines of the cited line |
| 13 | Chunk merge could pair a malicious verdict with a benign behavior text | Behavior and summary come from the worst chunk |
| 14 | Upload regex was quadratic on hostile long lines | Each command is examined once within a 600-character bound |

Also: credential regex covers `.env.local`, `~/.aws` and `credentials.json`; base64 check requires entropy ≥ 4 bits/char; `tools/jev_filter.py` now uses the same Jev validation and decision code as SkillGuard; an unknown verdict renders instead of crashing; transient HTTP 52x errors are retried.

Regression after the fixes (Luna): malicious 8/8 BLOCK; benign 0/19 BLOCK, 3/19 REVIEW. The REVIEWs: `web-artifacts-builder` ships a `.tar.gz` of source code that it extracts into the user's project and that nobody inspects (a correct new coverage gap; inspecting archives is a possible follow-up); `claude-api` hit a transient HTTP 520 in triage (now retried); `skill-creator`'s real script-injection issue was rated HIGH this run instead of MEDIUM (LLM variance).

## References

- OWASP Agentic Skills Top 10: https://github.com/OWASP/www-project-agentic-skills-top-10 (`checklist.md`, `ast01.md`–`ast10.md`, `skill-scanner-integration.md`)
- Cisco skill-scanner: https://github.com/cisco-ai-defense/skill-scanner
- NVIDIA SkillSpector: https://github.com/nvidia/skillspector
- TypeSafe Jev: https://typesafe.ai/blog/introducing-system-one-models-and-jev
- Snyk ToxicSkills research: https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/
