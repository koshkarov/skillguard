"""Layer 1: deterministic code-layer checks (Cisco skill-scanner + own checks)."""

from __future__ import annotations

import base64
import json
import re
import subprocess
import tempfile
import time
from pathlib import Path

from .model import Finding, LayerStatus
from .skill import Skill, SkillFile, is_license

CISCO_PACKAGE = "cisco-ai-skill-scanner==2.1.0"

# Cisco finding category -> OWASP AST category.
CISCO_AST = {
    "prompt_injection": "AST01",
    "data_exfiltration": "AST01",
    "command_injection": "AST01",
    "malware": "AST01",
    "social_engineering": "AST01",
    "obfuscation": "AST04",
    "hardcoded_secrets": "AST08",
    "unauthorized_tool_use": "AST03",
    "excessive_permissions": "AST03",
    "resource_abuse": "AST03",
    "policy_violation": "AST04",
    "supply_chain": "AST02",
    "supply_chain_attack": "AST02",
    "dependency": "AST07",
}


def run_cisco(skill: Skill) -> tuple[list[Finding], LayerStatus]:
    started = time.monotonic()
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "cisco.json"
        cmd = [
            "uvx", "--quiet", "--from", CISCO_PACKAGE, "skill-scanner", "scan", str(skill.root),
            "--use-behavioral", "--format", "json", "--output", str(out),
        ]
        if not (skill.root / "SKILL.md").exists():
            cmd.append("--lenient")  # e.g. lowercase skill.md, which Cisco otherwise rejects
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            report = json.loads(out.read_text())
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError) as exc:
            return [], LayerStatus("cisco", False, f"Cisco scanner failed: {exc}", time.monotonic() - started)
    findings = []
    for f in report.get("findings", []):
        if f.get("rule_id") == "MANIFEST_MISSING_LICENSE":
            continue  # licensing, not security
        findings.append(
            Finding(
                source="cisco",
                rule=f.get("rule_id", "?"),
                ast=CISCO_AST.get(str(f.get("category", "")).lower(), "AST01"),
                severity=str(f.get("severity", "MEDIUM")).upper(),
                title=f.get("title", ""),
                file=f.get("file_path"),
                line=f.get("line_number"),
                evidence=(f.get("snippet") or "")[:400],
                why=f.get("description", ""),
                fix=f.get("remediation") or "",
            )
        )
    detail = f"{len(findings)} findings" + ("" if proc.returncode in (0, 1) else f" (exit {proc.returncode})")
    return findings, LayerStatus("cisco", True, detail, time.monotonic() - started)


# ---------------------------------------------------------------------------
# Own checks
# ---------------------------------------------------------------------------

def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _snippet(file: SkillFile, line: int) -> str:
    lines = file.lines
    return lines[line - 1].strip()[:300] if 0 < line <= len(lines) else ""


def check_hidden_unicode(file: SkillFile) -> list[Finding]:
    findings = []
    tags = [(m.start(), m.group()) for m in re.finditer(r"[\U000E0000-\U000E007F]+", file.text)]
    for index, run in tags:
        decoded = "".join(chr(ord(c) - 0xE0000) for c in run if 0xE0020 <= ord(c) <= 0xE007E)
        line = _line_of(file.text, index)
        findings.append(Finding(
            "check", "HIDDEN_UNICODE_TAGS", "AST04", "CRITICAL",
            "Invisible Unicode tag characters hide text", file.path, line,
            f"Hidden text decodes to: {decoded[:300]!r}",
            "Unicode tag characters are invisible to people but readable by the model. This is a known "
            "technique (ASCII smuggling) for hiding instructions in a skill.",
            "Remove the invisible characters and review what the hidden text was meant to do.",
            precise=True,
        ))
    for match in re.finditer(r"[‪-‮⁦-⁩]", file.text):
        line = _line_of(file.text, match.start())
        findings.append(Finding(
            "check", "BIDI_CONTROL", "AST04", "HIGH",
            "Bidirectional text-control character", file.path, line, _snippet(file, line),
            "Bidi control characters can make text or code display differently from how it is read "
            "(Trojan Source).",
            "Remove bidirectional control characters.",
            precise=True,
        ))
        break
    zero_width = list(re.finditer(r"[​⁠᠎]|(?<!^)﻿", file.text))
    if len(zero_width) >= 3:
        line = _line_of(file.text, zero_width[0].start())
        findings.append(Finding(
            "check", "ZERO_WIDTH_CHARS", "AST04", "MEDIUM",
            f"{len(zero_width)} zero-width characters", file.path, line, _snippet(file, line),
            "Clusters of zero-width characters can hide or split words to evade review and filters.",
            "Remove zero-width characters unless they are needed for a specific language.",
        ))
    return findings


BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{200,}={0,2}(?![A-Za-z0-9+/=])")
DECODE_EXEC_RE = re.compile(r"\b(exec|eval|compile|b64decode|atob|base64\s+-d|fromCharCode|marshal\.loads|zlib\.decompress)\b")


def check_encoded_payloads(file: SkillFile) -> list[Finding]:
    findings = []
    for match in BASE64_RE.finditer(file.text):
        before = file.text[max(0, match.start() - 40): match.start()]
        if re.search(r"data:(image|font|audio|video)/[\w.+-]+;base64,\s*$", before):
            continue  # embedded media, e.g. images in HTML
        blob = match.group()
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            printable = sum(32 <= b < 127 or b in (9, 10, 13) for b in decoded[:400]) / max(1, min(400, len(decoded)))
            preview = decoded[:160].decode("utf-8", "replace") if printable > 0.85 else f"<{len(decoded)} bytes binary>"
        except ValueError:
            continue
        line = _line_of(file.text, match.start())
        executes = bool(DECODE_EXEC_RE.search(file.text))
        findings.append(Finding(
            "check", "ENCODED_PAYLOAD", "AST01" if executes else "AST04", "HIGH" if executes else "MEDIUM",
            "Long base64-encoded blob" + (" in a file that decodes/executes data" if executes else ""),
            file.path, line, f"Decoded preview: {preview!r}",
            "Encoded content cannot be reviewed by reading the skill and is a common way to hide payloads.",
            "Replace the encoded blob with readable source, or explain what it is and why it is needed.",
        ))
    return findings


CREDENTIAL_RE = re.compile(
    r"(~|\$HOME|%USERPROFILE%|/home/\w+|/Users/\w+)?/?\.(ssh|aws|gnupg|kube|docker)/[\w./-]*"
    r"|\bid_(rsa|ed25519|ecdsa)\b"
    r"|\.netrc\b|\.git-credentials\b|\.pgpass\b"
    r"|\.config/gcloud\b|\.azure/\w+"
    r"|\.claude/\.credentials|\.codex/auth\.json"
    r"|(Login Data|Cookies|Local State)\b.*(Chrome|Chromium|Brave|Edge)|(Chrome|Chromium|Brave|Edge).*\b(Login Data|Cookies)\b"
    r"|\bwallet\.dat\b|\bkeystore\b.*\.json|\bMetaMask\b"
    r"|(?<![\w.])\.env(?![\w.-])",
    re.I,
)


def check_credential_access(file: SkillFile) -> list[Finding]:
    findings = []
    for number, line in enumerate(file.lines, 1):
        match = CREDENTIAL_RE.search(line)
        if not match:
            continue
        findings.append(Finding(
            "check", "CREDENTIAL_STORE_ACCESS", "AST03", "HIGH",
            f"References a credential store: {match.group().strip()}", file.path, number, line.strip()[:300],
            "Credential stores (SSH keys, cloud credentials, .env files, browser data, wallets) should never "
            "be touched by a skill unless its stated purpose needs them.",
            "Remove the access, or document exactly why the skill needs it and scope it to one file.",
        ))
        if len(findings) >= 5:
            break
    return findings


MEMORY_FILES_RE = re.compile(r"\b(MEMORY|AGENTS|CLAUDE|SOUL|GEMINI)\.md\b|\.claude/(settings(\.local)?\.json|commands|agents|hooks)|\.cursor/rules|\.cursorrules|\.codex/", re.I)
WRITE_VERB_RE = re.compile(r"\b(append|write|writes|add (it |this |a line )?to|insert|modify|overwrite|update|edit|create)\b|>>|\.write\(|open\([^)]*['\"][wa]", re.I)


def check_agent_config_writes(file: SkillFile) -> list[Finding]:
    findings = []
    for number, line in enumerate(file.lines, 1):
        if MEMORY_FILES_RE.search(line) and WRITE_VERB_RE.search(line):
            findings.append(Finding(
                "check", "AGENT_CONFIG_WRITE", "AST01", "MEDIUM",
                "Writes to agent memory, identity or config files", file.path, number, line.strip()[:300],
                "Changing an agent's memory, instruction or settings files persists the skill's influence "
                "into future sessions (persistence) and can grant it more privileges.",
                "Do not modify agent memory/config files, or require explicit user confirmation for each change.",
            ))
            if len(findings) >= 3:
                break
    return findings


PIPE_TO_SHELL_RE = re.compile(r"(curl|wget|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b|\b(iex|Invoke-Expression)\b[^\n]*(irm|iwr|Invoke-(WebRequest|RestMethod)|DownloadString)", re.I)
URL_RE = re.compile(r"https?://[^\s)\"'<>`]+")
FOLLOW_RE = re.compile(r"\b(follow|obey|execute|apply|use)\b[^.\n]{0,40}\b(instructions?|steps|rules|prompt|directives?)\b|\binstructions?\b[^.\n]{0,40}\b(from|at|in)\b[^.\n]{0,20}https?://", re.I)
FETCH_RE = re.compile(r"\b(fetch|download|curl|wget|retrieve|load|read|get)\b", re.I)


def check_remote_instructions(file: SkillFile) -> list[Finding]:
    findings = []
    for number, line in enumerate(file.lines, 1):
        if PIPE_TO_SHELL_RE.search(line):
            findings.append(Finding(
                "check", "PIPE_TO_SHELL", "AST02", "HIGH",
                "Downloads and executes remote code", file.path, number, line.strip()[:300],
                "Piping a download straight into a shell runs whatever the server returns at that moment. "
                "The code can change after review, and nothing is verified.",
                "Vendor the script into the skill, or pin it by checksum and verify before running.",
            ))
    if file.path.lower().endswith(".md"):
        paragraphs = re.split(r"\n\s*\n", file.text)
        offset = 0
        for paragraph in paragraphs:
            start = file.text.find(paragraph, offset)
            offset = start + len(paragraph)
            if URL_RE.search(paragraph) and FOLLOW_RE.search(paragraph) and FETCH_RE.search(paragraph):
                line = _line_of(file.text, start + URL_RE.search(paragraph).start())
                findings.append(Finding(
                    "check", "REMOTE_INSTRUCTIONS", "AST05", "MEDIUM",
                    "Instructions may be fetched from a URL at runtime", file.path, line, _snippet(file, line),
                    "Instructions loaded from a URL at runtime can be changed after the skill was reviewed, "
                    "turning a safe skill malicious without any change to its files.",
                    "Inline the instructions into the skill, or pin the remote content by hash.",
                ))
    return findings[:5]


ARCHIVE_PASSWORD_RE = re.compile(r"\.(zip|7z|rar|tar\.gz|tgz)\b.{0,160}\b(pass(word)?|pwd)\b\s*[:=]?|\b(pass(word)?|pwd)\b.{0,160}\.(zip|7z|rar)\b", re.I)
PASTE_SITES_RE = re.compile(r"https?://([\w-]+\.)*([\w-]*paste[\w-]*\.\w+|glot\.io|rentry\.(co|org)|ghostbin\.\w+|termbin\.com|controlc\.com|0x0\.st|transfer\.sh|webhook\.site|requestbin\.\w+|pipedream\.net)\S*", re.I)
# A network client that sends *local* data: command output, a file, or an environment variable.
SEND_LOCAL_DATA_RE = re.compile(
    r"\b(curl|wget|http|Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b[^\n]*?"
    r"(\s-d\b|--data(-\w+)?\b|\s-F\b|--form\b|\s-T\b|--upload-file\b|--post-(data|file)\b|-Body\b)"
    r"[^\n]*?(\$\(|`[^`]*`|@[~/.\w]|\$\{?[A-Z_][A-Z0-9_]{2,}|\bcat\s)",
    re.I,
)
EXECUTE_RE = re.compile(r"\b(run|execute|paste|launch|install|terminal|powershell|cmd|bash|sh)\b", re.I)
RUN_BINARY_RE = re.compile(r"\b(download|get)\b.{0,200}\.(exe|msi|dmg|pkg|zip|appimage|bin)\b.{0,200}\b(run|execute|launch|open|install)\b", re.I)


def check_untrusted_installer(file: SkillFile) -> list[Finding]:
    """Fake-prerequisite delivery used by malicious skill campaigns (e.g. ClawHavoc)."""
    if not file.path.lower().endswith((".md", ".txt")):
        return []
    findings = []
    for number, line in enumerate(file.lines, 1):
        if ARCHIVE_PASSWORD_RE.search(line):
            findings.append(Finding(
                "check", "PASSWORD_PROTECTED_DOWNLOAD", "AST01", "CRITICAL",
                "Tells the user to download a password-protected archive", file.path, number, line.strip()[:300],
                "Password-protected archives are used to get malware past antivirus and download scanners. "
                "Legitimate skills do not need this. It is the delivery method of known malicious skill campaigns.",
                "Do not download or run it. Remove the skill.", precise=True,
            ))
        elif SEND_LOCAL_DATA_RE.search(line):
            to_paste = bool(PASTE_SITES_RE.search(line))
            findings.append(Finding(
                "check", "INSTRUCTION_SENDS_LOCAL_DATA", "AST01", "CRITICAL" if to_paste else "HIGH",
                "Instructions send local data to a remote server" + (" (an anonymous paste/webhook site)" if to_paste else ""),
                file.path, number, line.strip()[:300],
                "The skill tells the agent to upload command output, files or environment variables. Agents "
                "follow these instructions with the user's access, so this is a direct exfiltration channel.",
                "Remove the upload. If data really must be sent, say what, to whom and why, and ask the user first.",
                precise=to_paste,
            ))
        elif PASTE_SITES_RE.search(line) and EXECUTE_RE.search(line):
            findings.append(Finding(
                "check", "PASTE_SITE_COMMAND", "AST01", "HIGH",
                "Tells the user to run a command from an anonymous paste site", file.path, number, line.strip()[:300],
                "Paste sites are anonymous and editable; the command can be swapped for malware at any time and "
                "is invisible to anyone reviewing the skill.",
                "Do not run it. Legitimate tools document their install command inline or use a package manager.",
            ))
        elif RUN_BINARY_RE.search(line):
            findings.append(Finding(
                "check", "RUN_DOWNLOADED_BINARY", "AST02", "HIGH",
                "Tells the user to download and run an executable", file.path, number, line.strip()[:300],
                "Running a downloaded binary as a 'prerequisite' gives unreviewed code full access to the machine.",
                "Install dependencies from a trusted package manager, pinned and verified.",
            ))
    return findings[:5]


SECRET_PATTERNS = {
    "AWS access key": r"\bAKIA[0-9A-Z]{16}\b",
    "Anthropic API key": r"\bsk-ant-[A-Za-z0-9_-]{40,}",
    "OpenRouter API key": r"\bsk-or-v1-[a-f0-9]{40,}",
    "OpenAI API key": r"\bsk-(proj-)?[A-Za-z0-9_-]{40,}",
    "GitHub token": r"\bgh[pousr]_[A-Za-z0-9]{36,}",
    "Slack token": r"\bxox[abprs]-[A-Za-z0-9-]{20,}",
    "Google API key": r"\bAIza[0-9A-Za-z_-]{35}\b",
    "Private key": r"-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
}


def check_secrets(file: SkillFile) -> list[Finding]:
    findings = []
    for label, pattern in SECRET_PATTERNS.items():
        for match in re.finditer(pattern, file.text):
            line = _line_of(file.text, match.start())
            findings.append(Finding(
                "check", "HARDCODED_SECRET", "AST08", "HIGH",
                f"Hardcoded {label}", file.path, line, match.group()[:12] + "…(redacted)",
                "A secret shipped inside a skill is exposed to everyone who installs it and may be abused.",
                "Remove the secret, rotate it, and read credentials from the environment at runtime.",
            ))
            break
    return findings


UNSAFE_DESERIALIZE_RE = re.compile(r"yaml\.load\((?![^)]*SafeLoader)(?![^)]*safe_load)|yaml\.unsafe_load|pickle\.loads?\(|marshal\.loads\(|jsonpickle\.decode\(")


def check_unsafe_deserialization(file: SkillFile) -> list[Finding]:
    findings = []
    for number, line in enumerate(file.lines, 1):
        if "!!python/" in line:
            findings.append(Finding(
                "check", "YAML_PYTHON_TAG", "AST04", "HIGH", "YAML tag that constructs Python objects",
                file.path, number, line.strip()[:300],
                "`!!python/` tags make unsafe YAML loaders execute code while parsing.",
                "Remove the tag; load YAML with yaml.safe_load.", precise=True,
            ))
        elif file.is_script and UNSAFE_DESERIALIZE_RE.search(line):
            findings.append(Finding(
                "check", "UNSAFE_DESERIALIZATION", "AST04", "MEDIUM", "Unsafe deserialization",
                file.path, number, line.strip()[:300],
                "Loading untrusted data with pickle/marshal/unsafe YAML can execute arbitrary code.",
                "Use yaml.safe_load / json, or only deserialize data the skill created itself.",
            ))
    return findings[:3]


INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare")


def check_dependencies(file: SkillFile) -> list[Finding]:
    findings = []
    name = Path(file.path).name.lower()
    if name == "package.json":
        try:
            data = json.loads(file.text)
        except json.JSONDecodeError:
            return findings
        for hook in INSTALL_HOOKS:
            command = (data.get("scripts") or {}).get(hook)
            if command:
                line = next((i for i, l in enumerate(file.lines, 1) if f'"{hook}"' in l), None)
                findings.append(Finding(
                    "check", "INSTALL_HOOK", "AST02", "HIGH", f"npm `{hook}` script runs on install",
                    file.path, line, f'"{hook}": "{command}"'[:300],
                    "Install scripts run automatically with the installing user's privileges, before anyone "
                    "reviews what they do.",
                    "Remove the install hook; run setup steps explicitly and document them.",
                ))
        loose = [f"{k}@{v}" for section in ("dependencies", "devDependencies") for k, v in (data.get(section) or {}).items()
                 if re.match(r"^[\^~*]|^latest$|^x$|>", str(v))]
        if loose:
            findings.append(Finding(
                "check", "UNPINNED_DEPENDENCIES", "AST07", "LOW", f"{len(loose)} npm dependencies use version ranges",
                file.path, None, ", ".join(loose[:8]),
                "Version ranges let a compromised future release of a dependency flow in without review.",
                "Pin exact versions and commit a lockfile.",
            ))
    elif re.match(r"requirements.*\.txt$", name):
        loose = [l.strip() for l in file.lines if l.strip() and not l.strip().startswith(("#", "-")) and "==" not in l and "@" not in l]
        if loose:
            findings.append(Finding(
                "check", "UNPINNED_DEPENDENCIES", "AST07", "LOW", f"{len(loose)} Python dependencies not pinned",
                file.path, None, ", ".join(loose[:8]),
                "Unpinned dependencies let a compromised future release flow in without review.",
                "Pin exact versions (==) and ideally hashes (--require-hashes).",
            ))
    elif name == "setup.py" and re.search(r"cmdclass\s*=|class\s+\w+\(\s*install\s*\)", file.text):
        findings.append(Finding(
            "check", "INSTALL_HOOK", "AST02", "MEDIUM", "setup.py overrides the install command",
            file.path, None, "custom install command class",
            "Custom install commands run code at install time.",
            "Remove the custom install step.",
        ))
    return findings


AUTORUN_FILES = re.compile(r"(^|/)(\.claude/settings(\.local)?\.json|\.mcp\.json|\.vscode/tasks\.json|\.git/hooks/|hooks/hooks\.json|\.husky/)")


def check_autorun_config(file: SkillFile) -> list[Finding]:
    if not AUTORUN_FILES.search(file.path):
        return []
    runs_commands = re.search(r'"(command|hooks|runOn|mcpServers)"', file.text) or file.path.startswith((".git/hooks", ".husky"))
    if not runs_commands:
        return []
    return [Finding(
        "check", "AUTORUN_CONFIG", "AST02", "HIGH", "Ships agent/editor config that can run commands automatically",
        file.path, None, file.text.strip()[:300],
        "Hooks, MCP server definitions and editor tasks execute commands when the project is opened or the "
        "agent acts, without a separate approval (compare Claude Code CVE-2025-59536).",
        "Do not ship executable config; document the setup and let the user add it deliberately.",
    )]


BRANDS = ["anthropic", "openai", "google", "microsoft", "github", "aws", "amazon", "stripe", "paypal",
          "metamask", "coinbase", "binance", "vercel", "solana", "slack", "notion", "apple"]


def check_metadata(skill: Skill) -> list[Finding]:
    findings = []
    if not skill.get("SKILL.md"):
        findings.append(Finding("check", "NO_SKILL_MD", "AST04", "MEDIUM", "No SKILL.md manifest", None, None, "",
                                "Without a manifest the skill's purpose cannot be checked against its behavior.",
                                "Add a SKILL.md with name and description.", precise=True))
        return findings
    for key in ("name", "description"):
        if not skill.frontmatter.get(key):
            findings.append(Finding("check", f"MISSING_{key.upper()}", "AST04", "LOW", f"Frontmatter has no `{key}`",
                                    "SKILL.md", 1, "", "The declared purpose is needed to judge behavior.",
                                    f"Add a `{key}` field to the frontmatter.", precise=True))
    name = skill.frontmatter.get("name", "").lower()
    brand = next((b for b in BRANDS if re.search(rf"\b{b}\b", name)), None)
    if brand or "official" in name:
        findings.append(Finding(
            "check", "BRAND_IN_NAME", "AST04", "MEDIUM", f"Skill name uses a brand or 'official': {skill.frontmatter.get('name')}",
            "SKILL.md", 1, f"name: {skill.frontmatter.get('name')}",
            "Fake branded skills are a common way to gain trust for malicious skills.",
            "Confirm the publisher is affiliated with the brand before installing.",
        ))
    return findings


FILE_CHECKS = [
    check_hidden_unicode, check_encoded_payloads, check_credential_access, check_agent_config_writes,
    check_remote_instructions, check_untrusted_installer, check_secrets, check_unsafe_deserialization,
    check_dependencies, check_autorun_config,
]


def run_own_checks(skill: Skill) -> tuple[list[Finding], LayerStatus]:
    started = time.monotonic()
    findings = check_metadata(skill)
    for file in skill.files:
        if is_license(file.path):
            continue
        for check in FILE_CHECKS:
            findings.extend(check(file))
    if skill.binary_files:
        findings.append(Finding(
            "check", "UNREVIEWABLE_FILES", "AST08", "LOW", f"{len(skill.binary_files)} binary or oversized file(s) not inspected",
            None, None, ", ".join(skill.binary_files[:10]),
            "Binary files cannot be reviewed as text and may hide executables.",
            "Check these files manually or remove them if they are not needed.", precise=True,
        ))
    return findings, LayerStatus("checks", True, f"{len(findings)} findings", time.monotonic() - started)
