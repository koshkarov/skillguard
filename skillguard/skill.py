"""Load a skill folder: files, frontmatter, and numbered text for LLM review."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

TEXT_SUFFIXES = {
    ".md", ".txt", ".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".tsx",
    ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".html", ".htm", ".css", ".ps1",
    ".rb", ".go", ".rs", ".java", ".php", ".pl", ".lua", ".xml", ".svg", ".env",
}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}
LICENSE_NAMES = {"license", "license.txt", "license.md", "copying", "notice"}
MAX_FILE_BYTES = 2_000_000


@dataclass
class SkillFile:
    path: str           # relative to the skill root, POSIX style
    text: str
    is_script: bool

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()


@dataclass
class Skill:
    root: Path
    name: str
    description: str
    frontmatter: dict
    frontmatter_raw: str
    files: list[SkillFile] = field(default_factory=list)
    binary_files: list[str] = field(default_factory=list)

    def get(self, path: str) -> SkillFile | None:
        return next((f for f in self.files if f.path == path), None)


def parse_frontmatter(text: str) -> tuple[dict, str]:
    """Minimal, safe frontmatter parser: top-level `key: value` pairs only."""
    match = re.match(r"^---\s*\n(.*?)\n---\s*(\n|$)", text, re.S)
    if not match:
        return {}, ""
    raw = match.group(1)
    data: dict = {}
    key = None
    for line in raw.splitlines():
        top = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
        if top:
            key, value = top.group(1), top.group(2).strip()
            data[key] = value.strip("'\"") if value not in ("|", ">", "|-", ">-") else ""
        elif key and line.startswith((" ", "\t")):
            data[key] = (data[key] + " " + line.strip()).strip()
    return data, raw


def load_skill(root: Path) -> Skill:
    root = root.resolve()
    files: list[SkillFile] = []
    binary: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        rel = path.relative_to(root).as_posix()
        if path.stat().st_size > MAX_FILE_BYTES:
            binary.append(rel)
            continue
        raw = path.read_bytes()
        if path.suffix.lower() not in TEXT_SUFFIXES and b"\0" in raw[:4096]:
            binary.append(rel)
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            binary.append(rel)
            continue
        is_script = path.suffix.lower() in {".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".rb", ".pl", ".php", ".lua"}
        files.append(SkillFile(rel, text, is_script))

    skill_md = next((f for f in files if f.path.lower() == "skill.md"), None)
    frontmatter, raw = parse_frontmatter(skill_md.text) if skill_md else ({}, "")
    return Skill(
        root=root,
        name=frontmatter.get("name") or root.name,
        description=frontmatter.get("description", ""),
        frontmatter=frontmatter,
        frontmatter_raw=raw,
        files=files,
        binary_files=binary,
    )


def is_license(path: str) -> bool:
    return Path(path).name.lower() in LICENSE_NAMES


def numbered(file: SkillFile, start: int = 1, end: int | None = None) -> str:
    lines = file.lines
    end = min(len(lines), end or len(lines))
    return "\n".join(f"{i:5d}| {lines[i - 1]}" for i in range(max(1, start), end + 1))
