"""Load a skill folder: files, frontmatter, and numbered text for LLM review."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import config

TEXT_SUFFIXES = {
    ".md", ".txt", ".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".tsx",
    ".json", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".html", ".htm", ".css", ".ps1",
    ".rb", ".go", ".rs", ".java", ".php", ".pl", ".lua", ".xml", ".svg", ".env",
}
SCRIPT_SUFFIXES = {".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".ps1", ".rb", ".pl", ".php", ".lua"}
# Binary files that are ordinary skill assets (fonts, images, media, documents): reported as a note only.
MEDIA_SUFFIXES = {
    ".ttf", ".otf", ".woff", ".woff2", ".eot", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".bmp",
    ".tif", ".tiff", ".pdf", ".mp3", ".mp4", ".wav", ".ogg", ".webm", ".mov", ".docx", ".xlsx", ".pptx",
}
IGNORED_DIRS = {".git"}  # VCS metadata; never loaded by an agent
UNSCANNED_DIRS = {"node_modules", "__pycache__", ".venv", "venv"}  # skipped, but reported as a coverage gap
LICENSE_NAMES = {"license", "license.txt", "license.md", "copying", "notice"}


class SkillLoadError(ValueError):
    """The path cannot be scanned at all (missing, not a directory)."""


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
    binary_files: list[str] = field(default_factory=list)    # known media assets, not inspected
    coverage_gaps: list[str] = field(default_factory=list)   # anything not inspected that could matter

    def get(self, path: str) -> SkillFile | None:
        return next((f for f in self.files if f.path == path), None)

    @property
    def manifest(self) -> SkillFile | None:
        """The top-level SKILL.md, matched case-insensitively (some skills ship `skill.md`)."""
        return next((f for f in self.files if f.path.lower() == "skill.md"), None)


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


def _walk(root: Path, gaps: list[str]) -> list[Path]:
    """All regular files under root, without following symlinks and never leaving root."""
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        for name in list(dirnames):
            child = here / name
            rel = child.relative_to(root).as_posix()
            if child.is_symlink():
                gaps.append(f"{rel}/: symlinked directory not followed")
                dirnames.remove(name)
            elif name in IGNORED_DIRS:
                dirnames.remove(name)
            elif name in UNSCANNED_DIRS:
                count = sum(len(f) for _, _, f in os.walk(child, followlinks=False))
                gaps.append(f"{rel}/: bundled {name} directory ({count} files) not scanned")
                dirnames.remove(name)
        for name in filenames:
            path = here / name
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                gaps.append(f"{rel}: symlink to {os.readlink(path)} not followed")
                continue
            if not path.is_file() or root not in path.resolve().parents:
                gaps.append(f"{rel}: not a regular file inside the skill")
                continue
            found.append(path)
    return sorted(found)


def load_skill(root: Path) -> Skill:
    if not root.exists():
        raise SkillLoadError(f"{root} does not exist")
    if not root.is_dir():
        raise SkillLoadError(f"{root} is not a directory")
    root = root.resolve()
    files: list[SkillFile] = []
    media: list[str] = []
    gaps: list[str] = []
    for path in _walk(root, gaps):
        rel = path.relative_to(root).as_posix()
        suffix = path.suffix.lower()
        if path.stat().st_size > config.settings.max_file_bytes:
            if suffix in MEDIA_SUFFIXES:
                media.append(rel)
            else:
                gaps.append(f"{rel}: larger than {config.settings.max_file_bytes:,} bytes, not inspected")
            continue
        raw = path.read_bytes()
        text = None
        if suffix in TEXT_SUFFIXES or b"\0" not in raw[:4096]:
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = None
        if text is None:
            if suffix in MEDIA_SUFFIXES:
                media.append(rel)
            else:
                gaps.append(f"{rel}: binary file of unknown type, not inspected")
            continue
        files.append(SkillFile(rel, text, suffix in SCRIPT_SUFFIXES))

    skill_md = next((f for f in files if f.path.lower() == "skill.md"), None)
    if skill_md is None or not skill_md.text.strip():
        gaps.append("SKILL.md: missing or unreadable, so the declared purpose is unknown")
    frontmatter, raw = parse_frontmatter(skill_md.text) if skill_md else ({}, "")
    return Skill(
        root=root,
        name=frontmatter.get("name") or root.name,
        description=frontmatter.get("description", ""),
        frontmatter=frontmatter,
        frontmatter_raw=raw,
        files=files,
        binary_files=media,
        coverage_gaps=gaps,
    )


def is_license(path: str) -> bool:
    return Path(path).name.lower() in LICENSE_NAMES


def numbered(file: SkillFile, start: int = 1, end: int | None = None) -> str:
    lines = file.lines
    end = min(len(lines), end or len(lines))
    return "\n".join(f"{i:5d}| {lines[i - 1]}" for i in range(max(1, start), end + 1))
