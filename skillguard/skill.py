"""Load a skill folder or package: files, frontmatter, content hashes, and numbered text for LLM review.

Bundled archives (zip/tar) are inspected in memory: their text members are reviewed like any other file,
under virtual paths such as `assets/template.tar.gz!/src/index.js`. Nothing is ever executed.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import os
import re
import shutil
import stat
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

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
# Bundled archives whose members are inspected in memory. Others (.7z, .rar, ...) remain coverage gaps.
ARCHIVE_SUFFIXES = (".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz")
# Skill packages accepted as scan input (Claude skills are distributed as .zip or .skill files).
PACKAGE_SUFFIXES = (".zip", ".skill")
MAX_ARCHIVE_MEMBERS = 5000
MAX_ARCHIVE_BYTES = 50_000_000  # total uncompressed bytes read from one archive (zip-bomb guard)


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
    hashes: dict[str, str] = field(default_factory=dict)     # every file on disk (path -> sha256 or symlink:...)
    display: str = ""                                        # what the user asked to scan (dir or package)

    @property
    def content_sha256(self) -> str:
        """One hash over every file in the skill (including uninspected ones), for caching and approvals."""
        return tree_hash(self.hashes)

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


def _classify(rel: str, raw: bytes, media: list[str], gaps: list[str]) -> str | None:
    """Return the text of a file, or None after recording it as media or a coverage gap."""
    suffix = PurePosixPath(rel).suffix.lower()
    if suffix in TEXT_SUFFIXES or b"\0" not in raw[:4096]:
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            pass
    if suffix in MEDIA_SUFFIXES:
        media.append(rel)
    else:
        gaps.append(f"{rel}: binary file of unknown type, not inspected")
    return None


def is_archive(path: str) -> bool:
    return path.lower().endswith(ARCHIVE_SUFFIXES)


def archive_entries(name: str, data: bytes, limit: int):
    """Yield (member path, bytes or None, problem) for every member of a zip or tar archive, in memory.

    Never extracts or follows links. Members that are links, devices, encrypted, larger than `limit`
    or beyond the archive-wide budget come back with a problem description instead of bytes.
    """
    budget = MAX_ARCHIVE_BYTES
    if name.lower().endswith((".zip", ".skill")):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = archive.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                yield "", None, f"{len(members)} members, over the limit of {MAX_ARCHIVE_MEMBERS}"
                return
            for info in members:
                if info.is_dir():
                    continue
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    yield info.filename, None, "symlink in archive not followed"
                elif info.flag_bits & 0x1:
                    yield info.filename, None, "encrypted (password-protected) member"
                elif info.file_size > limit:
                    yield info.filename, None, f"larger than {limit:,} bytes"
                elif info.file_size > budget:
                    yield info.filename, None, "archive exceeds the total size budget"
                else:
                    with archive.open(info) as member:
                        content = member.read(limit + 1)  # declared sizes can lie
                    if len(content) > limit:
                        yield info.filename, None, f"larger than {limit:,} bytes"
                        continue
                    budget -= len(content)
                    yield info.filename, content, ""
        return
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
        for count, member in enumerate(archive):
            if count >= MAX_ARCHIVE_MEMBERS:
                yield "", None, f"more than {MAX_ARCHIVE_MEMBERS} members; the rest not inspected"
                return
            if member.isdir():
                continue
            if not member.isfile():
                yield member.name, None, "link or special file in archive not followed"
            elif member.size > limit or member.size > budget:
                # Skipping a member of a compressed tar still means decompressing it (a bomb costs CPU), and
                # the archive is a coverage gap either way, so stop reading here.
                yield member.name, None, f"larger than {min(limit, budget):,} bytes; rest of the archive not inspected"
                return
            else:
                content = archive.extractfile(member).read(limit + 1)
                budget -= len(content)
                yield member.name, content, ""


def _inspect_archive(rel: str, raw: bytes, files: list, media: list[str], gaps: list[str]) -> None:
    """Add an archive's text members as virtual files `rel!/member`; anything else becomes a gap."""
    limit = config.settings.max_file_bytes
    try:
        for name, data, problem in archive_entries(rel, raw, limit):
            virtual = f"{rel}!/{name}" if name else rel
            if problem:
                gaps.append(f"{virtual}: {problem}")
            elif is_archive(name):
                gaps.append(f"{virtual}: nested archive not inspected")
            else:
                text = _classify(virtual, data, media, gaps)
                if text is not None:
                    files.append(SkillFile(virtual, text, PurePosixPath(name).suffix.lower() in SCRIPT_SUFFIXES))
    except Exception as exc:  # noqa: BLE001 - corrupt or unsupported archive: fail closed as a gap
        gaps.append(f"{rel}: archive could not be read ({type(exc).__name__}), not inspected")


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def tree_hashes(root: Path) -> dict[str, str]:
    """sha256 of every regular file under root (except .git), symlinks by their target; nothing is followed."""
    hashes: dict[str, str] = {}
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        dirnames[:] = [d for d in dirnames if d not in IGNORED_DIRS]
        for name in dirnames + filenames:
            path = here / name
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                hashes[rel] = "symlink:" + os.readlink(path)
            elif name in filenames and path.is_file():
                hashes[rel] = file_sha256(path)
    return hashes


def tree_hash(hashes: dict[str, str]) -> str:
    return hashlib.sha256("".join(f"{p}\0{h}\n" for p, h in sorted(hashes.items())).encode()).hexdigest()


def load_skill(root: Path, *, display: str | None = None, extra_gaps: list[str] | None = None) -> Skill:
    if not root.exists():
        raise SkillLoadError(f"{root} does not exist")
    if not root.is_dir():
        raise SkillLoadError(f"{root} is not a directory")
    root = root.resolve()
    files: list[SkillFile] = []
    media: list[str] = []
    gaps: list[str] = list(extra_gaps or [])
    for path in _walk(root, gaps):
        rel = path.relative_to(root).as_posix()
        if path.stat().st_size > config.settings.max_file_bytes:
            if path.suffix.lower() in MEDIA_SUFFIXES:
                media.append(rel)
            else:
                gaps.append(f"{rel}: larger than {config.settings.max_file_bytes:,} bytes, not inspected")
            continue
        raw = path.read_bytes()
        if is_archive(rel):
            _inspect_archive(rel, raw, files, media, gaps)
            continue
        text = _classify(rel, raw, media, gaps)
        if text is not None:
            files.append(SkillFile(rel, text, path.suffix.lower() in SCRIPT_SUFFIXES))

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
        hashes=tree_hashes(root),
        display=display or str(root),
    )


def is_package(path: Path) -> bool:
    return path.is_file() and path.name.lower().endswith(PACKAGE_SUFFIXES)


def _safe_member_path(name: str) -> PurePosixPath | None:
    """The member's relative path, or None if it could escape the extraction directory."""
    if "\\" in name or re.match(r"^[A-Za-z]:", name):
        return None
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        return None
    return path


def extract_package(package: Path, dest: Path) -> tuple[Path, list[str]]:
    """Safely extract a .zip/.skill skill package. Returns (skill root, coverage gaps).

    No path traversal, no links, size limits per member and per archive. Entries that are not extracted
    are coverage gaps, so the verdict cannot be SAFE without them being looked at.
    """
    gaps: list[str] = []
    seen: set[PurePosixPath] = set()
    try:
        for name, data, problem in archive_entries(package.name, package.read_bytes(), config.settings.max_file_bytes):
            target = _safe_member_path(name) if name else None
            if target and target.parts[0] == "__MACOSX" and target.name.startswith("._"):
                continue  # macOS resource-fork metadata added by Finder's "Compress"
            if problem:
                gaps.append(f"{name or package.name}: {problem}")
            elif target is None:
                gaps.append(f"{name}: unsafe path in package, not extracted")
            elif target in seen:
                # Installers may keep the first or the last copy; the scan cannot know which one runs.
                gaps.append(f"{name}: duplicate entry in package, the installed version is ambiguous")
            else:
                seen.add(target)
                out = dest.joinpath(*target.parts)
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_bytes(data)
    except Exception as exc:  # noqa: BLE001 - any unreadable package is an error, never a verdict
        raise SkillLoadError(f"{package} is not a readable zip package: {type(exc).__name__}: {exc}") from exc
    entries = list(dest.iterdir())
    # Packages usually wrap the skill in one top-level folder.
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0], gaps
    return dest, gaps


@contextlib.contextmanager
def open_skill(path: Path):
    """Yield a loaded Skill for a skill directory or a .zip/.skill package (extracted to a temp dir)."""
    if is_package(path):
        tmp = Path(tempfile.mkdtemp(prefix="skillguard-"))
        try:
            extracted = tmp / path.name.rsplit(".", 1)[0]
            extracted.mkdir()
            root, gaps = extract_package(path, extracted)
            skill = load_skill(root, display=str(path), extra_gaps=gaps)
            skill.hashes = {**skill.hashes, "(package)": file_sha256(path)}
            yield skill
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    else:
        yield load_skill(path)


def is_license(path: str) -> bool:
    return Path(path).name.lower() in LICENSE_NAMES


def numbered(file: SkillFile, start: int = 1, end: int | None = None) -> str:
    lines = file.lines
    end = min(len(lines), end or len(lines))
    return "\n".join(f"{i:5d}| {lines[i - 1]}" for i in range(max(1, start), end + 1))
