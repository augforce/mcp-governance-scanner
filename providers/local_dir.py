"""Ingest a local MCP server directory into a ServerArtifact.

Manifest resolution, in order:
1. explicit ``manifest_path`` (the governance-intake case: the reviewer
   authors the manifest outside the server's own tree),
2. a manifest file at the server root (mcp-manifest.json, manifest.json,
   manifest.yaml, manifest.yml),
3. synthesis of the metadata fields from pyproject.toml or package.json,
4. a minimal ``{"name": <dirname>}`` — downstream scoring then reports the
   missing intake data honestly (permissions unassessable, no tools declared).

The sweep deliberately includes config files (.json/.yaml/.toml/.env.example)
alongside code: the undisclosed-network gate must see URLs that only live in
config. Markdown goes to ``docs`` — endpoints named there count as disclosed,
not as calls.
"""

from __future__ import annotations

import json
import tomllib
from pathlib import Path

import yaml

from scanning.models import ServerArtifact

MANIFEST_NAMES = ("mcp-manifest.json", "manifest.json", "manifest.yaml", "manifest.yml")
SOURCE_EXTENSIONS = {".py", ".js", ".ts", ".mjs", ".cjs", ".json", ".yaml", ".yml", ".toml"}
SPECIAL_SOURCE_NAMES = {".env.example", ".env.sample"}
DOC_EXTENSIONS = {".md"}
# Excluded outright: environment/install trees (dependency-tree scanning is a
# different tool's job) and the server's own test suite (dummy keys and dummy
# URLs there are calibration noise, not deployed behavior — see README).
SKIP_DIRS = {
    ".git", ".hg", ".venv", "venv", "node_modules", "__pycache__",
    ".pytest_cache", ".mypy_cache", "dist", "build", ".claude",
    "tests", "test", "__tests__", "spec",
}
# Checked-in third-party assets: still ingested and scanned (an undisclosed
# network call in a bundle must be caught) but marked vendored so the
# credential gate alone can exempt them.
VENDOR_DIRS = {"vendor", "vendored", "third_party"}
VENDOR_NAME_MARKERS = (".min.js", ".min.css", ".bundle.js")
MAX_FILE_BYTES = 1_000_000


class IngestError(ValueError):
    """Raised when a directory can't be ingested as an MCP server."""


def _load_manifest_file(path: Path) -> dict:
    try:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise IngestError(f"Could not parse manifest {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise IngestError(f"Manifest {path} is not a mapping")
    return data


def synth_pyproject_text(text: str) -> dict | None:
    """Synthesize manifest metadata from pyproject.toml content."""
    try:
        project = tomllib.loads(text).get("project", {})
    except tomllib.TOMLDecodeError:
        return None
    if not project:
        return None
    manifest: dict = {}
    for key in ("name", "version", "description"):
        if project.get(key):
            manifest[key] = project[key]
    authors = project.get("authors") or []
    if authors and isinstance(authors[0], dict) and authors[0].get("name"):
        manifest["author"] = authors[0]["name"]
    license_field = project.get("license")
    if isinstance(license_field, dict):
        license_field = license_field.get("text")
    if license_field:
        manifest["license"] = license_field
    urls = {k.lower(): v for k, v in (project.get("urls") or {}).items()}
    repo = urls.get("repository") or urls.get("source") or urls.get("homepage")
    if repo:
        manifest["repository"] = repo
    return manifest or None


def _synthesize_from_pyproject(path: Path) -> dict | None:
    try:
        return synth_pyproject_text(path.read_text(encoding="utf-8"))
    except OSError:
        return None


def synth_package_json_text(text: str) -> dict | None:
    """Synthesize manifest metadata from package.json content."""
    try:
        pkg = json.loads(text)
    except ValueError:
        return None
    if not isinstance(pkg, dict):
        return None
    manifest: dict = {}
    for key in ("name", "version", "description", "license"):
        if pkg.get(key):
            manifest[key] = pkg[key]
    author = pkg.get("author")
    if isinstance(author, dict):
        author = author.get("name")
    if author:
        manifest["author"] = author
    repo = pkg.get("repository")
    if isinstance(repo, dict):
        repo = repo.get("url")
    if repo:
        manifest["repository"] = repo
    return manifest or None


def _synthesize_from_package_json(path: Path) -> dict | None:
    try:
        return synth_package_json_text(path.read_text(encoding="utf-8"))
    except OSError:
        return None


def _resolve_manifest(root: Path, manifest_path: Path | str | None) -> tuple[dict, Path | None]:
    """Return (manifest, path-of-discovered-manifest-inside-root-or-None)."""
    if manifest_path is not None:
        return _load_manifest_file(Path(manifest_path)), None
    for name in MANIFEST_NAMES:
        candidate = root / name
        if candidate.is_file():
            return _load_manifest_file(candidate), candidate
    for synth, name in ((_synthesize_from_pyproject, "pyproject.toml"),
                        (_synthesize_from_package_json, "package.json")):
        candidate = root / name
        if candidate.is_file():
            manifest = synth(candidate)
            if manifest:
                return manifest, None
    return {"name": root.name}, None


def _iter_files(root: Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        parts = path.relative_to(root).parts
        if any(p in SKIP_DIRS or (p.startswith(".") and p not in SPECIAL_SOURCE_NAMES) for p in parts[:-1]):
            continue
        name = parts[-1]
        if name.startswith(".") and name not in SPECIAL_SOURCE_NAMES:
            continue
        yield path


def _is_vendored(rel_parts: tuple[str, ...]) -> bool:
    if any(p in VENDOR_DIRS for p in rel_parts[:-1]):
        return True
    return any(rel_parts[-1].lower().endswith(marker) for marker in VENDOR_NAME_MARKERS)


def ingest(root: Path | str, manifest_path: Path | str | None = None) -> ServerArtifact:
    """Ingest the server directory at ``root`` into a ServerArtifact."""
    root = Path(root)
    if not root.is_dir():
        raise IngestError(f"Not a directory: {root}")
    manifest, manifest_file = _resolve_manifest(root, manifest_path)
    source_files: dict[str, str] = {}
    docs: dict[str, str] = {}
    vendored: list[str] = []
    for path in _iter_files(root):
        if path == manifest_file:
            continue  # already the manifest; don't double-count as source
        suffix = path.suffix.lower()
        is_source = suffix in SOURCE_EXTENSIONS or path.name in SPECIAL_SOURCE_NAMES
        is_doc = suffix in DOC_EXTENSIONS
        if not (is_source or is_doc):
            continue
        if path.stat().st_size > MAX_FILE_BYTES:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue  # binary or unreadable — nothing to scan statically
        rel_parts = path.relative_to(root).parts
        rel = "/".join(rel_parts)
        if is_doc:
            docs[rel] = content
        else:
            source_files[rel] = content
            if _is_vendored(rel_parts):
                vendored.append(rel)
    return ServerArtifact(
        manifest=manifest, source_files=source_files, docs=docs, vendored=tuple(vendored)
    )
