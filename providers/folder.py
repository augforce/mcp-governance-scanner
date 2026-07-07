"""Ingest the file tree a browser folder-picker uploads.

A web page can't hand the server a filesystem path, but an
``<input webkitdirectory>`` picker delivers every file in the chosen folder
(each keyed by its folder-relative path). This provider takes that mapping,
decides whether the folder is actually an MCP server, and — if so — builds a
ServerArtifact with the same sweep rules as the local-directory provider
(config files scanned, docs separated, vendored assets marked, junk dirs and
binaries skipped). Returns None when the folder is not an MCP server.
"""

from __future__ import annotations

import json

import yaml

from providers.local_dir import (
    DOC_EXTENSIONS,
    MANIFEST_NAMES,
    MAX_FILE_BYTES,
    SOURCE_EXTENSIONS,
    SPECIAL_SOURCE_NAMES,
    _is_vendored,
    synth_package_json_text,
    synth_pyproject_text,
)
from providers.local_dir import SKIP_DIRS as _SKIP_DIRS
from scanning.models import ServerArtifact

# Tokens that mark a file as MCP-server code, so a folder with no manifest can
# still be recognized. Deliberately specific to avoid matching the bare word
# "mcp" in unrelated text.
_MCP_SIGNALS = (
    "FastMCP",
    "fastmcp",
    "mcp.server",
    "modelcontextprotocol",
    "@mcp.tool",
    "McpServer",
    "from mcp import",
    "import mcp",
    "mcp_server_",
)

_SYNTHESIZERS = {"pyproject.toml": synth_pyproject_text, "package.json": synth_package_json_text}


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1]


def _decode(content) -> str | None:
    if isinstance(content, str):
        return content
    try:
        return content.decode("utf-8")
    except (UnicodeDecodeError, AttributeError):
        return None


def _top_segment(files: dict) -> str:
    for path in files:
        if "/" in path:
            return path.split("/", 1)[0]
    return "uploaded-server"


def _parse_manifest_text(name: str, text: str) -> dict | None:
    try:
        data = json.loads(text) if name.endswith(".json") else yaml.safe_load(text)
    except (ValueError, yaml.YAMLError):
        return None
    return data if isinstance(data, dict) else None


def _resolve_manifest(decoded: dict[str, str], top: str) -> tuple[dict, str | None]:
    """Return (manifest, path-of-manifest-file-or-None)."""
    for name in MANIFEST_NAMES:
        for path, text in decoded.items():
            if _basename(path) == name:
                parsed = _parse_manifest_text(name, text)
                if parsed is not None:
                    return parsed, path
    for cfg_name, synth in _SYNTHESIZERS.items():
        for path, text in decoded.items():
            if _basename(path) == cfg_name:
                synthesized = synth(text)
                if synthesized:
                    return synthesized, None
    return {"name": top}, None


def _looks_like_mcp_server(decoded: dict[str, str]) -> bool:
    has_manifest = any(_basename(path) in MANIFEST_NAMES for path in decoded)
    if has_manifest:
        return True
    return any(
        signal in text for text in decoded.values() for signal in _MCP_SIGNALS
    )


def detect_mcp_server(files: dict[str, str | bytes]) -> ServerArtifact | None:
    """Ingest an uploaded folder tree, or None if it isn't an MCP server."""
    decoded = {
        path: text
        for path, content in files.items()
        if (text := _decode(content)) is not None
    }
    if not _looks_like_mcp_server(decoded):
        return None

    top = _top_segment(files)
    manifest, manifest_path = _resolve_manifest(decoded, top)
    source_files: dict[str, str] = {}
    docs: dict[str, str] = {}
    vendored: list[str] = []

    for path, text in decoded.items():
        if path == manifest_path:
            continue
        parts = tuple(path.split("/"))
        if any(
            part in _SKIP_DIRS or (part.startswith(".") and part not in SPECIAL_SOURCE_NAMES)
            for part in parts[:-1]
        ):
            continue
        name = parts[-1]
        if name.startswith(".") and name not in SPECIAL_SOURCE_NAMES:
            continue
        # Skip files too big to hold, matching the directory sweep's cap.
        raw = files.get(path)
        if isinstance(raw, (bytes, bytearray)) and len(raw) > MAX_FILE_BYTES:
            continue
        suffix = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
        is_source = suffix in SOURCE_EXTENSIONS or name in SPECIAL_SOURCE_NAMES
        is_doc = suffix in DOC_EXTENSIONS
        if is_doc:
            docs[path] = text
        elif is_source:
            source_files[path] = text
            if _is_vendored(parts):
                vendored.append(path)

    return ServerArtifact(
        manifest=manifest, source_files=source_files, docs=docs, vendored=tuple(vendored)
    )
