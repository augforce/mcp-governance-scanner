"""Ingest uploaded files (manifest + key source files) into a ServerArtifact.

Unlike the directory sweep, uploads are deliberate: every non-manifest,
non-doc file becomes source regardless of extension, and a file we can't
decode is an error the uploader should see — never a silent drop.
"""

from __future__ import annotations

import json

import yaml

from providers.local_dir import DOC_EXTENSIONS, MANIFEST_NAMES
from scanning.models import ServerArtifact

FALLBACK_NAME = "uploaded-server"


class IngestError(ValueError):
    """Raised when uploaded files can't be ingested as an MCP server."""


def _decode(name: str, content: str | bytes) -> str:
    if isinstance(content, str):
        return content
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise IngestError(f"Uploaded file '{name}' is not readable text: {exc}") from exc


def _parse_manifest(name: str, text: str) -> dict:
    try:
        data = json.loads(text) if name.endswith(".json") else yaml.safe_load(text)
    except (ValueError, yaml.YAMLError) as exc:
        raise IngestError(f"Could not parse manifest '{name}': {exc}") from exc
    if not isinstance(data, dict):
        raise IngestError(f"Manifest '{name}' is not a mapping")
    return data


def ingest_upload(files: dict[str, str | bytes]) -> ServerArtifact:
    """Ingest a mapping of uploaded filename -> content."""
    if not files:
        raise IngestError("No files uploaded")
    decoded = {name: _decode(name, content) for name, content in files.items()}
    manifest: dict | None = None
    source_files: dict[str, str] = {}
    docs: dict[str, str] = {}
    for name, text in decoded.items():
        basename = name.rsplit("/", 1)[-1]
        if manifest is None and basename in MANIFEST_NAMES:
            manifest = _parse_manifest(basename, text)
        elif any(basename.lower().endswith(ext) for ext in DOC_EXTENSIONS):
            docs[name] = text
        else:
            source_files[name] = text
    return ServerArtifact(
        manifest=manifest if manifest is not None else {"name": FALLBACK_NAME},
        source_files=source_files,
        docs=docs,
    )
