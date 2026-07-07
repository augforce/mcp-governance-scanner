"""Folder-scan provider: take the file tree a browser folder-picker uploads,
decide whether it's an MCP server at all, and (if so) build a ServerArtifact
using the same sweep rules as the local-directory provider."""

import json

from providers.folder import detect_mcp_server
from tests import fixtures


def clean_tree(extra=None):
    files = {
        "notes-server/manifest.json": json.dumps(fixtures.CLEAN_MANIFEST),
        "notes-server/server.py": fixtures.CLEAN_SOURCE,
    }
    if extra:
        files.update(extra)
    return files


class TestDetection:
    def test_manifest_marks_folder_as_server(self):
        artifact = detect_mcp_server(clean_tree())
        assert artifact is not None
        assert artifact.manifest["name"] == "notes-server"

    def test_mcp_import_without_manifest_marks_server(self):
        files = {"svc/server.py": "from mcp.server import FastMCP\nmcp = FastMCP('svc')\n"}
        artifact = detect_mcp_server(files)
        assert artifact is not None
        assert artifact.manifest["name"] == "svc"  # minimal, named after the folder

    def test_synthesizes_manifest_from_pyproject_when_no_manifest_file(self):
        files = {
            "svc/pyproject.toml": '[project]\nname = "svc"\nversion = "1.0"\n'
            'dependencies = ["fastmcp"]\n',
            "svc/main.py": "x = 1\n",
        }
        artifact = detect_mcp_server(files)
        assert artifact is not None
        assert artifact.manifest["version"] == "1.0"

    def test_ordinary_folder_is_not_a_server(self):
        files = {"notes/todo.txt": "buy milk", "notes/data.csv": "a,b\n1,2\n"}
        assert detect_mcp_server(files) is None

    def test_empty_upload_is_not_a_server(self):
        assert detect_mcp_server({}) is None


class TestSweep:
    def test_manifest_not_double_counted_as_source(self):
        artifact = detect_mcp_server(clean_tree())
        assert "notes-server/server.py" in artifact.source_files
        assert "notes-server/manifest.json" not in artifact.source_files

    def test_config_files_swept(self):
        artifact = detect_mcp_server(
            clean_tree({"notes-server/settings.yaml": "host: cfg.example.com\n"})
        )
        assert "notes-server/settings.yaml" in artifact.source_files

    def test_markdown_goes_to_docs(self):
        artifact = detect_mcp_server(
            clean_tree({"notes-server/README.md": "Talks to https://api.example.com."})
        )
        assert "notes-server/README.md" in artifact.docs
        assert "notes-server/README.md" not in artifact.source_files

    def test_junk_dirs_skipped(self):
        artifact = detect_mcp_server(
            clean_tree(
                {
                    "notes-server/node_modules/dep/index.js": "junk",
                    "notes-server/.venv/lib/junk.py": "junk",
                }
            )
        )
        assert not any(
            "node_modules" in p or ".venv" in p for p in artifact.source_files
        )

    def test_vendored_marked(self):
        artifact = detect_mcp_server(
            clean_tree({"notes-server/static/vendor/react.min.js": "bundle"})
        )
        assert "notes-server/static/vendor/react.min.js" in artifact.vendored

    def test_binary_files_skipped(self):
        artifact = detect_mcp_server(
            clean_tree({"notes-server/blob.json": b"\xff\xfe\x00\x01binary"})
        )
        assert "notes-server/server.py" in artifact.source_files

    def test_config_url_reaches_the_network_gate(self):
        from scanning import gates

        files = {
            "svc/manifest.json": json.dumps({"name": "svc", "permissions": {"network": []}}),
            "svc/settings.json": '{"telemetry": "https://sneaky.tracker.example/v1"}',
        }
        artifact = detect_mcp_server(files)
        findings = gates.check_undisclosed_network_calls(artifact)
        assert any("sneaky.tracker.example" in f.snippet for f in findings)
