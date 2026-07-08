"""local_dir provider: ingest a server directory into a ServerArtifact.

Key requirement (Phase 2 sign-off): the sweep must include config files
(.json/.yaml/.toml/.env.example) alongside code, because the undisclosed-
network gate depends on seeing URLs that only live in config.
"""

import json

import pytest

from providers import local_dir
from providers.local_dir import IngestError, ingest


def make_server(tmp_path, manifest=None):
    (tmp_path / "server.py").write_text("import os\n")
    if manifest is not None:
        (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    return tmp_path


class TestManifestDiscovery:
    def test_discovers_manifest_json_at_root(self, tmp_path):
        make_server(tmp_path, {"name": "svc", "version": "1.0"})
        artifact = ingest(tmp_path)
        assert artifact.manifest["name"] == "svc"

    def test_manifest_file_not_double_counted_as_source(self, tmp_path):
        make_server(tmp_path, {"name": "svc"})
        artifact = ingest(tmp_path)
        assert "manifest.json" not in artifact.source_files

    def test_yaml_manifest_supported(self, tmp_path):
        (tmp_path / "manifest.yaml").write_text("name: svc\nversion: '2.0'\n")
        (tmp_path / "server.py").write_text("x = 1\n")
        assert ingest(tmp_path).manifest["version"] == "2.0"

    def test_explicit_manifest_override(self, tmp_path):
        # The governance-intake case: reviewer authors the manifest outside
        # the server's own tree (e.g. for a third-party server under review).
        server = tmp_path / "server"
        server.mkdir()
        (server / "server.py").write_text("x = 1\n")
        intake = tmp_path / "intake.json"
        intake.write_text(json.dumps({"name": "reviewed-svc", "permissions": {}}))
        artifact = ingest(server, manifest_path=intake)
        assert artifact.manifest["name"] == "reviewed-svc"

    def test_synthesizes_manifest_from_pyproject(self, tmp_path):
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "pyproj-svc"\nversion = "0.3.0"\n'
            'description = "A demo server."\n'
            'license = {text = "MIT"}\n'
            'authors = [{name = "Jane Dev"}]\n'
            '[project.urls]\nRepository = "https://github.com/jane/pyproj-svc"\n'
        )
        (tmp_path / "server.py").write_text("x = 1\n")
        manifest = ingest(tmp_path).manifest
        assert manifest["name"] == "pyproj-svc"
        assert manifest["version"] == "0.3.0"
        assert manifest["author"] == "Jane Dev"
        assert manifest["license"] == "MIT"
        assert manifest["repository"] == "https://github.com/jane/pyproj-svc"

    def test_synthesizes_manifest_from_package_json(self, tmp_path):
        (tmp_path / "package.json").write_text(
            json.dumps(
                {
                    "name": "node-svc",
                    "version": "1.1.0",
                    "author": "Jane Dev",
                    "license": "MIT",
                    "repository": {"url": "https://github.com/jane/node-svc"},
                }
            )
        )
        (tmp_path / "index.js").write_text("const x = 1;\n")
        manifest = ingest(tmp_path).manifest
        assert manifest["name"] == "node-svc"
        assert manifest["repository"] == "https://github.com/jane/node-svc"

    def test_bare_directory_gets_minimal_manifest(self, tmp_path):
        (tmp_path / "server.py").write_text("x = 1\n")
        assert ingest(tmp_path).manifest == {"name": tmp_path.name}

    def test_missing_directory_raises(self, tmp_path):
        with pytest.raises(IngestError):
            ingest(tmp_path / "nope")


class TestFileSweep:
    def test_sweeps_code_and_config_files(self, tmp_path):
        make_server(tmp_path, {"name": "svc"})
        (tmp_path / "settings.json").write_text('{"endpoint": "https://cfg.example.com"}')
        (tmp_path / "conf.yaml").write_text("host: cfg.example.com\n")
        (tmp_path / "extra.toml").write_text('url = "https://cfg.example.com"\n')
        (tmp_path / ".env.example").write_text("API_URL=https://cfg.example.com\n")
        (tmp_path / "index.ts").write_text("const x = 1;\n")
        files = ingest(tmp_path).source_files
        for name in ("server.py", "settings.json", "conf.yaml", "extra.toml", ".env.example", "index.ts"):
            assert name in files, f"{name} missing from sweep"

    def test_markdown_goes_to_docs_not_source(self, tmp_path):
        make_server(tmp_path, {"name": "svc"})
        (tmp_path / "README.md").write_text("Talks to https://api.example.com only.")
        artifact = ingest(tmp_path)
        assert "README.md" in artifact.docs
        assert "README.md" not in artifact.source_files

    def test_nested_paths_preserved_and_junk_dirs_skipped(self, tmp_path):
        make_server(tmp_path, {"name": "svc"})
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "tools.py").write_text("y = 2\n")
        (tmp_path / "node_modules" / "dep").mkdir(parents=True)
        (tmp_path / "node_modules" / "dep" / "index.js").write_text("junk\n")
        (tmp_path / ".venv" / "lib").mkdir(parents=True)
        (tmp_path / ".venv" / "lib" / "junk.py").write_text("junk\n")
        files = ingest(tmp_path).source_files
        assert "src/tools.py" in files
        assert not any("node_modules" in p or ".venv" in p for p in files)

    def test_vendored_and_minified_assets_ingested_but_marked(self, tmp_path):
        # Bundled third-party assets are still scanned (an undisclosed network
        # call in a vendored bundle must be caught) but are marked vendored so
        # the credential gate alone can exempt them from secret-shaped noise.
        make_server(tmp_path, {"name": "svc"})
        (tmp_path / "static" / "vendor").mkdir(parents=True)
        (tmp_path / "static" / "vendor" / "react.js").write_text("bundle\n")
        (tmp_path / "static" / "app.min.js").write_text("minified\n")
        (tmp_path / "static" / "app.js").write_text("const x = 1;\n")
        artifact = ingest(tmp_path)
        for name in ("static/app.js", "static/vendor/react.js", "static/app.min.js"):
            assert name in artifact.source_files
        assert set(artifact.vendored) == {"static/vendor/react.js", "static/app.min.js"}

    def test_server_test_directories_skipped(self, tmp_path):
        # The scan covers the deployed tool surface; the server's own test
        # suite (dummy keys, dummy URLs) is calibration noise, not behavior.
        make_server(tmp_path, {"name": "svc"})
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_server.py").write_text('URL = "https://x/"\n')
        (tmp_path / "__tests__").mkdir()
        (tmp_path / "__tests__" / "server.test.ts").write_text('const u = "https://x/";\n')
        files = ingest(tmp_path).source_files
        assert not any("tests" in p for p in files)

    def test_unreadable_binary_files_skipped(self, tmp_path):
        make_server(tmp_path, {"name": "svc"})
        (tmp_path / "blob.json").write_bytes(b"\xff\xfe\x00\x01binary")
        files = ingest(tmp_path).source_files
        assert "server.py" in files  # sweep survived the binary file


class TestEndToEnd:
    def test_ingested_config_url_reaches_the_network_gate(self, tmp_path):
        # A URL that lives ONLY in a config file must still be visible to
        # gate 3 — this is the reason config files are in the sweep.
        from scanning import gates

        make_server(tmp_path, {"name": "svc", "permissions": {"network": []}})
        (tmp_path / "settings.json").write_text(
            '{"telemetry": "https://sneaky.tracker.example/v1"}'
        )
        findings = gates.check_undisclosed_network_calls(ingest(tmp_path))
        assert any("sneaky.tracker.example" in f.snippet for f in findings)


class TestReadTree:
    def test_paths_prefixed_with_folder_name_like_a_browser_upload(self, tmp_path):
        root = tmp_path / "my-server"
        root.mkdir()
        (root / "server.py").write_text("x = 1\n")
        tree = local_dir.read_tree(root)
        assert tree == {"my-server/server.py": b"x = 1\n"}

    def test_bulk_directories_excluded(self, tmp_path):
        root = tmp_path / "proj"
        root.mkdir()
        (root / "server.py").write_text("x = 1\n")
        for junk in (".venv/lib/mod.py", "node_modules/pkg/index.js",
                     "__pycache__/server.cpython-312.pyc", ".git/config",
                     "dist/bundle.js", "build/out.js"):
            path = root / junk
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("junk\n")
        tree = local_dir.read_tree(root)
        assert list(tree) == ["proj/server.py"]

    def test_oversized_files_skipped(self, tmp_path):
        root = tmp_path / "proj"
        root.mkdir()
        (root / "server.py").write_text("x = 1\n")
        (root / "huge.json").write_bytes(b"x" * (local_dir.MAX_FILE_BYTES + 1))
        assert list(local_dir.read_tree(root)) == ["proj/server.py"]

    def test_feeds_the_same_detection_pipeline_as_an_upload(self, tmp_path):
        from providers.folder import detect_mcp_server

        root = tmp_path / "svc"
        root.mkdir()
        (root / "manifest.json").write_text('{"name": "svc"}')
        (root / "server.py").write_text("from mcp import tool\n")
        artifact = detect_mcp_server(local_dir.read_tree(root))
        assert artifact is not None
        assert artifact.manifest["name"] == "svc"
        assert "svc/server.py" in artifact.source_files
