"""Web UI + scan history. The home page is one folder picker + a Scan button;
scanning ingests the uploaded folder tree. TestClient is in-process ASGI, so
these stay fully offline."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import db as scan_db
from app.main import create_app
from app.scan import scan_artifact
from tests import fixtures

CORPUS = Path(__file__).resolve().parent.parent / "corpus"


@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(db_path=tmp_path / "scans.db"))


def folder_upload(root: Path):
    """Mimic a browser folder picker: every file keyed by its folder-relative
    path (top segment = the chosen folder's name), as multipart 'files'."""
    parts = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            rel = path.relative_to(root.parent).as_posix()
            parts.append(("files", (rel, path.read_bytes(), "application/octet-stream")))
    return parts


class TestDb:
    def test_save_and_get_roundtrip(self, tmp_path):
        path = tmp_path / "scans.db"
        result = scan_artifact(fixtures.clean_artifact())
        scan_id = scan_db.save_scan(path, name="notes-server", source="folder", result=result, report="# Verdict")
        row = scan_db.get_scan(path, scan_id)
        assert row["name"] == "notes-server"
        assert row["verdict"] == "Approved with Conditions"
        assert row["score"] == 100

    def test_list_scans_newest_first(self, tmp_path):
        path = tmp_path / "scans.db"
        result = scan_artifact(fixtures.clean_artifact())
        first = scan_db.save_scan(path, name="a", source="folder", result=result, report="r")
        second = scan_db.save_scan(path, name="b", source="folder", result=result, report="r")
        assert [row["id"] for row in scan_db.list_scans(path)] == [second, first]


class TestHomePage:
    def test_shows_folder_picker_and_scan_button(self, client):
        html = client.get("/").text
        assert "webkitdirectory" in html
        assert "Scan" in html

    def test_has_no_legacy_upload_form(self, client):
        html = client.get("/").text
        assert 'name="manifest_path"' not in html
        assert "/upload" not in html

    def test_offers_local_path_fallback(self, client):
        html = client.get("/").text
        assert 'name="local_path"' in html
        assert "/scan-path" in html

    def test_embeds_bulk_dir_skip_list_for_the_picker(self, client):
        # The browser must filter dependency/system folders BEFORE upload —
        # the skip list is injected from the provider so there is one source
        # of truth with the server-side sweep.
        html = client.get("/").text
        for skip in ("node_modules", ".venv", "__pycache__", ".git", "dist", "build"):
            assert skip in html


class TestScanPath:
    def test_scans_a_corpus_server_by_path(self, client):
        response = client.post(
            "/scan-path",
            data={"local_path": str(CORPUS / "known_bad" / "hardcoded_key")},
            follow_redirects=True,
        )
        assert response.status_code == 200
        assert "Fail" in response.text

    def test_nonexistent_path_shows_plain_error(self, client):
        response = client.post("/scan-path", data={"local_path": "/no/such/folder"})
        assert response.status_code == 200
        assert "Not a folder on this machine" in response.text
        assert "Traceback" not in response.text

    def test_empty_path_shows_plain_error(self, client):
        response = client.post("/scan-path", data={"local_path": "  "})
        assert response.status_code == 200
        assert "Not a folder on this machine" in response.text

    def test_non_mcp_folder_shows_not_found_message(self, client, tmp_path):
        (tmp_path / "todo.txt").write_text("buy milk")
        response = client.post("/scan-path", data={"local_path": str(tmp_path)})
        assert "No MCP server found in this folder" in response.text

    def test_path_scan_persists_to_history(self, client):
        client.post(
            "/scan-path",
            data={"local_path": str(CORPUS / "known_bad" / "hardcoded_key")},
            follow_redirects=True,
        )
        assert "weather-briefing" in client.get("/history").text


class TestUploadLimits:
    def test_more_than_starlette_default_1000_files_accepted(self, client):
        # Real projects exceed multipart's default max_files=1000 even after
        # client-side filtering; the raised cap must absorb them.
        parts = [
            ("files", ("proj/manifest.json", b'{"name": "big-proj"}', "application/octet-stream")),
        ]
        parts += [
            ("files", (f"proj/mod_{i}.py", b"from mcp import tool\n", "application/octet-stream"))
            for i in range(1200)
        ]
        response = client.post("/scan", files=parts, follow_redirects=True)
        assert response.status_code == 200
        assert "big-proj" in response.text

    def test_over_the_file_cap_gets_plain_guidance_not_an_error_page(self, client, monkeypatch):
        # Exceeding the (raised) multipart file cap must point at the no-limit
        # local-path fallback, not surface a parser error. The cap is lowered
        # here so the test doesn't have to build 20k+ multipart parts.
        import app.main as main

        monkeypatch.setattr(main, "UPLOAD_MAX_FILES", 5)
        parts = [
            ("files", (f"proj/f{i}.py", b"x = 1\n", "application/octet-stream"))
            for i in range(6)
        ]
        response = client.post("/scan", files=parts)
        assert response.status_code == 200
        assert "local path" in response.text.lower()
        assert "Traceback" not in response.text


class TestScan:
    def test_scan_failing_server_shows_gate(self, client):
        files = folder_upload(CORPUS / "known_bad" / "covert_telemetry")
        response = client.post("/scan", files=files, follow_redirects=True)
        assert response.status_code == 200
        assert "Fail" in response.text
        assert "Undisclosed network calls" in response.text

    def test_scan_good_server_shows_conditions(self, client):
        files = folder_upload(CORPUS / "known_good" / "anthropic_fetch")
        response = client.post("/scan", files=files, follow_redirects=True)
        assert "Approved with Conditions" in response.text

    def test_folder_without_server_shows_plain_message(self, client, tmp_path):
        junk = tmp_path / "just-notes"
        junk.mkdir()
        (junk / "todo.txt").write_text("buy milk")
        (junk / "data.csv").write_text("a,b\n1,2\n")
        response = client.post("/scan", files=folder_upload(junk))
        assert response.status_code == 200
        assert "No MCP server found in this folder" in response.text
        # Plain message only — no error codes or stack-trace language.
        assert "Traceback" not in response.text
        assert "400" not in response.text

    def test_scan_persists_to_history(self, client):
        client.post("/scan", files=folder_upload(CORPUS / "known_bad" / "hardcoded_key"), follow_redirects=True)
        history = client.get("/history").text
        assert "weather-briefing" in history

    def test_scan_detail_by_id(self, client):
        client.post("/scan", files=folder_upload(CORPUS / "known_bad" / "shell_exec"), follow_redirects=True)
        assert client.get("/scan/1").status_code == 200

    def test_missing_scan_404s(self, client):
        assert client.get("/scan/999").status_code == 404
