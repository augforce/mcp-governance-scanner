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

    def test_has_no_path_textbox_or_upload_form(self, client):
        html = client.get("/").text
        assert 'name="path"' not in html
        assert 'name="manifest_path"' not in html
        assert "/upload" not in html


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
