"""Web UI + scan history: routes and SQLite storage. TestClient is
in-process ASGI, so these stay fully offline."""

import json

import pytest
from fastapi.testclient import TestClient

from app import db as scan_db
from app.main import create_app
from app.scan import scan_artifact
from tests import fixtures


@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(db_path=tmp_path / "scans.db"))


@pytest.fixture
def clean_server_dir(tmp_path):
    server = tmp_path / "clean-server"
    server.mkdir()
    (server / "manifest.json").write_text(json.dumps(fixtures.CLEAN_MANIFEST))
    (server / "server.py").write_text(fixtures.CLEAN_SOURCE)
    return server


class TestDb:
    def test_save_and_get_roundtrip(self, tmp_path):
        path = tmp_path / "scans.db"
        result = scan_artifact(fixtures.clean_artifact())
        scan_id = scan_db.save_scan(path, name="notes-server", source="local", result=result, report="# Verdict")
        row = scan_db.get_scan(path, scan_id)
        assert row["name"] == "notes-server"
        assert row["verdict"] == "Approved with Conditions"
        assert row["score"] == 100
        assert row["report"] == "# Verdict"

    def test_list_scans_newest_first(self, tmp_path):
        path = tmp_path / "scans.db"
        result = scan_artifact(fixtures.clean_artifact())
        first = scan_db.save_scan(path, name="a", source="local", result=result, report="r")
        second = scan_db.save_scan(path, name="b", source="local", result=result, report="r")
        rows = scan_db.list_scans(path)
        assert [row["id"] for row in rows] == [second, first]

    def test_gate_findings_persisted(self, tmp_path):
        path = tmp_path / "scans.db"
        result = scan_artifact(fixtures.hardcoded_credentials_artifact())
        scan_id = scan_db.save_scan(path, name="bad", source="local", result=result, report="r")
        row = scan_db.get_scan(path, scan_id)
        gates = json.loads(row["gate_findings"])
        assert gates[0]["gate"] == "hardcoded_credentials"

    def test_get_missing_scan_returns_none(self, tmp_path):
        assert scan_db.get_scan(tmp_path / "scans.db", 999) is None


class TestRoutes:
    def test_index_shows_scan_form(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert "form" in response.text

    def test_scan_local_directory_end_to_end(self, client, clean_server_dir):
        response = client.post("/scan", data={"path": str(clean_server_dir)}, follow_redirects=True)
        assert response.status_code == 200
        assert "Approved with Conditions" in response.text
        assert "100" in response.text

    def test_scan_failing_server_shows_gate(self, client, tmp_path):
        server = tmp_path / "bad-server"
        server.mkdir()
        (server / "manifest.json").write_text(json.dumps(fixtures.CLEAN_MANIFEST))
        (server / "auth.py").write_text(fixtures.HARDCODED_KEY_SOURCE)
        response = client.post("/scan", data={"path": str(server)}, follow_redirects=True)
        assert "Fail" in response.text
        assert "Hardcoded credentials" in response.text

    def test_scan_invalid_path_reports_error(self, client):
        response = client.post("/scan", data={"path": "/does/not/exist"})
        assert response.status_code == 400
        assert "Not a directory" in response.text

    def test_upload_end_to_end(self, client):
        files = [
            ("files", ("manifest.json", json.dumps(fixtures.CLEAN_MANIFEST), "application/json")),
            ("files", ("server.py", fixtures.CLEAN_SOURCE, "text/x-python")),
        ]
        response = client.post("/upload", files=files, follow_redirects=True)
        assert response.status_code == 200
        assert "Approved with Conditions" in response.text

    def test_history_lists_scans(self, client, clean_server_dir):
        client.post("/scan", data={"path": str(clean_server_dir)}, follow_redirects=True)
        response = client.get("/history")
        assert response.status_code == 200
        assert "notes-server" in response.text
        assert "Approved with Conditions" in response.text

    def test_scan_detail_by_id(self, client, clean_server_dir):
        client.post("/scan", data={"path": str(clean_server_dir)}, follow_redirects=True)
        response = client.get("/scan/1")
        assert response.status_code == 200
        assert "notes-server" in response.text

    def test_missing_scan_404s(self, client):
        assert client.get("/scan/999").status_code == 404
