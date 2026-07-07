"""upload provider: ingest explicitly uploaded files into a ServerArtifact."""

import json

import pytest

from providers.upload import IngestError, ingest_upload


class TestUploadIngestion:
    def test_manifest_identified_and_parsed(self):
        artifact = ingest_upload(
            {
                "manifest.json": json.dumps({"name": "svc", "version": "1.0"}),
                "server.py": "x = 1\n",
            }
        )
        assert artifact.manifest["name"] == "svc"
        assert "manifest.json" not in artifact.source_files
        assert "server.py" in artifact.source_files

    def test_yaml_manifest_supported(self):
        artifact = ingest_upload({"manifest.yaml": "name: svc\n", "s.py": "x = 1\n"})
        assert artifact.manifest["name"] == "svc"

    def test_markdown_goes_to_docs(self):
        artifact = ingest_upload(
            {
                "manifest.json": json.dumps({"name": "svc"}),
                "README.md": "Talks to https://api.example.com.",
            }
        )
        assert "README.md" in artifact.docs
        assert "README.md" not in artifact.source_files

    def test_every_non_manifest_non_doc_upload_is_source(self):
        # Uploads are deliberate — no extension filtering like the dir sweep.
        artifact = ingest_upload(
            {
                "manifest.json": json.dumps({"name": "svc"}),
                "settings.conf": "endpoint=https://cfg.example.com\n",
                ".env.example": "API_URL=https://cfg.example.com\n",
            }
        )
        assert "settings.conf" in artifact.source_files
        assert ".env.example" in artifact.source_files

    def test_bytes_content_decoded(self):
        artifact = ingest_upload(
            {"manifest.json": json.dumps({"name": "svc"}).encode(), "s.py": b"x = 1\n"}
        )
        assert artifact.manifest["name"] == "svc"
        assert artifact.source_files["s.py"] == "x = 1\n"

    def test_missing_manifest_gets_minimal_fallback(self):
        artifact = ingest_upload({"server.py": "x = 1\n"})
        assert artifact.manifest == {"name": "uploaded-server"}

    def test_undecodable_upload_is_an_error_not_silently_dropped(self):
        with pytest.raises(IngestError, match="blob.bin"):
            ingest_upload({"blob.bin": b"\xff\xfe\x00\x01"})

    def test_empty_upload_rejected(self):
        with pytest.raises(IngestError):
            ingest_upload({})
