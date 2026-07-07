"""Orchestrator: gates run first; a tripped gate overrides any score; an
unverified provenance category caps the verdict below plain Approved."""

import copy

from app.scan import scan_artifact
from scanning import rubric
from scanning.models import ServerArtifact
from tests import fixtures


def artifact_with_manifest(mutate):
    manifest = copy.deepcopy(fixtures.CLEAN_MANIFEST)
    mutate(manifest)
    return ServerArtifact(manifest=manifest, source_files={"server.py": fixtures.CLEAN_SOURCE})


class TestScanDirectory:
    def test_scan_directory_end_to_end(self, tmp_path):
        import json

        from app.scan import scan_directory

        (tmp_path / "manifest.json").write_text(json.dumps(fixtures.CLEAN_MANIFEST))
        (tmp_path / "server.py").write_text(fixtures.CLEAN_SOURCE)
        result = scan_directory(tmp_path)
        assert result.verdict == rubric.VERDICT_CONDITIONS
        assert result.score == 100

    def test_scan_directory_with_intake_manifest(self, tmp_path):
        import json

        from app.scan import scan_directory

        server = tmp_path / "server"
        server.mkdir()
        (server / "server.py").write_text(fixtures.CLEAN_SOURCE)
        intake = tmp_path / "intake.json"
        intake.write_text(json.dumps(fixtures.CLEAN_MANIFEST))
        result = scan_directory(server, manifest_path=intake)
        assert result.score == 100


class TestScanVerdicts:
    def test_clean_server_capped_at_conditions_offline(self):
        # Perfect on every assessed category, but provenance is self-reported
        # and unverified offline — a server must not reach plain Approved on
        # its own claims. Condition: verify provenance.
        result = scan_artifact(fixtures.clean_artifact())
        assert result.verdict == rubric.VERDICT_CONDITIONS
        assert result.score == 100
        assert result.gate_findings == ()
        maintenance = next(
            c for c in result.rubric.categories if c.category == rubric.CATEGORY_MAINTENANCE
        )
        assert maintenance.unverified is True

    def test_mid_band_server_approved_with_conditions(self):
        art = artifact_with_manifest(lambda m: m["permissions"].update(filesystem=["*"]))
        result = scan_artifact(art)
        assert result.verdict == rubric.VERDICT_CONDITIONS
        assert result.score == 84

    def test_low_scoring_server_review_required(self):
        # The provenance cap only pulls Approved down to Conditions; a server
        # that scores into the Review band stays Review Required.
        def mutate(m):
            m["permissions"].update(filesystem=["*"], network=["*"])
            m["tools"] = [{"name": "do_stuff", "description": "runs"}]

        result = scan_artifact(artifact_with_manifest(mutate))
        assert result.verdict == rubric.VERDICT_REVIEW
        assert result.score < 60

    def test_gate_trip_fails_regardless_of_score(self):
        # Same clean, perfectly-scoring server plus one hardcoded key.
        result = scan_artifact(fixtures.hardcoded_credentials_artifact())
        assert result.verdict == rubric.VERDICT_FAIL
        assert result.score is None
        assert result.rubric is None
        assert result.gate_findings
        assert result.gate_findings[0].gate == "hardcoded_credentials"
