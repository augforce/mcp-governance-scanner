"""Deterministic explainer: offline prose for every finding, no API needed."""

from analysis.explainer import explain
from app.scan import scan_artifact
from tests import fixtures


class TestGateFailReport:
    def test_fail_report_explains_the_gate_with_citation(self):
        report = explain(scan_artifact(fixtures.hardcoded_credentials_artifact()))
        assert "Fail" in report
        assert "Hardcoded credentials" in report
        assert "auth.py:1" in report
        assert "sk-live" in report  # cites the offending snippet
        assert "regardless of" in report  # states that gates override scoring

    def test_fail_report_has_no_category_scores(self):
        report = explain(scan_artifact(fixtures.hardcoded_credentials_artifact()))
        assert "Permission & Scope" not in report


class TestScoredReport:
    def test_clean_report_headline_and_categories(self):
        report = explain(scan_artifact(fixtures.clean_artifact()))
        assert "Approved with Conditions" in report
        assert "100" in report
        assert "75/100" in report  # assessed-weight disclosure
        for label in ("Permission & Scope", "Tool Definition Hygiene", "Network & Data Exposure"):
            assert label in report

    def test_unverified_provenance_labeled_na_and_explains_cap(self):
        report = explain(scan_artifact(fixtures.clean_artifact()))
        assert "Maintenance & Provenance" in report
        assert "N/A" in report
        assert "not independently verified" in report
        assert "condition" in report.lower()  # why the verdict is capped

    def test_category_findings_included(self):
        import copy

        from scanning.models import ServerArtifact

        manifest = copy.deepcopy(fixtures.CLEAN_MANIFEST)
        manifest["permissions"]["filesystem"] = ["*"]
        report = explain(
            scan_artifact(
                ServerArtifact(
                    manifest=manifest, source_files={"server.py": fixtures.CLEAN_SOURCE}
                )
            )
        )
        assert "Wildcard or unbounded filesystem grant" in report

    def test_conditions_section_names_each_specific_reason(self):
        # A wildcard-access case must not read identically to a provenance-
        # only case: every condition is tied to its actual cause.
        import copy

        from scanning.models import ServerArtifact

        manifest = copy.deepcopy(fixtures.CLEAN_MANIFEST)
        manifest["permissions"]["network"] = ["*"]
        dynamic_source = (
            'import os\nimport requests\n\n\ndef call(p):\n'
            '    return requests.get(os.environ["API"] + p)\n'
        )
        report = explain(
            scan_artifact(
                ServerArtifact(
                    manifest=manifest,
                    source_files={"server.py": fixtures.CLEAN_SOURCE, "dyn.py": dynamic_source},
                )
            )
        )
        assert "## Conditions" in report
        assert "Wildcard network grant: '*'" in report  # the broad-scope condition
        assert "runtime-built network call destinations" in report  # manual-review condition
        assert "verify provenance" in report.lower()  # provenance condition still present
        # The same '*' grant is flagged by two categories; it is ONE condition.
        assert report.count("broad access grant") == 1

    def test_provenance_only_case_has_single_condition(self):
        report = explain(scan_artifact(fixtures.clean_artifact()))
        assert "## Conditions" in report
        assert "verify provenance" in report.lower()
        assert "Wildcard" not in report
        assert "runtime-built" not in report

    def test_output_is_deterministic(self):
        a = explain(scan_artifact(fixtures.clean_artifact()))
        b = explain(scan_artifact(fixtures.clean_artifact()))
        assert a == b
