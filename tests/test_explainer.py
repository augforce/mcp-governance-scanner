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


class TestFindingTranslations:
    # One representative engine string per translation pattern -> the plain
    # sentence it must produce. This is the closed set rubric.py can emit.
    CASES = [
        (
            "No permission declarations in the manifest — requested access cannot be assessed.",
            "The server never says what file or internet access it wants, so its requests can't be judged.",
        ),
        (
            "Wildcard or unbounded filesystem grant: '*'",
            "It asks for sweeping file access ('*') instead of just the specific folders it needs.",
        ),
        (
            "Wildcard network grant: '*.example.com'",
            "It asks for broad internet access ('*.example.com') instead of naming the specific sites it needs.",
        ),
        (
            "No tools declared in the manifest.",
            "The server doesn't describe any tools, so there is nothing to check its behavior against.",
        ),
        (
            "Tool 'do_task' has a missing or vague description.",
            "The tool 'do_task' doesn't explain what it does.",
        ),
        (
            "Tool 'do_task' declares no input schema.",
            "The tool 'do_task' doesn't say what input it expects.",
        ),
        (
            "Tool 'do_task' has no input constraints or validation.",
            "The tool 'do_task' accepts anything sent to it, with no checks or limits.",
        ),
        (
            "Broad network scope: '*'",
            "Its declared internet access ('*') covers far more sites than a single purpose needs.",
        ),
        (
            "4 distinct network hosts declared — each third-party data flow widens exposure.",
            "It talks to 4 different internet services — each one is another place your data can go.",
        ),
        (
            "server.py:13 — network call destination is not statically determinable "
            "('resp = requests.post(base)'); requires manual review against the disclosed endpoints.",
            "At server.py:13, the code builds an internet address while running, so we can't "
            "confirm where it sends data — a person should check this.",
        ),
        (
            "Manifest field 'author' claimed as 'anon' — not independently verified.",
            "It says its author is 'anon', but nothing confirms that claim.",
        ),
        (
            "Manifest field 'license' missing — provenance not verified.",
            "It doesn't state its license at all.",
        ),
        (
            "Repository verified on GitHub: example/notes-server.",
            "Its code repository was found on GitHub and matches what it claims (example/notes-server).",
        ),
        (
            "Repository is archived — no active maintenance.",
            "The project is archived — nobody maintains it anymore.",
        ),
        (
            "Last push 200 days ago — aging maintenance.",
            "The code was last updated 200 days ago — it may be falling out of date.",
        ),
        (
            "Last push 900 days ago — effectively unmaintained.",
            "The code hasn't been touched in 900 days — it is effectively abandoned.",
        ),
        (
            "120 open issues.",
            "It has 120 unresolved problem reports.",
        ),
        (
            "300 open issues — significant unaddressed backlog.",
            "It has 300 unresolved problem reports — a large backlog nobody is addressing.",
        ),
        (
            "No license detected on the repository.",
            "The project publishes no license, so its terms of use are unclear.",
        ),
    ]

    def test_every_engine_finding_translates(self):
        from analysis.explainer import _plain_finding

        for engine_text, plain_text in self.CASES:
            assert _plain_finding(engine_text) == plain_text

    def test_unknown_finding_returns_none(self):
        from analysis.explainer import _plain_finding

        assert _plain_finding("Some future finding the engine grew later.") is None

    def test_finding_lines_keep_engine_text_as_evidence(self):
        from analysis.explainer import _finding_lines

        lines = _finding_lines("Wildcard network grant: '*'")
        assert lines[0].startswith("- It asks for broad internet access")
        assert lines[1] == "  - Evidence: Wildcard network grant: '*'"

    def test_finding_lines_fall_back_verbatim(self):
        from analysis.explainer import _finding_lines

        assert _finding_lines("Mystery finding.") == ["- Mystery finding."]

    def test_join_reasons(self):
        from analysis.explainer import _join_reasons

        assert _join_reasons(["a"]) == "a"
        assert _join_reasons(["a", "b"]) == "a; and b"
        assert _join_reasons(["a", "b", "c"]) == "a; b; and c"


class TestPlainFailReport:
    def test_bottom_line_states_plain_reason(self):
        report = explain(scan_artifact(fixtures.hardcoded_credentials_artifact()))
        assert "**Bottom line:**" in report
        assert "fails automatically" in report
        assert "secret key or password is written directly into its code" in report

    def test_gate_section_keeps_evidence(self):
        report = explain(scan_artifact(fixtures.shell_injection_artifact()))
        assert "without checking it first" in report
        # Technical evidence still cited: file:line and the offending snippet.
        assert "shell_tool.py:5" in report
        assert "os.system" in report

    def test_single_gate_states_plain_reason_only_once(self):
        # The Bottom line already gives the plain reason; a lone gate section
        # must not repeat it verbatim as an intro.
        report = explain(scan_artifact(fixtures.hardcoded_credentials_artifact()))
        assert "In plain terms:" not in report
        assert report.count("written directly into its code") == 1

    def _multi_gate_report(self):
        from scanning.models import ServerArtifact

        art = fixtures.hardcoded_credentials_artifact()
        files = dict(art.source_files)
        files["debug.py"] = fixtures.CREDENTIAL_ECHO_SOURCE
        return explain(scan_artifact(ServerArtifact(manifest=art.manifest, source_files=files)))

    def test_multiple_gates_all_named_in_bottom_line(self):
        report = self._multi_gate_report()
        assert "written directly into its code" in report
        assert "output or logs" in report

    def test_multiple_gates_keep_per_section_intros(self):
        # With several gates, each section's intro says which plain reason
        # belongs to which gate.
        report = self._multi_gate_report()
        assert report.count("In plain terms:") == 2


class TestPlainScoredReport:
    def _low_scoring_artifact(self):
        import copy

        from scanning.models import ServerArtifact

        manifest = copy.deepcopy(fixtures.CLEAN_MANIFEST)
        manifest["permissions"]["filesystem"] = ["*"]
        manifest["permissions"]["network"] = ["*"]
        manifest["tools"] = [{"name": "do_task"}]
        return ServerArtifact(manifest=manifest, source_files={"server.py": fixtures.CLEAN_SOURCE})

    def test_bottom_line_names_score_band_and_worst_categories(self):
        report = explain(scan_artifact(self._low_scoring_artifact()))
        assert "**Bottom line:**" in report
        assert "out of 100" in report
        assert "a person should review it" in report          # Review Required band
        assert "The biggest problems:" in report
        # tool_hygiene scores 0 -> named first; permission_scope 30 -> second.
        assert "don't clearly say what they do" in report
        assert "more access than its tools appear to need" in report

    def test_scores_are_rounded_whole_numbers(self):
        report = explain(scan_artifact(self._low_scoring_artifact()))
        assert ".6667" not in report
        assert ".0/100" not in report

    def test_unverified_publisher_named_in_bottom_line(self):
        report = explain(scan_artifact(fixtures.clean_artifact()))
        assert "could not confirm who publishes or maintains this server" in report

    def test_category_headings_carry_plain_questions(self):
        report = explain(scan_artifact(fixtures.clean_artifact()))
        assert "Does it ask for only the access it needs?" in report
        assert "Do its tools say what they do and check their inputs?" in report

    def test_findings_rendered_plain_with_evidence(self):
        report = explain(scan_artifact(self._low_scoring_artifact()))
        assert "It asks for sweeping file access ('*')" in report
        assert "  - Evidence: Wildcard or unbounded filesystem grant: '*'" in report

    def test_clean_categories_say_no_problems_found(self):
        report = explain(scan_artifact(fixtures.clean_artifact()))
        assert "No problems found." in report
