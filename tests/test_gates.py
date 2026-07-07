"""Each hard gate fires correctly, independently, and not on clean input."""

import pytest

from scanning import gates
from tests import fixtures

ALL_CHECKS = {
    gates.GATE_HARDCODED_CREDENTIALS: gates.check_hardcoded_credentials,
    gates.GATE_UNVALIDATED_INPUT: gates.check_unvalidated_input,
    gates.GATE_UNDISCLOSED_NETWORK: gates.check_undisclosed_network_calls,
    gates.GATE_CREDENTIAL_ECHO: gates.check_credential_echo,
}


def assert_only_gate_fires(artifact, expected_gate):
    """The expected gate finds something; the other three stay silent."""
    for gate_name, check in ALL_CHECKS.items():
        findings = check(artifact)
        if gate_name == expected_gate:
            assert findings, f"{gate_name} should have fired"
            assert all(f.gate == expected_gate for f in findings)
        else:
            assert findings == [], f"{gate_name} fired unexpectedly: {findings}"


class TestCleanServer:
    def test_no_gate_fires_on_clean_artifact(self):
        artifact = fixtures.clean_artifact()
        for gate_name, check in ALL_CHECKS.items():
            assert check(artifact) == [], f"{gate_name} fired on clean input"

    def test_run_gates_returns_empty_on_clean_artifact(self):
        assert gates.run_gates(fixtures.clean_artifact()) == []


class TestHardcodedCredentials:
    def test_fires_on_hardcoded_key_in_source(self):
        assert_only_gate_fires(
            fixtures.hardcoded_credentials_artifact(), gates.GATE_HARDCODED_CREDENTIALS
        )

    def test_fires_on_credential_in_manifest(self):
        findings = gates.check_hardcoded_credentials(fixtures.hardcoded_manifest_artifact())
        assert findings
        assert any(f.file == "manifest" for f in findings)

    def test_finding_cites_file_and_line(self):
        findings = gates.check_hardcoded_credentials(fixtures.hardcoded_credentials_artifact())
        f = findings[0]
        assert f.file == "auth.py"
        assert f.line == 1
        assert "sk-live" in f.snippet

    def test_setenv_test_fixture_is_not_a_credential(self):
        # Real-world calibration: servers' own test suites set fake keys via
        # monkeypatch.setenv / os.environ writes. Environment writes are the
        # same approved family as environment reads.
        art = fixtures.artifact_with_source(
            'def test_key_isolation(monkeypatch):\n'
            '    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-shell-key-belongs-to-other-tools")\n',
            "tests/test_keys.py",
        )
        assert gates.check_hardcoded_credentials(art) == []

    def test_env_var_lookup_is_not_a_credential(self):
        # The clean server reads its key from the environment — that is the
        # approved pattern and must not trip the gate.
        assert gates.check_hardcoded_credentials(fixtures.clean_artifact()) == []


class TestVendoredFileScope:
    def test_vendored_files_exempt_from_credential_gate_only(self):
        # A bundled asset full of secret-shaped strings must not trip the
        # credential gate — but an undisclosed network call or an injection
        # sink inside it absolutely must still be caught.
        from scanning.models import ServerArtifact

        base = fixtures.clean_artifact()
        bundle = (
            'var key = "sk-abcdef1234567890abcdef99";\n'
            'fetch("https://sneaky.cdn-metrics.example/v1/beacon");\n'
        )
        art = ServerArtifact(
            manifest=base.manifest,
            source_files={**base.source_files, "static/vendor/bundle.min.js": bundle},
            vendored=("static/vendor/bundle.min.js",),
        )
        assert gates.check_hardcoded_credentials(art) == []
        network = gates.check_undisclosed_network_calls(art)
        assert any("sneaky.cdn-metrics.example" in f.snippet for f in network)

    def test_same_content_unvendored_trips_credential_gate(self):
        # Control: the exemption is the vendored marking, not the content.
        art = fixtures.artifact_with_source(
            'var key = "sk-abcdef1234567890abcdef99";\n', "static/app.js"
        )
        assert gates.check_hardcoded_credentials(art)


class TestUnvalidatedInput:
    @pytest.mark.parametrize(
        "artifact_builder",
        [
            fixtures.shell_injection_artifact,
            fixtures.path_injection_artifact,
            fixtures.sql_injection_artifact,
        ],
        ids=["shell", "path", "sql"],
    )
    def test_fires_on_each_injection_sink(self, artifact_builder):
        assert_only_gate_fires(artifact_builder(), gates.GATE_UNVALIDATED_INPUT)

    def test_parameterized_query_and_list_subprocess_are_safe(self):
        # Clean source uses execute("... ?", params) and subprocess.run([...]).
        assert gates.check_unvalidated_input(fixtures.clean_artifact()) == []


class TestUndisclosedNetworkCalls:
    def test_fires_on_endpoint_absent_from_manifest(self):
        assert_only_gate_fires(
            fixtures.undisclosed_network_artifact(), gates.GATE_UNDISCLOSED_NETWORK
        )

    def test_finding_names_the_undisclosed_host(self):
        findings = gates.check_undisclosed_network_calls(
            fixtures.undisclosed_network_artifact()
        )
        assert any("telemetry.evil-analytics.io" in f.snippet for f in findings)

    def test_disclosed_endpoint_is_allowed(self):
        # api.example.com is declared in manifest permissions.network.
        assert gates.check_undisclosed_network_calls(fixtures.clean_artifact()) == []

    def test_spec_namespace_urls_are_not_network_calls(self):
        # Real-world calibration: XML/JSON-schema namespace identifiers
        # (http://www.w3.org/2000/svg, https://json-schema.org/...) are spec
        # references, not endpoints the server contacts.
        art = fixtures.artifact_with_source(
            'SVG_NS = "http://www.w3.org/2000/svg"\n'
            'SCHEMA = "https://json-schema.org/draft/2020-12/schema"\n',
            "ns.py",
        )
        assert gates.check_undisclosed_network_calls(art) == []

    def test_endpoint_named_in_docs_counts_as_disclosed(self):
        # The gate spec: "endpoints not named in the server's
        # documentation/manifest" — a host in the README is disclosed.
        from scanning.models import ServerArtifact

        art = fixtures.artifact_with_source(
            'import requests\n\ndef geocode(q):\n    return requests.get("https://geo.example.org/v1/lookup", params={"q": q})\n',
            "geo.py",
        )
        undocumented = ServerArtifact(manifest=art.manifest, source_files=art.source_files)
        assert gates.check_undisclosed_network_calls(undocumented)  # not in manifest -> fires

        documented = ServerArtifact(
            manifest=art.manifest,
            source_files=art.source_files,
            docs={"README.md": "Geocoding is served by https://geo.example.org/v1/lookup."},
        )
        assert gates.check_undisclosed_network_calls(documented) == []


class TestCredentialEcho:
    def test_fires_on_printed_and_logged_credentials(self):
        artifact = fixtures.credential_echo_artifact()
        assert_only_gate_fires(artifact, gates.GATE_CREDENTIAL_ECHO)
        findings = gates.check_credential_echo(artifact)
        # Both the print() and the logger.error() lines should be caught.
        assert len(findings) >= 2

    def test_plain_logging_is_safe(self):
        assert gates.check_credential_echo(fixtures.clean_artifact()) == []


class TestRunGates:
    def test_aggregates_findings_across_gates(self):
        # Combine two violations in one artifact; run_gates reports both.
        art = fixtures.artifact_with_source(fixtures.HARDCODED_KEY_SOURCE, "auth.py")
        files = dict(art.source_files)
        files["shell_tool.py"] = fixtures.SHELL_INJECTION_SOURCE
        from scanning.models import ServerArtifact

        combined = ServerArtifact(manifest=art.manifest, source_files=files)
        tripped = {f.gate for f in gates.run_gates(combined)}
        assert tripped == {gates.GATE_HARDCODED_CREDENTIALS, gates.GATE_UNVALIDATED_INPUT}
