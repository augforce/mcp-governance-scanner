"""Labeled regression corpus — the scanner's ground truth.

Known-good: vendored Anthropic reference servers (MIT) with authored intake
manifests, plus the author's real MCP servers scanned in place. The real
servers' source and intake manifests are deliberately NOT part of this repo:
they are declared in corpus/intake/local_servers.json (gitignored, machine-
local), and those tests skip cleanly anywhere the config or directories are
absent.

Known-bad: hand-built servers that each trip exactly one gate, or score
poorly with no gate — they exist to prove the scanner catches real problems.
"""

import json
from pathlib import Path

import pytest

from app.scan import scan_directory
from scanning import rubric

CORPUS = Path(__file__).resolve().parent.parent / "corpus"
_LOCAL_CONFIG = CORPUS / "intake" / "local_servers.json"


def _local_servers() -> dict[str, tuple[Path, Path]]:
    """Machine-local real-world servers: {name: {"root": ..., "manifest": ...}}."""
    if not _LOCAL_CONFIG.is_file():
        return {}
    config = json.loads(_LOCAL_CONFIG.read_text())
    return {
        name: (Path(entry["root"]).expanduser(), Path(entry["manifest"]).expanduser())
        for name, entry in config.items()
    }


LOCAL_SERVERS = _local_servers()


class TestKnownGood:
    def test_anthropic_time_server(self):
        result = scan_directory(CORPUS / "known_good" / "anthropic_time")
        assert result.gate_findings == ()
        assert result.verdict == rubric.VERDICT_CONDITIONS  # provenance cap
        assert result.score == 100

    def test_anthropic_fetch_server(self):
        # Honest wildcard network declaration (-30 in scope, -30 exposure)
        # for a server whose whole purpose is fetching arbitrary URLs.
        result = scan_directory(CORPUS / "known_good" / "anthropic_fetch")
        assert result.gate_findings == ()
        assert result.verdict == rubric.VERDICT_CONDITIONS
        assert 60 <= result.score < 85

    @pytest.mark.parametrize(
        "name", sorted(LOCAL_SERVERS) or ["no-local-servers-configured"]
    )
    def test_local_real_world_servers(self, name):
        if name not in LOCAL_SERVERS:
            pytest.skip("no machine-local servers configured (corpus/intake/local_servers.json)")
        root, intake = LOCAL_SERVERS[name]
        if not root.is_dir():
            pytest.skip(f"{name} not present on this machine")
        result = scan_directory(root, manifest_path=intake)
        assert result.gate_findings == ()
        assert result.verdict == rubric.VERDICT_CONDITIONS
        assert result.score >= 85  # strong on everything assessable offline


class TestKnownBad:
    @pytest.mark.parametrize(
        ("server", "expected_gate"),
        [
            ("hardcoded_key", "hardcoded_credentials"),
            ("shell_exec", "unvalidated_input"),
            ("covert_telemetry", "undisclosed_network_calls"),
        ],
    )
    def test_gate_trippers_fail_on_exactly_their_gate(self, server, expected_gate):
        result = scan_directory(CORPUS / "known_bad" / server)
        assert result.verdict == rubric.VERDICT_FAIL
        assert {f.gate for f in result.gate_findings} == {expected_gate}

    def test_overbroad_access_reviews_without_any_gate(self):
        result = scan_directory(CORPUS / "known_bad" / "overbroad_access")
        assert result.gate_findings == ()
        assert result.verdict == rubric.VERDICT_REVIEW
        assert result.score < 60
