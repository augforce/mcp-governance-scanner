"""Rubric config validation, category scoring, weighted total, and bands."""

import copy

import pytest

from scanning import rubric
from scanning.models import ServerArtifact
from tests import fixtures


def artifact_with_manifest(mutate):
    manifest = copy.deepcopy(fixtures.CLEAN_MANIFEST)
    mutate(manifest)
    return ServerArtifact(manifest=manifest, source_files={"server.py": fixtures.CLEAN_SOURCE})


class TestConfig:
    def test_default_config_loads_and_weights_sum_to_100(self):
        config = rubric.load_rubric_config()
        assert sum(config["weights"].values()) == 100
        assert set(config["weights"]) == {
            rubric.CATEGORY_PERMISSION_SCOPE,
            rubric.CATEGORY_TOOL_HYGIENE,
            rubric.CATEGORY_NETWORK_EXPOSURE,
            rubric.CATEGORY_MAINTENANCE,
        }

    def test_weights_not_summing_to_100_rejected(self, tmp_path):
        bad = tmp_path / "rubric.yaml"
        bad.write_text(
            "weights:\n"
            "  permission_scope: 30\n"
            "  tool_hygiene: 25\n"
            "  network_exposure: 20\n"
            "  maintenance_provenance: 20\n"  # sums to 95
            "bands:\n  approved_min: 85\n  conditions_min: 60\n"
        )
        with pytest.raises(rubric.RubricConfigError):
            rubric.load_rubric_config(bad)

    def test_missing_category_rejected(self, tmp_path):
        bad = tmp_path / "rubric.yaml"
        bad.write_text(
            "weights:\n"
            "  permission_scope: 50\n"
            "  tool_hygiene: 50\n"
            "bands:\n  approved_min: 85\n  conditions_min: 60\n"
        )
        with pytest.raises(rubric.RubricConfigError):
            rubric.load_rubric_config(bad)


class TestPermissionScope:
    def test_scoped_grants_score_100(self):
        result = rubric.score_permission_scope(fixtures.clean_artifact())
        assert result.score == 100
        assert result.findings == ()

    def test_wildcard_filesystem_deducted(self):
        art = artifact_with_manifest(lambda m: m["permissions"].update(filesystem=["*"]))
        result = rubric.score_permission_scope(art)
        assert result.score == 60
        assert any("filesystem" in f for f in result.findings)

    def test_root_filesystem_grant_deducted(self):
        art = artifact_with_manifest(lambda m: m["permissions"].update(filesystem=["/"]))
        assert rubric.score_permission_scope(art).score == 60

    def test_wildcard_network_deducted(self):
        art = artifact_with_manifest(lambda m: m["permissions"].update(network=["*"]))
        result = rubric.score_permission_scope(art)
        assert result.score == 70
        assert any("network" in f for f in result.findings)

    def test_wildcards_stack(self):
        art = artifact_with_manifest(
            lambda m: m["permissions"].update(filesystem=["*"], network=["*"])
        )
        assert rubric.score_permission_scope(art).score == 30

    def test_missing_permission_declarations_scores_50(self):
        art = artifact_with_manifest(lambda m: m.pop("permissions"))
        result = rubric.score_permission_scope(art)
        assert result.score == 50
        assert result.findings  # must be called out, never silently passed


class TestToolHygiene:
    def test_specific_tools_with_constraints_score_100(self):
        assert rubric.score_tool_hygiene(fixtures.clean_artifact()).score == 100

    def test_vague_tool_without_schema_scores_0(self):
        art = artifact_with_manifest(
            lambda m: m.update(tools=[{"name": "do_stuff", "description": "runs"}])
        )
        result = rubric.score_tool_hygiene(art)
        assert result.score == 0
        assert result.findings

    def test_mixed_tools_average(self):
        def mutate(m):
            m["tools"].append({"name": "do_stuff", "description": "runs"})

        art = artifact_with_manifest(mutate)
        # Two perfect tools + one zero-scoring tool -> average 200/3.
        assert rubric.score_tool_hygiene(art).score == pytest.approx(200 / 3)

    def test_no_tools_declared_scores_0(self):
        art = artifact_with_manifest(lambda m: m.update(tools=[]))
        result = rubric.score_tool_hygiene(art)
        assert result.score == 0
        assert result.findings


class TestNetworkExposure:
    def test_single_disclosed_host_scores_100(self):
        assert rubric.score_network_exposure(fixtures.clean_artifact()).score == 100

    def test_no_network_access_scores_100(self):
        art = artifact_with_manifest(lambda m: m["permissions"].update(network=[]))
        assert rubric.score_network_exposure(art).score == 100

    def test_wildcard_scope_deducted(self):
        art = artifact_with_manifest(lambda m: m["permissions"].update(network=["*"]))
        result = rubric.score_network_exposure(art)
        assert result.score == 70
        assert result.findings

    def test_many_hosts_deducted(self):
        art = artifact_with_manifest(
            lambda m: m["permissions"].update(
                network=["a.example.com", "b.example.com", "c.example.com", "d.example.com"]
            )
        )
        # Two hosts beyond the first two -> -10 each.
        result = rubric.score_network_exposure(art)
        assert result.score == 80
        assert result.findings


class TestDynamicDestinationFlag:
    # Runtime-assembled URLs (env vars, concat, f-strings) can't be checked
    # against the manifest statically. That is a documented limitation of the
    # hard gate; here we make it visible as a SOFT flag — a Network & Data
    # Exposure deduction marked "requires manual review" — never a hard fail,
    # because env-based endpoint config is legitimate practice.

    def test_env_built_url_soft_flagged_not_gated(self):
        art = fixtures.artifact_with_source(
            'import os\nimport requests\n\n\ndef call_api(path):\n'
            '    return requests.get(os.environ["API_BASE_URL"] + path)\n',
            "dyn.py",
        )
        from scanning import gates

        assert gates.check_undisclosed_network_calls(art) == []  # gate silent
        result = rubric.score_network_exposure(art)
        assert result.score == 85
        assert any("not statically determinable" in f and "dyn.py" in f for f in result.findings)

    def test_fstring_url_soft_flagged(self):
        art = fixtures.artifact_with_source(
            'import requests\n\n\ndef call(host):\n'
            '    return requests.get(f"https://{host}/v1/data")\n',
            "dyn.py",
        )
        assert rubric.score_network_exposure(art).score == 85

    def test_javascript_fetch_with_variable_flagged(self):
        art = fixtures.artifact_with_source(
            "async function call(endpoint) {\n  return await fetch(endpoint);\n}\n",
            "client.ts",
        )
        assert rubric.score_network_exposure(art).score == 85

    def test_literal_urls_not_flagged(self):
        # The clean fixture calls requests.get("https://api.example.com/...").
        result = rubric.score_network_exposure(fixtures.clean_artifact())
        assert result.score == 100
        assert result.findings == ()

    def test_commented_out_network_call_not_soft_flagged(self):
        # Same principle as the network gate: a call in a comment is not a
        # call the program makes, so it needs no manual review.
        art = fixtures.artifact_with_source(
            "# resp = requests.post(base + path)\n"
            "// return await fetch(endpoint);\n",
            "dead_code.py",
        )
        result = rubric.score_network_exposure(art)
        assert result.score == 100
        assert result.findings == ()

    def test_deduction_applied_once_and_stacks_with_broad_scope(self):
        source = (
            'import os\nimport requests\n\n\ndef a(p):\n'
            '    return requests.get(os.environ["A"] + p)\n\n\ndef b(p):\n'
            '    return requests.post(os.environ["B"] + p)\n'
        )
        art = artifact_with_manifest(lambda m: m["permissions"].update(network=["*"]))
        art = ServerArtifact(
            manifest=art.manifest,
            source_files={**art.source_files, "dyn.py": source},
        )
        result = rubric.score_network_exposure(art)
        # -30 wildcard, -15 dynamic destinations (flat, not per call).
        assert result.score == 55
        assert sum("not statically determinable" in f for f in result.findings) == 2


class TestMaintenanceProvenance:
    # Offline, this category is self-reported metadata only. It must never
    # produce a confident score from the server's own claims: it is N/A
    # (unverified) until Phase 3's independent provenance check runs.

    def test_offline_provenance_is_unverified_not_scored(self):
        result = rubric.score_maintenance_provenance(fixtures.clean_artifact())
        assert result.unverified is True
        assert result.score is None

    def test_manifest_fields_reported_as_unverified_claims(self):
        result = rubric.score_maintenance_provenance(fixtures.clean_artifact())
        assert any("repository" in f and "claimed" in f for f in result.findings)
        assert any("not independently verified" in f for f in result.findings)

    def test_missing_fields_still_called_out(self):
        def mutate(m):
            for key in ("repository", "author", "version", "license"):
                m.pop(key)

        result = rubric.score_maintenance_provenance(artifact_with_manifest(mutate))
        assert result.unverified is True
        assert result.score is None
        for field in ("repository", "author", "version", "license"):
            assert any(field in f for f in result.findings)


class TestWeightedScore:
    def test_clean_artifact_scores_100_on_assessed_weight(self):
        score = rubric.score_rubric(fixtures.clean_artifact())
        # Maintenance is N/A offline; the other three are perfect, so the
        # normalized total over the assessed 75 weight is still 100.
        assert score.total == 100
        assert score.assessed_weight == 75
        assert {c.category for c in score.categories} == {
            rubric.CATEGORY_PERMISSION_SCOPE,
            rubric.CATEGORY_TOOL_HYGIENE,
            rubric.CATEGORY_NETWORK_EXPOSURE,
            rubric.CATEGORY_MAINTENANCE,
        }

    def test_unverified_category_excluded_from_total(self):
        # Stripping every provenance field must not change the total —
        # unverified claims contribute nothing either way.
        def mutate(m):
            for key in ("repository", "author", "version", "license"):
                m.pop(key)

        assert rubric.score_rubric(artifact_with_manifest(mutate)).total == 100

    def test_total_is_normalized_weighted_sum_of_assessed_categories(self):
        art = artifact_with_manifest(lambda m: m["permissions"].update(filesystem=["*"]))
        config = rubric.load_rubric_config()
        score = rubric.score_rubric(art, config)
        assessed = [c for c in score.categories if not c.unverified]
        expected = (
            sum(config["weights"][c.category] * c.score / 100 for c in assessed)
            / sum(config["weights"][c.category] for c in assessed)
            * 100
        )
        # Wildcard filesystem: permission 60, hygiene 100, network 100
        # -> (18 + 25 + 20) / 75 * 100 = 84.
        assert score.total == pytest.approx(expected) == pytest.approx(84)


class TestBands:
    @pytest.mark.parametrize(
        ("score", "band"),
        [
            (100, rubric.VERDICT_APPROVED),
            (85, rubric.VERDICT_APPROVED),
            (84.9, rubric.VERDICT_CONDITIONS),
            (60, rubric.VERDICT_CONDITIONS),
            (59.9, rubric.VERDICT_REVIEW),
            (0, rubric.VERDICT_REVIEW),
        ],
    )
    def test_band_boundaries(self, score, band):
        assert rubric.band_for_score(score) == band
