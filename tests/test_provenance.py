"""Opt-in GitHub provenance: verified data lifts the offline N/A; every
failure path degrades to None so the deterministic 'not verified' stands."""

from datetime import datetime, timedelta, timezone

import pytest

from app.scan import scan_artifact
from scanning import provenance, rubric
from tests import fixtures

NOW = datetime(2026, 7, 7, tzinfo=timezone.utc)


def fake_fetch(payload):
    def _fetch(url):
        return payload

    return _fetch


GOOD_REPO = {
    "full_name": "example/notes-server",
    "pushed_at": (NOW - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "open_issues_count": 4,
    "archived": False,
    "license": {"spdx_id": "MIT"},
}


class TestFetchGithubProvenance:
    def test_healthy_repo_produces_verified_report(self):
        report = provenance.fetch_github_provenance(
            "https://github.com/example/notes-server", fetch_json=fake_fetch(GOOD_REPO), now=NOW
        )
        assert report.verified is True
        assert report.days_since_push == 10
        assert report.open_issues == 4
        assert report.license_id == "MIT"

    def test_non_github_url_returns_none(self):
        assert (
            provenance.fetch_github_provenance(
                "https://gitlab.com/x/y", fetch_json=fake_fetch(GOOD_REPO), now=NOW
            )
            is None
        )

    def test_fetch_failure_returns_none(self):
        def boom(url):
            raise OSError("network down")

        assert (
            provenance.fetch_github_provenance(
                "https://github.com/example/notes-server", fetch_json=boom, now=NOW
            )
            is None
        )

    def test_malformed_payload_returns_none(self):
        assert (
            provenance.fetch_github_provenance(
                "https://github.com/example/notes-server",
                fetch_json=fake_fetch({"unexpected": "shape"}),
                now=NOW,
            )
            is None
        )

    def test_maybe_fetch_is_noop_without_token(self, monkeypatch):
        # Opt-in gate: no GITHUB_TOKEN (conftest clears it) -> no attempt.
        assert provenance.maybe_fetch_provenance(fixtures.CLEAN_MANIFEST) is None


class TestProvenanceScoring:
    def test_verified_healthy_repo_scores_100_and_lifts_cap(self):
        report = provenance.fetch_github_provenance(
            "https://github.com/example/notes-server", fetch_json=fake_fetch(GOOD_REPO), now=NOW
        )
        result = scan_artifact(fixtures.clean_artifact(), provenance_report=report)
        assert result.verdict == rubric.VERDICT_APPROVED  # cap lifted
        assert result.score == 100
        assert result.rubric.assessed_weight == 100
        maintenance = next(
            c for c in result.rubric.categories if c.category == rubric.CATEGORY_MAINTENANCE
        )
        assert maintenance.unverified is False
        assert maintenance.score == 100

    def test_stale_archived_repo_scores_low(self):
        stale = dict(
            GOOD_REPO,
            pushed_at=(NOW - timedelta(days=700)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            archived=True,
            open_issues_count=300,
            license=None,
        )
        report = provenance.fetch_github_provenance(
            "https://github.com/example/notes-server", fetch_json=fake_fetch(stale), now=NOW
        )
        cat = rubric.score_maintenance_provenance(fixtures.clean_artifact(), report)
        assert cat.unverified is False
        assert cat.score == 20  # repo exists (20); recency/issues/license all zero
        assert any("archived" in f for f in cat.findings)

    def test_moderately_stale_repo_gets_partial_recency(self):
        aging = dict(GOOD_REPO, pushed_at=(NOW - timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        report = provenance.fetch_github_provenance(
            "https://github.com/example/notes-server", fetch_json=fake_fetch(aging), now=NOW
        )
        cat = rubric.score_maintenance_provenance(fixtures.clean_artifact(), report)
        assert cat.score == 80  # 20 recency instead of 40

    def test_no_report_keeps_offline_na_behavior(self):
        result = scan_artifact(fixtures.clean_artifact())
        assert result.verdict == rubric.VERDICT_CONDITIONS
        assert result.rubric.assessed_weight == 75
