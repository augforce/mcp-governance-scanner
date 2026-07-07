"""Scan orchestrator: ingest -> gates -> rubric -> verdict.

Pure function over an already-ingested ServerArtifact. Provenance and the
Claude explanation layer plug in here in later phases; the deterministic
result below never depends on them.
"""

from __future__ import annotations

from pathlib import Path

from scanning import rubric
from scanning.gates import run_gates
from scanning.models import ScanResult, ServerArtifact


def scan_artifact(
    artifact: ServerArtifact, config: dict | None = None, provenance_report=None
) -> ScanResult:
    """Run gates, then (only if clean) the scored rubric; return the verdict."""
    gate_findings = tuple(run_gates(artifact))
    if gate_findings:
        # A tripped gate is an automatic fail — the rubric is never consulted.
        return ScanResult(
            verdict=rubric.VERDICT_FAIL, score=None, gate_findings=gate_findings, rubric=None
        )
    if config is None:
        config = rubric.load_rubric_config()
    score = rubric.score_rubric(artifact, config, provenance_report=provenance_report)
    verdict = rubric.band_for_score(score.total, config)
    # A category we couldn't independently assess (provenance offline) caps
    # the verdict: no server reaches plain Approved on self-reported claims.
    # The condition is to verify provenance; lower bands are unaffected.
    if verdict == rubric.VERDICT_APPROVED and any(c.unverified for c in score.categories):
        verdict = rubric.VERDICT_CONDITIONS
    return ScanResult(
        verdict=verdict,
        score=score.total,
        gate_findings=(),
        rubric=score,
    )


def scan_directory(
    root: Path | str,
    manifest_path: Path | str | None = None,
    config: dict | None = None,
    with_provenance: bool = False,
) -> ScanResult:
    """Ingest a local server directory and scan it.

    with_provenance=True attempts the opt-in GitHub check; it is still a
    no-op unless GITHUB_TOKEN is set, and any failure keeps the offline
    "not verified" verdict.
    """
    from providers.local_dir import ingest

    artifact = ingest(root, manifest_path=manifest_path)
    provenance_report = None
    if with_provenance:
        from scanning.provenance import maybe_fetch_provenance

        provenance_report = maybe_fetch_provenance(artifact.manifest)
    return scan_artifact(artifact, config=config, provenance_report=provenance_report)


if __name__ == "__main__":
    import sys

    from analysis.explainer import explain

    target = sys.argv[1] if len(sys.argv) > 1 else "."
    intake = sys.argv[2] if len(sys.argv) > 2 else None
    # with_provenance is a no-op unless GITHUB_TOKEN is set (opt-in).
    print(explain(scan_directory(target, manifest_path=intake, with_provenance=True)))
