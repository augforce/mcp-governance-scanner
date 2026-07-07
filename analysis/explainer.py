"""Deterministic prose explanation of a scan — the default, offline narrative.

Every finding the engine produced is rendered with its citation; nothing is
generated, sampled, or fetched. The optional Claude layer (Phase 3) adds a
narrative on top of this; it never replaces it.
"""

from __future__ import annotations

from scanning import rubric
from scanning.models import ScanResult

GATE_LABELS = {
    "hardcoded_credentials": "Hardcoded credentials",
    "unvalidated_input": "Unvalidated input reaching a shell/path/query",
    "undisclosed_network_calls": "Undisclosed network calls",
    "credential_echo": "Credentials echoed in output or logs",
}

CATEGORY_LABELS = {
    rubric.CATEGORY_PERMISSION_SCOPE: "Permission & Scope",
    rubric.CATEGORY_TOOL_HYGIENE: "Tool Definition Hygiene",
    rubric.CATEGORY_NETWORK_EXPOSURE: "Network & Data Exposure",
    rubric.CATEGORY_MAINTENANCE: "Maintenance & Provenance",
}


def _explain_fail(result: ScanResult) -> str:
    lines = [
        "# Verdict: Fail",
        "",
        "One or more hard gates tripped. A tripped gate is an automatic fail "
        "regardless of how the server would have scored on the weighted rubric, "
        "so no category scores are reported.",
        "",
    ]
    for gate in sorted({f.gate for f in result.gate_findings}):
        lines.append(f"## Hard gate: {GATE_LABELS.get(gate, gate)}")
        lines.append("")
        for f in result.gate_findings:
            if f.gate != gate:
                continue
            location = f.file if f.line == 0 else f"{f.file}:{f.line}"
            lines.append(f"- **{location}** — {f.explanation}")
            lines.append(f"  - `{f.snippet}`")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _conditions(score) -> list[str]:
    """Concrete conditions for an Approved with Conditions verdict.

    Each condition is tied to its actual cause — a wildcard-access case must
    not read identically to an unverified-provenance case.
    """
    conditions = []
    all_findings = [f for c in score.categories for f in c.findings]
    seen_grants = set()
    for finding in all_findings:
        if "Wildcard" in finding or "Broad network scope" in finding or "unbounded" in finding:
            # Two categories may flag the same grant (e.g. '*'); one condition.
            grant = finding.rsplit(":", 1)[-1].strip()
            if grant in seen_grants:
                continue
            seen_grants.add(grant)
            conditions.append(
                f"Review whether this broad access grant is actually required, and scope "
                f"it down if not: {finding}"
            )
    if any("not statically determinable" in f for f in all_findings):
        conditions.append(
            "Manually review the runtime-built network call destinations flagged under "
            "Network & Data Exposure against the disclosed endpoints."
        )
    unverified = [c for c in score.categories if c.unverified]
    if unverified:
        labels = ", ".join(CATEGORY_LABELS[c.category] for c in unverified)
        conditions.append(
            f"Independently verify provenance ({labels}) via the opt-in GitHub check or "
            "manual review — self-reported manifest claims are never accepted as evidence "
            "of legitimacy."
        )
    return conditions


def _explain_scored(result: ScanResult) -> str:
    score = result.rubric
    assessed = int(score.assessed_weight)
    lines = [
        f"# Verdict: {result.verdict}",
        "",
        f"Weighted score: **{result.score:g}/100** "
        f"(scored on {assessed}/100 assessed rubric weight).",
        "",
    ]
    if result.verdict == rubric.VERDICT_CONDITIONS:
        lines.append("## Conditions")
        lines.append("")
        lines.extend(
            f"{i}. {condition}" for i, condition in enumerate(_conditions(score), 1)
        )
        lines.append("")
    for cat in score.categories:
        label = CATEGORY_LABELS.get(cat.category, cat.category)
        if cat.unverified:
            lines.append(f"## {label}: N/A — not independently verified")
        else:
            lines.append(f"## {label}: {cat.score:g}/100")
        lines.append("")
        if cat.findings:
            lines.extend(f"- {finding}" for finding in cat.findings)
        else:
            lines.append("- No findings.")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def explain(result: ScanResult) -> str:
    """Render the deterministic markdown report for a scan result."""
    if result.verdict == rubric.VERDICT_FAIL:
        return _explain_fail(result)
    return _explain_scored(result)
