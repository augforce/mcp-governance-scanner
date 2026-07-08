"""Scored rubric categories, weighted total, and verdict bands.

Only evaluated when no hard gate has tripped. Weights come from
config/rubric.yaml and are validated to sum to 100 on load.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from scanning.gates import strip_comment_text
from scanning.models import CategoryResult, RubricScore, ServerArtifact

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "rubric.yaml"

VERDICT_APPROVED = "Approved"
VERDICT_CONDITIONS = "Approved with Conditions"
VERDICT_REVIEW = "Review Required"
VERDICT_FAIL = "Fail"

CATEGORY_PERMISSION_SCOPE = "permission_scope"
CATEGORY_TOOL_HYGIENE = "tool_hygiene"
CATEGORY_NETWORK_EXPOSURE = "network_exposure"
CATEGORY_MAINTENANCE = "maintenance_provenance"

ALL_CATEGORIES = (
    CATEGORY_PERMISSION_SCOPE,
    CATEGORY_TOOL_HYGIENE,
    CATEGORY_NETWORK_EXPOSURE,
    CATEGORY_MAINTENANCE,
)

# Self-reported provenance fields — enumerated as unverified claims offline;
# Phase 3's GitHub check is what scores them.
_PROVENANCE_FIELDS = ("repository", "author", "version", "license")

# Deductions and per-tool point splits used by the category scorers.
_WILDCARD_FS_DEDUCTION = 40
_WILDCARD_NET_DEDUCTION = 30
_UNDECLARED_PERMISSIONS_SCORE = 50
_BROAD_SCOPE_DEDUCTION = 30
_EXTRA_HOST_DEDUCTION = 10
_BASELINE_HOST_ALLOWANCE = 2
_DYNAMIC_DEST_DEDUCTION = 15

# Network calls whose destination argument is captured for literal-vs-dynamic
# inspection. Deliberately excludes generic method names (e.g. session.get)
# that would false-positive on non-network objects. 'fetch' means the global
# JS fetch() API only: not 'obj.fetch()' (the server's own method), and not
# 'def fetch('/'function fetch(' (a definition, not a call).
_NETWORK_CALL_RE = re.compile(
    r"\b(?:(?:requests|httpx|axios)\.(?:get|post|put|delete|patch|head|options)"
    r"|urllib\.request\.urlopen"
    r"|(?<![\w.])(?<!def )(?<!function )fetch)\s*\(\s*(?P<arg>[^,)\n]*)"
)
# A destination we can check statically: a plain (non-f-string) string literal.
_LITERAL_ARG_RE = re.compile(r"""^["']""")
_TOOL_DESC_POINTS = 40
_TOOL_SCHEMA_POINTS = 30
_TOOL_CONSTRAINT_POINTS = 30
_MIN_DESCRIPTION_LEN = 20


class RubricConfigError(ValueError):
    """Raised when the rubric config is invalid (e.g. weights don't sum to 100)."""


def load_rubric_config(path: Path | str | None = None) -> dict:
    """Load and validate the rubric config. Weights must sum to exactly 100."""
    config_path = Path(path) if path is not None else DEFAULT_CONFIG_PATH
    config = yaml.safe_load(config_path.read_text())
    weights = config.get("weights")
    if not isinstance(weights, dict):
        raise RubricConfigError("rubric config must define a 'weights' mapping")
    if set(weights) != set(ALL_CATEGORIES):
        raise RubricConfigError(
            f"weights must cover exactly {sorted(ALL_CATEGORIES)}, got {sorted(weights)}"
        )
    total = sum(weights.values())
    if total != 100:
        raise RubricConfigError(f"rubric weights must sum to 100, got {total}")
    bands = config.get("bands") or {}
    if "approved_min" not in bands or "conditions_min" not in bands:
        raise RubricConfigError("rubric config must define bands.approved_min and bands.conditions_min")
    return config


def score_permission_scope(artifact: ServerArtifact) -> CategoryResult:
    """Requested access vs. what declared tools need; flags wildcard grants."""
    permissions = artifact.manifest.get("permissions")
    if permissions is None:
        return CategoryResult(
            category=CATEGORY_PERMISSION_SCOPE,
            score=_UNDECLARED_PERMISSIONS_SCORE,
            findings=("No permission declarations in the manifest — requested access cannot be assessed.",),
        )
    score = 100.0
    findings = []
    for path in permissions.get("filesystem", []):
        if path in ("/",) or "*" in path:
            score -= _WILDCARD_FS_DEDUCTION
            findings.append(f"Wildcard or unbounded filesystem grant: '{path}'")
    for host in permissions.get("network", []):
        if "*" in host:
            score -= _WILDCARD_NET_DEDUCTION
            findings.append(f"Wildcard network grant: '{host}'")
    return CategoryResult(
        category=CATEGORY_PERMISSION_SCOPE, score=max(score, 0.0), findings=tuple(findings)
    )


def _has_constraints(schema: dict) -> bool:
    if schema.get("required"):
        return True
    constraint_keys = {"enum", "pattern", "maxLength", "minLength", "minimum", "maximum", "format"}
    return any(
        constraint_keys & set(prop)
        for prop in (schema.get("properties") or {}).values()
        if isinstance(prop, dict)
    )


def score_tool_hygiene(artifact: ServerArtifact) -> CategoryResult:
    """Specificity of tool descriptions; presence of input constraints."""
    tools = artifact.manifest.get("tools") or []
    if not tools:
        return CategoryResult(
            category=CATEGORY_TOOL_HYGIENE,
            score=0.0,
            findings=("No tools declared in the manifest.",),
        )
    findings = []
    total = 0.0
    for tool in tools:
        name = tool.get("name", "<unnamed>")
        points = 0
        if len(tool.get("description", "")) >= _MIN_DESCRIPTION_LEN:
            points += _TOOL_DESC_POINTS
        else:
            findings.append(f"Tool '{name}' has a missing or vague description.")
        schema = tool.get("inputSchema") or {}
        if schema.get("properties"):
            points += _TOOL_SCHEMA_POINTS
        else:
            findings.append(f"Tool '{name}' declares no input schema.")
        if _has_constraints(schema):
            points += _TOOL_CONSTRAINT_POINTS
        else:
            findings.append(f"Tool '{name}' has no input constraints or validation.")
        total += points
    return CategoryResult(
        category=CATEGORY_TOOL_HYGIENE, score=total / len(tools), findings=tuple(findings)
    )


def _dynamic_destination_findings(artifact: ServerArtifact) -> list[str]:
    """Network calls whose destination isn't a checkable string literal.

    Runtime-assembled URLs (env vars, concat, f-strings) are invisible to the
    undisclosed-network hard gate — an inherent static-analysis boundary. They
    are surfaced here as a soft flag needing manual review, not a hard fail,
    because env-based endpoint configuration is legitimate practice.
    """
    findings = []
    for path, content in artifact.source_files.items():
        for lineno, line in enumerate(content.splitlines(), 1):
            for call in _NETWORK_CALL_RE.finditer(strip_comment_text(line)):
                if not _LITERAL_ARG_RE.match(call.group("arg").strip()):
                    findings.append(
                        f"{path}:{lineno} — network call destination is not statically "
                        f"determinable ('{line.strip()}'); requires manual review against "
                        f"the disclosed endpoints."
                    )
    return findings


def score_network_exposure(artifact: ServerArtifact) -> CategoryResult:
    """Disclosed-but-broad scopes; noteworthy third-party data flows."""
    permissions = artifact.manifest.get("permissions") or {}
    hosts = permissions.get("network") or []
    score = 100.0
    findings = []
    for host in hosts:
        if "*" in host:
            score -= _BROAD_SCOPE_DEDUCTION
            findings.append(f"Broad network scope: '{host}'")
    extra_hosts = max(0, len(hosts) - _BASELINE_HOST_ALLOWANCE)
    if extra_hosts:
        score -= _EXTRA_HOST_DEDUCTION * extra_hosts
        findings.append(
            f"{len(hosts)} distinct network hosts declared — each third-party data flow widens exposure."
        )
    dynamic = _dynamic_destination_findings(artifact)
    if dynamic:
        score -= _DYNAMIC_DEST_DEDUCTION  # flat: it flags review need, not per-call badness
        findings.extend(dynamic)
    return CategoryResult(
        category=CATEGORY_NETWORK_EXPOSURE, score=max(score, 0.0), findings=tuple(findings)
    )


def score_maintenance_provenance(
    artifact: ServerArtifact, provenance_report=None
) -> CategoryResult:
    """Maintenance & provenance — N/A offline, never scored from self-reports.

    Everything the manifest says about itself (repository, author, version,
    license) is self-reported: a malicious server can claim all of it. Offline
    this category is therefore unverified — score None, excluded from the
    weighted total — and the findings enumerate the claims so a reviewer can
    check them. A verified ProvenanceReport from the opt-in GitHub check is
    what turns claims into an actual score.
    """
    if provenance_report is not None and provenance_report.verified:
        return _score_verified_provenance(provenance_report)
    findings = []
    for field in _PROVENANCE_FIELDS:
        value = artifact.manifest.get(field)
        if value:
            findings.append(f"Manifest field '{field}' claimed as '{value}' — not independently verified.")
        else:
            findings.append(f"Manifest field '{field}' missing — provenance not verified.")
    return CategoryResult(
        category=CATEGORY_MAINTENANCE, score=None, findings=tuple(findings), unverified=True
    )


def _score_verified_provenance(report) -> CategoryResult:
    """Score independently verified repository facts (points sum to 100)."""
    findings = [f"Repository verified on GitHub: {report.repo}."]
    score = 20.0  # the repo exists and matches the claim
    if report.archived:
        findings.append("Repository is archived — no active maintenance.")
    elif report.days_since_push <= 90:
        score += 40
    elif report.days_since_push <= 365:
        score += 20
        findings.append(f"Last push {report.days_since_push} days ago — aging maintenance.")
    else:
        findings.append(f"Last push {report.days_since_push} days ago — effectively unmaintained.")
    if report.open_issues < 50:
        score += 25
    elif report.open_issues < 200:
        score += 10
        findings.append(f"{report.open_issues} open issues.")
    else:
        findings.append(f"{report.open_issues} open issues — significant unaddressed backlog.")
    if report.license_id and report.license_id != "NOASSERTION":
        score += 15
    else:
        findings.append("No license detected on the repository.")
    return CategoryResult(
        category=CATEGORY_MAINTENANCE, score=score, findings=tuple(findings), unverified=False
    )


_SCORERS = {
    CATEGORY_PERMISSION_SCOPE: score_permission_scope,
    CATEGORY_TOOL_HYGIENE: score_tool_hygiene,
    CATEGORY_NETWORK_EXPOSURE: score_network_exposure,
    CATEGORY_MAINTENANCE: score_maintenance_provenance,
}


def score_rubric(
    artifact: ServerArtifact, config: dict | None = None, provenance_report=None
) -> RubricScore:
    """Score all categories; the 0-100 total is normalized over the assessed ones.

    Unverified categories (score None) are excluded from the weighting rather
    than counted as 0 or 100 — unknown is neither good nor bad. The configured
    weights still sum to 100; assessed_weight reports how much of that the
    total actually covers.
    """
    if config is None:
        config = load_rubric_config()
    categories = tuple(
        score_maintenance_provenance(artifact, provenance_report)
        if category == CATEGORY_MAINTENANCE
        else _SCORERS[category](artifact)
        for category in ALL_CATEGORIES
    )
    weights = config["weights"]
    assessed = [c for c in categories if not c.unverified]
    assessed_weight = sum(weights[c.category] for c in assessed)
    if assessed_weight == 0:
        return RubricScore(total=0.0, categories=categories, assessed_weight=0.0)
    raw = sum(weights[c.category] * c.score / 100 for c in assessed)
    return RubricScore(
        total=raw / assessed_weight * 100, categories=categories, assessed_weight=assessed_weight
    )


def band_for_score(score: float, config: dict | None = None) -> str:
    """Map a weighted score to its verdict band (gates handled elsewhere)."""
    bands = (config or {}).get("bands") or {}
    approved_min = bands.get("approved_min", 85)
    conditions_min = bands.get("conditions_min", 60)
    if score >= approved_min:
        return VERDICT_APPROVED
    if score >= conditions_min:
        return VERDICT_CONDITIONS
    return VERDICT_REVIEW
