"""Shared data structures for the deterministic scanning engine.

Pure data, no I/O and no logic — everything downstream (gates, rubric,
orchestrator) operates on these.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ServerArtifact:
    """An ingested MCP server: its manifest plus source files.

    manifest: parsed manifest/tool-definition document (dict).
    source_files: mapping of relative file path -> file content. Includes
        config files (.json/.yaml/.toml/.env.example) — they are scanned the
        same as code.
    docs: documentation files (e.g. README.md). Endpoints named here count
        as *disclosed* for the undisclosed-network gate; docs are not scanned
        as code.
    vendored: paths (keys of source_files) that are bundled third-party
        assets (vendor/ dirs, minified bundles). Scanned by every check
        EXCEPT the hardcoded-credentials gate, which they would flood with
        secret-shaped noise.
    """

    manifest: dict
    source_files: dict[str, str] = field(default_factory=dict)
    docs: dict[str, str] = field(default_factory=dict)
    vendored: tuple[str, ...] = ()


@dataclass(frozen=True)
class GateFinding:
    """A single hard-gate violation. Any one of these = automatic fail."""

    gate: str  # gate identifier, e.g. "hardcoded_credentials"
    file: str  # file path (or "manifest") where the violation was found
    line: int  # 1-indexed line number; 0 when not line-addressable
    snippet: str  # the offending text
    explanation: str  # plain-English reason this trips the gate


@dataclass(frozen=True)
class CategoryResult:
    """Score for one rubric category, 0-100, with cited findings.

    unverified=True means the category could not be independently assessed
    (e.g. provenance offline, where the manifest's claims are self-reported):
    score is None, the findings label the claims, and the category is
    excluded from the weighted total rather than contributing false confidence.
    """

    category: str
    score: float | None  # 0-100 within the category; None when unverified
    findings: tuple[str, ...] = ()
    unverified: bool = False


@dataclass(frozen=True)
class RubricScore:
    """Weighted rubric outcome across all categories.

    total is normalized over the assessed categories only; assessed_weight
    says how much of the full 100 rubric weight that covers, so output can
    read "100 (on 75/100 assessed weight)" instead of implying full coverage.
    """

    total: float  # 0-100, normalized over assessed categories
    categories: tuple[CategoryResult, ...]
    assessed_weight: float = 100.0


@dataclass(frozen=True)
class ScanResult:
    """Final deterministic verdict for a scanned server."""

    verdict: str  # Approved / Approved with Conditions / Review Required / Fail
    score: float | None  # weighted score; None when a gate tripped
    gate_findings: tuple[GateFinding, ...]
    rubric: RubricScore | None  # None when a gate tripped
