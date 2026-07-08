"""Deterministic prose explanation of a scan — the default, offline narrative.

Every finding the engine produced is rendered with its citation; nothing is
generated, sampled, or fetched. The optional Claude layer (Phase 3) adds a
narrative on top of this; it never replaces it.
"""

from __future__ import annotations

import re

from scanning import rubric
from scanning.models import ScanResult

GATE_LABELS = {
    "hardcoded_credentials": "Hardcoded credentials",
    "unvalidated_input": "Unvalidated input reaching a shell/path/query",
    "undisclosed_network_calls": "Undisclosed network calls",
    "credential_echo": "Credentials echoed in output or logs",
}

# Plain-language reason per gate — lowercase clauses composed into the
# Bottom line sentence and capitalized as each gate section's intro.
GATE_PLAIN = {
    "hardcoded_credentials": (
        "a secret key or password is written directly into its code or settings, "
        "so anyone who obtains a copy of this server gets the secret too"
    ),
    "unvalidated_input": (
        "it passes text it receives straight into system commands, file paths, "
        "or queries without checking it first — an attacker could exploit that "
        "to run their own commands"
    ),
    "undisclosed_network_calls": (
        "it contacts internet addresses that its documentation never mentions, "
        "so it may be sending data somewhere you don't know about"
    ),
    "credential_echo": (
        "it writes secret keys or passwords into its output or logs, where "
        "they can easily leak"
    ),
}

CATEGORY_LABELS = {
    rubric.CATEGORY_PERMISSION_SCOPE: "Permission & Scope",
    rubric.CATEGORY_TOOL_HYGIENE: "Tool Definition Hygiene",
    rubric.CATEGORY_NETWORK_EXPOSURE: "Network & Data Exposure",
    rubric.CATEGORY_MAINTENANCE: "Maintenance & Provenance",
}

# Ordered (pattern, template) pairs covering every finding string the engine
# can emit (scanning/rubric.py). First match wins; a finding matching nothing
# renders verbatim — never dropped. Order matters only where one pattern is a
# prefix of another ("open issues — significant" before "open issues.").
_TRANSLATIONS: tuple[tuple[re.Pattern, str], ...] = (
    (
        re.compile(r"^No permission declarations in the manifest"),
        "The server never says what file or internet access it wants, so its requests can't be judged.",
    ),
    (
        re.compile(r"^Wildcard or unbounded filesystem grant: '(?P<path>.*)'"),
        "It asks for sweeping file access ('{path}') instead of just the specific folders it needs.",
    ),
    (
        re.compile(r"^Wildcard network grant: '(?P<host>.*)'"),
        "It asks for broad internet access ('{host}') instead of naming the specific sites it needs.",
    ),
    (
        re.compile(r"^No tools declared in the manifest\."),
        "The server doesn't describe any tools, so there is nothing to check its behavior against.",
    ),
    (
        re.compile(r"^Tool '(?P<name>.*)' has a missing or vague description\."),
        "The tool '{name}' doesn't explain what it does.",
    ),
    (
        re.compile(r"^Tool '(?P<name>.*)' declares no input schema\."),
        "The tool '{name}' doesn't say what input it expects.",
    ),
    (
        re.compile(r"^Tool '(?P<name>.*)' has no input constraints or validation\."),
        "The tool '{name}' accepts anything sent to it, with no checks or limits.",
    ),
    (
        re.compile(r"^Broad network scope: '(?P<host>.*)'"),
        "Its declared internet access ('{host}') covers far more sites than a single purpose needs.",
    ),
    (
        re.compile(r"^(?P<count>\d+) distinct network hosts declared"),
        "It talks to {count} different internet services — each one is another place your data can go.",
    ),
    (
        re.compile(r"^(?P<where>\S+:\d+) — network call destination is not statically"),
        "At {where}, the code builds an internet address while running, so we can't "
        "confirm where it sends data — a person should check this.",
    ),
    (
        re.compile(r"^Manifest field '(?P<field>.*)' claimed as '(?P<value>.*)' — not independently verified\."),
        "It says its {field} is '{value}', but nothing confirms that claim.",
    ),
    (
        re.compile(r"^Manifest field '(?P<field>.*)' missing"),
        "It doesn't state its {field} at all.",
    ),
    (
        re.compile(r"^Repository verified on GitHub: (?P<repo>.*)\."),
        "Its code repository was found on GitHub and matches what it claims ({repo}).",
    ),
    (
        re.compile(r"^Repository is archived"),
        "The project is archived — nobody maintains it anymore.",
    ),
    (
        re.compile(r"^Last push (?P<days>\d+) days ago — aging"),
        "The code was last updated {days} days ago — it may be falling out of date.",
    ),
    (
        re.compile(r"^Last push (?P<days>\d+) days ago — effectively unmaintained"),
        "The code hasn't been touched in {days} days — it is effectively abandoned.",
    ),
    (
        re.compile(r"^(?P<count>\d+) open issues — significant"),
        "It has {count} unresolved problem reports — a large backlog nobody is addressing.",
    ),
    (
        re.compile(r"^(?P<count>\d+) open issues\."),
        "It has {count} unresolved problem reports.",
    ),
    (
        re.compile(r"^No license detected"),
        "The project publishes no license, so its terms of use are unclear.",
    ),
)


def _plain_finding(finding: str) -> str | None:
    """Translate an engine finding to plain language; None when unrecognized."""
    for pattern, template in _TRANSLATIONS:
        match = pattern.match(finding)
        if match:
            return template.format(**match.groupdict())
    return None


def _finding_lines(finding: str) -> list[str]:
    """Markdown bullet for one finding: plain sentence, engine text as evidence."""
    plain = _plain_finding(finding)
    if plain is None:
        return [f"- {finding}"]
    return [f"- {plain}", f"  - Evidence: {finding}"]


def _join_reasons(reasons: list[str]) -> str:
    """'a' / 'a; and b' / 'a; b; and c' — reads as one sentence."""
    if len(reasons) == 1:
        return reasons[0]
    return "; ".join(reasons[:-1]) + "; and " + reasons[-1]


def _explain_fail(result: ScanResult) -> str:
    gates = sorted({f.gate for f in result.gate_findings})
    reasons = [GATE_PLAIN.get(gate, GATE_LABELS.get(gate, gate)) for gate in gates]
    lines = [
        "# Verdict: Fail",
        "",
        f"**Bottom line:** This server fails automatically because "
        f"{_join_reasons(reasons)}. A problem like this is a deal-breaker "
        "regardless of how well the server would have scored elsewhere, so no "
        "category scores are reported.",
        "",
    ]
    for gate in gates:
        lines.append(f"## Hard gate: {GATE_LABELS.get(gate, gate)}")
        lines.append("")
        plain = GATE_PLAIN.get(gate)
        if plain:
            lines.append(f"In plain terms: {plain[0].upper()}{plain[1:]}.")
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
