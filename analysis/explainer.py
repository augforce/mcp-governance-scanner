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

# Actionable remedy per gate, rendered once per gate section.
GATE_FIXES = {
    "hardcoded_credentials": (
        "Remove the secret from the code, read it from an environment "
        "variable or a secrets manager instead, and rotate the exposed key — "
        "treat it as already leaked."
    ),
    "unvalidated_input": (
        "Validate the input before it reaches the sink: use parameterized "
        "queries, pass subprocess arguments as a list instead of building "
        "shell strings, and allow-list acceptable file paths."
    ),
    "undisclosed_network_calls": (
        "Either remove the call or disclose the endpoint in the manifest "
        "(permissions.network) or documentation so the data flow can be "
        "reviewed and approved."
    ),
    "credential_echo": (
        "Remove the credential from the message, or mask it (for example, "
        "log only the last four characters)."
    ),
}

CATEGORY_LABELS = {
    rubric.CATEGORY_PERMISSION_SCOPE: "Permission & Scope",
    rubric.CATEGORY_TOOL_HYGIENE: "Tool Definition Hygiene",
    rubric.CATEGORY_NETWORK_EXPOSURE: "Network & Data Exposure",
    rubric.CATEGORY_MAINTENANCE: "Maintenance & Provenance",
}

# One-line plain question each category answers, shown under its heading.
CATEGORY_QUESTIONS = {
    rubric.CATEGORY_PERMISSION_SCOPE: "Does it ask for only the access it needs?",
    rubric.CATEGORY_TOOL_HYGIENE: "Do its tools say what they do and check their inputs?",
    rubric.CATEGORY_NETWORK_EXPOSURE: "How widely does it share data over the internet?",
    rubric.CATEGORY_MAINTENANCE: "Who publishes it, and is it kept up to date?",
}

# Plain problem summary per category, used in the Bottom line when it scores low.
CATEGORY_PROBLEMS = {
    rubric.CATEGORY_PERMISSION_SCOPE: "it asks for more access than its tools appear to need",
    rubric.CATEGORY_TOOL_HYGIENE: "its tools don't clearly say what they do or check the input they receive",
    rubric.CATEGORY_NETWORK_EXPOSURE: "its internet access is broader than it should be",
    rubric.CATEGORY_MAINTENANCE: "it shows signs of being unmaintained",
}

# A category below this is called out as a "biggest problem" in the Bottom
# line (mirrors the conditions band floor; presentation only, not scoring).
_LOW_CATEGORY = 60

_BAND_PHRASES = {
    rubric.VERDICT_APPROVED: "high enough to be approved",
    rubric.VERDICT_CONDITIONS: (
        "good, but not good enough for automatic approval — it should only be "
        "used once the conditions below are addressed"
    ),
    rubric.VERDICT_REVIEW: (
        "too low for approval, so a person should review it before anyone uses it"
    ),
}

# Ordered (pattern, plain template, suggested-fix template) triples covering
# every finding string the engine can emit (scanning/rubric.py). First match
# wins; a finding matching nothing renders verbatim — never dropped. A None
# fix is deliberate: good-news and purely informational findings have nothing
# to fix. Order matters only where one pattern is a prefix of another
# ("open issues — significant" before "open issues.").
_TRANSLATIONS: tuple[tuple[re.Pattern, str, str | None], ...] = (
    (
        re.compile(r"^No permission declarations in the manifest"),
        "The server never says what file or internet access it wants, so its requests can't be judged.",
        "Add a 'permissions' section to the manifest declaring the file and internet access the server needs.",
    ),
    (
        re.compile(r"^Wildcard or unbounded filesystem grant: '(?P<path>.*)'"),
        "It asks for sweeping file access ('{path}') instead of just the specific folders it needs.",
        "Replace '{path}' with the specific folder(s) the tools actually need to read or write.",
    ),
    (
        re.compile(r"^Wildcard network grant: '(?P<host>.*)'"),
        "It asks for broad internet access ('{host}') instead of naming the specific sites it needs.",
        "Replace '{host}' with the specific hostname(s) the server actually contacts.",
    ),
    (
        re.compile(r"^No tools declared in the manifest\."),
        "The server doesn't describe any tools, so there is nothing to check its behavior against.",
        "Declare each tool in the manifest with a name, a description, and an input schema.",
    ),
    (
        re.compile(r"^Tool '(?P<name>.*)' has a missing or vague description\."),
        "The tool '{name}' doesn't explain what it does.",
        "Write a description that says what the tool does, what input it takes, and what it returns.",
    ),
    (
        re.compile(r"^Tool '(?P<name>.*)' declares no input schema\."),
        "The tool '{name}' doesn't say what input it expects.",
        "Add an inputSchema to the tool listing each parameter and its type.",
    ),
    (
        re.compile(r"^Tool '(?P<name>.*)' has no input constraints or validation\."),
        "The tool '{name}' accepts anything sent to it, with no checks or limits.",
        "Add validation to the schema: mark required fields and set limits "
        "(enum, maxLength, minimum/maximum, pattern).",
    ),
    (
        re.compile(r"^Broad network scope: '(?P<host>.*)'"),
        "Its declared internet access ('{host}') covers far more sites than a single purpose needs.",
        "Narrow '{host}' to the specific hostname(s) this server needs.",
    ),
    (
        re.compile(r"^(?P<count>\d+) distinct network hosts declared"),
        "It talks to {count} different internet services — each one is another place your data can go.",
        "Remove any hosts the tools don't strictly need; each remaining one should be justifiable.",
    ),
    (
        re.compile(r"^(?P<where>\S+:\d+) — network call destination is not statically"),
        "At {where}, the code builds an internet address while running, so we can't "
        "confirm where it sends data — a person should check this.",
        "Use a fixed URL where possible; if the destination must be configurable, "
        "document the allowed endpoint(s) so a reviewer can check them.",
    ),
    (
        re.compile(r"^Manifest field '(?P<field>.*)' claimed as '(?P<value>.*)' — not independently verified\."),
        "It says its {field} is '{value}', but nothing confirms that claim.",
        "Verify the claim independently — run the opt-in GitHub provenance check "
        "(set GITHUB_TOKEN) or review the {field} by hand.",
    ),
    (
        re.compile(r"^Manifest field '(?P<field>.*)' missing"),
        "It doesn't state its {field} at all.",
        "Add the {field} field to the manifest so it can be independently verified.",
    ),
    (
        re.compile(r"^Repository verified on GitHub: (?P<repo>.*)\."),
        "Its code repository was found on GitHub and matches what it claims ({repo}).",
        None,  # good news — nothing to fix
    ),
    (
        re.compile(r"^Repository is archived"),
        "The project is archived — nobody maintains it anymore.",
        "Prefer a maintained fork or an actively maintained alternative server.",
    ),
    (
        re.compile(r"^Last push (?P<days>\d+) days ago — aging"),
        "The code was last updated {days} days ago — it may be falling out of date.",
        "Check with the publisher whether the project is still maintained before relying on it.",
    ),
    (
        re.compile(r"^Last push (?P<days>\d+) days ago — effectively unmaintained"),
        "The code hasn't been touched in {days} days — it is effectively abandoned.",
        "Treat it as abandoned: prefer a maintained fork or an alternative server.",
    ),
    (
        re.compile(r"^(?P<count>\d+) open issues — significant"),
        "It has {count} unresolved problem reports — a large backlog nobody is addressing.",
        "Review the open issues for security-relevant reports before adopting this server.",
    ),
    (
        re.compile(r"^(?P<count>\d+) open issues\."),
        "It has {count} unresolved problem reports.",
        None,  # informational at this volume — the score already reflects it
    ),
    (
        re.compile(r"^No license detected"),
        "The project publishes no license, so its terms of use are unclear.",
        "Ask the publisher to add a license; without one the terms of use are undefined.",
    ),
)


def _match_translation(finding: str):
    for pattern, plain, fix in _TRANSLATIONS:
        match = pattern.match(finding)
        if match:
            return match, plain, fix
    return None, None, None


def _plain_finding(finding: str) -> str | None:
    """Translate an engine finding to plain language; None when unrecognized."""
    match, plain, _fix = _match_translation(finding)
    return plain.format(**match.groupdict()) if match else None


def _suggested_fix(finding: str) -> str | None:
    """Actionable fix for a finding; None when unrecognized or nothing to fix."""
    match, _plain, fix = _match_translation(finding)
    return fix.format(**match.groupdict()) if match and fix else None


def _finding_lines(finding: str) -> list[str]:
    """Markdown bullet for one finding: plain sentence, engine text as
    evidence, and a suggested fix where one applies."""
    plain = _plain_finding(finding)
    if plain is None:
        return [f"- {finding}"]
    lines = [f"- {plain}", f"  - Evidence: {finding}"]
    fix = _suggested_fix(finding)
    if fix:
        lines.append(f"  - Suggested fix: {fix}")
    return lines


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
        # With a single gate the Bottom line already gave this exact reason;
        # per-gate intros only earn their place when there are several.
        plain = GATE_PLAIN.get(gate) if len(gates) > 1 else None
        if plain:
            lines.append(f"In plain terms: {plain[0].upper()}{plain[1:]}.")
            lines.append("")
        for f in result.gate_findings:
            if f.gate != gate:
                continue
            location = f.file if f.line == 0 else f"{f.file}:{f.line}"
            lines.append(f"- **{location}** — {f.explanation}")
            lines.append(f"  - `{f.snippet}`")
        fix = GATE_FIXES.get(gate)
        if fix:
            lines.append("")
            lines.append(f"**Suggested fix:** {fix}")
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


def _bottom_line_scored(result: ScanResult) -> str:
    score = result.rubric
    sentences = [
        f"**Bottom line:** This server scored {round(result.score)} out of 100 "
        f"on what could be checked — {_BAND_PHRASES[result.verdict]}."
    ]
    low = sorted(
        (c for c in score.categories if not c.unverified and c.score < _LOW_CATEGORY),
        key=lambda c: c.score,
    )
    if low:
        problems = [CATEGORY_PROBLEMS[c.category] for c in low[:2]]
        label = "The biggest problem" if len(problems) == 1 else "The biggest problems"
        sentences.append(f"{label}: {_join_reasons(problems)}.")
    if any(c.unverified for c in score.categories):
        sentences.append(
            "We also could not confirm who publishes or maintains this server, "
            "so that part is left out of the score."
        )
    return " ".join(sentences)


def _explain_scored(result: ScanResult) -> str:
    score = result.rubric
    assessed = int(score.assessed_weight)
    lines = [
        f"# Verdict: {result.verdict}",
        "",
        _bottom_line_scored(result),
        "",
        f"Score: **{round(result.score)}/100**, based on the {assessed}/100 "
        "rubric points that could be verified offline.",
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
            lines.append(f"## {label}: {round(cat.score)}/100")
        question = CATEGORY_QUESTIONS.get(cat.category)
        if question:
            lines.append(f"*{question}*")
        lines.append("")
        if cat.findings:
            for finding in cat.findings:
                lines.extend(_finding_lines(finding))
        else:
            lines.append("- No problems found.")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def explain(result: ScanResult) -> str:
    """Render the deterministic markdown report for a scan result."""
    if result.verdict == rubric.VERDICT_FAIL:
        return _explain_fail(result)
    return _explain_scored(result)
