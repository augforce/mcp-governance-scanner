# Plain-Language Scan Reports Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every scan report opens with a plain-English "Bottom line" explaining the verdict, and every technical finding is rendered as a plain sentence with the original engine finding kept beneath it as cited evidence.

**Architecture:** Presentation-only change inside `analysis/explainer.py`. The scanning engine (gates, rubric, scoring, finding strings) is untouched — `_conditions()` and engine tests pattern-match on those strings. Translation is a deterministic ordered list of (regex, template) pairs covering the closed set of finding strings the engine can emit; anything unrecognized renders verbatim, never dropped.

**Tech Stack:** Python 3, stdlib `re` only. Tests with pytest (offline — conftest already blocks network/API).

**Spec:** `docs/superpowers/specs/2026-07-08-plain-language-reports-design.md`

## Global Constraints

- The explainer must stay deterministic and offline: no API, no network, no randomness (CLAUDE.md hard constraint).
- Engine finding strings in `scanning/rubric.py` and `scanning/gates.py` MUST NOT change.
- Every existing test in `tests/test_explainer.py` must keep passing unmodified — the strings they assert on ("75/100", "Wildcard or unbounded filesystem grant", "## Conditions", "regardless of", "N/A", "not independently verified", etc.) are kept in the new output on purpose.
- Run tests with: `python3 -m pytest -q` from the repo root.

---

### Task 1: Finding translation layer

**Files:**
- Modify: `analysis/explainer.py` (add constants + two functions; touch nothing existing yet)
- Test: `tests/test_explainer.py` (append a new test class)

**Interfaces:**
- Produces: `_plain_finding(finding: str) -> str | None` (plain sentence, or None when unrecognized), `_finding_lines(finding: str) -> list[str]` (markdown bullet lines: plain sentence + `  - Evidence: <original>`; just the original when unrecognized), `_join_reasons(reasons: list[str]) -> str` ("a", "a; and b", "a; b; and c"). Tasks 2–3 consume all three.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_explainer.py`:

```python
class TestFindingTranslations:
    # One representative engine string per translation pattern -> the plain
    # sentence it must produce. This is the closed set rubric.py can emit.
    CASES = [
        (
            "No permission declarations in the manifest — requested access cannot be assessed.",
            "The server never says what file or internet access it wants, so its requests can't be judged.",
        ),
        (
            "Wildcard or unbounded filesystem grant: '*'",
            "It asks for sweeping file access ('*') instead of just the specific folders it needs.",
        ),
        (
            "Wildcard network grant: '*.example.com'",
            "It asks for broad internet access ('*.example.com') instead of naming the specific sites it needs.",
        ),
        (
            "No tools declared in the manifest.",
            "The server doesn't describe any tools, so there is nothing to check its behavior against.",
        ),
        (
            "Tool 'do_task' has a missing or vague description.",
            "The tool 'do_task' doesn't explain what it does.",
        ),
        (
            "Tool 'do_task' declares no input schema.",
            "The tool 'do_task' doesn't say what input it expects.",
        ),
        (
            "Tool 'do_task' has no input constraints or validation.",
            "The tool 'do_task' accepts anything sent to it, with no checks or limits.",
        ),
        (
            "Broad network scope: '*'",
            "Its declared internet access ('*') covers far more sites than a single purpose needs.",
        ),
        (
            "4 distinct network hosts declared — each third-party data flow widens exposure.",
            "It talks to 4 different internet services — each one is another place your data can go.",
        ),
        (
            "server.py:13 — network call destination is not statically determinable "
            "('resp = requests.post(base)'); requires manual review against the disclosed endpoints.",
            "At server.py:13, the code builds an internet address while running, so we can't "
            "confirm where it sends data — a person should check this.",
        ),
        (
            "Manifest field 'author' claimed as 'anon' — not independently verified.",
            "It says its author is 'anon', but nothing confirms that claim.",
        ),
        (
            "Manifest field 'license' missing — provenance not verified.",
            "It doesn't state its license at all.",
        ),
        (
            "Repository verified on GitHub: example/notes-server.",
            "Its code repository was found on GitHub and matches what it claims (example/notes-server).",
        ),
        (
            "Repository is archived — no active maintenance.",
            "The project is archived — nobody maintains it anymore.",
        ),
        (
            "Last push 200 days ago — aging maintenance.",
            "The code was last updated 200 days ago — it may be falling out of date.",
        ),
        (
            "Last push 900 days ago — effectively unmaintained.",
            "The code hasn't been touched in 900 days — it is effectively abandoned.",
        ),
        (
            "120 open issues.",
            "It has 120 unresolved problem reports.",
        ),
        (
            "300 open issues — significant unaddressed backlog.",
            "It has 300 unresolved problem reports — a large backlog nobody is addressing.",
        ),
        (
            "No license detected on the repository.",
            "The project publishes no license, so its terms of use are unclear.",
        ),
    ]

    def test_every_engine_finding_translates(self):
        from analysis.explainer import _plain_finding

        for engine_text, plain_text in self.CASES:
            assert _plain_finding(engine_text) == plain_text

    def test_unknown_finding_returns_none(self):
        from analysis.explainer import _plain_finding

        assert _plain_finding("Some future finding the engine grew later.") is None

    def test_finding_lines_keep_engine_text_as_evidence(self):
        from analysis.explainer import _finding_lines

        lines = _finding_lines("Wildcard network grant: '*'")
        assert lines[0].startswith("- It asks for broad internet access")
        assert lines[1] == "  - Evidence: Wildcard network grant: '*'"

    def test_finding_lines_fall_back_verbatim(self):
        from analysis.explainer import _finding_lines

        assert _finding_lines("Mystery finding.") == ["- Mystery finding."]

    def test_join_reasons(self):
        from analysis.explainer import _join_reasons

        assert _join_reasons(["a"]) == "a"
        assert _join_reasons(["a", "b"]) == "a; and b"
        assert _join_reasons(["a", "b", "c"]) == "a; b; and c"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_explainer.py -q`
Expected: FAIL — `ImportError: cannot import name '_plain_finding'`

- [ ] **Step 3: Implement the translation layer**

In `analysis/explainer.py`: add `import re` after `from __future__ import annotations`, then add below `CATEGORY_LABELS`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_explainer.py -q`
Expected: all PASS (new class passes; existing tests untouched by this task).

- [ ] **Step 5: Commit**

```bash
git add analysis/explainer.py tests/test_explainer.py
git commit -m "feat: plain-language translation layer for engine findings"
```

---

### Task 2: Plain-language Fail reports

**Files:**
- Modify: `analysis/explainer.py` (add `GATE_PLAIN`; rewrite `_explain_fail`)
- Test: `tests/test_explainer.py` (append tests)

**Interfaces:**
- Consumes: `_join_reasons` from Task 1.
- Produces: `GATE_PLAIN: dict[str, str]` (gate id → lowercase plain reason clause) — Task 3 does not use it, but tests reference it.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_explainer.py`:

```python
class TestPlainFailReport:
    def test_bottom_line_states_plain_reason(self):
        report = explain(scan_artifact(fixtures.hardcoded_credentials_artifact()))
        assert "**Bottom line:**" in report
        assert "fails automatically" in report
        assert "secret key or password is written directly into its code" in report

    def test_gate_section_has_plain_intro_and_keeps_evidence(self):
        report = explain(scan_artifact(fixtures.shell_injection_artifact()))
        assert "In plain terms:" in report
        assert "without checking it first" in report
        # Technical evidence still cited: file:line and the offending snippet.
        assert "shell_tool.py:5" in report
        assert "os.system" in report

    def test_multiple_gates_all_named_in_bottom_line(self):
        from scanning.models import ServerArtifact

        art = fixtures.hardcoded_credentials_artifact()
        files = dict(art.source_files)
        files["debug.py"] = fixtures.CREDENTIAL_ECHO_SOURCE
        report = explain(scan_artifact(ServerArtifact(manifest=art.manifest, source_files=files)))
        assert "written directly into its code" in report
        assert "output or logs" in report
```

Note: `shell_tool.py:5` is the `os.system(...)` line of `fixtures.SHELL_INJECTION_SOURCE`. If the gate reports a different line number, fix the test to the actual line, not the code.

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_explainer.py -q`
Expected: FAIL — "Bottom line" / "In plain terms" not in report.

- [ ] **Step 3: Implement**

In `analysis/explainer.py`, add below `GATE_LABELS`:

```python
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
```

Replace `_explain_fail` with:

```python
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
```

(The existing tests' "regardless of" assertion is satisfied by the Bottom line sentence; "Hardcoded credentials", "auth.py:1", and the snippet citation are unchanged.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_explainer.py -q`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add analysis/explainer.py tests/test_explainer.py
git commit -m "feat: plain-language Bottom line and gate intros for Fail reports"
```

---

### Task 3: Plain-language scored reports

**Files:**
- Modify: `analysis/explainer.py` (add category blurbs + `_bottom_line_scored`; rewrite `_explain_scored`)
- Test: `tests/test_explainer.py` (append tests)

**Interfaces:**
- Consumes: `_finding_lines`, `_join_reasons` (Task 1).
- Produces: nothing new for later tasks (final task changing the module).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_explainer.py`:

```python
class TestPlainScoredReport:
    def _low_scoring_artifact(self):
        import copy

        from scanning.models import ServerArtifact

        manifest = copy.deepcopy(fixtures.CLEAN_MANIFEST)
        manifest["permissions"]["filesystem"] = ["*"]
        manifest["permissions"]["network"] = ["*"]
        manifest["tools"] = [{"name": "do_task"}]
        return ServerArtifact(manifest=manifest, source_files={"server.py": fixtures.CLEAN_SOURCE})

    def test_bottom_line_names_score_band_and_worst_categories(self):
        report = explain(scan_artifact(self._low_scoring_artifact()))
        assert "**Bottom line:**" in report
        assert "out of 100" in report
        assert "a person should review it" in report          # Review Required band
        assert "The biggest problems:" in report
        # tool_hygiene scores 0 -> named first; permission_scope 30 -> second.
        assert "don't clearly say what they do" in report
        assert "more access than its tools appear to need" in report

    def test_scores_are_rounded_whole_numbers(self):
        report = explain(scan_artifact(self._low_scoring_artifact()))
        assert ".6667" not in report
        assert ".0/100" not in report

    def test_unverified_publisher_named_in_bottom_line(self):
        report = explain(scan_artifact(fixtures.clean_artifact()))
        assert "could not confirm who publishes or maintains this server" in report

    def test_category_headings_carry_plain_questions(self):
        report = explain(scan_artifact(fixtures.clean_artifact()))
        assert "Does it ask for only the access it needs?" in report
        assert "Do its tools say what they do and check their inputs?" in report

    def test_findings_rendered_plain_with_evidence(self):
        report = explain(scan_artifact(self._low_scoring_artifact()))
        assert "It asks for sweeping file access ('*')" in report
        assert "  - Evidence: Wildcard or unbounded filesystem grant: '*'" in report

    def test_clean_categories_say_no_problems_found(self):
        report = explain(scan_artifact(fixtures.clean_artifact()))
        assert "No problems found." in report
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_explainer.py -q`
Expected: FAIL — "Bottom line" / plain questions not in scored report.

- [ ] **Step 3: Implement**

In `analysis/explainer.py`, add below `CATEGORY_LABELS`:

```python
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
```

Add above `_explain_scored`, and replace `_explain_scored`, with:

```python
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
```

(`_conditions` is unchanged — its output strings are asserted by existing tests and remain reasonably plain. The old "Weighted score … assessed rubric weight" line is replaced by the plain "Score: …/100, based on the N/100 rubric points that could be verified offline." — which keeps the "75/100" substring the existing test asserts.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_explainer.py -q`
Expected: all PASS, including every pre-existing test.

- [ ] **Step 5: Commit**

```bash
git add analysis/explainer.py tests/test_explainer.py
git commit -m "feat: plain-language Bottom line, questions, and findings for scored reports"
```

---

### Task 4: End-to-end verification

**Files:** none created/modified (verification only; fix regressions if found).

- [ ] **Step 1: Full test suite**

Run: `python3 -m pytest -q`
Expected: all tests pass, 0 failures.

- [ ] **Step 2: Real reports from the corpus**

Run:
```bash
python3 -m app.scan corpus/known_bad/overbroad_access
python3 -m app.scan corpus/known_bad/hardcoded_key
python3 -m app.scan corpus/known_good/anthropic_time
```
Expected: each report opens with `**Bottom line:**` in plain English; findings read as plain sentences with `Evidence:` lines; no raw `26.6667`-style scores. Read the output as a non-expert would — if any sentence still needs security vocabulary to parse, fix the template and re-run Task 1's tests.

- [ ] **Step 3: Web view smoke check**

Run: `python3 -m pytest tests/test_web.py -q` (already covered in Step 1; re-run only if templates were touched — they should not be).
